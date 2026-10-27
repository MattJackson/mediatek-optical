//! Complete native response-commit data flow and balanced return validation.
use super::decoded::{exact, literal_load, memory_is, transfer};
use super::response_expr::{clamp_allows, Expr, Guards};
use super::Error;
use std::collections::{BTreeSet, VecDeque};
use thumb_asm::isa::{decode_at, AddrMode, Operand, Reg};

const SOURCE_REGISTER: u32 = 0x040300e8;
const LENGTH_REGISTER: u32 = 0x04042154;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Value {
    Unknown,
    Constant(u32),
    Offset,
    Source,
    Expression(Expr),
    Length,
}
impl Value {
    fn expression(self) -> Option<Expr> {
        Some(match self {
            Self::Unknown => return None,
            Self::Constant(v) => Expr::constant(v),
            Self::Source => Expr::SOURCE,
            Self::Offset => Expr::OFFSET,
            Self::Length => Expr::LENGTH,
            Self::Expression(expr) => expr,
        })
    }
    fn from_expression(expr: Expr) -> Self {
        expr.as_constant()
            .map_or(Self::Expression(expr), Self::Constant)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Protocol {
    pub length_writes: Vec<usize>,
    pub ready_cell: u32,
    pub returns: Vec<usize>,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    registers: [Value; 16],
    frame: Option<u16>,
    source: Option<Expr>,
    comparison: Option<(Expr, Expr)>,
    guards: Guards,
    length: bool,
    queued: Option<u32>,
}
impl State {
    fn define(&mut self, register: Reg, value: Value) -> Result<(), Error> {
        let reg = register.num();
        if reg >= 13
            || ((4..=11).contains(&reg) && self.frame.map_or(true, |mask| mask & (1 << reg) == 0))
        {
            return Err(Error::InvalidContract);
        }
        self.registers[usize::from(reg)] = value;
        Ok(())
    }
    fn operand(&self, operand: Operand) -> Result<Value, Error> {
        match operand {
            Operand::Reg(reg) => Ok(self.registers[usize::from(reg.num())]),
            Operand::Imm(value) => Ok(Value::Constant(
                u32::try_from(value).map_err(|_| Error::InvalidContract)?,
            )),
            _ => Err(Error::InvalidContract),
        }
    }
}
/// Prove the OEM saturating/even-byte length normalization, including both
/// guards. Arithmetic roles alone cannot distinguish an increment from a decrement.
fn normalization(image: &[u8], at: usize) -> Option<(usize, usize)> {
    use Operand::{Imm, Reg as R};
    let (value, memory) = transfer(image, at, "ldrh")?;
    let (limit, sentinel) = literal_load(image, at + 2)?;
    if sentinel != 0xffff
        || memory.offset != 0
        || value == limit
        || value == memory.base
        || limit == memory.base
    {
        return None;
    }
    let v = value.num();
    let base = memory.base.num();
    if !exact(image, at + 4, "cmp", &[R(value), R(limit)])
        || super::conditional(image, at + 6, thumb_asm::Cond::Ne) != Some(at + 14)
        || !memory_is(image, at + 8, "ldrh", v, base, 0)
        || !exact(image, at + 10, "sub", &[R(value), R(value), Imm(1)])
        || !memory_is(image, at + 12, "strh", v, base, 0)
        || !memory_is(image, at + 14, "ldrh", v, base, 0)
        || !exact(image, at + 16, "lsl", &[R(value), R(value), Imm(31)])
        || super::conditional(image, at + 18, thumb_asm::Cond::Eq) != Some(at + 26)
        || !memory_is(image, at + 20, "ldrh", v, base, 0)
        || !exact(image, at + 22, "add", &[R(value), R(value), Imm(1)])
        || !memory_is(image, at + 24, "strh", v, base, 0)
    {
        return None;
    }
    Some((at + 10, at + 22))
}
pub(super) fn validate(
    image: &[u8],
    entry: usize,
    source_cell: u32,
    length_cell: u32,
) -> Result<Protocol, Error> {
    let normalizations: Vec<_> = (entry..entry.saturating_add(0x80).min(image.len()))
        .step_by(2)
        .filter_map(|at| normalization(image, at))
        .collect();
    let [(decrement, increment)] = normalizations.as_slice() else {
        return Err(Error::InvalidContract);
    };
    let mut registers = [Value::Unknown; 16];
    registers[0] = Value::Offset;
    let initial = State {
        registers,
        frame: None,
        source: None,
        comparison: None,
        guards: Guards::new(),
        length: false,
        queued: None,
    };
    let mut queue = VecDeque::from([(entry, initial)]);
    let mut seen = BTreeSet::new();
    let mut returns = BTreeSet::new();
    let mut writes = BTreeSet::new();
    let mut ready_cells = BTreeSet::new();
    while let Some((pc, mut state)) = queue.pop_front() {
        if !seen.insert((pc, state.clone())) {
            continue;
        }
        if seen.len() > 4096 || pc < entry || pc >= entry + 0x180 {
            return Err(Error::InvalidContract);
        }
        let ins = decode_at(image, pc).ok_or(Error::Truncated)?;
        if ins.len() != 2 || ins.is_call() {
            return Err(Error::InvalidContract);
        }
        let next = pc + ins.len();
        let first = ins.operands.get(0);
        let second = ins.operands.get(1);
        if ins.mnemonic == "cmp" {
            state.comparison = state
                .operand(first.ok_or(Error::InvalidContract)?)?
                .expression()
                .zip(
                    state
                        .operand(second.ok_or(Error::InvalidContract)?)?
                        .expression(),
                );
        } else if ins.sets_flags {
            state.comparison = None;
        }
        if ins.mnemonic == "push" {
            let Some(Operand::RegList(mask)) = first else {
                return Err(Error::InvalidContract);
            };
            if state.frame.is_some() || mask & (1 << 14) == 0 || mask & (1 << 15) != 0 {
                return Err(Error::InvalidContract);
            }
            state.frame = Some(mask);
        } else if ins.mnemonic == "pop" {
            let Some(Operand::RegList(mask)) = first else {
                return Err(Error::InvalidContract);
            };
            let expected = state.frame.ok_or(Error::InvalidContract)?;
            if mask != (expected & !(1 << 14)) | (1 << 15)
                || state.source.is_none()
                || !state.length
                || state.queued.is_none()
            {
                return Err(Error::InvalidContract);
            }
            ready_cells.insert(state.queued.ok_or(Error::InvalidContract)?);
            returns.insert(pc);
            continue;
        } else if ins.mnemonic == "bx" {
            if first != Some(Operand::Reg(Reg::LR))
                || state.frame.is_some()
                || state.source.is_none()
                || !state.length
                || state.queued.is_none()
            {
                return Err(Error::InvalidContract);
            }
            ready_cells.insert(state.queued.ok_or(Error::InvalidContract)?);
            returns.insert(pc);
            continue;
        } else if ins.is_branch() {
            if ins.mnemonic != "b" {
                return Err(Error::InvalidContract);
            }
            let target = ins.branch_target().ok_or(Error::InvalidContract)? as usize;
            if target <= pc {
                return Err(Error::InvalidContract);
            }
            let mut taken = state.clone();
            if let (Some(cond), Some((a, b))) = (ins.cond, state.comparison) {
                taken.guards.insert((a, cond, b));
                state.guards.insert((a, cond.invert(), b));
            }
            queue.push_back((target, taken));
            if ins.cond.is_some() {
                queue.push_back((next, state));
            }
            continue;
        } else if ins.writes_pc() || ins.cond.is_some() {
            return Err(Error::InvalidContract);
        } else if let (Some(Operand::Reg(reg)), Some(Operand::Mem(memory))) = (first, second) {
            if memory.mode != AddrMode::Offset || memory.index.is_some() || !memory.add {
                return Err(Error::InvalidContract);
            }
            let base = state.registers[usize::from(memory.base.num())];
            if ins.mnemonic == "ldr" && memory.base == Reg::PC {
                state.define(
                    reg,
                    Value::Constant(
                        thumb_asm::analysis::literal_value(image, pc).ok_or(Error::Truncated)?,
                    ),
                )?;
            } else {
                let Value::Constant(base) = base else {
                    return Err(Error::InvalidContract);
                };
                let address = base
                    .checked_add(memory.offset)
                    .ok_or(Error::InvalidContract)?;
                match ins.mnemonic {
                    "ldr" => {
                        let value = if address == source_cell {
                            Value::Source
                        } else if address == SOURCE_REGISTER && state.source.is_some() {
                            Value::Expression(state.source.ok_or(Error::InvalidContract)?)
                        } else {
                            return Err(Error::InvalidContract);
                        };
                        state.define(reg, value)?;
                    }
                    "ldrh" if address == length_cell => state.define(reg, Value::Length)?,
                    "strh"
                        if address == length_cell
                            && state.registers[usize::from(reg.num())] == Value::Length => {}
                    "str" if address == SOURCE_REGISTER => {
                        let value = state.registers[usize::from(reg.num())]
                            .expression()
                            .ok_or(Error::InvalidContract)?;
                        if state.source.is_none() {
                            if value != Expr::ADDRESS {
                                return Err(Error::InvalidContract);
                            }
                        } else if !clamp_allows(&state.guards, value, true) {
                            return Err(Error::InvalidContract);
                        }
                        state.source = Some(value);
                    }
                    "str" if address == LENGTH_REGISTER => {
                        let value = state.registers[usize::from(reg.num())]
                            .expression()
                            .ok_or(Error::InvalidContract)?;
                        if value != Expr::LENGTH && !clamp_allows(&state.guards, value, false) {
                            return Err(Error::InvalidContract);
                        }
                        state.length = true;
                        writes.insert(pc);
                    }
                    "strb"
                        if (0x02000000..0x02002000).contains(&address)
                            && address < length_cell
                            && length_cell - address <= 8
                            && state.registers[usize::from(reg.num())] == Value::Constant(1)
                            && state.source.is_some()
                            && state.length =>
                    {
                        state.queued = Some(address)
                    }
                    _ => return Err(Error::InvalidContract),
                }
            }
        } else if ins.mnemonic == "mov" {
            let Some(Operand::Reg(dest)) = first else {
                return Err(Error::InvalidContract);
            };
            state.define(dest, state.operand(second.ok_or(Error::InvalidContract)?)?)?;
        } else if matches!(ins.mnemonic, "add" | "sub") {
            let Some(Operand::Reg(dest)) = first else {
                return Err(Error::InvalidContract);
            };
            let (left, right) = if let Some(third) = ins.operands.get(2) {
                (
                    state.operand(second.ok_or(Error::InvalidContract)?)?,
                    state.operand(third)?,
                )
            } else {
                (
                    state.registers[usize::from(dest.num())],
                    state.operand(second.ok_or(Error::InvalidContract)?)?,
                )
            };
            let value = if left == Value::Length
                && right == Value::Constant(1)
                && ((ins.mnemonic == "sub" && pc == *decrement)
                    || (ins.mnemonic == "add" && pc == *increment))
            {
                Value::Length
            } else {
                Value::from_expression(left.expression().ok_or(Error::InvalidContract)?.combine(
                    right.expression().ok_or(Error::InvalidContract)?,
                    ins.mnemonic == "sub",
                )?)
            };
            state.define(dest, value)?;
        } else if matches!(ins.mnemonic, "lsl" | "lsr") {
            let Some(Operand::Reg(dest)) = first else {
                return Err(Error::InvalidContract);
            };
            state.define(dest, Value::Unknown)?;
        } else if !matches!(ins.mnemonic, "cmp" | "tst" | "nop") {
            return Err(Error::InvalidContract);
        }
        queue.push_back((next, state));
    }
    if returns.is_empty() || writes.is_empty() || ready_cells.len() != 1 {
        return Err(Error::InvalidContract);
    }
    Ok(Protocol {
        length_writes: writes.into_iter().collect(),
        ready_cell: *ready_cells.first().ok_or(Error::InvalidContract)?,
        returns: returns.into_iter().collect(),
    })
}

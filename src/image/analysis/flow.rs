//! Bounded straight-line value provenance for native scratch preparation.
//! Values describe relationships; they never infer a proprietary operation from
//! an address alone. Every accepted instruction replaces its destination value.
use super::decoded::plain;
use super::Error;
use std::collections::BTreeMap;
use thumb_asm::isa::{decode_at, Operand, Reg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Unknown,
    Literal(u32),
    Stack,
    IncomingPointer,
    Byte(u32, u8),
    Agid(u32),
    Word,
    Pointer,
    Biased,
    Quarter,
    Aligned,
}

pub(super) struct ScratchFlow {
    registers: [Value; 16],
    stack: BTreeMap<u32, (u32, Value)>,
}
impl ScratchFlow {
    pub fn new() -> Self {
        let mut registers = [Value::Unknown; 16];
        registers[13] = Value::Stack;
        registers[4..8].fill(Value::IncomingPointer);
        Self {
            registers,
            stack: BTreeMap::new(),
        }
    }
    pub fn byte_load(&self, image: &[u8], pc: usize) -> Option<(u8, u32)> {
        let ins = decode_at(image, pc)?;
        let (Some(Operand::Reg(dest)), Some(Operand::Mem(memory))) =
            (ins.operands.get(0), ins.operands.get(1))
        else {
            return None;
        };
        if ins.mnemonic != "ldrb" || !plain(memory) || memory.offset != 0 {
            return None;
        }
        let Value::Literal(address) = self.registers[usize::from(memory.base.num())] else {
            return None;
        };
        Some((dest.num(), address))
    }
    pub fn complete(&self) -> bool {
        self.stack.iter().any(|(offset, value)| {
            *value == (4, Value::Aligned)
                && matches!(self.stack.get(&(offset + 4)), Some((1, Value::Agid(_))))
        })
    }
    fn store(&mut self, offset: u32, size: u32, value: Value) {
        // Any overlapping write invalidates a previously established object.
        self.stack.retain(|at, old| {
            let old_size = old.0;
            *at + old_size <= offset || *at >= offset + size
        });
        self.stack.insert(offset, (size, value));
    }
    pub fn step(&mut self, image: &[u8], pc: usize) -> Result<(), Error> {
        let ins = decode_at(image, pc).ok_or(Error::InvalidContract)?;
        if ins.len() != 2 || ins.cond.is_some() || ins.is_branch() || ins.writes_pc() {
            return Err(Error::InvalidContract);
        }
        let first = ins.operands.get(0);
        let second = ins.operands.get(1);
        let third = ins.operands.get(2);
        match (ins.mnemonic, first, second) {
            ("ldr" | "ldrb", Some(Operand::Reg(dest)), Some(Operand::Mem(memory)))
                if plain(memory) =>
            {
                let source = self.registers[usize::from(memory.base.num())];
                let value = if ins.mnemonic == "ldr" && memory.base == Reg::PC {
                    Value::Literal(
                        thumb_asm::analysis::literal_value(image, pc).ok_or(Error::Truncated)?,
                    )
                } else if ins.mnemonic == "ldrb" {
                    match source {
                        Value::Literal(base) => Value::Byte(
                            base,
                            u8::try_from(memory.offset).map_err(|_| Error::InvalidContract)?,
                        ),
                        _ => Value::Unknown,
                    }
                } else if memory.offset == 0 {
                    match source {
                        Value::IncomingPointer => Value::Word,
                        Value::Literal(cell) if (0x02000000..0x02002000).contains(&cell) => {
                            Value::Word
                        }
                        _ => Value::Unknown,
                    }
                } else {
                    Value::Unknown
                };
                self.define(dest, value)?;
            }
            ("str" | "strb", Some(Operand::Reg(source)), Some(Operand::Mem(memory)))
                if plain(memory) =>
            {
                if self.registers[usize::from(memory.base.num())] != Value::Stack {
                    return Err(Error::InvalidContract);
                }
                let size = if ins.mnemonic == "str" { 4 } else { 1 };
                self.store(
                    memory.offset,
                    size,
                    self.registers[usize::from(source.num())],
                );
            }
            ("mov", Some(Operand::Reg(dest)), Some(Operand::Reg(source))) if third.is_none() => {
                self.define(dest, self.registers[usize::from(source.num())])?
            }
            ("mov", Some(Operand::Reg(dest)), Some(Operand::Imm(value))) if third.is_none() => self
                .define(
                    dest,
                    Value::Literal(u32::try_from(value).map_err(|_| Error::InvalidContract)?),
                )?,
            ("lsr" | "lsl", Some(Operand::Reg(dest)), Some(Operand::Reg(source))) => {
                let Some(Operand::Imm(amount)) = third else {
                    return Err(Error::InvalidContract);
                };
                let value = match (
                    ins.mnemonic,
                    self.registers[usize::from(source.num())],
                    amount,
                ) {
                    ("lsr", Value::Byte(base, 10), 6)
                        if (0x02000000..0x02002000).contains(&base) =>
                    {
                        Value::Agid(base)
                    }
                    ("lsr", Value::Biased, 2) => Value::Quarter,
                    ("lsl", Value::Quarter, 2) => Value::Aligned,
                    _ => Value::Unknown,
                };
                self.define(dest, value)?;
            }
            ("add", Some(Operand::Reg(dest)), Some(right)) => {
                let (left, right) = match third {
                    Some(last) => (self.operand(right)?, self.operand(last)?),
                    None => (
                        self.registers[usize::from(dest.num())],
                        self.operand(right)?,
                    ),
                };
                let value = match (left, right) {
                    (Value::Literal(a), Value::Literal(b)) => {
                        Value::Literal(a.checked_add(b).ok_or(Error::InvalidContract)?)
                    }
                    (Value::Word, Value::Literal(_)) | (Value::Literal(_), Value::Word) => {
                        Value::Pointer
                    }
                    (Value::Pointer, Value::Literal(3)) => Value::Biased,
                    _ => Value::Unknown,
                };
                self.define(dest, value)?;
            }
            _ => return Err(Error::InvalidContract),
        }
        Ok(())
    }
    fn operand(&self, operand: Operand) -> Result<Value, Error> {
        match operand {
            Operand::Reg(reg) => Ok(self.registers[usize::from(reg.num())]),
            Operand::Imm(value) => Ok(Value::Literal(
                u32::try_from(value).map_err(|_| Error::InvalidContract)?,
            )),
            _ => Err(Error::InvalidContract),
        }
    }
    fn define(&mut self, register: Reg, value: Value) -> Result<(), Error> {
        if register.num() >= 13 {
            return Err(Error::InvalidContract);
        }
        self.registers[usize::from(register.num())] = value;
        Ok(())
    }
}

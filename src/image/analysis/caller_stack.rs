//! Explicit stack-pointer provenance over thumb-asm's decoded operands.
use super::Error;
use std::collections::BTreeMap;
use thumb_asm::isa::{AddrMode, Insn, Mem, Operand};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Alias {
    #[default]
    Plain,
    At(i32),
    /// Precision was lost; a later store must not silently become unchecked.
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct StackFlow {
    aliases: [Alias; 16],
    /// Byte provenance retains pointer spills, including partial overwrites.
    bytes: BTreeMap<i32, Alias>,
}

impl StackFlow {
    fn address(&self, mem: Mem, scalars: &[Option<u32>; 16]) -> Result<Alias, Error> {
        let base = self.aliases[usize::from(mem.base.num())];
        if base == Alias::Plain {
            return Ok(base);
        }
        if mem.mode != AddrMode::Offset {
            return Err(Error::InvalidContract);
        }
        let index = match mem.index {
            None => Some(0),
            Some((reg, None)) => scalars[usize::from(reg.num())],
            Some(_) => None,
        };
        let Some(offset) = index
            .and_then(|v| v.checked_add(mem.offset))
            .and_then(|v| i32::try_from(v).ok())
        else {
            return Ok(Alias::Unknown);
        };
        Ok(match base {
            Alias::At(base) => base
                .checked_add(if mem.add { offset } else { -offset })
                .map_or(Alias::Unknown, Alias::At),
            other => other,
        })
    }

    fn store(
        &mut self,
        address: Alias,
        width: i32,
        value: Alias,
        protected: &[i32],
    ) -> Result<(), Error> {
        match address {
            Alias::Plain => Ok(()),
            Alias::Unknown => Err(Error::InvalidContract),
            Alias::At(start) => {
                let end = start.checked_add(width).ok_or(Error::InvalidContract)?;
                if protected.iter().any(|slot| start < slot + 4 && end > *slot) {
                    return Err(Error::InvalidContract);
                }
                for byte in start..end {
                    if value == Alias::Plain {
                        self.bytes.remove(&byte);
                    } else {
                        self.bytes.insert(byte, value);
                    }
                }
                Ok(())
            }
        }
    }

    fn load(&self, address: Alias, width: i32) -> Alias {
        let Alias::At(start) = address else {
            return if address == Alias::Unknown {
                Alias::Unknown
            } else {
                Alias::Plain
            };
        };
        let values: Vec<_> = (start..start + width)
            .map(|at| self.bytes.get(&at).copied().unwrap_or_default())
            .collect();
        if values.iter().all(|value| *value == Alias::Plain) {
            Alias::Plain
        } else if width == 4 && values.iter().all(|value| *value == values[0]) {
            values[0]
        } else {
            Alias::Unknown
        }
    }

    fn operand(&self, operand: Option<Operand>) -> Alias {
        match operand {
            Some(Operand::Reg(reg) | Operand::RegShifted(reg, _)) => {
                self.aliases[usize::from(reg.num())]
            }
            _ => Alias::Plain,
        }
    }

    pub(super) fn observe(
        &mut self,
        ins: &Insn,
        depth: i32,
        scalars: &[Option<u32>; 16],
        protected: &[i32],
        call_clobbers: u16,
    ) -> Result<(), Error> {
        self.aliases[13] = Alias::At(-depth);
        if ins.is_call() {
            for (reg, alias) in self.aliases.iter_mut().enumerate() {
                if call_clobbers & (1 << reg) != 0 {
                    *alias = Alias::Plain;
                }
            }
            return Ok(());
        }
        if matches!(ins.mnemonic, "push" | "pop") {
            let Some(Operand::RegList(mask)) = ins.operands.get(0) else {
                return Err(Error::InvalidContract);
            };
            let mut slot = if ins.mnemonic == "push" {
                -depth - mask.count_ones() as i32 * 4
            } else {
                -depth
            };
            for reg in 0..16 {
                if mask & (1 << reg) == 0 {
                    continue;
                }
                if ins.mnemonic == "push" {
                    // A native save is the protected slot's legitimate initialization.
                    self.store(
                        Alias::At(slot),
                        4,
                        self.aliases[reg],
                        if depth == 0 { &[] } else { protected },
                    )?;
                } else {
                    self.aliases[reg] = self.load(Alias::At(slot), 4);
                }
                slot += 4;
            }
            return Ok(());
        }
        if matches!(ins.mnemonic, "stm" | "stmia" | "ldm" | "ldmia") {
            let (base, writeback) = match ins.operands.get(0) {
                Some(Operand::Reg(reg)) => (reg.num(), false),
                Some(Operand::Text(text)) => (
                    text.strip_prefix('r')
                        .and_then(|s| s.strip_suffix('!'))
                        .and_then(|s| s.parse::<u8>().ok())
                        .filter(|r| *r < 13)
                        .ok_or(Error::InvalidContract)?,
                    true,
                ),
                _ => return Err(Error::InvalidContract),
            };
            let Some(Operand::RegList(mask)) = ins.operands.get(1) else {
                return Err(Error::InvalidContract);
            };
            let mut address = self.aliases[usize::from(base)];
            for reg in 0..16 {
                if mask & (1 << reg) == 0 {
                    continue;
                }
                if ins.mnemonic.starts_with("stm") {
                    self.store(address, 4, self.aliases[reg], protected)?;
                } else {
                    self.aliases[reg] = self.load(address, 4);
                }
                if let Alias::At(at) = address {
                    address = at.checked_add(4).map_or(Alias::Unknown, Alias::At);
                }
            }
            if writeback {
                self.aliases[usize::from(base)] = address;
            }
            return Ok(());
        }
        if let (Some(Operand::Reg(reg)), Some(Operand::Mem(mem))) =
            (ins.operands.get(0), ins.operands.get(1))
        {
            let address = self.address(mem, scalars)?;
            let width = match ins.mnemonic {
                "str" | "ldr" => 4,
                "strh" | "ldrh" | "ldrsh" => 2,
                "strb" | "ldrb" | "ldrsb" => 1,
                _ => return Err(Error::InvalidContract),
            };
            if ins.mnemonic.starts_with("str") {
                self.store(
                    address,
                    width,
                    self.aliases[usize::from(reg.num())],
                    protected,
                )?;
            } else {
                self.aliases[usize::from(reg.num())] = self.load(address, width);
            }
            return Ok(());
        }
        if matches!(ins.mnemonic, "cmp" | "cmn" | "tst" | "teq" | "b" | "nop") {
            return Ok(());
        }
        let Some(Operand::Reg(dest)) = ins.operands.get(0) else {
            return Ok(());
        };
        let (left, right) = if ins.operands.get(2).is_some() {
            (ins.operands.get(1), ins.operands.get(2))
        } else {
            (Some(Operand::Reg(dest)), ins.operands.get(1))
        };
        let a = self.operand(left);
        let b = self.operand(right);
        let scalar = |op| super::caller::scalar_operand(op, scalars);
        let value = match ins.mnemonic {
            "mov" => self.operand(ins.operands.get(1)),
            "add" | "sub" => {
                let (alias, offset) = if a != Alias::Plain {
                    (a, scalar(right))
                } else if ins.mnemonic == "add" && b != Alias::Plain {
                    (b, scalar(left))
                } else {
                    (Alias::Plain, None)
                };
                match (alias, offset.and_then(|v| i32::try_from(v).ok())) {
                    (Alias::Plain, _) if b == Alias::Plain => Alias::Plain,
                    (Alias::At(base), Some(offset)) => base
                        .checked_add(if ins.mnemonic == "sub" {
                            -offset
                        } else {
                            offset
                        })
                        .map_or(Alias::Unknown, Alias::At),
                    _ => Alias::Unknown,
                }
            }
            // Nonlinear transformations retain taint even when their exact address is unknown.
            _ if a != Alias::Plain || b != Alias::Plain => Alias::Unknown,
            _ => Alias::Plain,
        };
        self.aliases[usize::from(dest.num())] = value;
        Ok(())
    }
}

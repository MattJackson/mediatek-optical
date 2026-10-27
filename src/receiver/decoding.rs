//! Bounded Thumb argument tracing for receiver AES calls.
//!
//! A nearby MOV #16 is not argument evidence. Trace each supported instruction
//! from supplied incoming register facts to the actual call. Conditional branches,
//! stores, unknown instructions and overflow stop analysis. Handler ownership
//! and incoming facts remain separate obligations of the control-flow analyzer.

/// Values sufficient to distinguish staging addresses from scratch outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// No established value; never usable as an AES argument.
    Unknown,
    /// An exact immediate or literal value.
    Constant(u32),
    /// Byte offset relative to the upload staging buffer.
    Staging(u32),
    /// Byte offset relative to the current stack pointer.
    Stack(u32),
    /// Pointer loaded from a specific RAM cell, before assigning it a staging
    /// role. Keeping provenance avoids guessing that every RAM load is staging.
    Loaded {
        /// Address of the pointer cell.
        cell: u32,
        /// Constant offset added after loading the pointer.
        offset: u32,
    },
}

impl Value {
    fn add(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Constant(a), Self::Constant(b)) => Some(Self::Constant(a.checked_add(b)?)),
            (Self::Staging(a), Self::Constant(b)) | (Self::Constant(b), Self::Staging(a)) => {
                Some(Self::Staging(a.checked_add(b)?))
            }
            (Self::Stack(a), Self::Constant(b)) | (Self::Constant(b), Self::Stack(a)) => {
                Some(Self::Stack(a.checked_add(b)?))
            }
            (Self::Loaded { cell, offset }, Self::Constant(b))
            | (Self::Constant(b), Self::Loaded { cell, offset }) => Some(Self::Loaded {
                cell,
                offset: offset.checked_add(b)?,
            }),
            _ => None,
        }
    }
}

/// Proven arguments at a direct Thumb BL call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    /// Instruction address of the call, for retained evidence and revalidation.
    pub address: u32,
    /// Exact target, which still requires independent AES-routine verification.
    pub target: u32,
    /// Source of the input blocks.
    pub source: Value,
    /// Distinguishes scratch decoding from in-place staging decoding.
    pub destination: Value,
    /// Exact length, established through data flow into r2.
    pub length: u32,
    /// Preserved r3 evidence; programming wrappers use it to select their mode.
    pub fourth_argument: Value,
}

fn word(bytes: &[u8], base: u32, address: u32) -> Option<u16> {
    let offset = usize::try_from(address.checked_sub(base)?).ok()?;
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// Decode the legacy Thumb BL used by the audited MT19xx receivers.
/// BLX and malformed/truncated instructions deliberately do not match.
pub fn branch_link(bytes: &[u8], base: u32, address: u32) -> Option<u32> {
    let offset = usize::try_from(address.checked_sub(base)?).ok()?;
    let ins =
        thumb_asm::isa::decode_at_with(bytes, offset, address, thumb_asm::isa::Target::Union)?;
    (ins.mnemonic == "bl" && ins.is_call()).then(|| ins.branch_target())?
}

/// Trace an argument block and direct trampolines, at most 32 instructions.
/// `load` supplies established values for nonliteral memory reads. It must not
/// infer staging pointers from model strings or the target firmware identity.
pub fn trace_call(
    bytes: &[u8],
    base: u32,
    start: u32,
    mut registers: [Value; 8],
    mut load: impl FnMut(Value) -> Option<Value>,
) -> Option<Call> {
    if base & 1 != 0 || start & 1 != 0 {
        return None;
    }
    let mut address = start;
    let mut visited = [u32::MAX; 32];
    for step in 0..32 {
        if visited[..step].contains(&address) {
            return None;
        }
        visited[step] = address;
        use thumb_asm::isa::{AddrMode, Operand, Reg};
        let offset = usize::try_from(address.checked_sub(base)?).ok()?;
        let ins =
            thumb_asm::isa::decode_at_with(bytes, offset, address, thumb_asm::isa::Target::Union)?;
        if let Some(target) = branch_link(bytes, base, address) {
            let Value::Constant(length) = registers[2] else {
                return None;
            };
            if length == 0 || length % 16 != 0 || registers[..2].contains(&Value::Unknown) {
                return None;
            }
            return Some(Call {
                address,
                target,
                source: registers[0],
                destination: registers[1],
                length,
                fourth_argument: registers[3],
            });
        }
        if ins.mnemonic == "b" && ins.cond.is_none() {
            address = ins.branch_target()?;
            continue;
        }
        if ins.is_branch() || ins.writes_pc() || ins.cond.is_some() {
            return None;
        }
        let Some(Operand::Reg(dest)) = ins.operands.get(0) else {
            return None;
        };
        if dest.num() >= 8 {
            return None;
        }
        let d = usize::from(dest.num());
        let operand = |value: Operand| match value {
            Operand::Reg(reg) if reg.num() < 8 => Some(registers[usize::from(reg.num())]),
            Operand::Reg(Reg::SP) => Some(Value::Stack(0)),
            Operand::Imm(value) => Some(Value::Constant(u32::try_from(value).ok()?)),
            _ => None,
        };
        match (ins.mnemonic, ins.operands.get(1), ins.operands.get(2)) {
            ("mov", Some(source), None) => registers[d] = operand(source)?,
            ("lsl", Some(Operand::Reg(source)), Some(Operand::Imm(shift))) if source.num() < 8 => {
                let Value::Constant(value) = registers[usize::from(source.num())] else {
                    return None;
                };
                let shift = u32::try_from(shift).ok()?;
                registers[d] =
                    Value::Constant(u32::try_from(u64::from(value).checked_shl(shift)?).ok()?);
            }
            ("add", Some(source), third) => {
                let (left, right) = if let Some(right) = third {
                    (operand(source)?, operand(right)?)
                } else {
                    (registers[d], operand(source)?)
                };
                registers[d] = left.add(right)?;
            }
            ("ldr", Some(Operand::Mem(memory)), target)
                if memory.mode == AddrMode::Offset && memory.index.is_none() && memory.add =>
            {
                if memory.base == Reg::PC {
                    let Some(Operand::Target(literal)) = target else {
                        return None;
                    };
                    let low = u32::from(word(bytes, base, literal)?);
                    let high = u32::from(word(bytes, base, literal.checked_add(2)?)?);
                    registers[d] = Value::Constant(low | high << 16);
                } else {
                    registers[d] = load(
                        operand(Operand::Reg(memory.base))?.add(Value::Constant(memory.offset))?,
                    )?;
                }
            }
            _ => return None,
        }
        address = address.checked_add(ins.len() as u32)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // INTM application's actual header setup, including its PC-relative literal.
    fn header() -> Vec<u8> {
        let mut bytes = vec![0; 0x370];
        bytes[..18].copy_from_slice(&[
            0xda, 0x48, 0x03, 0x23, 0x00, 0x68, 0x1b, 0x03, 0x10, 0x22, 0xc0, 0x18, 0x05, 0xa9,
            0xfd, 0xf7, 0xc9, 0xfd,
        ]);
        bytes[0x36c..0x370].copy_from_slice(&0x0200_0c34u32.to_le_bytes());
        bytes
    }

    fn inspect(bytes: &[u8]) -> Option<Call> {
        trace_call(bytes, 0x9d480, 0x9d480, [Value::Unknown; 8], |address| {
            (address == Value::Constant(0x0200_0c34)).then_some(Value::Staging(0))
        })
    }

    #[test]
    fn actual_header_arguments_are_scratch_not_in_place() {
        let call = inspect(&header()).unwrap();
        assert_eq!(
            call,
            Call {
                address: 0x9d48e,
                target: 0x9b024,
                source: Value::Staging(0x3000),
                destination: Value::Stack(0x14),
                length: 16,
                fourth_argument: Value::Constant(0x3000),
            }
        );
    }

    #[test]
    fn operand_changes_cannot_retain_the_same_proof() {
        let bytes = header();
        let original = inspect(&bytes).unwrap();
        for at in [0, 2, 4, 6, 8, 10, 12, 14, 16, 0x36c] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert_ne!(inspect(&changed), Some(original), "mutation at {at:#x}");
        }
    }

    #[test]
    fn truncated_literals_unknown_memory_and_control_flow_fail_closed() {
        let bytes = header();
        assert!(inspect(&bytes[..0x36f]).is_none());
        assert!(trace_call(&bytes, 0x9d480, 0x9d480, [Value::Unknown; 8], |_| None).is_none());
        let mut branch = bytes;
        branch[2..4].copy_from_slice(&0xe000u16.to_le_bytes());
        assert!(inspect(&branch).is_none());
        branch[..2].copy_from_slice(&0xe7feu16.to_le_bytes());
        assert!(inspect(&branch).is_none());
        assert!(trace_call(
            &branch,
            u32::MAX - 1,
            u32::MAX - 1,
            [Value::Unknown; 8],
            |_| None
        )
        .is_none());
    }
}

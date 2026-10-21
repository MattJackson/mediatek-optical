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
    let first = word(bytes, base, address)?;
    let second = word(bytes, base, address.checked_add(2)?)?;
    if first & 0xf800 != 0xf000 || second & 0xf800 != 0xf800 {
        return None;
    }
    let encoded = (u32::from(first & 2047) << 12) | (u32::from(second & 2047) << 1);
    let delta = ((encoded as i32) << 9) >> 9;
    u32::try_from(i64::from(address) + 4 + i64::from(delta)).ok()
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
        let op = word(bytes, base, address)?;
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
        let d = usize::from(op & 7);
        let s = usize::from((op >> 3) & 7);
        if op & 0xf800 == 0xe000 {
            let delta = ((i32::from(op & 0x7ff) << 21) >> 20) as i64;
            address = u32::try_from(i64::from(address) + 4 + delta).ok()?;
            continue;
        } else if op & 0xf800 == 0x4800 {
            let literal = (address.checked_add(4)? & !3).checked_add(u32::from(op & 255) * 4)?;
            let low = u32::from(word(bytes, base, literal)?);
            let high = u32::from(word(bytes, base, literal.checked_add(2)?)?);
            registers[usize::from((op >> 8) & 7)] = Value::Constant(low | high << 16);
        } else if op & 0xf800 == 0x2000 {
            registers[usize::from((op >> 8) & 7)] = Value::Constant(u32::from(op & 255));
        } else if op & 0xf800 == 0x0000 {
            let shift = u32::from((op >> 6) & 31);
            registers[d] = if shift == 0 {
                registers[s]
            } else if let Value::Constant(value) = registers[s] {
                Value::Constant(u32::try_from(u64::from(value) << shift).ok()?)
            } else {
                return None;
            };
        } else if op & 0xfe00 == 0x1800 {
            registers[d] = registers[s].add(registers[usize::from((op >> 6) & 7)])?;
        } else if op & 0xfe00 == 0x1c00 {
            registers[d] = registers[s].add(Value::Constant(u32::from((op >> 6) & 7)))?;
        } else if op & 0xf800 == 0x3000 {
            let d = usize::from((op >> 8) & 7);
            registers[d] = registers[d].add(Value::Constant(u32::from(op & 255)))?;
        } else if op & 0xf800 == 0x6800 {
            let pointer = registers[s].add(Value::Constant(u32::from((op >> 6) & 31) * 4))?;
            registers[d] = load(pointer)?;
        } else if op & 0xf800 == 0xa800 {
            registers[usize::from((op >> 8) & 7)] = Value::Stack(u32::from(op & 255) * 4);
        } else {
            return None;
        }
        address = address.checked_add(2)?;
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

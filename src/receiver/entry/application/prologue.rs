//! Fixed pre-table instruction grammar. No instruction outside this grammar
//! is interpreted, and no command or model selects a fallback.
use super::{Candidate, ModeBufferGuard, Window, MODE_GUARD_BYTES};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    Unknown,
    Constant(u32),
    Cdb(u32),
    ByteOne,
    ShiftedMode,
    Mode,
    Buffer,
    GuardResult,
}

/// Operand-bound application prelude, including an optional complete guard.
/// Dispatcher ownership, flag stores and completion remain separate proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prologue {
    /// First literal load or PUSH of the handler.
    pub start: u32,
    /// RAM address supplying the CDB.
    pub cdb_address: u32,
    /// Registers carrying that CDB pointer at the table.
    pub cdb_registers: u8,
    /// Immediate/literal values established by the fixed prelude grammar.
    pub constants: [Option<u32>; 8],
    /// Complete mode/buffer guard helper address, when called.
    pub guard: Option<u32>,
    /// Branch taken on a zero guard result. Its completion is not inferred.
    pub rejection: Option<u32>,
    /// Stack allocation restored by the entry epilogue.
    pub stack_bytes: u16,
}

fn parse(w: &Window<'_>, start: u32, end: u32) -> Option<Prologue> {
    if w.word(start)? != 0xb5f0 && w.literal(start).is_none() {
        return None;
    }
    let mut values = [Value::Unknown; 8];
    let mut at = start;
    let mut pushed = false;
    let mut stack = false;
    let mut stack_bytes = 0;
    let mut cdb = None;
    let mut guard = None;
    let mut rejection = None;
    let mut compared = false;
    while at < end {
        let op = w.word(at)?;
        if compared && op & 0xff00 != 0xd000 {
            return None;
        }
        if op == 0xb5f0 && !pushed {
            pushed = true;
        } else if matches!(op, 0xb08f | 0xb091) && pushed && !stack {
            stack = true;
            stack_bytes = (op & 127) * 4;
        } else if op & 0xf800 == 0x4800 {
            if !pushed && (at != start || w.word(at.checked_add(2)?)? != 0xb5f0) {
                return None;
            }
            let (reg, value) = w.literal(at)?;
            values[reg as usize] = Value::Constant(value);
        } else if op & 0xf800 == 0x7800 && pushed {
            let base = ((op >> 3) & 7) as usize;
            let dest = (op & 7) as usize;
            let offset = (op >> 6) & 31;
            let address = match values[base] {
                Value::Cdb(address) | Value::Constant(address)
                    if (0x0200_0000..0x0201_0000).contains(&address) =>
                {
                    address
                }
                _ => return None,
            };
            if cdb.is_some_and(|previous| previous != address) {
                return None;
            }
            cdb = Some(address);
            values[base] = Value::Cdb(address);
            values[dest] = match offset {
                1 => Value::ByteOne,
                2 => Value::Buffer,
                _ => return None,
            };
        } else if op & 0xf800 == 0x2000 && pushed {
            values[((op >> 8) & 7) as usize] = Value::Constant(u32::from(op & 255));
        } else if op & 0xf800 == 0 || op & 0xf800 == 0x0800 {
            let source = values[((op >> 3) & 7) as usize];
            let shift = (op >> 6) & 31;
            let left = op & 0xf800 == 0;
            values[(op & 7) as usize] = match (source, shift, left) {
                (value, 0, true) => value,
                (Value::ByteOne, 27, true) => Value::ShiftedMode,
                (Value::ShiftedMode, 27, false) => Value::Mode,
                (Value::Constant(value), shift, true) => Value::Constant(value << shift),
                _ => return None,
            };
        } else if op & 0xf800 == 0xf000 && guard.is_none() {
            if values[0] != Value::Mode || values[1] != Value::Buffer {
                return None;
            }
            let second = w.word(at.checked_add(2)?)?;
            if second & 0xf800 != 0xf800 {
                return None;
            }
            let delta = (u32::from(op & 2047) << 12) | (u32::from(second & 2047) << 1);
            let delta = ((delta as i32) << 9) >> 9;
            let target = u32::try_from(i64::from(at) + 4 + i64::from(delta)).ok()?;
            ModeBufferGuard::inspect(w.bytes(target, MODE_GUARD_BYTES)?)?;
            guard = Some(target);
            // The complete matched helper writes only r0/r2 and flags, while
            // leaving r1/r3 and callee-saved registers unchanged.
            values[0] = Value::GuardResult;
            values[2] = Value::Unknown;
            at = at.checked_add(2)?;
        } else if op == 0x2800 && values[0] == Value::GuardResult && !compared {
            compared = true;
        } else if op & 0xff00 == 0xd000 && compared && rejection.is_none() {
            rejection = Some(w.conditional(at, 0xd000)?);
            compared = false;
        } else {
            return None;
        }
        at = at.checked_add(2)?;
    }
    if at != end
        || !pushed
        || !stack
        || compared
        || guard.is_some() != rejection.is_some()
        || values[3] != Value::Mode
    {
        return None;
    }
    let cdb_address = cdb?;
    let mut cdb_registers = 0;
    let mut constants = [None; 8];
    for (reg, value) in values.iter().enumerate() {
        match value {
            Value::Cdb(address) if *address == cdb_address => cdb_registers |= 1 << reg,
            Value::Constant(value) => constants[reg] = Some(*value),
            _ => (),
        }
    }
    Some(Prologue {
        start,
        cdb_address,
        cdb_registers,
        constants,
        guard,
        rejection,
        stack_bytes,
    })
}

/// Bind a complete fixed instruction prelude to an already identified table.
/// Guard helpers must be present in the supplied window and match completely.
/// The table decoder's own helper, entry stores and rejection completion still
/// require their separate evidence; this function never authorizes a write.
pub fn inspect_prologue(bytes: &[u8], address: u32, table: &Candidate) -> Option<Prologue> {
    let w = Window {
        bytes,
        base: address,
    };
    let end = if table.helper.is_some() {
        table.table
    } else {
        table.table.checked_sub(6)?
    };
    let mut result = None;
    for distance in (20..=64).step_by(2) {
        let Some(start) = end.checked_sub(distance) else {
            continue;
        };
        // A literal immediately before PUSH belongs to this prelude too. Do
        // not accept a truncated prefix that loses the CDB pointer binding.
        if let Some(found) = parse(&w, start, end) {
            if result.is_some() {
                return None;
            }
            result = Some(found);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1() -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0xff; 0x1800];
        for (address, hex) in [
            (0x9ba38, "0122022804d0052805d00a280ad108e08f2907d105e0042903d0052901d0062900d1002210007047"),
            (0x9ca02, "564bf0b599788fb05878c006c00efff712f80126634f002808d059781800cb06db0e042100255f4c092b00d3f9e3"),
            (0x9ca30, "5b007b449b885b009f44ac0508002900ac052f001401ee02ac057104"),
            (0x9ca4c, "574a93691b091b019361437adb0702d0936933439361437a9b0703d59369022423439361437a5b0702d5936919439161407a000703d590690821084390610fb0f0bd"),
            (0x9cb5c, "f40c0002"),
            (0x9cba4, "220c0002380c0002"),
            (0x9cbac, "40200004"),
        ] {
            for i in (0..hex.len()).step_by(2) {
                bytes[address - 0x9ba00 + i / 2] = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
            }
        }
        bytes
    }

    fn table() -> Candidate {
        Candidate {
            table: 0x9ca30,
            entry: 0x9ca4c,
            mode1_target: 0x9ca4c,
            mode6_target: 0x9d018,
            helper: None,
        }
    }

    #[test]
    fn real_v1_prologue_binds_guard_arguments_and_preloaded_constants() {
        let bytes = v1();
        let found = inspect_prologue(&bytes, 0x9ba00, &table()).unwrap();
        assert_eq!(found.start, 0x9ca02);
        assert_eq!(found.cdb_address, 0x02000cf4);
        assert_eq!(found.guard, Some(0x9ba38));
        assert_eq!(found.rejection, Some(0x9ca2e));
        assert_eq!(found.constants[1], Some(4));
        assert_eq!(found.constants[5], Some(0));
        assert_eq!(found.constants[6], Some(1));
        assert_ne!(found.cdb_registers & 1, 0);
        for address in [0x9ca06, 0x9ca0c, 0x9ca10, 0x9ca18, 0x9ca1b, 0x9cb5f] {
            let mut changed = bytes.clone();
            changed[address - 0x9ba00] ^= 1;
            assert!(
                inspect_prologue(&changed, 0x9ba00, &table()).is_none(),
                "{address:x}"
            );
        }
        for offset in 0..MODE_GUARD_BYTES {
            let mut changed = bytes.clone();
            changed[0x38 + offset] ^= 1;
            assert!(inspect_prologue(&changed, 0x9ba00, &table()).is_none());
        }
        assert!(inspect_prologue(&bytes[..0x100], 0x9ba00, &table()).is_none());
        assert!(inspect_prologue(&bytes, u32::MAX - 4, &table()).is_none());
    }

    #[test]
    fn real_v1_flag_body_binds_all_stores_branches_and_preloaded_constants() {
        let bytes = v1();
        let prelude = inspect_prologue(&bytes, 0x9ba00, &table()).unwrap();
        let found = super::super::inspect_flags(&bytes, 0x9ba00, &table(), &prelude).unwrap();
        assert_eq!(found.end, 0x9ca8e);
        for address in [
            0x9ca5a, 0x9ca60, 0x9ca66, 0x9ca6e, 0x9ca74, 0x9ca7a, 0x9ca80, 0x9ca88, 0x9ca8c,
        ] {
            let mut changed = bytes.clone();
            changed[address - 0x9ba00] ^= 1;
            assert!(
                super::super::inspect_flags(&changed, 0x9ba00, &table(), &prelude).is_none(),
                "{address:x}"
            );
        }
        let mut invented = prelude.clone();
        invented.constants[6] = Some(2);
        assert!(super::super::inspect_flags(&bytes, 0x9ba00, &table(), &invented).is_none());
        // A valid-looking OR cannot license destroying the MMIO base or CDB
        // pointer while constructing the bit-one constant.
        // Nor may it overwrite the work register just loaded from MMIO (r3),
        // which would discard the read-modify-write.
        for register in [0u16, 2, 3] {
            let mut changed = bytes.clone();
            changed[0x106a..0x106c].copy_from_slice(&(0x2002 | (register << 8)).to_le_bytes());
            changed[0x106c..0x106e].copy_from_slice(&(0x4303 | (register << 3)).to_le_bytes());
            assert!(super::super::inspect_flags(&changed, 0x9ba00, &table(), &prelude).is_none());
        }
    }

    #[test]
    fn mode_six_cdb_reload_cannot_clobber_a_prelude_constant() {
        // Mode-six target: LDR rC,=CDB; LDRB r3,[rC,#2]; CMP r3,#0x67; BNE; B entry.
        let guarded = |register: u16| {
            let mut bytes = v1();
            let put = |bytes: &mut std::vec::Vec<u8>, at: usize, op: u16| {
                bytes[at - 0x9ba00..at - 0x9ba00 + 2].copy_from_slice(&op.to_le_bytes());
            };
            put(&mut bytes, 0x9d018, 0x4800 | register << 8 | 2);
            put(&mut bytes, 0x9d01a, 0x7800 | 2 << 6 | register << 3 | 3);
            put(&mut bytes, 0x9d01c, 0x2b67);
            put(&mut bytes, 0x9d01e, 0xd100);
            let delta = (0x9ca4ci64 - (0x9d020 + 4)) / 2;
            put(&mut bytes, 0x9d020, 0xe000 | (delta & 0x7ff) as u16);
            bytes[0x9d024 - 0x9ba00..0x9d028 - 0x9ba00]
                .copy_from_slice(&0x02000cf4u32.to_le_bytes());
            let prelude = inspect_prologue(&bytes, 0x9ba00, &table()).unwrap();
            super::super::inspect_mode_six(&bytes, 0x9ba00, &table(), &prelude)
        };
        // Control: a register without a prelude constant is accepted.
        assert!(matches!(
            guarded(2),
            Some(super::super::ModeSix::Entry67 { .. })
        ));
        // r6 and r1 hold prelude constants used by the flag body.
        assert!(guarded(6).is_none());
        assert!(guarded(1).is_none());
    }
}

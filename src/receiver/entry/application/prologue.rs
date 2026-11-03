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
#[path = "prologue_tests.rs"]
mod tests;

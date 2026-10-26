//! Bind a saved-state slot to the command frame and common restoring return.
use super::{word, AcceptanceTail, Selection};
use crate::receiver::entry::application;

/// Matched save/store/load/restore pairing within one application command frame.
/// Intervening control flow and possible overwrites still need independent
/// validation; this record alone is not an executable receiver contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSlotEvidence {
    /// Beginning of the checked application prelude.
    pub prologue: u32,
    /// Bytes allocated by that prelude and restored by the common epilogue.
    pub stack_bytes: u16,
    /// Byte offset of the paired saved-state word within that allocation.
    pub slot: u16,
    /// Native save-state call immediately before selection.
    pub save_call: u32,
    /// Store of that returned state into the frame.
    pub store: u32,
    /// Restore-state call after the programming/skip paths converge.
    pub restore_call: u32,
    /// Common stack-restoring epilogue reached after the restore call.
    pub epilogue: u32,
    /// Checked unconditional branches connecting restore to that epilogue.
    pub return_path: Vec<u32>,
}

// Legacy Thumb BLX immediate, with the ARM destination aligned to a word.
// This deliberately does not broaden the BL-only argument tracer.
pub(super) fn blx(bytes: &[u8], base: u32, address: u32) -> Option<u32> {
    let first = word(bytes, base, address)?;
    let second = word(bytes, base, address.checked_add(2)?)?;
    if first & 0xf800 != 0xf000 || second & 0xf801 != 0xe800 {
        return None;
    }
    let encoded = (u32::from(first & 2047) << 12) | (u32::from(second & 2047) << 1);
    let delta = ((encoded as i32) << 9) >> 9;
    u32::try_from(i64::from(address.checked_add(4)? & !3) + i64::from(delta)).ok()
}

pub(crate) fn inspect_state_slot(
    bytes: &[u8],
    base: u32,
    selection: &Selection,
    tail: &AcceptanceTail,
) -> Option<StateSlotEvidence> {
    if super::inspect_selection(bytes, base, selection.address)? != *selection {
        return None;
    }
    let candidate = application::inspect(bytes, base)?;
    let prelude = application::inspect_prologue(bytes, base, &candidate)?;
    let flags = application::inspect_flags(bytes, base, &candidate, &prelude)?;
    let store = selection.address.checked_sub(2)?;
    let save_call = store.checked_sub(4)?;
    let setup = save_call.checked_sub(2)?;
    let restore_call = tail.continuation.checked_add(2)?;
    let epilogue = flags.end.checked_sub(4)?;
    let slot = tail.saved_state_offset;
    if slot & 3 != 0
        || slot.checked_add(4)? > prelude.stack_bytes
        || setup < prelude.start
        || selection.address < flags.end
        || tail.program_call < selection.end
        || tail.continuation <= tail.program_call
        || word(bytes, base, setup)? != 0x20c0
        || blx(bytes, base, save_call)? != 0x2d4
        || word(bytes, base, store)? != (0x9000 | (slot / 4))
        || word(bytes, base, tail.continuation)? != (0x9800 | (slot / 4))
        || blx(bytes, base, restore_call)? != 0x2cc
    {
        return None;
    }
    let mut at = restore_call.checked_add(4)?;
    let mut return_path = Vec::new();
    for _ in 0..8 {
        if at == epilogue {
            break;
        }
        if return_path.contains(&at) {
            return None;
        }
        let op = word(bytes, base, at)?;
        if op & 0xf800 != 0xe000 {
            return None;
        }
        return_path.push(at);
        let delta = (i32::from(op & 0x7ff) << 21) >> 20;
        at = u32::try_from(i64::from(at) + 4 + i64::from(delta)).ok()?;
    }
    if at != epilogue {
        return None;
    }
    Some(StateSlotEvidence {
        prologue: prelude.start,
        stack_bytes: prelude.stack_bytes,
        slot,
        save_call,
        store,
        restore_call,
        epilogue,
        return_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_blx_alignment_and_destination_are_checked() {
        assert_eq!(
            blx(&[0x58, 0xf7, 0xce, 0xed], 0xa7736, 0xa7736),
            Some(0x2d4)
        );
        assert_eq!(
            blx(&[0x58, 0xf7, 0xc0, 0xec], 0xa7948, 0xa7948),
            Some(0x2cc)
        );
        assert_eq!(blx(&[0x58, 0xf7, 0xcf, 0xed], 0xa7736, 0xa7736), None);
        assert_eq!(blx(&[0x58, 0xf7, 0xce], 0xa7736, 0xa7736), None);
        assert_eq!(blx(&[0x58, 0xf7, 0xce, 0xfd], 0xa7736, 0xa7736), None);
    }
}

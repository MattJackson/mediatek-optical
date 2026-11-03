//! Application command-table evidence, separated from BOOT decoding.
//!
//! A command table is relevant only when its mode-1 target reaches the unique
//! update-flag clearing site. READ BUFFER tables cannot supply an entry recipe.
//! This is one proof component, not authorization to write: the entry guard,
//! complete flag-copy semantics, opcode dispatch and completion still matter.
use super::Window;

mod prologue;
pub use prologue::{inspect_prologue, Prologue};
mod flags;
pub use flags::{inspect_flags, FlagCopy};
mod mode_six;
pub use mode_six::{inspect_mode_six, ModeSix};
mod registration;
pub use registration::{inspect_registration, Registration};

/// A command table bound to an update-flag clearing block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Thumb switch sequence or compiler-helper call.
    pub table: u32,
    /// The literal load of MMIO 0x04002040 preceding the flag clear.
    pub entry: u32,
    /// Mode 1 target before an optional unconditional branch.
    pub mode1_target: u32,
    /// Mode 6 target. Its buffer-id guard is a separate proof obligation.
    pub mode6_target: u32,
    /// ARM compiler helper requiring an independent read and signature check.
    pub helper: Option<u32>,
}

const THUMB_TABLE: &[u8] = b"\x5b\x00\x7b\x44\x9b\x88\x5b\x00\x9f\x44";
use crate::compiler::ARM_BYTE_SWITCH as ARM_HELPER;

/// Verify the complete compiler helper referenced by a candidate. A partial
/// read or different helper never licenses interpreting its inline table.
pub fn matches_helper(bytes: &[u8]) -> bool {
    bytes.get(..ARM_HELPER.len()) == Some(ARM_HELPER)
}

/// Required bounded read length at [`Candidate::helper`].
pub const HELPER_BYTES: usize = ARM_HELPER.len();

/// Complete size of the supported mode/buffer exclusion helper.
pub const MODE_GUARD_BYTES: usize = 40;
const MODE_GUARD: &[u8; MODE_GUARD_BYTES] = b"\x01\x22\x02\x28\x04\xd0\x05\x28\x05\xd0\x0a\x28\x0a\xd1\x08\xe0\x8f\x29\x07\xd1\x05\xe0\x04\x29\x03\xd0\x05\x29\x01\xd0\x06\x29\x00\xd1\x00\x22\x10\x00\x70\x47";

/// Evidence for the complete mode/buffer exclusion helper. This establishes
/// the helper's return value only; the caller must separately prove argument
/// setup and how it uses that return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeBufferGuard(());

impl ModeBufferGuard {
    /// Match every instruction, including conditional branches and return.
    /// Unknown or truncated helpers never acquire an inferred behavior.
    pub fn inspect(bytes: &[u8]) -> Option<Self> {
        (bytes.get(..MODE_GUARD_BYTES) == Some(MODE_GUARD.as_slice())).then_some(Self(()))
    }

    /// Whether the matched helper returns one for its mode and buffer inputs.
    /// A one is not itself authorization: interpretation belongs to the caller.
    pub fn returns_one(self, mode: u8, buffer: u8) -> bool {
        match mode {
            2 => buffer != 0x8f,
            5 => !(4..=6).contains(&buffer),
            10 => false,
            _ => true,
        }
    }
}

fn clear_site(w: &Window<'_>, address: u32) -> Option<u32> {
    let load = w.word(address)?;
    if load & 0xffc0 != 0x6980 {
        return None;
    }
    let tmp = load & 7;
    let base = (load >> 3) & 7;
    if tmp == base {
        return None;
    }
    if w.word(address.checked_add(2)?)? != 0x0900 | (tmp << 3) | tmp
        || w.word(address.checked_add(4)?)? != 0x0100 | (tmp << 3) | tmp
        || w.word(address.checked_add(6)?)? != 0x6180 | (base << 3) | tmp
    {
        return None;
    }
    let entry = address.checked_sub(2)?;
    if w.literal(entry)? != (base, 0x0400_2040) {
        return None;
    }
    Some(entry)
}

fn bind(
    w: &Window<'_>,
    entry: u32,
    table: u32,
    mode1: u32,
    mode6: u32,
    helper: Option<u32>,
) -> Option<Candidate> {
    if mode1 != entry && w.branch(mode1)? != entry {
        return None;
    }
    // Both targets must be instructions in the supplied code window.
    w.word(mode6)?;
    if mode1 & 1 != 0 || mode6 & 1 != 0 {
        return None;
    }
    Some(Candidate {
        table,
        entry,
        mode1_target: mode1,
        mode6_target: mode6,
        helper,
    })
}

fn thumb(w: &Window<'_>, at: u32, entry: u32) -> Option<Candidate> {
    if w.bytes(at, THUMB_TABLE.len())? != THUMB_TABLE {
        return None;
    }
    let compare = w.word(at.checked_sub(6)?)?;
    if compare & 0xff00 != 0x2b00
        || !(7..=32).contains(&(compare & 255))
        || w.conditional(at.checked_sub(4)?, 0xd300)? != at
    {
        return None;
    }
    w.branch(at.checked_sub(2)?)?;
    let target = |mode: u32| -> Option<u32> {
        let offset = w.word(at.checked_add(10 + mode * 2)?)?;
        at.checked_add(12)?.checked_add(u32::from(offset) * 2)
    };
    bind(w, entry, at, target(1)?, target(6)?, None)
}

fn helper(w: &Window<'_>, at: u32, entry: u32) -> Option<Candidate> {
    let first = w.word(at)?;
    let second = w.word(at.checked_add(2)?)?;
    // BLX(1) with suffix bit 0 set is UNDEFINED, not a call.
    if first & 0xf800 != 0xf000 || second & 0xf801 != 0xe800 {
        return None;
    }
    let encoded = (u32::from(first & 2047) << 12) | (u32::from(second & 2047) << 1);
    let delta = ((encoded as i32) << 9) >> 9;
    let helper = u32::try_from(i64::from(at) + 4 + i64::from(delta)).ok()? & !3;
    if !(0x10000..0x1c0000).contains(&helper) {
        return None;
    }
    let table = at.checked_add(4)?;
    let maximum = *w.bytes(table, 1)?.first()?;
    if !(7..32).contains(&maximum) {
        return None;
    }
    w.bytes(table, usize::from(maximum) + 2)?;
    let target = |mode: u32| -> Option<u32> {
        let offset = *w.bytes(table.checked_add(1 + mode)?, 1)?.first()?;
        table.checked_add(u32::from(offset) * 2)
    };
    bind(w, entry, at, target(1)?, target(6)?, Some(helper))
}

/// Locate one relevant command table and one flag-clearing block in a bounded
/// application window. Unknown, truncated and ambiguous windows return `None`.
/// A helper candidate remains provisional until [`matches_helper`] succeeds.
/// This never performs I/O or selects transfer encoding or error policy.
pub fn inspect(bytes: &[u8], address: u32) -> Option<Candidate> {
    let w = Window {
        bytes,
        base: address,
    };
    let mut entry = None;
    for offset in (0..bytes.len()).step_by(2) {
        let at = address.checked_add(u32::try_from(offset).ok()?)?;
        if at & 1 != 0 {
            continue;
        }
        if let Some(found) = clear_site(&w, at) {
            if entry.is_some() {
                return None;
            }
            entry = Some(found);
        }
    }
    let entry = entry?;
    let mut found = None;
    for offset in (0..bytes.len()).step_by(2) {
        let at = address.checked_add(u32::try_from(offset).ok()?)?;
        if at & 1 != 0 {
            continue;
        }
        if let Some(candidate) = thumb(&w, at, entry).or_else(|| helper(&w, at, entry)) {
            if found.is_some() {
                return None;
            }
            found = Some(candidate);
        }
    }
    found
}

#[cfg(test)]
#[path = "application_tests.rs"]
mod tests;

//! The flash loop's reserved-region branches. These facts require incoming
//! register/cell bindings and a complete loop proof before authorizing writes.
use super::word;

/// Complete checked skip branches and their register preconditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedSkips {
    /// Start of the checked block.
    pub address: u32,
    /// First skipped destination offset.
    pub first_start: u32,
    /// Length added to both source and destination and removed from remaining.
    pub first_length: u32,
    /// Destination offset at which the final skip terminates programming.
    pub final_start: u32,
    /// Incoming r4 value needed by the final skip.
    pub required_r4: u32,
    /// Normal continuation, reached after the first skip or neither match.
    pub continuation: u32,
    /// Continuation after the final skip has set remaining length to zero.
    pub finished: u32,
}

/// Check every instruction in both reserved-region branches. r7/r6/r5 must
/// separately be established as destination/source/remaining pointers, and r4
/// must equal 0x10000. Matching this component alone does not establish a loop.
pub fn inspect_reserved_skips(bytes: &[u8], base: u32, start: u32) -> Option<ReservedSkips> {
    if start & 1 != 0 || base & 1 != 0 {
        return None;
    }
    // All data movement and both conditional joins are operand-bound. Only the
    // final unconditional branch is relocatable; its destination is recorded.
    let words = [
        0x6838, 0x211d, 0x0409, 0x4288, 0xd10b, 0x6839, 0x2007, 0x0380, 0x1809, 0x6039, 0x6831,
        0x1809, 0x6031, 0x6829, 0x1a08, 0x6028, 0xe00d, 0x6838, 0x211f, 0x0409, 0x4288, 0xd108,
        0x6838, 0x1900, 0x6038, 0x6830, 0x1900, 0x6030, 0x2300, 0x602b,
    ];
    for (index, expected) in words.into_iter().enumerate() {
        let at = start.checked_add(u32::try_from(index).ok()?.checked_mul(2)?)?;
        if word(bytes, base, at)? != expected {
            return None;
        }
    }
    let branch_at = start.checked_add(60)?;
    let instruction = word(bytes, base, branch_at)?;
    if instruction & 0xf800 != 0xe000 {
        return None;
    }
    let displacement = (i32::from(instruction & 0x7ff) << 21) >> 20;
    let finished = u32::try_from(i64::from(branch_at) + 4 + i64::from(displacement)).ok()?;
    let continuation = start.checked_add(62)?;
    if finished <= continuation {
        return None;
    }
    word(bytes, base, finished)?;
    word(bytes, base, continuation)?;
    Some(ReservedSkips {
        address: start,
        first_start: 0x1d0000,
        first_length: 0x1c000,
        final_start: 0x1f0000,
        required_r4: 0x10000,
        continuation,
        finished,
    })
}

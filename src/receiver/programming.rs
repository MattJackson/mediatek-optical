//! Operand-checked evidence for application update range selection.
//!
//! Selection is not a write proof: the caller must bind the total-length source
//! and establish that the programming call consumes the selected cells. In
//! particular, matching a header does not imply that boot is preserved.

mod acceptance;
pub(super) use acceptance::inspect_acceptance_with_staging;
pub use acceptance::{inspect_acceptance_tail, AcceptanceTail, ResultCheck};

mod reserved;
pub use reserved::{inspect_reserved_skips, ReservedSkips};

mod loop_evidence;
pub use loop_evidence::{
    inspect_compact_program_loop, inspect_program_loop, ProgramLoopEvidence, ProgramLoopVariant,
};

mod state_slot;
pub(super) use state_slot::inspect_state_slot;
pub use state_slot::StateSlotEvidence;

mod mode_three;
pub use mode_three::{inspect_mode_three_wrapper, ModeThreeWrapper};

/// Check the native 16-entry integrity walker against its complete instruction
/// grammar. Both staging loads must bind to the caller's decoded staging cell;
/// all diagnostic calls share one target. The crypto routine is retained OEM
/// code, not replaced or inferred from a firmware/model name.
pub fn inspect_integrity_walker(
    bytes: &[u8],
    base: u32,
    start: u32,
    staging_cell: u32,
) -> Option<u32> {
    use super::decoding::branch_link;
    if !ram(staging_cell) {
        return None;
    }
    let expected = super::mixed::COMPACT_INTEGRITY.get(15..96)?;
    let mut index = 0;
    let mut diagnostic = None;
    let mut crypto = None;
    while index < expected.len() {
        let delta = u32::try_from(index * 2).ok()?;
        let at = start.checked_add(delta)?;
        let original = expected[index];
        let actual = word(bytes, base, at)?;
        if original & 0xf800 == 0x4800 {
            if actual & 0xff00 != original & 0xff00 {
                return None;
            }
            let value = literal(bytes, base, at, (original >> 8) & 7)?;
            if matches!(delta, 2 | 0x62) && value != staging_cell {
                return None;
            }
        } else if original & 0xf800 == 0xf000 && expected.get(index + 1)? & 0xf800 == 0xf800 {
            let target = branch_link(bytes, base, at)?;
            match delta {
                0x0e => {}
                0x70 => crypto = Some(target),
                _ => {
                    if diagnostic.is_some_and(|previous| previous != target) {
                        return None;
                    }
                    diagnostic = Some(target);
                }
            }
            index += 1;
        } else if actual != original {
            return None;
        }
        index += 1;
    }
    let crypto = crypto?;
    if Some(crypto) == diagnostic {
        return None;
    }
    let helper = |address: u32, expected: &[u16]| -> Option<()> {
        for (index, &expected) in expected.iter().enumerate() {
            let at = address.checked_add(u32::try_from(index * 2).ok()?)?;
            let actual = word(bytes, base, at)?;
            if expected & 0xf800 == 0x4800 {
                if actual & 0xff00 != expected & 0xff00
                    || literal(bytes, base, at, (expected >> 8) & 7)? != 0x04063000
                {
                    return None;
                }
            } else if actual != expected {
                return None;
            }
        }
        Some(())
    };
    let code = super::mixed::COMPACT_CMAC_RANGE;
    let helpers = super::mixed::CMAC_RANGE_HELPERS;
    let mut index = 0;
    while index < code.len() {
        let expected = code[index];
        let at = crypto.checked_add(u32::try_from(index * 2).ok()?)?;
        let actual = word(bytes, base, at)?;
        if expected & 0xf800 == 0x4800 {
            if actual & 0xff00 != expected & 0xff00
                || literal(bytes, base, at, (expected >> 8) & 7)? != 0x04063000
            {
                return None;
            }
        } else if expected & 0xf800 == 0xf000 && code.get(index + 1)? & 0xf800 == 0xf800 {
            let role = match index * 2 {
                0x3e => helpers.get(..56)?,
                0xa4 => helpers.get(56..67)?,
                0xd8 => helpers.get(67..)?,
                _ => return None,
            };
            helper(branch_link(bytes, base, at)?, role)?;
            index += 1;
        } else if actual != expected {
            return None;
        }
        index += 1;
    }
    Some(crypto)
}

/// Both branches of the legacy application's update-bit-zero range selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// First instruction of the checked range-selection block.
    pub address: u32,
    /// First instruction after the complete selection block.
    pub end: u32,
    /// RAM cell receiving the selected upload offset.
    pub offset_cell: u32,
    /// RAM cell receiving the selected programming start.
    pub start_cell: u32,
    /// RAM cell receiving total length minus selected start.
    pub length_cell: u32,
    /// Register holding a pointer to the upload's total-length cell.
    pub total_pointer_register: u8,
}

/// Calls and branches selecting optional boot CMAC and mandatory application CMAC.
/// The referenced checker routines still require independent validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegritySelection {
    /// Address of the update-state load.
    pub address: u32,
    /// Called only when update flag bit zero is set.
    pub boot_check: u32,
    /// Called with mask one unless the boot check has already failed.
    pub application_check: u32,
    /// Continuation reached only when the selected checks returned nonzero.
    pub success: u32,
    /// Error path reached when a selected checker returns zero.
    pub failure: u32,
}

/// A direct staged-byte signature comparison following range selection.
/// Every instruction between selection and comparison is checked: there is no
/// intervening decoder call on this path. Earlier stream effects remain a
/// separate obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainSignature {
    /// RAM cell containing the upload staging pointer.
    pub staging_cell: u32,
    /// Image offset compared with the installed signature.
    pub offset: u32,
    /// Number of bytes compared.
    pub length: u32,
    /// Continuation after all bytes match.
    pub success: u32,
    /// Continuation when a byte differs.
    pub mismatch: u32,
    /// Continuation when the selected range does not cover the guard region.
    pub outside_range: u32,
}

/// Bind the legacy direct signature loop to an independently matched selection.
/// This establishes a plaintext constraint, not acceptance of the whole image.
pub fn inspect_plain_signature(
    bytes: &[u8],
    base: u32,
    selection: &Selection,
) -> Option<PlainSignature> {
    if inspect_selection(bytes, base, selection.address)? != *selection {
        return None;
    }
    let start = selection.end;
    let at = |index: u32| start.checked_add(index.checked_mul(2)?);
    let op = |index| word(bytes, base, at(index)?);
    for (index, expected) in [
        (0, 0x2201),
        (1, 0x0692),
        (2, 0x6810),
        (3, 0x2110),
        (4, 0x4388),
        (5, 0x6010),
        (7, 0x6820),
        (8, 0x2283),
        (9, 0x0252),
        (10, 0x4290),
        (12, 0x6820),
        (14, 0x1840),
        (16, 0x4288),
        (19, 0x2100),
        (20, 0x6800),
        (21, 0x0213),
        (23, 0x0a1b),
        (24, 0x181b),
        (25, 0x781b),
        (29, 0x1c49),
        (30, 0x0609),
        (31, 0x0e09),
        (32, 0x1c52),
        (33, 0x2908),
        (34, 0xd3f1),
    ] {
        if op(index)? != expected {
            return None;
        }
    }
    if literal(bytes, base, at(6)?, 4)? != selection.offset_cell
        || literal(bytes, base, at(15)?, 1)? != 0x10700
    {
        return None;
    }
    // The length pointer survives selection in the destination register of its
    // last literal load; bind the use here to that exact register.
    let last_load = word(bytes, base, selection.end.checked_sub(4)?)?;
    let length_register = (last_load >> 8) & 7;
    // Indices 0-12 clobber r0, r1, r2 and r4 before index 13 reads the pointer.
    if matches!(length_register, 0 | 1 | 2 | 4) {
        return None;
    }
    if op(13)? != 0x6801 | length_register << 3 {
        return None;
    }
    let signature_register = (op(22)? >> 8) & 7;
    if signature_register < 4
        || literal(bytes, base, at(22)?, signature_register)? != 0x10600
        || op(26)? != 0x5c40 | signature_register << 3 | signature_register
        || op(27)? != 0x4283 | signature_register << 3
    {
        return None;
    }
    let branch = |index, condition| {
        let instruction = op(index)?;
        if instruction & 0xff00 != condition {
            return None;
        }
        let target =
            u32::try_from(i64::from(at(index)?) + 4 + i64::from(instruction as u8 as i8) * 2)
                .ok()?;
        word(bytes, base, target)?;
        Some(target)
    };
    let outside_range = branch(11, 0xd800)?;
    if branch(17, 0xd900)? != outside_range {
        return None;
    }
    let mismatch = branch(28, 0xd100)?;
    let success = at(35)?;
    if outside_range < success || mismatch < success {
        return None;
    }
    let staging_cell = literal(bytes, base, at(18)?, 0)?;
    if !ram(staging_cell)
        || [
            selection.offset_cell,
            selection.start_cell,
            selection.length_cell,
        ]
        .contains(&staging_cell)
    {
        return None;
    }
    Some(PlainSignature {
        staging_cell,
        offset: 0x10600,
        length: 8,
        success,
        mismatch,
        outside_range,
    })
}

fn word(bytes: &[u8], base: u32, address: u32) -> Option<u16> {
    let offset = usize::try_from(address.checked_sub(base)?).ok()?;
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn literal(bytes: &[u8], base: u32, address: u32, register: u16) -> Option<u32> {
    let op = word(bytes, base, address)?;
    if op & 0xff00 != 0x4800 | register << 8 {
        return None;
    }
    let at = (address.checked_add(4)? & !3).checked_add(u32::from(op & 255) * 4)?;
    Some(
        u32::from(word(bytes, base, at)?) | u32::from(word(bytes, base, at.checked_add(2)?)?) << 16,
    )
}

fn ram(address: u32) -> bool {
    address & 3 == 0 && (0x02000000..0x02010000).contains(&address)
}

/// Inspect either established compiler form, rejecting ambiguous matches.
pub fn inspect_selection(bytes: &[u8], base: u32, start: u32) -> Option<Selection> {
    match (
        inspect_legacy_selection(bytes, base, start),
        inspect_shared_selection(bytes, base, start),
    ) {
        (Some(proof), None) | (None, Some(proof)) => Some(proof),
        _ => None,
    }
}

fn inspect_shared_selection(bytes: &[u8], base: u32, start: u32) -> Option<Selection> {
    if start & 1 != 0 || base & 1 != 0 {
        return None;
    }
    // The compiler may insert a literal pool between the two arms. Follow
    // their explicit branch targets instead of assuming adjacent blocks.
    let branch_target = |address: u32, conditional: bool| {
        let instruction = word(bytes, base, address)?;
        let delta = if conditional {
            if instruction & 0xff00 != 0xd000 {
                return None;
            }
            i64::from(instruction as u8 as i8) * 2
        } else {
            if instruction & 0xf800 != 0xe000 {
                return None;
            }
            i64::from((i32::from(instruction & 0x7ff) << 21) >> 20)
        };
        u32::try_from(i64::from(address) + 4 + delta).ok()
    };
    let alternate = branch_target(start.checked_add(8)?, true)?;
    let join = branch_target(start.checked_add(20)?, false)?;
    if alternate < start.checked_add(22)? || join != alternate.checked_add(14)? {
        return None;
    }
    let at = |index: u32| {
        if index < 11 {
            start.checked_add(index.checked_mul(2)?)
        } else {
            alternate.checked_add(index.checked_sub(11)?.checked_mul(2)?)
        }
    };
    let op = |index| word(bytes, base, at(index)?);
    if literal(bytes, base, start, 0)? != 0x04002040 {
        return None;
    }
    for (index, expected) in [
        (1, 0x6980),
        (2, 0x07c1),
        (6, 0x2100),
        (7, 0x6011),
        (8, 0x6001),
        (12, 0x2101),
        (13, 0x0409),
        (14, 0x6011),
        (15, 0x6001),
        (17, 0x1a51),
    ] {
        if op(index)? != expected {
            return None;
        }
    }
    let start_cell = literal(bytes, base, at(3)?, 0)?;
    let offset_cell = literal(bytes, base, at(5)?, 2)?;
    if literal(bytes, base, at(11)?, 2)? != offset_cell {
        return None;
    }
    let total = op(9)?;
    if total & 0xffc7 != 0x6801 || op(16)? != (total & !7) | 2 {
        return None;
    }
    let pointer = ((total >> 3) & 7) as u8;
    if pointer < 3 {
        return None;
    }
    let length_register = (op(18)? >> 8) & 7;
    let length_cell = literal(bytes, base, at(18)?, length_register)?;
    if length_register == 1 || op(19)? != 0x6001 | length_register << 3 {
        return None;
    }
    if ![offset_cell, start_cell, length_cell].into_iter().all(ram)
        || offset_cell == start_cell
        || offset_cell == length_cell
        || start_cell == length_cell
    {
        return None;
    }
    Some(Selection {
        address: start,
        end: at(20)?,
        offset_cell,
        start_cell,
        length_cell,
        total_pointer_register: pointer,
    })
}

/// Establish the application's complete boot/application CMAC choice.
/// Clearing update bit zero skips the boot checker, never the application one.
/// The result test may be immediate or reached by an explicit forward join.
pub fn inspect_legacy_integrity(bytes: &[u8], base: u32, start: u32) -> Option<IntegritySelection> {
    use super::decoding::branch_link;
    if base & 1 != 0 || start & 1 != 0 || literal(bytes, base, start, 0)? != 0x04002040 {
        return None;
    }
    let at = |delta: u32| start.checked_add(delta);
    for (offset, expected) in [
        (2, 0x6980),
        (4, 0x07c0),
        (6, 0xd003),
        (12, 0x2801),
        (16, 0x2001),
    ] {
        if word(bytes, base, at(offset)?)? != expected {
            return None;
        }
    }
    let after_call = at(22)?;
    let op = word(bytes, base, after_call)?;
    let join = if op == 0x2800 {
        after_call
    } else if op & 0xf800 == 0xe000 {
        let delta = (i32::from(op & 0x7ff) << 21) >> 20;
        let target = u32::try_from(i64::from(after_call) + 4 + i64::from(delta)).ok()?;
        if target <= after_call || target.checked_sub(after_call)? > 256 {
            return None;
        }
        target
    } else {
        return None;
    };
    // Boot-check failure and application-check completion must test the same
    // unmodified r0. Never linearly decode a skipped literal/padding island.
    let boot_failure = word(bytes, base, at(14)?)?;
    if boot_failure & 0xff00 != 0xd100
        || u32::try_from(i64::from(at(14)?) + 4 + i64::from(boot_failure as u8 as i8) * 2).ok()?
            != join
        || word(bytes, base, join)? != 0x2800
    {
        return None;
    }
    let branch_at = join.checked_add(2)?;
    let branch = word(bytes, base, branch_at)?;
    if branch & 0xff00 != 0xd100 {
        return None;
    }
    let success =
        u32::try_from(i64::from(branch_at) + 4 + i64::from(branch as u8 as i8) * 2).ok()?;
    let failure = join.checked_add(4)?;
    if success <= failure {
        return None;
    }
    word(bytes, base, success)?;
    word(bytes, base, failure)?;
    Some(IntegritySelection {
        address: start,
        boot_check: branch_link(bytes, base, at(8)?)?,
        application_check: branch_link(bytes, base, at(18)?)?,
        success,
        failure,
    })
}

#[cfg(test)]
#[path = "programming_integrity_join_tests.rs"]
mod integrity_join_tests;

/// Match all instructions, both branches, literals and the branch join.
/// This compiler form selects start zero when MMIO bit zero is set, otherwise
/// `0x10000`; it always stores length `total - start`. Other forms return None.
pub fn inspect_legacy_selection(bytes: &[u8], base: u32, start: u32) -> Option<Selection> {
    if start & 1 != 0 || base & 1 != 0 {
        return None;
    }
    let at = |index: u32| start.checked_add(index.checked_mul(2)?);
    let op = |index| word(bytes, base, at(index)?);
    if literal(bytes, base, start, 0)? != 0x04002040 {
        return None;
    }
    // Exact branch displacements bind both arms and their join, not just opcodes.
    for (index, expected) in [
        (1, 0x6980),
        (2, 0x07c0),
        (3, 0xd006),
        (5, 0x2000),
        (6, 0x6008),
        (8, 0x6008),
        (10, 0xe007),
        (12, 0x2101),
        (13, 0x0409),
        (14, 0x6001),
        (16, 0x6001),
        (18, 0x1a40),
    ] {
        if op(index)? != expected {
            return None;
        }
    }
    let offset_cell = literal(bytes, base, at(4)?, 1)?;
    let start_cell = literal(bytes, base, at(7)?, 1)?;
    if literal(bytes, base, at(11)?, 0)? != offset_cell
        || literal(bytes, base, at(15)?, 0)? != start_cell
    {
        return None;
    }
    let total = op(9)?;
    if total & 0xffc7 != 0x6800 || op(17)? != total {
        return None;
    }
    let pointer = ((total >> 3) & 7) as u8;
    // Both r0 and r1 have been overwritten in these arms.
    if pointer < 2 {
        return None;
    }
    let load = op(19)?;
    let length_register = (load >> 8) & 7;
    let length_cell = literal(bytes, base, at(19)?, length_register)?;
    if length_register == 0 || op(20)? != 0x6000 | length_register << 3 {
        return None;
    }
    if ![offset_cell, start_cell, length_cell].into_iter().all(ram)
        || offset_cell == start_cell
        || offset_cell == length_cell
        || start_cell == length_cell
    {
        return None;
    }
    Some(Selection {
        address: start,
        end: at(21)?,
        offset_cell,
        start_cell,
        length_cell,
        total_pointer_register: pointer,
    })
}

#[cfg(test)]
#[path = "programming_tests.rs"]
mod tests;

//! Operand-checked evidence for application update range selection.
//!
//! Selection is not a write proof: the caller must bind the total-length source
//! and establish that the programming call consumes the selected cells. In
//! particular, matching a header does not imply that boot is preserved.

mod acceptance;
pub use acceptance::{inspect_acceptance_tail, AcceptanceTail};

mod reserved;
pub use reserved::{inspect_reserved_skips, ReservedSkips};

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

/// Establish the legacy application's complete boot/application CMAC choice.
/// Clearing update bit zero skips the boot checker, never the application one.
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
        (14, 0xd102),
        (16, 0x2001),
        (22, 0x2800),
    ] {
        if word(bytes, base, at(offset)?)? != expected {
            return None;
        }
    }
    let branch = word(bytes, base, at(24)?)?;
    if branch & 0xff00 != 0xd100 {
        return None;
    }
    let success = u32::try_from(i64::from(at(24)?) + 4 + i64::from(branch as u8 as i8) * 2).ok()?;
    let failure = at(26)?;
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
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let words = [
            0x48b5u16, 0x6980, 0x07c0, 0xd006, 0x49a3, 0x2000, 0x6008, 0x49b6, 0x6008, 0x6820,
            0xe007, 0x489f, 0x2101, 0x0409, 0x6001, 0x48b2, 0x6001, 0x6820, 0x1a40, 0x4ea1, 0x6030,
        ];
        let mut bytes = vec![0; 0x300];
        for (i, op) in words.into_iter().enumerate() {
            bytes[2 * i..2 * i + 2].copy_from_slice(&op.to_le_bytes());
        }
        for (address, value) in [
            (0x9d7f8u32, 0x04002040u32),
            (0x9d7b8, 0x02000c60),
            (0x9d80c, 0x02000c68),
            (0x9d7d0, 0x02000c6c),
        ] {
            let at = (address - 0x9d522) as usize;
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    // Relocated operand-equivalent shared-load form, with an optional literal
    // island between the branches (as in UH12NS40 1.03).
    fn shared_fixture(island: usize) -> Vec<u8> {
        let mut bytes = vec![0; 0x300];
        let alternate = 22 + island;
        let join = alternate + 14;
        let mut put = |at: usize, value: u16| {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        };
        for (at, op) in [
            (2, 0x6980),
            (4, 0x07c1),
            (12, 0x2100),
            (14, 0x6011),
            (16, 0x6001),
            (18, 0x6821),
        ] {
            put(at, op);
        }
        put(8, 0xd000 | ((alternate - 12) / 2) as u16);
        put(20, 0xe000 | ((join - 24) / 2) as u16);
        for (offset, op) in [
            (2, 0x2101),
            (4, 0x0409),
            (6, 0x6011),
            (8, 0x6001),
            (10, 0x6822),
            (12, 0x1a51),
            (16, 0x6031),
        ] {
            put(alternate + offset, op);
        }
        for (at, reg, literal_at, value) in [
            (0, 0, 0x200, 0x04002040u32),
            (6, 0, 0x204, 0x02000c68),
            (10, 2, 0x208, 0x02000c60),
            (alternate, 2, 0x208, 0x02000c60),
            (join, 6, 0x20c, 0x02000c6c),
        ] {
            let op = 0x4800u16 | reg << 8 | ((literal_at - ((at + 4) & !3)) / 4) as u16;
            bytes[at..at + 2].copy_from_slice(&op.to_le_bytes());
            bytes[literal_at..literal_at + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn shared_selection_follows_branches_over_literal_islands() {
        for island in [0, 0x76] {
            let bytes = shared_fixture(island);
            let proof = inspect_selection(&bytes, 0, 0).unwrap();
            assert_eq!(proof.end, (40 + island) as u32);
            assert_eq!(proof.start_cell, 0x02000c68);
            assert_eq!(proof.total_pointer_register, 4);
            // Both branch destinations and both arms must remain bound.
            for at in [8, 20, 22 + island + 4, 22 + island + 12, 22 + island + 16] {
                let mut changed = bytes.clone();
                changed[at] ^= 1;
                assert!(inspect_selection(&changed, 0, 0).is_none(), "at {at:#x}");
            }
            // Literal data is not executable fallthrough.
            if island != 0 {
                let mut changed = bytes.clone();
                changed[22..22 + island].fill(0xff);
                assert_eq!(inspect_selection(&changed, 0, 0), Some(proof));
            }
        }
    }

    #[test]
    fn intm_selection_binds_both_arms_and_distinct_cells() {
        let evidence = inspect_legacy_selection(&fixture(), 0x9d522, 0x9d522).unwrap();
        assert_eq!(evidence.offset_cell, 0x02000c60);
        assert_eq!(evidence.start_cell, 0x02000c68);
        assert_eq!(evidence.length_cell, 0x02000c6c);
        assert_eq!(evidence.total_pointer_register, 4);
        assert_eq!(evidence.end, 0x9d54c);
    }

    #[test]
    fn changed_guards_stores_subtraction_and_joins_are_rejected() {
        let bytes = fixture();
        for index in [1, 2, 3, 5, 6, 8, 10, 12, 13, 14, 16, 17, 18, 20] {
            let mut changed = bytes.clone();
            changed[index * 2] ^= 1;
            assert!(
                inspect_legacy_selection(&changed, 0x9d522, 0x9d522).is_none(),
                "instruction {index}"
            );
        }
        assert!(inspect_legacy_selection(&bytes[..42], 0x9d522, 0x9d522).is_none());
        assert!(inspect_legacy_selection(&bytes, u32::MAX - 1, u32::MAX - 1).is_none());
    }
}

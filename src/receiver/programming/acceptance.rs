//! The checked continuation from integrity success to the programming call.
//! Called helper semantics and the incoming r4/r7 bindings remain obligations.
use super::{literal, word, IntegritySelection, PlainSignature, Selection};
use crate::receiver::decoding::branch_link;

/// Operand-bound acceptance checks and programming arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptanceTail {
    /// Start of the continuation, equal to integrity success.
    pub address: u32,
    /// Tag-check helper, required to return nonzero.
    pub tag_check: u32,
    /// Marker-check helper, required to return nonzero.
    pub marker_check: u32,
    /// Staged byte required to equal 0xDE.
    pub descriptor_byte: u32,
    /// Actual programming call instruction.
    pub program_call: u32,
    /// Programming wrapper called with mode three.
    pub program_target: u32,
    /// Incoming register that must still hold selection.offset_cell.
    pub source_pointer_register: u8,
    /// Incoming register pointing to the failure-state byte.
    pub failure_pointer_register: u8,
    /// Common error-report continuation for invalid descriptor/tag/marker.
    pub error: u32,
    /// Helpers called after validation, before examining failure state.
    pub before_program: [u32; 2],
}

/// Match both validation branches and every instruction of the success path.
/// This proves argument use, not the independently called helper bodies.
pub fn inspect_acceptance_tail(
    bytes: &[u8],
    base: u32,
    selection: &Selection,
    signature: &PlainSignature,
    integrity: &IntegritySelection,
) -> Option<AcceptanceTail> {
    if super::inspect_selection(bytes, base, selection.address)? != *selection
        || super::inspect_plain_signature(bytes, base, selection)? != *signature
        || super::inspect_legacy_integrity(bytes, base, integrity.address)? != *integrity
    {
        return None;
    }
    inspect_acceptance_with_staging(bytes, base, selection, signature.staging_cell, integrity)
}

/// Shared argument grammar after independently traced plaintext or bulk decode.
/// This remains component evidence, not proof of the intervening control flow.
pub(crate) fn inspect_acceptance_with_staging(
    bytes: &[u8],
    base: u32,
    selection: &Selection,
    staging_cell: u32,
    integrity: &IntegritySelection,
) -> Option<AcceptanceTail> {
    if super::inspect_selection(bytes, base, selection.address)? != *selection
        || super::inspect_legacy_integrity(bytes, base, integrity.address)? != *integrity
        || staging_cell & 3 != 0
        || !(0x02000000..0x02010000).contains(&staging_cell)
    {
        return None;
    }
    let start = integrity.success;
    let at = |delta: u32| start.checked_add(delta);
    for (offset, expected) in [
        (4, 0x2800),
        (6, 0xd103),
        (14, 0xe00a),
        (20, 0x6809),
        (22, 0x1840),
        (24, 0x7801),
        (26, 0x29de),
        (28, 0xd006),
        (32, 0x22de),
        (38, 0x2200),
        (40, 0x2124),
        (48, 0x2800),
        (50, 0xd105),
        (58, 0x2203),
        (60, 0x2126),
        (68, 0x2107),
        (70, 0x2000),
        (76, 0x7838),
        (78, 0x2801),
        (80, 0xd007),
        (84, 0x6832),
        (86, 0x6821),
        (90, 0x6800),
        (92, 0x2303),
        (98, 0x980d),
    ] {
        if word(bytes, base, at(offset)?)? != expected {
            return None;
        }
    }
    if literal(bytes, base, at(16)?, 1)? != staging_cell
        || literal(bytes, base, at(82)?, 6)? != selection.length_cell
        || literal(bytes, base, at(88)?, 0)? != selection.start_cell
    {
        return None;
    }
    let descriptor_byte = literal(bytes, base, at(18)?, 0)?;
    if descriptor_byte != 0x1ec056 {
        return None;
    }
    let diagnostic = branch_link(bytes, base, at(10)?)?;
    for offset in [34, 54] {
        if branch_link(bytes, base, at(offset)?)? != diagnostic {
            return None;
        }
    }
    for offset in [8, 30, 52] {
        literal(bytes, base, at(offset)?, 0)?;
    }
    let branch = |offset| {
        let address = at(offset)?;
        let op = word(bytes, base, address)?;
        if op & 0xf800 != 0xe000 {
            return None;
        }
        let delta = (i32::from(op & 0x7ff) << 21) >> 20;
        u32::try_from(i64::from(address) + 4 + i64::from(delta)).ok()
    };
    let error = branch(42)?;
    if error != branch(62)? || (start..at(100)?).contains(&error) {
        return None;
    }
    Some(AcceptanceTail {
        address: start,
        tag_check: branch_link(bytes, base, start)?,
        marker_check: branch_link(bytes, base, at(44)?)?,
        descriptor_byte,
        program_call: at(94)?,
        program_target: branch_link(bytes, base, at(94)?)?,
        source_pointer_register: 4,
        failure_pointer_register: 7,
        error,
        before_program: [
            branch_link(bytes, base, at(64)?)?,
            branch_link(bytes, base, at(72)?)?,
        ],
    })
}

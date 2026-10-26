//! The checked continuation from integrity success to the programming call.
//! Called helper semantics and the incoming pointer bindings remain obligations.
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
    /// Shared continuation after programming, also used when failure state is one.
    pub continuation: u32,
    /// Stack byte offset of the saved state loaded by that continuation.
    pub saved_state_offset: u16,
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
        (78, 0x2801),
        (90, 0x6800),
        (92, 0x2303),
    ] {
        if word(bytes, base, at(offset)?)? != expected {
            return None;
        }
    }
    let failure_load = word(bytes, base, at(76)?)?;
    let length_load = word(bytes, base, at(82)?)?;
    let source_load = word(bytes, base, at(86)?)?;
    let failure_register = (failure_load >> 3) & 7;
    let length_register = (length_load >> 8) & 7;
    let source_register = (source_load >> 3) & 7;
    if failure_load & 0xffc7 != 0x7800
        || source_load & 0xffc7 != 0x6801
        || failure_register < 4
        || source_register < 4
        || length_register < 4
        || length_register == source_register
        || word(bytes, base, at(84)?)? != 0x6802 | length_register << 3
        || literal(bytes, base, at(16)?, 1)? != staging_cell
        || literal(bytes, base, at(82)?, length_register)? != selection.length_cell
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
    let skip_at = at(80)?;
    let skip = word(bytes, base, skip_at)?;
    if skip & 0xff00 != 0xd000 {
        return None;
    }
    let continuation =
        u32::try_from(i64::from(skip_at) + 4 + i64::from(skip as u8 as i8) * 2).ok()?;
    if continuation < at(98)? {
        return None;
    }
    // The compiler can place a pool after the call. Both the skip path and
    // normal completion must reach the same saved-state load, without treating
    // the intervening data as executable fallthrough.
    if continuation != at(98)? && branch(98)? != continuation {
        return None;
    }
    let saved_state = word(bytes, base, continuation)?;
    if saved_state & 0xff00 != 0x9800 {
        return None;
    }
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
        source_pointer_register: source_register as u8,
        failure_pointer_register: failure_register as u8,
        continuation,
        saved_state_offset: (saved_state & 255) * 4,
        error,
        before_program: [
            branch_link(bytes, base, at(64)?)?,
            branch_link(bytes, base, at(72)?)?,
        ],
    })
}

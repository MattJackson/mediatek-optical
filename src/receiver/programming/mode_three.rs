//! Mode-three argument binding for the shared native programming wrapper.
use super::{literal, word, ProgramLoopEvidence};
use crate::receiver::decoding::branch_link;

/// Native wrapper's checked stores, loop and cache-setup calls. Called routines
/// use the firmware's callee-saved register ABI; their hardware behavior and
/// application reachability remain separate from these argument facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeThreeWrapper {
    /// First instruction of the wrapper, called with r3 equal to three.
    pub address: u32,
    /// Exact native loop called by this path.
    pub loop_address: u32,
    /// Complete loop and page-copy instruction evidence.
    pub program: ProgramLoopEvidence,
    /// Setup and geometry helper calls preceding the mode-three branch.
    pub setup_helpers: [u32; 4],
    /// Helper receiving the native loop's Thumb pointer and copied byte count.
    pub copy_helper: u32,
    /// Helper called after copying and before entering the loop.
    pub activate_helper: u32,
    /// Count passed to the code-copy helper.
    pub copied_bytes: u32,
    /// Teardown helper calls after the loop returns.
    pub cleanup_helpers: [u32; 2],
}

/// Match the complete mode-three entry, stores and restoring exit. Unexecuted
/// mode-zero/one/two bodies are not inferred from this component. Every branch
/// and register move on this path is fixed; only checked literal/call operands
/// relocate. This does not authorize a transfer by itself.
pub fn inspect_mode_three_wrapper(
    bytes: &[u8],
    base: u32,
    address: u32,
) -> Option<ModeThreeWrapper> {
    let at = |delta: u32| address.checked_add(delta);
    let expected = super::super::mixed::COMPACT_WRAPPER;
    let calls = [
        0x16, 0x1c, 0x22, 0x26, 0x2a, 0x9c, 0x136, 0x13a, 0x13e, 0x17a, 0x17e, 0x190,
    ];
    let literals = [0x32, 0x40, 0x124, 0x12a, 0x12e, 0x132, 0x134, 0x182];
    // 0x9a..0xa2 is the restoring exit taken by the setup checks at +0x30,
    // +0x38 and +0x3e before the mode branch.
    for range in [0..0x54u32, 0x9a..0xa2, 0x10a..0x144, 0x17a..0x198] {
        for delta in range.step_by(2) {
            if calls.iter().any(|&call| delta == call || delta == call + 2)
                || literals.contains(&delta)
            {
                continue;
            }
            if word(bytes, base, at(delta)?)? != *expected.get(delta as usize / 2)? {
                return None;
            }
        }
    }
    if address & 1 != 0
        || super::state_slot::blx(bytes, base, at(0x16)?)? != 0x2d4
        || super::state_slot::blx(bytes, base, at(0x9c)?)? != 0x2cc
        || super::state_slot::blx(bytes, base, at(0x190)?)? != 0x2cc
        || literal(bytes, base, at(0x40)?, 3)? != 0x04002240
        || literal(bytes, base, at(0x182)?, 3)? != 0x04002240
    {
        return None;
    }
    let geometry = literal(bytes, base, at(0x32)?, 1)?;
    let loop_address = branch_link(bytes, base, at(0x13e)?)?;
    if loop_address & 3 != 0 {
        return None;
    }
    let offset = usize::try_from(loop_address.checked_sub(base)?).ok()?;
    let program = super::inspect_program_loop(bytes.get(offset..)?)?;
    if geometry != program.flash_status_cell
        || literal(bytes, base, at(0x124)?, 1)? != program.source_offset_cell
        || literal(bytes, base, at(0x12a)?, 0)? != program.destination_cell
        || literal(bytes, base, at(0x12e)?, 0)? != program.remaining_cell
        || literal(bytes, base, at(0x134)?, 0)? != loop_address | 1
    {
        return None;
    }
    let copied_bytes = literal(bytes, base, at(0x132)?, 1)?;
    let minimum = match program.variant {
        super::ProgramLoopVariant::Compact => 2016,
        super::ProgramLoopVariant::Wide => 2060,
        super::ProgramLoopVariant::WideWithoutPrelude => 2088,
    };
    if copied_bytes < minimum
        || copied_bytes > 0x10000
        || bytes
            .get(offset..offset.checked_add(copied_bytes as usize)?)
            .is_none()
    {
        return None;
    }
    let call = |delta| {
        let target = branch_link(bytes, base, at(delta)?)?;
        let offset = usize::try_from(target.checked_sub(base)?).ok()?;
        bytes.get(offset..offset.checked_add(2)?)?;
        Some(target)
    };
    Some(ModeThreeWrapper {
        address,
        loop_address,
        program,
        setup_helpers: [call(0x1c)?, call(0x22)?, call(0x26)?, call(0x2a)?],
        copy_helper: call(0x136)?,
        activate_helper: call(0x13a)?,
        copied_bytes,
        cleanup_helpers: [call(0x17a)?, call(0x17e)?],
    })
}

#[cfg(test)]
#[path = "mode_three_tests.rs"]
mod tests;

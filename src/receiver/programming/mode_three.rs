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
        0x16, 0x1c, 0x22, 0x26, 0x2a, 0x136, 0x13a, 0x13e, 0x17a, 0x17e, 0x190,
    ];
    let literals = [0x32, 0x40, 0x124, 0x12a, 0x12e, 0x132, 0x134, 0x182];
    for range in [0..0x54u32, 0x10a..0x144, 0x17a..0x198] {
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
        || super::state_slot::blx(bytes, base, at(0x190)?)? != 0x2cc
        || literal(bytes, base, at(0x40)?, 3)? != 0x04002240
        || literal(bytes, base, at(0x182)?, 3)? != 0x04002240
    {
        return None;
    }
    let geometry = literal(bytes, base, at(0x32)?, 1)?;
    let loop_address = branch_link(bytes, base, at(0x13e)?)?;
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
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut image = vec![0; 0x200000];
        let wrapper = include_bytes!("../../../tests/fixtures/analysis/uh12-wrapper.bin");
        let program = include_bytes!("../../../tests/fixtures/analysis/uh12-program.bin");
        image[0x17c44e..0x17c44e + wrapper.len()].copy_from_slice(wrapper);
        image[0x17000..0x17000 + program.len()].copy_from_slice(program);
        image
    }

    #[test]
    fn native_mode_three_stores_bind_to_the_actual_loop_cells() {
        let image = fixture();
        let proof = inspect_mode_three_wrapper(&image, 0, 0x17c44e).unwrap();
        assert_eq!(proof.loop_address, 0x17000);
        assert_eq!(proof.copied_bytes, 0x1bfc);
        assert_eq!(proof.program.destination_cell, 0x02000c58);
        assert_eq!(proof.program.source_offset_cell, 0x02000c60);
        assert_eq!(proof.program.remaining_cell, 0x02000c64);
        assert_eq!(proof.copy_helper, 0xaa942);
        assert_eq!(proof.activate_helper, 0xaa90a);
        for relative in [
            0, 2, 4, 6, 0x50, 0x52, 0x10a, 0x10c, 0x126, 0x128, 0x12c, 0x130, 0x142, 0x194, 0x196,
        ] {
            let mut changed = image.clone();
            changed[0x17c44e + relative] ^= 1;
            assert!(
                inspect_mode_three_wrapper(&changed, 0, 0x17c44e).is_none(),
                "{relative:#x}"
            );
        }
        for at in [0x17c76c, 0x17c770, 0x17c774, 0x17c778, 0x17002] {
            let mut changed = image.clone();
            changed[at] ^= 1;
            assert!(
                inspect_mode_three_wrapper(&changed, 0, 0x17c44e).is_none(),
                "{at:#x}"
            );
        }
    }
}

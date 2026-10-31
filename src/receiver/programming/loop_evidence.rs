//! Complete programming-loop matching with role-checked RAM literal relocation.
use core::ops::Range;

#[path = "loop_without_prelude.rs"]
mod without_prelude;

/// Complete instruction forms, independent of model names and RAM relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramLoopVariant {
    /// Compact loop with the first reserved span starting at 0x1d0000.
    Compact,
    /// Wider loop with the first reserved span starting at 0x1c8000.
    Wide,
    /// Same reserved spans as Wide, without its alternate-controller prelude.
    WideWithoutPrelude,
}

/// Evidence for the native mode-three programming loop and raw page copy.
/// This is not an executable receiver contract: the application selection,
/// wrapper arguments, integrity checks and external helpers need binding too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramLoopEvidence {
    /// Instruction form which supplied this evidence.
    pub variant: ProgramLoopVariant,
    /// RAM cell holding the next flash destination.
    pub destination_cell: u32,
    /// RAM cell holding the next source offset within staging.
    pub source_offset_cell: u32,
    /// RAM cell holding the remaining byte count.
    pub remaining_cell: u32,
    /// RAM cell containing the staging base used by the page copy.
    pub staging_cell: u32,
    /// Temporary page-copy pointer cell.
    pub copy_pointer_cell: u32,
    /// Flash-status structure referenced by the native page helper.
    pub flash_status_cell: u32,
    /// Spans selected when the caller starts at 0x10000 with a full 2 MiB image.
    /// These do not establish that the caller actually chooses those arguments.
    pub preserving_boot_spans: [Range<usize>; 2],
}

const RAM_WORDS: [usize; 5] = [0x348, 0x350, 0x358, 0x7c4, 0x7cc];
const STATUS_WORDS: [usize; 3] = [0x35c, 0x360, 0x7dc];
const WIDE_RAM_WORDS: [usize; 5] = [0x374, 0x37c, 0x384, 0x7f0, 0x7f8];
const WIDE_STATUS_WORDS: [usize; 3] = [0x388, 0x38c, 0x808];
const NO_PRELUDE_RAM_WORDS: [usize; 5] = [0x358, 0x360, 0x368, 0x7d4, 0x7dc];
const NO_PRELUDE_STATUS_WORDS: [usize; 3] = [0x36c, 0x370, 0x7ec];

/// Select one complete known programming-loop form, rejecting ambiguity.
pub fn inspect_program_loop(bytes: &[u8]) -> Option<ProgramLoopEvidence> {
    match (
        inspect_compact_program_loop(bytes),
        inspect_wide_program_loop(bytes),
        inspect_wide_without_prelude(bytes),
    ) {
        (Some(proof), None, None) | (None, Some(proof), None) | (None, None, Some(proof)) => {
            Some(proof)
        }
        _ => None,
    }
}

fn inspect_wide_without_prelude(bytes: &[u8]) -> Option<ProgramLoopEvidence> {
    inspect(
        bytes,
        without_prelude::WIDE_WITHOUT_PRELUDE,
        &NO_PRELUDE_RAM_WORDS,
        &NO_PRELUDE_STATUS_WORDS,
        ProgramLoopVariant::WideWithoutPrelude,
        0x1c8000,
    )
}

/// Match all instructions, branch operands, hardware literals and skip constants
/// of the shared compact loop. Only five distinct aligned RAM pointer cells and
/// three distinct status addresses may relocate within their proven regions.
/// `bytes` must start at the loop prologue; no model or source hash is used.
pub fn inspect_compact_program_loop(bytes: &[u8]) -> Option<ProgramLoopEvidence> {
    inspect(
        bytes,
        super::super::mixed::COMPACT_PROGRAM,
        &RAM_WORDS,
        &STATUS_WORDS,
        ProgramLoopVariant::Compact,
        0x1d0000,
    )
}

fn inspect_wide_program_loop(bytes: &[u8]) -> Option<ProgramLoopEvidence> {
    inspect(
        bytes,
        super::super::mixed::WIDE_PROGRAM,
        &WIDE_RAM_WORDS,
        &WIDE_STATUS_WORDS,
        ProgramLoopVariant::Wide,
        0x1c8000,
    )
}

fn inspect(
    bytes: &[u8],
    expected: &[u16],
    ram_words: &[usize; 5],
    status_words: &[usize; 3],
    variant: ProgramLoopVariant,
    first_end: usize,
) -> Option<ProgramLoopEvidence> {
    let bytes = bytes.get(..expected.len().checked_mul(2)?)?;
    for (index, (actual, expected)) in bytes.chunks_exact(2).zip(expected).enumerate() {
        let at = index * 2;
        if ram_words
            .iter()
            .chain(status_words)
            .any(|&p| (p..p + 4).contains(&at))
        {
            continue;
        }
        if u16::from_le_bytes(actual.try_into().ok()?) != *expected {
            return None;
        }
    }
    let word = |at| Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    let mut ram = [0; 5];
    for (index, &at) in ram_words.iter().enumerate() {
        let value = word(at)?;
        if value & 3 != 0
            || !(0x02000000..0x02010000).contains(&value)
            || ram[..index].contains(&value)
        {
            return None;
        }
        ram[index] = value;
    }
    let mut status = [0; 3];
    for (index, &at) in status_words.iter().enumerate() {
        let value = word(at)?;
        if !(0x01ff0000..0x02000000).contains(&value) || status[..index].contains(&value) {
            return None;
        }
        status[index] = value;
    }
    Some(ProgramLoopEvidence {
        variant,
        destination_cell: ram[0],
        source_offset_cell: ram[1],
        remaining_cell: ram[2],
        copy_pointer_cell: ram[3],
        staging_cell: ram[4],
        flash_status_cell: status[2],
        preserving_boot_spans: [0x10000..first_end, 0x1ec000..0x1f0000],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELD: &[u8] = include_bytes!("../../../tests/fixtures/analysis/uh12-program.bin");
    const WIDE: &[u8] = include_bytes!("../../../tests/fixtures/analysis/bp55-program.bin");
    const NO_PRELUDE: &[u8] = include_bytes!("../../../tests/fixtures/analysis/wh16-program.bin");

    #[test]
    fn wide_loop_without_prelude_binds_complete_native_code_and_reserved_spans() {
        let proof = inspect_program_loop(NO_PRELUDE).unwrap();
        assert_eq!(proof.variant, ProgramLoopVariant::WideWithoutPrelude);
        assert_eq!(proof.destination_cell, 0x02000c68);
        assert_eq!(proof.source_offset_cell, 0x02000c70);
        assert_eq!(proof.remaining_cell, 0x02000c74);
        assert_eq!(proof.staging_cell, 0x02000c3c);
        assert_eq!(proof.copy_pointer_cell, 0x02000c90);
        assert_eq!(proof.flash_status_cell, 0x01ffc2f8);
        assert_eq!(
            proof.preserving_boot_spans,
            [0x10000..0x1c8000, 0x1ec000..0x1f0000]
        );
        for reserved in
            core::iter::once(crate::layout::BOOT_AREA).chain(crate::layout::DRIVE_WRITTEN)
        {
            assert!(proof
                .preserving_boot_spans
                .iter()
                .all(|span| span.end <= reserved.start || span.start >= reserved.end()));
        }
        assert!(inspect_compact_program_loop(NO_PRELUDE).is_none());
        assert!(inspect_wide_program_loop(NO_PRELUDE).is_none());
        // Every instruction, branch destination and hardware/skip constant is
        // fixed, including code after the page helper's embedded literal pool.
        for at in (0..NO_PRELUDE.len()).step_by(2) {
            if NO_PRELUDE_RAM_WORDS
                .iter()
                .chain(&NO_PRELUDE_STATUS_WORDS)
                .any(|&p| (p..p + 4).contains(&at))
            {
                continue;
            }
            let mut changed = NO_PRELUDE.to_vec();
            changed[at] ^= 1;
            assert!(inspect_program_loop(&changed).is_none(), "{at:#x}");
        }
        for at in NO_PRELUDE_RAM_WORDS {
            let alias = if at == NO_PRELUDE_RAM_WORDS[0] {
                proof.source_offset_cell
            } else {
                proof.destination_cell
            };
            for bad in [0x02000c69u32, 0x04011000, alias] {
                let mut changed = NO_PRELUDE.to_vec();
                changed[at..at + 4].copy_from_slice(&bad.to_le_bytes());
                assert!(inspect_program_loop(&changed).is_none(), "{at:#x}/{bad:#x}");
            }
        }
        assert!(inspect_program_loop(&NO_PRELUDE[..NO_PRELUDE.len() - 1]).is_none());
    }

    #[test]
    fn wide_form_has_distinct_skip_and_role_checked_relocations() {
        let proof = inspect_program_loop(WIDE).unwrap();
        assert_eq!(proof.variant, ProgramLoopVariant::Wide);
        assert_eq!(proof.destination_cell, 0x02000ca4);
        assert_eq!(proof.source_offset_cell, 0x02000cac);
        assert_eq!(proof.remaining_cell, 0x02000cb0);
        assert_eq!(proof.staging_cell, 0x02000c78);
        assert_eq!(proof.copy_pointer_cell, 0x02000ccc);
        assert_eq!(
            proof.preserving_boot_spans,
            [0x10000..0x1c8000, 0x1ec000..0x1f0000]
        );
        assert!(inspect_compact_program_loop(WIDE).is_none());
        for at in (0..WIDE.len()).step_by(2) {
            if WIDE_RAM_WORDS
                .iter()
                .chain(&WIDE_STATUS_WORDS)
                .any(|&p| (p..p + 4).contains(&at))
            {
                continue;
            }
            let mut changed = WIDE.to_vec();
            changed[at] ^= 1;
            assert!(inspect_program_loop(&changed).is_none(), "{at:#x}");
        }
        for bad in [0x02000cacu32, 0x02000ca5, 0x04011000] {
            let mut changed = WIDE.to_vec();
            changed[0x374..0x378].copy_from_slice(&bad.to_le_bytes());
            assert!(inspect_program_loop(&changed).is_none(), "{bad:#x}");
        }
        assert!(inspect_program_loop(&WIDE[..WIDE.len() - 1]).is_none());
    }

    #[test]
    fn relocated_native_loop_preserves_cell_roles() {
        let proof = inspect_compact_program_loop(HELD).unwrap();
        assert_eq!(proof.destination_cell, 0x02000c58);
        assert_eq!(proof.source_offset_cell, 0x02000c60);
        assert_eq!(proof.remaining_cell, 0x02000c64);
        assert_eq!(proof.staging_cell, 0x02000c2c);
        assert_eq!(proof.copy_pointer_cell, 0x02000c80);
        assert_eq!(
            proof.preserving_boot_spans,
            [0x10000..0x1d0000, 0x1ec000..0x1f0000]
        );
        let mut moved = HELD.to_vec();
        for (i, at) in RAM_WORDS.iter().enumerate() {
            moved[*at..*at + 4].copy_from_slice(&(0x02001000u32 + i as u32 * 4).to_le_bytes());
        }
        assert!(inspect_compact_program_loop(&moved).is_some());
    }

    #[test]
    fn every_nonrelocatable_halfword_is_load_bearing() {
        for at in (0..HELD.len()).step_by(2) {
            if RAM_WORDS
                .iter()
                .chain(&STATUS_WORDS)
                .any(|&p| (p..p + 4).contains(&at))
            {
                continue;
            }
            let mut changed = HELD.to_vec();
            changed[at] ^= 1;
            assert!(inspect_compact_program_loop(&changed).is_none(), "{at:#x}");
        }
        assert!(inspect_compact_program_loop(&HELD[..HELD.len() - 1]).is_none());
    }

    #[test]
    fn rejects_cell_aliases_unaligned_cells_and_wrong_memory_roles() {
        for bad in [
            0x02000c60u32,
            0x02000c59,
            0x04011000,
            0x01ff9dd0,
            0xffff_fffc,
        ] {
            let mut changed = HELD.to_vec();
            changed[0x348..0x34c].copy_from_slice(&bad.to_le_bytes());
            assert!(inspect_compact_program_loop(&changed).is_none(), "{bad:#x}");
        }
        let mut changed = HELD.to_vec();
        changed[0x35c..0x360].copy_from_slice(&0x02000c58u32.to_le_bytes());
        assert!(inspect_compact_program_loop(&changed).is_none());
    }
}

//! Complete compact loop matching with role-checked RAM literal relocation.
use core::ops::Range;

/// Evidence for the native mode-three programming loop and raw page copy.
/// This is not an executable receiver contract: the application selection,
/// wrapper arguments, integrity checks and external helpers need binding too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramLoopEvidence {
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
    /// Spans selected when the caller starts at 0x10000 with a full 2 MiB image.
    /// These do not establish that the caller actually chooses those arguments.
    pub preserving_boot_spans: [Range<usize>; 2],
}

const RAM_WORDS: [usize; 5] = [0x348, 0x350, 0x358, 0x7c4, 0x7cc];
const STATUS_WORDS: [usize; 3] = [0x35c, 0x360, 0x7dc];

/// Match all instructions, branch operands, hardware literals and skip constants
/// of the shared compact loop. Only five distinct aligned RAM pointer cells and
/// three distinct status addresses may relocate within their proven regions.
/// `bytes` must start at the loop prologue; no model or source hash is used.
pub fn inspect_compact_program_loop(bytes: &[u8]) -> Option<ProgramLoopEvidence> {
    let expected = super::super::mixed::COMPACT_PROGRAM;
    let bytes = bytes.get(..expected.len().checked_mul(2)?)?;
    for (index, (actual, expected)) in bytes.chunks_exact(2).zip(expected).enumerate() {
        let at = index * 2;
        if RAM_WORDS
            .iter()
            .chain(&STATUS_WORDS)
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
    for (index, &at) in RAM_WORDS.iter().enumerate() {
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
    for (index, &at) in STATUS_WORDS.iter().enumerate() {
        let value = word(at)?;
        if !(0x01ff0000..0x02000000).contains(&value) || status[..index].contains(&value) {
            return None;
        }
        status[index] = value;
    }
    Some(ProgramLoopEvidence {
        destination_cell: ram[0],
        source_offset_cell: ram[1],
        remaining_cell: ram[2],
        copy_pointer_cell: ram[3],
        staging_cell: ram[4],
        preserving_boot_spans: [0x10000..0x1d0000, 0x1ec000..0x1f0000],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELD: &[u8] = include_bytes!("../../../tests/fixtures/analysis/uh12-program.bin");

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

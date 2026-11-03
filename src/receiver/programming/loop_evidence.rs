//! Complete programming-loop matching with role-checked RAM literal relocation.
use core::ops::Range;

/// Complete instruction forms, independent of model names and RAM relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramLoopVariant {
    /// Compact loop with the first reserved span starting at 0x1d0000.
    Compact,
    /// Wider loop with the first reserved span starting at 0x1c8000.
    Wide,
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

/// Select one complete known programming-loop form, rejecting ambiguity.
pub fn inspect_program_loop(bytes: &[u8]) -> Option<ProgramLoopEvidence> {
    match (
        inspect_compact_program_loop(bytes),
        inspect_wide_program_loop(bytes),
    ) {
        (Some(proof), None) | (None, Some(proof)) => Some(proof),
        _ => None,
    }
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
#[path = "loop_evidence_tests.rs"]
mod tests;

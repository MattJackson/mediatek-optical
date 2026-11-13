//! Integrity-coverage extension: grow one AES-CMAC table entry over an
//! adjacent erased span, when the receiver's programming contract proves the
//! drive writes and authenticates that span exactly as the table says.
//!
//! Only used after an allocation failed; input bytes and unused table records
//! are never treated as code space.

use crate::classify::receiver::{analysis::ApplicationAnalysis, decoding::Value, programming};
use crate::envelope::image::cmac;
use crate::envelope::{reserved_ranges, Envelope};
use crate::prepare::receiver::Receiver;

/// An image whose table entry `entry` now ends at `new_end` (from `old_end`),
/// re-signed and verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageExtension {
    /// The re-signed image.
    pub image: Vec<u8>,
    /// Index of the extended table entry.
    pub entry: u32,
    /// The entry's inclusive end before extension.
    pub old_end: u32,
    /// The entry's inclusive end after extension.
    pub new_end: u32,
}

/// The single deterministic coverage extension of `image` into an erased
/// span at or after `code_start`, or `None` when the receiver contract does
/// not bind exactly one programming path to the table, or no span qualifies.
pub fn extend_coverage(image: &[u8], code_start: usize) -> Option<CoverageExtension> {
    if image.len() != 0x200000 || !cmac::verify(image) {
        return None;
    }
    let entries = cmac::parse_table(image).ok()?;
    if entries
        .iter()
        .any(|e| !matches!(e.enabled, 0 | 1 | u32::MAX))
    {
        return None;
    }
    let analysis = ApplicationAnalysis::inspect(image, 0)?;
    if analysis.conflicting_arguments() {
        return None;
    }
    let envelope = Envelope::load(image).ok()?;
    let receiver = Receiver::from_firmware(&envelope).ok()?;
    let mut bindings = analysis.ranges().iter().filter_map(|range| {
        let tail = range.acceptance.as_ref()?;
        let frame = range.state_slot.as_ref()?;
        if !(frame.prologue..tail.continuation).contains(&receiver.signature_address()) {
            return None;
        }
        let binding = programming::inspect_mode_three_wrapper(image, 0, tail.program_target)?;
        if binding.program.destination_cell != range.selection.offset_cell
            || binding.program.source_offset_cell != range.selection.start_cell
            || binding.program.remaining_cell != range.selection.length_cell
        {
            return None;
        }
        let staged = binding.program.staging_cell;
        let decoded = range.signature.is_some_and(|p| p.staging_cell == staged)
            || analysis.bulk_decoders().iter().any(|p| {
                p.selection_address == range.selection.address
                    && p.from_zero.source
                        == (Value::Loaded {
                            cell: staged,
                            offset: 0,
                        })
            });
        if !decoded {
            return None;
        }
        let check = analysis
            .integrity_selections()
            .iter()
            .find(|p| p.success == tail.address)?;
        programming::inspect_integrity_walker(image, 0, check.application_check, staged)?;
        Some(binding)
    });
    let binding = bindings.next()?;
    if bindings.next().is_some() {
        return None;
    }
    let reserved = reserved_ranges();
    let mut best: Option<(usize, usize, usize)> = None;
    for window in &binding.program.preserving_boot_spans {
        let mut at = window.start.max(code_start);
        while at < window.end {
            if image[at] != 0xff {
                at += 1;
                continue;
            }
            let start = at;
            while at < window.end && image[at] == 0xff {
                at += 1;
            }
            let end = at & !15;
            let aligned = (start + 3) & !3;
            if aligned >= end {
                continue;
            }
            for entry in &entries {
                if !entry.is_active() || entry.covers_table() {
                    continue;
                }
                let old_end = (entry.end as usize).checked_add(1)?;
                if old_end > start
                    || old_end < window.start
                    || entry.start & 15 != 0
                    || old_end & 15 != 0
                {
                    continue;
                }
                if reserved.iter().any(|r| old_end < r.end && end > r.start)
                    || entries.iter().any(|e| {
                        e.index != entry.index
                            && e.enabled != u32::MAX
                            && e.start <= e.end
                            && old_end <= e.end as usize
                            && end > e.start as usize
                    })
                {
                    continue;
                }
                let candidate = (end - aligned, entry.index, end - 1);
                if best.map_or(true, |previous| candidate.0 > previous.0) {
                    best = Some(candidate);
                }
            }
        }
    }
    let (_, index, new_end) = best?;
    let entry = entries.get(index)?;
    let mut output = image.to_vec();
    output[entry.entry_off + 8..entry.entry_off + 12]
        .copy_from_slice(&(new_end as u32).to_le_bytes());
    let output = cmac::resign(&output).ok()?;
    if !cmac::verify(&output) {
        return None;
    }
    Some(CoverageExtension {
        image: output,
        entry: index as u32,
        old_end: entry.end,
        new_end: new_end as u32,
    })
}

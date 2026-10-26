//! Immutable application receiver evidence collected from one code snapshot.
//!
//! Discovery is deliberately separate from an executable transfer contract.
//! A scratch decoder and direct plaintext comparison do not, by themselves,
//! prove the complete integrity/programming path or authorize a write.
use super::{
    decoding::{self, Call, Value},
    programming::{self, IntegritySelection, PlainSignature, Selection},
};

/// Range selection and the immediately following direct signature comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedRange {
    /// Operand-bound range selection.
    pub selection: Selection,
    /// Present only if the uninterrupted direct comparison grammar matches.
    pub signature: Option<PlainSignature>,
    /// Unique checked acceptance tail using these selection cells. Reachability
    /// from the signature loop and helper semantics are separate obligations.
    pub acceptance: Option<programming::AcceptanceTail>,
}

#[cfg(test)]
mod bulk_acceptance_tests {
    use super::*;
    const BASE: u32 = 0xa5288;
    const HELD: &[u8] = include_bytes!("../../tests/fixtures/analysis/uh12-application.bin");

    #[test]
    fn bulk_decoder_and_integrity_bind_the_selected_programming_tail() {
        let analysis = ApplicationAnalysis::inspect(HELD, BASE).unwrap();
        assert_eq!(analysis.ranges().len(), 1);
        assert_eq!(analysis.bulk_decoders().len(), 1);
        assert_eq!(analysis.integrity_selections().len(), 1);
        let tail = analysis.ranges()[0].acceptance.unwrap();
        assert_eq!(tail.program_target, 0x17c44e);
        assert_eq!(tail.program_call, 0xa7942);
        for address in [0xa77ea, 0xa78ca, 0xa78f4, 0xa7938, 0xa7940] {
            let mut changed = HELD.to_vec();
            changed[(address - BASE) as usize] ^= 1;
            let analysis = ApplicationAnalysis::inspect(&changed, BASE).unwrap();
            assert!(analysis.ranges()[0].acceptance.is_none(), "{address:#x}");
        }
        let mut changed = HELD.to_vec();
        changed[(0xa7942 - BASE) as usize] ^= 1;
        let changed = ApplicationAnalysis::inspect(&changed, BASE).unwrap();
        assert_ne!(changed.ranges()[0].acceptance, Some(tail));
    }
}

/// A scratch header call and in-place body call sharing the same pointer cell
/// and AES routine. Both selected-start policies are traced independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkDecode {
    /// Range-selection block whose two starts supplied these decode calls.
    pub selection_address: u32,
    /// Scratch header input/output evidence.
    pub header: Call,
    /// Body call when the selected start is zero.
    pub from_zero: Call,
    /// Body call when boot is preserved. Its footprint may exceed image size;
    /// consumers must not silently clip it to uploaded bytes.
    pub preserving_boot: Call,
}

/// Read-only evidence retained by the loaded application receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationAnalysis {
    ranges: Vec<SelectedRange>,
    integrity: Vec<IntegritySelection>,
    scratch: Vec<Call>,
    bulk: Vec<BulkDecode>,
    conflicting_arguments: bool,
}

impl ApplicationAnalysis {
    /// Analyze a bounded application code snapshot once. No firmware target,
    /// filename, model or version string contributes to the result.
    pub fn inspect(bytes: &[u8], base: u32) -> Option<Self> {
        if base & 1 != 0 {
            return None;
        }
        let end = base.checked_add(u32::try_from(bytes.len()).ok()?)?;
        let mut ranges = Vec::new();
        let mut integrity = Vec::new();
        for address in (base..end).step_by(2) {
            if let Some(selection) = programming::inspect_selection(bytes, base, address) {
                let signature = programming::inspect_plain_signature(bytes, base, &selection);
                ranges.push(SelectedRange {
                    selection,
                    signature,
                    acceptance: None,
                });
            }
            if let Some(proof) = programming::inspect_legacy_integrity(bytes, base, address) {
                integrity.push(proof);
            }
        }
        let mut scratch: Vec<Call> = Vec::new();
        let mut conflicting_arguments = false;
        for range in &mut ranges {
            let Some(signature) = range.signature else {
                continue;
            };
            let mut candidates = integrity.iter().filter_map(|checks| {
                if checks.address < signature.success
                    || checks.address.checked_sub(signature.success)? > 1024
                {
                    return None;
                }
                programming::inspect_acceptance_tail(
                    bytes,
                    base,
                    &range.selection,
                    &signature,
                    checks,
                )
            });
            let first = candidates.next();
            if candidates.next().is_some() {
                conflicting_arguments = true;
            } else {
                range.acceptance = first;
            }
        }
        for range in &ranges {
            let Some(signature) = range.signature else {
                continue;
            };
            // The signature grammar independently establishes which RAM cell
            // holds staged bytes. Trace candidate setups without treating every
            // RAM load as a staging pointer. Reachability remains unproven here.
            let first = range.selection.address.saturating_sub(512).max(base);
            for start in (first..range.selection.address).step_by(2) {
                let Some(call) =
                    decoding::trace_call(bytes, base, start, [Value::Unknown; 8], |a| {
                        (a == Value::Constant(signature.staging_cell)).then_some(Value::Staging(0))
                    })
                else {
                    continue;
                };
                if call.address >= range.selection.address
                    || call.length != 16
                    || call.source != Value::Staging(0x3000)
                    || !matches!(call.destination, Value::Stack(_))
                {
                    continue;
                }
                let Some(offset) = call
                    .target
                    .checked_sub(base)
                    .and_then(|x| usize::try_from(x).ok())
                else {
                    continue;
                };
                let Some(routine) = bytes.get(offset..) else {
                    continue;
                };
                if !super::matches(routine, super::AES) {
                    continue;
                }
                if let Some(previous) = scratch.iter().find(|c| c.address == call.address) {
                    // r3 is not an AES argument. Different tracing start points
                    // can establish different irrelevant r3 facts.
                    conflicting_arguments |= previous.target != call.target
                        || previous.source != call.source
                        || previous.destination != call.destination
                        || previous.length != call.length;
                } else {
                    scratch.push(call);
                }
            }
        }
        scratch.sort_by_key(|c| c.address);
        let mut bulk = Vec::new();
        for range in &ranges {
            let trace = |start| {
                decoding::trace_call(bytes, base, range.selection.end, [Value::Unknown; 8], |a| {
                    match a {
                        Value::Constant(cell) if cell == range.selection.start_cell => {
                            Some(Value::Constant(start))
                        }
                        Value::Constant(cell)
                            if cell & 3 == 0 && (0x02000000..0x02010000).contains(&cell) =>
                        {
                            Some(Value::Loaded { cell, offset: 0 })
                        }
                        _ => None,
                    }
                })
            };
            let (Some(from_zero), Some(preserving_boot)) = (trace(0), trace(0x10000)) else {
                continue;
            };
            let Value::Loaded { cell, offset: 0 } = from_zero.source else {
                continue;
            };
            if from_zero.destination != from_zero.source
                || from_zero.length != 0x200000
                || preserving_boot.address != from_zero.address
                || preserving_boot.target != from_zero.target
                || preserving_boot.length != from_zero.length
                || preserving_boot.source
                    != (Value::Loaded {
                        cell,
                        offset: 0x10000,
                    })
                || preserving_boot.destination != preserving_boot.source
            {
                continue;
            }
            let Some(offset) = from_zero
                .target
                .checked_sub(base)
                .and_then(|x| usize::try_from(x).ok())
            else {
                continue;
            };
            if !bytes
                .get(offset..)
                .is_some_and(|routine| super::matches(routine, super::AES))
            {
                continue;
            }
            let first = range.selection.address.saturating_sub(512).max(base);
            let mut header: Option<Call> = None;
            let mut ambiguous = false;
            for start in (first..range.selection.address).step_by(2) {
                let Some(call) =
                    decoding::trace_call(bytes, base, start, [Value::Unknown; 8], |a| {
                        (a == Value::Constant(cell)).then_some(Value::Loaded { cell, offset: 0 })
                    })
                else {
                    continue;
                };
                if call.address >= range.selection.address
                    || call.target != from_zero.target
                    || call.source
                        != (Value::Loaded {
                            cell,
                            offset: 0x3000,
                        })
                    || call.length != 16
                    || !matches!(call.destination, Value::Stack(_))
                {
                    continue;
                }
                if let Some(previous) = header {
                    ambiguous |= previous.address != call.address
                        || previous.destination != call.destination;
                } else {
                    header = Some(call);
                }
            }
            if ambiguous {
                conflicting_arguments = true;
            } else if let Some(header) = header {
                bulk.push(BulkDecode {
                    selection_address: range.selection.address,
                    header,
                    from_zero,
                    preserving_boot,
                });
            }
        }
        for range in &mut ranges {
            if range.signature.is_some() {
                continue;
            }
            let mut candidates = bulk
                .iter()
                .filter(|decode| decode.selection_address == range.selection.address)
                .flat_map(|decode| {
                    let cell = match decode.from_zero.source {
                        Value::Loaded { cell, offset: 0 } => cell,
                        _ => return Vec::new(),
                    };
                    integrity
                        .iter()
                        .filter_map(|checks| {
                            if checks.address <= decode.from_zero.address
                                || checks.address.checked_sub(decode.from_zero.address)? > 1024
                            {
                                return None;
                            }
                            programming::inspect_acceptance_with_staging(
                                bytes,
                                base,
                                &range.selection,
                                cell,
                                checks,
                            )
                        })
                        .collect::<Vec<_>>()
                });
            let first = candidates.next();
            if candidates.next().is_some() {
                conflicting_arguments = true;
            } else {
                range.acceptance = first;
            }
        }
        Some(Self {
            ranges,
            integrity,
            scratch,
            bulk,
            conflicting_arguments,
        })
    }

    /// All matched range selections, retaining missing signature evidence.
    pub fn ranges(&self) -> &[SelectedRange] {
        &self.ranges
    }
    /// Matched integrity-selection blocks; checker semantics remain separate.
    pub fn integrity_selections(&self) -> &[IntegritySelection] {
        &self.integrity
    }
    /// Argument-traced scratch header decoder calls, not whole-image decoders.
    pub fn scratch_decoders(&self) -> &[Call] {
        &self.scratch
    }
    /// Whether candidate traces disagree about a decoder's actual arguments.
    pub fn conflicting_arguments(&self) -> bool {
        self.conflicting_arguments
    }
    /// Positive header/body call evidence. An empty result never means that
    /// the receiver accepts plaintext; incomplete grammars remain unknown.
    pub fn bulk_decoders(&self) -> &[BulkDecode] {
        &self.bulk
    }
}

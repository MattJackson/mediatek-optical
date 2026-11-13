//! Receiver-bound preparation, immutable entry/encoding selection and
//! pre-write receiver revalidation.
use super::{Encoding, Receiver};
use crate::{envelope::Envelope, prepare::update};

pub(crate) use crate::prepare::update::ExecutionMode;

/// An update prepared for the receiver that will accept its bytes.
/// The transfer format cannot be overridden by a caller.
#[derive(Debug)]
pub struct PreparedUpdate {
    pub(crate) plan: TransferPlan,
}

/// Header and body representation on the wire, derived from receiver code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferEncoding {
    /// The 16-byte transport header at image offset 0x3000.
    pub header: Encoding,
    /// The image body accepted by the receiver.
    pub body: Encoding,
}

/// Immutable encoding, entry sequence, host policy and receiver binding for
/// one Flash or Recovery operation.
#[derive(Debug, Clone)]
pub struct TransferPlan {
    pub(crate) receiver: Receiver,
    pub(crate) class: crate::DriveClass,
    pub(crate) image: Vec<u8>,
    pub(crate) transfer: Option<Vec<u8>>,
    pub(crate) encoding: TransferEncoding,
    pub(crate) prepare: crate::cdb::Prepare,
    pub(crate) mode: ExecutionMode,
}

impl Receiver {
    /// Bind an already validated update to this receiver without decoding or
    /// repeating image integrity and installed-family analysis.
    pub fn bind_prepared(
        &self,
        update: &update::ValidatedUpdate,
    ) -> Result<PreparedUpdate, crate::Refusal> {
        Ok(PreparedUpdate {
            plan: TransferPlan::new(self, update.image(), update.class(), ExecutionMode::Flash)?,
        })
    }

    /// Prepare with explicit unavailable installed-image evidence. The host
    /// owns consent; target integrity, chip and receiver gates remain mandatory.
    pub fn prepare_without_installed(
        &self,
        envelope: &Envelope,
        live: &crate::Identity,
    ) -> Result<PreparedUpdate, crate::Refusal> {
        let update = update::ValidatedUpdate::prepare_without_installed(envelope.image(), live)?;
        self.bind_prepared(&update)
    }

    /// Apply normal Flash image/hardware gates, then select wire encoding from
    /// the positively identified running receiver, regardless of input format.
    /// This does not perform I/O or waive the caller's backup/consent policy.
    ///
    /// Every check that needs no I/O runs here, so there is no separate plan
    /// check (Pioneer's `check_plan`): a returned [`PreparedUpdate`] has
    /// passed all of them and its execution mode is fixed; execution only
    /// revalidates the live receiver before writing.
    pub fn prepare(
        &self,
        envelope: &Envelope,
        installed: &crate::classify::InstalledFirmware,
    ) -> Result<PreparedUpdate, crate::Refusal> {
        // InstalledFirmware is bound by its descriptor and/or BOOT banner;
        // its INQUIRY may deliberately be absent for offline gate evidence.
        // The executable plan separately binds and revalidates live INQUIRY.
        let update = update::ValidatedUpdate::prepare(envelope.image(), installed)?;
        self.bind_prepared(&update)
    }
}

impl PreparedUpdate {
    /// Inspect the immutable execution plan.
    pub fn plan(&self) -> &TransferPlan {
        &self.plan
    }
}

fn wire(image: &[u8], operations: &[super::layout::Operation]) -> Result<Vec<u8>, crate::Refusal> {
    let layout = super::layout::analyze(image.len(), operations).map_err(crate::Refusal::Layout)?;
    layout.encode(image).map_err(crate::Refusal::Layout)
}

// The receiver code does not establish an executable transfer contract.
const RECEIVER_EVIDENCE: crate::Refusal = crate::Refusal::ReceiverContract {
    reason: crate::envelope::refusal::ContractReason::ReceiverEvidence,
};

// Both Flash and Recovery use this decision. A recognized scratch decoder must
// never fall back to whole-image encryption merely because it calls AES.
fn encode_transfer(
    receiver: &Receiver,
    image: &[u8],
) -> Result<(Option<Vec<u8>>, TransferEncoding, bool), crate::Refusal> {
    if let Some(analysis) = receiver.application_analysis() {
        if analysis.conflicting_arguments() {
            return Err(RECEIVER_EVIDENCE);
        }
        if !analysis.scratch_decoders().is_empty() {
            let contract = receiver
                .profile
                .as_ref()
                .and_then(|p| p.mixed.as_ref())
                .ok_or(RECEIVER_EVIDENCE)?;
            if image.get(contract.descriptor_byte()) != Some(&0xde) {
                return Err(crate::Refusal::ReceiverContract {
                    reason: crate::envelope::refusal::ContractReason::DescriptorByte,
                });
            }
            use super::layout::Operation;
            let mut operations = vec![Operation::CheckDecrypted(contract.header_range())];
            // Integrity reads must never consume encrypted staging bytes. The
            // matched preservation branch excludes the separate boot CMAC.
            // Callers reach this only after `cmac::verify` accepted the image,
            // so every entry is either active or unused (`is_active` suffices).
            for entry in crate::envelope::image::cmac::parse_table(image)
                .map_err(|_| crate::Refusal::Integrity)?
                .into_iter()
                .filter(|entry| entry.is_active())
            {
                let range = entry.start as usize..entry.end as usize + 1;
                if !contract.programmed_ranges().iter().any(|programmed| {
                    programmed.start <= range.start && programmed.end >= range.end
                }) {
                    // A complete input cannot require changed authenticated
                    // bytes in a region this receiver deliberately preserves.
                    return Err(crate::Refusal::ReceiverContract {
                        reason: crate::envelope::refusal::ContractReason::PreservedRange,
                    });
                }
                operations.push(Operation::CheckPlaintext(range));
            }
            for range in contract.programmed_ranges() {
                operations.push(Operation::Program(range.clone()));
            }
            let wire = wire(image, &operations)?;
            return Ok((
                Some(wire),
                TransferEncoding {
                    header: Encoding::Encrypted,
                    body: Encoding::Plaintext,
                },
                true,
            ));
        }
        if receiver.encoding() == Encoding::Encrypted {
            let [bulk] = analysis.bulk_decoders() else {
                return Err(RECEIVER_EVIDENCE);
            };
            use crate::classify::receiver::decoding::Value;
            let Value::Loaded { cell, offset: 0 } = bulk.from_zero.source else {
                return Err(RECEIVER_EVIDENCE);
            };
            if bulk.from_zero.destination != bulk.from_zero.source
                || bulk.from_zero.length as usize != image.len()
                || bulk.header.source
                    != (Value::Loaded {
                        cell,
                        offset: 0x3000,
                    })
                || bulk.header.length != 16
                || !matches!(bulk.header.destination, Value::Stack(_))
                || bulk.header.target != bulk.from_zero.target
            {
                return Err(RECEIVER_EVIDENCE);
            }
            let mut wire = image.to_vec();
            // The checked start-zero body call consumes precisely this range.
            crate::envelope::enc::encrypt(&mut wire)
                .map_err(|_| crate::Refusal::Size(image.len()))?;
            return Ok((
                Some(wire),
                TransferEncoding {
                    header: Encoding::Encrypted,
                    body: Encoding::Encrypted,
                },
                false,
            ));
        }
        if !analysis.bulk_decoders().is_empty() {
            return Err(RECEIVER_EVIDENCE);
        }
    }
    // BOOT and direct-plaintext receivers retain their existing positive
    // detection while their complete path analysis is integrated separately.
    if receiver.encoding() == Encoding::Encrypted {
        let mut wire = image.to_vec();
        crate::envelope::enc::encrypt(&mut wire).map_err(|_| crate::Refusal::Size(image.len()))?;
        Ok((
            Some(wire),
            TransferEncoding {
                header: Encoding::Encrypted,
                body: Encoding::Encrypted,
            },
            false,
        ))
    } else {
        Ok((
            None,
            TransferEncoding {
                header: Encoding::Plaintext,
                body: Encoding::Plaintext,
            },
            false,
        ))
    }
}

impl TransferPlan {
    pub(crate) fn new(
        receiver: &Receiver,
        image: &[u8],
        class: crate::DriveClass,
        mode: ExecutionMode,
    ) -> Result<Self, crate::Refusal> {
        let profile = receiver
            .profile
            .as_ref()
            .ok_or(crate::Refusal::ReceiverEntry)?;
        let image_chip = crate::Chip::from_banner(
            crate::envelope::layout::BANNER
                .of(image)
                .ok_or(crate::Refusal::UnknownChip)?,
        )
        .ok_or(crate::Refusal::UnknownChip)?;
        if image_chip != profile.chip {
            // A user-supplied reference's profile comes from the file, whose
            // chip need not be the drive's: the update and recovery chip gates
            // have already matched the image to the live drive, so this is the
            // file's receiver contract refusing the image.
            if receiver.provenance() == super::reference::Provenance::UserSuppliedReference {
                return Err(crate::Refusal::ReceiverContract {
                    reason: crate::envelope::refusal::ContractReason::ReferenceChip,
                });
            }
            return Err(crate::Refusal::ChipMismatch {
                image: image_chip,
                drive: profile.chip,
            });
        }
        if class.verification_ranges(image).is_empty() {
            return Err(crate::Refusal::Integrity);
        }
        let mut prepare = profile.prepare;
        let (transfer, encoding, preserve_boot) = encode_transfer(receiver, image)?;
        if preserve_boot {
            use crate::cdb::Prepare;
            prepare = match prepare {
                Prepare::ModeOne | Prepare::ModeOnePreserveBoot => Prepare::ModeOnePreserveBoot,
                Prepare::ModeSix67 | Prepare::ModeSix67PreserveBoot => {
                    Prepare::ModeSix67PreserveBoot
                }
            };
        }
        Ok(Self {
            receiver: receiver.clone(),
            class,
            image: image.to_vec(),
            transfer,
            encoding,
            prepare,
            mode,
        })
    }

    /// Actual header and body formats; an AES header does not imply an AES body.
    pub fn encoding(&self) -> TransferEncoding {
        self.encoding
    }

    /// Programmed image spans when the receiver's complete programming-loop
    /// signature establishes them. `None` means no complete span inventory,
    /// not that every image byte will be written.
    pub fn programmed_ranges(&self) -> Option<&[core::ops::Range<usize>]> {
        self.receiver
            .profile
            .as_ref()?
            .mixed
            .as_ref()
            .map(|contract| contract.programmed_ranges())
    }

    /// Regions explicitly preserved by a known programming-loop contract.
    /// These retain installed bytes and are not claimed to match the target.
    pub fn preserved_ranges(&self) -> Option<Vec<core::ops::Range<usize>>> {
        let programmed = self.programmed_ranges()?;
        let mut preserved = Vec::new();
        let mut end = 0;
        for range in programmed {
            if end < range.start {
                preserved.push(end..range.start);
            }
            end = range.end;
        }
        if end < self.image.len() {
            preserved.push(end..self.image.len());
        }
        Some(preserved)
    }

    /// Receiver-derived PREPARE dialect, fixed at preparation.
    pub fn prepare_command(&self) -> crate::cdb::Prepare {
        self.prepare
    }
    /// Controller dialect retained by the validated update.
    pub fn class(&self) -> crate::DriveClass {
        self.class
    }
    /// Active receiver whose instructions determine the wire format.
    pub fn receiver(&self) -> &Receiver {
        &self.receiver
    }
    /// Canonical bytes used for protected readback verification.
    pub fn image(&self) -> &[u8] {
        &self.image
    }
    /// Actual bytes sent to the running receiver.
    pub fn transfer(&self) -> &[u8] {
        self.transfer.as_deref().unwrap_or(&self.image)
    }
    /// Ordered session commands from the current shared executor.
    pub fn steps(&self) -> std::vec::Vec<update::Step> {
        let mut steps = self.class.steps();
        if self.mode == ExecutionMode::Recovery {
            // Recovery enters directly: the application-only PROBE and
            // readiness preconditions must not block a BOOT receiver.
            steps.drain(..2);
        }
        for step in &mut steps {
            if step.label == "PREPARE" {
                step.cdb = self.prepare.command();
            }
        }
        steps
    }
}

#[cfg(test)]
#[path = "prepared_tests.rs"]
mod tests;

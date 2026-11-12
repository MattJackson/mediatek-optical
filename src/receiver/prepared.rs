//! Receiver-bound preparation, immutable entry/encoding selection and
//! pre-write receiver revalidation.
use super::{Encoding, Receiver};
use crate::{envelope::Envelope, update};

/// An update prepared for the receiver that will accept its bytes.
/// The transfer format cannot be overridden by a caller.
#[derive(Debug)]
pub struct PreparedUpdate {
    plan: TransferPlan,
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
    receiver: Receiver,
    class: crate::DriveClass,
    image: Vec<u8>,
    transfer: Option<Vec<u8>>,
    encoding: TransferEncoding,
    prepare: crate::cdb::Prepare,
    mode: update::flash::ExecutionMode,
}

/// Receiver revalidation or execution failed.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::receiver::ExecutionError<()>) -> u8 { match e { mediatek_optical::receiver::ExecutionError::Receiver { .. } => 0, mediatek_optical::receiver::ExecutionError::Flash { .. } => 1, } }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecutionError<E> {
    /// No write was attempted because the receiver could not be revalidated.
    Receiver(super::Error<E>),
    /// The shared transfer/verification engine failed.
    Flash(update::FlashError<E>),
}

impl<E> ExecutionError<E> {
    /// Firmware data may have been sent to the drive. `false` for a receiver
    /// revalidation refusal and for a failed update entry (PROBE, TEST UNIT
    /// READY or PREPARE), which send no firmware data; `true` for every later
    /// failure, which may leave partial or unverified firmware.
    pub fn firmware_write_started(&self) -> bool {
        match self {
            Self::Receiver(_) => false,
            Self::Flash(error) => error.firmware_write_started(),
        }
    }

    /// Any device mutation may have been attempted. MediaTek execution writes
    /// no settings separately from the firmware, so this equals
    /// [`Self::firmware_write_started`].
    pub fn write_started(&self) -> bool {
        self.firmware_write_started()
    }

    /// The boundary which failed, suitable for operation diagnostics:
    /// `"receiver binding"`, `"update entry"`, `"firmware transfer"`,
    /// `"target startup"` or `"readback"`. Diagnostic text, not a parsing
    /// contract; route on [`crate::CodedError::code`].
    pub fn phase(&self) -> &'static str {
        match self {
            Self::Receiver(_) => "receiver binding",
            Self::Flash(error) => error.phase(),
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for ExecutionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Receiver(error) => {
                write!(f, "receiver revalidation failed before writing: {error}")
            }
            Self::Flash(error) => write!(f, "{error}"),
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for ExecutionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Receiver(source) => Some(source),
            Self::Flash(source) => Some(source),
        }
    }
}

impl Receiver {
    /// Bind an already validated update to this receiver without decoding or
    /// repeating image integrity and installed-family analysis.
    pub fn bind_prepared(
        &self,
        update: &update::ValidatedUpdate,
    ) -> Result<PreparedUpdate, update::PreparationError> {
        Ok(PreparedUpdate {
            plan: TransferPlan::new(
                self,
                update.image(),
                update.class(),
                update::flash::ExecutionMode::Flash,
            )?,
        })
    }

    /// Prepare with explicit unavailable installed-image evidence. The host
    /// owns consent; target integrity, chip and receiver gates remain mandatory.
    pub fn prepare_without_installed(
        &self,
        envelope: &Envelope,
        live: &crate::Identity,
    ) -> Result<PreparedUpdate, update::PreparationError> {
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
        installed: &update::InstalledFirmware,
    ) -> Result<PreparedUpdate, update::PreparationError> {
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
    /// Revalidate, execute, and require the target identity after the write.
    /// An unreadable protected region is retained as limited verification,
    /// never full success. Hosts must check [`update::Startup::evidence`]:
    /// [`update::StartupEvidence::Unobserved`] means the restart into the
    /// target was not observed and is not confirmed startup.
    pub fn flash_completed<R, W, H>(
        &self,
        io: update::FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<update::FlashOutcome, ExecutionError<W::Error>>
    where
        W: crate::drive::Transport,
        R: crate::drive::Transport<Error = W::Error>,
        H: update::ExecutionRuntime<W::Error>,
    {
        self.plan.execute_completed(io, runtime)
    }
}

fn wire(
    image: &[u8],
    operations: &[super::layout::Operation],
) -> Result<Vec<u8>, update::PreparationError> {
    let layout = super::layout::analyze(image.len(), operations)
        .map_err(update::PreparationError::Layout)?;
    layout
        .encode(image)
        .map_err(update::PreparationError::Layout)
}

// The receiver code does not establish an executable transfer contract.
const RECEIVER_EVIDENCE: update::PreparationError = update::PreparationError::ReceiverContract {
    reason: update::ContractReason::ReceiverEvidence,
};

// Both Flash and Recovery use this decision. A recognized scratch decoder must
// never fall back to whole-image encryption merely because it calls AES.
fn encode_transfer(
    receiver: &Receiver,
    image: &[u8],
) -> Result<(Option<Vec<u8>>, TransferEncoding, bool), update::PreparationError> {
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
                return Err(update::PreparationError::ReceiverContract {
                    reason: update::ContractReason::DescriptorByte,
                });
            }
            use super::layout::Operation;
            let mut operations = vec![Operation::CheckDecrypted(contract.header_range())];
            // Integrity reads must never consume encrypted staging bytes. The
            // matched preservation branch excludes the separate boot CMAC.
            // Callers reach this only after `cmac::verify` accepted the image,
            // so every entry is either active or unused (`is_active` suffices).
            for entry in crate::image::cmac::parse_table(image)
                .map_err(|_| update::PreparationError::Integrity)?
                .into_iter()
                .filter(|entry| entry.is_active())
            {
                let range = entry.start as usize..entry.end as usize + 1;
                if !contract.programmed_ranges().iter().any(|programmed| {
                    programmed.start <= range.start && programmed.end >= range.end
                }) {
                    // A complete input cannot require changed authenticated
                    // bytes in a region this receiver deliberately preserves.
                    return Err(update::PreparationError::ReceiverContract {
                        reason: update::ContractReason::PreservedRange,
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
            use super::decoding::Value;
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
            crate::enc::encrypt(&mut wire)
                .map_err(|_| update::PreparationError::Size(image.len()))?;
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
        crate::enc::encrypt(&mut wire).map_err(|_| update::PreparationError::Size(image.len()))?;
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
        mode: update::flash::ExecutionMode,
    ) -> Result<Self, update::PreparationError> {
        let profile = receiver
            .profile
            .as_ref()
            .ok_or(update::PreparationError::ReceiverEntry)?;
        let image_chip = crate::Chip::from_banner(
            crate::layout::BANNER
                .of(image)
                .ok_or(update::PreparationError::UnknownChip)?,
        )
        .ok_or(update::PreparationError::UnknownChip)?;
        if image_chip != profile.chip {
            // A user-supplied reference's profile comes from the file, whose
            // chip need not be the drive's: the update and recovery chip gates
            // have already matched the image to the live drive, so this is the
            // file's receiver contract refusing the image.
            if receiver.provenance() == super::reference::Provenance::UserSuppliedReference {
                return Err(update::PreparationError::ReceiverContract {
                    reason: update::ContractReason::ReferenceChip,
                });
            }
            return Err(update::PreparationError::ChipMismatch {
                image: image_chip,
                drive: profile.chip,
            });
        }
        if class.verification_ranges(image).is_empty() {
            return Err(update::PreparationError::Integrity);
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

    pub(crate) fn execute_completed<R, W, H>(
        &self,
        io: update::FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<update::FlashOutcome, ExecutionError<W::Error>>
    where
        W: crate::drive::Transport,
        R: crate::drive::Transport<Error = W::Error>,
        H: update::ExecutionRuntime<W::Error>,
    {
        self.receiver
            .revalidate(io.reads)
            .map_err(ExecutionError::Receiver)?;
        update::flash::Payload {
            class: self.class,
            image: self.image(),
            transfer: self.transfer(),
        }
        // The identity just revalidated: mode and INQUIRY bytes 8..36 match
        // the physical drive on every path (see `completion::classify`).
        .flash_completed(
            io,
            runtime,
            self.mode,
            self.prepare,
            &self.receiver.identity,
        )
        .map_err(ExecutionError::Flash)
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
        if self.mode == update::flash::ExecutionMode::Recovery {
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

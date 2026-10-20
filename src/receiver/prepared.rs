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
#[derive(Debug)]
pub enum ExecuteError<E> {
    /// No write was attempted because the receiver could not be revalidated.
    Receiver(super::Error<E>),
    /// The shared transfer/verification engine failed.
    Flash(update::FlashError<E>),
}

impl<E: core::fmt::Debug> core::fmt::Display for ExecuteError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Receiver(error) => {
                write!(f, "receiver revalidation failed before writing: {error}")
            }
            Self::Flash(error) => write!(f, "{error}"),
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for ExecuteError<E> {}

impl Receiver {
    /// Bind an already validated update to this receiver without decoding or
    /// repeating image integrity and installed-family analysis.
    pub fn bind_prepared(
        &self,
        update: &update::PreparedUpdate,
    ) -> Result<PreparedUpdate, update::PrepareError> {
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
    ) -> Result<PreparedUpdate, update::PrepareError> {
        let update = update::PreparedUpdate::prepare_without_installed(envelope.image(), live)?;
        self.bind_prepared(&update)
    }

    /// Apply normal Flash image/hardware gates, then select wire encoding from
    /// the positively identified running receiver, regardless of input format.
    /// This does not perform I/O or waive the caller's backup/consent policy.
    pub fn prepare(
        &self,
        envelope: &Envelope,
        installed: &update::InstalledFirmware,
    ) -> Result<PreparedUpdate, update::PrepareError> {
        // InstalledFirmware is bound by its descriptor and/or BOOT banner;
        // its INQUIRY may deliberately be absent for offline gate evidence.
        // The executable plan separately binds and revalidates live INQUIRY.
        let update = update::PreparedUpdate::prepare(envelope.image(), installed)?;
        self.bind_prepared(&update)
    }
}

impl PreparedUpdate {
    /// Inspect the immutable execution plan.
    pub fn plan(&self) -> &TransferPlan {
        &self.plan
    }
    /// Revalidate the bound receiver before entering the shared Flash engine.
    pub fn flash<R, W, H>(
        &self,
        io: update::FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<update::Verified, ExecuteError<W::Error>>
    where
        W: crate::drive::Transport,
        R: crate::drive::Transport<Error = W::Error>,
        H: update::FlashRuntime<W::Error>,
    {
        self.flash_completed(io, runtime)?
            .into_verified()
            .map_err(ExecuteError::Flash)
    }

    /// Revalidate, execute, and confirm exact target startup. An unreadable
    /// protected region is retained as limited verification, never full success.
    pub fn flash_completed<R, W, H>(
        &self,
        io: update::FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<update::Completion, ExecuteError<W::Error>>
    where
        W: crate::drive::Transport,
        R: crate::drive::Transport<Error = W::Error>,
        H: update::FlashRuntime<W::Error>,
    {
        self.plan.execute_completed(io, runtime)
    }
}

// Both Flash and Recovery use this decision. A recognized scratch decoder must
// never fall back to whole-image encryption merely because it calls AES.
fn encode_transfer(
    receiver: &Receiver,
    image: &[u8],
) -> Result<(Option<Vec<u8>>, TransferEncoding, bool), update::PrepareError> {
    if let Some(analysis) = receiver.application_analysis() {
        if analysis.conflicting_arguments() {
            return Err(update::PrepareError::ReceiverContract);
        }
        if !analysis.scratch_decoders().is_empty() {
            let contract = receiver
                .profile
                .as_ref()
                .and_then(|p| p.mixed.as_ref())
                .ok_or(update::PrepareError::ReceiverContract)?;
            if image.get(contract.descriptor_byte()) != Some(&0xde) {
                return Err(update::PrepareError::ReceiverContract);
            }
            use super::layout::Operation;
            let mut operations = vec![Operation::CheckDecrypted(contract.header_range())];
            // Integrity reads must never consume encrypted staging bytes. The
            // matched preservation branch excludes the separate boot CMAC.
            for entry in crate::image::cmac::parse_table(image)
                .map_err(|_| update::PrepareError::Integrity)?
                .into_iter()
                .filter(|entry| entry.is_active())
            {
                let range = entry.start as usize..entry.end as usize + 1;
                if !contract.programmed_ranges().iter().any(|programmed| {
                    programmed.start <= range.start && programmed.end >= range.end
                }) {
                    // A complete input cannot require changed authenticated
                    // bytes in a region this receiver deliberately preserves.
                    return Err(update::PrepareError::ReceiverContract);
                }
                operations.push(Operation::CheckPlaintext(range));
            }
            for range in contract.programmed_ranges() {
                operations.push(Operation::Program(range.clone()));
            }
            let layout = super::layout::analyze(image.len(), &operations)
                .map_err(|_| update::PrepareError::ReceiverContract)?;
            let wire = layout
                .encode(image)
                .map_err(|_| update::PrepareError::ReceiverContract)?;
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
                return Err(update::PrepareError::ReceiverContract);
            };
            use super::decoding::Value;
            let Value::Loaded { cell, offset: 0 } = bulk.from_zero.source else {
                return Err(update::PrepareError::ReceiverContract);
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
                return Err(update::PrepareError::ReceiverContract);
            }
            let mut wire = image.to_vec();
            // The checked start-zero body call consumes precisely this range.
            crate::enc::encrypt(&mut wire).map_err(|_| update::PrepareError::ReceiverContract)?;
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
            return Err(update::PrepareError::ReceiverContract);
        }
    }
    // BOOT and direct-plaintext receivers retain their existing positive
    // detection while their complete path analysis is integrated separately.
    if receiver.encoding() == Encoding::Encrypted {
        let mut wire = image.to_vec();
        crate::enc::encrypt(&mut wire).map_err(|_| update::PrepareError::ReceiverContract)?;
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
    ) -> Result<Self, update::PrepareError> {
        let mut prepare = receiver
            .profile
            .as_ref()
            .ok_or(update::PrepareError::ReceiverEntry)?
            .prepare;
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
    ) -> Result<update::Completion, ExecuteError<W::Error>>
    where
        W: crate::drive::Transport,
        R: crate::drive::Transport<Error = W::Error>,
        H: update::FlashRuntime<W::Error>,
    {
        self.receiver
            .revalidate(io.reads)
            .map_err(ExecuteError::Receiver)?;
        update::flash::Payload {
            class: self.class,
            image: self.image(),
            transfer: self.transfer(),
        }
        .flash_completed(io, runtime, self.mode, self.prepare)
        .map_err(ExecuteError::Flash)
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
mod tests {
    use super::*;
    use crate::{
        fixtures::{self, BU3},
        layout, Identity, INQUIRY_LEN,
    };

    #[test]
    fn input_envelope_never_selects_the_running_receivers_wire_encoding() {
        let image = fixtures::image(&BU3, 7);
        let identity = Identity::parse(
            &[0; INQUIRY_LEN],
            layout::BANNER.of(&image).unwrap(),
            layout::DESCRIPTOR.of(&image).unwrap(),
        )
        .unwrap();
        let installed =
            update::InstalledFirmware::new(identity, &fixtures::drive_read(&image)).unwrap();
        let mut ciphertext = image.clone();
        crate::enc::encrypt(&mut ciphertext).unwrap();
        for encoding in [Encoding::Plaintext, Encoding::Encrypted] {
            let receiver = Receiver {
                identity: super::super::DetectedMode {
                    mode: super::super::Mode::Firmware,
                    inquiry: [0; INQUIRY_LEN],
                },
                encoding,
                site: super::super::Evidence::new(0x98000, &[1, 2]),
                transform: None,
                reference: None,
                profile: Some(super::super::profile::Profile::testing()),
            };
            for input in [&image, &ciphertext] {
                let prepared = receiver
                    .prepare(&Envelope::load(input).unwrap(), &installed)
                    .unwrap();
                assert_eq!(prepared.plan().image(), image);
                assert_eq!(
                    prepared.plan().transfer(),
                    if encoding == Encoding::Encrypted {
                        &ciphertext
                    } else {
                        &image
                    }
                );
                assert_eq!(prepared.plan().receiver(), &receiver);
                let steps = prepared.plan().steps();
                assert_eq!(
                    steps[..3].iter().map(|s| s.label).collect::<Vec<_>>(),
                    ["PROBE", "READY", "PREPARE"]
                );
                let recovery = TransferPlan::new(
                    &receiver,
                    &image,
                    prepared.plan().class(),
                    update::flash::ExecutionMode::Recovery,
                )
                .unwrap();
                let recovery_steps = recovery.steps();
                assert_eq!(recovery_steps[0].label, "PREPARE");
                assert_eq!(recovery_steps.len() + 2, steps.len());
                for (recovery, flash) in recovery_steps.iter().zip(&steps[2..]) {
                    assert_eq!(recovery.cdb, flash.cdb);
                    assert_eq!(recovery.direction, flash.direction);
                    assert_eq!(recovery.length, flash.length);
                }
            }
        }
    }
}

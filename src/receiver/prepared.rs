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

/// Immutable encoding and receiver binding for one normal Flash operation.
#[derive(Debug, Clone)]
pub struct TransferPlan {
    receiver: Receiver,
    class: crate::DriveClass,
    image: Vec<u8>,
    transfer: Option<Vec<u8>>,
    prepare: crate::cdb::Prepare,
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
    /// Apply normal Flash image/hardware gates, then select wire encoding from
    /// the positively identified running receiver, regardless of input format.
    /// This does not perform I/O or waive the caller's backup/consent policy.
    pub fn prepare(
        &self,
        envelope: &Envelope,
        installed: &update::InstalledFirmware,
    ) -> Result<PreparedUpdate, update::PrepareError> {
        if installed.identity().inquiry != self.identity.inquiry {
            return Err(update::PrepareError::InstalledMismatch);
        }
        let update = update::PreparedUpdate::prepare(envelope.image(), installed)?;
        Ok(PreparedUpdate {
            plan: TransferPlan::new(self, envelope.image(), update.class())?,
        })
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
        self.plan
            .execute(io, runtime, update::flash::ExecutionMode::Flash)
    }
}

impl TransferPlan {
    pub(crate) fn new(
        receiver: &Receiver,
        image: &[u8],
        class: crate::DriveClass,
    ) -> Result<Self, update::PrepareError> {
        let prepare = receiver
            .profile
            .as_ref()
            .ok_or(update::PrepareError::ReceiverEntry)?
            .prepare;
        let transfer = if receiver.encoding() == Encoding::Encrypted {
            let mut wire = image.to_vec();
            crate::enc::encrypt(&mut wire).expect("validated image is whole AES blocks");
            Some(wire)
        } else {
            None
        };
        Ok(Self {
            receiver: receiver.clone(),
            class,
            image: image.to_vec(),
            transfer,
            prepare,
        })
    }

    pub(crate) fn execute<R, W, H>(
        &self,
        io: update::FlashTransport<'_, R, W>,
        runtime: &mut H,
        mode: update::flash::ExecutionMode,
    ) -> Result<update::Verified, ExecuteError<W::Error>>
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
        .flash(io, runtime, mode, self.prepare)
        .map_err(ExecuteError::Flash)
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
            }
            let mut changed = receiver.clone();
            changed.identity.inquiry[32] = b'2';
            assert!(matches!(
                changed.prepare(&Envelope::load(&image).unwrap(), &installed),
                Err(update::PrepareError::InstalledMismatch)
            ));
        }
    }
}

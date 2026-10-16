//! Receiver-bound preparation. Entry contracts remain an independent proof
//! obligation; this layer binds encoding and pre-write receiver revalidation.
use super::{Encoding, Receiver};
use crate::{envelope::Envelope, update};

/// An update prepared for the receiver that will accept its bytes.
/// The transfer format cannot be overridden by a caller.
#[derive(Debug)]
pub struct PreparedUpdate {
    plan: TransferPlan,
}

/// Immutable encoding and receiver binding for one normal Flash operation.
/// Entry dialect currently follows the legacy executor; this type does not
/// claim the separate entry-contract proof has been completed.
#[derive(Debug)]
pub struct TransferPlan {
    receiver: Receiver,
    update: update::PreparedUpdate,
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
        let update = update::PreparedUpdate::prepare(envelope.image(), installed)?;
        let update = match self.encoding() {
            Encoding::Plaintext => update,
            Encoding::Encrypted => update.encrypted(),
        };
        Ok(PreparedUpdate {
            plan: TransferPlan {
                receiver: self.clone(),
                update,
            },
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
            .receiver
            .revalidate(io.reads)
            .map_err(ExecuteError::Receiver)?;
        self.plan
            .update
            .flash(io, runtime)
            .map_err(ExecuteError::Flash)
    }
}

impl TransferPlan {
    /// Active receiver whose instructions determine the wire format.
    pub fn receiver(&self) -> &Receiver {
        &self.receiver
    }
    /// Canonical bytes used for protected readback verification.
    pub fn image(&self) -> &[u8] {
        self.update.image()
    }
    /// Actual bytes sent to the running receiver.
    pub fn transfer(&self) -> &[u8] {
        self.update.transfer()
    }
    /// Ordered session commands from the current shared executor.
    pub fn steps(&self) -> std::vec::Vec<update::Step> {
        self.update.steps()
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
        }
    }
}

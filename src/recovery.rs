//! Explicit recovery without installed-firmware, model, family or backup policy.
//! Requires `drive` and `envelope` (`image` + `enc`). Identification and preparation are
//! read-only; the caller owns consent and write authorization.
use crate::update::{ExecutionRuntime, FlashError, FlashTransport, PreparationError};
use crate::{
    drive::{self, Transport},
    image, layout, receiver, Chip, DriveClass,
};

/// A recognized receiver and its live controller generation.
#[derive(Debug, Clone)]
pub struct Receiver {
    receiver: receiver::Receiver,
    chip: Chip,
    banner: [u8; layout::BANNER.len],
}
/// Recovery identification, preparation or execution failed.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::recovery::Error<()>) -> u8 { match e { mediatek_optical::recovery::Error::Receiver { .. } => 0, mediatek_optical::recovery::Error::Reference { .. } => 1, mediatek_optical::recovery::Error::Read { .. } => 2, mediatek_optical::recovery::Error::Image { .. } => 3, mediatek_optical::recovery::Error::Flash { .. } => 4, mediatek_optical::recovery::Error::Changed { .. } => 5, mediatek_optical::recovery::Error::Startup { .. } => 6, } }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
    /// Receiver identification or revalidation failed.
    Receiver(receiver::Error<E>),
    /// Explicit Current reference analysis or metadata binding failed.
    Reference(receiver::reference::Error<E>),
    /// A required device read failed.
    Read(drive::Error<E>),
    /// Image size, integrity, form or chip is unacceptable.
    Image(PreparationError),
    /// Transfer or protected-region verification failed.
    Flash(FlashError<E>),
    /// The live chip/banner changed after identification.
    Changed,
    /// The receiver did not start the selected firmware.
    Startup(crate::update::StartupError<E>),
}
impl<E> Error<E> {
    /// Firmware data may have been sent to the drive: `true` only for
    /// [`Error::Flash`] after update entry and for [`Error::Startup`].
    /// Identification, preparation, revalidation and banner checks precede
    /// every write. As for [`receiver::ExecutionError::firmware_write_started`].
    pub fn firmware_write_started(&self) -> bool {
        match self {
            Self::Receiver(_) | Self::Reference(_) | Self::Read(_) | Self::Image(_) => false,
            Self::Changed => false,
            Self::Flash(error) => error.firmware_write_started(),
            Self::Startup(_) => true,
        }
    }

    /// Any device mutation may have been attempted; recovery writes no
    /// settings, so this equals [`Self::firmware_write_started`].
    pub fn write_started(&self) -> bool {
        self.firmware_write_started()
    }

    /// The boundary which failed, suitable for operation diagnostics:
    /// `"receiver binding"`, `"preflight"` (an unacceptable image),
    /// `"update entry"`, `"firmware transfer"`, `"target startup"` or
    /// `"readback"`. Diagnostic text, not a parsing contract.
    pub fn phase(&self) -> &'static str {
        match self {
            Self::Receiver(_) | Self::Reference(_) | Self::Read(_) | Self::Changed => {
                "receiver binding"
            }
            Self::Image(_) => "preflight",
            Self::Flash(error) => error.phase(),
            Self::Startup(_) => "target startup",
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Receiver(e)=>write!(f,"{e}"), Self::Reference(e)=>write!(f,"{e}"), Self::Read(e)=>write!(f,"{e}"),
            Self::Image(e)=>write!(f,"{e}"), Self::Flash(e)=>write!(f,"{e}"),
            Self::Changed=>f.write_str("MediaTek boot banner changed; re-plan recovery"),
            Self::Startup(e)=>write!(f,"recovery did not confirm startup of the selected firmware; drive may still be in BOOT: {e}"),
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Receiver(source) => Some(source),
            Self::Reference(source) => Some(source),
            Self::Read(source) => Some(source),
            Self::Image(source) => Some(source),
            Self::Flash(source) => Some(source),
            Self::Startup(source) => Some(source),
            Self::Changed => None,
        }
    }
}

impl Receiver {
    /// Recognize a MediaTek receiver without MMC features or application metadata.
    /// Returns `None` when the device does not identify as a MediaTek receiver
    /// (an `InvalidIdentity` INQUIRY shape or a non-MediaTek banner). Reads no backup.
    pub fn identify<T: Transport>(t: &mut T) -> Result<Option<Self>, Error<T::Error>> {
        let mode = match receiver::detect_mode(t) {
            Ok(mode) => mode,
            Err(receiver::Error::InvalidIdentity) => return Ok(None),
            Err(e) => return Err(Error::Receiver(e)),
        };
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner).map_err(Error::Read)?;
        let Some(evidence) = crate::protocol::Evidence::parse(mode.inquiry(), &banner)
            .map_err(|_| Error::Receiver(receiver::Error::InvalidIdentity))?
        else {
            return Ok(None);
        };
        let chip = evidence.identity().chip().ok_or(Error::Changed)?;
        let receiver = receiver::detect(t, &mode).map_err(Error::Receiver)?;
        Ok(Some(Self {
            receiver,
            chip,
            banner,
        }))
    }
    /// Identify using explicit Current firmware when live code cannot be read.
    /// Physical identity and build metadata bind the offline instruction evidence.
    pub fn identify_reference<T: Transport>(
        t: &mut T,
        envelope: &crate::envelope::Envelope,
    ) -> Result<Self, Error<T::Error>> {
        let receiver = receiver::reference::detect(t, envelope).map_err(Error::Reference)?;
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner).map_err(Error::Read)?;
        let chip = Chip::from_banner(&banner).ok_or(Error::Changed)?;
        Ok(Self {
            receiver,
            chip,
            banner,
        })
    }
    /// Identify using user-supplied receiver code when live code is restricted.
    /// The file's identity/build need not match the drive. Its native receiver
    /// contract remains distinct from the live banner/chip and session metadata;
    /// this does not verify equivalence to the running receiver's code.
    pub fn identify_user_supplied_reference<T: Transport>(
        t: &mut T,
        envelope: &crate::envelope::Envelope,
    ) -> Result<Self, Error<T::Error>> {
        let receiver =
            receiver::reference::detect_user_supplied(t, envelope).map_err(Error::Reference)?;
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner).map_err(|error| {
            Error::Reference(receiver::reference::Error::Session(receiver::Error::Read(
                error,
            )))
        })?;
        receiver
            .revalidate(t)
            .map_err(|error| Error::Reference(receiver::reference::Error::Session(error)))?;
        // The banner was just bound by revalidation: no supported chip here
        // is an unsupported drive, not a change since identification.
        let chip =
            Chip::from_banner(&banner).ok_or(Error::Image(PreparationError::UnknownDriveChip))?;
        Ok(Self {
            receiver,
            chip,
            banner,
        })
    }
    /// Active operating mode.
    pub fn mode(&self) -> receiver::Mode {
        self.receiver.mode()
    }
    /// Automatically detected transfer format.
    pub fn encoding(&self) -> receiver::Encoding {
        self.receiver.encoding()
    }
    /// Controller generation from the live boot banner.
    pub fn chip(&self) -> Chip {
        self.chip
    }
    /// Verify identity, receiver evidence and chip/banner before a write.
    ///
    /// INQUIRY identity is read first and again last, after the banner; a
    /// change in between is [`Error::Receiver`] with
    /// [`receiver::Error::Changed`].
    ///
    /// A receiver from [`Receiver::identify_reference`] or
    /// [`Receiver::identify_user_supplied_reference`] re-reads only INQUIRY
    /// identity, the boot banner and build metadata; its instruction evidence
    /// comes from the reference image and is not re-read.
    pub fn revalidate<T: Transport>(&self, t: &mut T) -> Result<(), Error<T::Error>> {
        self.receiver.revalidate(t).map_err(Error::Receiver)?;
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner).map_err(Error::Read)?;
        if banner != self.banner {
            return Err(Error::Changed);
        }
        self.receiver
            .revalidate_identity(t)
            .map_err(Error::Receiver)
    }
    /// Validate a recovery image, bypassing model/family and rollback policy.
    /// No installed image, Current file or backup is needed.
    ///
    /// As for `receiver::Receiver::prepare`, every check that needs no I/O
    /// runs here; a returned [`PreparedRecovery`] has nothing left to check
    /// before consent.
    pub fn prepare(&self, image: &[u8]) -> Result<PreparedRecovery, PreparationError> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(PreparationError::Size(image.len()));
        }
        if !image::cmac::verify(image) {
            return Err(PreparationError::Integrity);
        }
        if image::is_drive_read(image) {
            return Err(PreparationError::DriveRead);
        }
        let chip = image::detect_chip(image)
            .map_err(|_| PreparationError::UnknownChip)?
            .family;
        if chip != self.chip {
            return Err(PreparationError::ChipMismatch {
                image: chip,
                drive: self.chip,
            });
        }
        Ok(PreparedRecovery {
            receiver: self.clone(),
            plan: receiver::TransferPlan::new(
                &self.receiver,
                image,
                DriveClass::of(self.chip),
                crate::update::flash::ExecutionMode::Recovery,
            )?,
        })
    }
}

/// A recovery target validated against a live receiver, without family policy.
#[derive(Debug, Clone)]
pub struct PreparedRecovery {
    receiver: Receiver,
    plan: receiver::TransferPlan,
}
impl PreparedRecovery {
    /// Required wire encoding.
    pub fn encoding(&self) -> receiver::Encoding {
        self.receiver.encoding()
    }
    /// Receiver state at preparation.
    pub fn mode(&self) -> receiver::Mode {
        self.receiver.mode()
    }
    /// Bytes transmitted; the canonical image remains separate for verification.
    pub fn transfer(&self) -> &[u8] {
        self.plan.transfer()
    }
    /// Immutable receiver-derived transfer and PREPARE plan.
    pub fn plan(&self) -> &receiver::TransferPlan {
        &self.plan
    }
    /// Execute recovery and require the target identity after the write,
    /// preserving limited read-back as structured evidence for the host to
    /// report. Hosts must check [`crate::update::Startup::evidence`]:
    /// [`crate::update::StartupEvidence::Unobserved`] is not confirmed startup.
    pub fn flash_completed<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<crate::update::FlashOutcome, Error<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(io.reads, layout::BANNER.start as u32, &mut banner)
            .map_err(Error::Read)?;
        if banner != self.receiver.banner {
            return Err(Error::Changed);
        }
        self.plan
            .execute_completed(io, runtime)
            .map_err(from_execute)
    }
}

fn from_execute<E>(e: receiver::ExecutionError<E>) -> Error<E> {
    match e {
        receiver::ExecutionError::Receiver(e) => Error::Receiver(e),
        receiver::ExecutionError::Flash(FlashError::Startup(e)) => Error::Startup(e),
        receiver::ExecutionError::Flash(e) => Error::Flash(e),
    }
}

#[cfg(test)]
#[path = "recovery_from_execute_tests.rs"]
mod from_execute_tests;

//! Explicit recovery without installed-firmware, model, family or backup policy.
//! Requires `drive`, `image` and `enc`. Identification and preparation are
//! read-only; the caller owns consent and write authorization.
use crate::update::{FlashError, FlashRuntime, FlashTransport, PrepareError, Verified};
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
    Image(PrepareError),
    /// Transfer or protected-region verification failed.
    Flash(FlashError<E>),
    /// The live chip/banner changed after identification.
    Changed,
    /// The receiver did not start the selected firmware.
    Startup(crate::update::StartupError<E>),
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
    /// Returns `None` for a readable non-MediaTek banner. Reads no backup.
    pub fn identify<T: Transport>(t: &mut T) -> Result<Option<Self>, Error<T::Error>> {
        let mode = match receiver::detect_mode(t) {
            Ok(mode) => mode,
            Err(receiver::Error::InvalidIdentity) => return Ok(None),
            Err(e) => return Err(Error::Receiver(e)),
        };
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner).map_err(Error::Read)?;
        let Some(evidence) = crate::protocol::Evidence::parse(mode.inquiry(), &banner)
            .map_err(|_| Error::Changed)?
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
    /// Verify identity, receiver instructions and chip/banner before a write.
    pub fn revalidate<T: Transport>(&self, t: &mut T) -> Result<(), Error<T::Error>> {
        self.receiver.revalidate(t).map_err(Error::Receiver)?;
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner).map_err(Error::Read)?;
        if banner != self.banner {
            return Err(Error::Changed);
        }
        Ok(())
    }
    /// Validate a recovery image, bypassing model/family and rollback policy.
    /// No installed image, Current file or backup is needed.
    pub fn prepare(&self, image: &[u8]) -> Result<PreparedRecovery, PrepareError> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(PrepareError::Size(image.len()));
        }
        if !image::cmac::verify(image) {
            return Err(PrepareError::Integrity);
        }
        if image::is_drive_read(image) {
            return Err(PrepareError::DriveRead);
        }
        let chip = image::detect_chip(image)
            .map_err(|_| PrepareError::UnknownChip)?
            .family;
        if chip != self.chip {
            return Err(PrepareError::ChipMismatch {
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
    /// Revalidate, PREPARE, stream and verify, then confirm the target started.
    /// A PREPARE error is reported through `FlashRuntime::recovery_entry_failed`
    /// and recovery continues once. STREAM errors remain fatal; no writes retry.
    /// No backup, full pre-read, model or family gate is performed.
    pub fn flash<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<Verified, Error<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
    {
        self.flash_completed(io, runtime)?
            .into_verified()
            .map_err(Error::Flash)
    }

    /// Execute recovery and require exact target startup, preserving limited
    /// read-back as structured evidence for the host to report.
    pub fn flash_completed<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<crate::update::Completion, Error<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
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

fn from_execute<E>(e: receiver::ExecuteError<E>) -> Error<E> {
    match e {
        receiver::ExecuteError::Receiver(e) => Error::Receiver(e),
        receiver::ExecuteError::Flash(FlashError::Startup(e)) => Error::Startup(e),
        receiver::ExecuteError::Flash(e) => Error::Flash(e),
    }
}

#[cfg(test)]
mod from_execute_tests {
    use super::*;
    use crate::update::StartupError;

    #[test]
    fn unconfirmed_startup_maps_to_startup_error() {
        let e = from_execute::<&'static str>(receiver::ExecuteError::Flash(FlashError::Startup(
            StartupError::TargetMismatch,
        )));
        assert!(matches!(e, Error::Startup(StartupError::TargetMismatch)));
        assert_eq!(crate::CodedError::code(&e), "mediatek.recovery.startup");
    }
}

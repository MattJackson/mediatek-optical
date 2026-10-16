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
#[derive(Debug)]
pub enum Error<E> {
    /// Receiver identification or revalidation failed.
    Receiver(receiver::Error<E>),
    /// A required device read failed.
    Read(drive::Error<E>),
    /// Image size, integrity, form or chip is unacceptable.
    Image(PrepareError),
    /// Transfer or protected-region verification failed.
    Flash(FlashError<E>),
    /// The live chip/banner changed after identification.
    Changed,
    /// The receiver did not start the selected firmware.
    Startup,
}
impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Receiver(e)=>write!(f,"{e}"), Self::Read(e)=>write!(f,"{e}"),
            Self::Image(e)=>write!(f,"{e}"), Self::Flash(e)=>write!(f,"{e}"),
            Self::Changed=>f.write_str("MediaTek boot banner changed; re-plan recovery"),
            Self::Startup=>f.write_str("recovery did not confirm startup of the selected firmware; drive may still be in BOOT"),
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for Error<E> {}

impl Receiver {
    /// Recognize a MediaTek receiver without MMC features or application metadata.
    /// Returns `None` for a readable non-MediaTek banner. Reads no backup.
    pub fn identify<T: Transport>(t: &mut T) -> Result<Option<Self>, Error<T::Error>> {
        let mode = match receiver::detect_mode(t) {
            Ok(mode) => mode,
            Err(receiver::Error::InvalidIdentity) => return Ok(None),
            Err(e) => return Err(Error::Receiver(e)),
        };
        if [&b"PIONEER "[..], &b"RENESAS "[..]].contains(&&mode.inquiry()[8..16]) {
            return Ok(None);
        }
        let mut banner = [0; layout::BANNER.len];
        if drive::read_memory(t, layout::BANNER.start as u32, &mut banner).is_err() {
            return Ok(None);
        }
        let Some(chip) = Chip::from_banner(&banner) else {
            return Ok(None);
        };
        let receiver = receiver::detect_encoding(t, &mode).map_err(Error::Receiver)?;
        Ok(Some(Self {
            receiver,
            chip,
            banner,
        }))
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
        let transfer = if self.encoding() == receiver::Encoding::Encrypted {
            let mut bytes = image.to_vec();
            crate::enc::encrypt(&mut bytes).expect("whole AES blocks");
            Some(bytes)
        } else {
            None
        };
        Ok(PreparedRecovery {
            receiver: self.clone(),
            image: image.to_vec(),
            transfer,
        })
    }
}

/// A recovery target validated against a live receiver, without family policy.
#[derive(Debug, Clone)]
pub struct PreparedRecovery {
    receiver: Receiver,
    image: Vec<u8>,
    transfer: Option<Vec<u8>>,
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
        self.transfer.as_deref().unwrap_or(&self.image)
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
        self.receiver.revalidate(io.reads)?;
        let verified = crate::update::flash::Payload {
            class: DriveClass::of(self.receiver.chip),
            image: &self.image,
            transfer: self.transfer(),
        }
        .flash(
            FlashTransport {
                reads: io.reads,
                writes: io.writes,
            },
            runtime,
            crate::update::flash::ExecutionMode::Recovery,
        )
        .map_err(Error::Flash)?;
        let mode = receiver::detect_mode(io.reads).map_err(Error::Receiver)?;
        if mode.mode() != receiver::Mode::Firmware {
            return Err(Error::Startup);
        }
        let mut descriptor = [0; layout::DESCRIPTOR.len];
        drive::read_memory(io.reads, layout::DESCRIPTOR.start as u32, &mut descriptor)
            .map_err(Error::Read)?;
        // Includes target model, revision and build metadata; exclude the
        // device-written tail. No descriptor was required before the write.
        let expected = layout::DESCRIPTOR.of(&self.image).expect("complete image");
        if descriptor[..0x58] != expected[..0x58] || mode.inquiry()[8..36] != expected[..28] {
            return Err(Error::Startup);
        }
        Ok(verified)
    }
}

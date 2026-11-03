//! Explicit firmware-reference evidence for receivers with restricted code reads.
//! Code analysis is offline. Physical metadata binds that evidence to a running
//! application; it does not establish byte-for-byte equality of its live code.
use super::{Mode, Receiver};
use crate::{
    cdb,
    drive::{self, Data, Transport},
    envelope::Envelope,
    layout, INQUIRY_LEN,
};
use core::convert::Infallible;

/// Where the receiver's instruction evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Instructions were read from the live device.
    LiveCode,
    /// Instructions came from an explicit firmware reference. Live identity and
    /// build metadata must match before execution; live code was not verified.
    CurrentReference,
}

/// Reference analysis or physical metadata binding failed.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::receiver::reference::Error<()>) -> u8 { match e { mediatek_optical::receiver::reference::Error::Analysis { .. } => 0, mediatek_optical::receiver::reference::Error::Binding { .. } => 1, } }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
    /// The firmware reference did not contain a recognized application receiver.
    Analysis(super::Error<&'static str>),
    /// Live metadata could not be read or did not match the reference.
    Binding(super::Error<E>),
}
impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Analysis(e) => write!(f, "Current firmware receiver analysis failed: {e}"),
            Self::Binding(e) => write!(
                f,
                "Current firmware does not match the running receiver: {e}"
            ),
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Analysis(source) => Some(source),
            Self::Binding(source) => Some(source),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Binding {
    identity: [u8; 28],
    banner: [u8; layout::BANNER.len],
    descriptor: [u8; layout::DESCRIPTOR.len],
    live_banner: Option<[u8; layout::BANNER.len]>,
    image_hash: [u8; 32],
}
impl Binding {
    // Mode and identity bytes only: an offline-stage receiver from
    // `from_firmware` holds a synthetic INQUIRY record.
    pub(super) fn revalidate_identity<T: Transport>(
        &self,
        t: &mut T,
    ) -> Result<(), super::Error<T::Error>> {
        let mode = super::detect_mode(t)?;
        if mode.mode() != Mode::Firmware || mode.inquiry()[8..36] != self.identity {
            return Err(super::Error::Changed);
        }
        Ok(())
    }

    fn read_banner<T: Transport>(
        &self,
        t: &mut T,
    ) -> Result<[u8; layout::BANNER.len], super::Error<T::Error>> {
        self.revalidate_identity(t)?;
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner)
            .map_err(super::Error::Read)?;
        let mut descriptor = [0; layout::DESCRIPTOR.len];
        drive::read_memory(t, layout::DESCRIPTOR.start as u32, &mut descriptor)
            .map_err(super::Error::Read)?;
        if banner[..16] != self.banner[..16]
            || descriptor != self.descriptor
            || self.live_banner.is_some_and(|expected| banner != expected)
        {
            return Err(super::Error::Changed);
        }
        Ok(banner)
    }

    // INQUIRY is read again last: banner and descriptor reads return the same
    // flash bytes whichever receiver is running.
    pub(super) fn revalidate<T: Transport>(&self, t: &mut T) -> Result<(), super::Error<T::Error>> {
        self.read_banner(t)?;
        self.revalidate_identity(t)
    }
}

impl Receiver {
    /// Analyze a validated application image for a future stage. Execution must
    /// still bind its identity, banner and build metadata to the physical drive.
    /// A reference cannot be used to infer a BOOT receiver.
    pub fn from_firmware(envelope: &Envelope) -> Result<Self, Error<Infallible>> {
        let image = envelope.image();
        let descriptor = layout::DESCRIPTOR.of(image).expect("validated envelope");
        let mut inquiry = [0; INQUIRY_LEN];
        inquiry[0] = 5;
        inquiry[4] = 31;
        inquiry[8..36].copy_from_slice(&descriptor[..28]);
        let mut source = ImageSource { image, inquiry };
        let mode = super::detect_mode(&mut source).map_err(Error::Analysis)?;
        if mode.mode() != Mode::Firmware {
            return Err(Error::Analysis(super::Error::InvalidIdentity));
        }
        let mut receiver = super::detect(&mut source, &mode).map_err(Error::Analysis)?;
        receiver.reference = Some(Binding {
            identity: descriptor[..28].try_into().expect("descriptor identity"),
            banner: layout::BANNER
                .of(image)
                .expect("validated banner")
                .try_into()
                .unwrap(),
            descriptor: descriptor.try_into().expect("descriptor length"),
            live_banner: None,
            image_hash: *envelope.image_sha256(),
        });
        Ok(receiver)
    }

    /// Source of the cached instruction evidence.
    pub fn provenance(&self) -> Provenance {
        if self.reference.is_some() {
            Provenance::CurrentReference
        } else {
            Provenance::LiveCode
        }
    }

    /// Canonical image digest when the receiver uses explicit reference code.
    pub fn reference_sha256(&self) -> Option<&[u8; 32]> {
        self.reference
            .as_ref()
            .map(|reference| &reference.image_hash)
    }
}

/// Analyze an explicit Current reference and bind it to physical application
/// metadata. The resulting receiver revalidates physical metadata before writes;
/// execution and verification never substitute file bytes for device reads.
pub fn detect<T: Transport>(t: &mut T, envelope: &Envelope) -> Result<Receiver, Error<T::Error>> {
    let mut receiver = Receiver::from_firmware(envelope).map_err(|error| match error {
        Error::Analysis(error) => Error::Analysis(error),
        Error::Binding(_) => unreachable!("offline analysis performs no physical binding"),
    })?;
    let binding = receiver.reference.as_mut().expect("reference receiver");
    binding.live_banner = Some(binding.read_banner(t).map_err(Error::Binding)?);
    // Preserve the actual INQUIRY record for diagnostics, never synthesize live identity.
    let identity = super::detect_mode(t).map_err(Error::Binding)?;
    if identity.mode() != Mode::Firmware || identity.inquiry()[8..36] != binding.identity {
        return Err(Error::Binding(super::Error::Changed));
    }
    receiver.identity = identity;
    receiver.revalidate(t).map_err(Error::Binding)?;
    Ok(receiver)
}

// This adapter exists only during offline analysis and has no physical handle.
// It cannot escape into execution or verification.
struct ImageSource<'a> {
    image: &'a [u8],
    inquiry: [u8; INQUIRY_LEN],
}
impl Transport for ImageSource<'_> {
    type Error = &'static str;
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        let Data::In(bytes) = data else {
            return Err("offline source cannot execute commands");
        };
        if command == cdb::inquiry(INQUIRY_LEN as u16) {
            bytes.copy_from_slice(&self.inquiry);
        } else if command.len() == 10 && command[..3] == cdb::read_memory(0, 0)[..3] {
            let address =
                ((command[3] as usize) << 16) | ((command[4] as usize) << 8) | command[5] as usize;
            let source = self
                .image
                .get(address..address + bytes.len())
                .ok_or("offline read outside image")?;
            bytes.copy_from_slice(source);
        } else {
            return Err("unsupported offline analysis read");
        }
        Ok(bytes.len())
    }
}

#[cfg(test)]
#[path = "reference_tests.rs"]
mod tests;

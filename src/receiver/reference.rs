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
#[derive(Debug)]
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
impl<E: core::fmt::Debug> std::error::Error for Error<E> {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Binding {
    identity: [u8; 28],
    banner: [u8; layout::BANNER.len],
    descriptor: [u8; 0x58],
    live_banner: Option<[u8; layout::BANNER.len]>,
    image_hash: [u8; 32],
}
impl Binding {
    fn read_banner<T: Transport>(
        &self,
        t: &mut T,
    ) -> Result<[u8; layout::BANNER.len], super::Error<T::Error>> {
        let mode = super::detect_mode(t)?;
        if mode.mode() != Mode::Firmware || mode.inquiry()[8..36] != self.identity {
            return Err(super::Error::Changed);
        }
        let mut banner = [0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner)
            .map_err(super::Error::Read)?;
        let mut descriptor = [0; layout::DESCRIPTOR.len];
        drive::read_memory(t, layout::DESCRIPTOR.start as u32, &mut descriptor)
            .map_err(super::Error::Read)?;
        if banner[..16] != self.banner[..16]
            || descriptor[..0x58] != self.descriptor
            || self.live_banner.is_some_and(|expected| banner != expected)
        {
            return Err(super::Error::Changed);
        }
        Ok(banner)
    }

    pub(super) fn revalidate<T: Transport>(&self, t: &mut T) -> Result<(), super::Error<T::Error>> {
        self.read_banner(t).map(|_| ())
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
            descriptor: descriptor[..0x58].try_into().expect("descriptor metadata"),
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
mod tests {
    use super::*;

    struct Restricted {
        image: Vec<u8>,
        reads: usize,
    }
    impl Transport for Restricted {
        type Error = &'static str;
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            self.reads += 1;
            let Data::In(bytes) = data else {
                panic!("reference binding must not write")
            };
            if command == cdb::inquiry(INQUIRY_LEN as u16) {
                bytes.fill(0);
                bytes[0] = 5;
                bytes[4] = 31;
                bytes[8..36].copy_from_slice(
                    &self.image[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28],
                );
            } else {
                let address = ((command[3] as usize) << 16)
                    | ((command[4] as usize) << 8)
                    | command[5] as usize;
                if ![layout::BANNER, layout::DESCRIPTOR]
                    .iter()
                    .any(|range| address == range.start && bytes.len() == range.len)
                {
                    return Err("physical code reads unavailable");
                }
                bytes.copy_from_slice(&self.image[address..address + bytes.len()]);
            }
            Ok(bytes.len())
        }
    }

    fn fixture() -> (Envelope, Restricted) {
        let mut image = crate::fixtures::image(&crate::fixtures::BU3, 7);
        for (i, &byte) in super::super::PLAIN_APP.iter().enumerate() {
            image[0x9a300 + i] = if byte == super::super::ANY {
                0
            } else {
                byte as u8
            };
        }
        let image = crate::fixtures::sign(image);
        let envelope = Envelope::load(&image).unwrap();
        (envelope, Restricted { image, reads: 0 })
    }

    #[test]
    fn explicit_reference_binds_without_physical_code_reads() {
        let (envelope, mut live) = fixture();
        let receiver = detect(&mut live, &envelope).unwrap();
        assert_eq!(receiver.provenance(), Provenance::CurrentReference);
        assert_eq!(receiver.reference_sha256(), Some(envelope.image_sha256()));
        assert!(receiver.prepare_command().is_some());
        receiver.revalidate(&mut live).unwrap();
        assert!(live.reads > 0);
    }

    #[test]
    fn offline_stage_requires_actual_matching_application_at_handoff() {
        let (envelope, mut live) = fixture();
        let receiver = Receiver::from_firmware(&envelope).unwrap();
        assert_eq!(live.reads, 0);
        receiver.revalidate(&mut live).unwrap();
        live.image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
            .copy_from_slice(b"INTM");
        assert!(matches!(
            receiver.revalidate(&mut live),
            Err(super::super::Error::Changed)
        ));
        live.image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
            .copy_from_slice(b"BOOT");
        assert!(detect(&mut live, &envelope).is_err());
    }

    #[test]
    fn reference_binding_checks_build_metadata_and_preserves_live_boot_snapshot() {
        let (envelope, mut live) = fixture();
        live.image[layout::BANNER.start + 20] ^= 1;
        let receiver = detect(&mut live, &envelope).unwrap();
        receiver.revalidate(&mut live).unwrap();
        live.image[layout::BANNER.start + 20] ^= 2;
        assert!(receiver.revalidate(&mut live).is_err());
        let receiver = Receiver::from_firmware(&envelope).unwrap();
        receiver.revalidate(&mut live).unwrap();
        live.image[layout::DESCRIPTOR.start + 0x40] ^= 1;
        assert!(receiver.revalidate(&mut live).is_err());
    }

    #[test]
    fn unknown_reference_code_does_not_gain_a_receiver_from_matching_metadata() {
        let (envelope, mut live) = fixture();
        let mut image = envelope.image().to_vec();
        image[0x98000..0xb4000].fill(0);
        let envelope = Envelope::load(&crate::fixtures::sign(image)).unwrap();
        assert!(matches!(
            detect(&mut live, &envelope),
            Err(Error::Analysis(_))
        ));
        assert_eq!(live.reads, 0);
    }

    #[test]
    fn reference_is_not_a_source_of_live_readback_bytes() {
        let (envelope, mut live) = fixture();
        let receiver = detect(&mut live, &envelope).unwrap();
        receiver.revalidate(&mut live).unwrap();
        let mut code = [0; 32];
        assert!(drive::read_memory(&mut live, 0x9a300, &mut code).is_err());
    }
}

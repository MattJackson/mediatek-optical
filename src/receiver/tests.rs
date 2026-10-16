use super::*;
use crate::drive::Data;
extern crate std;
use std::{vec, vec::Vec};
struct Device {
    image: Vec<u8>,
    inquiry: [u8; 36],
    reads: usize,
    short: bool,
}
impl Device {
    fn new(mode: Mode) -> Self {
        let mut inquiry = [b' '; 36];
        inquiry[0] = 5;
        inquiry[4] = 31;
        inquiry[32..].copy_from_slice(if mode == Mode::Boot { b"BOOT" } else { b"INTM" });
        Self {
            image: vec![0; 0x200000],
            inquiry,
            reads: 0,
            short: false,
        }
    }
    fn stamp(&mut self, at: usize, pattern: &[u16]) {
        for (i, &b) in pattern.iter().enumerate() {
            self.image[at + i] = if b == ANY { 0 } else { b as u8 };
        }
    }
}
impl Transport for Device {
    type Error = &'static str;
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        self.reads += 1;
        let Data::In(buf) = data else {
            panic!("detection must never write or issue no-data commands")
        };
        if cdb[0] == 0x12 {
            buf.copy_from_slice(&self.inquiry);
            return Ok(buf.len());
        }
        assert_eq!(&cdb[..3], &[0x3c, 6, 0]);
        if self.short {
            return Ok(0);
        }
        let off = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
        let src = self.image.get(off..off + buf.len()).ok_or("unmapped")?;
        buf.copy_from_slice(src);
        Ok(buf.len())
    }
}
#[test]
fn active_mode_selects_the_receiver_and_revalidation_detects_changes() {
    let mut dev = Device::new(Mode::Firmware);
    dev.stamp(0x36c4, PLAIN_DIRECT);
    dev.stamp(0x9a300, PLAIN_APP);
    let mode = detect_mode(&mut dev).unwrap();
    assert_eq!(mode.mode(), Mode::Firmware);
    let receiver = detect_encoding(&mut dev, &mode).unwrap();
    assert_eq!(receiver.encoding(), Encoding::Plaintext);
    assert_eq!(receiver.signature_address(), 0x9a300);
    dev.inquiry[32..].copy_from_slice(b"BOOT");
    assert!(matches!(receiver.revalidate(&mut dev), Err(Error::Changed)));
    let mode = detect_mode(&mut dev).unwrap();
    let boot = detect_encoding(&mut dev, &mode).unwrap();
    assert_eq!(boot.signature_address(), 0x36c4);
    dev.image[0x36c4] ^= 1;
    assert!(matches!(boot.revalidate(&mut dev), Err(Error::Changed)));
}
#[test]
fn missing_short_and_conflicting_code_never_mean_plaintext() {
    let mut dev = Device::new(Mode::Firmware);
    let mode = detect_mode(&mut dev).unwrap();
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Unknown)
    ));
    dev.stamp(0x9a300, PLAIN_APP);
    dev.short = true;
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Unknown)
    ));
    dev.short = false;
    dev.stamp(0xa3000, PLAIN_APP);
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Conflict)
    ));
}
#[test]
fn encrypted_requires_header_call_and_matching_transform() {
    let mut dev = Device::new(Mode::Boot);
    let call = 0x35d2;
    let target = 0x5500;
    dev.image[call - 12..call]
        .copy_from_slice(&[0xeb, 0x69, 0x10, 0x22, 1, 0xa9, 3, 0x20, 0, 3, 0x18, 0x18]);
    let delta = target - call - 4;
    dev.image[call..call + 2].copy_from_slice(&(0xf000u16 | ((delta >> 12) as u16)).to_le_bytes());
    dev.image[call + 2..call + 4]
        .copy_from_slice(&(0xf800u16 | ((delta >> 1) as u16 & 2047)).to_le_bytes());
    let mode = detect_mode(&mut dev).unwrap();
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Unknown)
    ));
    dev.stamp(target, AES);
    let receiver = detect_encoding(&mut dev, &mode).unwrap();
    assert_eq!(receiver.encoding(), Encoding::Encrypted);
    dev.image[target] ^= 1;
    assert!(matches!(receiver.revalidate(&mut dev), Err(Error::Changed)));
}
#[test]
fn signature_across_read_boundary_is_found() {
    let mut dev = Device::new(Mode::Firmware);
    dev.stamp(0x983fa, PLAIN_APP);
    let mode = detect_mode(&mut dev).unwrap();
    assert_eq!(
        detect_encoding(&mut dev, &mode).unwrap().encoding(),
        Encoding::Plaintext
    );
}
#[test]
fn invalid_inquiry_is_not_assumed_to_be_running_firmware() {
    let mut dev = Device::new(Mode::Boot);
    dev.inquiry[32..].fill(0);
    assert!(matches!(detect_mode(&mut dev), Err(Error::InvalidIdentity)));
}

#[cfg(all(feature = "image", feature = "enc"))]
#[test]
fn recovery_boot_without_application_metadata_validates_image_and_stale_receiver() {
    use crate::{fixtures, recovery, update::PrepareError};
    let mut dev = Device::new(Mode::Boot);
    dev.image = fixtures::image(&fixtures::JB8, 1);
    dev.stamp(0x36c4, PLAIN_DIRECT);
    // Application metadata is not needed to recognize the BOOT receiver.
    dev.image[0x1ec000..0x1ed000].fill(0);
    let receiver = recovery::Receiver::identify(&mut dev).unwrap().unwrap();
    assert_eq!(receiver.mode(), Mode::Boot);
    let target = fixtures::image(&fixtures::BU3, 2);
    let prepared = receiver.prepare(&target).unwrap();
    assert_eq!(prepared.transfer(), target);
    assert!(matches!(receiver.prepare(&[]), Err(PrepareError::Size(0))));
    let mut corrupt = target.clone();
    corrupt[0x20000] ^= 1;
    assert!(matches!(
        receiver.prepare(&corrupt),
        Err(PrepareError::Integrity)
    ));
    let wrong_chip = fixtures::image(&fixtures::JB7, 2);
    assert!(matches!(
        receiver.prepare(&wrong_chip),
        Err(PrepareError::ChipMismatch { .. })
    ));
    dev.image[0x36c4] ^= 1;
    assert!(receiver.revalidate(&mut dev).is_err());
}

#[cfg(all(feature = "image", feature = "enc"))]
#[test]
fn recovery_does_not_probe_pioneer_memory() {
    let mut dev = Device::new(Mode::Boot);
    dev.inquiry[8..16].copy_from_slice(b"PIONEER ");
    assert!(crate::recovery::Receiver::identify(&mut dev)
        .unwrap()
        .is_none());
    assert_eq!(dev.reads, 1);
}

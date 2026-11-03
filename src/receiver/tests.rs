use super::*;
use crate::drive::Data;
extern crate std;
use std::{vec, vec::Vec};
struct Device {
    image: Vec<u8>,
    inquiry: [u8; 36],
    reads: usize,
    short: bool,
    fail_at: Option<usize>,
    opcodes: Vec<u8>,
    // After this many commands, INQUIRY reports the given record.
    flip: Option<(usize, [u8; 36])>,
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
            fail_at: None,
            opcodes: Vec::new(),
            flip: None,
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
        if let Some((after, inquiry)) = self.flip {
            if self.reads == after {
                self.inquiry = inquiry;
                self.flip = None;
            }
        }
        self.reads += 1;
        self.opcodes.push(cdb[0]);
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
        if self.fail_at == Some(off) {
            return Err("injected read failure");
        }
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
        Err(Error::Read(_))
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
fn header_call_ending_at_the_window_end_is_examined() {
    // The last halfword-aligned 4-byte call in the BOOT window ends at 0x3800.
    let mut dev = Device::new(Mode::Boot);
    let call = 0x37fc;
    let target = 0x5500;
    dev.image[call - 12..call]
        .copy_from_slice(&[0xeb, 0x69, 0x10, 0x22, 1, 0xa9, 3, 0x20, 0, 3, 0x18, 0x18]);
    let delta = target - call - 4;
    dev.image[call..call + 2].copy_from_slice(&(0xf000u16 | ((delta >> 12) as u16)).to_le_bytes());
    dev.image[call + 2..call + 4]
        .copy_from_slice(&(0xf800u16 | ((delta >> 1) as u16 & 2047)).to_le_bytes());
    dev.stamp(target, AES);
    let mode = detect_mode(&mut dev).unwrap();
    assert_eq!(
        detect_encoding(&mut dev, &mode).unwrap().encoding(),
        Encoding::Encrypted
    );
    // A plaintext signature elsewhere now conflicts instead of winning.
    dev.stamp(0x36c4, PLAIN_DIRECT);
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Conflict)
    ));
}
#[test]
fn header_call_at_the_window_start_is_examined() {
    // The call's setup precedes the BOOT window; the call itself is inside it.
    let mut dev = Device::new(Mode::Boot);
    let call = 0x3404;
    let target = 0x5500;
    dev.image[call - 12..call]
        .copy_from_slice(&[0xeb, 0x69, 0x10, 0x22, 1, 0xa9, 3, 0x20, 0, 3, 0x18, 0x18]);
    let delta = target - call - 4;
    dev.image[call..call + 2].copy_from_slice(&(0xf000u16 | ((delta >> 12) as u16)).to_le_bytes());
    dev.image[call + 2..call + 4]
        .copy_from_slice(&(0xf800u16 | ((delta >> 1) as u16 & 2047)).to_le_bytes());
    dev.stamp(target, AES);
    let mode = detect_mode(&mut dev).unwrap();
    let receiver = detect_encoding(&mut dev, &mode).unwrap();
    assert_eq!(receiver.encoding(), Encoding::Encrypted);
    assert!(receiver.revalidate(&mut dev).is_ok());
    // A plaintext signature elsewhere conflicts instead of winning.
    dev.stamp(0x3600, PLAIN_BOOT);
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Conflict)
    ));
    // Code before the window is context only, never a candidate itself.
    let mut dev = Device::new(Mode::Boot);
    dev.stamp(0x33e0, PLAIN_DIRECT);
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Unknown)
    ));
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
    // An unrecognised integrity-table enabled word is refused like corruption.
    let mut unknown = target.clone();
    let at = crate::image::cmac::TABLE_OFFSET + crate::image::cmac::ENTRY_SIZE;
    unknown[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        receiver.prepare(&unknown),
        Err(PrepareError::Integrity)
    ));
    let wrong_chip = fixtures::image(&fixtures::JB7, 2);
    assert!(matches!(
        receiver.prepare(&wrong_chip),
        Err(PrepareError::ChipMismatch { .. })
    ));
    dev.image[0x36c4] ^= 1;
    assert!(matches!(
        receiver.revalidate(&mut dev),
        Err(recovery::Error::Receiver(Error::Changed))
    ));
}

#[cfg(all(feature = "image", feature = "enc"))]
#[test]
fn recovery_protocol_evidence_is_independent_of_inquiry_brand() {
    let mut dev = Device::new(Mode::Boot);
    dev.image = crate::fixtures::image(&crate::fixtures::JB8, 1);
    dev.stamp(0x36c4, PLAIN_DIRECT);
    dev.inquiry[8..16].copy_from_slice(b"PIONEER ");
    let receiver = crate::recovery::Receiver::identify(&mut dev)
        .unwrap()
        .unwrap();
    assert_eq!(receiver.mode(), Mode::Boot);
    dev.image[0x3000..0x3020].fill(0);
    assert!(crate::recovery::Receiver::identify(&mut dev)
        .unwrap()
        .is_none());
}

#[test]
fn a_failed_scan_or_routine_read_is_an_error_not_partial_evidence() {
    // The plaintext signature sits in the failing block: it must not be
    // reported as "no receiver" (or chosen from the other blocks).
    let mut dev = Device::new(Mode::Boot);
    dev.stamp(0x36c4, PLAIN_DIRECT);
    let mode = detect_mode(&mut dev).unwrap();
    dev.fail_at = Some(0x3400);
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Read(_))
    ));
    // A failing AES routine read must not leave the header call unvalidated.
    let mut dev = Device::new(Mode::Boot);
    let call = 0x35d2;
    let target = 0x5500;
    dev.image[call - 12..call]
        .copy_from_slice(&[0xeb, 0x69, 0x10, 0x22, 1, 0xa9, 3, 0x20, 0, 3, 0x18, 0x18]);
    let delta = target - call - 4;
    dev.image[call..call + 2].copy_from_slice(&(0xf000u16 | ((delta >> 12) as u16)).to_le_bytes());
    dev.image[call + 2..call + 4]
        .copy_from_slice(&(0xf800u16 | ((delta >> 1) as u16 & 2047)).to_le_bytes());
    dev.stamp(target, AES);
    let mode = detect_mode(&mut dev).unwrap();
    assert_eq!(
        detect_encoding(&mut dev, &mode).unwrap().encoding(),
        Encoding::Encrypted
    );
    dev.fail_at = Some(target);
    assert!(matches!(
        detect_encoding(&mut dev, &mode),
        Err(Error::Read(_))
    ));
}

#[cfg(all(feature = "image", feature = "enc"))]
#[test]
fn recovery_revalidates_an_unchanged_drive_and_refuses_a_changed_banner_before_writing() {
    use crate::{fixtures, recovery, update};
    struct Runtime;
    impl update::FlashRuntime<&'static str> for Runtime {
        fn elapsed(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
        fn sleep(&mut self, _: std::time::Duration) {
            panic!("unexpected wait")
        }
    }
    let mut dev = Device::new(Mode::Boot);
    dev.image = fixtures::image(&fixtures::JB8, 1);
    dev.stamp(0x36c4, PLAIN_DIRECT);
    let receiver = recovery::Receiver::identify(&mut dev).unwrap().unwrap();
    receiver.revalidate(&mut dev).unwrap();
    let prepared = receiver
        .prepare(&fixtures::image(&fixtures::BU3, 2))
        .unwrap();
    // Same receiver signature and INQUIRY, different live boot banner. The
    // receiver's own snapshot and recovery's banner binding both refuse it.
    dev.image[crate::layout::BANNER.start + 0x1f] ^= 1;
    assert!(matches!(
        receiver.revalidate(&mut dev),
        Err(recovery::Error::Changed | recovery::Error::Receiver(Error::Changed))
    ));
    let mut writes = Device::new(Mode::Boot);
    let result = prepared.flash_completed(
        update::FlashTransport {
            reads: &mut dev,
            writes: &mut writes,
        },
        &mut Runtime,
    );
    assert!(matches!(
        result,
        Err(recovery::Error::Changed | recovery::Error::Receiver(Error::Changed))
    ));
    assert_eq!(writes.reads, 0, "no command may reach the write session");
}

#[test]
fn revalidation_reads_identity_after_receiver_evidence() {
    // READ BUFFER returns the same flash bytes from BOOT and the application;
    // only INQUIRY binds the running receiver, so it must also come last.
    let mut app = Device::new(Mode::Firmware);
    app.stamp(0x9a300, PLAIN_APP);
    let mut boot = Device::new(Mode::Boot);
    boot.stamp(0x36c4, PLAIN_DIRECT);
    for (dev, other) in [(&mut app, b"BOOT"), (&mut boot, b"INTM")] {
        let mode = detect_mode(dev).unwrap();
        let receiver = detect_encoding(dev, &mode).unwrap();
        dev.opcodes.clear();
        receiver.revalidate(dev).unwrap();
        assert_eq!(dev.opcodes.first(), Some(&0x12));
        assert_eq!(dev.opcodes.last(), Some(&0x12));
        assert!(dev.opcodes.contains(&0x3c));
        let original = dev.inquiry;
        // A mode change after the leading INQUIRY is refused.
        let mut changed = original;
        changed[32..36].copy_from_slice(other);
        dev.flip = Some((dev.reads + 1, changed));
        assert!(matches!(receiver.revalidate(dev), Err(Error::Changed)));
        dev.inquiry = original;
        // Vendor/model identity bytes are bound too, not just the mode.
        let mut changed = original;
        changed[8..16].copy_from_slice(b"PIONEER ");
        dev.flip = Some((dev.reads + 1, changed));
        assert!(matches!(receiver.revalidate(dev), Err(Error::Changed)));
        dev.inquiry = original;
        receiver.revalidate(dev).unwrap();
    }
}

#[cfg(all(feature = "image", feature = "enc"))]
#[test]
fn recovery_refuses_mode_change_during_execution_revalidation() {
    use crate::{fixtures, recovery, update};
    struct Runtime;
    impl update::FlashRuntime<&'static str> for Runtime {
        fn elapsed(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
        fn sleep(&mut self, _: std::time::Duration) {
            panic!("unexpected wait")
        }
    }
    let mut dev = Device::new(Mode::Boot);
    dev.image = fixtures::image(&fixtures::JB8, 1);
    dev.stamp(0x36c4, PLAIN_DIRECT);
    let receiver = recovery::Receiver::identify(&mut dev).unwrap().unwrap();
    let prepared = receiver
        .prepare(&fixtures::image(&fixtures::BU3, 2))
        .unwrap();
    // flash_completed reads the banner, then execution revalidation issues
    // its leading INQUIRY; the application starts after both.
    let mut application = dev.inquiry;
    application[32..36].copy_from_slice(b"INTM");
    dev.flip = Some((dev.reads + 2, application));
    dev.opcodes.clear();
    let mut writes = Device::new(Mode::Boot);
    let result = prepared.flash_completed(
        update::FlashTransport {
            reads: &mut dev,
            writes: &mut writes,
        },
        &mut Runtime,
    );
    assert!(
        dev.flip.is_none(),
        "the change must happen during execution"
    );
    assert!(matches!(
        result,
        Err(recovery::Error::Receiver(Error::Changed))
    ));
    assert_eq!(writes.reads, 0, "no command may reach the write session");
    assert_eq!(dev.opcodes[..2], [0x3c, 0x12]);
}

#[cfg(all(feature = "image", feature = "enc"))]
#[test]
fn recovery_revalidation_rechecks_identity_last_without_changing_banner_codes() {
    use crate::{fixtures, recovery, CodedError};
    let mut dev = Device::new(Mode::Boot);
    dev.image = fixtures::image(&fixtures::JB8, 1);
    dev.stamp(0x36c4, PLAIN_DIRECT);
    let receiver = recovery::Receiver::identify(&mut dev).unwrap().unwrap();
    dev.opcodes.clear();
    receiver.revalidate(&mut dev).unwrap();
    assert_eq!(dev.opcodes.first(), Some(&0x12));
    assert_eq!(dev.opcodes.last(), Some(&0x12));
    // A banner change keeps its existing classification.
    dev.image[crate::layout::BANNER.start + 0x1f] ^= 1;
    let error = receiver.revalidate(&mut dev).unwrap_err();
    assert_eq!(error.code(), "mediatek.recovery.receiver");
    dev.image[crate::layout::BANNER.start + 0x1f] ^= 1;
    // An identity change after the leading INQUIRY is refused.
    let mut application = dev.inquiry;
    application[32..36].copy_from_slice(b"INTM");
    dev.flip = Some((dev.reads + 1, application));
    assert!(matches!(
        receiver.revalidate(&mut dev),
        Err(recovery::Error::Receiver(Error::Changed))
    ));
}

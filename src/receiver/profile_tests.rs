use super::*;
use crate::{drive::Data, envelope::Envelope, fixtures, layout, update, Identity, INQUIRY_LEN};
use std::collections::BTreeMap;
struct Device {
    image: Vec<u8>,
    reads: BTreeMap<(u32, usize), usize>,
    writes: usize,
    change_after_capture: bool,
    // Once this address is read, INQUIRY reports these identity bytes;
    // flash contents are untouched.
    identity_after: Option<(u32, [u8; 28])>,
    identity: Option<[u8; 28]>,
}
impl Transport for Device {
    type Error = &'static str;
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        let Data::In(out) = data else {
            self.writes += 1;
            return Err("write forbidden");
        };
        if command[0] == 0x12 {
            out.fill(0);
            out[0] = 5;
            out[4] = 31;
            out[8..36].copy_from_slice(
                &self.image[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28],
            );
            if let Some(identity) = self.identity {
                out[8..36].copy_from_slice(&identity);
            }
        } else {
            let address = u32::from_be_bytes([0, command[3], command[4], command[5]]);
            *self.reads.entry((address, out.len())).or_default() += 1;
            out.copy_from_slice(&self.image[address as usize..address as usize + out.len()]);
            if self.change_after_capture && address == 0x1afc00 {
                self.image[0x9a300] ^= 1;
            }
            if let Some((after, identity)) = self.identity_after {
                if address == after {
                    self.identity = Some(identity);
                }
            }
        }
        Ok(out.len())
    }
}
fn device() -> Device {
    let mut image = fixtures::image(&fixtures::BU3, 7);
    for (i, &byte) in crate::receiver::PLAIN_APP.iter().enumerate() {
        image[0x9a300 + i] = if byte == crate::receiver::ANY {
            0
        } else {
            byte as u8
        };
    }
    Device {
        image: fixtures::sign(image),
        reads: BTreeMap::new(),
        writes: 0,
        change_after_capture: false,
        identity_after: None,
        identity: None,
    }
}
struct Runtime;
impl update::FlashRuntime<&'static str> for Runtime {
    fn elapsed(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    fn sleep(&mut self, _: std::time::Duration) {
        panic!("unexpected wait")
    }
}
#[test]
fn detection_captures_once_but_execution_revalidates_every_snapshot() {
    let mut live = device();
    let mode = crate::receiver::detect_mode(&mut live).unwrap();
    let receiver = detect(&mut live, &mode).unwrap();
    for address in (0x98000..0xb4000)
        .step_by(1024)
        .chain((0x140000..0x1b0000).step_by(1024))
    {
        assert_eq!(live.reads.get(&(address, 1024)), Some(&1));
    }
    assert!(
        !live.reads.keys().any(|(_, length)| *length == 1088),
        "encoding must reuse the code capture"
    );
    let image = live.image.clone();
    let identity = Identity::parse(
        &[0; INQUIRY_LEN],
        layout::BANNER.of(&image).unwrap(),
        layout::DESCRIPTOR.of(&image).unwrap(),
    )
    .unwrap();
    let update = update::PreparedUpdate::prepare_without_installed(&image, &identity).unwrap();
    let prepared = receiver.bind_prepared(&update).unwrap();
    // Mutation outside the small encoding signature must be caught before
    // PROBE/PREPARE/STREAM, by physical snapshot validation at execution.
    live.image[0x1affff] ^= 1;
    let mut writes = device();
    let result = prepared.flash_completed(
        update::FlashTransport {
            reads: &mut live,
            writes: &mut writes,
        },
        &mut Runtime,
    );
    assert!(matches!(
        result,
        Err(crate::receiver::ExecuteError::Receiver(Error::Changed))
    ));
    assert_eq!(writes.writes, 0);
    assert!(writes.reads.is_empty());
    assert_eq!(live.reads.get(&(0x1afc00, 1024)), Some(&2));
}
#[test]
fn detection_still_checks_live_signature_after_capture() {
    let mut live = device();
    live.change_after_capture = true;
    let mode = crate::receiver::detect_mode(&mut live).unwrap();
    assert!(matches!(detect(&mut live, &mode), Err(Error::Changed)));
    assert_eq!(live.writes, 0);
}
#[test]
fn validated_target_cannot_bind_to_a_receiver_of_another_chip() {
    let mut live = device();
    let mode = crate::receiver::detect_mode(&mut live).unwrap();
    let receiver = detect(&mut live, &mode).unwrap();
    let image = fixtures::image(&fixtures::JB7, 1);
    let identity = Identity::parse(
        &[0; INQUIRY_LEN],
        layout::BANNER.of(&image).unwrap(),
        layout::DESCRIPTOR.of(&image).unwrap(),
    )
    .unwrap();
    let validated = update::PreparedUpdate::prepare_without_installed(&image, &identity).unwrap();
    assert!(matches!(
        receiver.bind_prepared(&validated),
        Err(update::PrepareError::ChipMismatch {
            image: crate::Chip::Mt1939,
            drive: crate::Chip::Mt1959
        })
    ));
    assert!(matches!(
        receiver.prepare_without_installed(&Envelope::load(&image).unwrap(), &identity),
        Err(update::PrepareError::ChipMismatch { .. })
    ));
    assert_eq!(live.writes, 0);
}

impl Profile {
    pub(in crate::receiver) fn testing() -> Self {
        Self {
            chip: crate::Chip::Mt1959,
            prepare: cdb::Prepare::ModeOne,
            application: None,
            mixed: None,
            snapshots: Vec::new(),
        }
    }
}

#[test]
fn execution_refuses_identity_change_during_snapshot_revalidation() {
    // READ BUFFER returns the same flash from BOOT and the application, so a
    // receiver change during the long snapshot re-read is visible only to a
    // trailing INQUIRY. 0x1afc00 is the last snapshot chunk.
    let base = device();
    let live_identity: [u8; 28] = base.image
        [layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28]
        .try_into()
        .unwrap();
    let mut boot = live_identity;
    boot[24..28].copy_from_slice(b"BOOT");
    let mut vendor = live_identity;
    vendor[..8].copy_from_slice(b"PIONEER ");
    for changed in [boot, vendor] {
        let mut live = device();
        let mode = crate::receiver::detect_mode(&mut live).unwrap();
        let receiver = detect(&mut live, &mode).unwrap();
        let image = live.image.clone();
        let identity = Identity::parse(
            &[0; INQUIRY_LEN],
            layout::BANNER.of(&image).unwrap(),
            layout::DESCRIPTOR.of(&image).unwrap(),
        )
        .unwrap();
        let update = update::PreparedUpdate::prepare_without_installed(&image, &identity).unwrap();
        let prepared = receiver.bind_prepared(&update).unwrap();
        live.identity_after = Some((0x1afc00, changed));
        let mut writes = device();
        let result = prepared.flash_completed(
            update::FlashTransport {
                reads: &mut live,
                writes: &mut writes,
            },
            &mut Runtime,
        );
        assert_eq!(live.identity, Some(changed), "change during snapshots");
        assert!(matches!(
            result,
            Err(crate::receiver::ExecuteError::Receiver(Error::Changed))
        ));
        assert_eq!(writes.writes, 0);
        assert!(writes.reads.is_empty());
    }
}

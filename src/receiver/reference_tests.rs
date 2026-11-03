use super::*;

struct Restricted {
    image: Vec<u8>,
    reads: usize,
    // Once the descriptor is read, INQUIRY reports this revision.
    revision_after_descriptor: Option<[u8; 4]>,
    revision: Option<[u8; 4]>,
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
            if let Some(revision) = self.revision {
                bytes[32..36].copy_from_slice(&revision);
            }
        } else {
            let address =
                ((command[3] as usize) << 16) | ((command[4] as usize) << 8) | command[5] as usize;
            if ![layout::BANNER, layout::DESCRIPTOR]
                .iter()
                .any(|range| address == range.start && bytes.len() == range.len)
            {
                return Err("physical code reads unavailable");
            }
            bytes.copy_from_slice(&self.image[address..address + bytes.len()]);
            if address == layout::DESCRIPTOR.start {
                self.revision = self.revision_after_descriptor.or(self.revision);
            }
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
    (
        envelope,
        Restricted {
            image,
            reads: 0,
            revision_after_descriptor: None,
            revision: None,
        },
    )
}

#[test]
fn explicit_reference_binds_without_physical_code_reads() {
    let (envelope, mut live) = fixture();
    let receiver = detect(&mut live, &envelope).unwrap();
    assert_eq!(receiver.provenance(), Provenance::CurrentReference);
    assert_eq!(receiver.reference_sha256(), Some(envelope.image_sha256()));
    assert!(receiver.prepare_command().is_some());
    let detected = live.reads;
    receiver.revalidate(&mut live).unwrap();
    assert!(live.reads > detected);
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

#[test]
fn offline_reference_defects_classify_as_firmware_not_connection() {
    use crate::{operation::IssueKind, CodedError};
    let (envelope, _) = fixture();
    let mut image = envelope.image().to_vec();
    image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28].copy_from_slice(b"BOOT");
    let envelope = Envelope::load(&crate::fixtures::sign(image)).unwrap();
    let error = Receiver::from_firmware(&envelope).unwrap_err();
    assert!(matches!(
        error,
        Error::Analysis(super::super::Error::InvalidIdentity)
    ));
    assert_eq!(error.kind(), IssueKind::InvalidFirmware);
}

#[test]
fn reference_revalidation_rechecks_identity_after_metadata() {
    let (envelope, mut live) = fixture();
    let receiver = detect(&mut live, &envelope).unwrap();
    live.revision_after_descriptor = Some(*b"BOOT");
    assert!(matches!(
        receiver.revalidate(&mut live),
        Err(super::super::Error::Changed)
    ));
    assert_eq!(live.revision, Some(*b"BOOT"));
    // The offline-stage receiver has the same trailing check.
    let (_, mut live) = fixture();
    let receiver = Receiver::from_firmware(&envelope).unwrap();
    receiver.revalidate(&mut live).unwrap();
    live.revision_after_descriptor = Some(*b"INTN");
    assert!(matches!(
        receiver.revalidate(&mut live),
        Err(super::super::Error::Changed)
    ));
}

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
            let address =
                ((command[3] as usize) << 16) | ((command[4] as usize) << 8) | command[5] as usize;
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
fn reference_binding_compares_the_complete_descriptor() {
    let (envelope, mut live) = fixture();
    // Control: the unmodified drive matches its Current reference.
    let offline = Receiver::from_firmware(&envelope).unwrap();
    offline.revalidate(&mut live).unwrap();
    let detected = detect(&mut live, &envelope).unwrap();
    detected.revalidate(&mut live).unwrap();
    // A byte past 0x58 of the live descriptor no longer matches the reference.
    live.image[layout::DESCRIPTOR.start + 0x80] ^= 1;
    assert!(matches!(
        offline.revalidate(&mut live),
        Err(super::super::Error::Changed)
    ));
    assert!(matches!(
        detected.revalidate(&mut live),
        Err(super::super::Error::Changed)
    ));
    assert!(matches!(
        detect(&mut live, &envelope),
        Err(Error::Binding(super::super::Error::Changed))
    ));
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
fn reference_receiver_restart_evidence_uses_only_revalidated_identity() {
    use crate::update::{classify, StartupEvidence};
    let (envelope, mut live) = fixture();
    let receiver = Receiver::from_firmware(&envelope).unwrap();
    // The stored identity is synthesized from the image: only bytes 0, 4 and
    // 8..36 are set. Execution revalidates mode and 8..36 before writing.
    receiver.revalidate(&mut live).unwrap();
    let prior = &receiver.identity;
    struct Physical([u8; INQUIRY_LEN]);
    impl Transport for Physical {
        type Error = &'static str;
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, _: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            let Data::In(out) = data else { panic!() };
            out.copy_from_slice(&self.0[..out.len()]);
            Ok(out.len())
        }
    }
    // A physical INQUIRY differs from the synthesized one outside 8..36.
    let mut inquiry = *prior.inquiry();
    inquiry[2] = 5;
    inquiry[3] = 2;
    inquiry[7] = 0x10;
    let same = super::super::detect_mode(&mut Physical(inquiry)).unwrap();
    assert_ne!(same.inquiry(), prior.inquiry());
    assert_eq!(classify(prior, &same), StartupEvidence::Unobserved);
    inquiry[32..36].copy_from_slice(b"1.04");
    let changed = super::super::detect_mode(&mut Physical(inquiry)).unwrap();
    assert_eq!(classify(prior, &changed), StartupEvidence::IdentityChanged);
}

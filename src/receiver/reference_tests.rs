use super::*;

struct Restricted {
    image: Vec<u8>,
    reads: usize,
    mutate_at_read: Option<(usize, usize)>,
    fail_at_read: Option<usize>,
    short_at_read: Option<usize>,
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
        if self.fail_at_read == Some(self.reads) {
            return Err("physical metadata unavailable");
        }
        if self.short_at_read == Some(self.reads) {
            return Ok(0);
        }
        if let Some((read, offset)) = self.mutate_at_read {
            if self.reads == read {
                self.image[offset] ^= 1;
            }
        }

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
            mutate_at_read: None,
            fail_at_read: None,
            short_at_read: None,
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
fn de_marker_difference_binds_then_live_metadata_stays_strict() {
    for (reference_de, live_de) in [(0xde, 0xff), (0xff, 0xde)] {
        let (envelope, mut live) = fixture();
        let mut reference = envelope.image().to_vec();
        reference[layout::DESCRIPTOR.start + 0x56] = reference_de;
        let envelope = Envelope::load(&crate::fixtures::sign(reference)).unwrap();
        live.image[layout::DESCRIPTOR.start + 0x56] = live_de;
        let receiver = detect(&mut live, &envelope).unwrap();
        receiver.revalidate(&mut live).unwrap();
        live.image[layout::DESCRIPTOR.start + 0x56] = reference_de;
        assert!(receiver.revalidate(&mut live).is_err());
    }
}

#[test]
fn unknown_de_marker_is_not_treated_as_a_known_transition() {
    for value in [0x00, 0x01, 0xdf] {
        let (envelope, mut live) = fixture();
        let mut reference = envelope.image().to_vec();
        reference[layout::DESCRIPTOR.start + 0x56] = 0xde;
        let envelope = Envelope::load(&crate::fixtures::sign(reference)).unwrap();
        live.image[layout::DESCRIPTOR.start + 0x56] = value;
        assert!(detect(&mut live, &envelope).is_err());
    }
}

#[test]
fn de_exception_does_not_hide_other_descriptor_mismatches() {
    for offset in 0..layout::DESCRIPTOR.len {
        if offset == 0x56 {
            continue;
        }
        let (envelope, mut live) = fixture();
        let mut reference = envelope.image().to_vec();
        reference[layout::DESCRIPTOR.start + 0x56] = 0xde;
        let envelope = Envelope::load(&crate::fixtures::sign(reference)).unwrap();
        live.image[layout::DESCRIPTOR.start + 0x56] = 0xff;
        live.image[layout::DESCRIPTOR.start + offset] ^= 1;
        assert!(detect(&mut live, &envelope).is_err(), "offset {offset:#x}");
    }
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

#[test]
fn user_supplied_reference_pins_actual_metadata_without_matching_the_file() {
    let (envelope, mut live) = fixture();
    let d = layout::DESCRIPTOR.start;
    live.image[d + 8..d + 24].copy_from_slice(b"OTHER DRIVE     ");
    live.image[d + 24..d + 28].copy_from_slice(b"LIVE");
    live.image[d + 0x28..d + 0x30].copy_from_slice(b"20261108");
    live.image[d + 0x46..d + 0x4c].copy_from_slice(b"SKU123");
    live.image[d + 0x56] = 0xde;
    live.image[layout::BANNER.start..layout::BANNER.start + 16]
        .copy_from_slice(b"MT1959 Boot NEW ");
    live.image[layout::BANNER.start + 31] ^= 1;
    let actual = super::super::detect_mode(&mut live).unwrap();
    let strict = Receiver::from_firmware(&envelope).unwrap();
    assert_ne!(strict.identity, actual);
    assert!(strict.revalidate(&mut live).is_err());
    assert!(matches!(
        detect(&mut live, &envelope),
        Err(Error::Binding(_))
    ));

    let before = live.reads;
    let receiver = detect_user_supplied(&mut live, &envelope).unwrap();
    assert_eq!(
        live.reads - before,
        8,
        "only bracketed physical metadata and revalidation"
    );
    assert_eq!(receiver.provenance(), Provenance::UserSuppliedReference);
    assert_eq!(receiver.reference_sha256(), Some(envelope.image_sha256()));
    assert_eq!(receiver.identity, actual);
    assert_eq!(receiver.profile, strict.profile);
    assert_eq!(receiver.site, strict.site);
    assert_eq!(receiver.transform, strict.transform);
    assert_eq!(receiver.encoding(), strict.encoding());
    let binding = receiver.reference.as_ref().unwrap();
    assert_eq!(binding.identity, actual.inquiry()[8..36]);
    assert_eq!(
        binding.banner,
        live.image[layout::BANNER.start..layout::BANNER.end()]
    );
    assert_eq!(
        binding.descriptor,
        live.image[d..d + layout::DESCRIPTOR.len]
    );
    assert_eq!(binding.live_banner, Some(binding.banner));
    assert_eq!(binding.live_descriptor, Some(binding.descriptor));
    receiver.revalidate(&mut live).unwrap();

    // The prepared executor's startup baseline must stay physical even
    // though its instruction profile and reference hash came from the file.
    let identity = crate::Identity::parse(
        actual.inquiry(),
        layout::BANNER.of(&live.image).unwrap(),
        layout::DESCRIPTOR.of(&live.image).unwrap(),
    )
    .unwrap();
    let prepared = receiver
        .prepare_without_installed(&envelope, &identity)
        .unwrap();
    assert_eq!(prepared.plan().receiver().identity, actual);
    let mut code = [0; 32];
    assert!(drive::read_memory(&mut live, 0x9a300, &mut code).is_err());
}

#[test]
fn user_supplied_reference_rejects_changes_to_actual_session_snapshots() {
    for offset in [
        layout::DESCRIPTOR.start + 8,
        layout::DESCRIPTOR.start + 24,
        layout::BANNER.start + 31,
        layout::DESCRIPTOR.start + 0x40,
        layout::DESCRIPTOR.start + 0x56,
        layout::DESCRIPTOR.start + 0x57,
        layout::DESCRIPTOR.start + 0x80,
        layout::DESCRIPTOR.end() - 1,
    ] {
        let (envelope, mut live) = fixture();
        let receiver = detect_user_supplied(&mut live, &envelope).unwrap();
        live.image[offset] ^= 1;
        assert!(matches!(
            receiver.revalidate(&mut live),
            Err(super::super::Error::Changed)
        ));
    }
    let (envelope, mut live) = fixture();
    let receiver = detect_user_supplied(&mut live, &envelope).unwrap();
    receiver.revalidate(&mut live).unwrap();

    // Descriptor bytes can remain identical even though INQUIRY changes
    // immediately after that read. Every later revalidation is bracketed.
    live.revision_after_descriptor = Some(*b"LIVE");
    assert!(matches!(
        receiver.revalidate(&mut live),
        Err(super::super::Error::Changed)
    ));
}

#[test]
fn user_supplied_reference_rejects_capture_races_and_read_failures() {
    for (read, offset) in [
        // Between the bracketing INQUIRY reads.
        (3, layout::DESCRIPTOR.start + 8),
        // After capture, during the mandatory strict revalidation.
        (5, layout::DESCRIPTOR.start + 24),
        (6, layout::BANNER.start + 20),
        (7, layout::DESCRIPTOR.start + 0x56),
    ] {
        let (envelope, mut live) = fixture();
        live.mutate_at_read = Some((read, offset));
        assert!(matches!(
            detect_user_supplied(&mut live, &envelope),
            Err(Error::Session(super::super::Error::Changed))
        ));
    }
    for read in 1..=8 {
        let (envelope, mut live) = fixture();
        live.fail_at_read = Some(read);
        let error = detect_user_supplied(&mut live, &envelope).unwrap_err();
        assert!(matches!(
            error,
            Error::Session(super::super::Error::Read(_))
        ));
        assert_eq!(
            crate::CodedError::code(&error),
            "mediatek.reference.session"
        );
        assert_eq!(
            crate::CodedError::kind(&error),
            crate::CodedError::kind(&super::super::Error::Read(drive::Error::Transport(
                "failure"
            )))
        );
        assert!(!error.to_string().contains("does not match"));
        assert!(std::error::Error::source(&error).is_some());
    }
    for read in 1..=8 {
        let (envelope, mut live) = fixture();
        live.short_at_read = Some(read);
        assert!(matches!(
            detect_user_supplied(&mut live, &envelope),
            Err(Error::Session(super::super::Error::Read(
                drive::Error::Short { .. }
            )))
        ));
    }
}

#[test]
fn user_supplied_reference_requires_valid_application_analysis_and_live_mode() {
    assert!(Envelope::load(&[0; 32]).is_err());
    let (envelope, mut live) = fixture();
    for boot_file in [false, true] {
        let mut image = envelope.image().to_vec();
        if boot_file {
            image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
                .copy_from_slice(b"BOOT");
        } else {
            image[0x98000..0xb4000].fill(0);
        }
        let unknown = Envelope::load(&crate::fixtures::sign(image)).unwrap();
        assert!(matches!(
            detect_user_supplied(&mut live, &unknown),
            Err(Error::Analysis(_))
        ));
        assert_eq!(live.reads, 0);
    }
    live.image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
        .copy_from_slice(b"BOOT");
    assert!(matches!(
        detect_user_supplied(&mut live, &envelope),
        Err(Error::Session(super::super::Error::InvalidIdentity))
    ));
}

#[test]
fn user_supplied_recovery_keeps_actual_and_native_profile_chip_gates() {
    use crate::{fixtures, recovery, update::PrepareError, Chip};
    let (envelope, mut live) = fixture();
    live.image[layout::BANNER.start..layout::BANNER.end()].fill(0);
    assert!(recovery::Receiver::identify_user_supplied_reference(&mut live, &envelope).is_err());
    live.image[layout::BANNER.start..layout::BANNER.start + 16]
        .copy_from_slice(b"MT1939 Boot Code");
    let receiver =
        recovery::Receiver::identify_user_supplied_reference(&mut live, &envelope).unwrap();
    assert_eq!(receiver.chip(), Chip::Mt1939);
    // This target matches the file profile but fails the physical-chip gate.
    assert!(matches!(
        receiver.prepare(envelope.image()),
        Err(PrepareError::ChipMismatch {
            image: Chip::Mt1959,
            drive: Chip::Mt1939
        })
    ));
    // This target matches the physical chip but fails the native-profile gate.
    let target = fixtures::image(&fixtures::JB7, 9);
    assert!(matches!(
        receiver.prepare(&target),
        Err(PrepareError::ChipMismatch {
            image: Chip::Mt1939,
            drive: Chip::Mt1959
        })
    ));
    live.image[layout::BANNER.start + 20] ^= 1;
    assert!(receiver.revalidate(&mut live).is_err());
}

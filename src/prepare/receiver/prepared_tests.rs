use super::*;

#[test]
fn contradictory_layout_keeps_its_cause() {
    use super::super::layout::{Error, Operation};
    let image = vec![0; layout::IMAGE_SIZE];
    let operations = [
        Operation::CheckDecrypted(0x3000..0x3010),
        Operation::CheckPlaintext(0x3000..0x3010),
        Operation::Program(0..layout::IMAGE_SIZE),
    ];
    assert!(matches!(
        wire(&image, &operations),
        Err(crate::Refusal::Layout(Error::Conflict { .. }))
    ));
}
use crate::{
    fixtures::{self, BU3},
    layout, Identity, INQUIRY_LEN,
};

#[test]
fn an_image_with_no_verifiable_ranges_is_refused_before_any_write() {
    let mut image = fixtures::image(&BU3, 7);
    let at = crate::envelope::image::cmac::TABLE_OFFSET;
    image[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
    image[at + 8..at + 12].copy_from_slice(&0xFFFu32.to_le_bytes());
    let image = crate::envelope::image::cmac::resign(&image).unwrap();
    let class = crate::DriveClass::of(crate::Chip::Mt1959);
    assert!(class.verification_ranges(&image).is_empty());
    let receiver = Receiver {
        identity: super::super::DetectedMode {
            mode: super::super::Mode::Firmware,
            inquiry: [0; INQUIRY_LEN],
        },
        encoding: Encoding::Plaintext,
        site: super::super::Evidence::new(0x98000, &[1, 2]),
        transform: None,
        reference: None,
        profile: Some(super::super::profile::Profile::testing()),
    };
    assert!(matches!(
        TransferPlan::new(
            &receiver,
            &image,
            class,
            crate::prepare::update::ExecutionMode::Flash
        ),
        Err(crate::Refusal::Integrity)
    ));
}

#[test]
fn input_envelope_never_selects_the_running_receivers_wire_encoding() {
    let image = fixtures::image(&BU3, 7);
    let identity = Identity::parse(
        &[0; INQUIRY_LEN],
        layout::BANNER.of(&image).unwrap(),
        layout::DESCRIPTOR.of(&image).unwrap(),
    )
    .unwrap();
    let installed =
        crate::classify::InstalledFirmware::new(identity, &fixtures::drive_read(&image)).unwrap();
    let mut ciphertext = image.clone();
    crate::envelope::enc::encrypt(&mut ciphertext).unwrap();
    for encoding in [Encoding::Plaintext, Encoding::Encrypted] {
        let receiver = Receiver {
            identity: super::super::DetectedMode {
                mode: super::super::Mode::Firmware,
                inquiry: [0; INQUIRY_LEN],
            },
            encoding,
            site: super::super::Evidence::new(0x98000, &[1, 2]),
            transform: None,
            reference: None,
            profile: Some(super::super::profile::Profile::testing()),
        };
        for input in [&image, &ciphertext] {
            let prepared = receiver
                .prepare(&Envelope::load(input).unwrap(), &installed)
                .unwrap();
            assert_eq!(prepared.plan().image(), image);
            assert_eq!(
                prepared.plan().transfer(),
                if encoding == Encoding::Encrypted {
                    &ciphertext
                } else {
                    &image
                }
            );
            assert_eq!(prepared.plan().receiver(), &receiver);
            let steps = prepared.plan().steps();
            assert_eq!(
                steps[..3].iter().map(|s| s.label).collect::<Vec<_>>(),
                ["PROBE", "READY", "PREPARE"]
            );
            let recovery = TransferPlan::new(
                &receiver,
                &image,
                prepared.plan().class(),
                crate::prepare::update::ExecutionMode::Recovery,
            )
            .unwrap();
            let recovery_steps = recovery.steps();
            assert_eq!(recovery_steps[0].label, "PREPARE");
            assert_eq!(recovery_steps.len() + 2, steps.len());
            for (recovery, flash) in recovery_steps.iter().zip(&steps[2..]) {
                assert_eq!(recovery.cdb, flash.cdb);
                assert_eq!(recovery.direction, flash.direction);
                assert_eq!(recovery.length, flash.length);
            }
        }
    }
}

fn contract_refusal(
    application: Option<super::super::analysis::ApplicationAnalysis>,
    mixed: Option<crate::classify::receiver::mixed::MixedContract>,
    image: &[u8],
) -> Result<TransferPlan, crate::Refusal> {
    let mut profile = super::super::profile::Profile::testing();
    profile.application = application;
    profile.mixed = mixed;
    let receiver = Receiver {
        identity: super::super::DetectedMode {
            mode: super::super::Mode::Firmware,
            inquiry: [0; INQUIRY_LEN],
        },
        encoding: Encoding::Plaintext,
        site: super::super::Evidence::new(0x98000, &[1, 2]),
        transform: None,
        reference: None,
        profile: Some(profile),
    };
    TransferPlan::new(
        &receiver,
        image,
        crate::DriveClass::of(crate::Chip::Mt1959),
        crate::prepare::update::ExecutionMode::Flash,
    )
}

fn scratch_call() -> crate::classify::receiver::decoding::Call {
    use crate::classify::receiver::decoding::{Call, Value};
    Call {
        address: 0x9d000,
        target: 0x9e000,
        source: Value::Loaded {
            cell: 0x2000_0000,
            offset: 0x3000,
        },
        destination: Value::Stack(0),
        length: 16,
        fourth_argument: Value::Unknown,
    }
}

#[test]
fn receiver_evidence_refusals_name_the_receiver() {
    use super::super::analysis::ApplicationAnalysis;
    use crate::{classify::ContractReason, Refusal};
    let image = fixtures::image(&BU3, 7);
    // Conflicting decoder arguments, and a scratch decoder without a
    // recognized mixed contract, are facts about the receiver code.
    for (application, mixed) in [
        (ApplicationAnalysis::testing(Vec::new(), true), None),
        (
            ApplicationAnalysis::testing(vec![scratch_call()], false),
            None,
        ),
    ] {
        assert_eq!(
            contract_refusal(Some(application), mixed, &image).err(),
            Some(Refusal::ReceiverContract {
                reason: ContractReason::ReceiverEvidence
            })
        );
    }
}

#[test]
fn a_descriptor_byte_refusal_names_the_image() {
    use crate::classify::receiver::{analysis::ApplicationAnalysis, mixed::MixedContract};
    use crate::{classify::ContractReason, Refusal};
    let image = fixtures::image(&BU3, 7);
    let mixed = MixedContract::testing([0x10000..0x1d0000, 0x1ec000..0x1f0000]);
    assert_ne!(image[mixed.descriptor_byte()], 0xde);
    assert_eq!(
        contract_refusal(
            Some(ApplicationAnalysis::testing(vec![scratch_call()], false)),
            Some(mixed),
            &image
        )
        .err(),
        Some(Refusal::ReceiverContract {
            reason: ContractReason::DescriptorByte
        })
    );
}

#[test]
fn an_integrity_range_into_a_preserved_region_names_the_image() {
    use crate::classify::receiver::{analysis::ApplicationAnalysis, mixed::MixedContract};
    use crate::{classify::ContractReason, Refusal};
    // The descriptor byte is accepted; the receiver programs nothing that
    // covers the image's active integrity ranges.
    let mixed = MixedContract::testing([0x10000..0x10000, 0x10000..0x10000]);
    let mut image = fixtures::image(&BU3, 7);
    image[mixed.descriptor_byte()] = 0xde;
    let image = crate::envelope::image::cmac::resign(&image).unwrap();
    assert!(crate::envelope::image::cmac::parse_table(&image)
        .unwrap()
        .iter()
        .any(|entry| entry.is_active()));
    assert_eq!(
        contract_refusal(
            Some(ApplicationAnalysis::testing(vec![scratch_call()], false)),
            Some(mixed),
            &image
        )
        .err(),
        Some(Refusal::ReceiverContract {
            reason: ContractReason::PreservedRange
        })
    );
}

#[test]
fn an_image_that_is_not_whole_aes_blocks_is_refused_by_its_size() {
    // Encrypting the transfer needs whole AES blocks; that is the image's
    // length, not a receiver contract.
    let mut image = fixtures::image(&BU3, 7);
    image.push(0);
    let receiver = Receiver {
        identity: super::super::DetectedMode {
            mode: super::super::Mode::Firmware,
            inquiry: [0; INQUIRY_LEN],
        },
        encoding: Encoding::Encrypted,
        site: super::super::Evidence::new(0x98000, &[1, 2]),
        transform: None,
        reference: None,
        profile: Some(super::super::profile::Profile::testing()),
    };
    assert_eq!(
        TransferPlan::new(
            &receiver,
            &image,
            crate::DriveClass::of(crate::Chip::Mt1959),
            crate::prepare::update::ExecutionMode::Flash
        )
        .err(),
        Some(crate::Refusal::Size(layout::IMAGE_SIZE + 1))
    );
}

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
        Err(update::PrepareError::Layout(Error::Conflict { .. }))
    ));
}
use crate::{
    fixtures::{self, BU3},
    layout, Identity, INQUIRY_LEN,
};

#[test]
fn an_image_with_no_verifiable_ranges_is_refused_before_any_write() {
    let mut image = fixtures::image(&BU3, 7);
    let at = crate::image::cmac::TABLE_OFFSET;
    image[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
    image[at + 8..at + 12].copy_from_slice(&0xFFFu32.to_le_bytes());
    let image = crate::image::cmac::resign(&image).unwrap();
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
            update::flash::ExecutionMode::Flash
        ),
        Err(update::PrepareError::Integrity)
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
        update::InstalledFirmware::new(identity, &fixtures::drive_read(&image)).unwrap();
    let mut ciphertext = image.clone();
    crate::enc::encrypt(&mut ciphertext).unwrap();
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
                update::flash::ExecutionMode::Recovery,
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

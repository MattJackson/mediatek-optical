use super::*;
use crate::fixtures::{self, Board, BU3, JB7};
use crate::INQUIRY_LEN;

/// The live identity of a drive running `image`.
fn identity_of(image: &[u8]) -> Identity {
    Identity::parse(
        &[0; INQUIRY_LEN],
        layout::BANNER.of(image).unwrap(),
        layout::DESCRIPTOR.of(image).unwrap(),
    )
    .unwrap()
}

/// A drive running `image`, as its pre-flash backup sees it.
fn installed(image: &[u8]) -> InstalledFirmware {
    InstalledFirmware::new(identity_of(image), &fixtures::drive_read(image)).unwrap()
}

fn prepare(target: &[u8], running: &[u8]) -> Result<PreparedUpdate, PrepareError> {
    PreparedUpdate::prepare(target, &installed(running))
}

#[test]
fn identity_selects_the_dialect() {
    let id = identity_of(&fixtures::image(&JB7, 1));
    assert_eq!(id.class(), Some(DriveClass::Mt19));
    let none = Identity::parse(&[0; INQUIRY_LEN], b"", b"").unwrap();
    assert_eq!(none.class(), None);
    assert_eq!(DriveClass::of(Chip::Mt1959), DriveClass::Mt19);
}

#[test]
fn same_family_prepares_for_another_build() {
    let running = fixtures::image(&JB7, 1);
    let target = fixtures::image(&JB7, 2);
    let prepared = prepare(&target, &running).unwrap();
    assert_eq!(prepared.class(), DriveClass::Mt19);
    assert_eq!(Some(prepared.family()), family(&running));
    assert_eq!(prepared.image(), &target[..]);
    assert_eq!(prepared.transfer(), &target[..]);
    assert_eq!(
        PreparedUpdate::check(&target, &identity_of(&running)),
        Ok(prepared.family())
    );
}

/// The audit's cross-line flash: the same model built for another board line
/// is refused in both directions.
#[test]
fn another_board_line_of_the_same_model_is_refused() {
    // Two board lines of the SAME chip (both MT1939, banner "MT1939 Boot Code")
    // and the same model, differing only by platform → a family mismatch, not a
    // chip mismatch.
    let jb7 = fixtures::image(&JB7, 1);
    let other_line = Board {
        platform: "JB9",
        descriptor_platform: "JB9",
        ..JB7
    };
    let jb9 = fixtures::image(&other_line, 1);
    assert_eq!(JB7.model, other_line.model);
    let (f7, f9) = (family(&jb7).unwrap(), family(&jb9).unwrap());
    assert_ne!(f7, f9);
    assert_eq!(
        prepare(&jb9, &jb7).unwrap_err(),
        PrepareError::FamilyMismatch {
            installed: f7,
            target: f9
        }
    );
    assert_eq!(
        prepare(&jb7, &jb9).unwrap_err(),
        PrepareError::FamilyMismatch {
            installed: f9,
            target: f7
        }
    );
    // The image alone is a valid update for the drive's chip.
    assert_eq!(PreparedUpdate::check(&jb9, &identity_of(&jb7)), Ok(f9));
}

/// Strip the hardware record so no family can be derived, keeping the
/// image validly signed.
fn without_record(board: &Board) -> Vec<u8> {
    let mut image = fixtures::image(board, 1);
    let at = fixtures::TEMPLATE_AT + fixtures::template(board).len();
    image[at] = 0;
    fixtures::sign(image)
}

#[test]
fn unknown_families_are_refused() {
    let running = fixtures::image(&JB7, 1);
    let nameless = without_record(&JB7);
    assert!(cmac::verify(&nameless));
    assert_eq!(
        prepare(&nameless, &running).unwrap_err(),
        PrepareError::UnknownTargetFamily
    );
    assert_eq!(
        prepare(&running, &nameless).unwrap_err(),
        PrepareError::UnknownInstalledFamily
    );
    assert_eq!(
        prepare(&nameless, &nameless).unwrap_err(),
        PrepareError::UnknownTargetFamily
    );
}

#[test]
fn chips_must_match() {
    let mt1939 = fixtures::image(&JB7, 1);
    let mt1959 = fixtures::image(&BU3, 1);
    assert_eq!(
        prepare(&mt1939, &mt1959).unwrap_err(),
        PrepareError::ChipMismatch {
            image: Chip::Mt1939,
            drive: Chip::Mt1959
        }
    );
    // The drive's chip comes from its boot banner, not any descriptor tag: a
    // drive that reports only a banner is identified fine (here it matches the
    // MT1939 image's chip, so the check proceeds past the chip gate).
    let banner_only = Identity::parse(&[0; INQUIRY_LEN], b"MT1939 Boot Code", &[]).unwrap();
    assert!(!matches!(
        PreparedUpdate::check(&mt1939, &banner_only),
        Err(PrepareError::ChipMismatch { .. } | PrepareError::UnknownDriveChip)
    ));
}

/// An image with no chip tag at all is matched by the drive's banner. It has
/// no hardware record either, so the family gate refuses it.
#[test]
fn an_untagged_image_is_matched_by_the_drive_banner() {
    let mut image = fixtures::image(&JB7, 1);
    let d = layout::DESCRIPTOR.start;
    image[d + 0x34..d + 0x3E].fill(b' ');
    let tag = fixtures::TEMPLATE_AT + fixtures::template(&JB7).len() + 2 + 0x10;
    image[tag..tag + 4].copy_from_slice(b"XTEK");
    let image = fixtures::sign(image);
    let banner = |text: &[u8]| Identity::parse(&[0; INQUIRY_LEN], text, &[]).unwrap();
    assert_eq!(
        PreparedUpdate::check(&image, &banner(b"MT1939 Boot Code")),
        Err(PrepareError::UnknownTargetFamily)
    );
    assert_eq!(
        PreparedUpdate::check(&image, &banner(b"MT1959 Boot BU5")),
        Err(PrepareError::ChipMismatch {
            image: Chip::Mt1939,
            drive: Chip::Mt1959
        })
    );
    assert_eq!(
        PreparedUpdate::check(&image, &banner(b"")),
        Err(PrepareError::UnknownDriveChip)
    );
}

#[test]
fn invalid_images_are_refused_first() {
    let running = fixtures::image(&JB7, 1);
    let mut short = running.clone();
    short.pop();
    assert_eq!(
        prepare(&short, &running).unwrap_err(),
        PrepareError::Size(layout::IMAGE_SIZE - 1)
    );
    let mut tampered = fixtures::image(&JB7, 2);
    tampered[0x1_2000] ^= 1;
    assert_eq!(
        prepare(&tampered, &running).unwrap_err(),
        PrepareError::Integrity
    );
    let read = fixtures::drive_read(&fixtures::image(&JB7, 2));
    assert!(cmac::verify(&read));
    assert_eq!(
        prepare(&read, &running).unwrap_err(),
        PrepareError::DriveRead
    );
    let mut nameless = fixtures::image(&JB7, 2);
    nameless[layout::DESCRIPTOR.start + 0x34..layout::DESCRIPTOR.start + 0x3E].fill(b' ');
    nameless[layout::BANNER.start..layout::BANNER.start + 4].copy_from_slice(b"XT19");
    let tag = fixtures::TEMPLATE_AT + fixtures::template(&JB7).len() + 2 + 0x10;
    nameless[tag..tag + 4].copy_from_slice(b"XTEK");
    let nameless = fixtures::sign(nameless);
    assert_eq!(
        prepare(&nameless, &running).unwrap_err(),
        PrepareError::UnknownChip
    );
}

#[test]
fn installed_firmware_must_be_the_live_drive() {
    let running = fixtures::image(&JB7, 1);
    let id = identity_of(&running);
    let mut other = fixtures::drive_read(&running);
    other[layout::DESCRIPTOR.start + 0x18] ^= 1;
    assert_eq!(
        InstalledFirmware::new(id.clone(), &other).unwrap_err(),
        PrepareError::InstalledMismatch
    );
    let mut banner = fixtures::drive_read(&running);
    banner[layout::BANNER.start + 13] ^= 1;
    assert_eq!(
        InstalledFirmware::new(id.clone(), &banner).unwrap_err(),
        PrepareError::InstalledMismatch
    );
    assert_eq!(
        InstalledFirmware::new(id.clone(), &running[..0x1000]).unwrap_err(),
        PrepareError::InstalledMismatch
    );
    let mut long = running.clone();
    long.push(0);
    assert_eq!(
        InstalledFirmware::new(id.clone(), &long).unwrap_err(),
        PrepareError::InstalledMismatch
    );
    let blank = Identity::parse(&[0; INQUIRY_LEN], &[], &[]).unwrap();
    assert_eq!(
        InstalledFirmware::new(blank, &running).unwrap_err(),
        PrepareError::InstalledMismatch
    );
    // The stored image binds as well as a drive read of it.
    let bound = InstalledFirmware::new(id.clone(), &running).unwrap();
    assert_eq!(bound.family(), family(&running));
    assert_eq!(bound.identity(), &id);
}

#[test]
fn steps_are_the_oem_session() {
    let steps = DriveClass::Mt19.steps();
    assert_eq!(steps.len(), 3 + 128 + 3);
    let labels: Vec<&str> = steps.iter().map(|s| s.label).collect();
    assert_eq!(&labels[..3], ["PROBE", "READY", "PREPARE"]);
    assert_eq!(&labels[131..], ["COMMIT", "READY", "STATUS"]);
    assert_eq!(steps[0].cdb, cdb::probe());
    assert_eq!(
        (steps[0].direction, steps[0].length),
        (Direction::In, 0x100)
    );
    assert_eq!(steps[2].cdb, cdb::enter_update());
    for (i, step) in steps[3..131].iter().enumerate() {
        assert_eq!(step.label, "STREAM");
        assert_eq!(step.cdb, cdb::transfer((i * 0x4000) as u32, 0x4000));
        assert_eq!((step.direction, step.length), (Direction::Out, 0x4000));
    }
    assert_eq!(steps[131].cdb, cdb::finish());
    assert_eq!(steps[132].direction, Direction::None);
    assert_eq!(
        steps[133].cdb,
        [0x03, 0, 0, 0, 0x10, 0x80, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(steps[133].length, 16);
}

#[test]
fn verification_skips_the_boot_area_and_inactive_entries() {
    let mut image = fixtures::image(&JB7, 1);
    let t = cmac::TABLE_OFFSET;
    let entry = |image: &mut Vec<u8>, i: usize, enabled: u32, start: u32, end: u32| {
        let at = t + i * cmac::ENTRY_SIZE;
        image[at..at + 4].copy_from_slice(&enabled.to_le_bytes());
        image[at + 4..at + 8].copy_from_slice(&start.to_le_bytes());
        image[at + 8..at + 12].copy_from_slice(&end.to_le_bytes());
    };
    entry(&mut image, 1, cmac::ENABLED, 0, 0x2FFF);
    entry(&mut image, 2, cmac::ENABLED, 0x100, 0xFFF);
    entry(&mut image, 3, 0xFFFF_FFFF, 0x4000, 0x4FFF);
    assert_eq!(
        DriveClass::Mt19.verification_ranges(&image),
        vec![0x1_1000..=0x2_FFFF, 0x1000..=0x2FFF]
    );
    assert!(DriveClass::Mt19.verification_ranges(&[0; 4]).is_empty());
}

#[test]
fn chip_labels_parse() {
    assert_eq!("MT1939".parse(), Ok(Chip::Mt1939));
    assert_eq!("MT1959".parse(), Ok(Chip::Mt1959));
    assert_eq!("MT1969".parse::<Chip>(), Err(crate::UnknownChip));
    for chip in [Chip::Mt1959, Chip::Mt1939] {
        assert_eq!(chip.label().parse(), Ok(chip));
    }
}

#[cfg(feature = "drive")]
#[path = "update/flash_tests.rs"]
mod flash;

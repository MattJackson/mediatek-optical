use super::*;
use crate::fixtures::{self, Board, BU3, JB7, JB8, TEMPLATE_AT};

/// Known answers: the families the reference implementation of
/// `mediatek.hardware.v1` computes for the three fixtures. They equal the
/// families of the real JB7, JB8 and BU3 board lines.
#[test]
fn fixtures_have_the_reference_families() {
    for (board, key, want) in [
        (
            JB7,
            "chip=MT1939\x1fplatform=JB7\x1floader=Code\x1fiface=00000007\x1fmedium=39\x1fbdwrite=1",
            "11e7527216405467",
        ),
        (
            JB8,
            "chip=MT1939\x1fplatform=JB8\x1floader=JB8\x1fiface=00000007\x1fmedium=39\x1fbdwrite=1",
            "70f72c46f9603141",
        ),
        (
            BU3,
            "chip=MT1959\x1fplatform=BU3\x1floader=BU5\x1fiface=00000007\x1fmedium=2b\x1fbdwrite=1",
            "309829e6c3c8f31d",
        ),
    ] {
        let image = fixtures::image(&board, 1);
        let hardware = hardware(&image).expect(board.platform);
        assert_eq!(hardware.key(), key);
        assert_eq!(family(&image).unwrap().to_string(), want);
        assert_eq!(format!("{:?}", hardware.family()), format!("Family({want})"));
    }
    assert_eq!(FAMILY_SCHEME, "mediatek.hardware.v1");
}

#[test]
fn family_ignores_code_outside_the_record() {
    assert_eq!(
        family(&fixtures::image(&JB7, 1)),
        family(&fixtures::image(&JB7, 2))
    );
}

#[test]
fn family_survives_a_drive_read() {
    for board in [JB7, JB8, BU3] {
        let image = fixtures::image(&board, 3);
        let read = fixtures::drive_read(&image);
        assert_ne!(image[..0x400], read[..0x400]);
        assert_eq!(family(&read), family(&image));
        assert!(family(&read).is_some());
    }
}

/// Each field of the key separates boards that differ only in that field.
#[test]
fn every_key_field_separates_boards() {
    let base = family(&fixtures::image(&JB7, 1)).unwrap();
    let variants = [
        Board {
            platform: "JB9",
            descriptor_platform: "JB9",
            ..JB7
        },
        Board {
            banner: "MT1939 Boot JB7",
            ..JB7
        },
        Board {
            interface: [0, 0, 0, 8],
            ..JB7
        },
        Board {
            medium: 0x2B,
            ..JB7
        },
        Board {
            bd_write: false,
            ..JB7
        },
        Board {
            tag: "MTEKMT1959",
            ..JB7
        },
    ];
    let mut seen = vec![base];
    for board in variants {
        let found = family(&fixtures::image(&board, 1)).unwrap_or_else(|| panic!("{board:?}"));
        assert!(!seen.contains(&found), "{board:?} collides");
        seen.push(found);
    }
}

#[test]
fn disabled_bd_profiles_clear_bd_write() {
    let write = hardware(&fixtures::image(&JB7, 1)).unwrap();
    let read_only = hardware(&fixtures::image(
        &Board {
            bd_write: false,
            ..JB7
        },
        1,
    ))
    .unwrap();
    assert!(write.bd_write);
    assert!(!read_only.bd_write);
    assert!(read_only.key().ends_with("bdwrite=0"));
}

/// The record's offset in a fixture image.
fn record_at(board: &Board) -> usize {
    TEMPLATE_AT + fixtures::template(board).len()
}

fn edited(edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut image = fixtures::image(&JB7, 1);
    edit(&mut image);
    image
}

#[test]
fn incomplete_or_inconsistent_hardware_has_no_family() {
    let record = record_at(&JB7);
    let unique = record + 2;
    let descriptor = layout::DESCRIPTOR.start;
    let banner = layout::BANNER.start;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "short image",
            edited(|i| i.truncate(layout::IMAGE_SIZE - 1)),
        ),
        ("long image", edited(|i| i.push(0))),
        (
            "no chip anywhere",
            edited(|i| {
                i[descriptor + 0x34..descriptor + 0x3E].fill(b' ');
                i[banner..banner + 4].copy_from_slice(b"XT19");
            }),
        ),
        (
            "no supported chip",
            edited(|i| {
                i[descriptor + 0x34..descriptor + 0x3E].fill(b' ');
                i[banner + 4..banner + 6].copy_from_slice(b"69");
            }),
        ),
        (
            "not an MT19 boot banner",
            edited(|i| i[banner..banner + 2].copy_from_slice(b"XX")),
        ),
        (
            "banner names no loader",
            edited(|i| i[banner + 7..banner + 11].copy_from_slice(b"Bxot")),
        ),
        (
            "empty loader",
            edited(|i| i[banner + 12..banner + 16].fill(0)),
        ),
        ("no record", edited(|i| i[record] = 0x54)),
        (
            "two records",
            edited(|i| {
                let copy = i[record..record + 40].to_vec();
                i[0x18_0000..0x18_0000 + 40].copy_from_slice(&copy);
            }),
        ),
        (
            "record tag names the other chip",
            edited(|i| i[unique + 0x18..unique + 0x1A].copy_from_slice(b"59")),
        ),
        (
            "descriptor platform differs",
            edited(|i| i[descriptor + 0x46..descriptor + 0x49].copy_from_slice(b"JB8")),
        ),
        (
            "unprintable platform",
            edited(|i| {
                i[unique + 0x23] = 0x01;
                i[descriptor + 0x47] = 0x01;
            }),
        ),
        (
            "empty platform",
            edited(|i| {
                i[unique + 0x22..unique + 0x28].fill(b' ');
                i[descriptor + 0x46..descriptor + 0x4C].fill(b' ');
            }),
        ),
        (
            "template does not start with Profile List and Core",
            edited(|i| i[TEMPLATE_AT + 4 + 32 + 1] = 0x05),
        ),
        (
            "Core is not the second feature",
            edited(|i| {
                // Swap Core (12 bytes) and feature 0x0002 (8 bytes).
                let core = TEMPLATE_AT + 4 + 32;
                let block = i[core..core + 20].to_vec();
                i[core..core + 8].copy_from_slice(&block[12..20]);
                i[core + 8..core + 20].copy_from_slice(&block[..12]);
            }),
        ),
        (
            "template does not end at the record",
            edited(|i| i[record - 9] = 9),
        ),
    ];
    for (what, image) in cases {
        assert_eq!(hardware(&image), None, "{what}");
        assert_eq!(family(&image), None, "{what}");
    }
}

#[test]
fn template_needs_core_and_the_medium_feature() {
    // Feature 0x0003 renamed: the template still walks, but has no medium.
    let medium = TEMPLATE_AT + 4 + 32 + 4 + 8 + 4 + 4;
    let image = edited(|i| i[medium + 1] = 0x05);
    assert_eq!(family(&image), None);
}

#[test]
fn a_record_outside_the_code_area_is_not_searched() {
    let record = record_at(&JB7);
    let image = edited(|i| {
        let copy = i[record - 0x80..record + 40].to_vec();
        let at = layout::CALIBRATION.start + 0x100;
        i[at..at + copy.len()].copy_from_slice(&copy);
    });
    assert!(family(&image).is_some());
}

/// An untagged descriptor carries no platform to compare; the banner names
/// the chip.
#[test]
fn untagged_descriptor_falls_back_to_the_banner() {
    let tagged = family(&fixtures::image(&JB7, 1));
    let image = edited(|i| {
        let d = layout::DESCRIPTOR.start;
        i[d + 0x34..d + 0x3E].fill(b' ');
        i[d + 0x46..d + 0x4C].copy_from_slice(b"XXXXXX");
    });
    assert_eq!(family(&image), tagged);
}

/// The template search never reads the boot area, so a drive read cannot
/// change the result through it.
#[test]
fn template_search_stops_at_the_boot_area() {
    let board = JB7;
    let template = fixtures::template(&board);
    let record = fixtures::record(&board);
    let mut image = fixtures::image(&board, 1);
    let (old_template, old_record) = (TEMPLATE_AT, record_at(&board));
    image[old_template..old_record + record.len()].fill(1);
    // The template straddles the end of the boot area.
    let start = layout::BOOT_AREA.len - 8;
    image[start..start + template.len()].copy_from_slice(&template);
    let at = start + template.len();
    image[at..at + record.len()].copy_from_slice(&record);
    assert_eq!(family(&image), None);
    image[..layout::BOOT_AREA.len].fill(0);
    assert_eq!(family(&image), None);
}

use super::*;
use std::string::ToString;

fn inquiry() -> [u8; INQUIRY_LEN] {
    let mut b = [b' '; INQUIRY_LEN];
    b[0] = 0x05;
    b[8..16].copy_from_slice(b"HL-DT-ST");
    b[16..27].copy_from_slice(b"BD-RE BU40N");
    b[32..36].copy_from_slice(b"1.00");
    b
}

fn descriptor(tag: &[u8]) -> [u8; layout::DESCRIPTOR.len] {
    let mut d = [0u8; layout::DESCRIPTOR.len];
    d[..0x40].fill(b' ');
    d[0..8].copy_from_slice(b"HL-DT-ST");
    d[0x08..0x13].copy_from_slice(b"BD-RE BU40N");
    d[0x18..0x1C].copy_from_slice(b"1.00");
    d[0x1C..0x23].copy_from_slice(b"N003600");
    d[0x34..0x34 + tag.len()].copy_from_slice(tag);
    d
}

#[test]
fn identity_fields() {
    let id = Identity::parse(&inquiry(), b"MT1959 Boot BU5\0", &descriptor(b"MTEKMT1959")).unwrap();
    assert_eq!(id.device_type(), 5);
    assert_eq!(id.vendor(), "HL-DT-ST");
    assert_eq!(id.product(), "BD-RE BU40N");
    assert_eq!(id.revision(), "1.00");
    assert_eq!(id.banner(), "MT1959 Boot BU5");
    assert_eq!(id.descriptor_model(), "BD-RE BU40N");
    assert_eq!(id.sku(), "N003600");
    assert_eq!(id.chip(), Some(Chip::Mt1959));
    assert!(id.is_mt19());
    assert!(Identity::parse(&[0; 35], &[], &[]).is_none());
}

#[test]
fn banner_decides_chip_not_the_tag() {
    // JB8 parts ship an "MT1959 Boot" banner with a stale MTEKMT1939 descriptor
    // tag; the banner decides, so this drive is MT1959. The tag never flips it.
    let id = Identity::parse(&inquiry(), b"MT1959 Boot JB8", &descriptor(b"MTEKMT1939")).unwrap();
    assert_eq!(id.chip(), Some(Chip::Mt1959));
    assert!(
        id.has_descriptor(),
        "descriptor tag still gates identity-page edits"
    );
    let banner_only = Identity::parse(&inquiry(), b"MT1939 Boot Code", &[]).unwrap();
    assert_eq!(banner_only.chip(), Some(Chip::Mt1939));
    assert!(!banner_only.has_descriptor());
    assert_eq!(banner_only.sku(), "");
    // A drive with no readable banner names no chip, even when a tag is present.
    let tag_only = Identity::parse(&inquiry(), b"", &descriptor(b"MTEKMT1939")).unwrap();
    assert_eq!(tag_only.chip(), None);
    let neither = Identity::parse(&inquiry(), b"", &[]).unwrap();
    assert_eq!(neither.chip(), None);
    assert!(!neither.is_mt19());
}

#[test]
fn chip_labels_and_digits() {
    assert_eq!(Chip::Mt1959.to_string(), "MT1959");
    assert_eq!(Chip::Mt1939.label(), "MT1939");
    assert_eq!(Chip::from_digits(b'5', b'9'), Some(Chip::Mt1959));
    assert_eq!(Chip::from_digits(b'6', b'9'), None);
    assert_eq!(
        Chip::from_tag(b"xxMTEKMT1969MTEKMT1939"),
        Some(Chip::Mt1939)
    );
    assert_eq!(Chip::from_banner(b"MT1869 Boot"), None);
}

#[test]
fn sense_parsing_and_classes() {
    let mut fixed = [0u8; 18];
    fixed[0] = 0x70;
    fixed[2] = 0x04;
    fixed[12] = 0x11;
    fixed[13] = 0x22;
    assert_eq!(sense::parse(&fixed), Some((0x04, 0x11, 0x22)));
    assert_eq!(
        sense::parse(&[0x72, 0x03, 0x0C, 0x00]),
        Some((0x03, 0x0C, 0x00))
    );
    assert_eq!(sense::parse(&fixed[..13]), None);
    assert_eq!(sense::parse(&[0x7F, 0, 0, 0]), None);
    assert_eq!(sense::parse(&[]), None);
    assert!(sense::is_flash_fault(sense::HARDWARE_ERROR));
    assert!(sense::is_flash_fault(sense::ABORTED_COMMAND));
    assert!(!sense::is_flash_fault(0x06));
    assert!(sense::is_no_medium(0x02, 0x3A));
    assert!(!sense::is_no_medium(0x02, 0x04));
}

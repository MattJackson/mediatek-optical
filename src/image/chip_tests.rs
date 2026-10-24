use super::*;
use crate::Chip;

/// A minimal buffer with a valid banner + descriptor at the right offsets,
/// everything else zeroed.
fn synthetic(banner: &str, family_tag: &str, model: &str, rev: &str) -> Vec<u8> {
    let mut img = vec![0u8; DESCRIPTOR_OFFSET + DESCRIPTOR_LEN + 0x100];
    img[BANNER_OFFSET..BANNER_OFFSET + banner.len()].copy_from_slice(banner.as_bytes());

    let desc = DESCRIPTOR_OFFSET;
    img[desc..desc + 0x40].fill(b' ');
    img[desc..desc + 8].copy_from_slice(b"HL-DT-ST");
    let m = model.as_bytes();
    img[desc + 0x08..desc + 0x08 + m.len()].copy_from_slice(m);
    let r = rev.as_bytes();
    img[desc + 0x18..desc + 0x18 + r.len()].copy_from_slice(r);
    let t = family_tag.as_bytes();
    img[desc + 0x34..desc + 0x34 + t.len()].copy_from_slice(t);
    img
}

#[test]
fn detects_mt1959() {
    let img = synthetic("MT1959 Boot BU5", "MTEKMT1959", "BD-RE BU40N", "1.00");
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, Chip::Mt1959);
    assert_eq!(chip.vendor, "HL-DT-ST");
    assert_eq!(chip.model, "BD-RE BU40N");
    assert_eq!(chip.rev, "1.00");
    assert_eq!(chip.family.label(), "MT1959");
    assert_eq!(chip.identity_tag.as_deref(), Some("MTEKMT1959"));
}

#[test]
fn detects_mt1939() {
    let img = synthetic("MT1939 Boot Code", "MTEKMT1939", "SOME MODEL", "2.01");
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, Chip::Mt1939);
}

/// The boot loader banner is authoritative. A JB8 build labelled `MTEKMT1939`
/// in its descriptor but carrying an `MT1959 Boot` banner is MT1959 — the stale
/// vendor tag never changes the decision; it is surfaced only for display.
#[test]
fn family_is_the_banner_not_the_identity_tag() {
    let img = synthetic("MT1959 Boot JB8", "MTEKMT1939", "BW-16D1HT", "3.10");
    let chip = detect_chip(&img).unwrap();
    assert_eq!(
        chip.family,
        Chip::Mt1959,
        "banner MT1959 must win over tag MT1939"
    );
    // The stale tag is still reported, as a curiosity.
    assert_eq!(chip.identity_tag.as_deref(), Some("MTEKMT1939"));
}

/// The identity tag drives no decision in either direction: a tag-1959 /
/// banner-1939 image is MT1939.
#[test]
fn identity_tag_never_flips_the_decision() {
    let img = synthetic("MT1939 Boot Code", "MTEKMT1959", "BH16NS40", "1.01");
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, Chip::Mt1939);
    assert_eq!(chip.identity_tag.as_deref(), Some("MTEKMT1959"));
}

/// An image with no identity string at all still resolves from the banner.
#[test]
fn banner_alone_is_enough() {
    let mut img = vec![0u8; BANNER_OFFSET + 64];
    img[BANNER_OFFSET..BANNER_OFFSET + 16].copy_from_slice(b"MT1939 Boot Code");
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, Chip::Mt1939);
    assert_eq!(chip.identity_tag, None);
    assert!(!chip.descriptor_present);
}

/// The descriptor marker byte at `+0x50` is a within-family variant flag,
/// never a family gate: detection succeeds regardless of its value.
#[test]
fn marker_0x50_is_not_a_family_gate() {
    let mut img = synthetic("MT1959 Boot BU5", "MTEKMT1959", "BD-RE BU40N", "1.00");
    img[DESCRIPTOR_OFFSET + 0x50] = 0x58; // not 0x78 — must not matter
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, Chip::Mt1959);
    assert_eq!(chip.marker_0x50, Some(0x58));
    assert!(chip.descriptor_present);
}

/// No recognizable boot banner → clean refusal, regardless of any identity tag.
#[test]
fn no_banner_is_undetectable() {
    let img = synthetic("XX9999 Boot", "MTEKXX9999", "X", "1.00");
    let err = detect_chip(&img).unwrap_err().to_string();
    assert!(err.contains("undetectable"), "got: {err}");
}

/// A banner naming an MT19xx variant this crate does not handle is undetectable
/// — the stale tag cannot rescue it.
#[test]
fn unsupported_banner_is_undetectable() {
    let img = synthetic("MT1900 Boot", "MTEKMT1959", "X", "1.00");
    assert_eq!(detect_chip(&img), Err(ChipError::Undetectable));
}

#[test]
fn too_small_image_is_refused() {
    let img = vec![0u8; 0x100];
    assert!(detect_chip(&img).is_err());
}

/// The real BU40N 1.00 stock image, if present, must resolve to MT1959.
#[test]
#[ignore = "requires FREEMKV_KAT_BASE (OEM BU40N 1.00 image)"]
fn real_stock_1_00_is_mt1959() {
    let path = std::env::var("FREEMKV_KAT_BASE")
        .expect("FREEMKV_KAT_BASE must be set for this ignored test");
    let img = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, Chip::Mt1959);
    assert_eq!(chip.rev, "1.00");
    assert!(chip.model.contains("BU40N"), "got model: {:?}", chip.model);
}

/// The real MK-signed BU40N 1.03 image, if present, must also resolve to MT1959.
#[test]
#[ignore = "requires FREEMKV_KAT_MK103 (MK-signed BU40N 1.03 image)"]
fn real_mk_1_03_is_mt1959() {
    let path = std::env::var("FREEMKV_KAT_MK103")
        .expect("FREEMKV_KAT_MK103 must be set for this ignored test");
    let img = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, Chip::Mt1959);
    assert_eq!(chip.rev, "1.03");
}

#[test]
fn tag_scanner_handles_exact_and_truncated_oem_tags() {
    for tag in [b"MTEKMT1939", b"MTEKMT1959"] {
        for n in 0..10 {
            assert_eq!(first_mtek_tag(&tag[..n]), None);
        }
        assert_eq!(
            first_mtek_tag(tag).as_deref(),
            Some(std::str::from_utf8(tag).unwrap())
        );
        let mut prefixed = b"MTEKMT19x9/MTEKMT195x/".to_vec();
        prefixed.extend_from_slice(tag);
        assert_eq!(
            first_mtek_tag(&prefixed).as_deref(),
            Some(std::str::from_utf8(tag).unwrap())
        );
    }
}

#[test]
fn banner_and_descriptor_require_complete_records_at_the_boundary() {
    let image = synthetic("MT1959 Boot BU5", "MTEKMT1959", "BD-RE BU40N", "1.00");
    assert_eq!(read_banner(&image[..BANNER_OFFSET + BANNER_LEN - 1]), None);
    assert_eq!(
        read_banner(&image[..BANNER_OFFSET + BANNER_LEN]).as_deref(),
        Some("MT1959 Boot BU5")
    );
    let short = parse_descriptor(&image[..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN - 1]);
    assert_eq!(
        short,
        (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            None,
            false
        )
    );
    let exact = parse_descriptor(&image[..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN]);
    assert_eq!(exact.0, "HL-DT-ST");
    assert_eq!(exact.1, "BD-RE BU40N");
    assert_eq!(exact.2, "1.00");
    assert_eq!(exact.4, None);
    assert!(exact.5);
}

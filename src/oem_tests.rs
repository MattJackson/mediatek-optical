use super::*;
use crate::layout::{BOOT_MIRROR, BOOT_PAGE, DRIVE_WRITTEN, IMAGE_SIZE, UHD_REVOCATION};

const STORED_BOOT: u8 = 0xB7;

/// An OEM update image of `chip` whose code bytes depend on `build`.
fn oem_image(chip: &[u8; 10], build: u8, uhd: bool) -> Vec<u8> {
    let mut img: Vec<u8> = (0..IMAGE_SIZE).map(|i| (i % 251) as u8 ^ build).collect();
    img[BOOT_PAGE.start..BOOT_PAGE.end()].fill(STORED_BOOT);
    img[0x1E_C034..0x1E_C03E].copy_from_slice(chip);
    for (i, range) in DRIVE_WRITTEN.iter().enumerate() {
        img[range.start..range.end()].fill(0x10 + i as u8);
    }
    if !uhd {
        img[UHD_REVOCATION.start..UHD_REVOCATION.end()].fill(0xFF);
    }
    img
}

/// What a drive returns after `image` is flashed and has run a while.
fn drive_read(image: &[u8]) -> Vec<u8> {
    let mut read = image.to_vec();
    let mirror = read[BOOT_MIRROR.start..BOOT_MIRROR.end()].to_vec();
    read[..BOOT_PAGE.len].copy_from_slice(&mirror);
    for range in DRIVE_WRITTEN {
        let region = &mut read[range.start..range.end()];
        if !layout::is_erased(region) {
            region[..64].fill(0x52); // per-unit data
        }
    }
    read
}

fn catalog_with(images: &[(&Vec<u8>, &str)], default: Option<(Chip, &Vec<u8>)>) -> Catalog {
    let mut catalog = Catalog::new();
    for (image, model) in images {
        catalog.insert(
            content_key(image).unwrap(),
            Build {
                model: model.to_string(),
                revision: "1.00".into(),
                factory: Factory::from_image(image).unwrap(),
            },
        );
    }
    if let Some((chip, image)) = default {
        catalog.set_default(chip, Factory::from_image(image).unwrap());
    }
    catalog
}

#[test]
fn content_key_ignores_only_per_unit_bytes() {
    let oem = oem_image(b"MTEKMT1959", 1, true);
    let read = drive_read(&oem);
    assert_eq!(content_key(&oem), content_key(&read));
    let mut code = oem.clone();
    code[0x2_0000] ^= 1;
    assert_ne!(content_key(&oem), content_key(&code));
    assert_eq!(content_key(&oem[..0x1000]), None);
}

#[test]
fn cataloged_build_rebuilds_byte_exact() {
    let oem = oem_image(b"MTEKMT1959", 1, true);
    let catalog = catalog_with(&[(&oem, "BD-RE BU40N")], None);
    let rebuilt = rebuild(&drive_read(&oem), &catalog).unwrap();
    assert_eq!(rebuilt.image, oem);
    let p = &rebuilt.provenance;
    assert!(p.is_exact());
    assert_eq!(p.chip, Chip::Mt1959);
    assert_eq!(p.boot_page, BootPage::Restored);
    assert_eq!(p.regions_reset.len(), 4);
    assert_eq!(
        p.source,
        Source::Exact {
            model: "BD-RE BU40N".into(),
            revision: "1.00".into()
        }
    );
}

#[test]
fn unknown_mt1939_build_uses_the_chip_default() {
    // The reported failure: an MT1939 build the catalog lacks.
    let reference = oem_image(b"MTEKMT1939", 2, false);
    let unknown = oem_image(b"MTEKMT1939", 3, false);
    let catalog = catalog_with(
        &[(&reference, "BD-RE BH14NS40")],
        Some((Chip::Mt1939, &reference)),
    );
    let rebuilt = rebuild(&drive_read(&unknown), &catalog).unwrap();
    assert_eq!(rebuilt.image, unknown);
    assert!(!rebuilt.provenance.is_exact());
    assert_eq!(rebuilt.provenance.source, Source::ChipDefault);
    assert_eq!(rebuilt.provenance.chip, Chip::Mt1939);
    // The erased UHD list was neither reset nor reported.
    assert_eq!(rebuilt.provenance.regions_reset.len(), 3);
}

#[test]
fn default_keeps_an_erased_region_erased() {
    let reference = oem_image(b"MTEKMT1959", 2, true);
    let bd_only = oem_image(b"MTEKMT1959", 4, false);
    let catalog = catalog_with(&[], Some((Chip::Mt1959, &reference)));
    let rebuilt = rebuild(&drive_read(&bd_only), &catalog).unwrap();
    assert!(layout::is_erased(
        UHD_REVOCATION.of(&rebuilt.image).unwrap()
    ));
}

#[test]
fn stored_images_pass_through() {
    let oem = oem_image(b"MTEKMT1959", 1, true);
    let catalog = catalog_with(&[(&oem, "BD-RE BU40N")], None);
    let rebuilt = rebuild(&oem, &catalog).unwrap();
    assert!(catalog.knows_boot_page(&oem[..BOOT_PAGE.len]));
    assert!(!catalog.knows_boot_page(&drive_read(&oem)[..BOOT_PAGE.len]));
    assert_eq!(rebuilt.image, oem);
    assert_eq!(rebuilt.provenance.boot_page, BootPage::Stored);
    assert!(rebuilt.provenance.regions_reset.is_empty());
}

#[test]
fn refusals() {
    let oem = oem_image(b"MTEKMT1959", 1, true);
    let catalog = catalog_with(&[], Some((Chip::Mt1959, &oem)));
    assert_eq!(rebuild(&oem[..16], &catalog), Err(RebuildError::Size(16)));

    // Neither the stored page nor a mirror: its stored form is unknown.
    let mut odd = drive_read(&oem);
    odd[0] ^= 1;
    let error = rebuild(&odd, &catalog).unwrap_err();
    assert!(matches!(error, RebuildError::UnknownBootPage(_)));
    assert!(error.to_string().contains("sha256 "));

    // No build match and no default for this chip.
    let mt1939 = oem_image(b"MTEKMT1939", 5, false);
    assert_eq!(
        rebuild(&drive_read(&mt1939), &catalog),
        Err(RebuildError::NoFactory(Chip::Mt1939))
    );

    let mut nameless = drive_read(&oem);
    nameless[0x1E_C034..0x1E_C03E].fill(0);
    assert!(matches!(
        rebuild(&nameless, &catalog),
        Err(RebuildError::Chip(_))
    ));
}

#[test]
fn factory_rejects_drive_reads_and_bad_lengths() {
    let oem = oem_image(b"MTEKMT1959", 1, true);
    assert_eq!(
        Factory::from_image(&drive_read(&oem)),
        Err(RebuildError::Factory("boot page"))
    );
    assert_eq!(Factory::from_image(&oem[..10]), Err(RebuildError::Size(10)));
    let f = Factory::from_image(&oem).unwrap();
    let short: Arc<[u8]> = Arc::from(&[0u8; 4][..]);
    let mut regions = f.regions().clone();
    regions[2] = short;
    assert_eq!(
        Factory::new(f.boot_page().into(), regions),
        Err(RebuildError::Factory("settings"))
    );
}

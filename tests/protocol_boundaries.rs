//! Boundary cases for the documented wire fields and OEM integrity table.
#![cfg(all(feature = "image", feature = "drive"))]
use mediatek_optical::{cdb, image::cmac, Chip};

#[test]
fn wire_fields_preserve_every_big_endian_byte() {
    // OEM descriptor address, with an allocation exercising all 24 bits.
    assert_eq!(
        cdb::read_buffer(6, 0, 0x1ec000, 0x123456),
        [0x3c, 6, 0, 0x1e, 0xc0, 0, 0x12, 0x34, 0x56, 0]
    );
    assert_eq!(
        cdb::write_buffer(6, 0, 0x1ec000, 0x123456),
        [0x3b, 6, 0, 0x1e, 0xc0, 0, 0x12, 0x34, 0x56, 0]
    );
    assert_eq!(cdb::inquiry(0x1234), [0x12, 0, 0, 0x12, 0x34, 0]);
    assert_eq!(
        cdb::get_configuration(0x010c, 0x1234),
        [0x46, 2, 1, 0x0c, 0, 0, 0, 0x12, 0x34, 0]
    );
    for (tag, expected) in [(b"MTEKMT1959", Chip::Mt1959), (b"MTEKMT1939", Chip::Mt1939)] {
        assert_eq!(Chip::from_tag(tag), Some(expected));
        for length in 0..tag.len() {
            assert_eq!(Chip::from_tag(&tag[..length]), None);
        }
    }
}

#[test]
fn integrity_table_requires_all_sixteen_complete_records() {
    // OEM table geometry: offset 0x10400, sixteen 28-byte little-endian records.
    let end = 0x10400 + 16 * 28;
    for length in [0, 0x10400 - 1, 0x10400, end - 28, end - 1] {
        assert!(
            matches!(cmac::parse_table(&vec![0; length]), Err(cmac::CmacError::ImageTooSmall { need, got }) if need == end && got == length)
        );
    }
    let entries = cmac::parse_table(&vec![0; end]).unwrap();
    assert_eq!(entries.len(), 16);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.index, i);
        assert_eq!(entry.entry_off, 0x10400 + i * 28);
        assert!(!entry.is_active());
    }
}

#[test]
fn table_coverage_is_an_inclusive_interval() {
    // OEM entries include [0x10400,0x1045f]; only ranges overlapping the table cover it.
    for (start, end, covers) in [
        (0x10400, 0x1045f, true),
        (0, 0x10400, true),
        (0x10400, 0x10400, true),
        (0, 0x103ff, false),
        (0x10401, 0x1045f, true),
        (0x1041c, 0x2ffff, true),
        (0x105c0, 0x2ffff, false),
    ] {
        let entry = cmac::CmacEntry {
            index: 0,
            entry_off: 0x10400,
            enabled: 0,
            start,
            end,
            stored: [0; 16],
        };
        assert_eq!(entry.covers_table(), covers);
    }
}

struct CountTransport(usize);
impl mediatek_optical::drive::Transport for CountTransport {
    type Error = ();
    fn exec(&mut self, _: &[u8], _: mediatek_optical::drive::Data<'_>) -> Result<usize, ()> {
        Ok(self.0)
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}

#[test]
fn feature_returns_actual_length_and_rejects_incomplete_header() {
    use mediatek_optical::drive::{feature, Error};
    let mut bytes = [0; 32];
    for n in [12, 16, 31, 32] {
        assert_eq!(
            feature(&mut CountTransport(n), 0x010c, &mut bytes).unwrap(),
            n
        );
    }
    for n in 0..12 {
        assert!(
            matches!(feature(&mut CountTransport(n), 0x010c, &mut bytes), Err(Error::Short { expected: 12, actual }) if actual == n)
        );
    }
}

#[test]
fn descriptor_sense_requires_all_four_bytes() {
    for response in [0x72, 0x73, 0xf2, 0xf3] {
        let sense = [response, 0x82, 0x3a, 2];
        for n in 0..4 {
            assert_eq!(mediatek_optical::sense::parse(&sense[..n]), None);
        }
        assert_eq!(mediatek_optical::sense::parse(&sense), Some((2, 0x3a, 2)));
    }
}

#[test]
fn allocation_accepts_the_largest_representable_field() {
    let mut bytes = vec![0; 65535];
    assert_eq!(
        mediatek_optical::drive::feature(&mut CountTransport(65535), 0x010c, &mut bytes).unwrap(),
        65535
    );
    bytes.push(0);
    assert!(matches!(
        mediatek_optical::drive::feature(&mut CountTransport(65536), 0x010c, &mut bytes),
        Err(mediatek_optical::drive::Error::Oversize(65536))
    ));
}

struct ShortWrite;
impl mediatek_optical::drive::Transport for ShortWrite {
    type Error = ();
    fn exec(&mut self, _: &[u8], data: mediatek_optical::drive::Data<'_>) -> Result<usize, ()> {
        use mediatek_optical::drive::Data;
        Ok(match data {
            Data::In(bytes) => bytes.len(),
            Data::Out(bytes) => bytes.len().saturating_sub(1),
            Data::None => 0,
        })
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}

#[test]
fn partial_outbound_chunk_is_not_a_completed_transfer() {
    let mut transport = ShortWrite;
    let mut session = mediatek_optical::drive::enter_update(&mut transport).unwrap();
    assert!(matches!(
        session.write(0x10000, &[0x5a; 16]),
        Err(mediatek_optical::drive::Error::Short {
            expected: 16,
            actual: 15
        })
    ));
    assert!(format!("{session:?}").contains("Session"));
}

#[test]
fn inclusive_integrity_range_can_contain_one_byte() {
    // Independent OpenSSL AES-CMAC of 00 under the public OEM key, reversed
    // for the stored format. start == end includes exactly one byte.
    let expected = [
        0x4f, 0x84, 0x75, 0x2e, 0xb2, 0xc9, 0x83, 0x28, 0x0d, 0xae, 0x20, 0xd7, 0x99, 0x16, 0xb7,
        0x32,
    ];
    assert_eq!(cmac::compute_stored_digest(&[0], 0, 0).unwrap(), expected);
    assert_eq!(
        cmac::compute_stored_digest(&[0xff, 0, 0xff], 1, 1).unwrap(),
        expected
    );
    assert!(cmac::compute_stored_digest(&[0], 1, 0).is_err());
    assert!(cmac::compute_stored_digest(&[0], 0, 1).is_err());
}

#[test]
fn public_table_geometry_matches_oem_records() {
    assert_eq!(mediatek_optical::layout::CMAC_TABLE.start, 0x10400);
    assert_eq!(mediatek_optical::layout::CMAC_TABLE.len, 448);
}

#[cfg(feature = "oem")]
#[test]
fn catalog_replaces_one_chip_default_and_preserves_other_builds() {
    use mediatek_optical::oem::{Build, Catalog, Factory};
    use std::sync::Arc;
    let factory = |byte| {
        Factory::new(
            Arc::from(vec![byte; 0x400]),
            [0x8000, 0x8000, 0x4000, 0x10000].map(|n| Arc::from(vec![byte; n])),
        )
        .unwrap()
    };
    let (first, second, third) = (factory(0x11), factory(0x22), factory(0x33));
    let mut catalog = Catalog::new();
    assert!(catalog.is_empty());
    assert_eq!(catalog.len(), 0);
    catalog.set_default(Chip::Mt1939, first.clone());
    catalog.set_default(Chip::Mt1959, second.clone());
    catalog.set_default(Chip::Mt1939, third.clone());
    assert_eq!(catalog.default_for(Chip::Mt1939), Some(&third));
    assert_eq!(catalog.default_for(Chip::Mt1959), Some(&second));
    for (key, data) in [([0x11; 32], first.clone()), ([0x22; 32], second)] {
        catalog.insert(
            key,
            Build {
                model: "OEM fixture".into(),
                revision: "1.00".into(),
                factory: data,
            },
        );
    }
    assert!(!catalog.is_empty());
    assert_eq!(catalog.len(), 2);
    assert!(catalog.knows_boot_page(first.boot_page()));
    assert!(!catalog.knows_boot_page(&vec![0x44; 0x400]));
    assert!(catalog.build(&[0x55; 32]).is_none());
    // The public SHA-256 helper has the standard empty-message known answer.
    assert_eq!(
        mediatek_optical::oem::sha256(&[]),
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]
    );
}

#[test]
fn resign_does_not_activate_or_rewrite_disabled_table_entries() {
    let mut image = vec![0xff; 0x10400 + 448];
    let entry = 0x10400 + 15 * 28;
    // An inactive entry remains opaque even if its stale range covers the table.
    image[entry + 4..entry + 8].copy_from_slice(&0u32.to_le_bytes());
    image[entry + 8..entry + 12].copy_from_slice(&0x10400u32.to_le_bytes());
    assert_eq!(cmac::resign(&image).unwrap(), image);
    assert!(!cmac::verify(&image));
}

#[test]
fn identity_preserves_inquiry_bytes_without_lossy_normalization() {
    let inquiry: Vec<u8> = (0..36).map(|i| i as u8 + 32).collect();
    let id = mediatek_optical::Identity::parse(&inquiry, b"MT1959 Boot BU5", &[]).unwrap();
    assert_eq!(id.inquiry_bytes().as_slice(), inquiry);
}

#[test]
fn failure_messages_retain_actionable_values() {
    use mediatek_optical::update::{FlashError, PrepareError};
    let unsupported = "MT1900".parse::<Chip>().unwrap_err().to_string();
    assert!(unsupported.contains("MT1959") && unsupported.contains("MT1939"));
    let size = PrepareError::Size(123).to_string();
    assert!(size.contains("123") && size.contains("2097152"));
    let range = cmac::CmacError::BadRange {
        start: 0xabc,
        end: 0xdef,
    }
    .to_string();
    assert!(range.contains("0xabc") && range.contains("0xdef"));
    let message = FlashError::Transfer {
        offset: 0x1234,
        length: 77,
        source: mediatek_optical::drive::Error::Transport("disconnected"),
    }
    .to_string();
    assert!(
        message.contains("0x1234") && message.contains("77") && message.contains("disconnected")
    );
    #[cfg(feature = "enc")]
    assert!(mediatek_optical::enc::LengthError(17)
        .to_string()
        .contains("17"));
}

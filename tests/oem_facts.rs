//! Raw OEM bytes and independently computed OpenSSL results are the oracle.
#![cfg(all(feature = "oem", feature = "enc"))]
use mediatek_optical::{
    image::{cmac, detect_chip},
    Chip,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn number(v: &Value, key: &str) -> usize {
    v[key].as_u64().unwrap() as usize
}
fn case(index: usize) {
    let rows: Vec<Value> = serde_json::from_str(include_str!("support/oem_manifest.json")).unwrap();
    let row = &rows[index];
    let root = PathBuf::from(
        std::env::var_os("MEDIATEK_OEM_HOARD")
            .expect("set MEDIATEK_OEM_HOARD; see tests/OEM_FACTS.md"),
    );
    let raw = std::fs::read(root.join(row["path"].as_str().unwrap())).unwrap();
    assert_eq!(hex(&Sha256::digest(&raw)), row["sha256"].as_str().unwrap());
    assert_eq!(raw.len(), 0x200000);
    let banner = bytes(row["banner_hex"].as_str().unwrap());
    assert_eq!(&raw[0x3000..0x3010], banner);
    assert_eq!(
        &raw[0x1ec000..0x1ec060],
        bytes(row["descriptor_hex"].as_str().unwrap())
    );
    let expected_chip = match &banner[..6] {
        b"MT1959" => Some(Chip::Mt1959),
        b"MT1939" => Some(Chip::Mt1939),
        _ => None,
    };
    assert_eq!(detect_chip(&raw).ok().map(|i| i.family), expected_chip);
    // A catalog entry built from an unchanged OEM file must preserve every
    // byte. This proves stored-file behavior, not drive-read reconstruction.
    let mirrored = row["mirrored_boot"].as_bool().unwrap();
    assert_eq!(raw[..0x400] == raw[0x10000..0x10400], mirrored);
    assert_eq!(mediatek_optical::image::is_drive_read(&raw), mirrored);
    if mirrored {
        assert!(
            mediatek_optical::oem::Factory::from_image(&raw).is_err(),
            "mirrored readback is not a known stored factory boot page"
        );
    }
    if expected_chip.is_some() && !mirrored {
        use mediatek_optical::oem::{self, Build, Catalog, Factory};
        let mut catalog = Catalog::new();
        catalog.insert(
            oem::content_key(&raw).unwrap(),
            Build {
                model: "corpus".into(),
                revision: "recorded".into(),
                factory: Factory::from_image(&raw).unwrap(),
            },
        );
        assert_eq!(oem::rebuild(&raw, &catalog).unwrap().image, raw);
    }
    let table = cmac::parse_table(&raw).unwrap();
    let expected = row["entries"].as_array().unwrap();
    assert_eq!(
        table.iter().filter(|e| e.is_active()).count(),
        expected.len()
    );
    for fact in expected {
        let index = number(fact, "index");
        let (start, end) = (number(fact, "start"), number(fact, "end"));
        let entry = &table[index];
        assert_eq!((entry.start as usize, entry.end as usize), (start, end));
        assert_eq!(hex(&entry.stored), fact["stored"].as_str().unwrap());
        if fact["invalid_range"] == true {
            assert!(cmac::compute_stored_digest(&raw, entry.start, entry.end).is_err());
            continue;
        }
        let actual = cmac::compute_stored_digest(&raw, entry.start, entry.end).unwrap();
        assert_eq!(hex(&actual), fact["openssl"].as_str().unwrap());
        // Exercise inclusive endpoints on actual OEM ranges. A one-byte change
        // at either endpoint must change this tag; adjacent outside bytes must not.
        let mut changed = raw.clone();
        for at in [start, end] {
            changed[at] ^= 1;
            assert_ne!(
                cmac::compute_stored_digest(&changed, entry.start, entry.end).unwrap(),
                actual
            );
            changed[at] ^= 1;
        }
        for at in [
            start.checked_sub(1),
            end.checked_add(1).filter(|i| *i < raw.len()),
        ]
        .into_iter()
        .flatten()
        {
            changed[at] ^= 1;
            assert_eq!(
                cmac::compute_stored_digest(&changed, entry.start, entry.end).unwrap(),
                actual
            );
            changed[at] ^= 1;
        }
    }
    let valid = expected.iter().all(|e| e["matches"] == true);
    assert_eq!(cmac::verify(&raw), valid);
    if valid {
        assert_eq!(
            cmac::resign(&raw).unwrap(),
            raw,
            "stock signing must be byte-exact"
        );
    }
    if let Some(at) = row["resign_mutation"].as_u64() {
        let mut changed = raw.clone();
        changed[at as usize] ^= 1;
        let signed = cmac::resign(&changed).unwrap();
        assert_eq!(
            hex(&Sha256::digest(&signed)),
            row["resigned_sha256"].as_str().unwrap(),
            "OpenSSL independently signed result"
        );
    }
    if let Some(expected) = row["encrypted_sha256"].as_str() {
        let mut encrypted = raw.clone();
        mediatek_optical::enc::encrypt(&mut encrypted).unwrap();
        assert_eq!(hex(&Sha256::digest(&encrypted)), expected);
        mediatek_optical::enc::decrypt(&mut encrypted).unwrap();
        assert_eq!(encrypted, raw);
    }
}
macro_rules! case {
    ($name:ident,$index:expr) => {
        #[test]
        #[ignore = "requires hash-pinned OEM corpus; see tests/OEM_FACTS.md"]
        fn $name() {
            case($index);
        }
    };
}
include!("support/oem_cases.rs.inc");

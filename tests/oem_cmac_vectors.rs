//! Small integrity-table data records from OEM installers (no executable code).
//! Expected tags are stored by the OEM, independently verified with OpenSSL.
#![cfg(feature = "image")]
use mediatek_optical::envelope::cmac;
use serde_json::Value;
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn all_small_oem_records_match_their_stored_cmac_tags() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("support/oem_cmac_vectors.json")).unwrap();
    assert_eq!(cases.len(), 73);
    for case in cases {
        let data = bytes(case["data"].as_str().unwrap());
        let expected = bytes(case["tag"].as_str().unwrap());
        assert_eq!(
            cmac::compute_stored_digest(&data, 0, data.len() as u32 - 1)
                .unwrap()
                .as_slice(),
            expected,
            "OEM {} entry {}",
            case["source_sha256"],
            case["index"]
        );
        // Every single byte in these bounded known-answer records is authenticated.
        for at in 0..data.len() {
            let mut changed = data.clone();
            changed[at] ^= 1;
            assert_ne!(
                cmac::compute_stored_digest(&changed, 0, changed.len() as u32 - 1)
                    .unwrap()
                    .as_slice(),
                expected
            );
        }
    }
}

/// The OEM records above are all shorter than `compute_stored_digest`'s
/// internal chunk buffer. Known answer computed outside this crate
/// (`openssl mac CMAC`, AES-128-CBC, the crate's CMAC key) over 2003
/// non-uniform bytes, each 16-byte block reversed (final short block too) and
/// the digest byte-reversed for storage, so chunk alignment is visible.
#[test]
fn long_non_uniform_range_matches_independent_known_answer() {
    const EXPECTED: [u8; 16] = [
        0xA6, 0x93, 0x42, 0x92, 0x92, 0xF9, 0xF4, 0xD8, 0x82, 0x34, 0xC2, 0x95, 0x72, 0x75, 0x2A,
        0x3E,
    ];
    let mut data = vec![0u8; 5 + 2003];
    for (i, byte) in data[5..].iter_mut().enumerate() {
        *byte = (i * 7 + 3) as u8;
    }
    assert_eq!(
        cmac::compute_stored_digest(&data, 5, data.len() as u32 - 1).unwrap(),
        EXPECTED
    );
}

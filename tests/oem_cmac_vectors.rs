//! Small integrity-table data records from OEM installers (no executable code).
//! Expected tags are stored by the OEM, independently verified with OpenSSL.
#![cfg(feature = "image")]
use mediatek_optical::image::cmac;
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

use super::classic_speed::ClassicSpeed;
use sha2::{Digest, Sha256};

fn fixtures() -> Vec<(Vec<u8>, serde_json::Value)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/analysis");
    let records: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("classic-speed-sources.json")).unwrap())
            .unwrap();
    records
        .into_iter()
        .map(|record| {
            let mut image = vec![0xff; 0x200000];
            for segment in record["segments"].as_array().unwrap() {
                let bytes = std::fs::read(root.join(segment["file"].as_str().unwrap())).unwrap();
                assert_eq!(
                    format!("{:x}", Sha256::digest(&bytes)),
                    segment["excerpt_sha256"].as_str().unwrap()
                );
                let at = segment["source_offset"].as_u64().unwrap() as usize;
                image[at..at + bytes.len()].copy_from_slice(&bytes);
            }
            (image, record)
        })
        .collect()
}

#[test]
fn classic_speed_binds_all_native_policy_forms_to_their_actual_cells() {
    for (image, expected) in fixtures() {
        let proof = ClassicSpeed::detect(&image).unwrap();
        assert_eq!(proof.entry as u64, expected["entry"].as_u64().unwrap());
        assert_eq!(proof.site as u64, expected["site"].as_u64().unwrap());
        assert_eq!(
            proof.maximum_cell as u64,
            expected["maximum_cell"].as_u64().unwrap()
        );
        assert_eq!(
            proof.optimum_cell as u64,
            expected["optimum_cell"].as_u64().unwrap()
        );
        assert_eq!(
            proof.consumer as u64,
            expected["consumer"].as_u64().unwrap()
        );
    }
}

#[test]
fn classic_speed_rejects_side_effects_loops_and_bypassed_return_hooks() {
    let (original, _) = fixtures().pop().unwrap();
    let proof = ClassicSpeed::detect(&original).unwrap();
    let site = proof.entry + 8;
    let skip_tail = (((proof.site + 2) as isize - site as isize - 4) / 2) as u16;
    for op in [0x7008u16, 0x4770, 0xe7fe, 0xe000 | (skip_tail & 0x7ff)] {
        let mut image = original.clone();
        image[site..site + 2].copy_from_slice(&op.to_le_bytes());
        assert!(ClassicSpeed::detect(&image).is_err(), "{op:04x}");
    }
    let mut call = original.clone();
    call[site..site + 4].copy_from_slice(&[0, 0xf0, 0, 0xf8]);
    assert!(ClassicSpeed::detect(&call).is_err());
    assert!(ClassicSpeed::detect(&original[..proof.entry + 8]).is_err());
}

#[test]
fn classic_speed_requires_connected_setter_and_consumer_roles() {
    for (original, record) in fixtures() {
        for segment in [0, 3] {
            let at = record["segments"][segment]["source_offset"]
                .as_u64()
                .unwrap() as usize;
            let mut image = original.clone();
            image[at] ^= 1;
            assert!(ClassicSpeed::detect(&image).is_err(), "segment {segment}");
        }
    }
}

use super::{NativeSpeedPolicy, RequestedRateClamp};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn number(value: &Value, key: &str) -> usize {
    value[key].as_u64().unwrap() as usize
}
fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/analysis/native-speed-policy.json"
    ))
    .unwrap()
}
fn reconstruct(row: &Value) -> Vec<u8> {
    let mut image = vec![0xff; 0x200000];
    for part in row["parts"].as_array().unwrap() {
        let text = part["hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            part["sha256"].as_str().unwrap()
        );
        let at = number(part, "offset");
        image[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    image
}
#[test]
fn native_defaults_and_clamp_bind_across_real_compiler_variants() {
    let rows = fixtures();
    assert_eq!(rows.len(), 18);
    let mut styles = std::collections::BTreeSet::new();
    for row in rows {
        let image = reconstruct(&row);
        let expected = &row["plan"];
        let actual = NativeSpeedPolicy::detect(&image).unwrap();
        styles.insert(actual.variant);
        assert_eq!(actual.variant, expected["variant"].as_str().unwrap());
        assert_eq!(actual.entry, number(expected, "entry"));
        assert_eq!(actual.length, number(expected, "length"));
        assert_eq!(actual.media_cell as usize, number(expected, "media_cell"));
        assert_eq!(
            actual.maximum_cell as usize,
            number(expected, "maximum_cell")
        );
        assert_eq!(
            actual.optimum_cell as usize,
            number(expected, "optimum_cell")
        );
        assert_eq!(
            actual.hardware_cell as usize,
            number(expected, "hardware_cell")
        );
        let clamp = &expected["clamp"];
        assert_eq!(actual.clamp.entry, number(clamp, "entry"));
        assert_eq!(actual.clamp.compare, number(clamp, "compare"));
        assert_eq!(actual.clamp.after_clamp, number(clamp, "after_clamp"));
        assert_eq!(
            actual.clamp.request_register as usize,
            number(clamp, "request_register")
        );
    }
    assert_eq!(styles.len(), 8);
}
#[test]
fn changed_clamp_branch_or_maximum_binding_is_refused() {
    for row in fixtures() {
        let image = reconstruct(&row);
        let plan = NativeSpeedPolicy::detect(&image).unwrap();
        assert!(RequestedRateClamp::detect(&image, plan.maximum_cell + 1).is_err());
        let mut changed = image.clone();
        // The unsigned <= branch must skip exactly the fallback maximum load.
        changed[plan.clamp.compare + 2..plan.clamp.compare + 4]
            .copy_from_slice(&0xd901u16.to_le_bytes());
        assert!(NativeSpeedPolicy::detect(&changed).is_err());
        let mut changed = image;
        // Loading the limit into another register does not clamp the request.
        changed[plan.clamp.compare + 4] ^= 1;
        assert!(NativeSpeedPolicy::detect(&changed).is_err());
    }
}

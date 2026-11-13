use super::*;
#[test]
fn a32_native_branches_keep_pc_bias_and_direction() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/analysis/a32");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("sources.json")).unwrap()).unwrap();
    for case in manifest["cases"].as_array().unwrap() {
        let at = case["offset"].as_u64().unwrap() as usize;
        let target = case["target"].as_u64().unwrap() as usize;
        let bytes = std::fs::read(root.join(case["file"].as_str().unwrap())).unwrap();
        let mut image = vec![0xff; 0x200000];
        image[at..at + bytes.len()].copy_from_slice(&bytes);
        assert_eq!(branch_target(&image, at), Some(target), "{}", case["file"]);
        assert!(external_branch(&image, target, at));
        assert!(!external_branch(&image, target, at + 4));
        assert!(instruction(&image, at + 2).is_none());
        assert!(instruction(&image[..at + 3], at).is_none());
    }
}

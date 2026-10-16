//! Independent real-image census and semantic mutations, without device I/O.
use mediatek_optical::receiver::entry::application;
use mediatek_optical::receiver::entry::{inspect_boot_dual, inspect_boot_legacy};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn index(dir: &Path, files: &mut BTreeMap<String, PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            index(&path, files);
        } else if path.extension().is_some_and(|x| x == "bin") {
            files.insert(path.file_stem().unwrap().to_str().unwrap().into(), path);
        }
    }
}

#[test]
#[ignore = "requires MTK_IMAGE_ROOT and MTK_RECEIVER_CENSUS"]
fn legacy_entry_grammar_agrees_with_independent_census_and_rejects_mutations() {
    let census: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MTK_RECEIVER_CENSUS").unwrap()).unwrap(),
    )
    .unwrap();
    let images = census["unique_images"].as_object().unwrap();
    assert_eq!(images.len(), 136);
    let mut files = BTreeMap::new();
    index(
        Path::new(&std::env::var("MTK_IMAGE_ROOT").unwrap()),
        &mut files,
    );
    let mut matched = 0;
    for (hash, image) in images {
        let data = std::fs::read(&files[hash]).unwrap();
        let expected = image["receivers"]["boot"]["boot_legacy_entry_candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e.get("grammar_end").is_some());
        let window = &data[0x3400..0x3a00];
        let hit = inspect_boot_legacy(window, 0x3400);
        assert_eq!(hit.is_some(), expected.is_some(), "{hash}");
        let Some(hit) = hit else {
            let dual = inspect_boot_dual(window, 0x3400).unwrap_or_else(|| {
                panic!("{hash}: missing independently disassembled alternate grammar")
            });
            assert_eq!(dual.decoder, 0x3544);
            assert_eq!(dual.stream, 0x35ba);
            assert!([0x3576, 0x357a].contains(&dual.entry));
            for offset in [0x354c, 0x3554, 0x3556, 0x3558, dual.entry + 8] {
                let mut bad = window.to_vec();
                bad[(offset - 0x3400) as usize] ^= 1;
                assert!(
                    inspect_boot_dual(&bad, 0x3400).is_none(),
                    "{hash}: alternate mutation {offset:#x}"
                );
            }
            for length in [
                0,
                1,
                32,
                (dual.entry - 0x3400) as usize,
                (dual.stream - 0x3400 - 1) as usize,
            ] {
                assert!(inspect_boot_dual(&window[..length], 0x3400).is_none());
            }
            continue;
        };
        assert!(inspect_boot_dual(window, 0x3400).is_none());
        let expected = expected.unwrap();
        assert_eq!(hit.decoder, expected["dispatch"].as_u64().unwrap() as u32);
        assert_eq!(hit.entry, expected["mode1_target"].as_u64().unwrap() as u32);
        assert_eq!(hit.end, expected["grammar_end"].as_u64().unwrap() as u32);
        matched += 1;
        // Addressed windows must not silently reinterpret PC-relative literals.
        assert!(inspect_boot_legacy(window, u32::MAX - 0x100).is_none());
        for length in [
            0,
            1,
            15,
            (hit.entry - 0x3400) as usize,
            (hit.end - 0x3400 - 1) as usize,
        ] {
            assert!(
                inspect_boot_legacy(&window[..length], 0x3400).is_none(),
                "{hash}: truncation {length}"
            );
        }
        let decoder = (hit.decoder - 0x3400) as usize;
        // Alter CDB byte offset, mask, or mode comparison. None is a relocation.
        for at in [decoder, decoder + 2, decoder + 4, decoder + 6, decoder + 8] {
            let mut bad = window.to_vec();
            bad[at] ^= 1;
            assert!(
                inspect_boot_legacy(&bad, 0x3400).is_none(),
                "{hash}: mutation {at:#x}"
            );
        }
        // Redirect a flag-guard branch into its body, breaking its semantics.
        let entry = (hit.entry - 0x3400) as usize;
        let flags = entry
            + if window[entry + 1] & 0xf8 == 0x48 {
                2
            } else {
                0
            };
        let mut bad = window.to_vec();
        bad[flags + 12] ^= 1;
        assert!(
            inspect_boot_legacy(&bad, 0x3400).is_none(),
            "{hash}: flag branch"
        );
    }
    assert_eq!(
        matched, 98,
        "38 other BOOT grammars must use the dual-entry matcher"
    );
    eprintln!(
        "136 images inspected: {matched} legacy matches and 38 validated dual-entry grammars"
    );
}

#[test]
#[ignore = "requires MTK_IMAGE_ROOT; optionally MTK_ENTRY_REPORT"]
fn entire_hoard_entry_inventory_keeps_unmatched_images_explicit() {
    let root = PathBuf::from(std::env::var("MTK_IMAGE_ROOT").unwrap());
    let mut files = BTreeMap::new();
    index(&root, &mut files);
    let mut rows = Vec::new();
    let mut matched = 0;
    let mut dual_count = 0;
    for (hash, path) in &files {
        let bytes = std::fs::read(path).unwrap();
        let hit = bytes
            .get(0x3400..0x3a00)
            .and_then(|w| inspect_boot_legacy(w, 0x3400));
        matched += usize::from(hit.is_some());
        let dual = bytes
            .get(0x3400..0x3a00)
            .and_then(|w| inspect_boot_dual(w, 0x3400));
        assert!(!(hit.is_some() && dual.is_some()));
        dual_count += usize::from(dual.is_some());
        rows.push(serde_json::json!({
            "sha256": hash,
            "path": path.strip_prefix(&root).unwrap().to_string_lossy(),
            "bytes": bytes.len(),
            "entry_evidence": hit.map(|h| serde_json::json!({
                "decoder": h.decoder, "entry": h.entry, "end": h.end,
            })),
            "dual_entry_evidence": dual.map(|h| serde_json::json!({
                "decoder": h.decoder, "entry": h.entry, "stream": h.stream,
            })),
            "complete_contract": false,
        }));
    }
    assert_eq!(
        files.len(),
        1024,
        "refresh the full-hoard inventory when inputs change"
    );
    let report = serde_json::json!({
        "qualification": "Entry flag-copy evidence only; unmatched is unresolved, not unsupported. No transfer authorized.",
        "images": rows, "legacy": matched, "dual_entry": dual_count, "unmatched": files.len() - matched - dual_count,
    });
    if let Ok(path) = std::env::var("MTK_ENTRY_REPORT") {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
    }
    eprintln!(
        "entire hoard: {} images, {matched} legacy and {dual_count} dual entry candidates, {} explicitly unresolved",
        files.len(),
        files.len() - matched - dual_count
    );
}

#[test]
#[ignore = "requires MTK_IMAGE_ROOT and MTK_RECEIVER_CENSUS"]
fn application_tables_bind_the_update_flags_instead_of_read_buffer_tables() {
    let census: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MTK_RECEIVER_CENSUS").unwrap()).unwrap(),
    )
    .unwrap();
    let images = census["unique_images"].as_object().unwrap();
    assert_eq!(images.len(), 136);
    let mut files = BTreeMap::new();
    index(
        Path::new(&std::env::var("MTK_IMAGE_ROOT").unwrap()),
        &mut files,
    );
    let mut helpers = 0;
    let mut indirect = 0;
    for (hash, row) in images {
        let data = std::fs::read(&files[hash]).unwrap();
        let window = &data[0x98000..0xb4000];
        let expected: Vec<_> = row["receivers"]["application"]["dispatch_tables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["mode1_reaches_flag_body"] == true)
            .collect();
        assert_eq!(
            expected.len(),
            1,
            "{hash}: independent binding must be unique"
        );
        let expected = expected[0];
        let found = application::inspect(window, 0x98000)
            .unwrap_or_else(|| panic!("{hash}: no application binding"));
        assert_eq!(
            found.table as u64,
            expected["address"].as_u64().unwrap(),
            "{hash}"
        );
        assert_eq!(
            found.entry as u64,
            expected["mode1_flag_target"].as_u64().unwrap()
        );
        assert_eq!(
            found.mode1_target as u64,
            expected["mode_targets"]["1"].as_u64().unwrap()
        );
        assert_eq!(
            found.mode6_target as u64,
            expected["mode_targets"]["6"].as_u64().unwrap()
        );
        assert_eq!(found.helper.map(u64::from), expected["helper"].as_u64());
        indirect += usize::from(found.entry != found.mode1_target);
        if let Some(at) = found.helper {
            helpers += 1;
            let helper = &data[at as usize..at as usize + application::HELPER_BYTES];
            assert!(application::matches_helper(helper));
            for i in 0..helper.len() {
                let mut bad = helper.to_vec();
                bad[i] ^= 1;
                assert!(!application::matches_helper(&bad));
            }
            assert!(!application::matches_helper(&helper[..helper.len() - 1]));
        }
        let mut changed = window.to_vec();
        // Corrupt the MMIO nibble-clear shift, preserving superficial table bytes.
        changed[(found.entry + 4 - 0x98000) as usize] ^= 1;
        assert!(
            application::inspect(&changed, 0x98000).is_none(),
            "{hash}: bad flags"
        );
        assert!(application::inspect(window, u32::MAX - 4).is_none());
    }
    assert_eq!(indirect, 18);
    eprintln!("136 application bindings, {helpers} compiler helpers, {indirect} indirect mode-1 branches; no write authorization inferred");
}

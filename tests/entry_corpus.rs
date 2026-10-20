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

#[test]
#[ignore = "requires MTK_IMAGE_ROOT and MTK_APP_FLAGS_CENSUS"]
fn application_preludes_and_flag_stores_match_the_independent_census() {
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MTK_APP_FLAGS_CENSUS").unwrap()).unwrap(),
    )
    .unwrap();
    let rows = report["images"].as_object().unwrap();
    assert_eq!(rows.len(), 136);
    let mut files = BTreeMap::new();
    index(
        Path::new(&std::env::var("MTK_IMAGE_ROOT").unwrap()),
        &mut files,
    );
    let mut matched = 0;
    let mut mutations = 0;
    let mut alternate_entries = 0;
    for (hash, row) in rows {
        let data = std::fs::read(&files[hash]).unwrap();
        let window = &data[0x98000..0xb4000];
        let candidate = application::inspect(window, 0x98000).unwrap();
        let prelude = application::inspect_prologue(window, 0x98000, &candidate)
            .unwrap_or_else(|| panic!("{hash}: unbound prelude"));
        let registration = application::inspect_registration(&data, 0, prelude.start)
            .unwrap_or_else(|| panic!("{hash}: no unique WRITE BUFFER registration"));
        assert_eq!(
            u64::from(registration.record),
            row["write_buffer_registration"]["record"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(registration.callback),
            row["write_buffer_registration"]["callback"]
                .as_u64()
                .unwrap()
        );
        let flags = application::inspect_flags(window, 0x98000, &candidate, &prelude)
            .unwrap_or_else(|| panic!("{hash}: unbound four-bit flag copy"));
        let returns: Vec<_> = row["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["mnemonic"] == "pop")
            .collect();
        assert_eq!(returns.len(), 1);
        assert_eq!(
            u64::from(flags.end),
            returns[0]["address"].as_u64().unwrap() + 2
        );
        let mode_six = application::inspect_mode_six(window, 0x98000, &candidate, &prelude)
            .unwrap_or_else(|| panic!("{hash}: unbound mode-six guard"));
        let expected_guard = row["mode_six"]["guard"].as_u64().unwrap() as u32;
        for (at, mask) in [
            (expected_guard, 1),
            (expected_guard + 2, 1),
            (expected_guard + 5, 1),
        ] {
            let mut changed = window.to_vec();
            changed[(at - 0x98000) as usize] ^= mask;
            assert!(
                application::inspect_mode_six(&changed, 0x98000, &candidate, &prelude).is_none(),
                "{hash}: altered mode-six guard at {at:x}"
            );
        }
        match mode_six {
            application::ModeSix::Entry67 { guard, stream } => {
                assert_eq!(guard, expected_guard);
                assert_eq!(
                    u64::from(stream),
                    row["mode_six"]["not_equal_target"].as_u64().unwrap()
                );
                assert_eq!(row["mode_six"]["equal_reaches_mode1_flag_body"], true);
                alternate_entries += 1;
            }
            application::ModeSix::StreamZero { guard, nonzero, .. } => {
                assert_eq!(guard, expected_guard);
                assert_eq!(
                    u64::from(nonzero),
                    row["mode_six"]["not_equal_target"].as_u64().unwrap()
                );
                assert_eq!(row["mode_six"]["buffer_id"], 0);
            }
        }
        for instruction in row["instructions"].as_array().unwrap() {
            let mnemonic = instruction["mnemonic"].as_str().unwrap();
            if ![
                "str", "orrs", "lsls", "ldrb", "pop", "b", "beq", "bne", "bpl", "bmi",
            ]
            .contains(&mnemonic)
            {
                continue;
            }
            let at = instruction["address"].as_u64().unwrap() as usize;
            let mut changed = window.to_vec();
            changed[at - 0x98000] ^= 1;
            assert!(
                application::inspect_flags(&changed, 0x98000, &candidate, &prelude).is_none(),
                "{hash}: altered {mnemonic} at {at:x}"
            );
            mutations += 1;
        }
        let guard = &row["prologue"]["guard"];
        if guard.is_null() {
            assert_eq!(prelude.guard, None);
            continue;
        }
        let at = guard["target"].as_u64().unwrap() as usize;
        assert_eq!(prelude.guard, Some(at as u32));
        let found =
            application::ModeBufferGuard::inspect(&data[at..at + application::MODE_GUARD_BYTES])
                .unwrap_or_else(|| panic!("{hash}: guard mismatch"));
        assert!(found.returns_one(1, 0));
        assert_eq!(guard["returns_one_for_mode1_buffer0"], true);
        matched += 1;
    }
    assert_eq!(matched, 73);
    assert_eq!(rows.len() - matched, 63);
    assert_eq!(alternate_entries, 38);
    eprintln!("38 mode-six/0x67 shared entries; 98 zero-buffer stream guards; 408 guard mutations rejected");
    eprintln!("136 bound preludes and four-bit flag stores; 73 guard helpers; {mutations} instruction mutations rejected");
}

#[test]
#[ignore = "requires MTK_IMAGE_ROOT, MTK_RECEIVER_CENSUS and MTK_APP_FLAGS_CENSUS"]
fn live_detection_selects_prepare_and_encoding_for_every_published_receiver() {
    use mediatek_optical::{
        cdb,
        drive::{Data, Transport},
        receiver::{self, Encoding, Mode},
    };
    struct Device {
        bytes: Vec<u8>,
        boot: bool,
    }
    impl Transport for Device {
        type Error = &'static str;
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            let Data::In(out) = data else {
                panic!("live detection attempted a write")
            };
            match command[0] {
                0x12 => {
                    out.fill(b' ');
                    out[0] = 5;
                    out[4] = 31;
                    out[8..36].copy_from_slice(&self.bytes[0x1ec000..0x1ec01c]);
                    if self.boot {
                        out[32..36].copy_from_slice(b"BOOT");
                    }
                }
                0x3c => {
                    let at = u32::from_be_bytes([0, command[3], command[4], command[5]]) as usize;
                    out.copy_from_slice(self.bytes.get(at..at + out.len()).ok_or("out of bounds")?);
                }
                _ => return Err("unexpected command"),
            }
            Ok(out.len())
        }
    }
    let census: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MTK_RECEIVER_CENSUS").unwrap()).unwrap(),
    )
    .unwrap();
    let flags: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MTK_APP_FLAGS_CENSUS").unwrap()).unwrap(),
    )
    .unwrap();
    let mut files = BTreeMap::new();
    index(
        Path::new(&std::env::var("MTK_IMAGE_ROOT").unwrap()),
        &mut files,
    );
    let mut count = 0;
    let mut scratch_receivers = 0;
    let mut bulk_receivers = 0;
    let mut transfer_counts = BTreeMap::<String, usize>::new();
    let mut transfer_cases = Vec::new();
    for (hash, row) in census["unique_images"].as_object().unwrap() {
        for boot in [true, false] {
            let mut device = Device {
                bytes: std::fs::read(&files[hash]).unwrap(),
                boot,
            };
            let mode = receiver::detect_mode(&mut device).unwrap();
            let detected = receiver::detect(&mut device, &mode)
                .unwrap_or_else(|e| panic!("{hash} BOOT={boot}: {e}"));
            let expected_mode = if boot { Mode::Boot } else { Mode::Firmware };
            let expected_encoding = match row["receivers"]
                [if boot { "boot" } else { "application" }]["encoding_evidence"]
                .as_str()
                .unwrap()
            {
                "plaintext" => Encoding::Plaintext,
                "encrypted" => Encoding::Encrypted,
                other => panic!("unknown independent encoding {other}"),
            };
            assert_eq!(detected.mode(), expected_mode);
            if boot {
                assert!(detected.application_analysis().is_none());
            } else {
                let analysis = detected
                    .application_analysis()
                    .expect("application evidence retained");
                assert!(!analysis.conflicting_arguments(), "{hash}");
                if !analysis.scratch_decoders().is_empty() {
                    scratch_receivers += 1;
                    assert_eq!(analysis.scratch_decoders().len(), 1, "{hash}");
                }
                if !analysis.bulk_decoders().is_empty() {
                    bulk_receivers += 1;
                    assert_eq!(analysis.bulk_decoders().len(), 1, "{hash}");
                    assert!(
                        analysis.scratch_decoders().is_empty(),
                        "contradictory direct-plaintext and bulk evidence: {hash}"
                    );
                }
                assert_eq!(
                    !analysis.scratch_decoders().is_empty() || !analysis.bulk_decoders().is_empty(),
                    expected_encoding == Encoding::Encrypted,
                    "every published AES receiver needs independently traced header/body evidence: {hash}"
                );
            }
            assert_eq!(detected.encoding(), expected_encoding);
            let alternate = !boot
                && expected_encoding == Encoding::Encrypted
                && flags["images"][hash]["mode_six"]["buffer_id"] == 0x67;
            assert_eq!(
                detected.prepare_command(),
                Some(if alternate {
                    cdb::Prepare::ModeSix67
                } else {
                    cdb::Prepare::ModeOne
                })
            );
            // Exercise the shared executable-plan constructor with a real
            // canonical image, not only the diagnostic encoding label.
            let recovery = mediatek_optical::recovery::Receiver::identify(&mut device)
                .unwrap()
                .unwrap();
            let prepared = recovery.prepare(&device.bytes);
            let scratch_only = detected
                .application_analysis()
                .is_some_and(|a| !a.scratch_decoders().is_empty());
            let prepared = prepared.unwrap_or_else(|e| panic!("{hash} BOOT={boot}: {e}"));
            let mut expected = device.bytes.clone();
            if scratch_only {
                mediatek_optical::enc::encrypt(&mut expected[0x3000..0x3010]).unwrap();
                assert_eq!(prepared.plan().prepare_command().command()[9], 0x0a);
                assert_eq!(prepared.plan().encoding().header, Encoding::Encrypted);
                assert_eq!(prepared.plan().encoding().body, Encoding::Plaintext);
            } else if expected_encoding == Encoding::Encrypted {
                mediatek_optical::enc::encrypt(&mut expected).unwrap();
                assert_eq!(prepared.plan().encoding().body, Encoding::Encrypted);
                assert_eq!(prepared.plan().prepare_command().command()[9], 0x0b);
            } else {
                assert_eq!(prepared.plan().encoding().header, Encoding::Plaintext);
                assert_eq!(prepared.plan().encoding().body, Encoding::Plaintext);
            }
            assert_eq!(
                prepared.transfer(),
                expected,
                "wire bytes {hash} BOOT={boot}"
            );
            assert_eq!(
                prepared.plan().image(),
                device.bytes,
                "canonical bytes must remain intact"
            );
            let envelope = mediatek_optical::envelope::Envelope::load(&device.bytes).unwrap();
            let identity = mediatek_optical::Identity::parse(
                &[0; mediatek_optical::INQUIRY_LEN],
                mediatek_optical::layout::BANNER.of(&device.bytes).unwrap(),
                mediatek_optical::layout::DESCRIPTOR
                    .of(&device.bytes)
                    .unwrap(),
            )
            .unwrap();
            let installed =
                mediatek_optical::update::InstalledFirmware::new(identity, &device.bytes).unwrap();
            let flash = detected
                .prepare(&envelope, &installed)
                .unwrap_or_else(|e| panic!("Flash {hash} BOOT={boot}: {e}"));
            assert_eq!(
                flash.plan().transfer(),
                prepared.transfer(),
                "Flash and Recovery share the same bytes"
            );
            assert_eq!(
                flash.plan().prepare_command(),
                prepared.plan().prepare_command()
            );
            let format = format!(
                "header_{:?}_body_{:?}",
                prepared.plan().encoding().header,
                prepared.plan().encoding().body
            );
            *transfer_counts.entry(format.clone()).or_default() += 1;
            transfer_cases.push(serde_json::json!({"sha256":hash,"mode":format!("{:?}",expected_mode),"format":format,"prepare":prepared.plan().prepare_command().command(),"flash_and_recovery_prepared":true}));
            device.bytes[detected.signature_address() as usize] ^= 1;
            assert!(detected.revalidate(&mut device).is_err());
            count += 1;
        }
    }
    assert_eq!(count, 272);
    assert_eq!(
        scratch_receivers, 2,
        "held INTM applications have scratch-header/direct-signature evidence"
    );
    assert_eq!(bulk_receivers, 15);
    assert_eq!(
        transfer_counts.get("header_Plaintext_body_Plaintext"),
        Some(&234)
    );
    assert_eq!(
        transfer_counts.get("header_Encrypted_body_Encrypted"),
        Some(&36)
    );
    assert_eq!(
        transfer_counts.get("header_Encrypted_body_Plaintext"),
        Some(&2)
    );
    std::fs::write("target/receiver-transfer-coverage.json", serde_json::to_vec_pretty(&serde_json::json!({"published_members":136,"receiver_modes":272,"transfer_combinations":transfer_counts,"cases":transfer_cases})).unwrap()).unwrap();
    eprintln!("272 live receiver mode/encoding/PREPARE selections and stale-binding refusals passed; no device writes");
}

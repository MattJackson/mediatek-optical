//! Real receiver instruction checks and explicit whole-hoard discovery accounting.
//! Discovery counts are not acceptance or authorization counts.
#![cfg(all(feature = "drive", feature = "image", feature = "enc"))]

use mediatek_optical::receiver::decoding::{branch_link, trace_call, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn images() -> (PathBuf, Vec<PathBuf>) {
    let root = PathBuf::from(std::env::var("MTK_HOARD_ROOT").expect("set MTK_HOARD_ROOT"));
    let mut paths = Vec::new();
    files(&root.join("images/mediatek"), &mut paths);
    paths.sort();
    (root, paths)
}

fn firmware(paths: &[PathBuf], digest: &str) -> Vec<u8> {
    let path = paths
        .iter()
        .find(|p| p.file_stem().unwrap() == digest)
        .unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), digest);
    bytes
}

#[test]
#[ignore = "requires private MTK_HOARD_ROOT"]
fn intm_and_v9_argument_proofs_match_independent_disassembly() {
    let (_, paths) = images();
    let intm = firmware(
        &paths,
        "c3a18eed17251d1508964647e833ffdfe01b13c28dff9a717dfac6336e7c70e6",
    );
    let v9 = firmware(
        &paths,
        "97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061",
    );
    let v9_selection =
        mediatek_optical::receiver::programming::inspect_selection(&v9, 0, 0x9d7fc).unwrap();
    assert_eq!(v9_selection.offset_cell, 0x02000c60);
    assert_eq!(v9_selection.start_cell, 0x02000c68);
    assert_eq!(v9_selection.length_cell, 0x02000c6c);
    assert_eq!(v9_selection.end, 0x9d824);
    for offset in [2, 4, 8, 12, 14, 16, 20, 24, 26, 28, 30, 32, 34, 38] {
        let mut changed = v9.clone();
        changed[0x9d7fc + offset] ^= 1;
        assert!(
            mediatek_optical::receiver::programming::inspect_selection(&changed, 0, 0x9d7fc)
                .is_none()
        );
    }
    let unknown = [Value::Unknown; 8];
    use mediatek_optical::receiver::analysis::ApplicationAnalysis;
    let v9_analysis = ApplicationAnalysis::inspect(&v9[0x98000..0xb4000], 0x98000).unwrap();
    assert_eq!(v9_analysis.bulk_decoders().len(), 1);
    let bulk = &v9_analysis.bulk_decoders()[0];
    assert_eq!(bulk.header.address, 0x9d768);
    assert_eq!(bulk.from_zero.address, 0x9d836);
    assert_eq!(
        bulk.from_zero.source,
        Value::Loaded {
            cell: 0x02000c34,
            offset: 0
        }
    );
    assert_eq!(
        bulk.preserving_boot.source,
        Value::Loaded {
            cell: 0x02000c34,
            offset: 0x10000
        }
    );
    assert_eq!(bulk.preserving_boot.length, 0x200000);
    for address in [
        0x9d824, 0x9d826, 0x9d828, 0x9d82a, 0x9d82c, 0x9d82e, 0x9d830, 0x9d832, 0x9d834, 0x9d836,
    ] {
        let mut mutated = v9[0x98000..0xb4000].to_vec();
        mutated[address - 0x98000] ^= 1;
        let changed = ApplicationAnalysis::inspect(&mutated, 0x98000).unwrap();
        assert!(
            changed.bulk_decoders().is_empty(),
            "bulk operand mutation {address:x}"
        );
    }
    let cached = ApplicationAnalysis::inspect(&intm[0x98000..0xb4000], 0x98000).unwrap();
    assert_eq!(cached.ranges().len(), 1);
    assert_eq!(
        cached.ranges()[0]
            .acceptance
            .as_ref()
            .unwrap()
            .program_target,
        0x140a5a
    );
    assert_eq!(cached.integrity_selections().len(), 1);
    assert_eq!(cached.scratch_decoders().len(), 1);
    assert_eq!(cached.scratch_decoders()[0].address, 0x9d48e);
    assert!(cached.bulk_decoders().is_empty());
    assert!(!cached.conflicting_arguments());
    let mut damaged = intm[0x98000..0xb4000].to_vec();
    damaged[0x9d580 - 0x98000] ^= 1;
    let changed = ApplicationAnalysis::inspect(&damaged, 0x98000).unwrap();
    assert_eq!(changed.ranges().len(), 1);
    assert!(changed.ranges()[0].signature.is_none());
    assert!(changed.ranges()[0].acceptance.is_none());
    assert!(changed.scratch_decoders().is_empty());
    assert!(ApplicationAnalysis::inspect(&damaged, u32::MAX - 1).is_none());
    // Bind the separately checked update-flag body to the actual WRITE BUFFER
    // registration and mode-six stream. This is entry evidence, not a proof of
    // the intervening stream-to-header control flow.
    use mediatek_optical::receiver::entry::application;
    let window = &intm[0x98000..0xb4000];
    let entry = application::inspect(window, 0x98000).unwrap();
    let prologue = application::inspect_prologue(window, 0x98000, &entry).unwrap();
    assert_eq!(prologue.start, 0x9cd6c);
    let registration =
        application::inspect_registration(&intm[0x140000..0x1b0000], 0x140000, prologue.start)
            .unwrap();
    assert_eq!(registration.callback, prologue.start);
    let flags = application::inspect_flags(window, 0x98000, &entry, &prologue).unwrap();
    assert_eq!(flags.entry, entry.entry);
    let stream = application::inspect_mode_six(window, 0x98000, &entry, &prologue).unwrap();
    assert!(matches!(
        stream,
        application::ModeSix::StreamZero { guard: 0x9d34c, .. }
    ));
    // Invalidate CDB byte-nine selection independently of the AES/range facts.
    // A recognized decoder must never make malformed entry code acceptable.
    let flag_load = (flags.entry as usize..flags.end as usize)
        .step_by(2)
        .find(|&at| {
            let word = u16::from_le_bytes(intm[at..at + 2].try_into().unwrap());
            word & 0xffc0 == 0x7800 | (9 << 6)
        })
        .unwrap();
    let mut changed = window.to_vec();
    changed[flag_load - 0x98000] ^= 0x40;
    assert!(application::inspect_flags(&changed, 0x98000, &entry, &prologue).is_none());
    let header = trace_call(&intm, 0, 0x9d480, unknown, |a| {
        (a == Value::Constant(0x02000c34)).then_some(Value::Staging(0))
    })
    .unwrap();
    assert_eq!(
        (header.address, header.target, header.length),
        (0x9d48e, 0x9b024, 16)
    );
    assert_eq!(header.source, Value::Staging(0x3000));
    assert_eq!(header.destination, Value::Stack(0x14));
    let selection =
        mediatek_optical::receiver::programming::inspect_legacy_selection(&intm, 0, 0x9d522)
            .unwrap();
    assert_eq!(selection.offset_cell, 0x02000c60);
    assert_eq!(selection.start_cell, 0x02000c68);
    assert_eq!(selection.length_cell, 0x02000c6c);
    assert_eq!(selection.total_pointer_register, 4);
    let signature =
        mediatek_optical::receiver::programming::inspect_plain_signature(&intm, 0, &selection)
            .unwrap();
    assert_eq!(signature.staging_cell, 0x02000c34);
    assert_eq!((signature.offset, signature.length), (0x10600, 8));
    assert_eq!(signature.mismatch, 0x9d602);
    assert_eq!(signature.success, 0x9d592);
    assert_eq!(signature.outside_range, 0x9d60c);
    let reserved =
        mediatek_optical::receiver::programming::inspect_reserved_skips(&intm, 0, 0x17078).unwrap();
    assert_eq!(
        (reserved.first_start, reserved.first_length),
        (0x1d0000, 0x1c000)
    );
    assert_eq!(
        (reserved.final_start, reserved.required_r4),
        (0x1f0000, 0x10000)
    );
    assert_eq!(reserved.continuation, 0x170b6);
    assert_eq!(reserved.finished, 0x17278);
    for address in (0x17078..0x170b4).step_by(2) {
        let mut changed = intm.clone();
        changed[address] ^= 1;
        assert!(
            mediatek_optical::receiver::programming::inspect_reserved_skips(&changed, 0, 0x17078,)
                .is_none(),
            "reserved-region mutation {address:x}"
        );
    }
    assert!(
        mediatek_optical::receiver::programming::inspect_reserved_skips(
            &intm[..0x170b6],
            0,
            0x17078,
        )
        .is_none()
    );
    for address in [0x9d54c, 0x9d566, 0x9d57c, 0x9d580, 0x9d58e, 0x9d590] {
        let mut changed = intm.clone();
        changed[address] ^= 1;
        assert!(
            mediatek_optical::receiver::programming::inspect_plain_signature(
                &changed, 0, &selection,
            )
            .is_none(),
            "signature mutation {address:x}"
        );
    }
    let integrity =
        mediatek_optical::receiver::programming::inspect_legacy_integrity(&intm, 0, 0x9d618)
            .unwrap();
    assert_eq!(integrity.boot_check, 0x140886);
    assert_eq!(integrity.application_check, 0x1408a4);
    assert_eq!(integrity.success, 0x9d63e);
    assert_eq!(integrity.failure, 0x9d632);
    for offset in [2, 4, 6, 12, 14, 16, 22] {
        let mut changed = intm.clone();
        changed[0x9d618 + offset] ^= 1;
        assert!(mediatek_optical::receiver::programming::inspect_legacy_integrity(
            &changed,0,0x9d618,
        ).is_none(), "integrity mutation {offset}");
    }
    let tail = mediatek_optical::receiver::programming::inspect_acceptance_tail(
        &intm, 0, &selection, &signature, &integrity,
    )
    .unwrap();
    assert_eq!(tail.program_call, 0x9d69c);
    assert_eq!(tail.program_target, 0x140a5a);
    assert_eq!(tail.tag_check, 0x9ccba);
    assert_eq!(tail.marker_check, 0x9cc90);
    assert_eq!(tail.descriptor_byte, 0x1ec056);
    assert_eq!(tail.error, 0x9d094);
    for offset in [
        4, 6, 14, 20, 22, 24, 26, 28, 32, 38, 40, 42, 48, 50, 58, 60, 62, 68, 70, 76, 78, 80, 84,
        86, 90, 92, 98,
    ] {
        let mut changed = intm.clone();
        changed[0x9d63e + offset] ^= 1;
        assert!(
            mediatek_optical::receiver::programming::inspect_acceptance_tail(
                &changed, 0, &selection, &signature, &integrity,
            )
            .is_none(),
            "acceptance mutation {offset:x}"
        );
    }
    for start in [0, 0x10000] {
        let mut registers = unknown;
        registers[4] = Value::Constant(selection.offset_cell);
        let write = trace_call(&intm, 0, 0x9d690, registers, |a| match a {
            Value::Constant(address)
                if address == selection.offset_cell || address == selection.start_cell =>
            {
                Some(Value::Constant(start))
            }
            Value::Constant(address) if address == selection.length_cell => {
                Some(Value::Constant(0x200000 - start))
            }
            _ => None,
        })
        .unwrap();
        assert_eq!(write.address, 0x9d69c);
        assert_eq!(write.target, 0x140a5a);
        assert_eq!(write.source, Value::Constant(start));
        assert_eq!(write.destination, Value::Constant(start));
        assert_eq!(write.length, 0x200000 - start);
        assert_eq!(write.fourth_argument, Value::Constant(3));
    }

    let bu40n = firmware(
        &paths,
        "29ad302647148e270c15a5a4542aa4796ee9ba25ea9fbf9f2be9465c01c139a7",
    );
    let header = trace_call(&bu40n, 0, 0x9d3dc, unknown, |a| {
        (a == Value::Constant(0x02000c78)).then_some(Value::Staging(0))
    })
    .unwrap();
    assert_eq!(
        (header.address, header.target, header.length),
        (0x9d3ee, 0x9ae04, 16)
    );
    assert_eq!(header.source, Value::Staging(0x3000));
    assert_eq!(header.destination, Value::Stack(0x1c));
    let bu_selection =
        mediatek_optical::receiver::programming::inspect_selection(&bu40n, 0, 0x9d482).unwrap();
    assert_eq!(bu_selection.end, 0x9d4ac);
    assert_eq!(bu_selection.total_pointer_register, 4);
    let bu_signature =
        mediatek_optical::receiver::programming::inspect_plain_signature(&bu40n, 0, &bu_selection)
            .unwrap();
    assert_eq!(bu_signature.staging_cell, 0x02000c78);
    assert_eq!(bu_signature.mismatch, 0x9d562);
    let cached = ApplicationAnalysis::inspect(&bu40n[0x98000..0xb4000], 0x98000).unwrap();
    assert_eq!(cached.scratch_decoders().len(), 1);
    assert_eq!(cached.scratch_decoders()[0].address, 0x9d3ee);
    assert!(!cached.conflicting_arguments());

    let mut boot_registers = unknown;
    boot_registers[4] = Value::Constant(0x200000);
    boot_registers[5] = Value::Constant(0x02000d80);
    let boot = trace_call(&intm, 0, 0x369e, boot_registers, |a| match a {
        Value::Constant(0x02000d94) => Some(Value::Constant(0)),
        Value::Constant(0x02000d9c) => Some(Value::Staging(0)),
        _ => None,
    })
    .unwrap();
    assert_eq!(
        (boot.address, boot.target, boot.length),
        (0x36ac, 0x5500, 0x200000)
    );
    assert_eq!(boot.source, Value::Staging(0));
    assert_eq!(boot.destination, boot.source);

    for start in [0, 0x10000] {
        let full = trace_call(&v9, 0, 0x9d824, unknown, |a| match a {
            Value::Constant(0x02000c68) => Some(Value::Constant(start)),
            Value::Constant(0x02000c34) => Some(Value::Staging(0)),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            (full.address, full.target, full.length),
            (0x9d836, 0x9b11e, 0x200000)
        );
        assert_eq!(full.source, Value::Staging(start));
        assert_eq!(full.destination, full.source);
    }
}

fn aes_prologue(bytes: &[u8], address: u32) -> bool {
    // Independent discovery fingerprint. Full routine/dispatch proofs are separate.
    let signature: &[u16] = &[
        0xf7, 0xb5, 6, 0, 0x14, 0, 256, 0x48, 0x11, 0, 0x84, 0xb0, 256, 256, 256, 256, 0, 0x2c, 1,
        0xd0, 0x20, 7, 2, 0xd0, 0, 0x20, 7, 0xb0, 0xf0, 0xbd, 0xa0, 8, 1, 0x22, 0x92, 6, 2, 0x90,
        0x10, 0x68, 0x10, 0x21, 0x88, 0x43, 0x10, 0x60,
    ];
    bytes
        .get(address as usize..)
        .and_then(|b| b.get(..signature.len()))
        .is_some_and(|b| {
            b.iter()
                .zip(signature)
                .all(|(&a, &e)| e == 256 || u16::from(a) == e)
        })
}

#[test]
#[ignore = "offline candidate validation; requires private MTK_HOARD_ROOT"]
fn intm_mixed_candidate_preserves_boot_and_passes_held_image_integrity() {
    use mediatek_optical::{
        enc,
        image::cmac,
        receiver::layout::{analyze, Operation},
    };
    let (_, paths) = images();
    let current = firmware(
        &paths,
        "c3a18eed17251d1508964647e833ffdfe01b13c28dff9a717dfac6336e7c70e6",
    );
    let target = firmware(
        &paths,
        "97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061",
    );
    // Facts from disassembly: scratch check, signature, normal tag/marker,
    // descriptor, CMAC-covered regions, and the two nonreserved write spans.
    let mut operations = vec![
        Operation::CheckDecrypted(0x3000..0x3010),
        Operation::CheckPlaintext(0x10600..0x10608),
        Operation::CheckPlaintext(0x105c0..0x105d0),
        Operation::CheckPlaintext(0x1ec056..0x1ec057),
    ];
    for entry in cmac::parse_table(&target)
        .unwrap()
        .into_iter()
        .filter(|e| e.is_active())
    {
        operations.push(Operation::CheckPlaintext(
            entry.start as usize..entry.end as usize + 1,
        ));
    }
    operations.push(Operation::Program(0x10000..0x1d0000));
    operations.push(Operation::Program(0x1ec000..0x1f0000));
    let plan = analyze(target.len(), &operations).unwrap();
    assert_eq!(plan.encrypted_ranges().len(), 1);
    assert_eq!(plan.encrypted_ranges()[0], 0x3000..0x3010);
    let wire = plan.encode(&target).unwrap();
    let mut scratch = wire[0x3000..0x3010].to_vec();
    enc::decrypt(&mut scratch).unwrap();
    assert_eq!(scratch, current[0x3000..0x3010]);
    assert_eq!(wire[0x10600..0x10608], current[0x10600..0x10608]);
    assert_eq!(wire[0x105c0..0x105d0], current[0x105c0..0x105d0]);
    assert_eq!(wire[0x1ec056], 0xde);
    // Independent execution of the held wrapper in emulate_intm.py establishes
    // these descriptor-derived inputs to secure service 0x72. The candidate
    // preserves them byte-for-byte; this is input equivalence, not emulation of
    // the encrypted service implementation.
    assert_eq!(
        &wire[0x10610..0x10618],
        &[0x00, 0x40, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x00]
    );
    assert_eq!(wire[0x14000..0x14c00], current[0x14000..0x14c00]);
    assert_eq!(wire[0x10618..0x10640], current[0x10618..0x10640]);
    assert!(cmac::verify(&wire));
    assert_ne!(
        cmac::compute_stored_digest(&wire, 0x1000, 0xffef).unwrap(),
        wire[0xfff0..0x10000]
    );

    let mut installed = current.clone();
    for range in plan.programmed_ranges() {
        installed[range.clone()].copy_from_slice(&wire[range.clone()]);
        assert_eq!(installed[range.clone()], target[range.clone()]);
    }
    assert_eq!(installed[..0x10000], current[..0x10000]);
    assert_eq!(installed[0x1d0000..0x1ec000], current[0x1d0000..0x1ec000]);
    assert_eq!(installed[0x1f0000..], current[0x1f0000..]);
    assert!(cmac::verify(&installed));
    assert_eq!(
        cmac::compute_stored_digest(&installed, 0x1000, 0xffef).unwrap(),
        installed[0xfff0..0x10000]
    );

    // With the original boot-validation policy the candidate must be rejected.
    operations.insert(1, Operation::CheckPlaintext(0x1000..0xfff0));
    assert!(matches!(
        analyze(target.len(), &operations),
        Err(mediatek_optical::receiver::layout::Error::Conflict { block: 0x3000 })
    ));
}

#[test]
#[ignore = "discovery only; requires MTK_HOARD_ROOT and optionally MTK_DECODING_REPORT"]
fn every_normalized_mediatek_file_is_accounted_for_in_discovery() {
    let (root, paths) = images();
    assert!(!paths.is_empty());
    let mut rows = Vec::new();
    let mut counts = BTreeMap::<String, usize>::new();
    for path in &paths {
        let bytes = std::fs::read(path).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let firmware = path.extension().is_some_and(|extension| extension == "bin");
        let image_validation = if firmware {
            use mediatek_optical::envelope::{Envelope, Error, InputEncoding};
            use mediatek_optical::update::PrepareError;
            assert_eq!(
                path.file_stem().unwrap().to_str().unwrap(),
                digest,
                "hoard filename must bind actual bytes: {}",
                path.display()
            );
            let (status, detail) = match Envelope::load(&bytes) {
                Ok(envelope) => {
                    let encoding = match envelope.input_encoding() {
                        InputEncoding::Plaintext => "plaintext",
                        InputEncoding::Encrypted => "encrypted",
                    };
                    *counts
                        .entry(format!("input_encoding:{encoding}"))
                        .or_default() += 1;
                    (
                        "valid",
                        serde_json::json!({"input_encoding": encoding,
                        "chip": format!("{:?}", envelope.chip()),
                        "canonical_sha256": format!("{:x}", Sha256::digest(envelope.image()))}),
                    )
                }
                Err(error) => {
                    let status = match &error {
                        Error::Image(PrepareError::Size(_)) => "unsupported_size",
                        Error::Image(PrepareError::DriveRead) => "drive_capture",
                        Error::Image(PrepareError::Integrity) => "integrity_rejected",
                        Error::UnknownFraming => "unsupported_framing",
                        Error::Ambiguous => "ambiguous",
                        _ => "validation_rejected",
                    };
                    (status, serde_json::json!({"error": format!("{error:?}")}))
                }
            };
            *counts
                .entry(format!("image_validation:{status}"))
                .or_default() += 1;
            serde_json::json!({"status": status, "detail": detail})
        } else {
            serde_json::Value::Null
        };
        let mut receivers = Vec::new();
        for (mode, low, high) in [("boot", 0x3400, 0x3a00), ("application", 0x98000, 0xb4000)] {
            if !firmware || bytes.len() != 0x200000 {
                continue;
            }
            let mut calls = Vec::new();
            let mut selections = Vec::new();
            let mut integrity = Vec::new();
            for address in (low..high).step_by(2) {
                if let Some(target) = branch_link(&bytes, 0, address) {
                    if aes_prologue(&bytes, target) {
                        calls.push(serde_json::json!({"address": address, "target": target}));
                    }
                }
                if mode == "application" {
                    if let Some(s) = mediatek_optical::receiver::programming::inspect_selection(
                        &bytes, 0, address,
                    ) {
                        let direct_signature =
                            mediatek_optical::receiver::programming::inspect_plain_signature(
                                &bytes, 0, &s,
                            );
                        if direct_signature.is_some() {
                            *counts
                                .entry("application:direct_plain_signature".into())
                                .or_default() += 1;
                        }
                        selections.push(serde_json::json!({"address": s.address, "end": s.end,
                            "offset_cell": s.offset_cell, "start_cell": s.start_cell,
                            "length_cell": s.length_cell, "total_pointer_register": s.total_pointer_register,
                            "direct_plain_signature": direct_signature.map(|proof| serde_json::json!({
                                "staging_cell": proof.staging_cell, "offset": proof.offset,
                                "length": proof.length, "success": proof.success,
                                "mismatch": proof.mismatch, "outside_range": proof.outside_range,
                            }))}));
                    }
                    if let Some(s) =
                        mediatek_optical::receiver::programming::inspect_legacy_integrity(
                            &bytes, 0, address,
                        )
                    {
                        integrity.push(serde_json::json!({"address": s.address,
                            "boot_check": s.boot_check, "application_check": s.application_check,
                            "success": s.success, "failure": s.failure}));
                    }
                }
            }
            if mode == "application" {
                *counts
                    .entry(format!("application:{}_range_selections", selections.len()))
                    .or_default() += 1;
                *counts
                    .entry(format!(
                        "application:{}_integrity_selections",
                        integrity.len()
                    ))
                    .or_default() += 1;
            }
            *counts
                .entry(format!("{mode}:{}_aes_calls", calls.len()))
                .or_default() += 1;
            receivers.push(serde_json::json!({"mode": mode, "aes_calls": calls,
                "range_selections": selections, "integrity_selections": integrity,
                "contract_status": "unproven", "encoding": null}));
        }
        let status = if !firmware {
            "non_firmware_file"
        } else if receivers.is_empty() {
            "outside_2MiB_discovery"
        } else {
            "discovered_not_proven"
        };
        *counts.entry(status.into()).or_default() += 1;
        rows.push(serde_json::json!({
            "path": path.strip_prefix(&root).unwrap().to_string_lossy(), "sha256": digest,
            "size": bytes.len(), "firmware": firmware, "status": status, "receivers": receivers,
            "image_validation": image_validation,
        }));
    }
    let report = serde_json::json!({
        "scope": "Every physical file under images/mediatek; no deduplication or skipped rows",
        "qualification": "Input validation plus receiver discovery; input encodings are not receiver transfer formats; zero complete contracts asserted",
        "files": paths.len(), "counts": counts, "rows": rows,
    });
    if let Ok(path) = std::env::var("MTK_DECODING_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    eprintln!("{} files: {}", paths.len(), report["counts"]);
    assert_eq!(report["rows"].as_array().unwrap().len(), paths.len());
}

#[test]
#[ignore = "requires private MTK_HOARD_ROOT"]
fn intm_to_v9_prepares_exact_mixed_wire_with_boot_preserved() {
    use mediatek_optical::{
        enc, envelope::Envelope, layout, receiver, update, Identity, INQUIRY_LEN,
    };
    let (_, paths) = images();
    let current = firmware(
        &paths,
        "c3a18eed17251d1508964647e833ffdfe01b13c28dff9a717dfac6336e7c70e6",
    );
    let target = firmware(
        &paths,
        "97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061",
    );
    let current_env = Envelope::load(&current).unwrap();
    let receiver = receiver::Receiver::from_firmware(&current_env).unwrap();
    let live = Identity::parse(
        &[0; INQUIRY_LEN],
        layout::BANNER.of(&current).unwrap(),
        layout::DESCRIPTOR.of(&current).unwrap(),
    )
    .unwrap();
    let installed = update::InstalledFirmware::new(live.clone(), &current).unwrap();
    let mut ciphertext = target.clone();
    enc::encrypt(&mut ciphertext).unwrap();
    for input in [&target, &ciphertext] {
        let env = Envelope::load(input).unwrap();
        for plan in [
            receiver.prepare(&env, &installed).unwrap(),
            receiver.prepare_without_installed(&env, &live).unwrap(),
        ] {
            assert_eq!(plan.plan().image(), target);
            assert_eq!(env.image(), target);
            assert_eq!(env.original(), input);
            assert_eq!(plan.plan().encoding().header, receiver::Encoding::Encrypted);
            assert_eq!(plan.plan().encoding().body, receiver::Encoding::Plaintext);
            assert_eq!(plan.plan().prepare_command().command()[9], 0x0a);
            assert_eq!(
                plan.plan().programmed_ranges().unwrap(),
                &[0x10000..0x1d0000, 0x1ec000..0x1f0000]
            );
            assert_eq!(
                plan.plan().preserved_ranges().unwrap(),
                vec![0..0x10000, 0x1d0000..0x1ec000, 0x1f0000..0x200000]
            );

            let wire = plan.plan().transfer();
            assert_eq!(&wire[..0x3000], &target[..0x3000]);
            assert_eq!(&wire[0x3010..], &target[0x3010..]);
            let mut header = wire[0x3000..0x3010].to_vec();
            enc::decrypt(&mut header).unwrap();
            assert_eq!(header, current[0x3000..0x3010]);
            assert_eq!(&wire[0x10600..0x10608], &current[0x10600..0x10608]);
            assert_ne!(&ciphertext[0x10600..0x10608], &current[0x10600..0x10608]);
        }
    }
    let mut missing_marker = target.clone();
    missing_marker[0x1ec056] = 0xff;
    let missing_marker = mediatek_optical::image::cmac::resign(&missing_marker).unwrap();
    let env = Envelope::load(&missing_marker).unwrap();
    assert!(matches!(
        receiver.prepare(&env, &installed),
        Err(update::PrepareError::ReceiverContract)
    ));
}

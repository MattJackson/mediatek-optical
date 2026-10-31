use super::{Error, UhdArea, UhdAreas};
use sha2::{Digest, Sha256};
use std::path::Path;

fn area(name: &str) -> UhdArea {
    match name {
        "di_identifier_recognition" => UhdArea::DiscInformation,
        "hardware_control_bit" => UhdArea::ControlBit,
        "hardware_control_field" => UhdArea::ControlField,
        "forward_calculation" => UhdArea::ForwardCalculation,
        "reverse_calculation" => UhdArea::ReverseCalculation,
        "hardware_parameter_nibble" => UhdArea::ParameterNibble,
        "speed_defaults_hardware_sensitive" => UhdArea::HardwareDefaults,
        _ => panic!("unknown fixture role"),
    }
}
fn fixtures() -> (std::path::PathBuf, Vec<serde_json::Value>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/analysis/uhd");
    let cases = serde_json::from_slice(&std::fs::read(root.join("sources.json")).unwrap()).unwrap();
    (root, cases)
}
fn image(root: &Path, case: &serde_json::Value) -> Vec<u8> {
    let mut image = vec![0xff; 0x200000];
    for part in case["parts"].as_array().unwrap() {
        let bytes = std::fs::read(root.join(part["file"].as_str().unwrap())).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            part["sha256"].as_str().unwrap()
        );
        let at = part["offset"].as_u64().unwrap() as usize;
        image[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    image
}
#[test]
fn uhd_contracts_bind_all_reference_variants_and_shared_state() {
    let (root, cases) = fixtures();
    for case in cases {
        let image = image(&root, &case);
        let contracts = UhdAreas::inspect(&image);
        for expected in case["areas"].as_array().unwrap() {
            let role = area(expected["area"].as_str().unwrap());
            let contract = contracts
                .area(role)
                .unwrap_or_else(|e| panic!("{} {role:?}: {e}", case["source_sha256"]));
            assert_eq!(contract.site(), expected["site"].as_u64().unwrap() as usize);
            assert_eq!(contract.variant(), expected["variant"].as_str().unwrap());
            if role == UhdArea::HardwareDefaults {
                assert_eq!(contract.selects_c7(), None);
            }
        }
        assert_eq!(
            contracts.state_address().unwrap(),
            case["state"].as_u64().unwrap() as u32
        );
    }
}
#[test]
fn uhd_contracts_reject_duplicate_role_and_disagreeing_state_cells() {
    let (root, cases) = fixtures();
    let mut original = image(&root, &cases[0]);
    let contracts = UhdAreas::inspect(&original);
    let contract = contracts.area(UhdArea::ControlBit).unwrap();
    let literal_at = contract.literals()[0].instruction;
    let op = u16::from_le_bytes(original[literal_at..literal_at + 2].try_into().unwrap());
    let pool = ((literal_at + 4) & !3) + (op & 255) as usize * 4;
    let other = contracts.state_address().unwrap() + 1;
    original[pool..pool + 4].copy_from_slice(&other.to_le_bytes());
    assert_eq!(
        UhdAreas::inspect(&original).state_address(),
        Err(Error::InvalidContract)
    );
    let mut duplicate = image(&root, &cases[0]);
    let part = cases[0]["parts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["file"].as_str().unwrap().contains("hardware_control_bit"))
        .unwrap();
    let bytes = std::fs::read(root.join(part["file"].as_str().unwrap())).unwrap();
    duplicate[0x1d0000..0x1d0000 + bytes.len()].copy_from_slice(&bytes);
    assert_eq!(
        UhdAreas::inspect(&duplicate).area(UhdArea::ControlBit),
        Err(Error::Ambiguous)
    );
}
#[test]
fn uhd_contracts_reject_a_selector_redirected_to_an_unrelated_native_block() {
    let (root, cases) = fixtures();
    let mut image = image(&root, &cases[0]);
    let analysis = UhdAreas::inspect(&image);
    let contract = analysis.area(UhdArea::ControlField).unwrap();
    let selection = contract.selection().unwrap();
    let branch = selection.site() + selection.replay().len() * 2;
    image[branch] = image[branch].wrapping_add(1);
    assert_eq!(
        UhdAreas::inspect(&image).area(UhdArea::ControlField),
        Err(Error::InvalidContract)
    );
}

#[test]
fn classic_reverse_selector_binds_the_shared_forward_rejection_gate() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let bytes = image(&root, &case);
        let areas = UhdAreas::inspect(&bytes);
        let reverse = areas.area(UhdArea::ReverseCalculation).unwrap();
        let Some(gate) = reverse.selection() else {
            continue;
        };
        let forward = areas.area(UhdArea::ForwardCalculation).unwrap();
        let forward_gate = forward.selection().unwrap();
        assert_eq!(gate.reject(), forward_gate.site() + 2);
        assert_eq!(gate.replay(), [0x4382]);
        if case["callers"].is_array() {
            super::SavedLink::detect(&bytes, gate.site()).unwrap();
        }
        let mut bad = bytes.clone();
        bad[gate.site() + 2] ^= 1;
        assert!(UhdAreas::inspect(&bad)
            .area(UhdArea::ReverseCalculation)
            .is_err());
        let mut bad = bytes.clone();
        bad[forward_gate.site() + 2] ^= 1;
        assert!(UhdAreas::inspect(&bad)
            .area(UhdArea::ReverseCalculation)
            .is_err());
        count += 1;
    }
    assert_eq!(count, 6);
}

#[test]
fn uhd_contracts_corpus_matches_inventory_without_chip_or_model_selection() {
    let Ok(path) = std::env::var("MTK_UHD_AREA_CORPUS") else {
        return;
    };
    let hoard = std::path::PathBuf::from(std::env::var("MTK_UHD_AREA_HOARD").unwrap());
    let inventory: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for row in inventory["images"].as_array().unwrap() {
        // Category reviews can move an image between bucket roots. The hash
        // below remains authoritative; the historical path is only a hint.
        let hint = Path::new(row["path"].as_str().unwrap());
        let tail: std::path::PathBuf = hint.iter().skip(1).collect();
        let source = std::iter::once(hoard.join(hint))
            .chain(["oem", "dump", "mk", "omni"].map(|b| hoard.join(b).join(&tail)))
            .find(|p| p.is_file())
            .expect("held corpus image");
        let bytes = std::fs::read(source).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            row["sha256"].as_str().unwrap()
        );
        let contracts = UhdAreas::inspect(&bytes);
        for (name, expected) in row["areas"].as_object().unwrap() {
            let role = area(name);
            let contract = contracts
                .area(role)
                .unwrap_or_else(|e| panic!("{} {role:?}: {e}", row["sha256"]));
            let found = &expected["matches"][0];
            assert_eq!(contract.site(), found["address"].as_u64().unwrap() as usize);
            assert_eq!(
                contract.variant(),
                found["reference_style"].as_str().unwrap()
            );
        }
        contracts.state_address().unwrap();
        if contracts
            .area(UhdArea::DiscInformation)
            .unwrap()
            .variant()
            .starts_with("classic")
        {
            super::ClassicDi::detect(&bytes).unwrap_or_else(|e| panic!("{}: {e}", row["sha256"]));
            super::ClassicConsumer::inspect(&bytes, contracts.state_address().unwrap())
                .unwrap_or_else(|e| panic!("{} consumers: {e}", row["sha256"]));
            super::ClassicPositionSetup::detect(&bytes, contracts.state_address().unwrap())
                .unwrap_or_else(|e| panic!("{} setup: {e}", row["sha256"]));
            super::ClassicReadPosition::detect(&bytes, contracts.state_address().unwrap())
                .unwrap_or_else(|e| panic!("{} read-position: {e}", row["sha256"]));
            super::ClassicCalibration::detect(&bytes, contracts.state_address().unwrap())
                .unwrap_or_else(|e| panic!("{} calibration: {e}", row["sha256"]));
            super::ClassicPosition::detect(&bytes, contracts.state_address().unwrap())
                .unwrap_or_else(|e| panic!("{} position: {e}", row["sha256"]));
            super::ClassicParameter::detect(&bytes, contracts.state_address().unwrap())
                .unwrap_or_else(|e| panic!("{} parameters: {e}", row["sha256"]));
        }
    }
}

#[test]
fn stack20_parameter_getter_is_state_independent_and_uses_its_native_table() {
    let (root, _) = fixtures();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("uh12-stack20.json")).unwrap()).unwrap();
    for case in cases {
        let bytes = image(&root, &case);
        let p = super::ClassicParameter::detect(&bytes, 0x01ff9d61).unwrap();
        assert_eq!(p.variant, super::ClassicParameterVariant::StateIndependent);
        assert_eq!(p.entry, 0xe755a);
        assert_eq!(p.lookup, 0xe758c);
        assert_eq!(p.rates, case["parameter_rates"].as_u64().unwrap() as usize);
        assert_eq!(p.coefficients, p.rates + 0x82);
        assert_eq!(p.coefficients, p.oem_coefficients);
        assert!(p.selection.is_none());
        let calibration = super::ClassicCalibration::detect(&bytes, 0x01ff9d61).unwrap();
        assert_eq!(calibration.site, 0xe6b70);
        assert_eq!(calibration.original_base as usize - 0xc, p.coefficients);
        assert!(calibration.c7_coefficients.is_none());
        let mut bad = bytes.clone();
        bad[0xe6a38..0xe6a3a].copy_from_slice(&0x00a6u16.to_le_bytes());
        assert!(super::ClassicCalibration::detect(&bad, 0x01ff9d61).is_err());
        assert!(super::ClassicParameter::detect(&bytes, 0x01ff9d62).is_err());
        let mut bad = bytes.clone();
        // Increasing the native six-entry limit can index outside this table.
        bad[0xe7560..0xe7562].copy_from_slice(&0x2407u16.to_le_bytes());
        assert!(super::ClassicParameter::detect(&bad, 0x01ff9d61).is_err());
        let mut bad = bytes;
        // A table outside the image cannot establish native coefficients.
        let site = 0xe7586;
        let op = u16::from_le_bytes(bad[site..site + 2].try_into().unwrap());
        let pool = ((site + 4) & !3) + usize::from(op & 255) * 4;
        bad[pool..pool + 4].copy_from_slice(&0x02000000u32.to_le_bytes());
        assert!(super::ClassicParameter::detect(&bad, 0x01ff9d61).is_err());
    }
}

#[test]
fn stack20_completion_binds_native_recovery_and_stack12_reflection() {
    let (root, _) = fixtures();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("uh12-stack20.json")).unwrap()).unwrap();
    for case in cases {
        let bytes = image(&root, &case);
        let c = super::ClassicReadCompletion::inspect(&bytes, 0x01ff9d61)
            .unwrap_or_else(|e| panic!("{}: {e}", case["source_sha256"]));
        assert_eq!(c.recovery_state_register, 0);
        assert_eq!(c.recovery_request_register, 6);
        assert_eq!(c.recovery_flag_register, 5);
        assert_eq!(c.boundaries, [0x02000f4c, 0x02000f48, 0x02000f44]);
        assert!(super::ClassicReadCompletion::inspect(&bytes, 0x01ff9d62).is_err());
        let mut bad = bytes.clone();
        // The native subtype path must reload the same media-state pointer.
        let at = c.recovery_region + 16;
        let op = u16::from_le_bytes(bad[at..at + 2].try_into().unwrap());
        let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
        bad[pool..pool + 4].copy_from_slice(&0x01ff9d62u32.to_le_bytes());
        assert!(super::ClassicReadCompletion::inspect(&bad, 0x01ff9d61).is_err());
        let mut bad = bytes;
        bad[c.boundary_region + 12..c.boundary_region + 14]
            .copy_from_slice(&0x9a0bu16.to_le_bytes());
        assert!(super::ClassicReadCompletion::inspect(&bad, 0x01ff9d61).is_err());
    }
}

#[test]
fn stack20_auxiliary_variants_bind_native_registers_and_continuations() {
    use super::{ClassicConsumer, ClassicConsumerKind as K};
    let (root, _) = fixtures();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("uh12-stack20.json")).unwrap()).unwrap();
    for case in cases {
        let bytes = image(&root, &case);
        for kind in [
            K::MediaDefaults,
            K::ReadControl,
            K::DiMode,
            K::InitializationBypass,
            K::Control18,
            K::Mode23,
            K::ParameterClass,
            K::RequestArgument,
            K::ReadValue,
            K::ReadStatus,
        ] {
            ClassicConsumer::inspect_kind(&bytes, 0x01ff9d61, kind)
                .unwrap_or_else(|e| panic!("{} {kind:?}: {e}", case["source_sha256"]));
        }
        let rom = ClassicConsumer::inspect_rom(&bytes, 0x01ff9d61)
            .unwrap_or_else(|e| panic!("{} ROM: {e}", case["source_sha256"]));
        assert_eq!(rom.len(), 10);
        assert!(rom.iter().all(|c| c.kind != K::ReadBoundary));
        let status = case["read_status_region"].as_u64().unwrap() as usize;
        for (kind, region, accept, reject) in [
            (K::DiMode, 0xec170, 0xec17c, 0xec1c0),
            (K::Control18, 0x306da, 0x306e4, 0x3070e),
            (K::ReadStatus, status, status + 10, status + 40),
        ] {
            let c = ClassicConsumer::inspect_kind(&bytes, 0x01ff9d61, kind)
                .unwrap_or_else(|e| panic!("{} {kind:?}: {e}", case["source_sha256"]));
            assert_eq!(c.region, region);
            assert_eq!(c.selection.accept(), accept);
            assert_eq!(c.selection.reject(), reject);
            assert!(ClassicConsumer::inspect_kind(&bytes, 0x01ff9d62, kind).is_err());
            let mut bad = bytes.clone();
            bad[c.selection.site() + if kind == K::DiMode { 4 } else { 2 }] ^= 1;
            assert!(ClassicConsumer::inspect_kind(&bad, 0x01ff9d61, kind).is_err());
        }
    }
}

#[test]
fn stack20_speed_policy_binds_native_fixed_six_defaults_and_request_clamp() {
    let (root, _) = fixtures();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("uh12-stack20.json")).unwrap()).unwrap();
    for case in cases {
        let bytes = image(&root, &case);
        let p = super::NativeSpeedPolicy::detect(&bytes).unwrap();
        assert_eq!(p.variant, "classic_default6");
        assert_eq!(p.entry, 0x60bb6);
        assert_eq!(p.media_cell, 0x01ff9d61);
        assert_eq!(p.maximum_cell, 0x01ff9d63);
        assert_eq!(p.clamp.entry, 0x63b2e);
        assert_eq!(p.clamp.compare, 0x63b38);
        assert_eq!(p.clamp.after_clamp, 0x63b3e);
        assert_eq!(p.clamp.request_register, 4);
        let mut bad = bytes.clone();
        // A different member offset is not the maximum written by defaults.
        bad[0x63b36..0x63b38].copy_from_slice(&0x7981u16.to_le_bytes());
        assert!(super::NativeSpeedPolicy::detect(&bad).is_err());
        let mut bad = bytes;
        bad[0x63b3a..0x63b3c].copy_from_slice(&0xd800u16.to_le_bytes());
        assert!(super::NativeSpeedPolicy::detect(&bad).is_err());
    }
}

#[test]
fn earliest_parameter_binds_four_native_rates_and_runtime_coefficients() {
    let (root, _) = fixtures();
    let case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("earliest-parameter.json")).unwrap())
            .unwrap();
    let bytes = image(&root, &case);
    let state = 0x01ff9def;
    let c = super::ClassicParameter::detect(&bytes, state).unwrap();
    assert_eq!(c.entry, 0xde3f2);
    assert_eq!(c.rate_count, 4);
    assert_eq!(c.rates, 0x1541bc);
    assert_eq!(c.oem_coefficients, c.rates + 0x56);
    assert_eq!(c.coefficients, 0x01ff7910);
    assert!(c.coefficients_are_runtime);
    let gate = c.selection.unwrap();
    assert_eq!(gate.site(), 0xde44a);
    assert_eq!(gate.accept(), 0xde44e);
    assert_eq!(gate.reject(), 0xde454);
    assert!(super::ClassicParameter::detect(&bytes, state + 1).is_err());
    let mut bad = bytes.clone();
    bad[0xde404..0xde406].copy_from_slice(&0x2405u16.to_le_bytes());
    assert!(super::ClassicParameter::detect(&bad, state).is_err());
    let mut bad = bytes;
    let site = 0xde44e;
    let op = u16::from_le_bytes(bad[site..site + 2].try_into().unwrap());
    let pool = ((site + 4) & !3) + usize::from(op & 255) * 4;
    bad[pool..pool + 4].copy_from_slice(&0x04200000u32.to_le_bytes());
    assert!(super::ClassicParameter::detect(&bad, state).is_err());
}

#[test]
fn classic_parameter_profiles_preserve_state_independent_lookups_and_bind_media_tables() {
    let (root, cases) = fixtures();
    let mut media = 0;
    let mut independent = 0;
    for case in cases {
        if !case["parameter"].is_object() {
            continue;
        }
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contract = super::ClassicParameter::detect(&bytes, state).unwrap();
        assert_eq!(
            contract.entry,
            case["parameter"]["entry"].as_u64().unwrap() as usize
        );
        assert_eq!(
            contract.rates,
            case["parameter"]["rates"].as_u64().unwrap() as usize
        );
        assert_eq!(
            contract.coefficients,
            case["parameter"]["coefficients"].as_u64().unwrap() as usize
        );
        let op = if contract.variant == super::ClassicParameterVariant::MediaSelected {
            assert!(contract.selection.is_some());
            assert_ne!(contract.coefficients, contract.oem_coefficients);
            media += 1;
            contract.entry + 0x62
        } else {
            assert!(contract.selection.is_none());
            assert_eq!(contract.coefficients, contract.oem_coefficients);
            independent += 1;
            contract.entry + 0x24
        };
        let half = u16::from_le_bytes(bytes[op..op + 2].try_into().unwrap());
        let pool = ((op + 4) & !3) + (half & 255) as usize * 4;
        let mut bad = bytes.clone();
        bad[pool..pool + 4].copy_from_slice(&0x02000000u32.to_le_bytes());
        assert!(super::ClassicParameter::detect(&bad, state).is_err());
        assert!(super::ClassicParameter::detect(&bytes, state + 1).is_err());
    }
    assert_eq!((media, independent), (3, 1));
}

#[test]
fn classic_auxiliary_gates_bind_shared_state_native_edges_and_saved_callers() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let Some(expected) = case["auxiliary_consumers"].as_array() else {
            continue;
        };
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contracts = super::ClassicConsumer::inspect(&bytes, state)
            .unwrap_or_else(|e| panic!("{} consumers: {e}", case["source_sha256"]));
        assert_eq!(contracts.len(), 11);
        let rom = super::ClassicConsumer::inspect_rom(&bytes, state).unwrap();
        assert_eq!(rom.len(), 10);
        assert!(rom.iter().all(|c| c.entry_media_family.is_none()));
        let recovery = contracts
            .iter()
            .find(|c| c.kind == super::ClassicConsumerKind::ReadBoundary)
            .unwrap();
        assert_eq!(recovery.entry_media_family, Some(0xf));
        let mut wrong_family = bytes.clone();
        wrong_family[recovery.caller.entry() + 0x4c..recovery.caller.entry() + 0x4e]
            .copy_from_slice(&0x280eu16.to_le_bytes());
        assert!(super::ClassicConsumer::inspect_rom(&wrong_family, state).is_err());
        for contract in &contracts {
            let expected = expected
                .iter()
                .find(|row| row["site"].as_u64() == Some(contract.selection.site() as u64))
                .expect("source-bound expected consumer");
            assert_eq!(
                contract.region,
                expected["start"].as_u64().unwrap() as usize
            );
            assert_eq!(
                contract.selection.site(),
                expected["site"].as_u64().unwrap() as usize
            );
            assert_eq!(
                contract.caller.entry,
                expected["caller"]["entry"].as_u64().unwrap() as usize
            );
            let mut bad = bytes.clone();
            let branch_offset = if contract.selection.span() == 6 { 4 } else { 2 };
            bad[contract.selection.site() + branch_offset] ^= 1;
            assert!(super::ClassicConsumer::inspect(&bad, state).is_err());
            if contract.kind == super::ClassicConsumerKind::InitializationBypass {
                let call = contract.selection.reject() + 2;
                let target = thumb_asm::decode_bl(&bytes, call).unwrap();
                let mut bad = bytes.clone();
                bad[call..call + 4]
                    .copy_from_slice(&thumb_asm::encode_bl(call, target + 2).unwrap());
                assert!(super::ClassicConsumer::inspect(&bad, state).is_err());
            }
            count += 1;
        }
        assert!(super::ClassicConsumer::inspect(&bytes, state + 1).is_err());
    }
    assert_eq!(count, 44);
}

#[test]
fn classic_di_binds_native_frame_format_and_layer_continuations() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let image = image(&root, &case);
        let areas = UhdAreas::inspect(&image);
        if !areas
            .area(UhdArea::DiscInformation)
            .unwrap()
            .variant()
            .starts_with("classic")
        {
            continue;
        }
        let contract = super::ClassicDi::detect(&image)
            .unwrap_or_else(|e| panic!("{}: {e}", case["source_sha256"]));
        assert_eq!(contract.state, areas.state_address().unwrap());
        assert!(contract.entry < contract.epilogue);
        assert!(contract.epilogue < contract.prevalidation);
        assert!(contract.prevalidation < contract.format);
        assert!(contract.format < contract.layers);
        // Reject altered layer arithmetic, rather than assuming all C states
        // normalize alike from the identification grammar alone.
        let mut bad = image.clone();
        bad[contract.layers + 26] ^= 8;
        assert!(super::ClassicDi::detect(&bad).is_err());
        let mut bad = image.clone();
        bad[contract.format + 6] ^= 1;
        assert!(super::ClassicDi::detect(&bad).is_err());
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn routing_callers_save_lr_and_restore_native_frames() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let Some(callers) = case["callers"].as_array() else {
            continue;
        };
        let bytes = image(&root, &case);
        for expected in callers {
            let site = expected["site"].as_u64().unwrap() as usize;
            let bound = super::SavedLink::detect(&bytes, site).unwrap();
            assert_eq!(bound.entry, expected["entry"].as_u64().unwrap() as usize);
            assert_eq!(
                bound.stack_bytes,
                expected["depths"][0].as_u64().unwrap() as usize
            );
            assert_eq!(serde_json::json!(bound.returns), expected["returns"]);
            let mut bad = bytes.clone();
            bad[bound.entry + 1] &= !1; // No native LR save.
            assert!(super::SavedLink::bind(&bad, bound.entry, site).is_err());
            let mut bad = bytes.clone();
            bad[site + 4..site + 6].copy_from_slice(&0x4670u16.to_le_bytes()); // MOV r0,LR observes the detour link.
            assert!(super::SavedLink::bind(&bad, bound.entry, site).is_err());
            count += 1;
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn classic_position_binds_complete_routine_and_both_native_scales() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let Some(entry) = case["position_entry"].as_u64() else {
            continue;
        };
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contract = super::ClassicPosition::detect(&bytes, state).unwrap();
        assert_eq!(contract.entry, entry as usize);
        for selection in [&contract.input, &contract.output] {
            assert_eq!(contract.callers[0].entry, contract.callers[1].entry);
            let mut bad = bytes.clone();
            bad[selection.site() + 2] ^= 1;
            assert!(super::ClassicPosition::detect(&bad, state).is_err());
        }
        let mut bad = bytes.clone();
        bad[contract.entry + 0x52] ^= 1;
        assert!(super::ClassicPosition::detect(&bad, state).is_err());
        assert!(super::ClassicPosition::detect(&bytes, state + 1).is_err());
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn classic_calibration_binds_startup_speed_indices_to_the_native_getter() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let Some(entry) = case["calibration_entry"].as_u64() else {
            continue;
        };
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contract = super::ClassicCalibration::detect(&bytes, state).unwrap();
        let getter = super::ClassicParameter::detect(&bytes, state).unwrap();
        assert_eq!(contract.caller.entry, entry as usize);
        assert_eq!(
            contract.original_base as usize + 0x58,
            getter.oem_coefficients
        );
        assert_eq!(
            contract.c7_coefficients.is_some(),
            getter.selection.is_some()
        );
        let mut bad = bytes.clone();
        bad[contract.site + 2] ^= 1;
        assert!(super::ClassicCalibration::detect(&bad, state).is_err());
        let mut bad = bytes.clone();
        bad[entry as usize + 0x5e] ^= 1;
        assert!(super::ClassicCalibration::detect(&bad, state).is_err());
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn classic_read_position_binds_decoder_masks_ranges_and_saved_frames() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let Some(entry) = case["read_position_entry"].as_u64() else {
            continue;
        };
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contract = super::ClassicReadPosition::detect(&bytes, state).unwrap();
        assert_eq!(contract.entry, entry as usize);
        for selection in [&contract.decode, &contract.ranges[0], &contract.ranges[1]] {
            let mut bad = bytes.clone();
            bad[selection.site() + 2] ^= 1;
            assert!(super::ClassicReadPosition::detect(&bad, state).is_err());
        }
        assert!(super::ClassicReadPosition::detect(&bytes, state + 1).is_err());
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn classic_position_setup_binds_both_selectors_and_native_table_operands() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let Some(entry) = case["position_setup_entry"].as_u64() else {
            continue;
        };
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contract = super::ClassicPositionSetup::detect(&bytes, state).unwrap();
        assert_eq!(contract.entry, entry as usize);
        assert_eq!(contract.callers[0].entry, contract.callers[1].entry);
        for selection in [&contract.input, &contract.command] {
            let mut bad = bytes.clone();
            bad[selection.site() + 2] ^= 1;
            assert!(super::ClassicPositionSetup::detect(&bad, state).is_err());
        }
        assert!(super::ClassicPositionSetup::detect(&bytes, state + 1).is_err());
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn read_completion_binds_native_fields_boundaries_and_saved_frames() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        if !case["auxiliary_consumers"].is_array() {
            continue;
        }
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let c = super::ClassicReadCompletion::inspect(&bytes, state)
            .unwrap_or_else(|e| panic!("{} completion: {e}", case["source_sha256"]));
        assert_eq!(c.selections.len(), 3);
        let expected = &case["read_completion"];
        assert_eq!(
            c.controller_region,
            expected["controller_region"].as_u64().unwrap() as usize
        );
        assert_eq!(
            c.boundary_region,
            expected["boundary_region"].as_u64().unwrap() as usize
        );
        assert_eq!(
            c.boundary_end,
            expected["boundary_end"].as_u64().unwrap() as usize
        );
        assert_eq!(
            c.recovery_region,
            expected["recovery_region"].as_u64().unwrap() as usize
        );
        assert_eq!(
            c.recovery_end,
            expected["recovery_end"].as_u64().unwrap() as usize
        );
        assert_eq!(
            c.recovery_state_load,
            expected["recovery_state_load"].as_u64().unwrap() as usize
        );
        assert_eq!(
            c.recovery_flag_register,
            u8::try_from(expected["recovery_flag_register"].as_u64().unwrap()).unwrap()
        );
        for (s, parent) in c.selections.iter().zip(&c.callers) {
            assert!(parent.entry < s.site());
            let mut bad = bytes.clone();
            bad[s.site() + s.span() - 2] ^= 1;
            assert!(super::ClassicReadCompletion::inspect(&bad, state).is_err());
        }
        // A syntactically intact old literal is insufficient after a clobber.
        let mut bad = bytes.clone();
        let overwrite = 0x2000u16 | u16::from(c.recovery_state_register) << 8;
        bad[c.recovery_state_load + 4..c.recovery_state_load + 6]
            .copy_from_slice(&overwrite.to_le_bytes());
        assert!(super::ClassicReadCompletion::inspect(&bad, state).is_err());
        // A live path bypassing the definition must also be refused.
        let mut bad = bytes.clone();
        let branch = c.recovery_state_load - 2;
        let delta = c.recovery_region as isize - branch as isize - 4;
        let instruction = 0xe000 | ((delta / 2) as u16 & 0x7ff);
        bad[branch..branch + 2].copy_from_slice(&instruction.to_le_bytes());
        assert!(super::ClassicReadCompletion::inspect(&bad, state).is_err());
        let mut bad = bytes.clone();
        bad[c.recovery_region + 14] ^= 1;
        assert!(super::ClassicReadCompletion::inspect(&bad, state).is_err());
        // An unchanged selector cannot authorize a changed controller field.
        let mut bad = bytes.clone();
        bad[c.controller_region + 0x20] ^= 1;
        assert!(super::ClassicReadCompletion::inspect(&bad, state).is_err());
        assert!(super::ClassicReadCompletion::inspect(&bytes, state + 1).is_err());
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn classic_di_follows_format_branch_across_native_literal_island() {
    let (root, _) = fixtures();
    let case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("46b41f15-di-island.json")).unwrap())
            .unwrap();
    let bytes = image(&root, &case);
    let di = super::ClassicDi::detect(&bytes).unwrap();
    assert_eq!(di.prevalidation, 0x10c546);
    assert_eq!(di.format, 0x10c6ba);
    assert_eq!(di.state, 0x01ff9ddc);
    assert_eq!(di.one_register, 0);
    // The longer branch does not relax the destination's switch contract.
    let mut bad = bytes.clone();
    bad[di.format + 6] ^= 1;
    assert!(super::ClassicDi::detect(&bad).is_err());
    let mut bad = bytes;
    bad[di.layers + 26] ^= 8;
    assert!(super::ClassicDi::detect(&bad).is_err());
}

#[test]
fn stack20_di_admission_is_identified_as_legacy_without_a_generic_detour() {
    let (root, _) = fixtures();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("uh12-stack20.json")).unwrap()).unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let bytes = image(&root, &case);
        let areas = UhdAreas::inspect(&bytes);
        let di = areas.area(UhdArea::DiscInformation).unwrap();
        assert_eq!(di.site(), case["site"].as_u64().unwrap() as usize);
        assert_eq!(di.variant(), "classic_stack20_state_r7");
        assert_eq!(di.selects_c7(), Some(false));
        assert!(di.selection().is_none());
        assert_eq!(areas.media_state_address().unwrap(), 0x01ff9d61);
        assert_eq!(areas.state_address().unwrap(), 0x01ff9d61);
        let mut unknown_defaults = bytes.clone();
        unknown_defaults[0x60bc0..0x60bc2].copy_from_slice(&0x2505u16.to_le_bytes());
        let unknown_defaults = UhdAreas::inspect(&unknown_defaults);
        assert!(unknown_defaults.state_address().is_err());
        assert_eq!(unknown_defaults.media_state_address().unwrap(), 0x01ff9d61);
        // A missing optional hardware policy does not permit routing roles to
        // disagree about the live state address.
        let load = areas.area(UhdArea::ControlBit).unwrap().literals()[0].instruction;
        let op = u16::from_le_bytes(bytes[load..load + 2].try_into().unwrap());
        let pool = ((load + 4) & !3) + usize::from(op & 255) * 4;
        let mut disagreement = bytes.clone();
        disagreement[pool..pool + 4].copy_from_slice(&0x01ff9d62u32.to_le_bytes());
        assert!(UhdAreas::inspect(&disagreement)
            .media_state_address()
            .is_err());
        let mut bad = bytes;
        bad[di.site() + 4] = b'U';
        assert!(UhdAreas::inspect(&bad)
            .area(UhdArea::DiscInformation)
            .is_err());
    }
}

#[test]
fn stack20_di_binds_native_validation_frame_and_noncontiguous_layers() {
    let (root, _) = fixtures();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("uh12-stack20.json")).unwrap()).unwrap();
    for case in cases {
        let bytes = image(&root, &case);
        let di = super::LegacyStackDi::detect(&bytes).unwrap();
        assert_eq!(di.stack_block, 32);
        assert_eq!(di.identifier_offset, 16);
        assert_eq!(di.state_register, Some(7));
        assert_eq!(di.caller.stack_bytes(), 72);
        assert!(di.layer_store > di.layers + 80);
        let mut bad = bytes.clone();
        bad[di.layers + 4] ^= 1; // The native normalization mask is part of the contract.
        assert!(super::LegacyStackDi::detect(&bad).is_err());
        let mut bad = bytes;
        bad[di.prevalidation + 8] ^= 1;
        assert!(super::LegacyStackDi::detect(&bad).is_err());
    }
}

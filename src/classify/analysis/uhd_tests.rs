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
#[ignore = "requires private MTK_UHD_AREA_CORPUS and MTK_UHD_AREA_HOARD"]
fn uhd_contracts_corpus_matches_inventory_without_chip_or_model_selection() {
    let path = std::env::var("MTK_UHD_AREA_CORPUS")
        .expect("MTK_UHD_AREA_CORPUS must be set for this ignored test");
    let hoard = std::path::PathBuf::from(
        std::env::var("MTK_UHD_AREA_HOARD")
            .expect("MTK_UHD_AREA_HOARD must be set for this ignored test"),
    );
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
fn earliest_auxiliary_targets_bind_native_bodies_instead_of_old_displacements() {
    use super::{ClassicConsumer, ClassicConsumerKind as K};
    let (root, _) = fixtures();
    let case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("earliest-parameter.json")).unwrap())
            .unwrap();
    let bytes = image(&root, &case);
    for (kind, accept, reject) in [
        (K::Control18, 0x33878, 0x338ae),
        (K::ParameterClass, 0x348fc, 0x3484a),
        (K::DiMode, 0xe2c0e, 0xe2c36),
        (K::MediaDefaults, 0x69268, 0x69278),
        (K::ReadControl, 0xded5a, 0xded78),
        (K::InitializationBypass, 0x7eee0, 0x7eeda),
        (K::ReadValue, 0xb9224, 0xb9230),
        (K::ReadStatus, 0x14428e, 0x1442a0),
    ] {
        let c = ClassicConsumer::inspect_kind(&bytes, 0x01ff9def, kind)
            .unwrap_or_else(|e| panic!("{kind:?}: {e:?}"));
        assert_eq!(c.selection.accept(), accept);
        assert_eq!(c.selection.reject(), reject);
        if kind == K::InitializationBypass {
            assert_eq!(c.state_definition, Some((7, 0x7eea2)));
            let mut bad = bytes.clone();
            bad[0x7eea2..0x7eea4].copy_from_slice(&0x4eb9u16.to_le_bytes());
            assert!(ClassicConsumer::inspect_kind(&bad, 0x01ff9def, kind).is_err());
            let mut bad = bytes.clone();
            bad[0x7eec2..0x7eec4].copy_from_slice(&0x2700u16.to_le_bytes());
            assert!(ClassicConsumer::inspect_kind(&bad, 0x01ff9def, kind).is_err());
        }
        if matches!(kind, K::ReadValue | K::ReadStatus) {
            let mut bad = bytes.clone();
            // Redirect just one load, breaking its cross-path cell identity.
            bad[c.region + 18] ^= 1;
            assert!(ClassicConsumer::inspect_kind(&bad, 0x01ff9def, kind).is_err());
        }
        let mut bad = bytes.clone();
        bad[c.selection.site()
            + if matches!(kind, K::DiMode | K::ReadControl) {
                4
            } else {
                2
            }] ^= 1;
        assert!(ClassicConsumer::inspect_kind(&bad, 0x01ff9def, kind).is_err());
    }
}

#[test]
fn earliest_preserved_recovery_requires_its_native_f_family_guard() {
    use super::{ClassicConsumer, ClassicConsumerKind as K};
    let (root, _) = fixtures();
    let case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("earliest-parameter.json")).unwrap())
            .unwrap();
    let bytes = image(&root, &case);
    let c = ClassicConsumer::inspect_kind(&bytes, 0x01ff9def, K::ReadBoundary).unwrap();
    assert_eq!(c.entry_media_family, Some(0xf));
    assert_eq!(c.region, 0x11aae0);
    for (at, op) in [(0x11aa3e, 0x280cu16), (0x11aa4e, 0xd06d)] {
        let mut bad = bytes.clone();
        bad[at..at + 2].copy_from_slice(&op.to_le_bytes());
        assert!(ClassicConsumer::inspect_kind(&bad, 0x01ff9def, K::ReadBoundary).is_err());
    }
}

#[test]
fn earliest_completion_binds_literal_pool_split_and_native_recovery_alias() {
    let (root, _) = fixtures();
    let case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("earliest-parameter.json")).unwrap())
            .unwrap();
    let bytes = image(&root, &case);
    let c = super::ClassicReadCompletion::inspect(&bytes, 0x01ff9def).unwrap();
    assert_eq!(c.controller_region, 0x273f8);
    assert_eq!(c.boundary_region, 0x143fb6);
    assert_eq!(c.boundary_end, 0x144036);
    assert_eq!(c.boundaries, [0x02000d9c, 0x02000d98, 0x02000d94]);
    assert_eq!(c.recovery_region, 0x6e63c);
    assert_eq!(c.recovery_state_register, 1);
    assert_eq!(c.recovery_state_load, 0x6e5e8);
    assert_eq!(c.recovery_request_register, 5);
    assert_eq!(c.recovery_flag_register, 4);
    for (at, op) in [
        (0x2740e, 0xd15eu16),
        (0x27422, 0xe05d),
        (0x6e5e8, 0x0039),
        (0x6e552, 0x1f36),
        (0x143fbe, 0xd145),
    ] {
        let mut bad = bytes.clone();
        bad[at..at + 2].copy_from_slice(&op.to_le_bytes());
        assert!(super::ClassicReadCompletion::inspect(&bad, 0x01ff9def).is_err());
    }
}

#[test]
fn earliest_read_position_binds_saved_position_and_both_native_ranges() {
    let (root, _) = fixtures();
    let case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("earliest-parameter.json")).unwrap())
            .unwrap();
    let bytes = image(&root, &case);
    let c = super::ClassicReadPosition::detect(&bytes, 0x01ff9def).unwrap();
    assert_eq!(c.entry, 0xdcbf0);
    assert_eq!(c.position, 0x02000b38);
    assert_eq!(c.position_register, 5);
    assert_eq!(c.cached_layer, 0x02000b03);
    assert_eq!(c.layer, 0x02000b04);
    assert_eq!(c.status, 0x02000b10);
    assert_eq!(c.decode.site(), 0xdcc34);
    assert_eq!(c.decode.accept(), 0xdcc38);
    assert_eq!(c.decode.reject(), 0xdccba);
    assert_eq!(c.layer_one, 0xdcc40);
    assert_eq!(c.layer_zero, 0xdccb4);
    assert_eq!(c.ranges[0].site(), 0xdcd20);
    assert_eq!(c.ranges[1].site(), 0xdcd2c);
    for (at, op) in [(0xdcc38, 0x78a1u16), (0xdcd26, 0x2821), (0xdcd34, 0xd207)] {
        let mut bad = bytes.clone();
        bad[at..at + 2].copy_from_slice(&op.to_le_bytes());
        assert!(super::ClassicReadPosition::detect(&bad, 0x01ff9def).is_err());
    }
    assert!(super::ClassicReadPosition::detect(&bytes, 0x01ff9df0).is_err());
}

#[test]
fn earliest_calibration_binds_four_rate_index_and_native_default_lookup() {
    let (root, _) = fixtures();
    let case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("earliest-parameter.json")).unwrap())
            .unwrap();
    let bytes = image(&root, &case);
    let c = super::ClassicCalibration::detect(&bytes, 0x01ff9def).unwrap();
    assert_eq!(c.caller.entry(), 0xdd814);
    assert_eq!(c.site, 0xdd998);
    assert_eq!(c.original_base, 0x15421a);
    assert_eq!(c.base_adjustment, -8);
    assert_eq!(c.c7_coefficients, Some(0x01ff7910));
    for (at, op) in [(0xdd828, 0x2808u16), (0xdd860, 0x0067), (0xdd99a, 0x380c)] {
        let mut bad = bytes.clone();
        bad[at..at + 2].copy_from_slice(&op.to_le_bytes());
        assert!(super::ClassicCalibration::detect(&bad, 0x01ff9def).is_err());
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
        assert_eq!(expected.len(), 11);
        let mut matched = std::collections::BTreeSet::new();
        for contract in &contracts {
            let (index, expected) = expected
                .iter()
                .enumerate()
                .find(|(_, row)| row["site"].as_u64() == Some(contract.selection.site() as u64))
                .expect("source-bound expected consumer");
            assert!(matched.insert(index), "expected consumer bound twice");
            assert_eq!(
                contract.region,
                expected["start"].as_u64().unwrap() as usize
            );
            use super::ClassicConsumerKind as Kind;
            let kind = match contract.kind {
                Kind::Control18 => "control18",
                Kind::DiMode => "di-mode",
                Kind::ReadBoundary => "read-boundary",
                Kind::ReadControl => "read-control",
                Kind::MediaDefaults => "media-defaults",
                Kind::Mode23 => "mode23",
                Kind::ParameterClass => "parameter-class",
                Kind::RequestArgument => "request-argument",
                Kind::ReadValue => "read-value",
                Kind::ReadStatus => "read-status",
                Kind::InitializationBypass => "initialization-bypass",
            };
            assert_eq!(expected["kind"].as_str(), Some(kind));
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
fn coefficient_requires_add_reading_the_loaded_constant() {
    let code: [u16; 6] = [
        0x4801, // ldr r0, [pc, #4] -> 0x51b1
        0x18d1, // adds r1, r2, r3 (does not read r0)
        0x1840, // adds r0, r0, r1 (reads r0)
        0xbf00, 0x51b1, 0x0000,
    ];
    let mut image = vec![0u8; 16];
    for (i, h) in code.iter().enumerate() {
        image[i * 2..i * 2 + 2].copy_from_slice(&h.to_le_bytes());
    }
    // literal word at offset 8
    image[8..12].copy_from_slice(&0x51b1u32.to_le_bytes());
    assert_eq!(super::uhd::coefficient(&image, 0, false), Ok(4));
    // An unrelated add must not count when the constant is overwritten first.
    image[2..4].copy_from_slice(&0x2000u16.to_le_bytes()); // movs r0, #0
    assert!(super::uhd::coefficient(&image, 0, false).is_err());
}

#[test]
fn coefficient_constant_ends_when_any_instruction_writes_the_register() {
    let code: [u16; 6] = [
        0x4801, // ldr r0, [pc, #4] -> 0x51b1
        0x1888, // adds r0, r1, r2 (overwrites r0 without reading it)
        0x1903, // adds r3, r0, r4 (reads the new r0, not 0x51b1)
        0xbf00, 0x51b1, 0x0000,
    ];
    let mut image = vec![0u8; 16];
    for (i, h) in code.iter().enumerate() {
        image[i * 2..i * 2 + 2].copy_from_slice(&h.to_le_bytes());
    }
    image[8..12].copy_from_slice(&0x51b1u32.to_le_bytes());
    assert!(super::uhd::coefficient(&image, 0, false).is_err());
}

#[test]
fn completion_scan_includes_pattern_at_last_offset() {
    use super::uhd_completion::{locate, CONTROLLER};
    let mut image = Vec::new();
    for (value, _) in CONTROLLER {
        image.extend_from_slice(&value.to_le_bytes());
    }
    // The pattern is the very last candidate; its literal is out of range, so
    // the match must be seen (and refused), not silently skipped as absent.
    assert_eq!(
        locate(&image, CONTROLLER, 0x0200_0000),
        Err(Error::InvalidContract)
    );
}

#[test]
fn coefficient_constant_ends_when_ldm_loads_the_register() {
    let code: [u16; 4] = [
        0x4901, // ldr r1, [pc, #4] -> 0x51b1
        0xc802, // ldmia r0!, {r1} (replaces r1)
        0x1852, // adds r2, r2, r1 (reads the loaded r1, not 0x51b1)
        0xbf00,
    ];
    let mut image = vec![0u8; 12];
    for (i, h) in code.iter().enumerate() {
        image[i * 2..i * 2 + 2].copy_from_slice(&h.to_le_bytes());
    }
    image[8..12].copy_from_slice(&0x51b1u32.to_le_bytes());
    assert!(super::uhd::coefficient(&image, 0, false).is_err());
}

#[test]
fn reverse_selector_with_a_non_forward_shared_gate_is_invalid_not_absent() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let bytes = image(&root, &case);
        let areas = UhdAreas::inspect(&bytes);
        if areas
            .area(UhdArea::ReverseCalculation)
            .unwrap()
            .selection()
            .is_none()
        {
            continue;
        }
        let forward = areas.area(UhdArea::ForwardCalculation).unwrap();
        let add = forward.coefficient_continuation().unwrap();
        let op = u16::from_le_bytes(bytes[add..add + 2].try_into().unwrap());
        assert_eq!(op & 0xfe00, 0x1800, "16-bit ADDS register form");
        let mut bad = bytes.clone();
        bad[add..add + 2].copy_from_slice(&(op | 0x0200).to_le_bytes()); // SUBS
                                                                         // The forward copy also matches the reverse prefix; make its own
                                                                         // rejection self-referential so that copy also needs this forward gate.
        let bne = forward.site() + 12;
        bad[bne..bne + 2].copy_from_slice(&0xd1feu16.to_le_bytes());
        assert_eq!(
            UhdAreas::inspect(&bad).area(UhdArea::ReverseCalculation),
            Err(Error::InvalidContract)
        );
        count += 1;
    }
    assert_eq!(count, 6);
}

#[test]
fn hardware_defaults_bl_suffix_does_not_pin_the_call_displacement() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let bytes = image(&root, &case);
        let areas = UhdAreas::inspect(&bytes);
        let Ok(contract) = areas.area(UhdArea::HardwareDefaults) else {
            continue;
        };
        if contract.variant() != "desktop_default8_c7_aware" {
            continue;
        }
        let call = contract.site() + 0x46;
        let target = thumb_asm::decode_bl(&bytes, call).unwrap();
        let mut moved = bytes.clone();
        moved[call..call + 4].copy_from_slice(&thumb_asm::encode_bl(call, target ^ 2).unwrap());
        let moved = UhdAreas::inspect(&moved);
        assert_eq!(
            moved.area(UhdArea::HardwareDefaults).unwrap().site(),
            contract.site()
        );
        count += 1;
    }
    assert!(count > 0);
}

#[test]
fn read_status_join_requires_the_fall_through_load_to_define_r0() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        if !case["auxiliary_consumers"].is_array() {
            continue;
        }
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contracts = super::ClassicConsumer::inspect(&bytes, state).unwrap();
        let status = contracts
            .iter()
            .find(|c| c.kind == super::ClassicConsumerKind::ReadStatus)
            .unwrap();
        let at = status.region + 30;
        let op = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let mut bad = bytes.clone();
        bad[at..at + 2].copy_from_slice(&(op | 0x0200).to_le_bytes()); // ldr r2, same pool
        assert!(super::ClassicConsumer::inspect(&bad, state).is_err());
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn read_completion_refuses_both_boundary_grammars() {
    let (root, cases) = fixtures();
    let sha = |c: &serde_json::Value| c["source_sha256"].as_str().unwrap().to_owned();
    let veneer_case = cases
        .iter()
        .find(|c| sha(c).starts_with("0b2cdb82"))
        .unwrap();
    let plain_case = cases
        .iter()
        .find(|c| sha(c).starts_with("40eb760e"))
        .unwrap();
    let veneer = image(&root, veneer_case);
    let mut bytes = image(&root, plain_case);
    let state = plain_case["state"].as_u64().unwrap() as u32;
    assert_eq!(state, veneer_case["state"].as_u64().unwrap() as u32);
    let original = super::ClassicReadCompletion::inspect(&bytes, state).unwrap();
    let from = veneer_case["read_completion"]["boundary_region"]
        .as_u64()
        .unwrap() as usize;
    // Copy the veneer body with its literal pool, preserving word alignment.
    let to = 0x1d0000 + from % 4;
    bytes[to..to + 0x500].copy_from_slice(&veneer[from..from + 0x500]);
    assert_eq!(
        super::uhd_completion::locate(&bytes, super::uhd_completion::BOUNDARY_VENEER, state),
        Ok(to)
    );
    assert!(original.boundary_region != to);
    assert_eq!(
        super::ClassicReadCompletion::inspect(&bytes, state).map(|c| c.boundary_region),
        Err(Error::Ambiguous)
    );
}

#[test]
fn recovery_state_producer_accepts_three_bit_adds_adjustment() {
    let (root, cases) = fixtures();
    let case = cases
        .iter()
        .find(|c| c["source_sha256"].as_str().unwrap().starts_with("b093a736"))
        .unwrap();
    let mut bytes = image(&root, case);
    let state = case["state"].as_u64().unwrap() as u32;
    let load = case["read_completion"]["recovery_state_load"]
        .as_u64()
        .unwrap() as usize;
    let op = u16::from_le_bytes(bytes[load..load + 2].try_into().unwrap());
    let pool = ((load + 4) & !3) + (op & 255) as usize * 4;
    // Native `ldr r5, =state+4; subs r5, r5, #4` becomes `ldr r5, =state-4; adds r5, r5, #4`.
    assert_eq!(&bytes[load + 2..load + 4], &0x1f2du16.to_le_bytes());
    assert_eq!(&bytes[pool..pool + 4], &(state + 4).to_le_bytes());
    bytes[pool..pool + 4].copy_from_slice(&(state - 4).to_le_bytes());
    bytes[load + 2..load + 4].copy_from_slice(&0x1d2du16.to_le_bytes());
    let c = super::ClassicReadCompletion::inspect(&bytes, state).unwrap();
    assert_eq!(c.recovery_state_load, load);
}

#[test]
fn read_position_binds_the_range_status_cell_written_by_the_gates() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let Some(entry) = case["read_position_entry"].as_u64() else {
            continue;
        };
        let entry = entry as usize;
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let contract = super::ClassicReadPosition::detect(&bytes, state).unwrap();
        // Point the range-status load at the (different, in-RAM) layer cell's pool word.
        let at = entry + 0x3e;
        let layer_op = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let layer_pool = ((at + 4) & !3) + (layer_op & 255) as usize * 4;
        let at = entry + 0x140;
        let base = (at + 4) & !3;
        assert!(layer_pool > base && contract.layer != contract.status);
        let op = 0x4a00 | ((layer_pool - base) / 4) as u16;
        let mut bad = bytes.clone();
        bad[at..at + 2].copy_from_slice(&op.to_le_bytes());
        assert_eq!(
            super::ClassicReadPosition::detect(&bad, state).map(|c| c.status),
            Err(Error::InvalidContract)
        );
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn whole_routine_detectors_report_short_images_as_unknown_layout() {
    let short = [0u8; 64];
    let state = 0x0200_0000;
    assert_eq!(
        super::ClassicPosition::detect(&short, state).map(|c| c.entry),
        Err(Error::UnknownLayout)
    );
    assert_eq!(
        super::ClassicPositionSetup::detect(&short, state).map(|c| c.entry),
        Err(Error::UnknownLayout)
    );
    assert_eq!(
        super::ClassicReadPosition::detect(&short, state).map(|c| c.entry),
        Err(Error::UnknownLayout)
    );
}

fn coefficient_image(code: &[u16], literal_at: usize) -> Vec<u8> {
    let mut image = vec![0u8; literal_at + 4];
    for (i, h) in code.iter().enumerate() {
        image[i * 2..i * 2 + 2].copy_from_slice(&h.to_le_bytes());
    }
    image[literal_at..].copy_from_slice(&0x51b1u32.to_le_bytes());
    image
}

#[test]
fn coefficient_refuses_a_return_before_the_operation() {
    // ldr r1,=0x51b1; pop {r4,pc}; subs r0,r0,r1 (next function).
    let image = coefficient_image(&[0x4902, 0xbd10, 0x1a40, 0xbf00, 0xbf00, 0xbf00], 12);
    assert_eq!(
        super::uhd::coefficient(&image, 0, true),
        Err(Error::InvalidContract)
    );
}

#[test]
fn coefficient_follows_a_wide_unconditional_branch() {
    // ldr r1,=0x51b1; b.w 10; adds r0,r0,r1 (skipped); nop; subs r0,r0,r1.
    let image = coefficient_image(
        &[
            0x4903, 0xf000, 0xb802, 0x1840, 0xbf00, 0x1a40, 0xbf00, 0xbf00,
        ],
        16,
    );
    assert_eq!(super::uhd::coefficient(&image, 0, true), Ok(10));
}

#[test]
fn coefficient_constant_ends_on_base_writeback() {
    // ldr r1,=0x51b1; ldmia r1!,{r2,r3}; adds r0,r0,r1.
    let image = coefficient_image(&[0x4902, 0xc90c, 0x1840, 0xbf00, 0xbf00, 0xbf00], 12);
    assert!(super::uhd::coefficient(&image, 0, false).is_err());
}

#[test]
fn coefficient_constant_ends_on_a_second_destination() {
    // ldr r1,=0x51b1; ldrd r0,r1,[sp,#8]; adds r0,r0,r1.
    let image = coefficient_image(&[0x4902, 0xe9dd, 0x0102, 0x1840, 0xbf00, 0xbf00], 12);
    assert!(super::uhd::coefficient(&image, 0, false).is_err());
}

#[test]
fn modern_calculations_claim_c7_only_when_the_rejection_tests_c7() {
    let (root, cases) = fixtures();
    let mut count = 0;
    for case in cases {
        let bytes = image(&root, &case);
        let areas = UhdAreas::inspect(&bytes);
        for (role, bne, compare) in [
            (UhdArea::ForwardCalculation, 12, 0),
            (UhdArea::ReverseCalculation, 14, 2),
        ] {
            let contract = areas.area(role).unwrap();
            if contract.variant() != "modern" {
                continue;
            }
            assert_eq!(contract.selects_c7(), Some(true));
            let edge = contract
                .edges()
                .iter()
                .find(|e| e.instruction == contract.site() + bne)
                .unwrap();
            let at = edge.target + compare;
            assert_eq!(&bytes[at..at + 2], &0x28c7u16.to_le_bytes());
            let mut bad = bytes.clone();
            bad[at..at + 2].copy_from_slice(&0x28c6u16.to_le_bytes()); // cmp r0,#0xc6
            assert_eq!(
                UhdAreas::inspect(&bad).area(role),
                Err(Error::InvalidContract)
            );
            count += 1;
        }
    }
    assert_eq!(count, 8);
}

#[test]
fn read_completion_reports_a_duplicated_veneer_boundary_as_ambiguous() {
    let (root, cases) = fixtures();
    let case = cases
        .iter()
        .find(|c| c["source_sha256"].as_str().unwrap().starts_with("0b2cdb82"))
        .unwrap();
    let mut bytes = image(&root, case);
    let state = case["state"].as_u64().unwrap() as u32;
    let from = case["read_completion"]["boundary_region"].as_u64().unwrap() as usize;
    let to = 0x1d0000 + from % 4;
    bytes.copy_within(from..from + 0x500, to);
    use super::uhd_completion::{locate, BOUNDARY_VENEER};
    assert_eq!(
        locate(&bytes, BOUNDARY_VENEER, state),
        Err(Error::Ambiguous)
    );
    // The plain grammar is absent; that absence must not hide the conflict.
    assert_eq!(
        super::ClassicReadCompletion::inspect(&bytes, state).map(|c| c.boundary_region),
        Err(Error::Ambiguous)
    );
}

#[test]
fn consumer_inspection_reports_a_short_image_as_unknown_layout() {
    assert_eq!(
        super::ClassicConsumer::inspect(&[0u8; 16], 0x0200_0000).map(|c| c.len()),
        Err(Error::UnknownLayout)
    );
}

#[test]
fn calibration_reports_an_image_shorter_than_its_routine_as_unknown_layout() {
    // Relocate one real native getter into an image too short for the
    // calibration routine, re-pointing its literals at in-image tables.
    let (root, cases) = fixtures();
    let mut checked = 0;
    for case in cases {
        if case["calibration_entry"].as_u64().is_none() {
            continue;
        }
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let getter = super::ClassicParameter::detect(&bytes, state).unwrap();
        let shift = getter.entry & !3;
        let mut short = bytes[shift..shift + 0x180].to_vec();
        let pools: Vec<usize> = (0..0x100)
            .step_by(2)
            .filter_map(|at| {
                let op = u16::from_le_bytes([short[at], short[at + 1]]);
                (op & 0xf800 == 0x4800).then(|| ((at + 4) & !3) + usize::from(op & 255) * 4)
            })
            .filter(|pool| pool + 4 <= short.len())
            .collect();
        for pool in pools {
            let value = u32::from_le_bytes(short[pool..pool + 4].try_into().unwrap());
            let local = if value as usize == getter.rates {
                0x40
            } else if value != state
                && (value as usize..value as usize + 0x100).contains(&getter.coefficients)
            {
                0x100 - (getter.coefficients - value as usize)
            } else {
                continue;
            };
            short[pool..pool + 4].copy_from_slice(&(local as u32).to_le_bytes());
        }
        let Ok(relocated) = super::ClassicParameter::detect(&short, state) else {
            continue;
        };
        assert_eq!(relocated.entry, getter.entry - shift);
        assert!(short.len() < 0x200);
        assert_eq!(
            super::ClassicCalibration::detect(&short, state).map(|c| c.site),
            Err(Error::UnknownLayout)
        );
        checked += 1;
    }
    assert!(checked > 0);
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

#[test]
fn older_oem_di_mode_binds_saved_r7_and_native_blx() {
    use super::{ClassicConsumer, ClassicConsumerKind as K};
    let (root, _) = fixtures();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("older-oem-di-mode.json")).unwrap())
            .unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let bytes = image(&root, &case);
        let state = case["state"].as_u64().unwrap() as u32;
        let region = case["region"].as_u64().unwrap() as usize;
        let definition = case["state_definition"].as_u64().unwrap() as usize;
        let c = ClassicConsumer::inspect_kind(&bytes, state, K::DiMode)
            .unwrap_or_else(|e| panic!("{}: {e}", case["source_sha256"]));
        assert_eq!(c.region, region);
        assert_eq!(c.selection.site(), region + 4);
        assert_eq!(c.selection.accept(), region + 10);
        assert_eq!(c.selection.reject(), region + 52);
        assert_eq!(c.state_definition, Some((7, definition)));
        assert!(c
            .relocated_load
            .is_some_and(|(reg, value)| reg == 0 && value >> 16 == 0x01ff));
        assert!(ClassicConsumer::inspect_kind(&bytes, state + 1, K::DiMode).is_err());
        // Change the defining literal, selector edge, dense mode and call ISA.
        let op = u16::from_le_bytes(bytes[definition..definition + 2].try_into().unwrap());
        let pool = ((definition + 4) & !3) + usize::from(op & 255) * 4;
        for at in [pool, region + 8, region + 22, region + 28, region + 54] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(
                ClassicConsumer::inspect_kind(&bad, state, K::DiMode).is_err(),
                "{} mutation {at:x}",
                case["source_sha256"]
            );
        }
        // Clobber the saved media pointer after its definition.
        let mut bad = bytes;
        bad[definition + 2..definition + 4].copy_from_slice(&0x2700u16.to_le_bytes());
        assert!(ClassicConsumer::inspect_kind(&bad, state, K::DiMode).is_err());
    }
}

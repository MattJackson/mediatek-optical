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
        let bytes = std::fs::read(hoard.join(row["path"].as_str().unwrap())).unwrap();
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
        }
    }
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
        assert_eq!(contracts.len(), 6);
        for (contract, expected) in contracts.iter().zip(expected) {
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
            bad[contract.selection.site() + 2] ^= 1;
            assert!(super::ClassicConsumer::inspect(&bad, state).is_err());
            count += 1;
        }
        assert!(super::ClassicConsumer::inspect(&bytes, state + 1).is_err());
    }
    assert_eq!(count, 24);
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

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
    }
}

use super::*;
#[test]
fn complete_walker_binds_staging_and_retains_native_crypto() {
    let checks = include_bytes!("../../../tests/fixtures/analysis/uh12-native-checks.bin");
    let crypto = include_bytes!("../../../tests/fixtures/analysis/uh12-cmac-range.bin");
    let helpers = include_bytes!("../../../tests/fixtures/analysis/uh12-cmac-helpers.bin");
    let mut bytes = vec![0; 0x200000];
    bytes[0x17c27a..0x17c27a + checks.len()].copy_from_slice(checks);
    bytes[0x17c0e0..0x17c0e0 + crypto.len()].copy_from_slice(crypto);
    bytes[0x17f9c..0x17f9c + helpers.len()].copy_from_slice(helpers);
    let mut relocated = bytes.clone();
    relocated[0x1afc8..0x1afc8 + helpers.len()].copy_from_slice(helpers);
    let install_call = |image: &mut [u8], at: usize, target: usize| {
        let delta = (target as i32 - at as i32 - 4) as u32;
        image[at..at + 2].copy_from_slice(&(0xf000 | ((delta >> 12) & 2047) as u16).to_le_bytes());
        image[at + 2..at + 4]
            .copy_from_slice(&(0xf800 | ((delta >> 1) & 2047) as u16).to_le_bytes());
    };
    for (offset, target) in [(0x3e, 0x1afc8), (0xa4, 0x1b038), (0xd8, 0x1b04e)] {
        install_call(&mut relocated, 0x17c0e0 + offset, target);
    }
    assert_eq!(
        inspect_integrity_walker(&relocated, 0, 0x17c298, 0x02000c2c),
        Some(0x17c0e0)
    );
    let mut wrong_role = relocated.clone();
    install_call(&mut wrong_role, 0x17c0e0 + 0x3e, 0x1b038);
    assert!(inspect_integrity_walker(&wrong_role, 0, 0x17c298, 0x02000c2c).is_none());
    relocated[0x1afc8 + 0x0c] ^= 1;
    assert!(inspect_integrity_walker(&relocated, 0, 0x17c298, 0x02000c2c).is_none());
    let bytes = bytes.as_slice();
    let base = 0;
    let start = 0x17c298;
    assert_eq!(
        inspect_integrity_walker(bytes, base, start, 0x02000c2c),
        Some(0x17c0e0)
    );
    assert_eq!(
        inspect_integrity_walker(bytes, base, start, 0x02000c34),
        None
    );
    for offset in [
        0, 4, 8, 12, 0x2a, 0x4e, 0x52, 0x56, 0x58, 0x66, 0x6c, 0x98, 0x9c,
    ] {
        let mut changed = bytes.to_vec();
        changed[(start - base) as usize + offset] ^= 1;
        assert!(
            inspect_integrity_walker(&changed, base, start, 0x02000c2c).is_none(),
            "{offset:#x}"
        );
    }
}
const BASE: u32 = 0xa78bc;
const HELD: &[u8] = include_bytes!("../../../tests/fixtures/analysis/uh12-integrity-selection.bin");

#[test]
fn shared_integrity_branches_join_on_the_same_result_test() {
    let proof = inspect_legacy_integrity(HELD, BASE, BASE).unwrap();
    assert_eq!(proof.boot_check, 0x17c27a);
    assert_eq!(proof.application_check, 0x17c298);
    assert_eq!(proof.success, 0xa78e4);
    assert_eq!(proof.failure, 0xa78da);
    for at in [6, 14, 16, 22, 26, 29] {
        let mut changed = HELD.to_vec();
        changed[at] ^= 1;
        assert!(
            inspect_legacy_integrity(&changed, BASE, BASE).is_none(),
            "{at:#x}"
        );
    }
    let mut island = HELD.to_vec();
    island[24..26].fill(0xff);
    assert_eq!(inspect_legacy_integrity(&island, BASE, BASE), Some(proof));
}

#[test]
fn immediate_integrity_join_remains_supported() {
    let mut immediate = HELD.to_vec();
    for (at, word) in [(14, 0xd102u16), (22, 0x2800), (24, 0xd106)] {
        immediate[at..at + 2].copy_from_slice(&word.to_le_bytes());
    }
    let proof = inspect_legacy_integrity(&immediate, BASE, BASE).unwrap();
    assert_eq!(proof.success, BASE + 40);
    assert_eq!(proof.failure, BASE + 26);
}

#[test]
fn walker_start_must_be_an_instruction_boundary() {
    let checks = include_bytes!("../../../tests/fixtures/analysis/uh12-native-checks.bin");
    let crypto = include_bytes!("../../../tests/fixtures/analysis/uh12-cmac-range.bin");
    let helpers = include_bytes!("../../../tests/fixtures/analysis/uh12-cmac-helpers.bin");
    let mut bytes = vec![0; 0x200000];
    bytes[0x17c27a..0x17c27a + checks.len()].copy_from_slice(checks);
    bytes[0x17c0e0..0x17c0e0 + crypto.len()].copy_from_slice(crypto);
    bytes[0x17f9c..0x17f9c + helpers.len()].copy_from_slice(helpers);
    let start = 0x17c298;
    assert!(inspect_integrity_walker(&bytes, 0, start, 0x02000c2c).is_some());
    // Shift the whole stream by one byte, then restore every literal word at
    // the word-aligned pool address an odd-PC load computes.
    let mut shifted = vec![0; bytes.len()];
    shifted[1..].copy_from_slice(&bytes[..bytes.len() - 1]);
    let mut pools = Vec::new();
    for at in (0..bytes.len() - 1).step_by(2) {
        let op = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        if op & 0xf800 == 0x4800 && op != 0 {
            pools.push(((at + 4) & !3) + usize::from(op & 255) * 4);
        }
    }
    for pool in pools {
        shifted[pool..pool + 4].copy_from_slice(&bytes[pool..pool + 4]);
    }
    assert_eq!(
        inspect_integrity_walker(&shifted, 0, start + 1, 0x02000c2c),
        None
    );
}

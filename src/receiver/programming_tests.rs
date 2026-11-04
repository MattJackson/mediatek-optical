use super::*;

fn fixture() -> Vec<u8> {
    let words = [
        0x48b5u16, 0x6980, 0x07c0, 0xd006, 0x49a3, 0x2000, 0x6008, 0x49b6, 0x6008, 0x6820, 0xe007,
        0x489f, 0x2101, 0x0409, 0x6001, 0x48b2, 0x6001, 0x6820, 0x1a40, 0x4ea1, 0x6030,
    ];
    let mut bytes = vec![0; 0x300];
    for (i, op) in words.into_iter().enumerate() {
        bytes[2 * i..2 * i + 2].copy_from_slice(&op.to_le_bytes());
    }
    for (address, value) in [
        (0x9d7f8u32, 0x04002040u32),
        (0x9d7b8, 0x02000c60),
        (0x9d80c, 0x02000c68),
        (0x9d7d0, 0x02000c6c),
    ] {
        let at = (address - 0x9d522) as usize;
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

// Relocated operand-equivalent shared-load form, with an optional literal
// island between the branches (as in UH12NS40 1.03).
fn shared_fixture(island: usize) -> Vec<u8> {
    let mut bytes = vec![0; 0x300];
    let alternate = 22 + island;
    let join = alternate + 14;
    let mut put = |at: usize, value: u16| {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    };
    for (at, op) in [
        (2, 0x6980),
        (4, 0x07c1),
        (12, 0x2100),
        (14, 0x6011),
        (16, 0x6001),
        (18, 0x6821),
    ] {
        put(at, op);
    }
    put(8, 0xd000 | ((alternate - 12) / 2) as u16);
    put(20, 0xe000 | ((join - 24) / 2) as u16);
    for (offset, op) in [
        (2, 0x2101),
        (4, 0x0409),
        (6, 0x6011),
        (8, 0x6001),
        (10, 0x6822),
        (12, 0x1a51),
        (16, 0x6031),
    ] {
        put(alternate + offset, op);
    }
    for (at, reg, literal_at, value) in [
        (0, 0, 0x200, 0x04002040u32),
        (6, 0, 0x204, 0x02000c68),
        (10, 2, 0x208, 0x02000c60),
        (alternate, 2, 0x208, 0x02000c60),
        (join, 6, 0x20c, 0x02000c6c),
    ] {
        let op = 0x4800u16 | reg << 8 | ((literal_at - ((at + 4) & !3)) / 4) as u16;
        bytes[at..at + 2].copy_from_slice(&op.to_le_bytes());
        bytes[literal_at..literal_at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn shared_selection_follows_branches_over_literal_islands() {
    for island in [0, 0x76] {
        let bytes = shared_fixture(island);
        let proof = inspect_selection(&bytes, 0, 0).unwrap();
        assert_eq!(proof.end, (40 + island) as u32);
        assert_eq!(proof.start_cell, 0x02000c68);
        assert_eq!(proof.total_pointer_register, 4);
        // Both branch destinations and both arms must remain bound.
        for at in [8, 20, 22 + island + 4, 22 + island + 12, 22 + island + 16] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert!(inspect_selection(&changed, 0, 0).is_none(), "at {at:#x}");
        }
        // Literal data is not executable fallthrough.
        if island != 0 {
            let mut changed = bytes.clone();
            changed[22..22 + island].fill(0xff);
            assert_eq!(inspect_selection(&changed, 0, 0), Some(proof));
        }
    }
}

#[test]
fn intm_selection_binds_both_arms_and_distinct_cells() {
    let evidence = inspect_legacy_selection(&fixture(), 0x9d522, 0x9d522).unwrap();
    assert_eq!(evidence.offset_cell, 0x02000c60);
    assert_eq!(evidence.start_cell, 0x02000c68);
    assert_eq!(evidence.length_cell, 0x02000c6c);
    assert_eq!(evidence.total_pointer_register, 4);
    assert_eq!(evidence.end, 0x9d54c);
}

// Legacy selection fixture followed by the plain signature body. The
// selection's length cell is loaded into `length_register`, and the
// signature's `LDR r1,[rL]` at index 13 uses `signature_pointer`.
fn plain_fixture(length_register: u16, signature_pointer: u16) -> Vec<u8> {
    const BASE: u32 = 0x9d522;
    let mut bytes = fixture();
    bytes.resize(0x300, 0);
    let mut put = |at: u32, op: u16| {
        let i = (at - BASE) as usize;
        bytes[i..i + 2].copy_from_slice(&op.to_le_bytes());
    };
    put(BASE + 19 * 2, 0x4aa1 & !0x0700 | length_register << 8);
    put(BASE + 20 * 2, 0x6000 | length_register << 3);
    let start = BASE + 42;
    let target = start + 36 * 2;
    let mut pool = Vec::new();
    for (index, op) in [
        (0u32, 0x2201u16),
        (1, 0x0692),
        (2, 0x6810),
        (3, 0x2110),
        (4, 0x4388),
        (5, 0x6010),
        (7, 0x6820),
        (8, 0x2283),
        (9, 0x0252),
        (10, 0x4290),
        (12, 0x6820),
        (13, 0x6801 | signature_pointer << 3),
        (14, 0x1840),
        (16, 0x4288),
        (19, 0x2100),
        (20, 0x6800),
        (21, 0x0213),
        (23, 0x0a1b),
        (24, 0x181b),
        (25, 0x781b),
        (26, 0x5c6d),
        (27, 0x42ab),
        (29, 0x1c49),
        (30, 0x0609),
        (31, 0x0e09),
        (32, 0x1c52),
        (33, 0x2908),
        (34, 0xd3f1),
    ] {
        put(start + index * 2, op);
    }
    for (index, high) in [(11u32, 0xd800u16), (17, 0xd900), (28, 0xd100)] {
        let at = start + index * 2;
        put(at, high | ((target - at - 4) / 2) as u16);
    }
    for (index, reg, value) in [
        (6u32, 4u16, 0x02000c60u32),
        (15, 1, 0x10700),
        (18, 0, 0x02000c70),
        (22, 5, 0x10600),
    ] {
        let at = start + index * 2;
        let slot = 0x9d624 + 4 * pool.len() as u32;
        pool.push((slot, value));
        put(
            at,
            0x4800 | reg << 8 | ((slot - ((at + 4) & !3)) / 4) as u16,
        );
    }
    put(target, 0);
    for (slot, value) in pool {
        let i = (slot - BASE) as usize;
        bytes[i..i + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn plain_signature_pointer_must_survive_the_signature_prefix() {
    let base = 0x9d522;
    // Control: the fixture's own length register (r6) is accepted.
    let bytes = plain_fixture(6, 6);
    let selection = inspect_legacy_selection(&bytes, base, base).unwrap();
    assert!(inspect_plain_signature(&bytes, base, &selection).is_some());
    // Indices 0-12 overwrite r0, r1, r2 and r4 before index 13 reads it.
    let bytes = plain_fixture(2, 2);
    let selection = inspect_legacy_selection(&bytes, base, base).unwrap();
    assert_eq!(selection.length_cell, 0x02000c6c);
    assert!(inspect_plain_signature(&bytes, base, &selection).is_none());
}

#[test]
fn changed_guards_stores_subtraction_and_joins_are_rejected() {
    let bytes = fixture();
    for index in [1, 2, 3, 5, 6, 8, 10, 12, 13, 14, 16, 17, 18, 20] {
        let mut changed = bytes.clone();
        changed[index * 2] ^= 1;
        assert!(
            inspect_legacy_selection(&changed, 0x9d522, 0x9d522).is_none(),
            "instruction {index}"
        );
    }
    assert!(inspect_legacy_selection(&bytes[..42], 0x9d522, 0x9d522).is_none());
    assert!(inspect_legacy_selection(&bytes, u32::MAX - 1, u32::MAX - 1).is_none());
}

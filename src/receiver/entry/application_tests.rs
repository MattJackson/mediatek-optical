use super::*;

#[test]
fn complete_guard_signature_preserves_mode_and_buffer_exclusions() {
    let guard = ModeBufferGuard::inspect(MODE_GUARD).unwrap();
    assert!(guard.returns_one(1, 0));
    assert!(guard.returns_one(6, 0x67));
    for buffer in 0..=255 {
        assert!(!guard.returns_one(10, buffer));
        assert_eq!(guard.returns_one(2, buffer), buffer != 0x8f);
    }
    for buffer in [4, 5, 6] {
        assert!(!guard.returns_one(5, buffer));
    }
    assert!(guard.returns_one(5, 3));
    assert!(guard.returns_one(5, 7));
    for i in 0..MODE_GUARD_BYTES {
        let mut changed = *MODE_GUARD;
        changed[i] ^= 1;
        assert!(ModeBufferGuard::inspect(&changed).is_none());
        assert!(ModeBufferGuard::inspect(&MODE_GUARD[..i]).is_none());
    }
}

// Real instruction excerpts, independently disassembled from V1 and INTM.
fn fixture(base: usize, length: usize, fragments: &[(usize, &str)]) -> std::vec::Vec<u8> {
    let mut bytes = std::vec![0xff; length];
    for &(address, hex) in fragments {
        for i in (0..hex.len()).step_by(2) {
            bytes[address - base + i / 2] = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
        }
    }
    bytes
}

fn v1() -> std::vec::Vec<u8> {
    fixture(0x9ca00, 0x800, &[
        (0x9ca2a, "092b00d3f9e35b007b449b885b009f44ac0508002900ac052f001401ee02ac057104574a93691b091b019361"),
        (0x9cbac, "40200004"),
        (0x9d018, "8178"),
    ])
}

#[test]
fn real_inline_table_binds_mode_one_to_mmio_clear() {
    let bytes = v1();
    assert_eq!(
        inspect(&bytes, 0x9ca00),
        Some(Candidate {
            table: 0x9ca30,
            entry: 0x9ca4c,
            mode1_target: 0x9ca4c,
            mode6_target: 0x9d018,
            helper: None,
        })
    );
    for offset in [0x2b, 0x2c, 0x30, 0x3c, 0x50, 0x1ac] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert_eq!(inspect(&corrupt, 0x9ca00), None, "offset {offset:x}");
    }
    assert_eq!(inspect(&bytes[..0x100], 0x9ca00), None);
    assert_eq!(inspect(&bytes, u32::MAX - 16), None);
    assert_eq!(inspect(&bytes, 0x9ca01), None);
}

#[test]
fn real_compiler_table_requires_separate_helper_proof() {
    let bytes = fixture(
        0x9cd00,
        0x400,
        &[
            (
                0x9cd90,
                "724c734e00219ff00ce809630627632df5f463f363006f498b691b091b018b61",
            ),
            (0x9cf64, "40200004"),
            (0x9cf82, "e3e1"),
        ],
    );
    assert_eq!(
        inspect(&bytes, 0x9cd00),
        Some(Candidate {
            table: 0x9cd96,
            entry: 0x9cda6,
            mode1_target: 0x9cda6,
            mode6_target: 0x9cf82,
            helper: Some(0x13bdb0),
        })
    );
    assert!(matches_helper(ARM_HELPER));
    assert!(!matches_helper(&ARM_HELPER[..HELPER_BYTES - 1]));
    for offset in 0..HELPER_BYTES {
        let mut corrupt = ARM_HELPER.to_vec();
        corrupt[offset] ^= 1;
        assert!(!matches_helper(&corrupt));
    }
}

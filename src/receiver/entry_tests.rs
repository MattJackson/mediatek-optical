use super::*;

// Instruction/literal excerpts from WH16NS58 V9 SHA256 97b28707...,
// checked against the independent disassembly. No firmware payload needed.
fn v9_window() -> std::vec::Vec<u8> {
    let mut bytes = std::vec![0xff; 0x600];
    for (address, hex) in [
        (0x352a, "e548f0b5827889b00127e349002a72d142781207120f42704278e04e012a49d0022a01d0062af2d1"),
        (0x35de, "b16909090901b161417ac90702d0b1693943b161417a890703d5b16902221143b161417a490703d5b16904221143b161407a000703d5b06908210843b06109b0f0bd"),
        (0x38c0, "fc0d0002800d000240200004"),
    ] {
        for i in (0..hex.len()).step_by(2) {
            bytes[address - 0x3400 + i / 2] = u8::from_str_radix(&hex[i..i+2], 16).unwrap();
        }
    }
    bytes
}

#[test]
fn actual_v9_entry_has_fixed_operands_and_bounded_literals() {
    let bytes = v9_window();
    assert_eq!(
        inspect_boot_legacy(&bytes, 0x3400),
        Some(LegacyCandidate {
            decoder: 0x353a,
            entry: 0x35de,
            end: 0x3620,
        })
    );
    for length in 0..0x4cc {
        assert!(inspect_boot_legacy(&bytes[..length], 0x3400).is_none());
    }
    for address in [
        0x352e, 0x3532, 0x3536, 0x3546, 0x3548, 0x35de, 0x35e6, 0x35e8, 0x35ea, 0x35ee, 0x361a,
        0x38c8,
    ] {
        let mut changed = bytes.clone();
        changed[address - 0x3400] ^= 1;
        assert!(
            inspect_boot_legacy(&changed, 0x3400).is_none(),
            "{address:#x}"
        );
    }
}

// The V9 window with its entry rebuilt around `base`: an optional literal
// load between the decoder and `CMP r2,#1` (`first`) and an optional local
// literal at the entry (`local`), each naming its destination register.
fn v9_rebuilt(first: u16, local: Option<u16>, base: u16) -> std::vec::Vec<u8> {
    v9_rebuilt_with(first, local, base, false)
}

// `explicit_one` spells bit zero's constant as a MOV instead of relying on
// the preloaded r7.
fn v9_rebuilt_with(
    first: u16,
    local: Option<u16>,
    base: u16,
    explicit_one: bool,
) -> std::vec::Vec<u8> {
    let mut bytes = v9_window();
    let mut put = |address: usize, op: u16| {
        bytes[address - 0x3400..address - 0x3400 + 2].copy_from_slice(&op.to_le_bytes());
    };
    put(0x3544, 0x4800 | first << 8 | 0xe0);
    let mut p = 0x35de;
    if let Some(reg) = local {
        put(p, 0x4800 | reg << 8 | 0xba);
        p += 2;
    }
    let load = 0x6800 | (6 << 6) | (base << 3) | 1;
    let source = if base == 2 { 3 } else { 2 };
    let mut ops = std::vec![load, 0x0909, 0x0109, 0x6000 | (6 << 6) | (base << 3) | 1];
    for (bit, tmp, constant) in [
        (0u16, 1u16, explicit_one.then_some(source)),
        (1, 1, Some(source)),
        (2, 1, Some(source)),
        (3, 0, Some(1)),
    ] {
        ops.push(0x7800 | (9 << 6) | tmp);
        ops.push(((31 - bit) << 6) | (tmp << 3) | tmp);
        let (condition, length) = match (bit, constant) {
            (0, None) => (0xd000, 2),
            (0, Some(_)) => (0xd000, 3),
            _ => (0xd500, 3),
        };
        ops.push(condition | length);
        ops.push(0x6800 | (6 << 6) | (base << 3) | tmp);
        let register = constant.unwrap_or(7);
        if constant.is_some() {
            ops.push(0x2000 | register << 8 | (1 << bit));
        }
        ops.push(0x4300 | (register << 3) | tmp);
        ops.push(0x6000 | (6 << 6) | (base << 3) | tmp);
    }
    ops.extend([0xb009, 0xbdf0]);
    for op in ops {
        put(p, op);
        p += 2;
    }
    bytes
}

#[test]
fn literal_loads_cannot_clobber_the_cdb_pointer_compare_or_preloaded_one() {
    // Controls: the rebuilt forms are accepted when no register the proof
    // relies on (r0 CDB pointer, r2 compare, r7 preloaded one) is touched.
    assert!(inspect_boot_legacy(&v9_rebuilt(6, None, 6), 0x3400).is_some());
    assert!(inspect_boot_legacy(&v9_rebuilt(5, Some(3), 3), 0x3400).is_some());
    // A first literal into r0 is superseded by a local literal, but still
    // destroys the CDB pointer before the mode nibble is compared.
    assert!(inspect_boot_legacy(&v9_rebuilt(0, Some(3), 3), 0x3400).is_none());
    // A first literal into r2 clobbers the compared mode nibble.
    assert!(inspect_boot_legacy(&v9_rebuilt(2, None, 2), 0x3400).is_none());
    // The same holds for r7, which carries the preloaded bit-zero one.
    assert!(inspect_boot_legacy(&v9_rebuilt(7, Some(3), 3), 0x3400).is_none());
    // After the branch r2 is dead, so a local literal may make it the base.
    assert!(inspect_boot_legacy(&v9_rebuilt(6, Some(2), 2), 0x3400).is_some());
    // A local literal into r0 still destroys the CDB pointer.
    assert!(inspect_boot_legacy(&v9_rebuilt(6, Some(0), 0), 0x3400).is_none());
    // A local literal into r7 is fine unless bit zero relies on the
    // preloaded r7 one.
    assert!(inspect_boot_legacy(&v9_rebuilt(6, Some(7), 7), 0x3400).is_none());
    assert!(inspect_boot_legacy(&v9_rebuilt_with(6, Some(7), 7, true), 0x3400).is_some());
}

#[test]
fn ambiguity_alignment_and_address_overflow_never_select_a_recipe() {
    let bytes = v9_window();
    let mut doubled = bytes.clone();
    doubled.extend_from_slice(&bytes);
    assert!(inspect_boot_legacy(&doubled, 0x3400).is_none());
    assert!(inspect_boot_legacy(&bytes, 0x3401).is_none());
    assert!(inspect_boot_legacy(&bytes, u32::MAX - 16).is_none());
}

#[test]
fn both_real_dual_entry_compiler_forms_bind_modes_and_flag_paths() {
    for (prefix, literal_at, literals, entry, body) in [
        ("de49f0b5487885b00007000f4870487808220423022401280bd0d74d0a3d022801d0062879d14878062824d18878672821d1d348", 0x38bc,
         "8a0d0002fc0d000240200004", 0x3576, DUAL_LOCAL),
        ("dd49f0b5487889b00007000f487048780822042302240127d84e01280bd0d54d0a3d022801d006286cd14878062822d1887867281fd1", 0x38b8,
         "8a0d0002fc0d000240200004", 0x357a, DUAL_PRELOADED),
    ] {
        let mut bytes = std::vec![0xff; 0x600];
        for (address, hex) in [(0x3544, prefix), (literal_at, literals)] {
            for i in (0..hex.len()).step_by(2) {
                bytes[address - 0x3400 + i / 2] = u8::from_str_radix(&hex[i..i+2], 16).unwrap();
            }
        }
        for (address, hex) in if entry == 0x3576 {
            [(0x365e, "7ce0"), (0x375a, "01262e7121e7")]
        } else {
            [(0x3648, "dbe0"), (0x3802, "2f71cfe6")]
        } {
            for i in (0..hex.len()).step_by(2) {
                bytes[address - 0x3400 + i / 2] = u8::from_str_radix(&hex[i..i+2], 16).unwrap();
            }
        }
        bytes[entry-0x3400..entry-0x3400+body.len()].copy_from_slice(body);
        if entry == 0x3576 { bytes[entry-0x3400] = 0xd3; }
        assert_eq!(inspect_boot_dual(&bytes, 0x3400), Some(DualCandidate {
            decoder: 0x3544, entry: entry as u32, stream: 0x35ba,
        }));
        assert!(inspect_boot_legacy(&bytes, 0x3400).is_none());
        for address in 0x3554..0x35ba {
            // Literal relocation is variable; every other body byte and
            // mode-routing byte is fixed in these complete compiler forms.
            if address == entry { continue; }
            let mut changed = bytes.clone(); changed[address-0x3400] ^= 1;
            assert!(inspect_boot_dual(&changed, 0x3400).is_none(), "{entry:#x}: {address:#x}");
        }
        let mut doubled = bytes.clone(); doubled.extend_from_slice(&bytes);
        assert!(inspect_boot_dual(&doubled, 0x3400).is_none());
        assert!(inspect_boot_dual(&bytes, u32::MAX - 16).is_none());
    }
}

use super::*;

fn v1() -> std::vec::Vec<u8> {
    let mut bytes = std::vec![0xff; 0x1800];
    for (address, hex) in [
        (0x9ba38, "0122022804d0052805d00a280ad108e08f2907d105e0042903d0052901d0062900d1002210007047"),
        (0x9ca02, "564bf0b599788fb05878c006c00efff712f80126634f002808d059781800cb06db0e042100255f4c092b00d3f9e3"),
        (0x9ca30, "5b007b449b885b009f44ac0508002900ac052f001401ee02ac057104"),
        (0x9ca4c, "574a93691b091b019361437adb0702d0936933439361437a9b0703d59369022423439361437a5b0702d5936919439161407a000703d590690821084390610fb0f0bd"),
        (0x9cb5c, "f40c0002"),
        (0x9cba4, "220c0002380c0002"),
        (0x9cbac, "40200004"),
    ] {
        for i in (0..hex.len()).step_by(2) {
            bytes[address - 0x9ba00 + i / 2] = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
        }
    }
    bytes
}

fn table() -> Candidate {
    Candidate {
        table: 0x9ca30,
        entry: 0x9ca4c,
        mode1_target: 0x9ca4c,
        mode6_target: 0x9d018,
        helper: None,
    }
}

#[test]
fn real_v1_prologue_binds_guard_arguments_and_preloaded_constants() {
    let bytes = v1();
    let found = inspect_prologue(&bytes, 0x9ba00, &table()).unwrap();
    assert_eq!(found.start, 0x9ca02);
    assert_eq!(found.cdb_address, 0x02000cf4);
    assert_eq!(found.guard, Some(0x9ba38));
    assert_eq!(found.rejection, Some(0x9ca2e));
    assert_eq!(found.constants[1], Some(4));
    assert_eq!(found.constants[5], Some(0));
    assert_eq!(found.constants[6], Some(1));
    assert_ne!(found.cdb_registers & 1, 0);
    for address in [0x9ca06, 0x9ca0c, 0x9ca10, 0x9ca18, 0x9ca1b, 0x9cb5f] {
        let mut changed = bytes.clone();
        changed[address - 0x9ba00] ^= 1;
        assert!(
            inspect_prologue(&changed, 0x9ba00, &table()).is_none(),
            "{address:x}"
        );
    }
    for offset in 0..MODE_GUARD_BYTES {
        let mut changed = bytes.clone();
        changed[0x38 + offset] ^= 1;
        assert!(inspect_prologue(&changed, 0x9ba00, &table()).is_none());
    }
    assert!(inspect_prologue(&bytes[..0x100], 0x9ba00, &table()).is_none());
    assert!(inspect_prologue(&bytes, u32::MAX - 4, &table()).is_none());
}

#[test]
fn real_v1_flag_body_binds_all_stores_branches_and_preloaded_constants() {
    let bytes = v1();
    let prelude = inspect_prologue(&bytes, 0x9ba00, &table()).unwrap();
    let found = super::super::inspect_flags(&bytes, 0x9ba00, &table(), &prelude).unwrap();
    assert_eq!(found.end, 0x9ca8e);
    for address in [
        0x9ca5a, 0x9ca60, 0x9ca66, 0x9ca6e, 0x9ca74, 0x9ca7a, 0x9ca80, 0x9ca88, 0x9ca8c,
    ] {
        let mut changed = bytes.clone();
        changed[address - 0x9ba00] ^= 1;
        assert!(
            super::super::inspect_flags(&changed, 0x9ba00, &table(), &prelude).is_none(),
            "{address:x}"
        );
    }
    let mut invented = prelude.clone();
    invented.constants[6] = Some(2);
    assert!(super::super::inspect_flags(&bytes, 0x9ba00, &table(), &invented).is_none());
    // A valid-looking OR cannot license destroying the MMIO base or CDB
    // pointer while constructing the bit-one constant.
    // Nor may it overwrite the work register just loaded from MMIO (r3),
    // which would discard the read-modify-write.
    for register in [0u16, 2, 3] {
        let mut changed = bytes.clone();
        changed[0x106a..0x106c].copy_from_slice(&(0x2002 | (register << 8)).to_le_bytes());
        changed[0x106c..0x106e].copy_from_slice(&(0x4303 | (register << 3)).to_le_bytes());
        assert!(super::super::inspect_flags(&changed, 0x9ba00, &table(), &prelude).is_none());
    }
}

#[test]
fn mode_six_cdb_reload_cannot_clobber_a_prelude_constant() {
    // Mode-six target: LDR rC,=CDB; LDRB r3,[rC,#2]; CMP r3,#0x67; BNE; B entry.
    let guarded = |register: u16| {
        let mut bytes = v1();
        let put = |bytes: &mut std::vec::Vec<u8>, at: usize, op: u16| {
            bytes[at - 0x9ba00..at - 0x9ba00 + 2].copy_from_slice(&op.to_le_bytes());
        };
        put(&mut bytes, 0x9d018, 0x4800 | register << 8 | 2);
        put(&mut bytes, 0x9d01a, 0x7800 | 2 << 6 | register << 3 | 3);
        put(&mut bytes, 0x9d01c, 0x2b67);
        put(&mut bytes, 0x9d01e, 0xd100);
        let delta = (0x9ca4ci64 - (0x9d020 + 4)) / 2;
        put(&mut bytes, 0x9d020, 0xe000 | (delta & 0x7ff) as u16);
        bytes[0x9d024 - 0x9ba00..0x9d028 - 0x9ba00].copy_from_slice(&0x02000cf4u32.to_le_bytes());
        let prelude = inspect_prologue(&bytes, 0x9ba00, &table()).unwrap();
        super::super::inspect_mode_six(&bytes, 0x9ba00, &table(), &prelude)
    };
    // Control: a register without a prelude constant is accepted.
    assert!(matches!(
        guarded(2),
        Some(super::super::ModeSix::Entry67 { .. })
    ));
    // r5 holds the constant 0, which the flag body never uses, so a
    // reload into it leaves the proven flag semantics intact.
    assert!(matches!(
        guarded(5),
        Some(super::super::ModeSix::Entry67 { .. })
    ));
    // r6 and r1 hold prelude constants used by the flag body.
    assert!(guarded(6).is_none());
    assert!(guarded(1).is_none());
}

use super::*;

const BU_AUTH: &[u8] = include_bytes!("../../../tests/fixtures/analysis/bu40n-auth.bin");
const WH_AUTH: &[u8] = include_bytes!("../../../tests/fixtures/analysis/wh-auth.bin");
const BU_MEDIA: &[u8] = include_bytes!("../../../tests/fixtures/analysis/bu40n-media.bin");
const WH_MEDIA: &[u8] = include_bytes!("../../../tests/fixtures/analysis/wh-media.bin");

#[test]
fn source_layouts_select_independent_media_contracts() {
    let bu = MediaGate::inspect(BU_MEDIA).unwrap();
    assert_eq!(bu.variant(), MediaGateVariant::Explicit);
    assert_eq!(bu.bd_site(), Some(16));
    assert_eq!(bu.uhd_site(), Some(4));
    let wh = MediaGate::inspect(WH_MEDIA).unwrap();
    assert_eq!(wh.variant(), MediaGateVariant::Descriptor);
    assert_eq!(
        wh.bd_site(),
        None,
        "descriptor bytes do not establish a BD role"
    );
    assert_eq!(
        wh.uhd_site(),
        None,
        "a descriptor is not proof of a UHD discriminator"
    );
    assert_eq!(wh.frame_instruction(), Some(0xb085));
}

#[test]
fn auth_checks_follow_the_success_branch_and_derive_state_addresses() {
    let bu = AuthCell::detect(BU_AUTH).unwrap();
    assert_eq!(bu.variant(), AuthCellVariant::R0StateR4);
    assert_eq!(bu.site(), 0x136826 - 0x13675c);
    assert_eq!(bu.state_address(), 0x01ff9e04);
    assert_eq!(bu.refusal(), bu.deny());
    let wh = AuthCell::detect(WH_AUTH).unwrap();
    assert_eq!(wh.variant(), AuthCellVariant::R1StateR1);
    assert_eq!(wh.site(), 0x13aa96 - 0x13a9ce + 2);
    assert_eq!(wh.state_address(), 0x01ff9e00);
    assert_ne!(wh.site(), 0x13ac68 - 0x13a9ce + 2);
}

#[test]
fn register_allocation_variants_reuse_the_same_success_path_contract() {
    let cases: &[(&[u8], usize, usize, usize, AuthCellVariant)] = &[
        (
            include_bytes!("../../../tests/fixtures/analysis/auth-r1-r4.bin"),
            2,
            84,
            202,
            AuthCellVariant::R1StateR4,
        ),
        (
            include_bytes!("../../../tests/fixtures/analysis/auth-r0-r0.bin"),
            2,
            84,
            198,
            AuthCellVariant::R0StateR0,
        ),
        (
            include_bytes!("../../../tests/fixtures/analysis/auth-r0-r5.bin"),
            0,
            82,
            196,
            AuthCellVariant::R0StateR5,
        ),
    ];
    for &(bytes, producer, gate, site, variant) in cases {
        let vid = VidGate::inspect(bytes).unwrap();
        assert_eq!(vid.producer(bytes).unwrap(), producer);
        assert_eq!(vid.comparison(), gate);
        let result = AuthCell::detect(bytes).unwrap();
        assert_eq!(result.site(), site);
        assert_eq!(result.variant(), variant);
    }
}

#[test]
fn ambiguity_is_not_retried_as_another_media_variant() {
    let mut image = BU_MEDIA.to_vec();
    image.extend_from_slice(BU_MEDIA);
    image.extend_from_slice(WH_MEDIA);
    assert_eq!(MediaGate::inspect(&image), Err(Error::Ambiguous));
}

#[test]
fn a_pattern_match_with_the_wrong_continuation_is_rejected() {
    let mut image = BU_MEDIA.to_vec();
    image[2] = 3; // still a BNE, but no longer the mode!=1 continuation
    assert_eq!(MediaGate::inspect(&image), Err(Error::InvalidContract));
    let mut image = WH_MEDIA.to_vec();
    image[0x42] = 0;
    assert_eq!(MediaGate::inspect(&image), Err(Error::InvalidContract));
}

#[test]
fn broken_auth_preparation_does_not_fall_back_to_the_later_nibble_check() {
    let mut image = WH_AUTH.to_vec();
    image[0x13aa8a - 0x13a9ce + 2] = 0; // destroy scratch alignment, retain both CMPs
    assert!(AuthCell::inspect(&image, 2, 0x58).is_err());
    let mut image = WH_AUTH.to_vec();
    image[0x13ab16 - 0x13a9ce + 2] = 0; // destroy the failure-path state store
    assert!(AuthCell::inspect(&image, 2, 0x58).is_err());
}

#[test]
fn truncated_inputs_never_panic_or_claim_support() {
    for len in 0..WH_AUTH.len() {
        let _ = AuthCell::inspect(&WH_AUTH[..len], 2, 0x58);
    }
    for len in 0..0x46 {
        assert!(MediaGate::inspect(&WH_MEDIA[..len]).is_err());
    }
}

#[test]
fn classic_vid_state_gate_retains_its_alternate_nibble_path() {
    let image = include_bytes!("../../../tests/fixtures/analysis/wh14-classic-vid.bin");
    let vid = VidGate::inspect(image).unwrap();
    assert_eq!(vid.variant(), VidGateVariant::TwoRound);
    assert_eq!(vid.comparison(), 0x17f532 - 0x17f4d6 + 2);
    assert_eq!(vid.producer(image).unwrap(), 2);
    let result = AuthCell::detect(image).unwrap();
    assert_eq!(result.variant(), AuthCellVariant::R0StateR1Alternate);
    assert_eq!(result.site(), 0x17f5ac - 0x17f4d6 + 2);
    assert_eq!(result.state_address(), 0x01ff9dd3);
    assert_eq!(result.deny(), 0x17f626 - 0x17f4d6 + 2);
    assert_eq!(result.refusal(), 0x17f65e - 0x17f4d6 + 2);
    assert_ne!(result.refusal(), result.deny());
}

#[test]
fn classic_state_gate_refuses_damaged_interleaving_and_alternate_paths() {
    let source = include_bytes!("../../../tests/fixtures/analysis/wh14-classic-vid.bin");
    for address in [0x17f5aa, 0x17f62a, 0x17f660] {
        let mut image = source.to_vec();
        image[address - 0x17f4d6 + 2] ^= 1;
        assert!(
            AuthCell::detect(&image).is_err(),
            "accepted damaged contract at {address:x}"
        );
    }
}

#[test]
fn authentication_requires_live_values_and_correct_stack_store_sources() {
    type Mutation = (usize, fn(&mut thumb_asm::Asm));
    let cases: &[Mutation] = &[
        (0xae, |a| {
            a.movs_imm(0, 0);
        }),
        (0xc2, |a| {
            a.str_sp(0, 0);
        }),
        (0xc0, |a| {
            a.lsls_imm(0, 1, 2);
        }),
        (0xb2, |a| {
            a.movs_imm(3, 0);
        }),
        (0xae, |a| {
            a.movs_imm(5, 0);
        }),
        (0xb6, |a| {
            a.ldr_imm(0, 3, 0);
        }),
        (0xc2, |a| {
            a.strb_imm(1, 3, 0);
        }),
        (0xb4, |a| {
            a.str_sp(0, 4);
        }),
    ];
    for &(at, build) in cases {
        let mut assembler = thumb_asm::Asm::new();
        build(&mut assembler);
        let bytes = assembler.finish().unwrap();
        assert_eq!(thumb_asm::isa::decode_at(&bytes, 0).unwrap().len(), 2);
        let mut image = WH_AUTH.to_vec();
        image[at..at + 2].copy_from_slice(&bytes[..2]);
        assert!(
            AuthCell::detect(&image).is_err(),
            "accepted broken auth flow at {at:#x}"
        );
    }
}

#[test]
fn diagnostic_preserves_its_typed_cause() {
    let diagnostic = Diagnostic {
        role: Role::SpeedPolicy,
        cause: Error::Ambiguous,
    };
    let source = std::error::Error::source(&diagnostic).expect("cause retained");
    assert_eq!(source.to_string(), Error::Ambiguous.to_string());
}

#[test]
fn refusal_store_base_must_be_the_loaded_literal_register() {
    for source in [BU_AUTH, WH_AUTH] {
        let cell = AuthCell::detect(source).unwrap();
        let deny = cell.deny();
        let first = u16::from_le_bytes([source[deny], source[deny + 1]]);
        let store = u16::from_le_bytes([source[deny + 2], source[deny + 3]]);
        if first & 0xf800 != 0x4800 || store & 0xffc0 != 0x7000 {
            continue;
        }
        // The literal is loaded into a register other than the store base.
        let mut image = source.to_vec();
        image[deny + 1] = 0x4b;
        assert!(
            AuthCell::detect(&image).is_err(),
            "accepted a store through a base the literal load did not define"
        );
        // No literal load: r0 still holds a value, not a state pointer.
        let mut image = source.to_vec();
        image.copy_within(deny + 2..deny + 6, deny);
        assert!(
            AuthCell::detect(&image).is_err(),
            "accepted an r0 store without a live pointer"
        );
    }
}

#[test]
fn preserved_r7_store_refuses_a_literal_loaded_into_another_register() {
    // wh-auth leaves through `strb r6,[r7]` (0x703e) on the preserved state
    // pointer. A literal load before that store must define r7 itself.
    let deny = AuthCell::detect(WH_AUTH).unwrap().deny();
    assert_eq!(&WH_AUTH[deny..deny + 4], &[0x3e, 0x70, 0x92, 0xe4]);
    let with_literal = |load: u16| {
        let mut image = WH_AUTH.to_vec();
        // ldr rN,[pc,#4]; strb r6,[r7]; b <same target>
        for (n, half) in [load, 0x703e, 0xe491].into_iter().enumerate() {
            image[deny + 2 * n..deny + 2 * n + 2].copy_from_slice(&half.to_le_bytes());
        }
        image
    };
    assert!(
        AuthCell::detect(&with_literal(0x4f01)).is_ok(),
        "a literal reloading r7 keeps the reviewed store base"
    );
    assert_eq!(
        AuthCell::detect(&with_literal(0x4b01)),
        Err(Error::InvalidContract),
        "accepted r7 store after a literal load into r3"
    );
}

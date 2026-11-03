use super::*;
fn fixture(middle: &[u16]) -> (Vec<u8>, usize) {
    let mut words = vec![0xb510, 0x4c00];
    words.extend(middle);
    let site = words.len() * 2;
    words.extend([0x7820, 0xbd10]);
    (words.into_iter().flat_map(u16::to_le_bytes).collect(), site)
}
#[test]
fn saved_frame_rejects_return_and_saved_register_overwrites() {
    for alias in [false, true] {
        for offset in [0, 4] {
            let mut asm = thumb_asm::Asm::new();
            asm.push(0x110).mov_reg(0, 0);
            if alias {
                asm.mov_reg(2, 13).str_imm(0, 2, offset);
            } else {
                asm.str_sp(0, offset);
            }
            asm.pop(0x110);
            let image = asm.finish().unwrap();
            assert!(
                SavedLink::bind(&image, 0, 2).is_err(),
                "alias={alias} offset={offset}"
            );
        }
    }
    // A volatile push slot can be used as native scratch, as the scanner does.
    let mut asm = thumb_asm::Asm::new();
    asm.push(0x118).mov_reg(0, 0).str_sp(0, 0).pop(0x118);
    assert!(SavedLink::bind(&asm.finish().unwrap(), 0, 2).is_ok());
}

#[test]
fn saved_frame_keeps_aliases_through_arithmetic_and_spills() {
    for case in 0..3 {
        let mut asm = thumb_asm::Asm::new();
        asm.push(0x118).mov_reg(0, 0).mov_reg(2, 13);
        match case {
            0 => {
                asm.movs_imm(1, 0).adds_reg(2, 2, 1);
            }
            1 => {
                asm.lsls_imm(2, 2, 1);
            }
            2 => {
                asm.str_sp(2, 0).ldr_imm(2, 2, 0);
            }
            _ => unreachable!(),
        }
        asm.str_imm(0, 2, 8).pop(0x118);
        assert!(
            SavedLink::bind(&asm.finish().unwrap(), 0, 2).is_err(),
            "alias case {case}"
        );
    }
}

#[test]
fn switch_preserves_argument_pointer_provenance() {
    use thumb_asm::isa::{encode_bytes, Insn, Operand, Width};
    for offset in [0, 8] {
        let mut image = vec![0xff; 0x300];
        let mut prefix = thumb_asm::Asm::new();
        prefix.push(0x118).mov_reg(0, 13).movs_imm(3, 0);
        image[..6].copy_from_slice(&prefix.finish().unwrap()[..6]);
        let call = Insn {
            mnemonic: "blx",
            encoding: "T2",
            addr: 6,
            width: Width::Wide,
            cond: None,
            sets_flags: false,
            explicit_width: false,
            operands: [Operand::Target(0x200)].into_iter().collect(),
        };
        image[6..10].copy_from_slice(&encode_bytes(&call).unwrap());
        image[10..14].copy_from_slice(&[1, 2, 2, 0]);
        let mut suffix = thumb_asm::Asm::new();
        suffix.str_imm(1, 0, offset).pop(0x118);
        image[14..18].copy_from_slice(&suffix.finish().unwrap());
        let body = crate::compiler::ARM_BYTE_SWITCH;
        image[0x200..0x200 + body.len()].copy_from_slice(body);
        assert_eq!(
            SavedLink::bind(&image, 0, 2).is_ok(),
            offset == 0,
            "stack offset {offset}"
        );
    }
}

#[test]
fn caller_witness_refuses_a_different_source() {
    let mut asm = thumb_asm::Asm::new();
    asm.push(0x110).movs_imm(0, 1).mov_reg(1, 1).pop(0x110);
    let image = asm.finish().unwrap();
    let witness = SavedLink::bind(&image, 0, 4).unwrap();
    assert!(witness.require_argument_definition(&image, 2, 4, 0).is_ok());
    let mut changed = image.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(witness
        .require_argument_definition(&changed, 2, 4, 0)
        .is_err());
}

#[test]
fn native_register_definition_rejects_writeback_and_clobber() {
    let (good, site) = fixture(&[0x46c0]);
    assert!(SavedLink::require_live_definition(&good, 0, site, 2, 4, 4).is_ok());
    for middle in [&[0xc401][..], &[0x2400][..], &[0xf844, 0x0b04][..]] {
        let (bad, site) = fixture(middle);
        assert!(SavedLink::require_live_definition(&bad, 0, site, 2, 4, 4).is_err());
    }
}

use super::*;
use thumb_asm::Asm;

fn byte_fill(length: u32, external: bool) -> Vec<u8> {
    let mut a = Asm::new();
    let body = a.label();
    let check = a.label();
    a.ldr_lit(1, 0x02000e20).ldr_lit(0, length).b(check);
    a.bind(body).strb_imm(2, 1, 0).adds_imm(1, 1).subs_imm(0, 1);
    a.bind(check).cmp_imm(0, 0).b_cond(Cond::Ne, body).bx(14);
    if external {
        a.b(body);
    }
    a.finish().unwrap()
}

#[test]
fn indexed_entries_agree_with_thumb_asm_reference_queries() {
    let image = byte_fill(0x40, true);
    let entries = Entries::inspect(&image);
    for prefix in (0..image.len()).step_by(2) {
        for end in (prefix + 2..=image.len()).step_by(2) {
            let expected = (prefix + 2..end).step_by(2).all(|target| {
                thumb_asm::analysis::xrefs(&image, target as u32)
                    .iter()
                    .all(|reference| {
                        reference.kind == thumb_asm::analysis::XrefKind::LiteralPool
                            || (reference.at >= prefix && reference.at < end)
                    })
            });
            assert_eq!(
                entries.closed(prefix, end),
                expected,
                "range {prefix}..{end}"
            );
        }
    }
}

#[test]
fn byte_fill_has_exact_prechecked_extent_and_rejects_external_entry() {
    for length in [0, 1, 0x40] {
        let image = byte_fill(length, false);
        let fill = Fill::byte_at(&image, 0, &Entries::inspect(&image)).unwrap();
        assert_eq!(fill.length, length);
        assert_eq!(fill.address, 0x02000e20);
        let refs = super::super::RamReferences::inspect(&image);
        assert!(!refs.bytes().contains(&0x02000e60));
        assert_eq!(refs.bytes().contains(&0x02000e5f), length == 0x40);
    }
    let external = byte_fill(0, true);
    assert!(Fill::byte_at(&external, 0, &Entries::inspect(&external)).is_none());
}

#[test]
fn implicit_flag_writers_do_not_reuse_an_earlier_compare() {
    use thumb_asm::isa::{Insn, Operands, Width};
    for mnemonic in ["tst", "cmn"] {
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(2)));
        operands.push(Operand::Reg(Reg(2)));
        let instruction = Insn {
            mnemonic,
            encoding: "T1",
            addr: 0,
            width: Width::Narrow,
            cond: None,
            sets_flags: false,
            explicit_width: false,
            operands,
        };
        let bytes = thumb_asm::isa::encode_bytes(&instruction).unwrap();
        let mut a = Asm::new();
        let write = a.label();
        a.ldr_lit(0, 0x02000e20).movs_imm(1, 0).cmp_imm(1, 0);
        a.replay(&bytes).b_cond(Cond::Ne, write).bx(14);
        a.bind(write).strb_imm(3, 0, 31).bx(14);
        let refs = super::super::RamReferences::inspect(&a.finish().unwrap());
        assert!(
            refs.bytes().contains(&0x02000e3f),
            "{mnemonic} must invalidate old Z"
        );
    }
}

#[test]
fn loader_lifetime_uses_real_entries_not_equal_numeric_data_words() {
    let mut a = Asm::new();
    let copy = a.label();
    let copy_check = a.label();
    a.ldr_lit(2, 0x7c).ldr_lit(0, 0x800).ldr_lit(1, 0x02000d80);
    a.lsrs_imm(2, 2, 2).b(copy_check);
    a.bind(copy).ldr_imm(3, 0, 0).str_imm(3, 1, 0);
    a.adds_imm(0, 4).adds_imm(1, 4).subs_imm(2, 1);
    a.bind(copy_check).cmp_imm(2, 0).b_cond(Cond::Ne, copy);
    let fill = a.label();
    let check = a.label();
    a.ldr_lit(1, 0x178)
        .ldr_lit(0, 0x02000dfc)
        .lsrs_imm(1, 1, 2)
        .b(check);
    a.bind(fill).str_imm(2, 0, 0);
    a.adds_imm(0, 4).subs_imm(1, 1);
    a.bind(check).cmp_imm(1, 0).b_cond(Cond::Ne, fill).bx(14);
    let body = a.finish().unwrap();
    let mut image = vec![0; 0x11000];
    image[0x1000..0x1000 + body.len()].copy_from_slice(&body);
    thumb_asm::install_branch(&mut image, 0x200, thumb_asm::BranchKind::Bl, 0x1000).unwrap();
    image[0x10100..0x10104].copy_from_slice(&0x1000u32.to_le_bytes());
    assert!(
        Fill::at(&image, 0x1018, &Entries::inspect(&image))
            .unwrap()
            .loader_private
    );
    thumb_asm::install_branch(&mut image, 0x10040, thumb_asm::BranchKind::Bl, 0x1000).unwrap();
    assert!(
        !Fill::at(&image, 0x1018, &Entries::inspect(&image))
            .unwrap()
            .loader_private
    );
}

#[test]
fn pointer_seed_recovers_a_closed_preheader_without_weakening_entry_checks() {
    // An outside branch into the body prevents whole-loop summarization.
    // Starting from the native preheader still has a known zero count and
    // must skip the store, rather than inventing an unbounded fill.
    let image = byte_fill(0, true);
    assert!(Fill::byte_at(&image, 0, &Entries::inspect(&image)).is_none());
    let refs = super::super::RamReferences::inspect(&image);
    assert!(!refs.bytes().contains(&0x02000e40));

    let mut a = Asm::new();
    let body = a.label();
    let check = a.label();
    a.ldr_lit(2, 0x40).ldr_lit(0, 0x100).ldr_lit(1, 0x02000da8);
    a.lsrs_imm(2, 2, 2).push(0x110).b(check);
    a.bind(body).ldr_imm(3, 0, 0).str_imm(3, 1, 0);
    a.adds_imm(0, 4).adds_imm(1, 4).subs_imm(2, 1);
    a.bind(check)
        .cmp_imm(2, 0)
        .b_cond(Cond::Ne, body)
        .pop(0x110);
    a.b(check); // genuine decoded external edge, retained as a refusal
    let image = a.finish().unwrap();
    assert!(CopyLoop::at(&image, 0, &Entries::inspect(&image)).is_none());
    let refs = super::super::RamReferences::inspect(&image);
    assert!(refs.bytes().contains(&0x02000de7));
    assert!(!refs.bytes().contains(&0x02000de8));
    assert!(!refs.bytes().contains(&0x02000e3c));
}

#[test]
fn word_clear_with_local_zero_initializer_has_a_bounded_extent() {
    let mut a = Asm::new();
    let body = a.label();
    let check = a.label();
    a.ldr_lit(1, 0x40).ldr_lit(0, 0x02000d80).lsrs_imm(1, 1, 2);
    a.movs_imm(4, 0).b(check);
    a.bind(body).str_imm(4, 0, 0).adds_imm(0, 4).subs_imm(1, 1);
    a.bind(check).cmp_imm(1, 0).b_cond(Cond::Ne, body).bx(14);
    let image = a.finish().unwrap();
    assert_eq!(
        Fill::at(&image, 0, &Entries::inspect(&image))
            .unwrap()
            .length,
        0x40
    );
    let refs = super::super::RamReferences::inspect(&image);
    assert!(refs.bytes().contains(&0x02000dbf));
    assert!(!refs.bytes().contains(&0x02000dc0));
}

#[test]
fn word_copy_uses_literal_count_not_pointer_walk_iteration_budget() {
    for (length, frame) in [(0, false), (4, false), (0x7f, false), (0x40, true)] {
        let mut a = Asm::new();
        let body = a.label();
        let check = a.label();
        a.ldr_lit(2, length)
            .ldr_lit(0, 0x100)
            .ldr_lit(1, 0x02000d80);
        a.lsrs_imm(2, 2, 2);
        if frame {
            a.push(0x110);
        }
        a.b(check);
        a.bind(body).ldr_imm(3, 0, 0).str_imm(3, 1, 0);
        a.adds_imm(0, 4).adds_imm(1, 4).subs_imm(2, 1);
        a.bind(check).cmp_imm(2, 0).b_cond(Cond::Ne, body);
        if frame {
            a.pop(0x110);
        } else {
            a.bx(14);
        }
        let image = a.finish().unwrap();
        let copy = CopyLoop::at(&image, 0, &Entries::inspect(&image)).unwrap();
        assert_eq!(copy.length, length & !3);
        let refs = super::super::RamReferences::inspect(&image);
        assert!(!refs.bytes().contains(&0x02000e40));
        assert_eq!(refs.bytes().contains(&0x02000dfb), length == 0x7f);
    }
}

#[test]
fn unmodelled_branch_marks_the_pointer_seed_incomplete() {
    let mut image = vec![0u8; 12];
    for (i, h) in [0x4801u16, 0xb101, 0x4770, 0xbf00].iter().enumerate() {
        image[i * 2..i * 2 + 2].copy_from_slice(&h.to_le_bytes());
    }
    image[8..12].copy_from_slice(&0x0200_0000u32.to_le_bytes());
    let refs = super::super::RamReferences::inspect(&image);
    assert!(refs.incomplete().contains(&0), "cbz path was silently lost");

    // A plain `bx lr` return still completes the path.
    image[2..4].copy_from_slice(&0x4770u16.to_le_bytes());
    let refs = super::super::RamReferences::inspect(&image);
    assert!(!refs.incomplete().contains(&0));
}

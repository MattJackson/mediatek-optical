use super::*;
use thumb_asm::Asm;

/// `stmia`/`ldmia` T1: `1100 L Rn register_list`.
fn multiple(load: bool, base: u16, list: u16) -> [u8; 2] {
    (0xC000 | u16::from(load) << 11 | base << 8 | list).to_le_bytes()
}

#[test]
fn load_store_multiple_through_a_tracked_pointer_is_observed() {
    // stmia r0!, {r1, r2}; str r1, [r0] -- the store after writeback lands
    // past the stored pair.
    let mut a = Asm::new();
    a.ldr_lit(0, 0x02000100).movs_imm(1, 0).movs_imm(2, 0);
    a.replay(&multiple(false, 0, 0b110)).str_imm(1, 0, 0).bx(14);
    let refs = RamReferences::inspect(&a.finish().unwrap());
    for address in 0x02000100..0x0200010c {
        assert!(refs.bytes().contains(&address), "{address:#x}");
    }
    assert!(refs.uses().contains(&(6, 0x02000104, 4)));
    assert!(refs.uses().contains(&(8, 0x02000108, 4)));

    // ldmia r3, {r1, r3} has no writeback: the base is overwritten, so the
    // following store through r3 is not attributed to any SRAM address.
    let mut a = Asm::new();
    a.ldr_lit(3, 0x02000200)
        .replay(&multiple(true, 3, 0b1010))
        .str_imm(1, 3, 0)
        .bx(14);
    let refs = RamReferences::inspect(&a.finish().unwrap());
    assert!(refs.bytes().contains(&0x02000207));
    assert!(!refs.bytes().contains(&0x02000208));
    assert!(refs.uses().contains(&(2, 0x02000204, 4)));
    assert!(
        refs.uses().iter().all(|(pc, _, _)| *pc != 4),
        "{:x?}",
        refs.uses()
    );
}

#[test]
fn tracked_pointer_in_the_index_register_is_observed_or_incomplete() {
    // ldr r1, =ram; movs r0, #4; ldrb r2, [r0, r1]: a known base plus the
    // tracked pointer is an exact address.
    let mut a = Asm::new();
    a.ldr_lit(1, 0x02000100)
        .movs_imm(0, 4)
        .ldrb_reg(2, 0, 1)
        .bx(14);
    let refs = RamReferences::inspect(&a.finish().unwrap());
    assert!(
        refs.uses().contains(&(4, 0x02000104, 1)),
        "{:x?}",
        refs.uses()
    );
    assert!(refs.bytes().contains(&0x02000104));
    assert!(!refs.incomplete().contains(&0));

    // ldr r1, =ram; ldrb r0, [r2, r1] with r2 unknown: the address is
    // unresolved, so the seed must be reported incomplete.
    let mut a = Asm::new();
    a.ldr_lit(1, 0x02000100).ldrb_reg(0, 2, 1).bx(14);
    let refs = RamReferences::inspect(&a.finish().unwrap());
    assert!(refs.incomplete().contains(&0), "{:x?}", refs.incomplete());
}

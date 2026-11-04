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

#[test]
fn live_definition_holds_on_every_arrival_at_a_looping_read() {
    // push {r4,lr}; movs r0,#5; L: bl X (site); cmp r4,#0; <tail>; pop {r4,pc}; X: bx lr.
    // The call clobbers r0, so a loop back to L reads the callee's result.
    let image = |tail: u16| thumb(&[0xb510, 0x2005, 0xf000, 0xf803, 0x2c00, tail, 0xbd10, 0x4770]);
    // bne L: the second arrival at the site no longer holds the constant.
    assert_eq!(
        SavedLink::require_live_definition(&image(0xd1fb), 0, 4, 2, 4, 0),
        Err(Error::InvalidContract)
    );
    // bne movs: every arrival re-executes the definition.
    assert!(SavedLink::require_live_definition(&image(0xd1fa), 0, 4, 2, 4, 0).is_ok());
    // nop: the site is reached once.
    assert!(SavedLink::require_live_definition(&image(0x46c0), 0, 4, 2, 4, 0).is_ok());
}

#[test]
fn tst_invalidates_cached_comparison() {
    // CMP r0,#1 would make BNE never taken, but TST rewrites the flags, so
    // the branch to the invalid path must still be explored.
    let mut asm = thumb_asm::Asm::new();
    let bad = asm.label();
    asm.push(0x110).movs_imm(0, 1).cmp_imm(0, 1).raw16(0x4200);
    asm.b_cond(thumb_asm::Cond::Ne, bad);
    let site = asm.pos();
    asm.mov_reg(0, 0).pop(0x110);
    asm.bind(bad).raw16(0xde00);
    let image = asm.finish().unwrap();
    assert!(SavedLink::bind(&image, 0, site).is_err());
}

#[test]
fn stack_alias_in_index_register_fails_closed() {
    // str r0,[r1,r2] with r1 plain and r2 = sp is not a plain store.
    let mut asm = thumb_asm::Asm::new();
    asm.push(0x110).mov_reg(2, 13).raw16(0x5088);
    let site = asm.pos();
    asm.mov_reg(0, 0).pop(0x110);
    let image = asm.finish().unwrap();
    assert!(SavedLink::bind(&image, 0, site).is_err());
}

#[test]
fn stack_load_near_address_limit_does_not_overflow() {
    // r2 = sp + 0x7fffffff, then ldmia r2!,{r0,r1,r3} walks the alias to i32::MAX.
    let mut asm = thumb_asm::Asm::new();
    asm.push(0x110)
        .movs_imm(3, 1)
        .lsls_imm(3, 3, 31)
        .subs_imm(3, 1)
        .mov_reg(2, 13)
        .adds_reg(2, 2, 3)
        .raw16(0xca0b);
    let site = asm.pos();
    asm.mov_reg(0, 0).pop(0x110);
    let image = asm.finish().unwrap();
    let _ = SavedLink::bind(&image, 0, site);
}

#[test]
fn register_shift_uses_only_the_low_byte() {
    // r1 = 0x100 shifts by zero, so r0 stays 5 and the udf path is live.
    let words: [u16; 9] = [
        0xb510, // push {r4, lr}
        0x2005, // movs r0, #5
        0x2101, // movs r1, #1
        0x0209, // lsls r1, r1, #8
        0x40c8, // lsrs r0, r1
        0x2800, // cmp r0, #0 (site)
        0xd000, // beq pop
        0xde00, // udf
        0xbd10, // pop {r4, pc}
    ];
    let image: Vec<u8> = words.into_iter().flat_map(u16::to_le_bytes).collect();
    assert_eq!(SavedLink::bind(&image, 0, 10), Err(Error::InvalidContract));
}

fn thumb(words: &[u16]) -> Vec<u8> {
    words.iter().copied().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn stack_pointer_spills_beyond_the_tracked_bound_are_refused() {
    // Nine `stmia r1!, {r0-r7}` of stack aliases spill 288 pointer bytes into
    // a 400-byte local frame, more than any native frame is modelled to hold.
    let mut words = vec![0xb510, 0xb0e4];
    words.extend((0..8).map(|rd| 0x4668 | rd));
    words.extend([0xc1ff; 9]);
    words.extend([0xb064, 0x46c0, 0xbd10]);
    let site = (words.len() - 2) * 2;
    let image = thumb(&words);
    assert_eq!(
        SavedLink::bind(&image, 0, site),
        Err(Error::InvalidContract)
    );
    // The same frame spilling eight stack pointers remains provable.
    let mut words = vec![0xb510, 0xb0e4];
    words.extend((0..8).map(|rd| 0x4668 | rd));
    words.extend([0xc1ff, 0xb064, 0x46c0, 0xbd10]);
    let site = (words.len() - 2) * 2;
    assert!(SavedLink::bind(&thumb(&words), 0, site).is_ok());
}

#[test]
fn looping_stack_pointer_spills_stay_bounded() {
    // push {r4,lr}; mov r0..r7, sp; loop: subs r1,#64; stmia r1!,{r0-r7}; b loop.
    // Every iteration spills 32 fresh pointer bytes, so no state repeats.
    let mut words = vec![0xb510];
    words.extend((0..8).map(|rd| 0x4668 | rd));
    words.extend([0x3940, 0xc1ff, 0xe7fc]);
    let mut image = thumb(&words);
    image.resize(0x2000, 0);
    let started = std::time::Instant::now();
    assert_eq!(
        SavedLink::bind(&image, 0, 0x100),
        Err(Error::InvalidContract)
    );
    // Unbounded spill tracking took over 10 s and several GB here.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn switch_fan_out_shares_queued_stack_models() {
    // push {r3,r4,lr}; mov r0,sp (site); movs r3,#0; blx byte-switch whose 33
    // targets all reach pop {r3,r4,pc}. Queued successors must not each own a
    // stack-model copy, or a 33-way fan-out holds 33x the states the cap bounds.
    use thumb_asm::isa::{encode_bytes, Insn, Operand, Width};
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
    // 32 cases plus the default, all at 10 + 2 * 17 = 44.
    image[10] = 32;
    image[11..44].fill(17);
    let mut suffix = thumb_asm::Asm::new();
    suffix.pop(0x118);
    image[44..46].copy_from_slice(&suffix.finish().unwrap()[..2]);
    let body = crate::compiler::ARM_BYTE_SWITCH;
    image[0x200..0x200 + body.len()].copy_from_slice(body);
    let mut counts = WalkCounts::default();
    let copies = || super::super::caller_stack::STACK_COPIES.with(core::cell::Cell::get);
    let before = copies();
    assert_eq!(
        SavedLink::frame_counted(&image, 0, 2, &mut counts),
        Ok((12, vec![44]))
    );
    // Each visited state copies the model it mutates once; a copy per queued
    // successor would add one for every switch target on top of that.
    let made = copies() - before;
    assert!(
        made <= counts.states,
        "{made} stack copies for {} states",
        counts.states
    );
}

#[test]
fn long_native_caller_is_bounded_by_flow_and_retains_saved_slot_guards() {
    let mut image = [0xc0, 0x46].repeat(0xa01);
    image[..2].copy_from_slice(&0xb500u16.to_le_bytes()); // PUSH {LR}
    image[0x1400..0x1402].copy_from_slice(&0xbd00u16.to_le_bytes()); // POP {PC}
    let witness = SavedLink::bind(&image, 0, 2).unwrap();
    assert_eq!(witness.stack_bytes(), 4);
    assert_eq!(witness.returns(), &[0x1400]);
    let mut overwrite = image.clone();
    overwrite[0x1300..0x1302].copy_from_slice(&0x9000u16.to_le_bytes()); // STR R0,[SP]
    assert!(SavedLink::bind(&overwrite, 0, 2).is_err());
    image[0x1400..0x1402].copy_from_slice(&0xbd10u16.to_le_bytes()); // POP {R4,PC}
    assert!(SavedLink::bind(&image, 0, 2).is_err());
}

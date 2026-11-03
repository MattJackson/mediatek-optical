use super::*;

fn fixture() -> Vec<u8> {
    let mut image = vec![0; 0x200000];
    let wrapper = include_bytes!("../../../tests/fixtures/analysis/uh12-wrapper.bin");
    let program = include_bytes!("../../../tests/fixtures/analysis/uh12-program.bin");
    image[0x17c44e..0x17c44e + wrapper.len()].copy_from_slice(wrapper);
    image[0x17000..0x17000 + program.len()].copy_from_slice(program);
    image
}

#[test]
fn native_mode_three_stores_bind_to_the_actual_loop_cells() {
    let image = fixture();
    let proof = inspect_mode_three_wrapper(&image, 0, 0x17c44e).unwrap();
    assert_eq!(proof.loop_address, 0x17000);
    assert_eq!(proof.copied_bytes, 0x1bfc);
    assert_eq!(proof.program.destination_cell, 0x02000c58);
    assert_eq!(proof.program.source_offset_cell, 0x02000c60);
    assert_eq!(proof.program.remaining_cell, 0x02000c64);
    assert_eq!(proof.copy_helper, 0xaa942);
    assert_eq!(proof.activate_helper, 0xaa90a);
    for relative in [
        0, 2, 4, 6, 0x50, 0x52, 0x10a, 0x10c, 0x126, 0x128, 0x12c, 0x130, 0x142, 0x194, 0x196,
    ] {
        let mut changed = image.clone();
        changed[0x17c44e + relative] ^= 1;
        assert!(
            inspect_mode_three_wrapper(&changed, 0, 0x17c44e).is_none(),
            "{relative:#x}"
        );
    }
    for at in [0x17c76c, 0x17c770, 0x17c774, 0x17c778, 0x17002] {
        let mut changed = image.clone();
        changed[at] ^= 1;
        assert!(
            inspect_mode_three_wrapper(&changed, 0, 0x17c44e).is_none(),
            "{at:#x}"
        );
    }
}

#[test]
fn unaligned_loop_address_is_rejected() {
    let mut image = fixture();
    let program = include_bytes!("../../../tests/fixtures/analysis/uh12-program.bin");
    // Move the loop two bytes: its PC-relative literal pools would no longer
    // be word aligned at run time, so the evidence cannot apply.
    image[0x17000..0x17000 + program.len() + 2].fill(0);
    image[0x17002..0x17002 + program.len()].copy_from_slice(program);
    let at = 0x17c44e + 0x13e;
    let delta = 0x17002i64 - (at as i64 + 4);
    let high = 0xf000u16 | ((delta >> 12) & 0x7ff) as u16;
    let low = 0xf800u16 | ((delta >> 1) & 0x7ff) as u16;
    image[at..at + 2].copy_from_slice(&high.to_le_bytes());
    image[at + 2..at + 4].copy_from_slice(&low.to_le_bytes());
    let pool = 0x17c44e..0x17c44e + 0x400;
    let literal = image[pool.clone()]
        .windows(4)
        .position(|w| w == 0x17001u32.to_le_bytes())
        .unwrap()
        + pool.start;
    image[literal..literal + 4].copy_from_slice(&0x17003u32.to_le_bytes());
    assert!(inspect_mode_three_wrapper(&image, 0, 0x17c44e).is_none());
}

use super::*;

const HELD: &[u8] = include_bytes!("../../../tests/fixtures/analysis/uh12-program.bin");
const WIDE: &[u8] = include_bytes!("../../../tests/fixtures/analysis/bp55-program.bin");
const NO_PRELUDE: &[u8] = include_bytes!("../../../tests/fixtures/analysis/wh16-program.bin");

#[test]
fn wide_loop_without_prelude_binds_complete_native_code_and_reserved_spans() {
    let proof = inspect_program_loop(NO_PRELUDE).unwrap();
    assert_eq!(proof.variant, ProgramLoopVariant::WideWithoutPrelude);
    assert_eq!(proof.destination_cell, 0x02000c68);
    assert_eq!(proof.source_offset_cell, 0x02000c70);
    assert_eq!(proof.remaining_cell, 0x02000c74);
    assert_eq!(proof.staging_cell, 0x02000c3c);
    assert_eq!(proof.copy_pointer_cell, 0x02000c90);
    assert_eq!(proof.flash_status_cell, 0x01ffc2f8);
    assert_eq!(
        proof.preserving_boot_spans,
        [0x10000..0x1c8000, 0x1ec000..0x1f0000]
    );
    for reserved in core::iter::once(crate::layout::BOOT_AREA).chain(crate::layout::DRIVE_WRITTEN) {
        assert!(proof
            .preserving_boot_spans
            .iter()
            .all(|span| span.end <= reserved.start || span.start >= reserved.end()));
    }
    assert!(inspect_compact_program_loop(NO_PRELUDE).is_none());
    assert!(inspect_wide_program_loop(NO_PRELUDE).is_none());
    // Every instruction, branch destination and hardware/skip constant is
    // fixed, including code after the page helper's embedded literal pool.
    for at in (0..NO_PRELUDE.len()).step_by(2) {
        if NO_PRELUDE_RAM_WORDS
            .iter()
            .chain(&NO_PRELUDE_STATUS_WORDS)
            .any(|&p| (p..p + 4).contains(&at))
        {
            continue;
        }
        let mut changed = NO_PRELUDE.to_vec();
        changed[at] ^= 1;
        assert!(inspect_program_loop(&changed).is_none(), "{at:#x}");
    }
    for at in NO_PRELUDE_RAM_WORDS {
        let alias = if at == NO_PRELUDE_RAM_WORDS[0] {
            proof.source_offset_cell
        } else {
            proof.destination_cell
        };
        for bad in [0x02000c69u32, 0x04011000, alias] {
            let mut changed = NO_PRELUDE.to_vec();
            changed[at..at + 4].copy_from_slice(&bad.to_le_bytes());
            assert!(inspect_program_loop(&changed).is_none(), "{at:#x}/{bad:#x}");
        }
    }
    assert!(inspect_program_loop(&NO_PRELUDE[..NO_PRELUDE.len() - 1]).is_none());
}

#[test]
fn wide_form_has_distinct_skip_and_role_checked_relocations() {
    let proof = inspect_program_loop(WIDE).unwrap();
    assert_eq!(proof.variant, ProgramLoopVariant::Wide);
    assert_eq!(proof.destination_cell, 0x02000ca4);
    assert_eq!(proof.source_offset_cell, 0x02000cac);
    assert_eq!(proof.remaining_cell, 0x02000cb0);
    assert_eq!(proof.staging_cell, 0x02000c78);
    assert_eq!(proof.copy_pointer_cell, 0x02000ccc);
    assert_eq!(
        proof.preserving_boot_spans,
        [0x10000..0x1c8000, 0x1ec000..0x1f0000]
    );
    assert!(inspect_compact_program_loop(WIDE).is_none());
    for at in (0..WIDE.len()).step_by(2) {
        if WIDE_RAM_WORDS
            .iter()
            .chain(&WIDE_STATUS_WORDS)
            .any(|&p| (p..p + 4).contains(&at))
        {
            continue;
        }
        for byte in [at, at + 1] {
            let mut changed = WIDE.to_vec();
            changed[byte] ^= 1;
            assert!(inspect_program_loop(&changed).is_none(), "{byte:#x}");
        }
    }
    for bad in [0x02000cacu32, 0x02000ca5, 0x04011000] {
        let mut changed = WIDE.to_vec();
        changed[0x374..0x378].copy_from_slice(&bad.to_le_bytes());
        assert!(inspect_program_loop(&changed).is_none(), "{bad:#x}");
    }
    assert!(inspect_program_loop(&WIDE[..WIDE.len() - 1]).is_none());
}

#[test]
fn relocated_native_loop_preserves_cell_roles() {
    let proof = inspect_compact_program_loop(HELD).unwrap();
    assert_eq!(proof.destination_cell, 0x02000c58);
    assert_eq!(proof.source_offset_cell, 0x02000c60);
    assert_eq!(proof.remaining_cell, 0x02000c64);
    assert_eq!(proof.staging_cell, 0x02000c2c);
    assert_eq!(proof.copy_pointer_cell, 0x02000c80);
    assert_eq!(
        proof.preserving_boot_spans,
        [0x10000..0x1d0000, 0x1ec000..0x1f0000]
    );
    let mut moved = HELD.to_vec();
    for (i, at) in RAM_WORDS.iter().enumerate() {
        moved[*at..*at + 4].copy_from_slice(&(0x02001000u32 + i as u32 * 4).to_le_bytes());
    }
    assert!(inspect_compact_program_loop(&moved).is_some());
}

#[test]
fn every_nonrelocatable_halfword_is_load_bearing() {
    for at in (0..HELD.len()).step_by(2) {
        if RAM_WORDS
            .iter()
            .chain(&STATUS_WORDS)
            .any(|&p| (p..p + 4).contains(&at))
        {
            continue;
        }
        for byte in [at, at + 1] {
            let mut changed = HELD.to_vec();
            changed[byte] ^= 1;
            assert!(
                inspect_compact_program_loop(&changed).is_none(),
                "{byte:#x}"
            );
        }
    }
    assert!(inspect_compact_program_loop(&HELD[..HELD.len() - 1]).is_none());
}

#[test]
fn rejects_cell_aliases_unaligned_cells_and_wrong_memory_roles() {
    for bad in [
        0x02000c60u32,
        0x02000c59,
        0x04011000,
        0x01ff9dd0,
        0xffff_fffc,
    ] {
        let mut changed = HELD.to_vec();
        changed[0x348..0x34c].copy_from_slice(&bad.to_le_bytes());
        assert!(inspect_compact_program_loop(&changed).is_none(), "{bad:#x}");
    }
    let mut changed = HELD.to_vec();
    changed[0x35c..0x360].copy_from_slice(&0x02000c58u32.to_le_bytes());
    assert!(inspect_compact_program_loop(&changed).is_none());
}

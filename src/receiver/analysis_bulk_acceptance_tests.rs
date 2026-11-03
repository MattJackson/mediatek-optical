use super::*;
const BASE: u32 = 0xa5288;
const HELD: &[u8] = include_bytes!("../../tests/fixtures/analysis/uh12-application.bin");

#[test]
fn acceptance_records_decoded_constant_results_without_inventing_a_call() {
    use programming::ResultCheck;
    let baseline = ApplicationAnalysis::inspect(HELD, BASE).unwrap();
    let original = baseline.ranges()[0].acceptance.unwrap();
    assert!(matches!(original.marker_check, ResultCheck::Call(_)));
    let at = (0xa7910 - BASE) as usize;
    for (first, second, expected) in [
        (0x2001u16, 0x2001u16, Some(1)),
        (0x2002, 0xbf00, Some(2)),
        (0x2000, 0x2001, Some(1)),
        (0x2001, 0x2000, None),
        (0x2101, 0x2001, None),
        (0x2001, 0x6001, None),
        (0xe000, 0x2001, None),
    ] {
        let mut changed = HELD.to_vec();
        changed[at..at + 2].copy_from_slice(&first.to_le_bytes());
        changed[at + 2..at + 4].copy_from_slice(&second.to_le_bytes());
        let result = ApplicationAnalysis::inspect(&changed, BASE).unwrap();
        match expected {
            Some(value) => {
                let tail = result.ranges()[0].acceptance.unwrap();
                assert_eq!(tail.marker_check, ResultCheck::ConstantNonzero(value));
                assert_eq!(tail.program_target, original.program_target);
                assert_eq!(tail.continuation, original.continuation);
                assert!(result.ranges()[0].state_slot.is_some());
            }
            None => assert!(result.ranges()[0].acceptance.is_none()),
        }
    }
}

#[test]
fn bulk_decoder_and_integrity_bind_the_selected_programming_tail() {
    let analysis = ApplicationAnalysis::inspect(HELD, BASE).unwrap();
    assert_eq!(analysis.ranges().len(), 1);
    assert_eq!(analysis.bulk_decoders().len(), 1);
    assert_eq!(analysis.integrity_selections().len(), 1);
    let tail = analysis.ranges()[0].acceptance.unwrap();
    assert_eq!(tail.program_target, 0x17c44e);
    assert_eq!(tail.program_call, 0xa7942);
    let frame = analysis.ranges()[0].state_slot.as_ref().unwrap();
    assert_eq!(frame.stack_bytes, 60);
    assert_eq!(frame.slot, 52);
    assert_eq!(frame.save_call, 0xa7736);
    assert_eq!(frame.restore_call, 0xa7948);
    assert_eq!(frame.return_path, [0xa794c, 0xa7280]);
    let mut looping = HELD.to_vec();
    let branch = (frame.return_path[0] - BASE) as usize;
    looping[branch..branch + 2].copy_from_slice(&0xe7feu16.to_le_bytes());
    assert!(ApplicationAnalysis::inspect(&looping, BASE)
        .unwrap()
        .ranges()[0]
        .state_slot
        .is_none());
    for address in [
        frame.save_call,
        frame.store,
        frame.restore_call,
        frame.epilogue,
    ] {
        let mut changed = HELD.to_vec();
        changed[(address - BASE) as usize] ^= 1;
        let analysis = ApplicationAnalysis::inspect(&changed, BASE).unwrap();
        assert!(analysis.ranges()[0].state_slot.is_none(), "{address:#x}");
    }
    for address in [0xa77ea, 0xa78ca, 0xa78f4, 0xa7938, 0xa7940] {
        let mut changed = HELD.to_vec();
        changed[(address - BASE) as usize] ^= 1;
        let analysis = ApplicationAnalysis::inspect(&changed, BASE).unwrap();
        assert!(analysis.ranges()[0].acceptance.is_none(), "{address:#x}");
    }
    let mut changed = HELD.to_vec();
    changed[(0xa7942 - BASE) as usize] ^= 1;
    let changed = ApplicationAnalysis::inspect(&changed, BASE).unwrap();
    assert_ne!(changed.ranges()[0].acceptance, Some(tail));
}

#[test]
fn tail_binds_register_allocation_and_cleanup_across_literal_islands() {
    for (bytes, base, target, failure_register, continuation, saved_offset) in [
        (
            include_bytes!("../../tests/fixtures/analysis/wp50-application.bin").as_slice(),
            0x9a2e0,
            0x13b522,
            7,
            0x9c9c0,
            60,
        ),
        (
            include_bytes!("../../tests/fixtures/analysis/bu40-a103-application.bin").as_slice(),
            0x9b520,
            0x13e9d2,
            6,
            0x9dc9c,
            60,
        ),
        (
            include_bytes!("../../tests/fixtures/analysis/be16-application.bin").as_slice(),
            0x9b1d0,
            0x140dd6,
            7,
            0x9d93c,
            52,
        ),
    ] {
        let analysis = ApplicationAnalysis::inspect(bytes, base).unwrap();
        assert_eq!(analysis.bulk_decoders().len(), 1);
        let tail = analysis.ranges()[0].acceptance.unwrap();
        assert_eq!(tail.program_target, target);
        assert_eq!(tail.source_pointer_register, 4);
        assert_eq!(tail.failure_pointer_register, failure_register);
        assert_eq!(tail.continuation, continuation);
        assert_eq!(tail.saved_state_offset, saved_offset);
        let frame = analysis.ranges()[0].state_slot.as_ref().unwrap();
        assert_eq!(frame.slot, saved_offset);
        assert_eq!(frame.stack_bytes, saved_offset + 8);
        for relative in [77, 81, 84, 86] {
            let mut changed = bytes.to_vec();
            changed[(tail.address + relative - base) as usize] ^= 1;
            let analysis = ApplicationAnalysis::inspect(&changed, base).unwrap();
            assert!(
                analysis.ranges()[0].acceptance.is_none(),
                "{base:#x}+{relative}"
            );
        }
    }
}

#[test]
fn proven_body_decode_without_its_header_call_is_conflicting_evidence() {
    let baseline = ApplicationAnalysis::inspect(HELD, BASE).unwrap();
    let [bulk] = baseline.bulk_decoders() else {
        panic!("held image has one bulk decoder")
    };
    assert!(!baseline.conflicting_arguments());
    // Break only the header call; the in-place body decode stays proven.
    let mut changed = HELD.to_vec();
    let at = (bulk.header.address - BASE) as usize;
    changed[at..at + 4].copy_from_slice(&[0, 0xbf, 0, 0xbf]);
    let analysis = ApplicationAnalysis::inspect(&changed, BASE).unwrap();
    assert!(analysis.bulk_decoders().is_empty());
    assert!(analysis.conflicting_arguments());
}

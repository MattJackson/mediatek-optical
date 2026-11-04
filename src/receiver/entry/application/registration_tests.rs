use super::*;

#[test]
fn real_v1_record_binds_opcode_type_and_thumb_pointer_uniquely() {
    let record = [0x3b, 1, 0, 0, 3, 0xca, 9, 0];
    assert_eq!(
        inspect_registration(&record, 0x155ba8, 0x9ca02),
        Some(Registration {
            record: 0x155ba8,
            callback: 0x9ca02
        })
    );
    for i in 0..8 {
        let mut bad = record;
        bad[i] ^= 1;
        assert!(inspect_registration(&bad, 0x155ba8, 0x9ca02).is_none());
        assert!(inspect_registration(&record[..i], 0x155ba8, 0x9ca02).is_none());
    }
    let mut duplicate = record.to_vec();
    duplicate.extend_from_slice(&record);
    assert!(inspect_registration(&duplicate, 0x155ba8, 0x9ca02).is_none());
    assert!(inspect_registration(&record, 0x155ba9, 0x9ca02).is_none());
    assert!(inspect_registration(&record, u32::MAX - 3, 0x9ca02).is_none());
    assert!(inspect_registration(&record, 0x155ba8, 0x9ca03).is_none());
}

#[test]
fn second_write_buffer_type_one_record_for_another_handler_is_ambiguous() {
    let record = [0x3b, 1, 0, 0, 3, 0xca, 9, 0];
    // Another WRITE BUFFER/type-1 handler leaves dispatcher selection unproven,
    // whichever order the two records appear in.
    let other = [0x3b, 1, 0, 0, 0x41, 0x10, 9, 0];
    for (first, second) in [(other, record), (record, other)] {
        let mut table = first.to_vec();
        table.extend_from_slice(&second);
        assert!(inspect_registration(&table, 0x155ba0, 0x9ca02).is_none());
    }
    // A different opcode or type with the same layout is not a competitor.
    let mut table = [0x3c, 1, 0, 0, 0x41, 0x10, 9, 0].to_vec();
    table.extend_from_slice(&[0x3b, 2, 0, 0, 0x41, 0x10, 9, 0]);
    table.extend_from_slice(&record);
    assert_eq!(
        inspect_registration(&table, 0x155b98, 0x9ca02),
        Some(Registration {
            record: 0x155ba8,
            callback: 0x9ca02
        })
    );
}

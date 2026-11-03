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

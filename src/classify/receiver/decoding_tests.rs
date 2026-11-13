use super::*;

// INTM application's actual header setup, including its PC-relative literal.
fn header() -> Vec<u8> {
    let mut bytes = vec![0; 0x370];
    bytes[..18].copy_from_slice(&[
        0xda, 0x48, 0x03, 0x23, 0x00, 0x68, 0x1b, 0x03, 0x10, 0x22, 0xc0, 0x18, 0x05, 0xa9, 0xfd,
        0xf7, 0xc9, 0xfd,
    ]);
    bytes[0x36c..0x370].copy_from_slice(&0x0200_0c34u32.to_le_bytes());
    bytes
}

fn inspect(bytes: &[u8]) -> Option<Call> {
    trace_call(bytes, 0x9d480, 0x9d480, [Value::Unknown; 8], |address| {
        (address == Value::Constant(0x0200_0c34)).then_some(Value::Staging(0))
    })
}

#[test]
fn actual_header_arguments_are_scratch_not_in_place() {
    let call = inspect(&header()).unwrap();
    assert_eq!(
        call,
        Call {
            address: 0x9d48e,
            target: 0x9b024,
            source: Value::Staging(0x3000),
            destination: Value::Stack(0x14),
            length: 16,
            fourth_argument: Value::Constant(0x3000),
        }
    );
}

#[test]
fn operand_changes_cannot_retain_the_same_proof() {
    let bytes = header();
    let original = inspect(&bytes).unwrap();
    for at in [0, 2, 4, 6, 8, 10, 12, 14, 16, 0x36c] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert_ne!(inspect(&changed), Some(original), "mutation at {at:#x}");
    }
}

#[test]
fn truncated_literals_unknown_memory_and_control_flow_fail_closed() {
    let bytes = header();
    assert!(inspect(&bytes[..0x36f]).is_none());
    assert!(trace_call(&bytes, 0x9d480, 0x9d480, [Value::Unknown; 8], |_| None).is_none());
    let mut branch = bytes;
    branch[2..4].copy_from_slice(&0xe000u16.to_le_bytes());
    assert!(inspect(&branch).is_none());
    branch[..2].copy_from_slice(&0xe7feu16.to_le_bytes());
    assert!(inspect(&branch).is_none());
    assert!(trace_call(
        &branch,
        u32::MAX - 1,
        u32::MAX - 1,
        [Value::Unknown; 8],
        |_| None
    )
    .is_none());
}

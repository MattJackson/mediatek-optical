use super::*;

const SIZE: usize = 0x20_0000;
const HEADER: Range<usize> = 0x3000..0x3010;

#[test]
fn scratch_decode_does_not_make_programmed_header_plaintext() {
    let operations = [
        Operation::CheckDecrypted(HEADER),
        Operation::Program(0..SIZE),
    ];
    assert_eq!(
        analyze(SIZE, &operations),
        Err(Error::Conflict { block: 0x3000 })
    );
}

#[test]
fn boot_integrity_check_also_prevents_header_only_encoding() {
    let operations = [
        Operation::CheckDecrypted(HEADER),
        Operation::CheckPlaintext(0x1000..0xfff0),
        Operation::Program(0x10000..SIZE),
    ];
    assert_eq!(
        analyze(SIZE, &operations),
        Err(Error::Conflict { block: 0x3000 })
    );
}

#[test]
fn preserved_unchecked_boot_allows_header_only_encoding() {
    let operations = [
        Operation::CheckDecrypted(HEADER),
        Operation::CheckPlaintext(0x10600..0x10608),
        Operation::Program(0x10000..SIZE),
    ];
    let plan = analyze(SIZE, &operations).unwrap();
    assert_eq!(plan.encrypted_ranges(), &[HEADER]);
    let image = vec![0x5a; SIZE];
    let wire = plan.encode(&image).unwrap();
    assert_eq!(wire[..HEADER.start], image[..HEADER.start]);
    assert_ne!(wire[HEADER.clone()], image[HEADER.clone()]);
    assert_eq!(wire[HEADER.end..], image[HEADER.end..]);
    let mut header = wire[HEADER.clone()].to_vec();
    crate::envelope::enc::decrypt(&mut header).unwrap();
    assert_eq!(header, image[HEADER]);
}

#[test]
fn full_decode_before_checks_and_programming_requires_full_encryption() {
    let operations = [
        Operation::CheckDecrypted(HEADER),
        Operation::DecryptInPlace(0..SIZE),
        Operation::CheckPlaintext(0x10600..0x10608),
        Operation::Program(0..SIZE),
    ];
    let plan = analyze(SIZE, &operations).unwrap();
    assert_eq!(plan.encrypted_ranges().len(), 1);
    assert_eq!(plan.encrypted_ranges()[0], 0..SIZE);
    let mut reordered = operations.to_vec();
    reordered.swap(1, 2);
    assert_eq!(
        analyze(SIZE, &reordered),
        Err(Error::Conflict { block: 0x10600 })
    );
}

#[test]
fn plaintext_and_body_only_are_distinct_constraints() {
    let plain = analyze(SIZE, &[Operation::Program(0..SIZE)]).unwrap();
    assert!(plain.encrypted_ranges().is_empty());
    let body = analyze(
        SIZE,
        &[
            Operation::CheckPlaintext(HEADER),
            Operation::DecryptInPlace(0x10000..SIZE),
            Operation::Program(0x10000..SIZE),
        ],
    )
    .unwrap();
    assert_eq!(body.encrypted_ranges().len(), 1);
    assert_eq!(body.encrypted_ranges()[0], 0x10000..SIZE);
}

#[test]
fn reject_unbounded_unaligned_repeated_and_incomplete_operations() {
    assert_eq!(
        analyze(SIZE, &[Operation::Program(0..SIZE + 1)]),
        Err(Error::Range)
    );
    assert_eq!(
        analyze(SIZE, &[Operation::CheckDecrypted(1..17)]),
        Err(Error::Alignment)
    );
    assert_eq!(
        analyze(SIZE, &[Operation::CheckPlaintext(HEADER)]),
        Err(Error::NoProgram)
    );
    assert_eq!(
        analyze(
            SIZE,
            &[
                Operation::DecryptInPlace(HEADER),
                Operation::CheckDecrypted(HEADER),
            ]
        ),
        Err(Error::MultipleDecryptions { block: 0x3000 })
    );
}

#[test]
fn layout_errors_are_standard_errors_with_stable_codes() {
    use super::{analyze, Error, Operation};
    use crate::CodedError;
    let error = analyze(16, &[Operation::CheckPlaintext(0..16)]).unwrap_err();
    let standard: &dyn std::error::Error = &error;
    assert_eq!(error, Error::NoProgram);
    assert_eq!(error.code(), "mediatek.layout.no_program");
    assert!(!standard.to_string().is_empty());
}

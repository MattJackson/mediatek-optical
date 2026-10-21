use mediatek_optical::CodedError;

#[test]
fn chip_label_failure_has_a_stable_code() {
    let error = "MT0000".parse::<mediatek_optical::Chip>().unwrap_err();
    assert_eq!(error.code(), "mediatek.chip.unknown_label");
}

#[cfg(feature = "drive")]
#[test]
fn transport_codes_do_not_contain_runtime_parameters() {
    use mediatek_optical::drive::Error;
    let first = Error::<()>::Short {
        expected: 8,
        actual: 3,
    };
    let second = Error::<()>::Short {
        expected: 32,
        actual: 0,
    };
    assert_eq!(first.code(), "mediatek.drive.short");
    assert_eq!(first.code(), second.code());
    assert_ne!(first.to_string(), second.to_string());
    assert_eq!(Error::Transport(()).code(), "mediatek.drive.transport");
    assert_eq!(
        Error::<()>::Oversize(0x1000000).code(),
        "mediatek.drive.oversize"
    );
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
#[test]
fn wrapper_errors_keep_stage_and_typed_cause() {
    use mediatek_optical::{drive, receiver};
    let error =
        receiver::ExecuteError::Receiver(receiver::Error::Read(drive::Error::<()>::Short {
            expected: 36,
            actual: 7,
        }));
    assert_eq!(error.code(), "mediatek.execute.receiver");
    let receiver::ExecuteError::Receiver(cause) = &error else {
        panic!("wrong stage")
    };
    assert_eq!(cause.code(), "mediatek.receiver.read");
    let receiver::Error::Read(cause) = cause else {
        panic!("missing transport cause")
    };
    assert_eq!(cause.code(), "mediatek.drive.short");
    use std::error::Error;
    assert!(error.source().unwrap().source().is_some());
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
#[test]
fn layout_errors_are_standard_errors_with_stable_codes() {
    use mediatek_optical::receiver::layout::{analyze, Error, Operation};
    let error = analyze(16, &[Operation::CheckPlaintext(0..16)]).unwrap_err();
    let standard: &dyn std::error::Error = &error;
    assert_eq!(error, Error::NoProgram);
    assert_eq!(error.code(), "mediatek.layout.no_program");
    assert!(!standard.to_string().is_empty());
}

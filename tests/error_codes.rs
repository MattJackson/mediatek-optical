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
fn execution_wrappers_report_the_cause_code_and_keep_the_typed_cause() {
    use mediatek_optical::drive::{self, ExecutionError, FlashError, ReceiverError};
    let error = ExecutionError::Receiver(ReceiverError::Read(drive::Error::<()>::Short {
        expected: 36,
        actual: 7,
    }));
    assert_eq!(error.code(), "mediatek.receiver.read");
    assert_eq!(error.phase(), "receiver binding");
    assert!(!error.firmware_write_started() && !error.write_started());
    let mismatch = FlashError::<()>::Mismatch {
        address: 0x4000,
        read: 0,
        wrote: 1,
        differing: 1,
        checked: 2,
    };
    assert_eq!(mismatch.code(), "mediatek.flash.mismatch");
    let error = ExecutionError::Flash(mismatch);
    assert_eq!(error.code(), "mediatek.flash.mismatch");
    assert_eq!(error.phase(), "readback");
    assert!(error.firmware_write_started() && error.write_started());
    let error = ExecutionError::Receiver(ReceiverError::Read(drive::Error::<()>::Short {
        expected: 36,
        actual: 7,
    }));
    let ExecutionError::Receiver(cause) = &error else {
        panic!("wrong stage")
    };
    assert_eq!(cause.code(), "mediatek.receiver.read");
    let ReceiverError::Read(cause) = cause else {
        panic!("missing transport cause")
    };
    assert_eq!(cause.code(), "mediatek.drive.short");
    use std::error::Error;
    assert!(error.source().unwrap().source().is_some());
}

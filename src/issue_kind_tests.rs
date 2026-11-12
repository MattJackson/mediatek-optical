#[test]
fn every_declared_code_has_a_deliberate_host_category() {
    for source in [
        include_str!("error_codes.rs"),
        include_str!("image/analysis/mod.rs"),
    ] {
        let mut codes = source
            .split('"')
            .filter(|s| s.starts_with("mediatek.") && !s.contains(char::is_whitespace))
            .peekable();
        assert!(codes.peek().is_some(), "no error codes extracted");
        for code in codes {
            assert_ne!(
                super::kind_for_code(code),
                crate::operation::IssueKind::Unexpected,
                "unclassified error code: {code}"
            );
        }
    }
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
#[test]
fn execute_and_flash_errors_classify_by_their_cause() {
    use crate::{
        operation::IssueKind,
        receiver::{self, ExecutionError},
        update::{FlashError, StartupError},
        CodedError,
    };
    // A pre-write receiver refusal never attempted a write.
    let refused = ExecutionError::<()>::Receiver(receiver::Error::Changed);
    assert_eq!(refused.kind(), IssueKind::ReceiverMismatch);
    let flash = ExecutionError::<()>::Flash(FlashError::Startup(StartupError::TargetMismatch));
    assert_eq!(flash.kind(), IssueKind::Verification);
    // The wrapper reports its cause's code.
    assert_eq!(refused.code(), "mediatek.receiver.changed");
    assert_eq!(flash.code(), "mediatek.startup.target_mismatch");
    let mismatch = FlashError::<()>::Startup(StartupError::TargetMismatch);
    assert_eq!(mismatch.kind(), IssueKind::Verification);
    let identity = FlashError::<()>::Startup(StartupError::Read(crate::drive::Error::Oversize(1)));
    assert_eq!(identity.kind(), IssueKind::Connection);
    assert_eq!(
        FlashError::<()>::ReadyTimeout(crate::drive::Error::Oversize(1)).kind(),
        IssueKind::Update
    );
}

#[cfg(feature = "image")]
#[test]
fn an_unrecognised_cmac_enabled_word_is_invalid_firmware() {
    use crate::{image::cmac::CmacError, operation::IssueKind, CodedError};
    let e = CmacError::UnknownEnabled {
        index: 1,
        enabled: 0,
    };
    assert_eq!(e.code(), "mediatek.cmac.unknown_enabled");
    assert_eq!(e.kind(), IssueKind::InvalidFirmware);
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
#[test]
fn reference_session_errors_classify_by_their_physical_cause() {
    use crate::{operation::IssueKind, receiver, CodedError};
    assert_eq!(
        super::kind_for_code("mediatek.reference.session"),
        IssueKind::Connection
    );
    let changed = receiver::reference::Error::<()>::Session(receiver::Error::Changed);
    assert_eq!(changed.kind(), IssueKind::ReceiverMismatch);
    let read = receiver::reference::Error::<()>::Session(receiver::Error::Read(
        crate::drive::Error::Transport(()),
    ));
    assert_eq!(read.kind(), IssueKind::Connection);
}

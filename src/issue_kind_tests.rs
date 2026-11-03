#[test]
fn every_declared_code_has_a_deliberate_host_category() {
    for source in [
        include_str!("error_codes.rs"),
        include_str!("image/analysis/mod.rs"),
    ] {
        let codes: Vec<&str> = source
            .split('"')
            .filter(|s| s.starts_with("mediatek.") && !s.contains(char::is_whitespace))
            .collect();
        assert!(!codes.is_empty(), "no error codes extracted");
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
        receiver::{self, ExecuteError},
        update::{FlashError, StartupError},
        CodedError,
    };
    // A pre-write receiver refusal never attempted a write.
    let refused = ExecuteError::<()>::Receiver(receiver::Error::Changed);
    assert_eq!(refused.kind(), IssueKind::ReceiverMismatch);
    let flash = ExecuteError::<()>::Flash(FlashError::Startup(StartupError::TargetMismatch));
    assert_eq!(flash.kind(), IssueKind::Verification);
    // The stage code stays stable.
    assert_eq!(refused.code(), "mediatek.execute.receiver");
    assert_eq!(flash.code(), "mediatek.execute.flash");
    let mismatch = FlashError::<()>::Startup(StartupError::TargetMismatch);
    assert_eq!(mismatch.kind(), IssueKind::Verification);
    let identity = FlashError::<()>::Startup(StartupError::Read(crate::drive::Error::Oversize(1)));
    assert_eq!(identity.kind(), IssueKind::Connection);
    assert_eq!(
        FlashError::<()>::ReadyTimeout(crate::drive::Error::Oversize(1)).kind(),
        IssueKind::Update
    );
}

#[test]
fn an_unobserved_restart_is_a_post_write_verification_state() {
    assert_eq!(
        super::kind_for_code("mediatek.startup.unobserved"),
        crate::operation::IssueKind::Verification
    );
}

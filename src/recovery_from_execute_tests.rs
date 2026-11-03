use super::*;
use crate::update::StartupError;

#[test]
fn unconfirmed_startup_maps_to_startup_error() {
    let e = from_execute::<&'static str>(receiver::ExecuteError::Flash(FlashError::Startup(
        StartupError::TargetMismatch,
    )));
    assert!(matches!(e, Error::Startup(StartupError::TargetMismatch)));
    assert_eq!(crate::CodedError::code(&e), "mediatek.recovery.startup");
}

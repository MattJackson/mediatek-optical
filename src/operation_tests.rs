use super::*;

#[test]
fn waiting_does_not_invent_a_percentage() {
    let waiting = Progress::waiting(Phase::Restarting, Component::Firmware);
    assert_eq!((waiting.done, waiting.total), (None, None));
    let measured = Progress::bytes(Phase::Verifying, Component::Firmware, 512, 1024);
    assert_eq!((measured.done, measured.total), (Some(512), Some(1024)));
}

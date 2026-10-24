//! Presentation-independent lifecycle observations shared by optical hosts.

/// A host-facing error category; detailed causes remain in the typed library error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueKind {
    /// The selected bytes cannot form a valid firmware update.
    InvalidFirmware,
    /// This firmware's update format is not implemented.
    UnsupportedFirmware,
    /// Installed evidence no longer matches the connected receiver.
    ReceiverMismatch,
    /// The selected firmware targets different hardware.
    HardwareMismatch,
    /// A required command or device read could not complete.
    Connection,
    /// Readback or target startup was not verified.
    Verification,
    /// An update command failed; transport evidence determines consequences.
    Update,
    /// The host needs to retain diagnostics for a new or unexpected condition.
    Unexpected,
}

/// A protocol-neutral operation phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Acquiring bytes from the installed firmware.
    Reading,
    /// Validating and assembling an executable update.
    Preparing,
    /// Sending firmware to the drive.
    Writing,
    /// Waiting for programming and restart to finish.
    Restarting,
    /// Comparing bytes read from the drive with the prepared target.
    Verifying,
}

/// A region label; hosts may translate these without knowing the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    /// A complete firmware image.
    Firmware,
    /// The boot and update component.
    Kernel,
    /// The application component.
    Normal,
}

/// Observed work in one phase; absent counts mean indeterminate activity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// What the library is doing.
    pub phase: Phase,
    /// Region whose bytes are being processed.
    pub component: Component,
    /// Completed bytes, never inferred from elapsed time.
    pub done: Option<usize>,
    /// Total bytes, when measurable.
    pub total: Option<usize>,
}

impl Progress {
    /// Measured progress in a region.
    pub const fn bytes(phase: Phase, component: Component, done: usize, total: usize) -> Self {
        Self {
            phase,
            component,
            done: Some(done),
            total: Some(total),
        }
    }

    /// A phase that cannot honestly report a percentage.
    pub const fn waiting(phase: Phase, component: Component) -> Self {
        Self {
            phase,
            component,
            done: None,
            total: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiting_does_not_invent_a_percentage() {
        let waiting = Progress::waiting(Phase::Restarting, Component::Firmware);
        assert_eq!((waiting.done, waiting.total), (None, None));
        let measured = Progress::bytes(Phase::Verifying, Component::Firmware, 512, 1024);
        assert_eq!((measured.done, measured.total), (Some(512), Some(1024)));
    }
}

//! Execution of prepared plans over the caller's transports.

use crate::drive::{ExecutionRuntime, FlashError, FlashOutcome, FlashTransport};
use crate::prepare::receiver::{PreparedUpdate, TransferPlan};

/// Receiver revalidation or execution failed.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::drive::ExecutionError<()>) -> u8 { match e { mediatek_optical::drive::ExecutionError::Receiver { .. } => 0, mediatek_optical::drive::ExecutionError::Flash { .. } => 1, } }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecutionError<E> {
    /// No write was attempted because the receiver could not be revalidated.
    Receiver(crate::prepare::receiver::Error<E>),
    /// The shared transfer/verification engine failed.
    Flash(FlashError<E>),
}

impl<E> ExecutionError<E> {
    /// Firmware data may have been sent to the drive. `false` for a receiver
    /// revalidation refusal and for a failed update entry (PROBE, TEST UNIT
    /// READY or PREPARE), which send no firmware data; `true` for every later
    /// failure, which may leave partial or unverified firmware.
    pub fn firmware_write_started(&self) -> bool {
        match self {
            Self::Receiver(_) => false,
            Self::Flash(error) => error.firmware_write_started(),
        }
    }

    /// Any device mutation may have been attempted. MediaTek execution writes
    /// no settings separately from the firmware, so this equals
    /// [`Self::firmware_write_started`].
    pub fn write_started(&self) -> bool {
        self.firmware_write_started()
    }

    /// The boundary which failed, suitable for operation diagnostics:
    /// `"receiver binding"`, `"update entry"`, `"firmware transfer"`,
    /// `"target startup"` or `"readback"`. Diagnostic text, not a parsing
    /// contract; route on [`crate::CodedError::code`].
    pub fn phase(&self) -> &'static str {
        match self {
            Self::Receiver(_) => "receiver binding",
            Self::Flash(error) => error.phase(),
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for ExecutionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Receiver(error) => {
                write!(f, "receiver revalidation failed before writing: {error}")
            }
            Self::Flash(error) => write!(f, "{error}"),
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for ExecutionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Receiver(source) => Some(source),
            Self::Flash(source) => Some(source),
        }
    }
}

impl PreparedUpdate {
    /// Revalidate, execute, and require the target identity after the write.
    /// An unreadable protected region is retained as limited verification,
    /// never full success. Hosts must check [`crate::drive::Startup::evidence`]:
    /// [`crate::drive::StartupEvidence::Unobserved`] means the restart into the
    /// target was not observed and is not confirmed startup.
    pub fn flash_completed<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: crate::transport::Transport,
        R: crate::transport::Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        self.plan.execute_completed(io, runtime)
    }
}

impl TransferPlan {
    pub(crate) fn execute_completed<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: crate::transport::Transport,
        R: crate::transport::Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        self.receiver
            .revalidate(io.reads)
            .map_err(ExecutionError::Receiver)?;
        crate::drive::flash::Payload {
            class: self.class,
            image: self.image(),
            transfer: self.transfer(),
        }
        // The identity just revalidated: mode and INQUIRY bytes 8..36 match
        // the physical drive on every path (see `completion::classify`).
        .flash_completed(
            io,
            runtime,
            self.mode,
            self.prepare,
            &self.receiver.identity,
        )
        .map_err(ExecutionError::Flash)
    }
}

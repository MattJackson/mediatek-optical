//! Command sequences over a caller-supplied `Transport`: identity and memory
//! reads, live receiver detection, update execution of a
//! `crate::prepare::PreparedUpdate`, and recovery.
//!
//! The caller owns the device: opening it, consent, backup and reporting.

pub use crate::protocol::{Evidence, Incomplete};
pub use crate::transport::{
    enter_recovery, enter_update, feature, identify, read_memory, request_sense, test_unit_ready,
    Data, Error, Session, Transport,
};

/// Sense-data parsing and classification.
pub mod sense {
    pub use crate::sense::*;
}

#[cfg(all(feature = "image", feature = "enc"))]
pub use crate::prepare::receiver::reference::Error as ReferenceError;
pub use crate::prepare::receiver::Error as ReceiverError;

use crate::prepare::receiver::{self, Receiver};

/// Detect the running update receiver from its code: mode, transfer encoding
/// and, with `image` + `enc`, the accepted entry recipe that
/// [`crate::prepare`] binds plans to. Read-only.
pub fn detect_receiver<T: Transport>(t: &mut T) -> Result<Receiver, ReceiverError<T::Error>> {
    let mode = receiver::detect_mode(t)?;
    #[cfg(all(feature = "image", feature = "enc"))]
    return receiver::detect(t, &mode);
    #[cfg(not(all(feature = "image", feature = "enc")))]
    receiver::detect_encoding(t, &mode)
}

/// The lightweight planning probe: the running receiver's mode and transfer
/// encoding only, without its entry recipe. Not enough to bind a plan.
pub fn detect_receiver_encoding<T: Transport>(
    t: &mut T,
) -> Result<Receiver, ReceiverError<T::Error>> {
    let mode = receiver::detect_mode(t)?;
    receiver::detect_encoding(t, &mode)
}

/// [`detect_receiver`] for a drive whose live code reads are restricted, with
/// `current` (the installed firmware) as the receiver code; the drive's
/// identity and build metadata must match it.
#[cfg(all(feature = "image", feature = "enc"))]
pub fn detect_receiver_with_current<T: Transport>(
    t: &mut T,
    current: &crate::envelope::Envelope,
) -> Result<Receiver, ReferenceError<T::Error>> {
    receiver::reference::detect(t, current)
}

/// [`detect_receiver`] with user-supplied receiver code whose identity need
/// not match the drive's; the physical session is still bound and revalidated.
#[cfg(all(feature = "image", feature = "enc"))]
pub fn detect_receiver_with_user_current<T: Transport>(
    t: &mut T,
    current: &crate::envelope::Envelope,
) -> Result<Receiver, ReferenceError<T::Error>> {
    receiver::reference::detect_user_supplied(t, current)
}

#[cfg(all(feature = "image", feature = "enc"))]
pub(crate) mod completion;
#[cfg(all(feature = "image", feature = "enc"))]
mod execute;
#[cfg(all(feature = "image", feature = "enc"))]
pub(crate) mod flash;
#[cfg(all(feature = "image", feature = "enc"))]
pub(crate) mod recovery;

#[cfg(all(feature = "image", feature = "enc"))]
pub use completion::{FlashOutcome, ReadbackQuality, Startup, StartupError, StartupEvidence};
#[cfg(all(feature = "image", feature = "enc"))]
pub use execute::ExecutionError;
#[cfg(all(feature = "image", feature = "enc"))]
pub use flash::{ExecutionRuntime, FlashError, FlashTransport, Stage, Status, Verified};
#[cfg(all(feature = "image", feature = "enc"))]
pub use recovery::{Error as RecoveryError, PreparedRecovery, Receiver as RecoveryReceiver};

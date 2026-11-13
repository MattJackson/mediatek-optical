//! Materialization: an image validated against the drive and bound to the
//! update receiver that will accept it, as an opaque [`TransferPlan`] that
//! yields the exact bytes and commands to write.
//!
//! The active [`Receiver`] is analyzed from code (the live drive's, through
//! [`crate::drive::detect_receiver`], or a Current firmware file's through
//! [`Receiver::from_firmware`]); its contract selects the wire encoding. A
//! plan cannot be built for a receiver that does not accept the image.
//!
//! Depends on [`crate::envelope`] and [`crate::classify`]; never on
//! [`crate::drive`], which executes the plans built here.

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
mod coverage;
#[cfg(feature = "drive")]
pub(crate) mod receiver;
#[cfg(feature = "image")]
pub(crate) mod update;

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
pub use coverage::{extend_coverage, CoverageExtension};
#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
pub use receiver::{reference::Provenance, PreparedUpdate, TransferEncoding, TransferPlan};
#[cfg(feature = "drive")]
pub use receiver::{Encoding, Mode, Receiver};
#[cfg(feature = "image")]
pub use update::{Direction, Step, ValidatedUpdate};

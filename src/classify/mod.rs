//! Verdicts without materialization: whether an image may be written to a
//! drive (or a drive running another image), and why not, as typed
//! `Refusal`s; and, with `analysis`, the Thumb-fingerprint evidence a Modify
//! plans from (`analysis`).
//!
//! Depends only on `crate::envelope`.

#[cfg(feature = "analysis")]
pub mod analysis;
#[cfg(feature = "image")]
mod installed;
#[cfg(feature = "image")]
mod model;
pub(crate) mod receiver;

#[cfg(feature = "image")]
pub use crate::envelope::refusal::{ContractReason, LayoutError, Refusal};
#[cfg(feature = "image")]
pub use installed::InstalledFirmware;
#[cfg(feature = "image")]
pub use model::{
    decide_authorized, decide_model, decide_plan, decide_rollback, ensure_unchanged, is_same_model,
    Build, HardwareDifference, ModelRefusal, Verdict, BACKUP_NOT_FLASHABLE_BACK, BANNER_LEN,
};

#[cfg(feature = "image")]
use crate::envelope::image::{cmac, detect_chip, family, is_drive_read, Family};
#[cfg(feature = "image")]
use crate::envelope::layout;
#[cfg(feature = "image")]
use crate::{Chip, DriveClass, Identity};

/// Every check that needs no installed firmware, in order: size,
/// integrity, raw drive read, chip against the drive and the image's own
/// hardware family. Returns that family.
///
/// Run it before capturing a backup; preparation repeats it.
#[cfg(feature = "image")]
pub fn check(image: &[u8], drive: &Identity) -> Result<Family, Refusal> {
    checked(image, drive).map(|(_, family)| family)
}

/// [`check`], also returning the drive's dialect.
#[cfg(feature = "image")]
pub(crate) fn checked(image: &[u8], drive: &Identity) -> Result<(DriveClass, Family), Refusal> {
    if image.len() != layout::IMAGE_SIZE {
        return Err(Refusal::Size(image.len()));
    }
    if !cmac::verify(image) {
        return Err(Refusal::Integrity);
    }
    if is_drive_read(image) {
        return Err(Refusal::DriveRead);
    }
    let image_chip = detect_chip(image).map_err(|_| Refusal::UnknownChip)?;
    // The drive's chip generation is decided by its boot banner and nothing
    // else, exactly as the image's is (see `crate::envelope::image::detect_chip`); the
    // `MTEKMT19xx` descriptor tag is a stale vendor label.
    let drive_chip = Chip::from_banner(drive.banner_bytes()).ok_or(Refusal::UnknownDriveChip)?;
    if image_chip.family != drive_chip {
        return Err(Refusal::ChipMismatch {
            image: image_chip.family,
            drive: drive_chip,
        });
    }
    let target = family(image).ok_or(Refusal::UnknownTargetFamily)?;
    Ok((DriveClass::of(drive_chip), target))
}

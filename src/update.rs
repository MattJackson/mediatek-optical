//! An update image validated against the drive's installed firmware.
//!
//! [`ValidatedUpdate::prepare`] takes the image to write and the
//! [`InstalledFirmware`] (the live [`Identity`] plus a complete read of the
//! drive, or the image rebuilt from one) and refuses, before any command:
//!
//! - an image that is not [`layout::IMAGE_SIZE`] bytes, fails its AES-CMAC
//!   integrity table, or is a raw drive read;
//! - an image for another chip than the drive's;
//! - an image whose hardware family differs from the installed firmware's, or
//!   where either family is unknown.
//!
//! The explicit `prepare_without_installed` path retains target and chip gates
//! but records that installed-family comparison is unavailable; host consent
//! is required separately. The prepared update carries the
//! [`DriveClass`] dialect chosen from the identity, which owns the command
//! sequence, chunking, readiness timing and read-back verification; with the
//! `drive` and `enc` features, `crate::receiver::Receiver::prepare` binds it
//! to the live receiver before executable transfer preparation.
//!
//! The caller still owns the drive: opening it, the pre-flash backup, tray and
//! consent policy, model checks and reporting.
//!
//! Requires the `image` feature.

use std::ops::RangeInclusive;

use crate::image::{cmac, detect_chip, family, is_drive_read, Family};
use crate::{cdb, layout, Chip, DriveClass, Identity};

#[cfg(feature = "drive")]
mod completion;
// Reference receivers (image + enc) test restart classification directly.
#[cfg(all(test, feature = "drive", feature = "enc"))]
pub(crate) use completion::classify;
#[cfg(feature = "drive")]
pub use completion::{FlashOutcome, ReadbackQuality, Startup, StartupError, StartupEvidence};
#[cfg(feature = "drive")]
pub(crate) mod flash;
#[cfg(feature = "drive")]
pub use flash::{ExecutionRuntime, FlashError, FlashTransport, Stage, Status, Verified};

/// Why an update was refused before any device command.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreparationError {
    /// No complete live entry profile was identified before preparation.
    ReceiverEntry,
    /// Decoder evidence does not yet establish an executable transfer contract,
    /// or the recognized contract does not accept this image (for example a
    /// required descriptor byte differs, or an active integrity range reaches
    /// a region the receiver deliberately preserves). It is also returned when
    /// a user-supplied reference names a different chip than the target image:
    /// that reference's receiver contract refuses the image, whereas a
    /// reference read from the drive reports `ChipMismatch` instead.
    ///
    /// `reason` tells the cases apart and says which input the refusal is
    /// about: the receiver (the live drive's code or the reference it was
    /// built from) or the image.
    ReceiverContract {
        /// Why the contract refused the image.
        reason: ContractReason,
    },
    /// The receiver's transfer layout is contradictory; no firmware was sent.
    #[cfg(all(feature = "drive", feature = "enc"))]
    Layout(crate::receiver::layout::Error),
    /// The image is not [`layout::IMAGE_SIZE`] bytes.
    Size(usize),
    /// The image fails its AES-CMAC integrity table (including an entry whose
    /// `enabled` word is unrecognised, see [`cmac::verify`]), or that table
    /// leaves no protected range that read-back can verify.
    Integrity,
    /// The image is a raw drive read: its boot page is the read-back mirror,
    /// and writing it would store that page in place of the boot page.
    DriveRead,
    /// The image names no supported chip.
    UnknownChip,
    /// The drive's boot banner names no supported chip generation.
    UnknownDriveChip,
    /// The image is for another chip than the drive's.
    ChipMismatch {
        /// The image's chip.
        image: Chip,
        /// The drive's chip.
        drive: Chip,
    },
    /// The installed firmware is not a complete image of the live drive: its
    /// size, identity descriptor or boot banner differ.
    InstalledMismatch,
    /// The installed firmware does not establish a hardware family.
    UnknownInstalledFamily,
    /// The image does not establish a hardware family.
    UnknownTargetFamily,
    /// The image is for other hardware than the installed firmware.
    FamilyMismatch {
        /// Family of the installed firmware.
        installed: Family,
        /// Family of the image.
        target: Family,
    },
}

/// Why [`PreparationError::ReceiverContract`] refused an image.
///
/// Hosts must keep a wildcard arm; the set of reasons may grow. An unknown
/// reason blames neither the receiver nor the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContractReason {
    /// The receiver was built from a user-supplied reference whose chip
    /// differs from the image's. The update and recovery chip gates have
    /// already matched the image to the live drive, so the reference is for
    /// another chip than the drive: the reference is at fault.
    ReferenceChip,
    /// The receiver's decoder evidence does not establish an executable
    /// transfer contract (conflicting or incomplete decoder arguments, a
    /// scratch decoder without a recognized mixed contract, or a bulk decoder
    /// this crate cannot bind). This is a fact about the receiver code (the
    /// live drive's, or the reference's), not about the image.
    ReceiverEvidence,
    /// The recognized mixed contract requires a descriptor byte of the image
    /// to be `0xDE` and it is not. The image does not fit the receiver's
    /// contract; that blames the image only when the contract is
    /// authoritative for the drive (live code, or a bound Current reference).
    /// A user-supplied reference's contract comes from a file not matched to
    /// the drive, so either file may be at fault.
    DescriptorByte,
    /// An active integrity range of the image reaches a region the
    /// recognized receiver deliberately preserves. As for
    /// [`Self::DescriptorByte`], this blames the image only when the contract
    /// is authoritative for the drive.
    PreservedRange,
}

impl core::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReceiverEntry => f.write_str(
                "receiver entry profile is unknown; detect the live receiver before preparing",
            ),
            Self::ReceiverContract { .. } => f.write_str(
                "receiver transfer contract is incomplete or does not accept this image; \
                     no firmware was sent",
            ),
            #[cfg(all(feature = "drive", feature = "enc"))]
            Self::Layout(e) => write!(f, "receiver transfer layout is unsupported: {e}"),
            Self::Size(n) => write!(
                f,
                "image is {n} bytes; an update image is exactly {} bytes",
                layout::IMAGE_SIZE
            ),
            Self::Integrity => f.write_str(
                "image fails its AES-CMAC integrity check or has no verifiable protected range",
            ),
            Self::DriveRead => f.write_str(
                "image is a raw drive read (its boot page is the read-back copy), not a \
                 flashable image",
            ),
            Self::UnknownChip => f.write_str("image names no MT1959 or MT1939 chip"),
            Self::UnknownDriveChip => f.write_str(
                "could not read this drive's controller generation (MT1959/MT1939) from its \
                 boot banner",
            ),
            Self::ChipMismatch { image, drive } => write!(
                f,
                "image is {image} firmware but this drive is {drive} silicon — refusing to \
                 flash across chip generations"
            ),
            Self::InstalledMismatch => f.write_str(
                "installed firmware is not a complete image of the live drive (size, identity \
                 descriptor or boot banner differ)",
            ),
            Self::UnknownInstalledFamily => {
                f.write_str("could not determine the installed firmware family")
            }
            Self::UnknownTargetFamily => {
                f.write_str("could not determine the target firmware family")
            }
            Self::FamilyMismatch { installed, target } => write!(
                f,
                "family mismatch: installed firmware is family {installed}, target is family \
                 {target}"
            ),
        }
    }
}

impl std::error::Error for PreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(all(feature = "drive", feature = "enc"))]
            Self::Layout(source) => Some(source),
            _ => None,
        }
    }
}

/// Data phase of one [`Step`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Device to host.
    In,
    /// Host to device.
    Out,
    /// No data phase.
    None,
}

/// One command of an update session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    /// Short name: `PROBE`, `READY`, `PREPARE`, `STREAM`, `COMMIT` or `STATUS`.
    pub label: &'static str,
    /// The CDB.
    pub cdb: [u8; 12],
    /// Data phase.
    pub direction: Direction,
    /// Bytes transferred (allocation length for [`Direction::In`]).
    pub length: usize,
}

impl DriveClass {
    /// The commands of one update session for a [`layout::IMAGE_SIZE`] image,
    /// as the OEM tool sends them. Readiness polling and read-back
    /// verification follow in the receiver-bound executor.
    pub fn steps(self) -> Vec<Step> {
        let chunk = self.chunk();
        let step = |label, cdb, direction, length| Step {
            label,
            cdb,
            direction,
            length,
        };
        let mut steps = vec![
            step("PROBE", cdb::probe(), Direction::In, cdb::PROBE_LEN),
            step("READY", cdb::test_unit_ready(), Direction::None, 0),
            step("PREPARE", cdb::enter_update(), Direction::Out, 0),
        ];
        steps.extend((0..layout::IMAGE_SIZE).step_by(chunk).map(|offset| {
            step(
                "STREAM",
                cdb::transfer(offset as u32, chunk as u16),
                Direction::Out,
                chunk,
            )
        }));
        steps.extend([
            step("COMMIT", cdb::finish(), Direction::Out, 0),
            step("READY", cdb::test_unit_ready(), Direction::None, 0),
            step(
                "STATUS",
                cdb::request_sense(),
                Direction::In,
                cdb::REQUEST_SENSE_LEN,
            ),
        ]);
        steps
    }

    /// Inclusive byte ranges a read-back must match: every active integrity
    /// entry, clipped to [`DriveClass::verify_floor`]. Per-unit regions are
    /// outside every entry.
    ///
    /// Returns no ranges when the integrity table cannot be parsed (a buffer
    /// too short to hold it) as well as when no active entry reaches above
    /// the floor. Either way nothing can be verified: an empty result is never
    /// evidence of a matching read-back, and the library's own preparation
    /// refuses such an image with [`PreparationError::Integrity`].
    ///
    /// The result is only meaningful for an image that passed
    /// [`cmac::verify`]: this filters entries by [`cmac::CmacEntry::is_active`]
    /// alone and does not itself refuse an unrecognised `enabled` word or an
    /// out-of-bounds or self-covering entry, which are returned as ranges.
    /// Every update and recovery path gates on `cmac::verify` before calling it.
    pub fn verification_ranges(self, image: &[u8]) -> Vec<RangeInclusive<usize>> {
        let Ok(entries) = cmac::parse_table(image) else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|entry| entry.is_active())
            .filter_map(|entry| {
                let start = (entry.start as usize).max(self.verify_floor());
                let end = entry.end as usize;
                (start <= end).then_some(start..=end)
            })
            .collect()
    }
}

/// The drive's installed firmware, bound to its live identity.
#[derive(Clone, Debug)]
pub struct InstalledFirmware {
    identity: Identity,
    family: Option<Family>,
}

impl InstalledFirmware {
    /// Bind `image`, a complete read of the drive's firmware or the image
    /// rebuilt from one, to the drive's live `identity`.
    ///
    /// Fails with [`PreparationError::InstalledMismatch`] unless the image is
    /// [`layout::IMAGE_SIZE`] bytes and holds the identity descriptor (when
    /// the identity has one) and the boot banner (when the identity read one)
    /// the drive reports; at least one of them must be present. All
    /// [`layout::DESCRIPTOR`] bytes must equal the live descriptor: a capture
    /// and the live read come from the same programmed flash, so any
    /// difference, including a short live descriptor that
    /// [`Identity::parse`] zero-pads, is refused.
    pub fn new(identity: Identity, image: &[u8]) -> Result<Self, PreparationError> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(PreparationError::InstalledMismatch);
        }
        let descriptor = identity
            .has_descriptor()
            .then(|| layout::DESCRIPTOR.of(image) == Some(&identity.descriptor_bytes()[..]));
        let banner = (!identity.banner().is_empty())
            .then(|| layout::BANNER.of(image) == Some(&identity.banner_bytes()[..]));
        match (descriptor, banner) {
            (None, None) | (Some(false), _) | (_, Some(false)) => {
                Err(PreparationError::InstalledMismatch)
            }
            _ => Ok(Self {
                family: family(image),
                identity,
            }),
        }
    }

    /// The live identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The installed firmware's hardware family, when it has one.
    pub fn family(&self) -> Option<Family> {
        self.family
    }
}

/// An image validated against the installed firmware (or explicitly without
/// it). Not executable: bind it to the live receiver with
/// `crate::receiver::Receiver::bind_prepared` (features `drive` and `enc`),
/// which returns the executable `receiver::PreparedUpdate`.
#[derive(Clone, Debug)]
pub struct ValidatedUpdate {
    class: DriveClass,
    family: Family,
    image: Vec<u8>,
    transfer: Option<Vec<u8>>,
}

impl ValidatedUpdate {
    /// Every check that needs no installed firmware, in order: size,
    /// integrity, raw drive read, chip against the drive and the image's own
    /// hardware family. Returns that family.
    ///
    /// Run it before capturing a backup; [`ValidatedUpdate::prepare`] repeats
    /// it.
    pub fn check(image: &[u8], drive: &Identity) -> Result<Family, PreparationError> {
        Self::checked(image, drive).map(|(_, family)| family)
    }

    /// [`Self::check`], also returning the drive's dialect.
    fn checked(image: &[u8], drive: &Identity) -> Result<(DriveClass, Family), PreparationError> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(PreparationError::Size(image.len()));
        }
        if !cmac::verify(image) {
            return Err(PreparationError::Integrity);
        }
        if is_drive_read(image) {
            return Err(PreparationError::DriveRead);
        }
        let image_chip = detect_chip(image).map_err(|_| PreparationError::UnknownChip)?;
        // The drive's chip generation is decided by its boot banner and nothing
        // else, exactly as the image's is (see `crate::image::detect_chip`); the
        // `MTEKMT19xx` descriptor tag is a stale vendor label.
        let drive_chip =
            Chip::from_banner(drive.banner_bytes()).ok_or(PreparationError::UnknownDriveChip)?;
        if image_chip.family != drive_chip {
            return Err(PreparationError::ChipMismatch {
                image: image_chip.family,
                drive: drive_chip,
            });
        }
        let target = family(image).ok_or(PreparationError::UnknownTargetFamily)?;
        Ok((DriveClass::of(drive_chip), target))
    }

    /// Prepare `image` for the drive `installed` describes: [`Self::check`]
    /// against its identity, then the family gate. Both families must be known
    /// and equal.
    pub fn prepare(image: &[u8], installed: &InstalledFirmware) -> Result<Self, PreparationError> {
        let (class, target) = Self::checked(image, installed.identity())?;
        let installed_family = installed
            .family()
            .ok_or(PreparationError::UnknownInstalledFamily)?;
        if installed_family != target {
            return Err(PreparationError::FamilyMismatch {
                installed: installed_family,
                target,
            });
        }
        Ok(Self {
            class,
            family: target,
            image: image.to_vec(),
            transfer: None,
        })
    }

    /// Prepare after the host explicitly accepted unavailable installed bytes.
    /// Image integrity, framing, chip and target-family checks still apply.
    /// Installed-family equality is unavailable, not inferred from the target.
    /// This method does not confer backup consent or verify installed firmware.
    pub fn prepare_without_installed(
        image: &[u8],
        live: &Identity,
    ) -> Result<Self, PreparationError> {
        let (class, target) = Self::checked(image, live)?;
        Ok(Self {
            class,
            family: target,
            image: image.to_vec(),
            transfer: None,
        })
    }

    /// Stream the AES-128-ECB transport envelope instead of the plaintext.
    /// Read-back still compares the plaintext the drive stores.
    #[cfg(all(feature = "enc", test))]
    pub(crate) fn encrypted(mut self) -> Self {
        let mut transfer = self.image.clone();
        crate::enc::encrypt(&mut transfer).expect("an update image is whole AES blocks");
        self.transfer = Some(transfer);
        self
    }

    /// The update dialect.
    pub fn class(&self) -> DriveClass {
        self.class
    }

    /// The target hardware family. The captured-installed preparation path
    /// also established equality with the installed family.
    pub fn family(&self) -> Family {
        self.family
    }

    /// The image the drive will store.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// The plaintext image as this receiver-independent preparation knows it.
    /// The wire bytes (for example an AES transport envelope) depend on the
    /// live receiver and are chosen when binding it; with the `drive` and `enc`
    /// features read them from the bound `crate::receiver` plan instead.
    pub fn transfer(&self) -> &[u8] {
        self.transfer.as_deref().unwrap_or(&self.image)
    }

    /// The OEM reference command sequence for this dialect; see
    /// [`DriveClass::steps`]. This is not the receiver-bound session: binding
    /// the live receiver may substitute the PREPARE command and, for recovery,
    /// drop PROBE/READY. With the `drive` and `enc` features read the commands
    /// actually sent from the bound `crate::receiver` prepared update.
    pub fn steps(&self) -> Vec<Step> {
        self.class.steps()
    }

    /// The ranges read-back verification compares; see
    /// [`DriveClass::verification_ranges`].
    pub fn verification_ranges(&self) -> Vec<RangeInclusive<usize>> {
        self.class.verification_ranges(&self.image)
    }
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;

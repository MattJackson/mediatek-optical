//! An update prepared against the drive's installed firmware.
//!
//! [`PreparedUpdate::prepare`] takes the image to write and the
//! [`InstalledFirmware`] (the live [`Identity`] plus a complete read of the
//! drive, or the image rebuilt from one) and refuses, before any command:
//!
//! - an image that is not [`layout::IMAGE_SIZE`] bytes, fails its AES-CMAC
//!   integrity table, or is a raw drive read;
//! - an image for another chip than the drive's;
//! - an image whose hardware family differs from the installed firmware's, or
//!   where either family is unknown.
//!
//! None of these can be overridden. The prepared update carries the
//! [`DriveClass`] dialect chosen from the identity, which owns the command
//! sequence, chunking, readiness timing and read-back verification; with the
//! `drive` feature, [`PreparedUpdate::flash`] runs it over a caller's
//! transport.
//!
//! The caller still owns the drive: opening it, the pre-flash backup, tray and
//! consent policy, model checks and reporting.
//!
//! Requires the `image` feature.

use std::ops::RangeInclusive;

use crate::image::{cmac, detect_chip, family, is_drive_read, Family};
use crate::{cdb, layout, Chip, DriveClass, Identity};

#[cfg(feature = "drive")]
mod flash;
#[cfg(feature = "drive")]
pub use flash::{FlashError, FlashRuntime, FlashTransport, Stage, Status, Verified};

/// Why an update was refused before any device command.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrepareError {
    /// The image is not [`layout::IMAGE_SIZE`] bytes.
    Size(usize),
    /// The image fails its AES-CMAC integrity table.
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

impl core::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Size(n) => write!(
                f,
                "image is {n} bytes; an update image is exactly {} bytes",
                layout::IMAGE_SIZE
            ),
            Self::Integrity => f.write_str("image fails its AES-CMAC integrity check"),
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

impl std::error::Error for PrepareError {}

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
    /// verification follow; see [`PreparedUpdate::flash`].
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
    /// Fails with [`PrepareError::InstalledMismatch`] unless the image is
    /// [`layout::IMAGE_SIZE`] bytes and holds the identity descriptor (when
    /// the identity has one) and the boot banner (when the identity read one)
    /// the drive reports; at least one of them must be present.
    pub fn new(identity: Identity, image: &[u8]) -> Result<Self, PrepareError> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(PrepareError::InstalledMismatch);
        }
        let descriptor = identity
            .has_descriptor()
            .then(|| layout::DESCRIPTOR.of(image) == Some(&identity.descriptor_bytes()[..]));
        let banner = (!identity.banner().is_empty())
            .then(|| layout::BANNER.of(image) == Some(&identity.banner_bytes()[..]));
        match (descriptor, banner) {
            (None, None) | (Some(false), _) | (_, Some(false)) => {
                Err(PrepareError::InstalledMismatch)
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

/// An update validated against the installed firmware, ready to write.
#[derive(Clone, Debug)]
pub struct PreparedUpdate {
    class: DriveClass,
    family: Family,
    image: Vec<u8>,
    transfer: Option<Vec<u8>>,
}

impl PreparedUpdate {
    /// Every check that needs no installed firmware, in order: size,
    /// integrity, raw drive read, chip against the drive and the image's own
    /// hardware family. Returns that family.
    ///
    /// Run it before capturing a backup; [`PreparedUpdate::prepare`] repeats
    /// it.
    pub fn check(image: &[u8], drive: &Identity) -> Result<Family, PrepareError> {
        Self::checked(image, drive).map(|(_, family)| family)
    }

    /// [`Self::check`], also returning the drive's dialect.
    fn checked(image: &[u8], drive: &Identity) -> Result<(DriveClass, Family), PrepareError> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(PrepareError::Size(image.len()));
        }
        if !cmac::verify(image) {
            return Err(PrepareError::Integrity);
        }
        if is_drive_read(image) {
            return Err(PrepareError::DriveRead);
        }
        let image_chip = detect_chip(image).map_err(|_| PrepareError::UnknownChip)?;
        // The drive's chip generation is decided by its boot banner and nothing
        // else, exactly as the image's is (see `crate::image::detect_chip`); the
        // `MTEKMT19xx` descriptor tag is a stale vendor label.
        let drive_chip =
            Chip::from_banner(drive.banner_bytes()).ok_or(PrepareError::UnknownDriveChip)?;
        if image_chip.family != drive_chip {
            return Err(PrepareError::ChipMismatch {
                image: image_chip.family,
                drive: drive_chip,
            });
        }
        let target = family(image).ok_or(PrepareError::UnknownTargetFamily)?;
        Ok((DriveClass::of(drive_chip), target))
    }

    /// Prepare `image` for the drive `installed` describes: [`Self::check`]
    /// against its identity, then the family gate. Both families must be known
    /// and equal.
    pub fn prepare(image: &[u8], installed: &InstalledFirmware) -> Result<Self, PrepareError> {
        let (class, target) = Self::checked(image, installed.identity())?;
        let installed_family = installed
            .family()
            .ok_or(PrepareError::UnknownInstalledFamily)?;
        if installed_family != target {
            return Err(PrepareError::FamilyMismatch {
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

    /// Stream the AES-128-ECB transport envelope instead of the plaintext.
    /// Read-back still compares the plaintext the drive stores.
    #[cfg(feature = "enc")]
    pub fn encrypted(mut self) -> Self {
        let mut transfer = self.image.clone();
        crate::enc::encrypt(&mut transfer).expect("an update image is whole AES blocks");
        self.transfer = Some(transfer);
        self
    }

    /// The update dialect.
    pub fn class(&self) -> DriveClass {
        self.class
    }

    /// The hardware family the image and the installed firmware share.
    pub fn family(&self) -> Family {
        self.family
    }

    /// The image the drive will store.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// The bytes streamed: the image, or its transport envelope.
    pub fn transfer(&self) -> &[u8] {
        self.transfer.as_deref().unwrap_or(&self.image)
    }

    /// The commands of the update session; see [`DriveClass::steps`].
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

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
//! `drive` and `enc` features, `crate::prepare::receiver::Receiver::prepare` binds it
//! to the live receiver before executable transfer preparation.
//!
//! The caller still owns the drive: opening it, the pre-flash backup, tray and
//! consent policy, model checks and reporting.
//!
//! Requires the `image` feature.

use std::ops::RangeInclusive;

use crate::classify::InstalledFirmware;
use crate::envelope::image::{cmac, Family};
use crate::envelope::layout;
use crate::{cdb, DriveClass, Identity, Refusal};

/// Host policy is separate from receiver encoding and entry-command evidence.
/// Only the corresponding public prepared operation selects this mode.
#[cfg_attr(not(all(feature = "drive", feature = "enc")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionMode {
    Flash,
    Recovery,
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
    /// refuses such an image with [`Refusal::Integrity`].
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

/// An image validated against the installed firmware (or explicitly without
/// it). Not executable: bind it to the live receiver with
/// `crate::prepare::receiver::Receiver::bind_prepared` (features `drive` and `enc`),
/// which returns the executable `receiver::PreparedUpdate`.
#[derive(Clone, Debug)]
pub struct ValidatedUpdate {
    class: DriveClass,
    family: Family,
    image: Vec<u8>,
    transfer: Option<Vec<u8>>,
}

impl ValidatedUpdate {
    /// Prepare `image` for the drive `installed` describes: [`crate::classify::check`]
    /// against its identity, then the family gate. Both families must be known
    /// and equal.
    pub fn prepare(image: &[u8], installed: &InstalledFirmware) -> Result<Self, Refusal> {
        let (class, target) = crate::classify::checked(image, installed.identity())?;
        let installed_family = installed.family().ok_or(Refusal::UnknownInstalledFamily)?;
        if installed_family != target {
            return Err(Refusal::FamilyMismatch {
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
    pub fn prepare_without_installed(image: &[u8], live: &Identity) -> Result<Self, Refusal> {
        let (class, target) = crate::classify::checked(image, live)?;
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
        crate::envelope::enc::encrypt(&mut transfer).expect("an update image is whole AES blocks");
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
    /// features read them from the bound `crate::prepare::receiver` plan instead.
    pub fn transfer(&self) -> &[u8] {
        self.transfer.as_deref().unwrap_or(&self.image)
    }

    /// The OEM reference command sequence for this dialect; see
    /// [`DriveClass::steps`]. This is not the receiver-bound session: binding
    /// the live receiver may substitute the PREPARE command and, for recovery,
    /// drop PROBE/READY. With the `drive` and `enc` features read the commands
    /// actually sent from the bound `crate::prepare::receiver` prepared update.
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

//! Rebuild the flashable OEM image from a drive read.
//!
//! A drive read differs from the image that was flashed in two ways (see
//! [`crate::layout`]): the boot page reads back as [`layout::BOOT_MIRROR`],
//! and the [`layout::DRIVE_WRITTEN`] regions hold this unit's runtime data.
//! [`rebuild`] restores both from a [`Catalog`] of factory contents and reports
//! where every substitution came from in a [`Provenance`]:
//!
//! - **Exact** — the read's [`content_key`] matches a cataloged OEM build. The
//!   result is byte-identical to that vendor image.
//! - **Chip default** — an unknown build (a revision the catalog lacks, or a
//!   modified image). Factory contents come from the catalog's default for the
//!   chip generation, so the result carries no per-unit data, but it is a
//!   reconstruction, not a known vendor file.
//!
//! The catalog is data, built from OEM images with [`Factory::from_image`] and
//! [`content_key`]; this crate ships none.
//!
//! Requires the `oem` feature.

use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use crate::image::{detect_chip, ChipError};
use crate::{layout, Chip};

/// A SHA-256 digest.
pub type Digest = [u8; 32];

/// Bytes of an image that identify its OEM build, excluding everything a drive
/// read changes: the boot page and the drive-written regions.
const MASKED: [layout::Range; 5] = [
    layout::BOOT_PAGE,
    layout::UHD_REVOCATION,
    layout::BD_REVOCATION,
    layout::SETTINGS,
    layout::CALIBRATION,
];

/// The build identity of a complete image: SHA-256 over every byte outside the
/// boot page and [`layout::DRIVE_WRITTEN`]. A drive read and the OEM image it
/// was flashed from have the same key. `None` unless `image` is exactly
/// [`layout::IMAGE_SIZE`] bytes.
pub fn content_key(image: &[u8]) -> Option<Digest> {
    if image.len() != layout::IMAGE_SIZE {
        return None;
    }
    let mut masked: Vec<layout::Range> = MASKED.to_vec();
    masked.sort_by_key(|r| r.start);
    let mut hasher = Sha256::new();
    let mut at = 0;
    for range in masked {
        hasher.update(&image[at..range.start]);
        at = range.end();
    }
    hasher.update(&image[at..]);
    Some(hasher.finalize().into())
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

/// The stored boot page and drive-written regions of one OEM build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Factory {
    boot_page: Arc<[u8]>,
    regions: [Arc<[u8]>; 4],
}

impl Factory {
    /// Assemble factory contents. `boot_page` must be [`layout::BOOT_PAGE`]
    /// long and each region as long as its [`layout::DRIVE_WRITTEN`] entry.
    pub fn new(boot_page: Arc<[u8]>, regions: [Arc<[u8]>; 4]) -> Result<Self, RebuildError> {
        if boot_page.len() != layout::BOOT_PAGE.len {
            return Err(RebuildError::Factory(layout::BOOT_PAGE.name));
        }
        for (range, bytes) in layout::DRIVE_WRITTEN.iter().zip(&regions) {
            if bytes.len() != range.len {
                return Err(RebuildError::Factory(range.name));
            }
        }
        Ok(Self { boot_page, regions })
    }

    /// Take the factory contents from an OEM update image. Fails on a wrong
    /// size or on a drive read, whose boot page is not in stored form.
    pub fn from_image(image: &[u8]) -> Result<Self, RebuildError> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(RebuildError::Size(image.len()));
        }
        if crate::image::is_drive_read(image) {
            return Err(RebuildError::Factory(layout::BOOT_PAGE.name));
        }
        let take =
            |range: layout::Range| -> Arc<[u8]> { Arc::from(&image[range.start..range.end()]) };
        Self::new(take(layout::BOOT_PAGE), layout::DRIVE_WRITTEN.map(take))
    }

    /// The boot page as flash stores it.
    pub fn boot_page(&self) -> &[u8] {
        &self.boot_page
    }

    /// The factory contents of each [`layout::DRIVE_WRITTEN`] region, in order.
    pub fn regions(&self) -> &[Arc<[u8]>; 4] {
        &self.regions
    }
}

/// A cataloged OEM build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Build {
    /// Product name, e.g. `BD-RE BU40N`.
    pub model: String,
    /// Firmware revision, e.g. `1.00`.
    pub revision: String,
    /// Its factory contents.
    pub factory: Factory,
}

/// Known OEM builds by [`content_key`], plus a fallback per chip generation.
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    exact: HashMap<Digest, Build>,
    defaults: Vec<(Chip, Factory)>,
}

impl Catalog {
    /// An empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the build whose [`content_key`] is `key`.
    pub fn insert(&mut self, key: Digest, build: Build) {
        self.exact.insert(key, build);
    }

    /// Set the factory contents used for an unknown build of `chip`.
    pub fn set_default(&mut self, chip: Chip, factory: Factory) {
        self.defaults.retain(|(c, _)| *c != chip);
        self.defaults.push((chip, factory));
    }

    /// The build with content key `key`.
    pub fn build(&self, key: &Digest) -> Option<&Build> {
        self.exact.get(key)
    }

    /// The fallback factory contents for `chip`.
    pub fn default_for(&self, chip: Chip) -> Option<&Factory> {
        self.defaults
            .iter()
            .find(|(c, _)| *c == chip)
            .map(|(_, f)| f)
    }

    /// `true` when `page` is the stored boot page of a cataloged build or chip
    /// default: a boot page whose flashed form is known.
    pub fn knows_boot_page(&self, page: &[u8]) -> bool {
        self.defaults.iter().any(|(_, f)| f.boot_page() == page)
            || self.exact.values().any(|b| b.factory.boot_page() == page)
    }

    /// Number of cataloged builds.
    pub fn len(&self) -> usize {
        self.exact.len()
    }

    /// `true` with no cataloged builds.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }
}

/// Where a rebuild's factory contents came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A cataloged OEM build; the image is byte-identical to it.
    Exact {
        /// Product name of the build.
        model: String,
        /// Firmware revision of the build.
        revision: String,
    },
    /// No cataloged build matched; the chip generation's defaults were used.
    ChipDefault,
}

/// What happened to the boot page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootPage {
    /// The input already held the stored boot page.
    Stored,
    /// The input was a drive read; the stored boot page was restored.
    Restored,
}

/// How a rebuilt image was produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// The chip generation the image names.
    pub chip: Chip,
    /// Where the factory contents came from.
    pub source: Source,
    /// What happened to the boot page.
    pub boot_page: BootPage,
    /// Drive-written regions reset to factory contents: `(name, bytes changed)`.
    pub regions_reset: Vec<(&'static str, usize)>,
}

impl Provenance {
    /// `true` when the image is byte-identical to a cataloged OEM build.
    pub fn is_exact(&self) -> bool {
        matches!(self.source, Source::Exact { .. })
    }
}

/// A rebuilt OEM image and how it was produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rebuild {
    /// The flashable 2 MiB image.
    pub image: Vec<u8>,
    /// How it was produced.
    pub provenance: Provenance,
}

/// Why no flashable image could be rebuilt.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RebuildError {
    /// The input is not exactly [`layout::IMAGE_SIZE`] bytes.
    Size(usize),
    /// The image names no supported chip generation.
    Chip(ChipError),
    /// The catalog has no build match and no default for this chip.
    NoFactory(Chip),
    /// The boot page is neither the factory's stored page nor the boot
    /// mirror of a drive read, so its stored form is unknown.
    UnknownBootPage(Digest),
    /// Factory contents of the named range have the wrong length or form.
    Factory(&'static str),
}

impl core::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Size(n) => write!(
                f,
                "image is {n} bytes; an OEM image is exactly {} bytes",
                layout::IMAGE_SIZE
            ),
            Self::Chip(e) => write!(f, "{e}"),
            Self::NoFactory(chip) => write!(f, "no factory contents are known for {chip}"),
            Self::UnknownBootPage(sha) => {
                f.write_str(
                    "boot page is neither a stored page nor a drive read's mirror (sha256 ",
                )?;
                sha.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
                f.write_str(")")
            }
            Self::Factory(name) => write!(f, "factory {name} has the wrong length or form"),
        }
    }
}

impl std::error::Error for RebuildError {}

/// Rebuild the flashable OEM image from `read`, a complete drive read (or an
/// image already in stored form).
///
/// A cataloged build is restored byte-exact. An unknown build gets its chip's
/// default factory contents, except that an erased drive-written region stays
/// erased (builds without UHD support never write their UHD list). The result
/// is never produced with a boot page of unknown stored form.
pub fn rebuild(read: &[u8], catalog: &Catalog) -> Result<Rebuild, RebuildError> {
    let key = content_key(read).ok_or(RebuildError::Size(read.len()))?;
    let chip = detect_chip(read).map_err(RebuildError::Chip)?.family;
    let (factory, source, exact) = match catalog.build(&key) {
        Some(build) => (
            &build.factory,
            Source::Exact {
                model: build.model.clone(),
                revision: build.revision.clone(),
            },
            true,
        ),
        None => (
            catalog
                .default_for(chip)
                .ok_or(RebuildError::NoFactory(chip))?,
            Source::ChipDefault,
            false,
        ),
    };

    let mut image = read.to_vec();
    let boot = &read[..layout::BOOT_PAGE.len];
    let boot_page = if boot == factory.boot_page() {
        BootPage::Stored
    } else if crate::image::is_drive_read(read) {
        image[..layout::BOOT_PAGE.len].copy_from_slice(factory.boot_page());
        BootPage::Restored
    } else {
        return Err(RebuildError::UnknownBootPage(sha256(boot)));
    };

    let mut regions_reset = Vec::new();
    for (range, contents) in layout::DRIVE_WRITTEN.iter().zip(factory.regions()) {
        let current = &read[range.start..range.end()];
        if !exact && layout::is_erased(current) {
            continue;
        }
        let changed = current
            .iter()
            .zip(contents.iter())
            .filter(|(a, b)| a != b)
            .count();
        if changed > 0 {
            image[range.start..range.end()].copy_from_slice(contents);
            regions_reset.push((range.name, changed));
        }
    }

    Ok(Rebuild {
        image,
        provenance: Provenance {
            chip,
            source,
            boot_page,
            regions_reset,
        },
    })
}

#[cfg(test)]
#[path = "oem_tests.rs"]
mod tests;

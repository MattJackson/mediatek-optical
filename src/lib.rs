//! MediaTek MT1959 / MT1939 optical drive (BD/DVD) protocol: command encoding,
//! identity decoding, firmware image analysis and OEM image reconstruction.
//!
//! The crate root is `no_std`, allocation-free and dependency-free:
//!
//! - [`cdb`] — the command descriptor blocks, as byte constructors.
//! - [`Identity`] — the decoded INQUIRY, boot banner and identity descriptor.
//! - [`Chip`] — which controller generation a drive or image belongs to.
//! - [`DriveClass`] — the update dialect a drive speaks ([`Identity::class`]).
//! - [`layout`] — the fixed 2 MiB image geometry and the drive-written regions.
//! - [`sense`] — sense-data parsing and classification of flash faults.
//!
//! Optional features add:
//!
//! - `drive` — `drive`: the command sequences (identify, memory read, flash
//!   session) over a caller-supplied `drive::Transport`.
//! - `image` — `image`: chip detection from image bytes and the AES-CMAC
//!   integrity table (`image::cmac`). Uses `std`.
//! - `enc` — `enc`: the AES-128-ECB transport envelope.
//! - `oem` — `oem`: rebuild the flashable OEM image from a drive read, with
//!   the provenance of every substituted byte. Implies `image`.
//! - `image` also enables `update`: an update prepared against the installed
//!   firmware, refused across chips and hardware families. With `drive`,
//!   the receiver-bound `receiver::PreparedUpdate::flash` runs it.
//! - `std` — links the standard library (implied by `image`).
//!
//! ## Drive memory
//!
//! READ BUFFER mode 6 exposes the 2 MiB flash at file offsets, with one
//! exception: the boot page `0x0..0x400` reads back as the image's own page at
//! [`layout::BOOT_MIRROR`] instead of its stored form. The drive also rewrites
//! the regions in [`layout::DRIVE_WRITTEN`] at runtime (revocation lists,
//! settings, calibration), so a read is never byte-identical to the image that
//! was flashed. `oem::rebuild` undoes both.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(all(test, not(feature = "std")))]
extern crate std;

mod error_codes;
pub use error_codes::CodedError;

pub mod cdb;
#[cfg(feature = "drive")]
pub mod drive;
#[cfg(feature = "enc")]
pub mod enc;
#[cfg(all(feature = "image", feature = "enc"))]
pub mod envelope;
#[cfg(feature = "image")]
pub mod image;
pub mod layout;
#[cfg(feature = "oem")]
pub mod oem;
#[cfg(feature = "drive")]
pub mod receiver;
#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
pub mod recovery;
#[cfg(feature = "image")]
pub mod update;

/// Length of a standard INQUIRY response header, in bytes.
pub const INQUIRY_LEN: usize = 36;

/// A MediaTek optical controller generation.
///
/// Deliberately exhaustive: a new generation is a breaking change, so every
/// caller that dispatches on the chip must decide how to handle it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Chip {
    /// MediaTek MT1959.
    Mt1959,
    /// MediaTek MT1939.
    Mt1939,
}

impl Chip {
    /// Short label, `"MT1959"` or `"MT1939"`.
    pub const fn label(self) -> &'static str {
        match self {
            Chip::Mt1959 => "MT1959",
            Chip::Mt1939 => "MT1939",
        }
    }

    /// Map the two trailing digits of an `MTEKMT19xx` or `MT19xx` tag.
    pub const fn from_digits(d0: u8, d1: u8) -> Option<Self> {
        match (d0, d1) {
            (b'5', b'9') => Some(Chip::Mt1959),
            (b'3', b'9') => Some(Chip::Mt1939),
            _ => None,
        }
    }

    /// The chip named by the first `MTEKMT19xx` identity tag in `bytes`.
    ///
    /// This is a label parser, not operational chip detection. OEM identity
    /// tags can be stale; [`Identity::chip`] and image analysis use the boot
    /// banner instead. Never use this label to override their result.
    pub fn from_tag(bytes: &[u8]) -> Option<Self> {
        const PREFIX: &[u8] = b"MTEKMT19";
        bytes
            .windows(PREFIX.len() + 2)
            .filter(|w| w.starts_with(PREFIX))
            .find_map(|w| Self::from_digits(w[PREFIX.len()], w[PREFIX.len() + 1]))
    }

    /// The chip named by a boot banner such as `MT1939 Boot JB7`. This is the
    /// source used by live identity and image analysis, even when a descriptor
    /// carries a conflicting [`Chip::from_tag`] label.
    pub fn from_banner(banner: &[u8]) -> Option<Self> {
        banner
            .windows(6)
            .filter(|w| w.starts_with(b"MT19"))
            .find_map(|w| Self::from_digits(w[4], w[5]))
    }
}

impl core::fmt::Display for Chip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

/// [`Chip::label`] did not name a chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownChip;

impl core::fmt::Display for UnknownChip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not an MT1959 or MT1939 label")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownChip {}

impl core::str::FromStr for Chip {
    type Err = UnknownChip;

    /// Parse a [`Chip::label`], e.g. `MT1939`.
    fn from_str(label: &str) -> Result<Self, Self::Err> {
        match label {
            "MT1959" => Ok(Chip::Mt1959),
            "MT1939" => Ok(Chip::Mt1939),
            _ => Err(UnknownChip),
        }
    }
}

/// The update dialect a drive speaks, chosen by [`Identity::class`].
///
/// The dialect owns the update session: its command sequence, chunking,
/// readiness timing after the burn and which bytes read-back verification may
/// compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DriveClass {
    /// MT1959 and MT1939: the OEM session of 12-byte CDBs. PROBE, TEST UNIT
    /// READY and PREPARE, the image in [`cdb::CHUNK`] STREAM writes, COMMIT,
    /// then TEST UNIT READY and REQUEST SENSE. The drive programs when the
    /// last chunk lands.
    Mt19,
}

impl DriveClass {
    /// Whether a host should offer automatic installed-firmware acquisition.
    ///
    /// Stock MT19 firmware does not provide a reliable complete firmware read.
    /// Hosts should request a Current firmware file instead. Metadata and
    /// restricted memory reads remain available; this does not forbid them or
    /// a modified firmware's separate dump command.
    pub const fn can_read(self) -> bool {
        match self {
            Self::Mt19 => false,
        }
    }

    /// The dialect of a drive with `chip`.
    pub const fn of(chip: Chip) -> Self {
        match chip {
            Chip::Mt1959 | Chip::Mt1939 => DriveClass::Mt19,
        }
    }

    /// Bytes per STREAM write.
    pub const fn chunk(self) -> usize {
        cdb::CHUNK
    }

    /// How long programming may keep the drive from answering TEST UNIT READY
    /// after COMMIT: 120 s.
    ///
    /// The OEM updaters wait for the drive without a total bound and give each
    /// command a 100 s timeout, so a drive that answers within one OEM command
    /// window must not be declared failed. 120 s covers that window plus 20 s
    /// (40 polls) of margin. A shorter bound fails a drive that is still
    /// programming and invites a power cycle mid-burn; a longer one only costs
    /// time on a drive that never comes back.
    pub const fn ready_timeout(self) -> core::time::Duration {
        core::time::Duration::from_secs(120)
    }

    /// Delay between TEST UNIT READY polls while the drive programs.
    pub const fn poll_interval(self) -> core::time::Duration {
        core::time::Duration::from_millis(500)
    }

    /// Read-back verification compares no byte below this offset: the drive
    /// serves its boot area remapped ([`layout::BOOT_AREA`]).
    pub const fn verify_floor(self) -> usize {
        layout::BOOT_AREA.end()
    }
}

/// Trim trailing ASCII spaces and NULs and decode as UTF-8; `""` if invalid.
fn field(raw: &[u8]) -> &str {
    let start = raw.iter().position(|&b| b != b' ').unwrap_or(raw.len());
    let raw = &raw[start..];
    let end = raw
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |i| i + 1);
    core::str::from_utf8(&raw[..end]).unwrap_or("")
}

/// A drive's identity: the standard INQUIRY response, the boot banner at
/// [`layout::BANNER`] and the identity descriptor at [`layout::DESCRIPTOR`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    inquiry: [u8; INQUIRY_LEN],
    banner: [u8; layout::BANNER.len],
    descriptor: [u8; layout::DESCRIPTOR.len],
}

impl Identity {
    /// Decode an INQUIRY response (at least [`INQUIRY_LEN`] bytes), a boot
    /// banner and an identity descriptor. Short banner and descriptor reads
    /// are zero-padded. Returns `None` if the INQUIRY is short.
    pub fn parse(inquiry: &[u8], banner: &[u8], descriptor: &[u8]) -> Option<Self> {
        if inquiry.len() < INQUIRY_LEN {
            return None;
        }
        let mut id = Self {
            inquiry: [0; INQUIRY_LEN],
            banner: [0; layout::BANNER.len],
            descriptor: [0; layout::DESCRIPTOR.len],
        };
        id.inquiry.copy_from_slice(&inquiry[..INQUIRY_LEN]);
        let n = banner.len().min(id.banner.len());
        id.banner[..n].copy_from_slice(&banner[..n]);
        let n = descriptor.len().min(id.descriptor.len());
        id.descriptor[..n].copy_from_slice(&descriptor[..n]);
        Some(id)
    }

    /// Peripheral device type; `0x05` for an optical drive.
    pub fn device_type(&self) -> u8 {
        self.inquiry[0] & 0x1f
    }
    /// Vendor identification, e.g. `HL-DT-ST`.
    pub fn vendor(&self) -> &str {
        field(&self.inquiry[8..16])
    }
    /// Product identification, e.g. `BD-RE BU40N`.
    pub fn product(&self) -> &str {
        field(&self.inquiry[16..32])
    }
    /// Firmware revision, e.g. `1.00`.
    pub fn revision(&self) -> &str {
        field(&self.inquiry[32..36])
    }
    /// The boot banner, e.g. `MT1959 Boot BU5`, up to its first NUL or
    /// non-printable byte.
    pub fn banner(&self) -> &str {
        let end = self
            .banner
            .iter()
            .position(|&b| !(0x20..0x7f).contains(&b))
            .unwrap_or(self.banner.len());
        field(&self.banner[..end])
    }
    /// `true` when the descriptor carries an `MTEKMT19xx` identity tag.
    pub fn has_descriptor(&self) -> bool {
        Chip::from_tag(&self.descriptor).is_some()
    }
    /// Model from the identity descriptor; `""` without a descriptor.
    pub fn descriptor_model(&self) -> &str {
        if self.has_descriptor() {
            field(&self.descriptor[0x08..0x18])
        } else {
            ""
        }
    }
    /// Vendor-specific SKU code from the identity descriptor, e.g. `N003600`;
    /// `""` without a descriptor.
    pub fn sku(&self) -> &str {
        if self.has_descriptor() {
            field(&self.descriptor[0x1C..0x24])
        } else {
            ""
        }
    }
    /// The controller generation, decided by the drive's boot banner
    /// ([`Chip::from_banner`]) and nothing else. The `MTEKMT19xx` identity tag
    /// is a stale vendor label and is never consulted. `None` for a drive whose
    /// banner names no supported generation.
    pub fn chip(&self) -> Option<Chip> {
        Chip::from_banner(&self.banner)
    }
    /// The update dialect this drive speaks: [`DriveClass::Mt19`] for a drive
    /// that names an MT1959 or MT1939 chip, else `None`.
    pub fn class(&self) -> Option<DriveClass> {
        self.chip().map(DriveClass::of)
    }
    /// `true` when the banner carries the MT19-family `MT19` signature.
    pub fn is_mt19(&self) -> bool {
        self.banner.windows(4).any(|w| w == b"MT19")
    }
    /// The raw INQUIRY response.
    pub fn inquiry_bytes(&self) -> &[u8; INQUIRY_LEN] {
        &self.inquiry
    }
    /// The raw boot banner.
    pub fn banner_bytes(&self) -> &[u8; layout::BANNER.len] {
        &self.banner
    }
    /// The raw identity descriptor.
    pub fn descriptor_bytes(&self) -> &[u8; layout::DESCRIPTOR.len] {
        &self.descriptor
    }
}

/// Sense-data parsing and classification.
pub mod sense {
    /// Parsed sense: `(key, asc, ascq)`.
    pub type Triplet = (u8, u8, u8);

    /// Sense key `NOT READY`.
    pub const NOT_READY: u8 = 0x02;
    /// Sense key `MEDIUM ERROR`.
    pub const MEDIUM_ERROR: u8 = 0x03;
    /// Sense key `HARDWARE ERROR`.
    pub const HARDWARE_ERROR: u8 = 0x04;
    /// Sense key `ILLEGAL REQUEST`.
    pub const ILLEGAL_REQUEST: u8 = 0x05;
    /// Sense key `ABORTED COMMAND`.
    pub const ABORTED_COMMAND: u8 = 0x0B;

    /// Parse fixed-format (`0x70`/`0x71`) or descriptor-format (`0x72`/`0x73`)
    /// sense data into `(key, asc, ascq)`. `None` when short or unrecognized.
    pub fn parse(data: &[u8]) -> Option<Triplet> {
        match *data.first()? & 0x7f {
            0x70 | 0x71 if data.len() >= 14 => Some((data[2] & 0x0f, data[12], data[13])),
            0x72 | 0x73 if data.len() >= 4 => Some((data[1] & 0x0f, data[2], data[3])),
            _ => None,
        }
    }

    /// `true` for the keys that prove a programming failure after a flash:
    /// MEDIUM ERROR, HARDWARE ERROR and ABORTED COMMAND. Every other key is a
    /// transient or unrelated condition; read-back verification decides.
    pub const fn is_flash_fault(key: u8) -> bool {
        matches!(key, MEDIUM_ERROR | HARDWARE_ERROR | ABORTED_COMMAND)
    }

    /// `true` for `02/3A/xx`, the benign "medium not present" of an empty tray.
    pub const fn is_no_medium(key: u8, asc: u8) -> bool {
        key == NOT_READY && asc == 0x3A
    }
}

#[cfg(all(test, feature = "image"))]
mod fixtures;

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
#[doc = include_str!("../README.md")]
mod readme_examples {}

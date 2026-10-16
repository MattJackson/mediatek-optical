//! The hardware family of an MT19xx image.
//!
//! Every MT1959 and MT1939 build carries a hardware configuration record in its
//! code area, right after the MMC feature template the firmware answers GET
//! CONFIGURATION from:
//!
//! ```text
//! [feature template: [code16 BE][version][length][data]..., Profile List first, then Core]
//! [55 AA]["UNIQUE" + 10 digits]["MTEKMT19xx"][6 spaces][00 00][platform, 6 bytes]...
//! ```
//!
//! The family ([`FAMILY_SCHEME`]) combines what the board is built around: the
//! chip, the record's platform code (`JB7`, `JB8`, `BU3`, ...), the bootloader
//! named by the boot banner, the Core feature's physical interface, the
//! current profile of feature `0x0003` and whether any BD writing profile is
//! enabled. Images of one model built for different board lines have different
//! families; an update is only compatible within a family.
//!
//! The family reads only the boot banner, the identity descriptor and the code
//! area `0x1000..0x1D8000`, none of which a drive rewrites or a drive read
//! remaps, so a drive read and the image it was flashed from have the same
//! family.

use crate::{layout, Chip};

/// Identifies the definition [`family`] implements. Recorded alongside a
/// family wherever one is persisted, so a future definition cannot be confused
/// with this one.
pub const FAMILY_SCHEME: &str = "mediatek.hardware.v1";

/// Where the hardware record is searched for: the code area, between the
/// remapped boot area and the first drive-written region.
const CODE: core::ops::Range<usize> = layout::BOOT_AREA.len..layout::UHD_REVOCATION.start;
/// How far before the record the feature template may start.
const TEMPLATE_REACH: usize = 0x800;
/// The record's marker.
const MARKER: [u8; 2] = [0x55, 0xAA];
/// Record bytes: marker, `UNIQUE`, ten digits, `MTEKMT19`, two digits.
const RECORD_LEN: usize = 2 + 6 + 10 + 8 + 2;
/// Offset of the chip tag from the start of `UNIQUE`.
const RECORD_TAG: usize = 0x10;
/// Offset of the platform code from the start of `UNIQUE`.
const RECORD_PLATFORM: usize = 0x22;
/// Length of a platform code.
const PLATFORM_LEN: usize = 6;
/// Complete record prefix consumed when deriving immutable hardware identity.
const RECORD_USED_LEN: usize = MARKER.len() + RECORD_PLATFORM + PLATFORM_LEN;
/// Offset of the platform code within the identity descriptor.
const DESCRIPTOR_PLATFORM: usize = 0x46;
/// Profile List, Core and the feature whose current profile is keyed.
const PROFILE_LIST: u16 = 0x0000;
const CORE: u16 = 0x0001;
const MEDIUM_FEATURE: u16 = 0x0003;
/// BD-R SRM, BD-R RRM and BD-RE.
const BD_WRITE_PROFILES: [u8; 3] = [0x41, 0x42, 0x43];
/// A boot banner names its bootloader with at most this many characters.
const LOADER_MAX: usize = 8;

/// A hardware family: equal families identify boards that accept each other's
/// firmware. Derived from the image's hardware configuration record by
/// [`family`] under [`FAMILY_SCHEME`].
///
/// The value is an opaque hash; only equality and the hex [`Display`] form
/// are meaningful.
///
/// [`Display`]: core::fmt::Display
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Family(u64);

impl core::fmt::Display for Family {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl core::fmt::Debug for Family {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Family({:x})", self.0)
    }
}

/// The hardware an image is built for, as its configuration record describes
/// it. [`Hardware::family`] hashes these fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Hardware {
    /// The controller generation.
    pub chip: Chip,
    /// The record's platform code, e.g. `JB7`.
    pub platform: String,
    /// The bootloader named by the boot banner, e.g. `Code` or `JB8`.
    pub loader: String,
    /// The first four bytes of the Core feature: its physical interface.
    pub interface: [u8; 4],
    /// The first byte of feature `0x0003`.
    pub medium: u8,
    /// Whether the Profile List enables a BD writing profile.
    pub bd_write: bool,
}

impl Hardware {
    /// The canonical key [`Hardware::family`] hashes: `name=value` fields
    /// separated by `0x1F`.
    pub fn key(&self) -> String {
        let interface: String = self.interface.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "chip={}\x1fplatform={}\x1floader={}\x1fiface={interface}\x1fmedium={:02x}\x1fbdwrite={}",
            self.chip.label(),
            self.platform,
            self.loader,
            self.medium,
            u8::from(self.bd_write)
        )
    }

    /// The family: FNV-1a 64 of [`Hardware::key`].
    pub fn family(&self) -> Family {
        Family(fnv1a(self.key().as_bytes()))
    }
}

/// FNV-1a, 64 bits.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h: u64, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// The hardware family of a complete image or drive read, or `None` when it
/// cannot be established. See [`hardware`].
pub fn family(image: &[u8]) -> Option<Family> {
    hardware(image).map(|h| h.family())
}

/// The hardware an image is built for, or `None` unless every part is present
/// and consistent:
///
/// - the image is exactly [`layout::IMAGE_SIZE`] bytes;
/// - it names a chip (descriptor tag, else boot banner) and its boot banner
///   reads `MT19xx Boot <loader>`;
/// - the code area holds exactly one hardware record, whose tag names the same
///   chip;
/// - a tagged descriptor carries the record's platform code at `+0x46`;
/// - the platform code is printable;
/// - the feature template ends exactly at the record, starts with the Profile
///   List and Core features, and holds Core and feature `0x0003`.
pub fn hardware(image: &[u8]) -> Option<Hardware> {
    if image.len() != layout::IMAGE_SIZE {
        return None;
    }
    let descriptor = layout::DESCRIPTOR.of(image)?;
    let banner = layout::BANNER.of(image)?;
    // The chip generation is decided by the boot loader banner and nothing else;
    // the `MTEKMT19xx` descriptor tag is a stale vendor label (see
    // `crate::image::detect_chip`). `tagged` is kept only to gate the descriptor's
    // platform-code cross-check below (a tagged descriptor must agree on the
    // platform), never to decide `chip`.
    let tagged = Chip::from_tag(descriptor).is_some();
    let chip = Chip::from_banner(banner)?;
    let loader = loader(banner)?;

    let mut records =
        (CODE.start..=CODE.end - RECORD_USED_LEN).filter(|&at| is_record(&image[at..]));
    let record = records.next()?;
    if records.next().is_some() {
        return None;
    }
    let unique = record + MARKER.len();
    // Structural corruption guard: the record must carry a parseable MT19xx tag.
    // We do NOT require it to equal `chip` — the record tag, like the descriptor
    // tag, is the stale vendor label and legitimately disagrees with the banner
    // on JB8/JBC6/JBP6/BUP1 builds (tag MT1939, banner/code MT1959).
    Chip::from_tag(&image[unique + RECORD_TAG..unique + RECORD_TAG + 10])?;
    let platform = trim(&image[unique + RECORD_PLATFORM..unique + RECORD_PLATFORM + PLATFORM_LEN]);
    if tagged
        && trim(&descriptor[DESCRIPTOR_PLATFORM..DESCRIPTOR_PLATFORM + PLATFORM_LEN]) != platform
    {
        return None;
    }
    if platform.is_empty() || !platform.iter().all(|b| (0x21..0x7F).contains(b)) {
        return None;
    }

    let features = template(image, record)?;
    let first = |code: u16| features.iter().find(|(c, _)| *c == code).map(|(_, d)| *d);
    let profiles = first(PROFILE_LIST)?;
    let core = first(CORE).filter(|d| d.len() >= 4)?;
    let medium = *first(MEDIUM_FEATURE)?.first()?;
    // Profile descriptors are [number BE][current][reserved]; a high byte of
    // 0xFE marks a profile the build disables.
    let bd_write = profiles
        .chunks_exact(4)
        .any(|p| p[0] == 0 && BD_WRITE_PROFILES.contains(&p[1]));

    Some(Hardware {
        chip,
        platform: String::from_utf8(platform.to_vec()).ok()?,
        loader,
        interface: [core[0], core[1], core[2], core[3]],
        medium,
        bd_write,
    })
}

/// `bytes` with trailing spaces and NULs removed.
fn trim(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |i| i + 1);
    &bytes[..end]
}

/// The bootloader a banner names: `MT19` + two digits + ` Boot ` + one to
/// eight printable characters.
fn loader(banner: &[u8]) -> Option<String> {
    let rest = banner.strip_prefix(b"MT19")?;
    if rest.len() < 2 || !rest[..2].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let token = rest[2..].strip_prefix(b" Boot ")?;
    let len = token
        .iter()
        .take(LOADER_MAX)
        .take_while(|b| (0x21..0x7F).contains(*b))
        .count();
    if len == 0 {
        return None;
    }
    String::from_utf8(token[..len].to_vec()).ok()
}

/// Whether `bytes` starts with a hardware record.
fn is_record(bytes: &[u8]) -> bool {
    bytes.len() >= RECORD_LEN
        && bytes.starts_with(&MARKER)
        && bytes[2..8] == *b"UNIQUE"
        && bytes[8..18].iter().all(u8::is_ascii_digit)
        && bytes[18..26] == *b"MTEKMT19"
        && bytes[26..28].iter().all(u8::is_ascii_digit)
}

/// The feature template ending exactly at `end`: the start nearest `end`
/// (within [`TEMPLATE_REACH`], never inside the boot page) whose walk begins
/// with the Profile List and Core features and lands exactly on `end`.
fn template(image: &[u8], end: usize) -> Option<Vec<(u16, &[u8])>> {
    let floor = end.saturating_sub(TEMPLATE_REACH).max(CODE.start - 1);
    (floor + 1..=end.checked_sub(4)?).rev().find_map(|start| {
        let length = image[start + 3];
        if image[start..start + 2] != [0, 0] || length == 0 || length % 4 != 0 {
            return None;
        }
        let mut features = Vec::new();
        let mut at = start;
        while at + 4 <= end {
            let code = u16::from_be_bytes([image[at], image[at + 1]]);
            let length = usize::from(image[at + 3]);
            let data = image.get(at + 4..at + 4 + length)?;
            features.push((code, data));
            at += 4 + length;
        }
        (at == end && features.len() > 1 && features[0].0 == PROFILE_LIST && features[1].0 == CORE)
            .then_some(features)
    })
}

#[cfg(test)]
#[path = "family_tests.rs"]
mod tests;

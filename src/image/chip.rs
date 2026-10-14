//! Chip generation and identity detection from image bytes.
//!
//! The authoritative signal for the chip generation (MT1959 vs MT1939) is the
//! **boot loader banner** at image offset `0x3000` ([`layout::BANNER`], 16
//! bytes), e.g. `"MT1959 Boot JB8 "` or `"MT1939 Boot Code"`. The family is
//! decided by [`Chip::from_banner`] over that banner and by nothing else.
//!
//! Why the banner and not the `MTEKMT19xx` identity string: across a 119-image
//! corpus of clean OEM images the banner agrees with the actual code generation
//! 119/119, whereas the `MTEKMT19xx` descriptor tag is a *stale vendor label*
//! that is wrong for 55 of them — the JB8/JBC6/JBP6/BUP1 builds (LG WH16NS58,
//! WH16NS60, BH16NS40..NS50, …) carry the tag `MTEKMT1939` but ship an MT1959
//! boot loader and MT1959 code. So the tag drives **no logic anywhere**: not the
//! family, not a fallback, not a gate, not the family hash, not an engine
//! choice. It is retained only as an optional display field ([`ChipInfo::identity_tag`])
//! — a curiosity, never a decision.
//!
//! Two other things that *look* like family signals are also NOT used to gate
//! the family:
//!
//! * the `MTEKMT19xx` identity string (see above) — display-only;
//! * the descriptor **marker byte** at `+0x50` takes `0x78/0x58/0x18/0x38`
//!   within a single family (a variant/region/downgrade flag beside the DE byte
//!   at `+0x56`) — display-only, never a gate.
//!
//! Detection refuses cleanly on an image whose boot banner names no supported
//! MT19xx generation ([`ChipError::Undetectable`]); the caller then aborts with
//! a clear message rather than guessing.

use crate::layout;
use crate::Chip;

const BANNER_OFFSET: usize = layout::BANNER.start;
const BANNER_LEN: usize = layout::BANNER.len;
const DESCRIPTOR_OFFSET: usize = layout::DESCRIPTOR.start;
/// Bytes of the descriptor record consumed by parsing.
const DESCRIPTOR_LEN: usize = 0x40;
/// Offset of the descriptor's `MTEKMT19..` family tag within the record.
const DESCRIPTOR_TAG_OFF: usize = 0x34;
/// Offset of the display-only marker byte within the descriptor record.
const DESCRIPTOR_MARKER_OFF: usize = 0x50;

/// Everything the tools could read off the image about its chip identity. The
/// `banner`, `vendor`, `model`, `rev`, `marker_0x50` and `identity_tag` fields
/// are display / corroboration only — the `family` is decided by
/// [`Chip::from_banner`] over the boot banner at [`layout::BANNER`] and nothing
/// else.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChipInfo {
    /// The chip family, decided by the boot banner ([`Chip::from_banner`]).
    pub family: Chip,
    /// The trimmed boot-banner string (e.g. `"MT1959 Boot BU5"`). The authoritative
    /// source of `family`; also shown for display.
    pub banner: String,
    /// Trimmed vendor field from the descriptor (e.g. `"HL-DT-ST"`). May be empty
    /// if the image has no well-formed identity page.
    pub vendor: String,
    /// Trimmed model field from the descriptor (e.g. `"BD-RE BU40N"`).
    pub model: String,
    /// Trimmed revision field from the descriptor (e.g. `"1.00"`).
    pub rev: String,
    /// Trimmed vendor-specific field from the descriptor (e.g. `"N003600"`) — the
    /// region/SKU code MakeMKV/LibreDrive key on. Empty if no identity page.
    pub vendor_specific: String,
    /// The matched `MTEKMT19xx` identity string, if any. A **stale vendor label**:
    /// display / audit only, it NEVER influences `family` (see module docs).
    pub identity_tag: Option<String>,
    /// The display-only marker byte at descriptor `+0x50`, if present. NEVER
    /// gates the family (see module docs).
    pub marker_0x50: Option<u8>,
    /// Whether the image carries a well-formed MTEK identity page at
    /// [`layout::DESCRIPTOR`] (tag `MTEKMT19..` present). Gates identity-page
    /// edits such as the downgrade-enable byte.
    pub descriptor_present: bool,
}

/// Trim NUL padding and surrounding whitespace from a lossily-decoded ASCII
/// field.
fn ascii_trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string()
}

/// Scan `image` for the first `MTEKMT19` + two-ASCII-digit occurrence and return
/// the matched 10-byte string (display / audit only — never used for `family`).
fn first_mtek_tag(image: &[u8]) -> Option<String> {
    const PREFIX: &[u8] = b"MTEKMT19";
    if image.len() < PREFIX.len() + 2 {
        return None;
    }
    let mut i = 0;
    while i + PREFIX.len() + 2 <= image.len() {
        if &image[i..i + PREFIX.len()] == PREFIX {
            let d0 = image[i + PREFIX.len()];
            let d1 = image[i + PREFIX.len() + 1];
            if d0.is_ascii_digit() && d1.is_ascii_digit() {
                return Some(String::from_utf8_lossy(&image[i..i + PREFIX.len() + 2]).into_owned());
            }
        }
        i += 1;
    }
    None
}

/// Why [`detect_chip`] could not name a chip.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChipError {
    /// The boot banner at [`layout::BANNER`] names no supported MT19xx
    /// generation (MT1959 or MT1939). Unpack packed/truncated dumps first.
    Undetectable,
}

impl std::fmt::Display for ChipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undetectable => f.write_str(
                "undetectable — the boot loader banner at 0x3000 names no supported MT19xx \
                 generation (only MT1959 and MT1939 are handled; unpack packed/truncated \
                 dumps first)",
            ),
        }
    }
}

impl std::error::Error for ChipError {}

/// Detect the chip family + model/rev from `image`.
///
/// Family is decided by the boot loader banner at [`layout::BANNER`] via
/// [`Chip::from_banner`], and by nothing else — the `MTEKMT19xx` identity string
/// is a stale vendor label kept only in [`ChipInfo::identity_tag`] for display.
/// Fails with [`ChipError::Undetectable`] only when the banner names no supported
/// generation.
pub fn detect_chip(image: &[u8]) -> Result<ChipInfo, ChipError> {
    // --- Family: the boot loader banner is the single authoritative source. ---
    let banner = read_banner(image);
    let family = banner
        .as_deref()
        .and_then(|b: &str| Chip::from_banner(b.as_bytes()))
        .ok_or(ChipError::Undetectable)?;

    // --- Identity tag (stale vendor label): display / audit only. ---
    let identity_tag = first_mtek_tag(image);

    // --- Descriptor parse (display-only + DE anchor). ---
    let (vendor, model, rev, vendor_specific, marker_0x50, descriptor_present) =
        parse_descriptor(image);

    Ok(ChipInfo {
        family,
        banner: banner.unwrap_or_default(),
        vendor,
        model,
        rev,
        vendor_specific,
        identity_tag,
        marker_0x50,
        descriptor_present,
    })
}

/// Read + trim the boot banner at [`layout::BANNER`], or `None` if the image is
/// too small to contain it.
fn read_banner(image: &[u8]) -> Option<String> {
    if image.len() < BANNER_OFFSET + BANNER_LEN {
        return None;
    }
    let banner_bytes = &image[BANNER_OFFSET..BANNER_OFFSET + BANNER_LEN];
    let nul = banner_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(banner_bytes.len());
    let s = ascii_trim(&banner_bytes[..nul]);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Parse the display-only descriptor fields and detect a well-formed identity
/// page. Returns `(vendor, model, rev, vendor_specific, marker_0x50,
/// descriptor_present)`; all strings empty and `descriptor_present == false` when
/// no identity page exists.
///
/// Descriptor record layout (mirrors the drive's SCSI INQUIRY): vendor@0x00 (8),
/// model@0x08 (16), rev@0x18 (4), `vendor_specific`@0x1C (8) — the region/SKU code
/// MakeMKV/LibreDrive key on (e.g. `N003600`) — then a `UNIQUE<ts>` stamp and the
/// `MTEKMT19xx` tag @0x34.
fn parse_descriptor(image: &[u8]) -> (String, String, String, String, Option<u8>, bool) {
    if image.len() < DESCRIPTOR_OFFSET + DESCRIPTOR_LEN {
        return (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            None,
            false,
        );
    }
    let desc = &image[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN];
    let tag_present = desc[DESCRIPTOR_TAG_OFF..].starts_with(b"MTEKMT19");
    let vendor = ascii_trim(&desc[0x00..0x08]);
    let model = ascii_trim(&desc[0x08..0x18]);
    let rev = ascii_trim(&desc[0x18..0x1C]);
    let vendor_specific = ascii_trim(&desc[0x1C..0x24]);
    // The marker byte lives at descriptor `+0x50`, PAST the 0x40-byte record, so
    // it is read from the image directly (with a bounds check), not the slice.
    let marker = image
        .get(DESCRIPTOR_OFFSET + DESCRIPTOR_MARKER_OFF)
        .copied();
    if tag_present {
        (vendor, model, rev, vendor_specific, marker, true)
    } else {
        // No identity page: still expose the marker byte for audit, but report
        // no descriptor and empty display fields (they'd be garbage).
        (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            marker,
            false,
        )
    }
}

#[cfg(test)]
#[path = "chip_tests.rs"]
mod tests;

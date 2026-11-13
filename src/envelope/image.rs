//! Firmware image analysis: chip detection, the hardware family and the
//! AES-CMAC integrity table.
//!
//! Requires the `image` feature.

mod chip;
pub mod cmac;
mod family;

pub use chip::{detect_chip, ChipError, ChipInfo};
pub use family::{family, hardware, Family, Hardware, FAMILY_SCHEME};

use crate::envelope::layout;

/// The identity a complete image (or a backup of one) reports as the drive
/// running it would: a blank INQUIRY, the image's boot banner at
/// [`layout::BANNER`] and its identity descriptor at [`layout::DESCRIPTOR`].
/// Missing regions read as zeros.
pub fn identity(image: &[u8]) -> crate::Identity {
    crate::Identity::parse(
        &[0; crate::INQUIRY_LEN],
        layout::BANNER.of(image).unwrap_or_default(),
        layout::DESCRIPTOR.of(image).unwrap_or_default(),
    )
    .expect("a full-length INQUIRY")
}

/// `true` when `image` carries a UHD revocation list, i.e. the build supports
/// UHD media. Builds without UHD support leave the region erased.
pub fn is_uhd(image: &[u8]) -> bool {
    layout::UHD_REVOCATION
        .of(image)
        .is_some_and(|region| !layout::is_erased(region))
}

/// `true` when `read` is a drive read rather than a stored image: its boot
/// page equals the page at [`layout::BOOT_MIRROR`]. A stored image never
/// satisfies this, because flash holds the boot page in a different form.
pub fn is_drive_read(read: &[u8]) -> bool {
    // These mirrored pages describe the fixed MT19xx geometry, not arbitrary
    // older optical firmware or a partial fragment with coincidentally equal data.
    if read.len() != layout::IMAGE_SIZE {
        return false;
    }
    match (layout::BOOT_PAGE.of(read), layout::BOOT_MIRROR.of(read)) {
        (Some(boot), Some(mirror)) => boot == mirror,
        _ => false,
    }
}

/// Flash that is never instruction padding, even when erased: the boot area,
/// banner, boot mirror, integrity table, identity descriptor, the
/// drive-written regions, BOOT's stored CMAC and the application update
/// signatures adjacent to the integrity table. Sorted by start.
pub fn reserved_ranges() -> Vec<core::ops::Range<usize>> {
    let mut out: Vec<_> = [
        layout::BOOT_AREA,
        layout::BANNER,
        layout::BOOT_MIRROR,
        layout::CMAC_TABLE,
        layout::DESCRIPTOR,
    ]
    .into_iter()
    .chain(layout::DRIVE_WRITTEN)
    .map(|r| r.start..r.end())
    .collect();
    // BOOT's stored CMAC and the application update signatures adjacent to
    // the integrity table are not instruction padding, including erased bytes.
    out.extend([0xfff0..0x10000, 0x105c0..0x10610]);
    out.sort_by_key(|r| r.start);
    out
}

#[cfg(test)]
#[path = "image_tests.rs"]
mod tests;

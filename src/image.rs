//! Firmware image analysis: chip detection, the hardware family and the
//! AES-CMAC integrity table.
//!
//! Requires the `image` feature.

mod chip;
pub mod cmac;
mod family;

pub use chip::{detect_chip, ChipError, ChipInfo, Confidence};
pub use family::{family, hardware, Family, Hardware, FAMILY_SCHEME};

use crate::layout;

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
    match (layout::BOOT_PAGE.of(read), layout::BOOT_MIRROR.of(read)) {
        (Some(boot), Some(mirror)) => boot == mirror,
        _ => false,
    }
}

#[cfg(test)]
#[path = "image_tests.rs"]
mod tests;

//! The fixed geometry of an MT19xx flash image.
//!
//! Every MT1959 and MT1939 image is a flat 2 MiB SPI image with load address
//! equal to file offset. The ranges below hold across the OEM corpus of both
//! generations (LG, HP and ASUS builds).

/// A named byte range of the flash image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Range {
    /// Short human-readable name.
    pub name: &'static str,
    /// First byte, as a file offset.
    pub start: usize,
    /// Length in bytes.
    pub len: usize,
}

impl Range {
    /// One past the last byte.
    pub const fn end(&self) -> usize {
        self.start + self.len
    }

    /// This range of `image`, or `None` if the image is too short.
    pub fn of<'a>(&self, image: &'a [u8]) -> Option<&'a [u8]> {
        image.get(self.start..self.end())
    }
}

/// Size of a complete firmware image (2 MiB).
pub const IMAGE_SIZE: usize = 0x20_0000;

/// The boot page. Flash stores it in a form that never reads back: READ BUFFER
/// returns the page at [`BOOT_MIRROR`] here instead.
pub const BOOT_PAGE: Range = Range {
    name: "boot page",
    start: 0,
    len: 0x400,
};

/// The page a drive read returns in place of [`BOOT_PAGE`].
pub const BOOT_MIRROR: Range = Range {
    name: "boot mirror",
    start: 0x1_0000,
    len: 0x400,
};

/// The AES-CMAC integrity table (16 entries of 28 bytes).
pub const CMAC_TABLE: Range = Range {
    name: "integrity table",
    start: 0x1_0400,
    len: 16 * 28,
};

/// The ASCII boot banner, e.g. `MT1959 Boot BU5`.
pub const BANNER: Range = Range {
    name: "boot banner",
    start: 0x3000,
    len: 0x20,
};

/// The identity descriptor: vendor, model, revision, SKU and the
/// `MTEKMT19xx` tag at `+0x34`, mirroring the drive's INQUIRY.
pub const DESCRIPTOR: Range = Range {
    name: "identity descriptor",
    start: 0x1E_C000,
    len: 0x100,
};

/// The UHD host revocation list. Erased on builds without UHD support.
pub const UHD_REVOCATION: Range = Range {
    name: "UHD revocation list",
    start: 0x1D_8000,
    len: 0x8000,
};

/// The BD host revocation list.
pub const BD_REVOCATION: Range = Range {
    name: "BD revocation list",
    start: 0x1E_0000,
    len: 0x8000,
};

/// The drive's settings page.
pub const SETTINGS: Range = Range {
    name: "settings",
    start: 0x1E_8000,
    len: 0x4000,
};

/// The per-unit calibration block.
pub const CALIBRATION: Range = Range {
    name: "calibration",
    start: 0x1F_0000,
    len: 0x1_0000,
};

/// Regions the drive rewrites at runtime and an update never overwrites. A
/// drive read differs from the flashed image here and at [`BOOT_PAGE`] only.
pub const DRIVE_WRITTEN: [Range; 4] = [UHD_REVOCATION, BD_REVOCATION, SETTINGS, CALIBRATION];

/// `true` when every byte of `bytes` is erased flash (`0xFF`).
pub fn is_erased(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0xFF)
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod tests;

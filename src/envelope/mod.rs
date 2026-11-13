//! The image codec: the fixed 2 MiB geometry, file loading and framing, the
//! identity an image carries (chip, model, hardware family), the AES-CMAC
//! integrity table (verify and re-sign), the AES-128-ECB transport encoding,
//! and OEM image reconstruction from a drive read.
//!
//! Nothing here reads a drive or decides compatibility; it depends on no other
//! public module.
//!
//! - geometry (`Range` and the fixed regions) is always available;
//! - `encrypt` / `decrypt` need `enc`;
//! - identity and `cmac` need `image`;
//! - `Envelope::load` needs `image` + `enc`;
//! - `rebuild` needs `oem`.

pub(crate) mod layout;
pub use layout::{
    is_erased, Range, BANNER, BD_REVOCATION, BOOT_AREA, BOOT_MIRROR, BOOT_PAGE, CALIBRATION,
    CMAC_TABLE, DESCRIPTOR, DRIVE_WRITTEN, IMAGE_SIZE, SETTINGS, UHD_REVOCATION,
};

#[cfg(feature = "enc")]
pub(crate) mod enc;
#[cfg(feature = "enc")]
pub use enc::{decrypt, encrypt, LengthError};

#[cfg(feature = "image")]
pub(crate) mod image;
#[cfg(feature = "image")]
pub use image::{
    cmac, detect_chip, family, hardware, identity, is_drive_read, is_uhd, reserved_ranges,
    ChipError, ChipInfo, Family, Hardware, FAMILY_SCHEME,
};

#[cfg(feature = "image")]
pub(crate) mod refusal;

#[cfg(all(feature = "image", feature = "enc"))]
mod load;
#[cfg(all(feature = "image", feature = "enc"))]
pub use load::{Envelope, Error, InputEncoding};

#[cfg(feature = "oem")]
pub(crate) mod oem;
#[cfg(feature = "oem")]
pub use oem::{
    content_key, rebuild, BootPage, Build as OemBuild, Catalog, Digest, Factory, Provenance,
    Rebuild, RebuildError, Source,
};

//! Static analysis of the update receiver code an image carries: application
//! and BOOT entry grammars, range selection and programming loops, decoder
//! calls and the mixed-encoding contract. Pure byte analysis, no I/O;
//! [`crate::prepare`] binds plans to what it proves.

#[cfg(all(
    feature = "image",
    feature = "enc",
    any(feature = "drive", feature = "analysis")
))]
pub(crate) mod analysis;
#[cfg(all(
    feature = "image",
    feature = "enc",
    any(feature = "drive", feature = "analysis")
))]
pub(crate) mod decoding;
#[cfg(all(
    feature = "image",
    feature = "enc",
    any(feature = "drive", feature = "analysis")
))]
pub(crate) mod entry;
#[cfg(all(
    feature = "image",
    feature = "enc",
    any(feature = "drive", feature = "analysis")
))]
pub(crate) mod mixed;
#[cfg(all(
    feature = "image",
    feature = "enc",
    any(feature = "drive", feature = "analysis")
))]
pub(crate) mod programming;

/// Whether `bytes` start with `pattern`, where `0x100` matches any byte.
#[cfg_attr(not(feature = "drive"), allow(dead_code))]
pub(crate) fn matches(bytes: &[u8], pattern: &[u16]) -> bool {
    bytes.len() >= pattern.len()
        && bytes
            .iter()
            .zip(pattern)
            .all(|(&b, &p)| p == ANY || p == b as u16)
}

// 0x100 masks a relocation/stack-slot byte. These are positive instruction
// sequences, not whole-build hashes. Matches are halfword aligned.
#[cfg_attr(not(feature = "drive"), allow(dead_code))]
pub(crate) const ANY: u16 = 0x100;
#[cfg_attr(not(feature = "drive"), allow(dead_code))]
pub(crate) const PLAIN_DIRECT: &[u16] = &[
    0x03, 0x21, 0x09, 0x03, 0x61, 0x18, ANY, 0xa8, 0x00, 0x5d, 0x09, 0x78, 0x88, 0x42,
];
#[cfg_attr(not(feature = "drive"), allow(dead_code))]
pub(crate) const PLAIN_APP: &[u16] = &[
    0x03, 0x20, ANY, 0x49, 0x00, 0x03, 0x20, 0x18, 0x09, 0x68, 0x00, 0x02, 0x00, 0x0a, 0x40, 0x18,
    ANY, 0xa9, 0x09, 0x5d, 0x00, 0x78, 0x88, 0x42,
];
#[cfg_attr(not(feature = "drive"), allow(dead_code))]
pub(crate) const PLAIN_BOOT: &[u16] = &[
    0x03, 0x20, 0x00, 0x03, 0x20, 0x18, 0xf9, 0x69, 0x00, 0x02, 0x00, 0x0a, 0x40, 0x18, ANY, 0xa9,
    0x09, 0x5d, 0x00, 0x78, 0x88, 0x42,
];
#[cfg_attr(not(feature = "drive"), allow(dead_code))]
pub(crate) const PLAIN_LOGGED: &[u16] = &[
    0x03, 0x20, 0x00, 0x03, 0x20, 0x18, 0x05, 0x02, 0xf8, 0x69, 0x2d, 0x0a, 0x28, 0x18, 0x02, 0x78,
    ANY, 0x48, 0x21, 0x00, ANY, ANY, ANY, ANY, 0xf8, 0x69, 0x28, 0x18, 0x00, 0x78, 0x31, 0x5d,
    0x88, 0x42,
];
#[cfg_attr(not(feature = "drive"), allow(dead_code))]
pub(crate) const AES: &[u16] = &[
    0xf7, 0xb5, 0x06, 0x00, 0x14, 0x00, ANY, 0x48, 0x11, 0x00, 0x84, 0xb0, ANY, ANY, ANY, ANY,
    0x00, 0x2c, 0x01, 0xd0, 0x20, 0x07, 0x02, 0xd0, 0x00, 0x20, 0x07, 0xb0, 0xf0, 0xbd, 0xa0, 0x08,
    0x01, 0x22, 0x92, 0x06, 0x02, 0x90, 0x10, 0x68, 0x10, 0x21, 0x88, 0x43, 0x10, 0x60,
];

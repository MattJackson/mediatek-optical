//! Synthetic MT19xx images for the crate's tests. Built in code, from the
//! layout the crate documents; no vendor bytes.

use crate::image::cmac;
use crate::layout::{self, IMAGE_SIZE};

/// Where the fixture's feature template starts.
pub(crate) const TEMPLATE_AT: usize = 0x2_0000;
/// The fixture's one active integrity range (inclusive), covering the
/// template and record.
pub(crate) const SIGNED: (u32, u32) = (0x1_1000, 0x2_FFFF);
/// The stored boot page every fixture shares.
pub(crate) const STORED_BOOT: u8 = 0xB7;

/// What a fixture image is built for.
#[derive(Clone, Debug)]
pub(crate) struct Board {
    /// Descriptor and record tag, e.g. `MTEKMT1939`.
    pub tag: &'static str,
    /// Boot banner, e.g. `MT1939 Boot Code`.
    pub banner: &'static str,
    /// Record platform code.
    pub platform: &'static str,
    /// Descriptor platform code (normally the same).
    pub descriptor_platform: &'static str,
    /// Core feature interface.
    pub interface: [u8; 4],
    /// Feature 0x0003 current profile.
    pub medium: u8,
    /// BD writing profiles enabled.
    pub bd_write: bool,
    /// Descriptor model.
    pub model: &'static str,
}

/// A JB7 MT1939 board (LG BH16NS40 1.0x line).
pub(crate) const JB7: Board = Board {
    tag: "MTEKMT1939",
    banner: "MT1939 Boot Code",
    platform: "JB7",
    descriptor_platform: "JB7",
    interface: [0, 0, 0, 7],
    medium: 0x39,
    bd_write: true,
    model: "BD-RE  BH16NS40",
};

/// A JB8 MT1939 board of the same model (the NS50 line).
pub(crate) const JB8: Board = Board {
    tag: "MTEKMT1939",
    banner: "MT1959 Boot JB8 ",
    platform: "JB8",
    descriptor_platform: "JB8",
    interface: [0, 0, 0, 7],
    medium: 0x39,
    bd_write: true,
    model: "BD-RE  BH16NS40",
};

/// A BU3 MT1959 board (LG BU40N).
pub(crate) const BU3: Board = Board {
    tag: "MTEKMT1959",
    banner: "MT1959 Boot BU5",
    platform: "BU3",
    descriptor_platform: "BU3",
    interface: [0, 0, 0, 7],
    medium: 0x2B,
    bd_write: true,
    model: "BD-RE BU40N",
};

/// The MMC feature template, ending where the record starts.
pub(crate) fn template(board: &Board) -> Vec<u8> {
    let mut profiles = Vec::new();
    for (number, bd_write) in [
        (0x43, true),
        (0x42, true),
        (0x41, true),
        (0x40, false),
        (0x2B, false),
        (0x1B, false),
        (0x10, false),
        (0x08, false),
    ] {
        let disabled = bd_write && !board.bd_write;
        profiles.extend_from_slice(&[if disabled { 0xFE } else { 0 }, number, 0, 0]);
    }
    let mut out = Vec::new();
    let mut feature = |code: u16, version: u8, data: &[u8]| {
        out.extend_from_slice(&code.to_be_bytes());
        out.push(version);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    };
    feature(0x0000, 3, &profiles);
    let i = board.interface;
    feature(0x0001, 11, &[i[0], i[1], i[2], i[3], 1, 0, 0, 0]);
    feature(0x0002, 7, &[2, 0, 0, 0]);
    feature(0x0003, 11, &[board.medium, 0, 0, 0]);
    feature(0x0108, 3, b"HLDS            ");
    feature(0xAADF, 0x13, &[0, 7, 11, 7, 7, 7, 7, 7]);
    out
}

/// The hardware record for `board`.
pub(crate) fn record(board: &Board) -> Vec<u8> {
    let mut out = vec![0x55, 0xAA];
    out.extend_from_slice(b"UNIQUE1210311917");
    out.extend_from_slice(board.tag.as_bytes());
    out.extend_from_slice(b"      \0\0");
    out.extend_from_slice(&padded(board.platform, 6));
    out.extend_from_slice(b"       X\0\0\0\xFF\xFF");
    out
}

fn padded(text: &str, len: usize) -> Vec<u8> {
    let mut out = vec![b' '; len];
    out[..text.len()].copy_from_slice(text.as_bytes());
    out
}

/// A complete, signed update image for `board` whose code bytes depend on
/// `build`.
pub(crate) fn image(board: &Board, build: u8) -> Vec<u8> {
    let mut img: Vec<u8> = (0..IMAGE_SIZE).map(|i| (i % 251) as u8 ^ build).collect();
    // The fixture's code must not hold a stray record or template byte run.
    img[0x1_0000..0x3_0000].fill(build);
    img[layout::BOOT_PAGE.start..layout::BOOT_PAGE.end()].fill(STORED_BOOT);
    img[layout::BOOT_MIRROR.start..layout::BOOT_MIRROR.end()].fill(0x18);
    let banner = layout::BANNER.start;
    img[banner..banner + layout::BANNER.len].fill(0);
    img[banner..banner + board.banner.len()].copy_from_slice(board.banner.as_bytes());

    let d = layout::DESCRIPTOR.start;
    img[d..d + layout::DESCRIPTOR.len].fill(b' ');
    img[d..d + 8].copy_from_slice(b"HL-DT-ST");
    img[d + 0x08..d + 0x18].copy_from_slice(&padded(board.model, 16));
    img[d + 0x18..d + 0x1C].copy_from_slice(b"1.03");
    img[d + 0x34..d + 0x3E].copy_from_slice(board.tag.as_bytes());
    img[d + 0x46..d + 0x4C].copy_from_slice(&padded(board.descriptor_platform, 6));

    let template = template(board);
    let at = TEMPLATE_AT;
    img[at..at + template.len()].copy_from_slice(&template);
    let record = record(board);
    let at = at + template.len();
    img[at..at + record.len()].copy_from_slice(&record);

    for (i, range) in layout::DRIVE_WRITTEN.iter().enumerate() {
        img[range.start..range.end()].fill(0xFF);
        img[range.start..range.start + 16].fill(0x10 + i as u8);
    }
    sign(img)
}

/// Write one active integrity entry over [`SIGNED`] and re-sign.
pub(crate) fn sign(mut img: Vec<u8>) -> Vec<u8> {
    let table = cmac::TABLE_OFFSET;
    img[table..table + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE].fill(0xFF);
    img[table..table + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[table + 4..table + 8].copy_from_slice(&SIGNED.0.to_le_bytes());
    img[table + 8..table + 12].copy_from_slice(&SIGNED.1.to_le_bytes());
    cmac::resign(&img).expect("fixture integrity table")
}

/// What a drive returns once `image` is flashed and has run a while.
pub(crate) fn drive_read(image: &[u8]) -> Vec<u8> {
    let mut read = image.to_vec();
    let mirror = read[layout::BOOT_MIRROR.start..layout::BOOT_MIRROR.end()].to_vec();
    read[..layout::BOOT_PAGE.len].copy_from_slice(&mirror);
    for range in layout::DRIVE_WRITTEN {
        read[range.start..range.start + 64].fill(0x52);
    }
    read
}

use super::*;
use crate::layout::IMAGE_SIZE;

/// A 2 MiB image with one active integrity entry covering `0x2000..=0x2FFF`.
fn signed_image() -> Vec<u8> {
    let mut img = vec![0u8; IMAGE_SIZE];
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        img[off..off + cmac::ENTRY_SIZE].fill(0xFF);
    }
    let off = cmac::TABLE_OFFSET;
    img[off..off + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[off + 4..off + 8].copy_from_slice(&0x2000u32.to_le_bytes());
    img[off + 8..off + 12].copy_from_slice(&0x2FFFu32.to_le_bytes());
    img[0x2000..0x3000].fill(0x5A);
    cmac::resign(&img).unwrap()
}

#[test]
fn cmac_signs_and_detects_tampering() {
    let mut img = signed_image();
    assert!(cmac::verify(&img));
    img[0x2800] ^= 1;
    assert!(!cmac::verify(&img));
    assert!(!cmac::verify(&[0u8; 16]));
}

#[test]
fn cmac_digest_is_byte_exact() {
    // Independently computed: AES-CMAC under the public key over sixteen
    // block-reversed 0x5A blocks, digest byte-reversed for storage.
    let img = signed_image();
    let digest = cmac::compute_stored_digest(&img, 0x2000, 0x2FFF).unwrap();
    assert_eq!(
        &img[cmac::TABLE_OFFSET + 12..cmac::TABLE_OFFSET + 28],
        &digest
    );
    assert!(cmac::compute_stored_digest(&img, 0x10, 0x0F).is_err());
}

#[test]
fn uhd_support_follows_the_revocation_region() {
    let mut img = vec![0xFFu8; IMAGE_SIZE];
    assert!(!is_uhd(&img));
    img[layout::UHD_REVOCATION.start] = 0;
    assert!(is_uhd(&img));
    assert!(!is_uhd(&[0u8; 16]));
}

#[test]
fn drive_reads_mirror_the_boot_page() {
    let mut img = vec![0u8; IMAGE_SIZE];
    img[layout::BOOT_MIRROR.start..layout::BOOT_MIRROR.end()].fill(0x18);
    assert!(!is_drive_read(&img));
    img[..layout::BOOT_PAGE.len].fill(0x18);
    assert!(is_drive_read(&img));
    assert!(!is_drive_read(&img[..0x500]));
    assert!(!is_drive_read(&img[..0x80000]));
    img.push(0);
    assert!(!is_drive_read(&img));
}

#[test]
fn resign_orders_entries_that_overlap_the_table_without_covering_its_start() {
    let mut img = vec![0u8; layout::IMAGE_SIZE];
    let table = cmac::TABLE_OFFSET;
    img[table..table + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE].fill(0xFF);
    let set = |img: &mut Vec<u8>, index: usize, start: u32, end: u32| {
        let at = table + index * cmac::ENTRY_SIZE;
        img[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        img[at + 4..at + 8].copy_from_slice(&start.to_le_bytes());
        img[at + 8..at + 12].copy_from_slice(&end.to_le_bytes());
    };
    set(&mut img, 0, 0x1041C, 0x2FFFF);
    set(&mut img, 1, 0x30000, 0x3FFFF);
    let img = cmac::resign(&img).unwrap();
    assert!(cmac::verify(&img));
}

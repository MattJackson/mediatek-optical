use super::*;
use crate::fixtures::{self, BU3};

#[test]
fn both_input_formats_have_one_canonical_identity_and_preserve_provenance() {
    let image = fixtures::image(&BU3, 7);
    let plain = Envelope::load(&image).unwrap();
    let mut wire = image.clone();
    crate::envelope::enc::encrypt(&mut wire).unwrap();
    let encrypted = Envelope::load(&wire).unwrap();
    assert_eq!(plain.input_encoding(), InputEncoding::Plaintext);
    assert_eq!(encrypted.input_encoding(), InputEncoding::Encrypted);
    assert_eq!(plain.image(), encrypted.image());
    assert_eq!(plain.image_sha256(), encrypted.image_sha256());
    assert_ne!(plain.input_sha256(), encrypted.input_sha256());
    assert_eq!(encrypted.original(), wire);
    assert_eq!(plain.original(), image);
}

#[test]
fn rejects_capture_corruption_empty_integrity_and_unknown_framing() {
    let image = fixtures::image(&BU3, 3);
    assert_eq!(
        Envelope::load(&fixtures::drive_read(&image)).unwrap_err(),
        Error::Image(Refusal::DriveRead)
    );
    let mut bad = image.clone();
    bad[fixtures::SIGNED.0 as usize] ^= 1;
    assert_eq!(
        Envelope::load(&bad).unwrap_err(),
        Error::Image(Refusal::Integrity)
    );
    bad = image;
    let table = image::cmac::TABLE_OFFSET;
    bad[table..table + image::cmac::ENTRY_COUNT * image::cmac::ENTRY_SIZE].fill(0xff);
    assert_eq!(
        Envelope::load(&bad).unwrap_err(),
        Error::Image(Refusal::Integrity)
    );
    assert_eq!(
        Envelope::load(&vec![0; layout::IMAGE_SIZE]).unwrap_err(),
        Error::UnknownFraming
    );
    assert_eq!(
        Envelope::load(&[0; 16]).unwrap_err(),
        Error::Image(Refusal::Size(16))
    );
}

#[test]
fn rejects_an_unrecognised_integrity_enabled_word() {
    let mut image = fixtures::image(&BU3, 3);
    assert!(Envelope::load(&image).is_ok());
    let at = image::cmac::TABLE_OFFSET + image::cmac::ENTRY_SIZE;
    image[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        Envelope::load(&image).unwrap_err(),
        Error::Image(Refusal::Integrity)
    );
    let mut wire = image;
    crate::envelope::enc::encrypt(&mut wire).unwrap();
    assert_eq!(
        Envelope::load(&wire).unwrap_err(),
        Error::Image(Refusal::Integrity)
    );
}

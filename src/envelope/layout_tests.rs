use super::*;
use std::vec;

#[test]
fn ranges_fit_the_image_and_do_not_overlap() {
    let mut all = vec![BOOT_PAGE, BOOT_MIRROR, CMAC_TABLE, BANNER, DESCRIPTOR];
    all.extend(DRIVE_WRITTEN);
    all.sort_by_key(|r| r.start);
    for pair in all.windows(2) {
        assert!(
            pair[0].end() <= pair[1].start,
            "{:?} overlaps {:?}",
            pair[0],
            pair[1]
        );
    }
    assert!(all.iter().all(|r| r.end() <= IMAGE_SIZE));
    assert_eq!(CALIBRATION.end(), IMAGE_SIZE);
}

#[test]
fn range_slicing_and_erased() {
    let image = vec![0xFFu8; 0x500];
    assert_eq!(BOOT_PAGE.of(&image).map(<[u8]>::len), Some(0x400));
    assert!(BOOT_MIRROR.of(&image).is_none());
    assert!(is_erased(&image));
    assert!(!is_erased(&[0xFF, 0x00]));
}

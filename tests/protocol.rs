use mediatek_optical::protocol::Evidence;
fn inquiry() -> [u8; 36] {
    let mut b = [0; 36];
    b[0] = 5;
    b
}
fn banner() -> [u8; 32] {
    let mut b = [0; 32];
    b[..15].copy_from_slice(b"MT1959 Boot BU5");
    b
}
#[test]
fn exact_boot_signature_not_brand_or_substring() {
    let mut i = inquiry();
    i[8..16].copy_from_slice(b"PIONEER ");
    assert_eq!(
        Evidence::parse(&i, &banner())
            .unwrap()
            .unwrap()
            .identity()
            .chip(),
        Some(mediatek_optical::Chip::Mt1959)
    );
    for bad in [
        b"badMT1959 Boot ".as_slice(),
        b"MT1959 garbage",
        b"MT1999 Boot X",
    ] {
        let mut b = [0; 32];
        b[..bad.len()].copy_from_slice(bad);
        assert!(Evidence::parse(&i, &b).unwrap().is_none());
    }
}
#[test]
fn short_and_non_optical_are_not_valid_evidence() {
    assert!(Evidence::parse(&inquiry(), &banner()[..15]).is_err());
    assert!(Evidence::parse(&[0; 36], &banner()).unwrap().is_none());
}

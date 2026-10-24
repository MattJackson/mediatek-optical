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
fn real_rom_boot_windows_keep_code_after_the_terminated_label() {
    // Offset 0x3000 of hoard SHA256 6a96f726... (BH14NS40 1.02) and
    // dd27dc39... (BH16NS40 NS50 1.05). The trailing bytes are instructions.
    let windows: [(&[u8; 32], mediatek_optical::Chip); 2] = [
        (
            b"MT1939 Boot Code\0\0\0\xea\x7e\x15\0\xea\x28\0\x8f\xe2\0\x0c\x90\xe8",
            mediatek_optical::Chip::Mt1939,
        ),
        (
            b"MT1959 Boot JB8 \0\0\0\xea\xa9\x15\0\xea\x28\0\x8f\xe2\0\x0c\x90\xe8",
            mediatek_optical::Chip::Mt1959,
        ),
    ];
    for (window, chip) in windows {
        for vendor in [
            b"HL-DT-ST",
            b"ASUS    ",
            b"LITE-ON ",
            b"PLEXTOR ",
            b"OEM     ",
        ] {
            let mut i = inquiry();
            i[8..16].copy_from_slice(vendor);
            let evidence = Evidence::parse(&i, window)
                .unwrap()
                .expect("real boot label must identify its chip");
            assert_eq!(evidence.identity().chip(), Some(chip));
            assert_eq!(evidence.identity().banner_bytes(), window);
        }
    }
}

#[test]
fn arbitrary_code_after_the_label_does_not_weaken_the_signature() {
    for tail in 0..=255 {
        let mut b = [tail; 32];
        b[..17].copy_from_slice(b"MT1959 Boot JBC6\0");
        assert!(Evidence::parse(&inquiry(), &b).unwrap().is_some());
        b[8] = 0xff;
        assert!(Evidence::parse(&inquiry(), &b).unwrap().is_none());
    }
}

#[test]
fn short_and_non_optical_are_not_valid_evidence() {
    assert!(Evidence::parse(&inquiry(), &banner()[..15]).is_err());
    assert!(Evidence::parse(&[0; 36], &banner()).unwrap().is_none());
}

#![no_main]
use libfuzzer_sys::fuzz_target;
use mediatek_optical::{
    enc,
    image::{self, cmac},
    layout,
};
fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * 1024 * 1024 {
        return;
    }
    let _ = image::detect_chip(data);
    let _ = image::family(data);
    // The family, hardware-record and descriptor parsers only run on a whole
    // 2 MiB image, which a bounded `-max_len` never produces. Embed shorter
    // inputs in an erased image: the tail lands on the identity descriptor,
    // the rest at offset 0 (banner, code area).
    if data.len() < layout::IMAGE_SIZE {
        let mut whole = vec![0xFF; layout::IMAGE_SIZE];
        let split = data.len().saturating_sub(layout::DESCRIPTOR.len);
        whole[..split].copy_from_slice(&data[..split]);
        let tail = &data[split..];
        whole[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + tail.len()]
            .copy_from_slice(tail);
        let _ = image::detect_chip(&whole);
        let _ = image::hardware(&whole);
    }
    let _ = cmac::parse_table(data);
    let _ = cmac::verify_detailed(data);
    let _ = cmac::resign(data);
    // ECB accepts whole 16-byte blocks; malformed lengths must not mutate input.
    let mut encoded = data.to_vec();
    if data.len() % 16 == 0 {
        enc::encrypt(&mut encoded).unwrap();
        enc::decrypt(&mut encoded).unwrap();
        assert_eq!(encoded, data);
    } else {
        assert!(enc::encrypt(&mut encoded).is_err());
        assert_eq!(encoded, data);
        assert!(enc::decrypt(&mut encoded).is_err());
        assert_eq!(encoded, data);
    }
    if data.len() >= 8 {
        let start = u32::from_le_bytes(data[..4].try_into().unwrap());
        let end = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let result = cmac::compute_stored_digest(data, start, end);
        if start > end || end as usize >= data.len() {
            assert!(result.is_err());
        }
    }
});

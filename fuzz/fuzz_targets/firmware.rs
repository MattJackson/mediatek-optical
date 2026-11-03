#![no_main]
use libfuzzer_sys::fuzz_target;
use mediatek_optical::{
    enc,
    envelope::Envelope,
    image::{
        self,
        analysis::{
            ClassicCalibration, ClassicConsumer, ClassicDi, ClassicParameter, ClassicPosition,
            ClassicPositionSetup, ClassicReadCompletion, ClassicReadPosition, ImageAnalysis,
            RequestedRateClamp,
        },
        cmac,
    },
    layout, oem,
    receiver::{analysis::ApplicationAnalysis, entry},
};

/// Every read-only instruction-grammar recognizer reachable from an image.
fn analyze(image: &[u8]) {
    let analysis = ImageAnalysis::inspect(image);
    let _ = analysis.identity();
    let _ = analysis.scanner();
    let _ = analysis.commands();
    let _ = analysis.response();
    let _ = analysis.vid();
    let _ = analysis.authentication();
    let _ = analysis.media();
    let _ = analysis.speed_policy();
    let _ = analysis.classic_speed();
    let _ = RequestedRateClamp::detect(image, 0x10);
    let _ = ClassicDi::detect(image);
    if let Ok(state) = analysis.uhd().state_address() {
        let _ = ClassicPosition::detect(image, state);
        let _ = ClassicParameter::detect(image, state);
        let _ = ClassicCalibration::detect(image, state);
        let _ = ClassicReadPosition::detect(image, state);
        let _ = ClassicPositionSetup::detect(image, state);
        let _ = ClassicReadCompletion::inspect(image, state);
        let _ = ClassicConsumer::inspect(image, state);
    }
}

/// Receiver application and boot-entry grammars over a code snapshot at `base`.
fn receiver(bytes: &[u8], base: u32) {
    let _ = ApplicationAnalysis::inspect(bytes, base);
    let _ = entry::application::inspect(bytes, base);
    let _ = entry::inspect_boot_legacy(bytes, base);
    let _ = entry::inspect_boot_dual(bytes, base);
}
fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * 1024 * 1024 {
        return;
    }
    let _ = image::detect_chip(data);
    let _ = image::family(data);
    analyze(data);
    receiver(data, 0);
    if data.len() >= 4 {
        let base = u32::from_le_bytes(data[..4].try_into().unwrap()) & !1;
        receiver(&data[4..], base);
    }
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
        let _ = Envelope::load(&whole);
        let _ = oem::rebuild(&whole, &oem::Catalog::default());
    } else {
        let _ = Envelope::load(data);
        let _ = oem::rebuild(data, &oem::Catalog::default());
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

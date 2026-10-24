//! The new rule, proven against the whole image hoard: for every MediaTek image
//! [`detect_chip`] recognizes, the chip it reports must equal the chip named by
//! the boot loader banner at `0x3000` — never the stale `MTEKMT19xx` identity
//! tag. This is the evidence that the banner is the single source of truth.
//!
//! Needs the hoard, so it does nothing unless `MEDIATEK_OPTICAL_HOARD` points at
//! a hoard directory (the one holding `index/identities.json` and `images/`).
//! Patched and fragment images are skipped, per the index.

use std::path::PathBuf;

use mediatek_optical::image::detect_chip;
use mediatek_optical::{layout, Chip};

use serde::Deserialize;

#[derive(Deserialize)]
struct Index {
    identities: Vec<Identity>,
}

#[derive(Deserialize)]
struct Identity {
    #[serde(default)]
    family: String,
    #[serde(default)]
    images: Vec<Image>,
}

#[derive(Deserialize)]
struct Image {
    path: String,
    #[serde(default)]
    mediatek: Option<Mediatek>,
}

#[derive(Deserialize, Default)]
struct Mediatek {
    #[serde(default)]
    patched: bool,
    #[serde(default)]
    fragment: bool,
}

/// The chip named by the 16-byte boot banner at [`layout::BANNER`].
fn banner_chip(image: &[u8]) -> Option<Chip> {
    image
        .get(layout::BANNER.start..layout::BANNER.end())
        .and_then(Chip::from_banner)
}

#[test]
#[ignore = "requires private MEDIATEK_OPTICAL_HOARD"]
fn every_image_chip_equals_its_banner_chip() {
    let root = std::env::var_os("MEDIATEK_OPTICAL_HOARD")
        .map(PathBuf::from)
        .expect("MEDIATEK_OPTICAL_HOARD must be set for this ignored test");
    let index: Index = serde_json::from_slice(
        &std::fs::read(root.join("index/identities.json")).expect("read index/identities.json"),
    )
    .expect("parse identities.json");

    let (mut checked, mut recognized, mut banner_only, mut skipped) = (0usize, 0, 0, 0);
    for identity in &index.identities {
        if identity.family != "mediatek" {
            continue;
        }
        for image in &identity.images {
            let mtk = image.mediatek.as_ref();
            if mtk.is_some_and(|m| m.patched || m.fragment) {
                continue;
            }
            let path = root.join(&image.path);
            let Ok(bytes) = std::fs::read(&path) else {
                skipped += 1;
                eprintln!("unreadable indexed image: {}", path.display());
                continue;
            };
            checked += 1;
            let banner = banner_chip(&bytes);
            match detect_chip(&bytes) {
                Ok(info) => {
                    recognized += 1;
                    assert_eq!(
                        Some(info.family),
                        banner,
                        "{}: detect_chip said {:?} but the boot banner says {banner:?}",
                        image.path,
                        info.family,
                    );
                }
                Err(_) => {
                    banner_only += 1;
                    assert!(
                        banner.is_none(),
                        "{}: boot banner names {banner:?} but detect_chip refused it",
                        image.path,
                    );
                }
            }
        }
    }
    eprintln!(
        "hoard chip-vs-banner: {checked} images checked ({recognized} recognized, \
         {banner_only} with no recognizable banner, {skipped} unreadable)"
    );
    assert_eq!(skipped, 0, "{skipped} indexed images were unreadable");
    assert!(checked > 0, "no MediaTek images found under {root:?}");
}

//! Validate every distinct BIN published in the audited MediaTek TAR corpus.
use mediatek_optical::{
    enc,
    envelope::{Envelope, InputEncoding},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn index(dir: &Path, files: &mut BTreeMap<String, PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            index(&path, files);
        } else if path.extension().is_some_and(|x| x == "bin") {
            files.insert(path.file_stem().unwrap().to_str().unwrap().into(), path);
        }
    }
}

#[test]
#[ignore = "requires MTK_IMAGE_ROOT and MTK_RECEIVER_CENSUS from firmware-extractor"]
fn every_published_member_loads_with_stable_canonical_identity() {
    let census: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MTK_RECEIVER_CENSUS").unwrap()).unwrap(),
    )
    .unwrap();
    let images = census["unique_images"].as_object().unwrap();
    assert_eq!(
        images.len(),
        136,
        "update the independent corpus census when releases change"
    );
    let mut files = BTreeMap::new();
    index(
        Path::new(&std::env::var("MTK_IMAGE_ROOT").unwrap()),
        &mut files,
    );
    for hash in images.keys() {
        let path = files
            .get(hash)
            .unwrap_or_else(|| panic!("missing published image {hash}"));
        let input = std::fs::read(path).unwrap();
        let plain = Envelope::load(&input).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(plain.input_encoding(), InputEncoding::Plaintext);
        let actual = plain
            .input_sha256()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(&actual, hash, "census must bind exact published bytes");
        let mut encrypted = input;
        enc::encrypt(&mut encrypted).unwrap();
        let encoded = Envelope::load(&encrypted).unwrap();
        assert_eq!(encoded.input_encoding(), InputEncoding::Encrypted);
        assert_eq!(plain.image_sha256(), encoded.image_sha256());
        assert_eq!(plain.image(), encoded.image());
        assert_eq!(encoded.original(), encrypted);
    }
    eprintln!(
        "validated {} published canonical images and {} encrypted envelopes",
        images.len(),
        images.len()
    );
}

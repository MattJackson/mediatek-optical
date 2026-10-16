//! Run against the private website audit with MTK_RECEIVER_AUDIT and MTK_HOARD_ROOT.
#![cfg(feature = "drive")]
use mediatek_optical::{
    drive::{Data, Transport},
    receiver::{self, Encoding, Mode},
};
struct Image {
    bytes: Vec<u8>,
    boot: bool,
}
impl Transport for Image {
    type Error = &'static str;
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn exec(&mut self, c: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        let Data::In(out) = data else {
            panic!("detector wrote to device")
        };
        if c[0] == 0x12 {
            out.fill(b' ');
            out[0] = 5;
            out[4] = 31;
            out[32..36].copy_from_slice(if self.boot { b"BOOT" } else { b"1.00" });
        } else {
            assert_eq!(&c[..3], &[0x3c, 6, 0]);
            let off = ((c[3] as usize) << 16) | ((c[4] as usize) << 8) | c[5] as usize;
            out.copy_from_slice(self.bytes.get(off..off + out.len()).ok_or("unmapped")?);
        }
        Ok(out.len())
    }
}
#[test]
#[ignore = "requires private website firmware corpus"]
fn every_website_binary_matches_both_receiver_expectations() {
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MTK_RECEIVER_AUDIT").unwrap()).unwrap(),
    )
    .unwrap();
    let root = std::path::PathBuf::from(std::env::var("MTK_HOARD_ROOT").unwrap());
    let rows = report["results"].as_array().unwrap();
    assert_eq!(rows.len(), report["packages"].as_u64().unwrap() as usize);
    for row in rows {
        let mut image = Image {
            bytes: std::fs::read(root.join(row["path"].as_str().unwrap())).unwrap(),
            boot: false,
        };
        for (boot, key) in [(true, "boot"), (false, "application")] {
            image.boot = boot;
            let mode = receiver::detect_mode(&mut image).unwrap();
            assert_eq!(mode.mode(), if boot { Mode::Boot } else { Mode::Firmware });
            let result = receiver::detect_encoding(&mut image, &mode)
                .unwrap_or_else(|e| panic!("{} {key}: {e}", row["filename"]));
            let expected = if row["receivers"][key]["encoding"] == "encrypted" {
                Encoding::Encrypted
            } else {
                Encoding::Plaintext
            };
            assert_eq!(result.encoding(), expected, "{} {key}", row["filename"]);
        }
    }
    eprintln!(
        "verified {} binaries / {} receivers",
        rows.len(),
        rows.len() * 2
    );
}

use mediatek_optical::protocol::Evidence;
use std::path::Path;

fn visit(dir: &Path, counts: &mut [usize; 3]) {
    for entry in std::fs::read_dir(dir).expect("read hoard directory") {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            visit(&path, counts);
        } else if path.extension().is_some_and(|ext| ext == "bin") {
            let image = std::fs::read(&path).unwrap();
            if image.len() != 0x20_0000 {
                continue;
            }
            let window = &image[0x3000..0x3020];
            if !(window.starts_with(b"MT1939 Boot ") || window.starts_with(b"MT1959 Boot ")) {
                counts[2] += 1;
                continue;
            }
            let mut inquiry = [0; 36];
            inquiry[0] = 5;
            if Evidence::parse(&inquiry, window).unwrap().is_some() {
                counts[0] += 1;
            } else {
                counts[1] += 1;
            }
        }
    }
}

#[test]
#[ignore = "requires FREEMKV_HOARD canonical MediaTek images"]
fn every_complete_hoard_mt19_boot_window_is_recognized() {
    let root = std::path::PathBuf::from(std::env::var_os("FREEMKV_HOARD").expect("FREEMKV_HOARD"));
    let root = root.join("images/mediatek");
    let mut counts = [0; 3];
    for chip in ["MT1939", "MT1959"] {
        visit(&root.join(chip), &mut counts);
    }
    println!(
        "boot windows: {} recognized, {} rejected, {} without the MT19 prefix",
        counts[0], counts[1], counts[2]
    );
    assert!(
        counts[0] + counts[1] >= 100,
        "need the complete held corpus"
    );
    assert_eq!(
        counts[1], 0,
        "real boot labels must survive following instructions"
    );
}

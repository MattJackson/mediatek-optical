//! The hardware families of a corpus of OEM MT1959/MT1939 update images must
//! reproduce the research table `mediatek.hardware.v1` was derived from: 207
//! images in 11 families, 90 images of the wrong size and one 2 MiB image
//! naming no chip.
//!
//! Needs the corpus, so it does nothing unless
//! `MEDIATEK_OPTICAL_FAMILY_CORPUS` lists its directories (separated like
//! `PATH`). Every `*.bin` below them is read as data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mediatek_optical::image::{family, hardware};
use mediatek_optical::{layout, Chip};

/// `(family, images, key, [(vendor and model, revisions)])`.
type Row = (
    &'static str,
    usize,
    &'static str,
    &'static [(&'static str, &'static [&'static str])],
);

const TABLE: &[Row] = &[
    (
        "336e449ab6a827e3",
        83,
        "chip=MT1959 platform=JB8 loader=JB8 iface=00000007 medium=39 bdwrite=1",
        &[
            ("ASUS BW-16D1H-U", &["A203", "A204"]),
            ("ASUS BW-16D1HT", &["3.01", "3.02", "3.03", "3.10"]),
            ("HL-DT-ST BH14NS50", &["1.01", "1.03"]),
            ("HL-DT-ST BH14NS58", &["1.00", "1.01"]),
            (
                "HL-DT-ST BH16NS40",
                &["1.02", "1.03", "1.04", "1.05", "INTM"],
            ),
            ("HL-DT-ST BH16NS50", &["1.01", "1.03"]),
            (
                "HL-DT-ST BH16NS55",
                &["1.01", "1.02", "1.03", "1.04", "1.05"],
            ),
            ("HL-DT-ST BH16NS58", &["1.00", "1.01", "1.02"]),
            ("HL-DT-ST BH16NS60", &["1.00", "1.02", "INTM"]),
            ("HL-DT-ST WH14NS40", &["1.02", "1.03", "1.04", "1.05"]),
            ("HL-DT-ST WH16NS40", &["1.02", "1.03", "1.05"]),
            ("HL-DT-ST WH16NS58", &["1.V1", "1.V2", "1.V5"]),
            ("HL-DT-ST WH16NS60", &["1.00", "1.01", "1.02", "1.03"]),
        ],
    ),
    (
        "309829e6c3c8f31d",
        41,
        "chip=MT1959 platform=BU3 loader=BU5 iface=00000007 medium=2b bdwrite=1",
        &[
            (
                "HL-DT-ST BU40N",
                &[
                    "1.00", "1.01", "1.02", "1.03", "1.04", "BN11", "BN12", "BU10", "BU12", "CB04",
                    "FR07", "INTM", "TK03", "U100", "U101",
                ],
            ),
            ("hp HLDS BU40N", &["BW41", "BW42"]),
        ],
    ),
    (
        "11e7527216405467",
        27,
        "chip=MT1939 platform=JB7 loader=Code iface=00000007 medium=39 bdwrite=1",
        &[
            ("ASUS BW-16D1HT", &["1.01"]),
            ("HL-DT-ST BE14NU40", &["1.00", "1.01"]),
            ("HL-DT-ST BH14NS40", &["1.00", "1.01", "1.02"]),
            ("HL-DT-ST BH14NS48", &["1.00", "1.01", "1.03"]),
            ("HL-DT-ST BH16NS40", &["1.00", "1.01", "1.02", "1.03"]),
            ("HL-DT-ST BH16NS48", &["1.01", "1.02"]),
            ("HL-DT-ST WH14NS40", &["1.00", "1.01", "1.02", "1.03"]),
            ("HL-DT-ST WH16NS40", &["1.01", "1.02"]),
            ("HL-DT-ST WH16NS48", &["1.D3"]),
            ("hp BH40N", &["B7C6"]),
        ],
    ),
    (
        "8c779fa82f683729",
        18,
        "chip=MT1959 platform=JB8 loader=JBC6 iface=00000007 medium=39 bdwrite=0",
        &[
            ("ASUS BC-12D2HT", &["3.00", "3.01", "3.11"]),
            ("ASUS b", &["3.01", "3.11"]),
            ("HL-DT-ST CH12NS40", &["1.01", "1.03", "INTM"]),
            ("HL-DT-ST UH12NS40", &["1.01", "1.03"]),
        ],
    ),
    (
        "ab4e219381d5f287",
        17,
        "chip=MT1959 platform=BU3 loader=BUP3 iface=00000007 medium=2b bdwrite=1",
        &[
            ("HL-DT-ST BP50NB40", &["1.01", "1.02", "1.03", "INTM"]),
            ("HL-DT-ST BP55EB40", &["1.01", "1.02", "1.03"]),
            ("HL-DT-ST WP50NB40", &["1.01", "1.03"]),
        ],
    ),
    (
        "c6031f4c104ccf7",
        7,
        "chip=MT1959 platform=JB8 loader=JBP6 iface=00000007 medium=39 bdwrite=1",
        &[("HL-DT-ST BE16NU50", &["1.01", "1.02", "1.04", "INTM"])],
    ),
    (
        "d86c13d9d87270c5",
        6,
        "chip=MT1959 platform=BU3 loader=BUP5 iface=00000007 medium=2b bdwrite=1",
        &[("HL-DT-ST BP60NB10", &["1.00", "1.01", "1.02"])],
    ),
    (
        "900ac5feeffe13f2",
        4,
        "chip=MT1959 platform=BU3 loader=BU51 iface=00000007 medium=2b bdwrite=1",
        &[("HL-DT-ST BU50N", &["1.00"]), ("hp HLDS BU50N", &["BW51"])],
    ),
    (
        "1f2fc2aafc26d8f",
        2,
        "chip=MT1939 platform=JBC5 loader=Code iface=00000007 medium=39 bdwrite=0",
        &[("HL-DT-ST UH12NS30", &["1.01", "1.02"])],
    ),
    (
        "7977ec490f2eb807",
        1,
        "chip=MT1959 platform=BU1 loader=BUP1 iface=00000007 medium=2b bdwrite=1",
        &[("HL-DT-ST BP50NB40", &["1.00"])],
    ),
    (
        "6913963c81aed3a4",
        1,
        "chip=MT1959 platform=BU3 loader=BP52 iface=00000007 medium=2b bdwrite=1",
        &[("HL-DT-ST BP60NB10", &["1.02"])],
    ),
];

fn images(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            images(&path, out);
        } else if path.extension().is_some_and(|e| e == "bin") {
            out.push(path);
        }
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// Vendor and the last word of the descriptor's product, e.g. `ASUS b`.
fn name(descriptor: &[u8]) -> String {
    let model = text(&descriptor[0x08..0x18]);
    let last = model.split_whitespace().last().unwrap_or_default();
    format!("{} {last}", text(&descriptor[0x00..0x08]))
}

type Found = BTreeMap<String, (usize, String, BTreeMap<String, BTreeSet<String>>)>;

#[test]
#[ignore = "requires MEDIATEK_OPTICAL_FAMILY_CORPUS"]
fn corpus_reproduces_the_research_table() {
    let dirs = std::env::var_os("MEDIATEK_OPTICAL_FAMILY_CORPUS")
        .expect("MEDIATEK_OPTICAL_FAMILY_CORPUS must be set for this ignored test");
    let mut paths = Vec::new();
    for dir in std::env::split_paths(&dirs) {
        images(&dir, &mut paths);
    }
    let (mut wrong_size, mut nameless) = (0, 0);
    let mut found = Found::new();
    for path in &paths {
        let image = std::fs::read(path).unwrap();
        let Some(family) = family(&image) else {
            if image.len() != layout::IMAGE_SIZE {
                wrong_size += 1;
            } else {
                let banner = layout::BANNER.of(&image).unwrap();
                assert!(
                    Chip::from_banner(banner).is_none(),
                    "{} names a chip but has no family",
                    path.display()
                );
                nameless += 1;
            }
            continue;
        };
        let key = hardware(&image).unwrap().key().replace('\x1f', " ");
        let descriptor = layout::DESCRIPTOR.of(&image).unwrap();
        let row = found
            .entry(family.to_string())
            .or_insert((0, key.clone(), BTreeMap::new()));
        assert_eq!(row.1, key, "one family, two keys");
        row.0 += 1;
        row.2
            .entry(name(descriptor))
            .or_default()
            .insert(text(&descriptor[0x18..0x1C]));
    }

    assert_eq!(paths.len(), 298, "corpus size");
    assert_eq!((wrong_size, nameless), (90, 1), "images without a family");
    let mut want = Found::new();
    for (family, count, key, members) in TABLE {
        let members = members
            .iter()
            .map(|(name, revisions)| {
                let revisions = revisions.iter().map(|r| r.to_string()).collect();
                (name.to_string(), revisions)
            })
            .collect();
        want.insert(family.to_string(), (*count, key.to_string(), members));
    }
    assert_eq!(found, want);
    assert_eq!(found.values().map(|row| row.0).sum::<usize>(), 207);
}

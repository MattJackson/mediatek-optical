use super::classic_speed::ClassicSpeed;
use sha2::{Digest, Sha256};

fn fixtures() -> Vec<(Vec<u8>, serde_json::Value)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/analysis");
    let records: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(root.join("classic-speed-sources.json")).unwrap())
            .unwrap();
    records
        .into_iter()
        .map(|record| {
            let mut image = vec![0xff; 0x200000];
            for segment in record["segments"].as_array().unwrap() {
                let bytes = std::fs::read(root.join(segment["file"].as_str().unwrap())).unwrap();
                assert_eq!(
                    format!("{:x}", Sha256::digest(&bytes)),
                    segment["excerpt_sha256"].as_str().unwrap()
                );
                let at = segment["source_offset"].as_u64().unwrap() as usize;
                image[at..at + bytes.len()].copy_from_slice(&bytes);
            }
            (image, record)
        })
        .collect()
}

#[test]
fn classic_speed_binds_all_native_policy_forms_to_their_actual_cells() {
    for (image, expected) in fixtures() {
        let proof = ClassicSpeed::detect(&image).unwrap();
        assert_eq!(proof.entry as u64, expected["entry"].as_u64().unwrap());
        assert_eq!(proof.site as u64, expected["site"].as_u64().unwrap());
        assert_eq!(
            proof.maximum_cell as u64,
            expected["maximum_cell"].as_u64().unwrap()
        );
        assert_eq!(
            proof.optimum_cell as u64,
            expected["optimum_cell"].as_u64().unwrap()
        );
        assert_eq!(
            proof.consumer as u64,
            expected["consumer"].as_u64().unwrap()
        );
    }
}

#[test]
fn classic_speed_rejects_side_effects_loops_and_bypassed_return_hooks() {
    let (original, _) = fixtures().pop().unwrap();
    let proof = ClassicSpeed::detect(&original).unwrap();
    let site = proof.entry + 8;
    let skip_tail = (((proof.site + 2) as isize - site as isize - 4) / 2) as u16;
    for op in [0x7008u16, 0x4770, 0xe7fe, 0xe000 | (skip_tail & 0x7ff)] {
        let mut image = original.clone();
        image[site..site + 2].copy_from_slice(&op.to_le_bytes());
        assert!(ClassicSpeed::detect(&image).is_err(), "{op:04x}");
    }
    let mut call = original.clone();
    call[site..site + 4].copy_from_slice(&[0, 0xf0, 0, 0xf8]);
    assert!(ClassicSpeed::detect(&call).is_err());
    assert!(ClassicSpeed::detect(&original[..proof.entry + 8]).is_err());
}

#[test]
fn classic_speed_requires_connected_setter_and_consumer_roles() {
    for (original, record) in fixtures() {
        for segment in [0, 3] {
            let at = record["segments"][segment]["source_offset"]
                .as_u64()
                .unwrap() as usize;
            let mut image = original.clone();
            image[at] ^= 1;
            assert!(ClassicSpeed::detect(&image).is_err(), "segment {segment}");
        }
    }
}

#[test]
fn classic_speed_setters_deduplicate_repeated_native_setters() {
    const COUNT: usize = 300;
    const LOGGER: usize = 0x1000;
    const MAX_CELL: u32 = 0x0200_0000;
    const OPT_CELL: u32 = 0x0200_0004;
    fn put(image: &mut [u8], at: usize, value: u32) {
        image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    // Branch placed at `at + 24` targeting LOGGER.
    fn branch(at: usize) -> u32 {
        let delta = LOGGER as i64 - at as i64 - 32;
        0xea00_0000 | ((delta >> 2) as u32 & 0x00ff_ffff)
    }
    let mut image = vec![0u8; 0x2000 + COUNT * 0x100];
    for i in 0..COUNT {
        let max = 0x2000 + i * 0x100;
        put(&mut image, max, 0xe1a01000);
        put(&mut image, max + 4, 0xe59f0040);
        put(&mut image, max + 8, 0xe1a0200e);
        put(&mut image, max + 12, 0xe5c01000);
        put(&mut image, max + 16, 0xe5d01000);
        put(&mut image, max + 20, 0xe28f0040);
        put(&mut image, max + 24, branch(max));
        put(&mut image, max + 0x4c, MAX_CELL);
        image[max + 0x5c..max + 0x61].copy_from_slice(b"RMAX\0");
        let opt = max + 0x80;
        put(&mut image, opt, 0xe59f1040);
        put(&mut image, opt + 4, 0xe1a0200e);
        put(&mut image, opt + 8, 0xe5c10000);
        put(&mut image, opt + 12, 0xe59f0040);
        put(&mut image, opt + 16, 0xe5d01000);
        put(&mut image, opt + 20, 0xe28f0040);
        put(&mut image, opt + 24, branch(opt));
        put(&mut image, opt + 0x48, OPT_CELL);
        put(&mut image, opt + 0x54, MAX_CELL);
        image[opt + 0x5c..opt + 0x61].copy_from_slice(b"OPTM\0");
    }
    let roles = super::classic_speed::setters(&image);
    assert_eq!(roles.len(), 1, "duplicate setters must collapse");
    assert_eq!(roles, vec![(MAX_CELL, OPT_CELL)]);
}

#[test]
fn classic_speed_stays_linear_in_consumers_times_setters() {
    // Many consumers of one three-cell selector and many setters of one OPTM
    // cell must not multiply: each consumer looks up only the cells it reads.
    const SETTERS: usize = 8000;
    const CONSUMERS: usize = 100_000;
    const LOGGER: usize = 0x1000;
    const SELECTOR: usize = 0x1100;
    const OPT_CELL: u32 = 0x0200_8000;
    const MEDIA_CELL: u32 = 0x0200_9000;
    const MAX_CELL: u32 = 0x0200_0000;
    fn put(image: &mut [u8], at: usize, value: u32) {
        image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn branch(at: usize) -> u32 {
        let delta = LOGGER as i64 - at as i64 - 32;
        0xea00_0000 | ((delta >> 2) as u32 & 0x00ff_ffff)
    }
    let setters = 0x2000;
    let consumers = setters + SETTERS * 0x100;
    let mut image = vec![0u8; consumers + CONSUMERS * 12];
    for i in 0..SETTERS {
        let max = setters + i * 0x100;
        put(&mut image, max, 0xe1a01000);
        put(&mut image, max + 4, 0xe59f0040);
        put(&mut image, max + 8, 0xe1a0200e);
        put(&mut image, max + 12, 0xe5c01000);
        put(&mut image, max + 16, 0xe5d01000);
        put(&mut image, max + 20, 0xe28f0040);
        put(&mut image, max + 24, branch(max));
        put(&mut image, max + 0x4c, MAX_CELL + i as u32);
        image[max + 0x5c..max + 0x61].copy_from_slice(b"RMAX\0");
        let opt = max + 0x80;
        put(&mut image, opt, 0xe59f1040);
        put(&mut image, opt + 4, 0xe1a0200e);
        put(&mut image, opt + 8, 0xe5c10000);
        put(&mut image, opt + 12, 0xe59f0040);
        put(&mut image, opt + 16, 0xe5d01000);
        put(&mut image, opt + 20, 0xe28f0040);
        put(&mut image, opt + 24, branch(opt));
        put(&mut image, opt + 0x48, OPT_CELL);
        put(&mut image, opt + 0x54, MAX_CELL + i as u32);
        image[opt + 0x5c..opt + 0x61].copy_from_slice(b"OPTM\0");
    }
    // ldr r0,=media; ldrb r0,[r0]; lsrs r0,#6; cmp r0,#3; ldr r1,=max;
    // ldrb r1,[r1]; ldr r2,=other; ldrb r2,[r2]; lsls/lsrs r0,#24; bx lr
    let selector: [u16; 12] = [
        0x4805, 0x7800, 0x0980, 0x2803, 0x4904, 0x7809, 0x4a04, 0x7812, 0x0600, 0x0e00, 0x4770,
        0xbf00,
    ];
    for (n, op) in selector.iter().enumerate() {
        image[SELECTOR + 2 * n..SELECTOR + 2 * n + 2].copy_from_slice(&op.to_le_bytes());
    }
    let maximum = MAX_CELL + SETTERS as u32 - 1;
    put(&mut image, SELECTOR + 24, MEDIA_CELL);
    put(&mut image, SELECTOR + 28, maximum);
    put(&mut image, SELECTOR + 32, MEDIA_CELL + 1);
    for n in 0..CONSUMERS {
        // bl selector; ldr r1,=optm; strb r0,[r1]
        let at = consumers + n * 12;
        image[at..at + 4].copy_from_slice(&thumb_asm::encode_bl(at, SELECTOR as u32).unwrap());
        image[at + 4..at + 8].copy_from_slice(&[0x00, 0x49, 0x08, 0x70]);
        put(&mut image, at + 8, OPT_CELL);
    }
    let started = std::time::Instant::now();
    let proof = ClassicSpeed::detect(&image).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(proof.entry, SELECTOR);
    assert_eq!(proof.maximum_cell, maximum);
    assert_eq!(proof.optimum_cell, OPT_CELL);
    assert_eq!(proof.media_cell, MEDIA_CELL);
    assert_eq!(proof.consumer, consumers);
    assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
}

//! Source-bound legacy reverse arithmetic substrate. This does not establish a
//! mode producer/lifecycle or authorize installation of a conversion.
use super::{conditional, half, matches, Error, SavedLink, UhdArea, UhdAreas};
use thumb_asm::analysis::literal_value;
use thumb_asm::isa::decode_at;

/// Existing reverse arithmetic and independent semantic mode consumers.
#[derive(Debug, Clone)]
pub struct LegacyReverse {
    /// Legacy BICS plus conditional branch replaced by a prospective detour.
    pub site: usize,
    /// Exact source bytes at `site`.
    pub original: Vec<u8>,
    /// Original branch-not-taken continuation.
    pub accept: usize,
    /// Original BNE destination.
    pub reject: usize,
    /// Common media-state RAM cell.
    pub state: u32,
    /// Mode cell independently loaded by zero/one coefficient consumers.
    pub mode: u32,
    /// Native ARM unsigned division entry, called with BLX.
    pub divide: usize,
    /// Native R7 minus twelve times quotient worker entry.
    pub mode_zero: usize,
    /// Native R0 to R6 low-halfword normalization and restoration path.
    pub normalize: usize,
    /// Source-bound saved-LR and balanced-return proof.
    pub caller: SavedLink,
}
fn branch(image: &[u8], at: usize) -> Result<usize, Error> {
    let i = decode_at(image, at).ok_or(Error::Truncated)?;
    if i.mnemonic != "b" || i.cond.is_some() {
        return Err(Error::InvalidContract);
    }
    let t = i.branch_target().ok_or(Error::InvalidContract)? as usize;
    if t + 2 > image.len() {
        return Err(Error::InvalidContract);
    }
    Ok(t)
}
fn divide(image: &[u8], at: usize) -> Result<usize, Error> {
    let i = decode_at(image, at).ok_or(Error::Truncated)?;
    if i.mnemonic != "blx" {
        return Err(Error::InvalidContract);
    }
    let t = i.branch_target().ok_or(Error::InvalidContract)? as usize;
    // Native ARM division dispatcher: two trial subtractions and branches into
    // the unsigned divide worker. Addresses/displacements are source-relative.
    let w = |a| {
        image
            .get(a..a + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };
    if t % 4 != 0
        || w(t) != Some(0xe071c220)
        || w(t + 4) != Some(0xe3a02000)
        || w(t + 12) != Some(0xe071c420)
        || w(t + 20) != Some(0xe3a03000)
        || w(t + 8).map(|v| v >> 24) != Some(0x3a)
        || w(t + 16).map(|v| v >> 24) != Some(0x3a)
        || w(t + 24).map(|v| v >> 24) != Some(0xea)
    {
        return Err(Error::InvalidContract);
    }
    for a in [t + 8, t + 16, t + 24] {
        let v = w(a).ok_or(Error::Truncated)?;
        let delta = ((v << 8) as i32 >> 6) as isize;
        let target = (a as isize + 8)
            .checked_add(delta)
            .ok_or(Error::InvalidContract)?;
        if target < 0 || target as usize + 4 > image.len() {
            return Err(Error::InvalidContract);
        }
    }
    Ok(t)
}
fn mode_consumer(image: &[u8], state: u32, value: u16) -> Result<u32, Error> {
    let pattern = [
        (0x4800, 0xff00),
        (0x7800, 0xffff),
        (0x2800 | value, 0xffff),
        (0xd100, 0xff00),
        (0x7829, 0xffff),
        (0x4800, 0xff00),
        (0xf000, 0xf800),
        (0xf800, 0xf800),
        (0x7820, 0xffff),
        (0x4900, 0xff00),
        (0x0840, 0xffff),
        (0x0040, 0xffff),
    ];
    let mut found = None;
    for at in (6..image.len().saturating_sub(pattern.len() * 2)).step_by(2) {
        if !matches(image, at, &pattern) {
            continue;
        }
        let cell = literal_value(image, at).ok_or(Error::InvalidContract)?;
        if !(0x01ff0000..0x02010000).contains(&cell) || cell == state {
            return Err(Error::InvalidContract);
        }
        // These independently recognized consumers explicitly admit C7. Bind
        // the preceding load to the same state pointer, rather than assuming a
        // neighboring mode address. The mode-one pointer is R6 from its entry.
        let load = half(image, at - 6).ok_or(Error::Truncated)?;
        if !matches!(load, 0x7800 | 0x7830)
            || half(image, at - 4) != Some(0x28c7)
            || conditional(image, at - 2, thumb_asm::Cond::Ne)
                != conditional(image, at + 6, thumb_asm::Cond::Ne)
        {
            return Err(Error::InvalidContract);
        }
        let register = if load == 0x7800 { 0u8 } else { 6u8 };
        let entry = SavedLink::detect(image, at)?.entry();
        let mut definitions = 0;
        for definition in (entry..at - 6).step_by(2) {
            if half(image, definition)
                .is_some_and(|h| h & 0xff00 == 0x4800 | (u16::from(register) << 8))
                && literal_value(image, definition) == Some(state)
                && SavedLink::require_live_definition(
                    image,
                    entry,
                    at - 6,
                    definition,
                    definition + 2,
                    register,
                )
                .is_ok()
            {
                definitions += 1;
            }
        }
        if definitions != 1 {
            return Err(if definitions > 1 {
                Error::Ambiguous
            } else {
                Error::InvalidContract
            });
        }
        if found.replace(cell).is_some() {
            return Err(Error::Ambiguous);
        }
    }
    found.ok_or(Error::UnknownLayout)
}
impl LegacyReverse {
    /// Recognize arithmetic only. No new RAM, mode entry/exit, or lifecycle is inferred.
    pub fn detect(image: &[u8], areas: &UhdAreas) -> Result<Self, Error> {
        let area = areas.area(UhdArea::ReverseCalculation)?;
        let fresh = super::uhd::inspect_role(image, UhdArea::ReverseCalculation)?;
        if area != &fresh || area.selects_c7() != Some(false) || area.variant() != "classic" {
            return Err(Error::InvalidContract);
        }
        let site = area.site();
        let state = literal_value(image, site).ok_or(Error::InvalidContract)?;
        if !(0x01ff0000..0x02010000).contains(&state) || areas.state_address()? != state {
            return Err(Error::InvalidContract);
        }
        let mode = mode_consumer(image, state, 0)?;
        if mode_consumer(image, state, 1)? != mode {
            return Err(Error::InvalidContract);
        }
        let mode_zero =
            conditional(image, site + 20, thumb_asm::Cond::Ne).ok_or(Error::InvalidContract)?;
        if !matches(
            image,
            mode_zero,
            &[
                (0x8820, 0xffff),
                (0x210a, 0xffff),
                (0xf000, 0xf800),
                (0xc000, 0xd001),
                (0x230c, 0xffff),
                (0x4358, 0xffff),
                (0x0039, 0xffff),
                (0x1a08, 0xffff),
                (0xe000, 0xf800),
            ],
        ) {
            return Err(Error::InvalidContract);
        }
        let divide = divide(image, mode_zero + 4)?;
        let nine = mode_zero.checked_sub(16).ok_or(Error::InvalidContract)?;
        if !matches(
            image,
            nine,
            &[
                (0x8820, 0xffff),
                (0x210a, 0xffff),
                (0xf000, 0xf800),
                (0xc000, 0xd001),
                (0x00c3, 0xffff),
                (0x1818, 0xffff),
                (0x1a28, 0xffff),
                (0xe000, 0xf800),
            ],
        ) || self::divide(image, nine + 4)? != divide
            || branch(image, nine + 14)? != site
        {
            return Err(Error::InvalidContract);
        }
        let normalize = branch(image, mode_zero + 16)?;
        if !matches(
            image,
            normalize,
            &[(0x0406, 0xffff), (0x0c36, 0xffff), (0xe000, 0xf800)],
        ) {
            return Err(Error::InvalidContract);
        }
        let restore = branch(image, normalize + 4)?;
        if !matches(image, restore, &[(0x9806, 0xffff), (0x8020, 0xffff)]) {
            return Err(Error::InvalidContract);
        }
        let caller = SavedLink::detect(image, site + 10)?;
        // R4 input and R5/R7 bases are established in this saved-register
        // function, not guessed incoming arguments from a numerical harness.
        let entry = caller.entry();
        let input = matches(
            image,
            entry,
            &[
                (0xb5f0, 0xffff),
                (0x6800, 0xffff),
                (0xb087, 0xffff),
                (0x9004, 0xffff),
                (0xa000, 0xf800),
                (0x6800, 0xffff),
                (0x4c00, 0xff00),
                (0x9003, 0xffff),
                (0x8820, 0xffff),
                (0x4e00, 0xff00),
                (0x9006, 0xffff),
            ],
        ) && literal_value(image, entry + 12)
            .is_some_and(|v| (0x01ff0000..0x02010000).contains(&v));
        let bases = (entry..site)
            .step_by(2)
            .filter(|&at| {
                matches(
                    image,
                    at,
                    &[
                        (0x4f00, 0xff00),
                        (0x4d00, 0xff00),
                        (0x4e00, 0xff00),
                        (0x045b, 0xffff),
                        (0x200b, 0xffff),
                        (0x429a, 0xffff),
                        (0xd300, 0xff00),
                        (0x4008, 0xffff),
                    ],
                )
            })
            .filter(|&at| {
                [at, at + 2, at + 4]
                    .into_iter()
                    .all(|p| literal_value(image, p).is_some_and(|v| v > 0 && v <= u16::MAX as u32))
            })
            .count();
        if !input || bases != 1 {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            site: site + 10,
            accept: site + 14,
            reject: conditional(image, site + 12, thumb_asm::Cond::Ne)
                .ok_or(Error::InvalidContract)?,
            original: image
                .get(site + 10..site + 14)
                .ok_or(Error::Truncated)?
                .to_vec(),
            state,
            mode,
            divide,
            mode_zero,
            normalize,
            caller,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn fixtures() -> Vec<(bool, Vec<u8>)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/analysis/uhd-reverse");
        let cases: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(root.join("sources.json")).unwrap()).unwrap();
        cases
            .into_iter()
            .map(|case| {
                let mut image = vec![0xff; 0x200000];
                for p in case["parts"].as_array().unwrap() {
                    let d = std::fs::read(root.join(p["file"].as_str().unwrap())).unwrap();
                    assert_eq!(
                        format!("{:x}", Sha256::digest(&d)),
                        p["sha256"].as_str().unwrap()
                    );
                    let at = p["offset"].as_u64().unwrap() as usize;
                    image[at..at + d.len()].copy_from_slice(&d);
                }
                (case["expected"].as_bool().unwrap(), image)
            })
            .collect()
    }
    #[test]
    fn source_fixtures_bind_arithmetic_and_refuse_missing_mode_evidence() {
        for (expected, b) in fixtures() {
            let p = LegacyReverse::detect(&b, &UhdAreas::inspect(&b));
            assert_eq!(p.is_ok(), expected, "{p:?}");
            if let Ok(p) = p {
                assert_eq!(p.original.len(), 4);
                assert_eq!(p.caller.site(), p.site);
                assert_ne!(p.mode, p.state);
                assert!(p.normalize > p.mode_zero);
            }
        }
    }
    #[test]
    fn mode_state_pointer_must_reach_c7_read_without_clobber() {
        let (_, original) = fixtures().remove(0);
        let proof = LegacyReverse::detect(&original, &UhdAreas::inspect(&original)).unwrap();
        for (value, register) in [(0u16, 0u8), (1, 6)] {
            let at = (6..original.len() - 24)
                .step_by(2)
                .find(|&a| {
                    half(&original, a).is_some_and(|h| h & 0xff00 == 0x4800)
                        && literal_value(&original, a) == Some(proof.mode)
                        && half(&original, a + 2) == Some(0x7800)
                        && half(&original, a + 4) == Some(0x2800 | value)
                        && half(&original, a - 4) == Some(0x28c7)
                        && half(&original, a + 8) == Some(0x7829)
                })
                .unwrap();
            let entry = SavedLink::detect(&original, at).unwrap().entry();
            let definition = (entry..at - 8)
                .step_by(2)
                .find(|&d| {
                    half(&original, d)
                        .is_some_and(|h| h & 0xff00 == 0x4800 | (u16::from(register) << 8))
                        && literal_value(&original, d) == Some(proof.state)
                        && SavedLink::require_live_definition(
                            &original,
                            entry,
                            at - 6,
                            d,
                            d + 2,
                            register,
                        )
                        .is_ok()
                })
                .unwrap();
            let mut bad = original.clone();
            bad[definition + 2..definition + 4]
                .copy_from_slice(&(0x2000 | (u16::from(register) << 8)).to_le_bytes());
            // Local mode and C7 grammars still match; domination/dataflow must fail.
            assert_eq!(half(&bad, at - 4), Some(0x28c7));
            assert_eq!(half(&bad, at + 4), Some(0x2800 | value));
            assert!(
                mode_consumer(&bad, proof.state, value).is_err(),
                "accepted clobbered R{register}"
            );
        }
    }
    #[test]
    fn mutations_refuse_neighbor_flag_divide_normalizer_and_forward_direction() {
        let (_, original) = fixtures().remove(0);
        let proof = LegacyReverse::detect(&original, &UhdAreas::inspect(&original)).unwrap();
        let mode_one = (0..original.len() - 4)
            .step_by(2)
            .find(|&a| {
                half(&original, a).is_some_and(|h| h & 0xff00 == 0x4800)
                    && literal_value(&original, a) == Some(proof.mode)
                    && half(&original, a + 4) == Some(0x2801)
            })
            .unwrap();
        let op = half(&original, mode_one).unwrap();
        let pool = ((mode_one + 4) & !3) + usize::from(op & 255) * 4;
        let mut neighbor = original.clone();
        neighbor[mode_one..mode_one + 2].copy_from_slice(&(op + 1).to_le_bytes());
        neighbor[pool + 4..pool + 8].copy_from_slice(&(proof.mode + 1).to_le_bytes());
        assert!(LegacyReverse::detect(&neighbor, &UhdAreas::inspect(&neighbor)).is_err());
        for (at, bytes) in [
            (proof.divide, 0xe071c221u32.to_le_bytes().to_vec()),
            (proof.normalize, 0x0407u16.to_le_bytes().to_vec()),
            (proof.mode_zero + 14, 0x1808u16.to_le_bytes().to_vec()),
        ] {
            let mut b = original.clone();
            b[at..at + bytes.len()].copy_from_slice(&bytes);
            assert!(
                LegacyReverse::detect(&b, &UhdAreas::inspect(&b)).is_err(),
                "accepted mutation at {at:x}"
            );
        }
    }
}

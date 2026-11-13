//! Source-bound slim-controller target selection, independent of patch policy.
//! Units are bound by the native measurement/normalization code, not assigned a
//! physical name. The stock slim target policy selects its high-density table
//! for state == 0xC7 or state >> 2 == 0x32 (C8 through CB), independently of
//! U identity. This contract does not qualify separate U-marker policies.
use super::{half, matches, Error, SavedLink};
use thumb_asm::isa::decode_at;

/// Shared immutable target policy observed in five stock slim UHD references.
/// These are not per-drive NV values or a universal desktop geometry table.
pub const SLIM_UHD_DENSITY_TARGETS: [u16; 4] = [1860, 2547, 3745, 4869];
const NORMAL: [u16; 4] = [2100, 3400, 5000, 6500];

/// Old local worker and its native target consumer. Recognition authorizes no
/// conversion. Native dense-class target selection is independent of the
/// separate U-marker provenance, reset, and caller-timing contracts.
#[derive(Debug, Clone)]
pub struct LegacyDensityTarget {
    /// First instruction of the four-byte detour span.
    pub site: usize,
    /// Exact source bytes, rechecked before any future emission.
    pub original: Vec<u8>,
    /// First native instruction after the displaced span.
    pub continuation: usize,
    /// Existing four-entry normal target table in this source image.
    pub normal_table: usize,
    /// Original normal-media values checked at recognition time.
    pub normal_targets: [u16; 4],
    /// Existing halfword load, R0 = [R0 + R6].
    pub lookup: usize,
    /// Whether the four displaced bytes include the halfword lookup. If true,
    /// a future detour must produce the selected halfword, not a table pointer.
    pub lookup_displaced: bool,
    /// Direct-load form: a dominating ORRS followed only by STR proves incoming
    /// N and Z cannot both be set. False for pointer-adjustment forms, where
    /// the displaced ADD/SUB itself produces the outgoing flags.
    pub incoming_nz_valid: bool,
    /// Bound table pointer and selected-target register (R0).
    pub target_register: u8,
    /// Bound byte-index register (R6), proven to be twice an index in 0..=3.
    pub index_register: u8,
    /// Native instruction producing R6 = R4 << 1.
    pub index_site: usize,
    /// Native call consuming the selected R0 halfword.
    pub call_site: usize,
    /// Source-native target/control routine; never donor code.
    pub consumer: usize,
    /// Native measured-value routine and its matched normalization grammar.
    pub measurement: usize,
    /// Native desired-target halfword written by the consumer.
    pub target_cell: u32,
    /// Bound media-state byte used later in that same consumer.
    pub state: u32,
    /// Native packed mode byte used by worker and consumer (BN11 02000B01).
    /// The matched worker writes 2; this is not the G05 reverse-mode selector.
    pub packed_mode: u32,
    /// Balanced source worker frame at the detour.
    pub caller: SavedLink,
}

fn literal(image: &[u8], at: usize, register: u16) -> Result<u32, Error> {
    let h = half(image, at).ok_or(Error::Truncated)?;
    if h & 0xff00 != 0x4800 | (register << 8) {
        return Err(Error::InvalidContract);
    }
    let p = ((at + 4) & !3) + usize::from(h & 255) * 4;
    Ok(u32::from_le_bytes(
        image
            .get(p..p + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn ram(value: u32) -> Result<u32, Error> {
    if (0x01ff0000..0x02010000).contains(&value) {
        Ok(value)
    } else {
        Err(Error::InvalidContract)
    }
}
fn call(image: &[u8], at: usize) -> Result<usize, Error> {
    let i = decode_at(image, at).ok_or(Error::Truncated)?;
    if i.mnemonic != "bl" || i.len() != 4 || i.cond.is_some() {
        return Err(Error::InvalidContract);
    }
    let target = i.branch_target().ok_or(Error::InvalidContract)? as usize;
    if target + 2 > image.len() {
        return Err(Error::Truncated);
    }
    Ok(target)
}

impl LegacyDensityTarget {
    /// Recognize the old slim local worker, its own table/index and source-native
    /// consumer. Modified tables, ABI/index changes, unknown measurement units,
    /// earliest-generation consumers, or ambiguous candidates refuse.
    pub fn detect(image: &[u8], state: u32) -> Result<Self, Error> {
        ram(state)?;
        let mut found = None;
        for site in (0..image.len().saturating_sub(10)).step_by(2) {
            if half(image, site).map_or(true, |h| h & 0xff00 != 0x4800) {
                continue;
            }
            let Ok(mut table) = literal(image, site, 0) else {
                continue;
            };
            let next = half(image, site + 2).ok_or(Error::Truncated)?;
            let lookup = if next == 0x5b80 {
                site + 2
            } else if next & 0xf700 == 0x3000 {
                table = if next & 0x0800 == 0 {
                    table.checked_add(u32::from(next & 255))
                } else {
                    table.checked_sub(u32::from(next & 255))
                }
                .ok_or(Error::InvalidContract)?;
                site + 4
            } else {
                continue;
            };
            if half(image, lookup) != Some(0x5b80) {
                continue;
            }
            let table = table as usize;
            let Some(bytes) = image.get(table..table.saturating_add(8)) else {
                continue;
            };
            if !NORMAL
                .iter()
                .enumerate()
                .all(|(i, v)| bytes[i * 2..i * 2 + 2] == v.to_le_bytes())
            {
                continue;
            }
            let Ok(candidate) = Self::bind(image, state, site, lookup, table) else {
                continue;
            };
            if found.replace(candidate).is_some() {
                return Err(Error::Ambiguous);
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
    fn bind(
        image: &[u8],
        state: u32,
        site: usize,
        lookup: usize,
        normal_table: usize,
    ) -> Result<Self, Error> {
        let consumer = call(image, lookup + 2)?;
        if !matches(image, consumer, CONSUMER_PREFIX) {
            return Err(Error::InvalidContract);
        }
        let packed_mode = ram(literal(image, consumer + 4, 0)?)?;
        ram(literal(image, consumer + 12, 1)?)?;
        let target_cell = ram(literal(image, consumer + 0x24, 0)?)?;
        if target_cell & 1 != 0 {
            return Err(Error::InvalidContract);
        }
        ram(literal(image, consumer + 0x42, 0)?)?;
        let measurement = call(image, consumer + 0x28)?;
        if !matches(image, measurement, MEASUREMENT)
            || literal(image, measurement + 0xa, 5)? != 0x04205080
            || literal(image, measurement + 0x38, 2)? != 0x0078b30c
            || literal(image, measurement + 0x3a, 1)? != 0x04042000
        {
            return Err(Error::InvalidContract);
        }
        ram(literal(image, measurement, 0)?)?;
        call(image, measurement + 0x14)?;
        let math = decode_at(image, consumer + 0x40)
            .and_then(|i| i.branch_target())
            .ok_or(Error::InvalidContract)? as usize;
        if math != consumer + 0xc2 || !matches(image, math, MATH_PREFIX) {
            return Err(Error::InvalidContract);
        }
        let base = literal(image, math + 6, 0)?;
        let body = if half(image, math + 8) == Some(0x3020) {
            if base != 0x04205000 {
                return Err(Error::InvalidContract);
            }
            math + 10
        } else {
            if base != 0x04205020 {
                return Err(Error::InvalidContract);
            }
            math + 8
        };
        let register_base = literal(image, body + 0x3a, 7)?;
        let tail = if half(image, body + 0x3e) == Some(0x3f20) {
            if register_base != 0x04205020 {
                return Err(Error::InvalidContract);
            }
            body + 0x40
        } else {
            if register_base != 0x04205000 {
                return Err(Error::InvalidContract);
            }
            body + 0x3e
        };
        if !matches(image, body, &MATH_BODY[..0x1f])
            || !matches(image, tail, &MATH_BODY[0x1f..])
            || literal(image, body + 4, 0)? != 0x04042000
            || literal(image, body + 6, 1)? != 0x15f20
            || literal(image, body + 0x2c, 0)? != 0x1ff
            || literal(image, tail + 0x1a, 0)? != state
        {
            return Err(Error::InvalidContract);
        }
        let caller = SavedLink::detect(image, site)?;
        let entry = caller.entry();
        if !matches(image, entry, WORKER_PREFIX)
            || literal(image, entry + 0x40, 1)? != packed_mode
            || literal(image, entry + 0x46, 2)? != 0x04206280
        {
            return Err(Error::InvalidContract);
        }
        ram(literal(image, entry + 0x1e, 6)?)?;
        call(image, entry + 0x32)?;
        caller.require_register_definition(image, entry + 0x4c, entry + 0x4e, 6)?;
        let incoming_nz_valid = lookup == site + 2;
        if incoming_nz_valid {
            let producer = site.checked_sub(4).ok_or(Error::InvalidContract)?;
            // ORRS r0,r1 defines consistent N/Z. STR r0,[r3,#0x24]
            // preserves every flag, and no entry path may bypass the ORRS.
            if half(image, producer) != Some(0x4308) || half(image, producer + 2) != Some(0x6258) {
                return Err(Error::InvalidContract);
            }
            SavedLink::require_live_definition(image, entry, site, producer, producer + 2, 0)?;
        }
        Ok(Self {
            site,
            original: image[site..site + 4].to_vec(),
            continuation: site + 4,
            normal_table,
            normal_targets: NORMAL,
            lookup,
            lookup_displaced: lookup == site + 2,
            incoming_nz_valid,
            target_register: 0,
            index_register: 6,
            index_site: entry + 0x4c,
            call_site: lookup + 2,
            consumer,
            measurement,
            target_cell,
            state,
            packed_mode,
            caller,
        })
    }
}
const WORKER_PREFIX: &[(u16, u16)] = &[
    (0xb5f8, 0xffff),
    (0x2500, 0xffff),
    (0x2803, 0xffff),
    (0xd801, 0xffff),
    (0x2400, 0xffff),
    (0xe008, 0xffff),
    (0x2804, 0xffff),
    (0xd801, 0xffff),
    (0x2401, 0xffff),
    (0xe004, 0xffff),
    (0x2806, 0xffff),
    (0xd801, 0xffff),
    (0x2402, 0xffff),
    (0xe000, 0xffff),
    (0x2403, 0xffff),
    (0x4e00, 0xff00),
    (0x7831, 0xffff),
    (0x4288, 0xffff),
    (0xd900, 0xffff),
    (0x2501, 0xffff),
    (0x2808, 0xffff),
    (0xd301, 0xffff),
    (0x2002, 0xffff),
    (0xe000, 0xffff),
    (0x2001, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
    (0x4800, 0xff00),
    (0x3862, 0xffff),
    (0x5d00, 0xffff),
    (0x0037, 0xffff),
    (0x7030, 0xffff),
    (0x4900, 0xff00),
    (0x2002, 0xffff),
    (0x7008, 0xffff),
    (0x4a00, 0xff00),
    (0x69d0, 0xffff),
    (0x4900, 0xff00),
    (0x0066, 0xffff),
    (0x3910, 0xffff),
];
const CONSUMER_PREFIX: &[(u16, u16)] = &[
    (0xb5fe, 0xffff),
    (0x0004, 0xffff),
    (0x4800, 0xff00),
    (0x7800, 0xffff),
    (0x07c0, 0xffff),
    (0xd00a, 0xffff),
    (0x4900, 0xff00),
    (0x2300, 0xffff),
    (0x56c8, 0xffff),
    (0x2814, 0xffff),
    (0xda01, 0xffff),
    (0x25e0, 0xffff),
    (0xe004, 0xffff),
    (0x2300, 0xffff),
    (0x56c8, 0xffff),
    (0x25d8, 0xffff),
    (0xe000, 0xffff),
    (0x25d0, 0xffff),
    (0x4800, 0xff00),
    (0x8004, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
    (0x0006, 0xffff),
    (0x0400, 0xffff),
    (0x0421, 0xffff),
    (0x1409, 0xffff),
    (0x1400, 0xffff),
    (0x1a08, 0xffff),
    (0x21ff, 0xffff),
    (0x312d, 0xffff),
    (0x3096, 0xffff),
    (0x4288, 0xffff),
    (0xd93f, 0xffff),
    (0x4800, 0xff00),
    (0x7801, 0xffff),
    (0x0849, 0xffff),
    (0x0049, 0xffff),
    (0x7001, 0xffff),
    (0x0020, 0xffff),
    (0xf000, 0xf800),
];
const MEASUREMENT: &[(u16, u16)] = &[
    (0x4800, 0xff00),
    (0xb570, 0xffff),
    (0x7800, 0xffff),
    (0x2400, 0xffff),
    (0x09c0, 0xffff),
    (0x4d00, 0xff00),
    (0x2800, 0xffff),
    (0xd00c, 0xffff),
    (0xe002, 0xffff),
    (0x20c8, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
    (0x7968, 0xffff),
    (0x09c0, 0xffff),
    (0xd105, 0xffff),
    (0x0020, 0xffff),
    (0x1c64, 0xffff),
    (0x0624, 0xffff),
    (0x0e24, 0xffff),
    (0x28c8, 0xffff),
    (0xd3f3, 0xffff),
    (0x6868, 0xffff),
    (0x2cc8, 0xffff),
    (0xd201, 0xffff),
    (0x0401, 0xffff),
    (0xd401, 0xffff),
    (0x2000, 0xffff),
    (0xbd70, 0xffff),
    (0x4a00, 0xff00),
    (0x4900, 0xff00),
    (0x610a, 0xffff),
    (0x0440, 0xffff),
    (0x0c40, 0xffff),
    (0x6148, 0xffff),
    (0x2002, 0xffff),
    (0x6188, 0xffff),
    (0x7e08, 0xffff),
    (0x0700, 0xffff),
    (0xd1fc, 0xffff),
    (0x8a08, 0xffff),
    (0xbd70, 0xffff),
];
const MATH_PREFIX: &[(u16, u16)] = &[
    (0x2c00, 0xffff),
    (0xd100, 0xffff),
    (0x2401, 0xffff),
    (0x4800, 0xff00),
];
const MATH_BODY: &[(u16, u16)] = &[
    (0x7cc0, 0xffff),
    (0x0685, 0xffff),
    (0x4800, 0xff00),
    (0x4900, 0xff00),
    (0x0ead, 0xffff),
    (0x1c6d, 0xffff),
    (0x6101, 0xffff),
    (0x6145, 0xffff),
    (0x2101, 0xffff),
    (0x6181, 0xffff),
    (0x7e01, 0xffff),
    (0x0709, 0xffff),
    (0xd1fc, 0xffff),
    (0x0002, 0xffff),
    (0x6144, 0xffff),
    (0x2102, 0xffff),
    (0x6181, 0xffff),
    (0x7e10, 0xffff),
    (0x0700, 0xffff),
    (0xd1fc, 0xffff),
    (0x6910, 0xffff),
    (0x0201, 0xffff),
    (0x4800, 0xff00),
    (0x0a09, 0xffff),
    (0x4281, 0xffff),
    (0xd802, 0xffff),
    (0x6910, 0xffff),
    (0x05c0, 0xffff),
    (0x0dc0, 0xffff),
    (0x4f00, 0xff00),
    (0x9002, 0xffff),
    (0x6bb8, 0xffff),
    (0x0a41, 0xffff),
    (0x9802, 0xffff),
    (0x0249, 0xffff),
    (0x1e40, 0xffff),
    (0x05c0, 0xffff),
    (0x0dc0, 0xffff),
    (0x4308, 0xffff),
    (0x63b8, 0xffff),
    (0x6a78, 0xffff),
    (0x0840, 0xffff),
    (0x0040, 0xffff),
    (0x6278, 0xffff),
    (0x4800, 0xff00),
    (0x7800, 0xffff),
    (0x0980, 0xffff),
    (0x2803, 0xffff),
];

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(which: usize) -> (Vec<u8>, usize, usize, u32) {
        let mut image = vec![0xff; 0x200000];
        let (site, consumer, state) = match which {
            0 => {
                image[0xdb800..0xdbe00].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/5c01c1fd-0db800.bin"
                ));
                image[0xdac00..0xdb100].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/5c01c1fd-0dac00.bin"
                ));
                image[0xd8f00..0xd9400].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/5c01c1fd-0d8f00.bin"
                ));
                image[0x14f800..0x14f900].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/5c01c1fd-14f800.bin"
                ));
                (0xdb9f8, 0xdac00, 0x1ff9e04)
            }
            1 => {
                image[0xdb200..0xdb900].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/a344e289-0db200.bin"
                ));
                image[0xda700..0xdac00].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/a344e289-0da700.bin"
                ));
                image[0xd8900..0xd8e00].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/a344e289-0d8900.bin"
                ));
                image[0x14e300..0x14e500].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/a344e289-14e300.bin"
                ));
                (0xdb4e4, 0xda71a, 0x1ff9e05)
            }
            2 => {
                image[0xdb400..0xdbb00].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/de24b000-0db400.bin"
                ));
                image[0xda800..0xdae00].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/de24b000-0da800.bin"
                ));
                image[0xd8c00..0xd9100].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/de24b000-0d8c00.bin"
                ));
                image[0x14ed00..0x14ee00].copy_from_slice(include_bytes!(
                    "../../../tests/fixtures/analysis/uhd-density/de24b000-14ed00.bin"
                ));
                (0xdb6ca, 0xda8f0, 0x1ff9e04)
            }
            _ => unreachable!(),
        };
        (image, site, consumer, state)
    }
    #[test]
    fn binds_source_workers_and_both_pointer_load_forms() {
        for which in 0..3 {
            let (image, site, consumer, state) = fixture(which);
            let x = LegacyDensityTarget::detect(&image, state).unwrap();
            assert_eq!((x.site, x.consumer), (site, consumer));
            assert_eq!(x.lookup_displaced, which == 2);
            assert_eq!(x.incoming_nz_valid, which == 2);
            assert_eq!((x.target_register, x.index_register), (0, 6));
            assert_eq!(x.caller.stack_bytes(), 24);
            assert_eq!(x.original, image[site..site + 4]);
            assert_eq!(SLIM_UHD_DENSITY_TARGETS, [1860, 2547, 3745, 4869]);
        }
    }
    #[test]
    fn rejects_mutated_table_index_register_call_and_consumer() {
        let (image, site, consumer, state) = fixture(0);
        let x = LegacyDensityTarget::detect(&image, state).unwrap();
        for at in [
            x.normal_table,
            x.index_site,
            site,
            x.lookup,
            x.call_site,
            consumer + 0x26,
            consumer + 0x36,
            consumer + 0x3c,
            x.measurement + 0x40,
            x.caller.entry() + 4,
        ] {
            let mut bad = image.clone();
            bad[at] ^= 1;
            assert!(
                LegacyDensityTarget::detect(&bad, state).is_err(),
                "mutation {at:x}"
            );
        }
        let mut clobbered = image.clone();
        clobbered[x.caller.entry() + 0x9c..x.caller.entry() + 0x9e]
            .copy_from_slice(&0x2600u16.to_le_bytes());
        assert!(LegacyDensityTarget::detect(&clobbered, state).is_err());
        assert!(LegacyDensityTarget::detect(&image, state ^ 1).is_err());
        let mut bad = image.clone();
        // The existing table is policy-bound, not an arbitrary calibration blob.
        bad[x.normal_table..x.normal_table + 2].copy_from_slice(&1860u16.to_le_bytes());
        assert!(LegacyDensityTarget::detect(&bad, state).is_err());
    }
    #[test]
    fn direct_lookup_requires_dominating_flags_producer() {
        let (image, site, _, state) = fixture(2);
        for (at, opcode) in [
            (site - 4, 0x4608u16), // MOV without flags replaces ORRS.
            (site - 2, 0x2000),    // Flag clobber replaces the STR.
            (site - 6, 0xe000),    // Branch skips ORRS, reaches STR.
            (site - 6, 0xe001),    // Branch skips ORRS and STR.
        ] {
            let mut bad = image.clone();
            bad[at..at + 2].copy_from_slice(&opcode.to_le_bytes());
            assert!(
                LegacyDensityTarget::detect(&bad, state).is_err(),
                "{at:x}/{opcode:x}"
            );
        }
    }
    #[test]
    fn refuses_earliest_different_target_consumer() {
        let mut image = vec![0xff; 0x200000];
        image[0x69c00..0x69d00].copy_from_slice(include_bytes!(
            "../../../tests/fixtures/analysis/uhd-density/c88a6901-069c00.bin"
        ));
        image[0xdd900..0xddb00].copy_from_slice(include_bytes!(
            "../../../tests/fixtures/analysis/uhd-density/c88a6901-0dd900.bin"
        ));
        image[0x154200..0x154300].copy_from_slice(include_bytes!(
            "../../../tests/fixtures/analysis/uhd-density/c88a6901-154200.bin"
        ));
        assert_eq!(image[0x154212..0x154214], 2100u16.to_le_bytes());
        assert!(LegacyDensityTarget::detect(&image, 0x01ff9def).is_err());
    }
}

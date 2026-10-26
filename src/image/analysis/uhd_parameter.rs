//! Native parameter lookup profiles. Extend media selection only where C7 is
//! excluded; a state-independent lookup already treats C7 and C8 alike.
use super::{conditional, matches, C7Selection, Error, SavedLink};
use thumb_asm::analysis::literal_value;

/// The lookup's native use of the disc-state cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicParameterVariant {
    /// Distinct tables selected through native media-state gates.
    MediaSelected,
    /// One native table, with no disc-state load in the complete getter.
    StateIndependent,
}
/// Complete getter plus its adjacent state-bound setter role. No physical
/// units or numerical calibration values are inferred or replaced.
#[derive(Debug, Clone)]
pub struct ClassicParameter {
    /// Positively recognized native implementation.
    pub variant: ClassicParameterVariant,
    /// Getter entry, including its native saved-register frame.
    pub entry: usize,
    /// Common native halfword lookup after the optional selection gate.
    pub lookup: usize,
    /// Native six-entry rate list used for C7 input selection.
    pub rates: usize,
    /// Native C7 coefficient table (the C8 table when media-selected).
    pub coefficients: usize,
    /// Native alternative used by OEM C7 in a media-selected implementation.
    pub oem_coefficients: usize,
    /// A new C7 detour is needed only for this native selection pair.
    pub selection: Option<C7Selection>,
    /// Balanced native getter frame at the selected instructions.
    pub caller: SavedLink,
}
struct Definition {
    variant: ClassicParameterVariant,
    pattern: &'static [(u16, u16)],
    setter_state: usize,
    rates: usize,
    oem_table: usize,
    target_table: usize,
    target_bias: usize,
    gate: usize,
    lookup: usize,
}
const DEFINITIONS: &[Definition] = &[
    // source 40eb760e, 0x104e00..0x104e7e; addresses are provenance only.
    Definition {
        variant: ClassicParameterVariant::MediaSelected,
        setter_state: 116,
        rates: 24,
        oem_table: 104,
        target_table: 98,
        target_bias: 0,
        gate: 94,
        lookup: 110,
        pattern: &[
            (0xb5f8, 0xffff),
            (0x4d00, 0xff00),
            (0x2200, 0xffff),
            (0x782c, 0xffff),
            (0x21c8, 0xffff),
            (0x000b, 0xffff),
            (0x43a3, 0xffff),
            (0xd101, 0xffff),
            (0x2408, 0xffff),
            (0xe000, 0xffff),
            (0x2406, 0xffff),
            (0x4e00, 0xff00),
            (0x4f00, 0xff00),
            (0x782b, 0xffff),
            (0x21c8, 0xffff),
            (0x4399, 0xffff),
            (0xd101, 0xffff),
            (0x5cb1, 0xffff),
            (0xe000, 0xffff),
            (0x5cb9, 0xffff),
            (0x4281, 0xffff),
            (0xd204, 0xffff),
            (0x1c52, 0xffff),
            (0x0612, 0xffff),
            (0x0e12, 0xffff),
            (0x42a2, 0xffff),
            (0xd3f1, 0xffff),
            (0x42a2, 0xffff),
            (0xd307, 0xffff),
            (0x0023, 0xffff),
            (0x0001, 0xffff),
            (0x4800, 0xff00),
            (0xf000, 0xf800),
            (0xd000, 0xd000),
            (0x1e64, 0xffff),
            (0x0622, 0xffff),
            (0x0e12, 0xffff),
            (0x7829, 0xffff),
            (0x23cc, 0xffff),
            (0x0018, 0xffff),
            (0x4388, 0xffff),
            (0xd102, 0xffff),
            (0x4900, 0xff00),
            (0x0050, 0xffff),
            (0xe009, 0xffff),
            (0x7828, 0xffff),
            (0x4018, 0xffff),
            (0x28c8, 0xffff),
            (0xd102, 0xffff),
            (0x4900, 0xff00),
            (0x0050, 0xffff),
            (0xe002, 0xffff),
            (0x4900, 0xff00),
            (0x0050, 0xffff),
            (0x3182, 0xffff),
            (0x5a08, 0xffff),
            (0xbdf8, 0xffff),
            (0xb5f8, 0xffff),
            (0x4e00, 0xff00),
            (0x000c, 0xffff),
            (0x7835, 0xffff),
            (0x27cc, 0xffff),
            (0x403d, 0xffff),
        ],
    },
    // source 0b2cdb82, 0x103870..0x1038aa; addresses are provenance only.
    Definition {
        variant: ClassicParameterVariant::StateIndependent,
        setter_state: 48,
        rates: 6,
        oem_table: 36,
        target_table: 36,
        target_bias: 130,
        gate: 36,
        lookup: 42,
        pattern: &[
            (0xb530, 0xffff),
            (0x0004, 0xffff),
            (0x4800, 0xff00),
            (0x4b00, 0xff00),
            (0x2100, 0xffff),
            (0x22ff, 0xffff),
            (0x5c5d, 0xffff),
            (0x42a5, 0xffff),
            (0xd301, 0xffff),
            (0x000a, 0xffff),
            (0xe004, 0xffff),
            (0x1c49, 0xffff),
            (0x0609, 0xffff),
            (0x0e09, 0xffff),
            (0x2906, 0xffff),
            (0xd3f5, 0xffff),
            (0x2aff, 0xffff),
            (0xd003, 0xffff),
            (0x4900, 0xff00),
            (0x0050, 0xffff),
            (0x3182, 0xffff),
            (0x5a08, 0xffff),
            (0xbd30, 0xffff),
            (0xb5f8, 0xffff),
            (0x4e00, 0xff00),
            (0x000c, 0xffff),
            (0x7835, 0xffff),
            (0x27cc, 0xffff),
            (0x403d, 0xffff),
        ],
    },
];
fn flash_range(image: &[u8], at: usize, length: usize) -> Result<usize, Error> {
    if at == 0 || at.checked_add(length).map_or(true, |end| end > image.len()) {
        return Err(Error::InvalidContract);
    }
    Ok(at)
}
impl ClassicParameter {
    /// Select a complete code grammar and require its adjacent setter to use
    /// the same state cell as the independently matched disc consumers.
    pub fn detect(image: &[u8], state: u32) -> Result<Self, Error> {
        if !(0x01ff0000..0x02010000).contains(&state) {
            return Err(Error::InvalidContract);
        }
        let mut found = None;
        for def in DEFINITIONS {
            let length = def.pattern.len() * 2;
            if image.len() < length {
                continue;
            }
            for entry in (0..=image.len() - length).step_by(2) {
                if !matches(image, entry, def.pattern) {
                    continue;
                }
                if literal_value(image, entry + def.setter_state) != Some(state) {
                    return Err(Error::InvalidContract);
                }
                let rates =
                    literal_value(image, entry + def.rates).ok_or(Error::InvalidContract)? as usize;
                let oem = literal_value(image, entry + def.oem_table)
                    .ok_or(Error::InvalidContract)? as usize;
                if rates != oem {
                    return Err(Error::InvalidContract);
                }
                flash_range(image, rates, 6)?;
                let oem_coefficients = flash_range(
                    image,
                    oem.checked_add(0x82).ok_or(Error::InvalidContract)?,
                    12,
                )?;
                let table = literal_value(image, entry + def.target_table)
                    .ok_or(Error::InvalidContract)? as usize;
                let coefficients = flash_range(
                    image,
                    table
                        .checked_add(def.target_bias)
                        .ok_or(Error::InvalidContract)?,
                    if def.variant == ClassicParameterVariant::MediaSelected {
                        16
                    } else {
                        12
                    },
                )?;
                if coefficients % 2 != 0 {
                    return Err(Error::InvalidContract);
                }
                let site = entry + def.gate;
                let selection = if def.variant == ClassicParameterVariant::MediaSelected {
                    if literal_value(image, entry + 2) != Some(state) {
                        return Err(Error::InvalidContract);
                    }
                    let reject =
                        conditional(image, site + 2, 0xd100).ok_or(Error::InvalidContract)?;
                    if reject != entry + 0x68 {
                        return Err(Error::InvalidContract);
                    }
                    Some(C7Selection {
                        site,
                        replay: vec![0x28c8],
                        span: 4,
                        accept: site + 4,
                        reject,
                    })
                } else {
                    None
                };
                let proof = Self {
                    variant: def.variant,
                    entry,
                    lookup: entry + def.lookup,
                    rates,
                    coefficients,
                    oem_coefficients,
                    selection,
                    caller: SavedLink::bind(image, entry, site)?,
                };
                if found.replace(proof).is_some() {
                    return Err(Error::Ambiguous);
                }
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
}

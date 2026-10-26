//! Complete native read-position decode routine and source-bound C7 entry points.
use super::{matches, C7Selection, Error, SavedLink};
/// Native decode and range contracts; matching does not enable UHD support.
#[derive(Debug, Clone)]
pub struct ClassicReadPosition {
    /// Complete native routine entry.
    pub entry: usize,
    /// Working position word, current layer and cached layer cells.
    pub position: u32,
    /// Native current-layer byte.
    pub layer: u32,
    /// Native cached-layer byte.
    pub cached_layer: u32,
    /// Native range-status byte.
    pub status: u32,
    /// Native CMP/conditional gate; C7 additionally chooses one or zero below.
    pub decode: C7Selection,
    /// Native first-layer reflect path, already using the 0x7fffff mask.
    pub layer_one: usize,
    /// Native clear-layer and upper-position-byte path.
    pub layer_zero: usize,
    /// Native upper/lower range checks with their existing thresholds.
    pub ranges: [C7Selection; 2],
    /// Native saved frames for decode and both range gates.
    pub callers: [SavedLink; 3],
}
const PATTERN: &[(u16, u16)] = &[
    (0xb5f8, 0xffff),
    (0x4a00, 0xff00),
    (0x7810, 0xffff),
    (0x21ef, 0xffff),
    (0x4008, 0xffff),
    (0x7010, 0xffff),
    (0x4800, 0xff00),
    (0x7c00, 0xffff),
    (0x0780, 0xffff),
    (0xd571, 0xffff),
    (0x4800, 0xff00),
    (0x6a00, 0xffff),
    (0x4c00, 0xff00),
    (0x6020, 0xffff),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x6820, 0xffff),
    (0x2800, 0xffff),
    (0xd068, 0xffff),
    (0x6820, 0xffff),
    (0x08c1, 0xffff),
    (0x4800, 0xff00),
    (0x6001, 0xffff),
    (0x6800, 0xffff),
    (0x6020, 0xffff),
    (0x4e00, 0xff00),
    (0x7830, 0xffff),
    (0x21c8, 0xffff),
    (0x4381, 0xffff),
    (0x2500, 0xffff),
    (0x4800, 0xff00),
    (0x4f00, 0xff00),
    (0x2900, 0xffff),
    (0xd140, 0xffff),
    (0x78a1, 0xffff),
    (0x0989, 0xffff),
    (0x2901, 0xffff),
    (0xd10c, 0xffff),
    (0x7839, 0xffff),
    (0x2901, 0xffff),
    (0xd006, 0xffff),
    (0x7800, 0xffff),
    (0x2801, 0xffff),
    (0xd003, 0xffff),
    (0x6821, 0xffff),
    (0x4800, 0xff00),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x6820, 0xffff),
    (0x4900, 0xff00),
    (0xe044, 0xffff),
    (0x2902, 0xffff),
    (0xd10f, 0xffff),
    (0x7839, 0xffff),
    (0x2902, 0xffff),
    (0xd006, 0xffff),
    (0x7800, 0xffff),
    (0x2802, 0xffff),
    (0xd003, 0xffff),
    (0x6821, 0xffff),
    (0x4800, 0xff00),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x78a0, 0xffff),
    (0x0680, 0xffff),
    (0x0e80, 0xffff),
    (0x70a0, 0xffff),
    (0x2002, 0xffff),
    (0xe010, 0xffff),
    (0x2903, 0xffff),
    (0x7839, 0xffff),
    (0xd10f, 0xffff),
    (0x2903, 0xffff),
    (0xd006, 0xffff),
    (0x7800, 0xffff),
    (0x2803, 0xffff),
    (0xd003, 0xffff),
    (0x6821, 0xffff),
    (0x4800, 0xff00),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x6820, 0xffff),
    (0x4900, 0xff00),
    (0x4048, 0xffff),
    (0x6020, 0xffff),
    (0x2003, 0xffff),
    (0x7038, 0xffff),
    (0xe008, 0xffff),
    (0x2900, 0xffff),
    (0xd005, 0xffff),
    (0x7800, 0xffff),
    (0x2800, 0xffff),
    (0xd002, 0xffff),
    (0x6821, 0xffff),
    (0x4800, 0xff00),
    (0xe023, 0xffff),
    (0x703d, 0xffff),
    (0x70e5, 0xffff),
    (0xe02e, 0xffff),
    (0x7831, 0xffff),
    (0x22cc, 0xffff),
    (0x4011, 0xffff),
    (0x29c4, 0xffff),
    (0xd11e, 0xffff),
    (0x78a1, 0xffff),
    (0x0689, 0xffff),
    (0x2900, 0xffff),
    (0x7839, 0xffff),
    (0xda0f, 0xffff),
    (0x2900, 0xffff),
    (0xd106, 0xffff),
    (0x7800, 0xffff),
    (0x2800, 0xffff),
    (0xd103, 0xffff),
    (0x6821, 0xffff),
    (0x4800, 0xff00),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x6820, 0xffff),
    (0x4900, 0xff00),
    (0x4048, 0xffff),
    (0x6020, 0xffff),
    (0x2001, 0xffff),
    (0xe7d9, 0xffff),
    (0xe027, 0xffff),
    (0x2901, 0xffff),
    (0xd1e0, 0xffff),
    (0x7800, 0xffff),
    (0x2801, 0xffff),
    (0xd1dd, 0xffff),
    (0x6821, 0xffff),
    (0x4800, 0xff00),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0xe7d8, 0xffff),
    (0x7839, 0xffff),
    (0x2901, 0xffff),
    (0xd106, 0xffff),
    (0x7800, 0xffff),
    (0x2801, 0xffff),
    (0xd103, 0xffff),
    (0x6821, 0xffff),
    (0x4800, 0xff00),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x703d, 0xffff),
    (0x7830, 0xffff),
    (0x22c8, 0xffff),
    (0x0011, 0xffff),
    (0x4381, 0xffff),
    (0xd102, 0xffff),
    (0x78a0, 0xffff),
    (0x2822, 0xffff),
    (0xd305, 0xffff),
    (0x7830, 0xffff),
    (0x4382, 0xffff),
    (0xd007, 0xffff),
    (0x78a0, 0xffff),
    (0x281c, 0xffff),
    (0xd204, 0xffff),
    (0x4a00, 0xff00),
    (0x7810, 0xffff),
    (0x2110, 0xffff),
    (0x4308, 0xffff),
    (0x7010, 0xffff),
    (0xbdf8, 0xffff),
];
fn literal(image: &[u8], at: usize) -> Result<u32, Error> {
    let op = u16::from_le_bytes(
        image
            .get(at..at + 2)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    );
    let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
    Ok(u32::from_le_bytes(
        image
            .get(pool..pool + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    ))
}
impl ClassicReadPosition {
    /// Bind the whole native routine, state cell, controller operands, first-layer
    /// reflection mask, class stores, range thresholds and balanced return paths.
    pub fn detect(image: &[u8], state: u32) -> Result<Self, Error> {
        let length = PATTERN.len() * 2;
        if image.len() < length {
            return Err(Error::Truncated);
        }
        let mut found = None;
        for entry in (0..=image.len() - length).step_by(2) {
            if !matches(image, entry, PATTERN) {
                continue;
            }
            if literal(image, entry + 0x32)? != state
                || literal(image, entry + 0xc)? != 0x04082000
                || literal(image, entry + 0x14)? != 0x04082100
                || literal(image, entry + 0x62)? != 0x7fffff
            {
                return Err(Error::InvalidContract);
            }
            let position = literal(image, entry + 0x18)?;
            let layer = literal(image, entry + 0x3e)?;
            let cached_layer = literal(image, entry + 0x3c)?;
            let status = literal(image, entry + 2)?;
            if [state, position, layer, cached_layer, status]
                .iter()
                .any(|p| !(0x01ff0000..0x02010000).contains(p))
                || position % 4 != 0
            {
                return Err(Error::InvalidContract);
            }
            let decode = C7Selection {
                site: entry + 0x40,
                replay: vec![0x2900],
                span: 4,
                accept: entry + 0x44,
                reject: entry + 0xc6,
            };
            let ranges = [
                C7Selection {
                    site: entry + 0x12a,
                    replay: vec![0x4381],
                    span: 4,
                    accept: entry + 0x12e,
                    reject: entry + 0x134,
                },
                C7Selection {
                    site: entry + 0x136,
                    replay: vec![0x4382],
                    span: 4,
                    accept: entry + 0x14a,
                    reject: entry + 0x13a,
                },
            ];
            let callers = [
                SavedLink::bind(image, entry, decode.site)?,
                SavedLink::bind(image, entry, ranges[0].site)?,
                SavedLink::bind(image, entry, ranges[1].site)?,
            ];
            let contract = Self {
                entry,
                position,
                layer,
                cached_layer,
                status,
                decode,
                ranges,
                layer_one: entry + 0x4c,
                layer_zero: entry + 0xc0,
                callers,
            };
            if found.replace(contract).is_some() {
                return Err(Error::Ambiguous);
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
}

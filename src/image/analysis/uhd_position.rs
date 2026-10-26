//! Complete native position-scaling routine, selected by instructions.
use super::{matches, C7Selection, Error, SavedLink};
/// Native input/output scaling pair; no capability or output image implied.
#[derive(Debug, Clone)]
pub struct ClassicPosition {
    /// Complete routine entry, including its saved native return address.
    pub entry: usize,
    /// Shared media-state byte loaded into the native preserved register.
    pub state: u32,
    /// Native mode byte indexing this routine’s parameter table.
    pub mode: u32,
    /// Native parameter table in this image.
    pub table: u32,
    /// Native quarter-scale input selector.
    pub input: C7Selection,
    /// Native doubled-result selector.
    pub output: C7Selection,
    /// Native frame for each selector in the same complete routine.
    pub callers: [SavedLink; 2],
}
const PATTERN: &[(u16, u16)] = &[
    (0xb5f0, 0xffff),
    (0x4e00, 0xff00),
    (0x00c0, 0xffff),
    (0x7831, 0xffff),
    (0x27c8, 0xffff),
    (0x003c, 0xffff),
    (0x438c, 0xffff),
    (0x4900, 0xff00),
    (0x4a00, 0xff00),
    (0x4b00, 0xff00),
    (0x2c00, 0xffff),
    (0xd10f, 0xffff),
    (0x7814, 0xffff),
    (0x0880, 0xffff),
    (0x190c, 0xffff),
    (0x78e4, 0xffff),
    (0x7815, 0xffff),
    (0x0424, 0xffff),
    (0x194d, 0xffff),
    (0x792d, 0xffff),
    (0x022d, 0xffff),
    (0x1964, 0xffff),
    (0x7815, 0xffff),
    (0x194d, 0xffff),
    (0x796d, 0xffff),
    (0x1964, 0xffff),
    (0x08a4, 0xffff),
    (0xe00c, 0xffff),
    (0x7814, 0xffff),
    (0x190c, 0xffff),
    (0x78e4, 0xffff),
    (0x7815, 0xffff),
    (0x0424, 0xffff),
    (0x194d, 0xffff),
    (0x792d, 0xffff),
    (0x022d, 0xffff),
    (0x1964, 0xffff),
    (0x7815, 0xffff),
    (0x194d, 0xffff),
    (0x796d, 0xffff),
    (0x1964, 0xffff),
    (0x615c, 0xffff),
    (0x6118, 0xffff),
    (0x2003, 0xffff),
    (0x6198, 0xffff),
    (0x7e18, 0xffff),
    (0x0700, 0xffff),
    (0xd1fc, 0xffff),
    (0x7810, 0xffff),
    (0x5c08, 0xffff),
    (0x7814, 0xffff),
    (0x0400, 0xffff),
    (0x190c, 0xffff),
    (0x7864, 0xffff),
    (0x7812, 0xffff),
    (0x0224, 0xffff),
    (0x1900, 0xffff),
    (0x1889, 0xffff),
    (0x7889, 0xffff),
    (0x1840, 0xffff),
    (0x6158, 0xffff),
    (0x2001, 0xffff),
    (0x6198, 0xffff),
    (0x7e18, 0xffff),
    (0x0700, 0xffff),
    (0xd1fc, 0xffff),
    (0x2005, 0xffff),
    (0x6198, 0xffff),
    (0x7e18, 0xffff),
    (0x0700, 0xffff),
    (0xd1fc, 0xffff),
    (0x6918, 0xffff),
    (0x7831, 0xffff),
    (0x438f, 0xffff),
    (0xd100, 0xffff),
    (0x0040, 0xffff),
    (0x0900, 0xffff),
    (0xbdf0, 0xffff),
];
impl ClassicPosition {
    /// Match the entire routine, including both scaling branches, hardware
    /// polling loops, native stores and return. Only PC literal displacements
    /// vary; no model, chipset or firmware hash selects this grammar.
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
            let at = entry + 2;
            let op = u16::from_le_bytes(image[at..at + 2].try_into().unwrap());
            let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
            let value = u32::from_le_bytes(
                image
                    .get(pool..pool + 4)
                    .ok_or(Error::Truncated)?
                    .try_into()
                    .unwrap(),
            );
            if value != state || !(0x01ff0000..0x02010000).contains(&state) {
                return Err(Error::InvalidContract);
            }
            let literal = |offset: usize| -> Result<u32, Error> {
                let at = entry + offset;
                let op = u16::from_le_bytes(image[at..at + 2].try_into().unwrap());
                let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
                Ok(u32::from_le_bytes(
                    image
                        .get(pool..pool + 4)
                        .ok_or(Error::Truncated)?
                        .try_into()
                        .unwrap(),
                ))
            };
            let table = literal(14)?;
            let mode = literal(16)?;
            if literal(18)? != 0x04042000
                || !(0x01ff0000..0x02010000).contains(&mode)
                || image.get(table as usize..table as usize + 40).is_none()
            {
                return Err(Error::InvalidContract);
            }
            let input = C7Selection {
                site: entry + 20,
                replay: vec![0x2c00],
                span: 4,
                accept: entry + 24,
                reject: entry + 56,
            };
            let output = C7Selection {
                site: entry + 146,
                replay: vec![0x438f],
                span: 4,
                accept: entry + 150,
                reject: entry + 152,
            };
            let callers = [
                SavedLink::bind(image, entry, input.site)?,
                SavedLink::bind(image, entry, output.site)?,
            ];
            if found
                .replace(Self {
                    entry,
                    state,
                    mode,
                    table,
                    input,
                    output,
                    callers,
                })
                .is_some()
            {
                return Err(Error::Ambiguous);
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
}

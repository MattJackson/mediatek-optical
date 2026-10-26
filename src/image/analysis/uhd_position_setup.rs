//! Complete native position-setup routine and its paired scaling selectors.
use super::{matches, C7Selection, Error, SavedLink};
/// Native setup selectors bound to one complete caller and its own table.
#[derive(Debug, Clone)]
pub struct ClassicPositionSetup {
    /// Native function entry with argument/local stack storage and saved LR.
    pub entry: usize,
    /// Native working-position cell.
    pub position: u32,
    /// Native parameter-table mode byte.
    pub mode: u32,
    /// Native coefficient bytes used by the controller setup.
    pub table: u32,
    /// Quarter-scale the native input and table term.
    pub input: C7Selection,
    /// Native 0x14 versus 0x0a command parameter.
    pub command: C7Selection,
    /// Saved frames for the two selectors in this complete routine.
    pub callers: [SavedLink; 2],
}
const PATTERN: &[(u16, u16)] = &[
    (0xb5f1, 0xffff),
    (0x4e00, 0xff00),
    (0xb082, 0xffff),
    (0x7830, 0xffff),
    (0x27c8, 0xffff),
    (0x003b, 0xffff),
    (0x4383, 0xffff),
    (0x4800, 0xff00),
    (0x4d00, 0xff00),
    (0x4900, 0xff00),
    (0x4a00, 0xff00),
    (0x2b00, 0xffff),
    (0xd111, 0xffff),
    (0x682b, 0xffff),
    (0x780c, 0xffff),
    (0x089b, 0xffff),
    (0x1904, 0xffff),
    (0x78e4, 0xffff),
    (0x780d, 0xffff),
    (0x0424, 0xffff),
    (0x1945, 0xffff),
    (0x792d, 0xffff),
    (0x022d, 0xffff),
    (0x1964, 0xffff),
    (0x780d, 0xffff),
    (0x1945, 0xffff),
    (0x796d, 0xffff),
    (0x1964, 0xffff),
    (0x08a4, 0xffff),
    (0x6154, 0xffff),
    (0xe00e, 0xffff),
    (0x780b, 0xffff),
    (0x18c3, 0xffff),
    (0x78db, 0xffff),
    (0x780c, 0xffff),
    (0x041b, 0xffff),
    (0x1904, 0xffff),
    (0x7924, 0xffff),
    (0x0224, 0xffff),
    (0x191b, 0xffff),
    (0x780c, 0xffff),
    (0x1904, 0xffff),
    (0x7964, 0xffff),
    (0x191b, 0xffff),
    (0x6153, 0xffff),
    (0x682b, 0xffff),
    (0x6113, 0xffff),
    (0x2303, 0xffff),
    (0x6193, 0xffff),
    (0x0014, 0xffff),
    (0x7e22, 0xffff),
    (0x0712, 0xffff),
    (0xd1fc, 0xffff),
    (0x6162, 0xffff),
    (0x2305, 0xffff),
    (0x61a3, 0xffff),
    (0x7e23, 0xffff),
    (0x071b, 0xffff),
    (0xd1fc, 0xffff),
    (0x7833, 0xffff),
    (0x439f, 0xffff),
    (0xd101, 0xffff),
    (0x2314, 0xffff),
    (0xe000, 0xffff),
    (0x230a, 0xffff),
    (0x6163, 0xffff),
    (0x2301, 0xffff),
    (0x61a3, 0xffff),
    (0x7e23, 0xffff),
    (0x071b, 0xffff),
    (0xd1fc, 0xffff),
    (0x7809, 0xffff),
    (0x1840, 0xffff),
    (0x7980, 0xffff),
    (0x0021, 0xffff),
    (0x6160, 0xffff),
    (0x2402, 0xffff),
    (0x618c, 0xffff),
    (0x7e08, 0xffff),
    (0x0700, 0xffff),
    (0xd1fc, 0xffff),
    (0x7c08, 0xffff),
    (0x4b00, 0xff00),
    (0x781b, 0xffff),
    (0x4d00, 0xff00),
    (0x07db, 0xffff),
    (0x782b, 0xffff),
    (0xd015, 0xffff),
    (0x07db, 0xffff),
    (0xd115, 0xffff),
    (0x9d02, 0xffff),
    (0x0843, 0xffff),
    (0x195b, 0xffff),
    (0xe001, 0xffff),
    (0x9d02, 0xffff),
    (0x1aeb, 0xffff),
    (0x9302, 0xffff),
    (0x466b, 0xffff),
    (0x895d, 0xffff),
    (0x9501, 0xffff),
    (0x891d, 0xffff),
    (0x9500, 0xffff),
    (0x6148, 0xffff),
    (0x8898, 0xffff),
    (0x881b, 0xffff),
    (0x0400, 0xffff),
    (0x4318, 0xffff),
    (0x6108, 0xffff),
    (0x618c, 0xffff),
    (0xe006, 0xffff),
    (0x07db, 0xffff),
    (0xd1e9, 0xffff),
    (0x9d02, 0xffff),
    (0x0843, 0xffff),
    (0x42ab, 0xffff),
    (0xd2ec, 0xffff),
    (0xe7e8, 0xffff),
    (0x7e08, 0xffff),
    (0x0700, 0xffff),
    (0xd1fc, 0xffff),
    (0x466b, 0xffff),
    (0x715a, 0xffff),
    (0x7c88, 0xffff),
    (0x7118, 0xffff),
    (0x7c48, 0xffff),
    (0x7058, 0xffff),
    (0x7c08, 0xffff),
    (0x7018, 0xffff),
    (0x8818, 0xffff),
    (0x8118, 0xffff),
    (0x8898, 0xffff),
    (0x8158, 0xffff),
    (0x9802, 0xffff),
    (0xbdfe, 0xffff),
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
impl ClassicPositionSetup {
    /// Match the entire routine, including both selectors, native polling loops,
    /// table assembly, result correction and balanced native return.
    pub fn detect(image: &[u8], state: u32) -> Result<Self, Error> {
        let length = PATTERN.len() * 2;
        if image.len() < length {
            return Err(Error::Truncated);
        }
        let mut result = None;
        for entry in (0..=image.len() - length).step_by(2) {
            if !matches(image, entry, PATTERN) {
                continue;
            }
            let position = literal(image, entry + 16)?;
            let mode = literal(image, entry + 18)?;
            let table = literal(image, entry + 14)?;
            if literal(image, entry + 2)? != state
                || literal(image, entry + 20)? != 0x04042000
                || [state, position, mode]
                    .iter()
                    .any(|p| !(0x01ff0000..0x02010000).contains(p))
                || position % 4 != 0
                || image.get(table as usize..table as usize + 40).is_none()
            {
                return Err(Error::InvalidContract);
            }
            let input = C7Selection {
                site: entry + 22,
                replay: vec![0x2b00],
                span: 4,
                accept: entry + 26,
                reject: entry + 62,
            };
            let command = C7Selection {
                site: entry + 120,
                replay: vec![0x439f],
                span: 4,
                accept: entry + 124,
                reject: entry + 128,
            };
            let callers = [
                SavedLink::bind(image, entry, input.site)?,
                SavedLink::bind(image, entry, command.site)?,
            ];
            let contract = Self {
                entry,
                position,
                mode,
                table,
                input,
                command,
                callers,
            };
            if result.replace(contract).is_some() {
                return Err(Error::Ambiguous);
            }
        }
        result.ok_or(Error::UnknownLayout)
    }
}

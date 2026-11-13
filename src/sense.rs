//! Sense-data parsing and classification (public as `drive::sense`).
/// Parsed sense: `(key, asc, ascq)`.
pub type Triplet = (u8, u8, u8);

/// Sense key `NOT READY`.
pub const NOT_READY: u8 = 0x02;
/// Sense key `MEDIUM ERROR`.
pub const MEDIUM_ERROR: u8 = 0x03;
/// Sense key `HARDWARE ERROR`.
pub const HARDWARE_ERROR: u8 = 0x04;
/// Sense key `ILLEGAL REQUEST`.
pub const ILLEGAL_REQUEST: u8 = 0x05;
/// Sense key `ABORTED COMMAND`.
pub const ABORTED_COMMAND: u8 = 0x0B;

/// Parse fixed-format (`0x70`/`0x71`) or descriptor-format (`0x72`/`0x73`)
/// sense data into `(key, asc, ascq)`. `None` when short or unrecognized.
pub fn parse(data: &[u8]) -> Option<Triplet> {
    match *data.first()? & 0x7f {
        0x70 | 0x71 if data.len() >= 14 => Some((data[2] & 0x0f, data[12], data[13])),
        0x72 | 0x73 if data.len() >= 4 => Some((data[1] & 0x0f, data[2], data[3])),
        _ => None,
    }
}

/// `true` for the keys that prove a programming failure after a flash:
/// MEDIUM ERROR, HARDWARE ERROR and ABORTED COMMAND. Every other key is a
/// transient or unrelated condition; read-back verification decides.
pub const fn is_flash_fault(key: u8) -> bool {
    matches!(key, MEDIUM_ERROR | HARDWARE_ERROR | ABORTED_COMMAND)
}

/// `true` for `02/3A/xx`, the benign "medium not present" of an empty tray.
pub const fn is_no_medium(key: u8, asc: u8) -> bool {
    key == NOT_READY && asc == 0x3A
}

//! Command descriptor blocks, as byte constructors.
//!
//! The flash sequence uses 12-byte CDBs byte-for-byte as the OEM update tool
//! issues them: [`probe`] → [`test_unit_ready`] → [`enter_update`] →
//! [`transfer`] per chunk → [`finish`] → [`test_unit_ready`] →
//! [`request_sense`]. The drive erases and programs flash when the last
//! [`transfer`] of a complete image lands; [`finish`] is a trailing handshake.

/// READ BUFFER / WRITE BUFFER mode addressing flash at file offsets.
pub const MODE_DATA: u8 = 0x06;
/// Buffer id of the flash.
pub const BUFFER_ID: u8 = 0x00;
/// Bytes per [`transfer`] in the OEM sequence (16 KiB).
pub const CHUNK: usize = 0x4000;
/// Bytes returned by [`probe`].
pub const PROBE_LEN: usize = 0x100;
/// Bytes requested by [`request_sense`].
pub const REQUEST_SENSE_LEN: usize = 16;
/// INQUIRY allocation used by `crate::drive::identify`.
pub const INQUIRY_ALLOC: u16 = 96;
/// GET CONFIGURATION feature carrying the ASCII serial number.
pub const FEATURE_SERIAL: u16 = 0x0108;
/// GET CONFIGURATION feature carrying the ASCII firmware date. Its presence is
/// one half of the MT19xx protocol probe.
pub const FEATURE_FIRMWARE_DATE: u16 = 0x010C;

/// READ BUFFER (`3C`) of `len` bytes at `off`. Both fields are 24 bits.
pub const fn read_buffer(mode: u8, buffer_id: u8, off: u32, len: u32) -> [u8; 10] {
    [
        0x3C,
        mode & 0x1f,
        buffer_id,
        (off >> 16) as u8,
        (off >> 8) as u8,
        off as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00,
    ]
}

/// WRITE BUFFER (`3B`) of `len` bytes at `off`. Both fields are 24 bits.
pub const fn write_buffer(mode: u8, buffer_id: u8, off: u32, len: u32) -> [u8; 10] {
    [
        0x3B,
        mode & 0x1f,
        buffer_id,
        (off >> 16) as u8,
        (off >> 8) as u8,
        off as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00,
    ]
}

/// READ BUFFER of flash memory at a file offset.
pub const fn read_memory(off: u32, len: u32) -> [u8; 10] {
    read_buffer(MODE_DATA, BUFFER_ID, off, len)
}

/// Standard INQUIRY (`12`).
pub const fn inquiry(alloc: u16) -> [u8; 6] {
    [0x12, 0x00, 0x00, (alloc >> 8) as u8, alloc as u8, 0x00]
}

/// GET CONFIGURATION (`46`) of the single feature `code` (RT = `02`).
pub const fn get_configuration(code: u16, alloc: u16) -> [u8; 10] {
    [
        0x46,
        0x02,
        (code >> 8) as u8,
        code as u8,
        0x00,
        0x00,
        0x00,
        (alloc >> 8) as u8,
        alloc as u8,
        0x00,
    ]
}

/// PROBE: READ BUFFER of the identity descriptor, [`PROBE_LEN`] bytes. Opens
/// the OEM flash sequence.
pub const fn probe() -> [u8; 12] {
    [
        0x3C, 0x06, 0x00, 0x1E, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// TEST UNIT READY, as the 12-byte all-zero CDB of the OEM sequence.
pub const fn test_unit_ready() -> [u8; 12] {
    [0; 12]
}

/// PREPARE: WRITE BUFFER mode 1 with no data; enters the update session.
pub const fn enter_update() -> [u8; 12] {
    [
        0x3B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00,
    ]
}

/// PREPARE dialects whose flag-copy bodies are recognized by the entry parser.
/// A byte constructor is not receiver detection or authorization to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prepare {
    /// Legacy WRITE BUFFER mode 1, buffer zero.
    ModeOne,
    /// WRITE BUFFER mode 6, buffer 0x67, entering the same flag-copy body.
    ModeSix67,
    /// Legacy entry with update bit zero cleared, preserving the boot region
    /// only when the receiver's range-selection contract establishes that meaning.
    ModeOnePreserveBoot,
    /// Buffer-0x67 entry with the same receiver-derived preservation policy.
    ModeSix67PreserveBoot,
}
impl Prepare {
    /// Zero-length data-out command with the selected boot policy.
    pub const fn command(self) -> [u8; 12] {
        let mut command = enter_update();
        if matches!(self, Self::ModeSix67 | Self::ModeSix67PreserveBoot) {
            command[1] = 6;
            command[2] = 0x67;
        }
        if matches!(
            self,
            Self::ModeOnePreserveBoot | Self::ModeSix67PreserveBoot
        ) {
            command[9] &= !1;
        }
        command
    }
}

/// STREAM: WRITE BUFFER mode 6 of `len` bytes at file offset `off` (24 bits).
pub const fn transfer(off: u32, len: u16) -> [u8; 12] {
    [
        0x3B,
        0x06,
        0x00,
        (off >> 16) as u8,
        (off >> 8) as u8,
        off as u8,
        0x00,
        (len >> 8) as u8,
        len as u8,
        0x00,
        0x00,
        0x00,
    ]
}

/// COMMIT: WRITE BUFFER mode 7 with no data and the `1B 12` trailer.
pub const fn finish() -> [u8; 12] {
    [
        0x3B, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x12,
    ]
}

/// STATUS: REQUEST SENSE exactly as the OEM update tools issue it: allocation
/// length [`REQUEST_SENSE_LEN`] in byte 4 and `80` in the control byte.
pub const fn request_sense() -> [u8; 12] {
    [
        0x03,
        0x00,
        0x00,
        0x00,
        REQUEST_SENSE_LEN as u8,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
}

#[cfg(test)]
#[path = "cdb_tests.rs"]
mod tests;

//! Read-only detection of the active MediaTek update receiver.
//!
//! BOOT and application receivers can require different transfer encodings,
//! even in the same image. Positive Thumb code signatures identify the direct
//! banner comparison or the decrypt-before-banner-check path. Neither a model,
//! revision date, target image nor absence of AES selects plaintext.
//!
//! The bounded search covers the receiver locations in the audited MT1939 /
//! MT1959 corpus. Unreadable or unrecognized code returns an error. This is not
//! permission to flash and does not replace image/hardware compatibility gates.
use crate::{
    cdb,
    drive::{self, Transport},
    INQUIRY_LEN,
};

pub mod entry;

#[cfg(all(feature = "image", feature = "enc"))]
mod prepared;
#[cfg(all(feature = "image", feature = "enc"))]
pub use prepared::{ExecuteError, PreparedUpdate, TransferPlan};
#[cfg(all(feature = "image", feature = "enc"))]
mod profile;
#[cfg(all(feature = "image", feature = "enc"))]
pub use profile::detect;

/// Code currently handling commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Recovery bootloader (INQUIRY revision `BOOT`).
    Boot,
    /// Running firmware application.
    Firmware,
}

/// Transfer format expected by the active receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Send the canonical image unchanged.
    Plaintext,
    /// Send the AES-128-ECB transport envelope.
    Encrypted,
}

/// A live INQUIRY binding, obtained by [`detect_mode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedMode {
    mode: Mode,
    inquiry: [u8; INQUIRY_LEN],
}
impl DetectedMode {
    /// Whether BOOT or the application is running.
    pub fn mode(&self) -> Mode {
        self.mode
    }
    /// Standard INQUIRY bytes used to bind this detection.
    pub fn inquiry(&self) -> &[u8; INQUIRY_LEN] {
        &self.inquiry
    }
}

/// Detection failed; no implicit encoding is selected.
#[derive(Debug)]
pub enum Error<E> {
    /// A required read failed or was short.
    Read(drive::Error<E>),
    /// INQUIRY is not a complete optical-drive identity with a revision.
    InvalidIdentity,
    /// No positive receiver signature was readable in the supported range.
    Unknown,
    /// More than one receiver location or encoding matched.
    Conflict,
    /// Identity or receiver bytes changed after detection.
    Changed,
    /// The running receiver's entry grammar is unreadable or unrecognized.
    UnknownEntry,
}
impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "receiver read failed: {e}"),
            Self::InvalidIdentity => f.write_str("invalid MediaTek receiver INQUIRY identity"),
            Self::Unknown => f.write_str(
                "active MediaTek receiver signature unreadable or unknown; encoding not selected",
            ),
            Self::Conflict => {
                f.write_str("conflicting MediaTek receiver signatures; encoding not selected")
            }
            Self::Changed => {
                f.write_str("MediaTek receiver changed since detection; re-plan the flash")
            }
            Self::UnknownEntry => f.write_str(
                "active MediaTek entry contract unreadable or unknown; no PREPARE selected",
            ),
        }
    }
}
#[cfg(feature = "std")]
impl<E: core::fmt::Debug> std::error::Error for Error<E> {}

/// Identify BOOT versus running firmware using standard INQUIRY only.
/// No feature 0x010C, descriptor, update command or data-out is required.
pub fn detect_mode<T: Transport>(t: &mut T) -> Result<DetectedMode, Error<T::Error>> {
    let mut inquiry = [0; INQUIRY_LEN];
    drive::read(
        t,
        &cdb::inquiry(INQUIRY_LEN as u16),
        &mut inquiry,
        INQUIRY_LEN,
    )
    .map_err(Error::Read)?;
    let revision = &inquiry[32..36];
    if inquiry[0] & 0x1f != 5
        || inquiry[4] < 31
        || !revision.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
        || revision.iter().all(|b| *b == b' ')
    {
        return Err(Error::InvalidIdentity);
    }
    let mode = if revision == b"BOOT" {
        Mode::Boot
    } else {
        Mode::Firmware
    };
    Ok(DetectedMode { mode, inquiry })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Evidence {
    address: u32,
    len: usize,
    bytes: [u8; 64],
}
impl Evidence {
    fn new(address: u32, bytes: &[u8]) -> Self {
        let mut e = Self {
            address,
            len: bytes.len(),
            bytes: [0; 64],
        };
        e.bytes[..bytes.len()].copy_from_slice(bytes);
        e
    }
}

/// Positive receiver evidence, bound to the live mode and code bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receiver {
    identity: DetectedMode,
    encoding: Encoding,
    site: Evidence,
    transform: Option<Evidence>,
    #[cfg(all(feature = "image", feature = "enc"))]
    profile: Option<profile::Profile>,
}
impl Receiver {
    /// Active receiver mode.
    pub fn mode(&self) -> Mode {
        self.identity.mode
    }
    /// Required wire encoding.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
    /// PREPARE dialect from full live entry detection; encoding-only detection
    /// deliberately supplies no command.
    #[cfg(all(feature = "image", feature = "enc"))]
    pub fn prepare_command(&self) -> Option<cdb::Prepare> {
        self.profile.as_ref().map(|profile| profile.prepare)
    }
    /// Address of the matched receiver instructions.
    pub fn signature_address(&self) -> u32 {
        self.site.address
    }
    /// Re-read identity and matched instructions immediately before writing.
    pub fn revalidate<T: Transport>(&self, t: &mut T) -> Result<(), Error<T::Error>> {
        if detect_mode(t)? != self.identity {
            return Err(Error::Changed);
        }
        for e in core::iter::once(&self.site).chain(self.transform.iter()) {
            let mut bytes = [0; 64];
            drive::read_memory(t, e.address, &mut bytes[..e.len]).map_err(Error::Read)?;
            if bytes[..e.len] != e.bytes[..e.len] {
                return Err(Error::Changed);
            }
        }
        #[cfg(all(feature = "image", feature = "enc"))]
        if let Some(profile) = &self.profile {
            profile.revalidate(t)?;
        }
        Ok(())
    }
}

// 0x100 masks a relocation/stack-slot byte. These are positive instruction
// sequences, not whole-build hashes. Matches are halfword aligned.
const ANY: u16 = 0x100;
const PLAIN_DIRECT: &[u16] = &[
    0x03, 0x21, 0x09, 0x03, 0x61, 0x18, ANY, 0xa8, 0x00, 0x5d, 0x09, 0x78, 0x88, 0x42,
];
const PLAIN_APP: &[u16] = &[
    0x03, 0x20, ANY, 0x49, 0x00, 0x03, 0x20, 0x18, 0x09, 0x68, 0x00, 0x02, 0x00, 0x0a, 0x40, 0x18,
    ANY, 0xa9, 0x09, 0x5d, 0x00, 0x78, 0x88, 0x42,
];
const PLAIN_BOOT: &[u16] = &[
    0x03, 0x20, 0x00, 0x03, 0x20, 0x18, 0xf9, 0x69, 0x00, 0x02, 0x00, 0x0a, 0x40, 0x18, ANY, 0xa9,
    0x09, 0x5d, 0x00, 0x78, 0x88, 0x42,
];
const PLAIN_LOGGED: &[u16] = &[
    0x03, 0x20, 0x00, 0x03, 0x20, 0x18, 0x05, 0x02, 0xf8, 0x69, 0x2d, 0x0a, 0x28, 0x18, 0x02, 0x78,
    ANY, 0x48, 0x21, 0x00, ANY, ANY, ANY, ANY, 0xf8, 0x69, 0x28, 0x18, 0x00, 0x78, 0x31, 0x5d,
    0x88, 0x42,
];
const AES: &[u16] = &[
    0xf7, 0xb5, 0x06, 0x00, 0x14, 0x00, ANY, 0x48, 0x11, 0x00, 0x84, 0xb0, ANY, ANY, ANY, ANY,
    0x00, 0x2c, 0x01, 0xd0, 0x20, 0x07, 0x02, 0xd0, 0x00, 0x20, 0x07, 0xb0, 0xf0, 0xbd, 0xa0, 0x08,
    0x01, 0x22, 0x92, 0x06, 0x02, 0x90, 0x10, 0x68, 0x10, 0x21, 0x88, 0x43, 0x10, 0x60,
];
fn matches(bytes: &[u8], pattern: &[u16]) -> bool {
    bytes.len() >= pattern.len()
        && bytes
            .iter()
            .zip(pattern)
            .all(|(&b, &p)| p == ANY || p == b as u16)
}
fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|b| b == needle)
}
fn branch_target(bytes: &[u8], address: u32) -> Option<u32> {
    let a = u16::from_le_bytes([bytes[0], bytes[1]]);
    let b = u16::from_le_bytes([bytes[2], bytes[3]]);
    if a & 0xf800 != 0xf000 || b & 0xf800 != 0xf800 {
        return None;
    }
    let delta = (((a & 2047) as i32) << 12) | (((b & 2047) as i32) << 1);
    let delta = (delta << 9) >> 9;
    u32::try_from(address as i64 + 4 + delta as i64).ok()
}

/// Detect the transfer encoding by reading the active receiver's instructions.
/// Reads memory only; never stages data or tries alternative write formats.
/// `mode` must come from [`detect_mode`]; identity is checked again on return.
pub fn detect_encoding<T: Transport>(
    t: &mut T,
    mode: &DetectedMode,
) -> Result<Receiver, Error<T::Error>> {
    let (start, end) = match mode.mode {
        Mode::Boot => (0x3400, 0x3800),
        Mode::Firmware => (0x98000, 0xb4000),
    };
    let mut found: Option<Receiver> = None;
    // 64-byte overlap preserves instructions spanning a read boundary.
    let mut block = [0; 1088];
    let mut base = start;
    while base < end {
        let len = core::cmp::min(block.len(), (end - base) as usize);
        if drive::read_memory(t, base, &mut block[..len]).is_ok() {
            for off in (0..len.saturating_sub(4)).step_by(2) {
                let bytes = &block[off..len];
                let address = base + off as u32;
                let mut candidate = None;
                for pattern in [PLAIN_DIRECT, PLAIN_APP, PLAIN_BOOT, PLAIN_LOGGED] {
                    if matches(bytes, pattern) {
                        candidate = Some(Receiver {
                            identity: mode.clone(),
                            encoding: Encoding::Plaintext,
                            site: Evidence::new(address, &bytes[..pattern.len()]),
                            transform: None,
                            #[cfg(all(feature = "image", feature = "enc"))]
                            profile: None,
                        });
                    }
                }
                // Validate a header-decrypt call AND its hardware AES routine.
                // The caller must pass staged header +0x3000 and length 16.
                let before = &block[off.saturating_sub(32)..off];
                if off >= 32
                    && contains(before, &[0x10, 0x22])
                    && (contains(before, &[3, 0x20, 0, 3])
                        || contains(before, &[3, 0x23]) && contains(before, &[0x1b, 3]))
                {
                    if let Some(target) = branch_target(bytes, address) {
                        let valid_range = match mode.mode {
                            Mode::Boot => target < 0x10000,
                            Mode::Firmware => (0x10000..0x1c0000).contains(&target),
                        };
                        let mut routine = [0; 46];
                        if valid_range
                            && drive::read_memory(t, target, &mut routine).is_ok()
                            && matches(&routine, AES)
                        {
                            let begin = off.saturating_sub(32);
                            candidate = Some(Receiver {
                                identity: mode.clone(),
                                encoding: Encoding::Encrypted,
                                site: Evidence::new(base + begin as u32, &block[begin..off + 4]),
                                transform: Some(Evidence::new(target, &routine)),
                                #[cfg(all(feature = "image", feature = "enc"))]
                                profile: None,
                            });
                        }
                    }
                }
                if let Some(candidate) = candidate {
                    if let Some(previous) = &found {
                        if previous != &candidate {
                            return Err(Error::Conflict);
                        }
                    } else {
                        found = Some(candidate);
                    }
                }
            }
        }
        base += 1024;
    }
    let receiver = found.ok_or(Error::Unknown)?;
    receiver.revalidate(t)?;
    Ok(receiver)
}

#[cfg(test)]
mod tests;

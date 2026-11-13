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
use crate::classify::receiver::{matches, AES, PLAIN_APP, PLAIN_BOOT, PLAIN_DIRECT, PLAIN_LOGGED};
use crate::transport::{self as drive, Transport};
use crate::{cdb, INQUIRY_LEN};

#[cfg(all(feature = "image", feature = "enc"))]
pub(crate) mod layout;

#[cfg(all(feature = "image", feature = "enc"))]
use crate::classify::receiver::{analysis, entry};
#[cfg(all(feature = "image", feature = "enc"))]
mod prepared;
#[cfg(all(feature = "image", feature = "enc"))]
pub use prepared::{PreparedUpdate, TransferEncoding, TransferPlan};
#[cfg(all(feature = "image", feature = "enc"))]
mod profile;
#[cfg(all(feature = "image", feature = "enc"))]
pub(crate) mod reference;
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

/// Encoding of a region in a receiver transfer plan.
/// Legacy receiver detection reports the header path; executable plans expose
/// header and body separately through `TransferEncoding`.
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
#[cfg_attr(not(all(feature = "image", feature = "enc")), allow(dead_code))]
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
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::drive::ReceiverError<()>) -> u8 { match e { mediatek_optical::drive::ReceiverError::Read { .. } => 0, mediatek_optical::drive::ReceiverError::InvalidIdentity { .. } => 1, mediatek_optical::drive::ReceiverError::Unknown { .. } => 2, mediatek_optical::drive::ReceiverError::Conflict { .. } => 3, mediatek_optical::drive::ReceiverError::Changed { .. } => 4, mediatek_optical::drive::ReceiverError::UnknownEntry { .. } => 5, } }
/// ```
#[derive(Debug)]
#[non_exhaustive]
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
impl<E: core::fmt::Debug + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(source) => Some(source),
            Self::InvalidIdentity
            | Self::Unknown
            | Self::Conflict
            | Self::Changed
            | Self::UnknownEntry => None,
        }
    }
}

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
    pub(crate) identity: DetectedMode,
    encoding: Encoding,
    site: Evidence,
    transform: Option<Evidence>,
    #[cfg(all(feature = "image", feature = "enc"))]
    profile: Option<profile::Profile>,
    #[cfg(all(feature = "image", feature = "enc"))]
    reference: Option<reference::Binding>,
}
impl Receiver {
    /// Cached application evidence from the same snapshot used by live entry
    /// detection. This is analysis, not a completed transfer authorization.
    #[cfg(all(feature = "image", feature = "enc"))]
    pub(crate) fn application_analysis(&self) -> Option<&analysis::ApplicationAnalysis> {
        self.profile.as_ref()?.application.as_ref()
    }
    /// Active receiver mode.
    pub fn mode(&self) -> Mode {
        self.identity.mode
    }
    /// Header-path classification retained for compatibility. Consult the
    /// prepared transfer plan for separate header/body wire encodings.
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
    ///
    /// INQUIRY identity is read first and again after every receiver byte:
    /// READ BUFFER returns the same flash from BOOT and the application, so
    /// only INQUIRY binds the running receiver, and a change during the
    /// code/table re-read is refused with [`Error::Changed`].
    ///
    /// A reference-bound receiver (`Provenance::CurrentReference`, built by
    /// `Receiver::from_firmware` or `reference::detect`, or
    /// `Provenance::UserSuppliedReference`, built by
    /// `reference::detect_user_supplied`) re-reads only INQUIRY identity, the
    /// boot banner and build metadata, then INQUIRY identity again; its
    /// instruction evidence is not re-read.
    pub fn revalidate<T: Transport>(&self, t: &mut T) -> Result<(), Error<T::Error>> {
        #[cfg(all(feature = "image", feature = "enc"))]
        if let Some(reference) = &self.reference {
            return reference.revalidate(t);
        }
        self.revalidate_signature(t)?;
        #[cfg(all(feature = "image", feature = "enc"))]
        if let Some(profile) = &self.profile {
            profile.revalidate(t)?;
        }
        self.revalidate_live_identity(t)
    }

    /// Re-read INQUIRY and require the identity bound by detection. This is
    /// the last command of [`Receiver::revalidate`].
    #[cfg(all(feature = "image", feature = "enc"))]
    pub(crate) fn revalidate_identity<T: Transport>(
        &self,
        t: &mut T,
    ) -> Result<(), Error<T::Error>> {
        // `from_firmware` holds a synthetic INQUIRY; reference receivers bind
        // only the mode and identity bytes.
        if let Some(reference) = &self.reference {
            return reference.revalidate_identity(t);
        }
        self.revalidate_live_identity(t)
    }

    fn revalidate_live_identity<T: Transport>(&self, t: &mut T) -> Result<(), Error<T::Error>> {
        if detect_mode(t)? != self.identity {
            return Err(Error::Changed);
        }
        Ok(())
    }

    // Detection finishes with a small coherence check. The complete snapshot
    // and a trailing identity check run immediately before any mutating
    // execution, through `revalidate`.
    fn revalidate_signature<T: Transport>(&self, t: &mut T) -> Result<(), Error<T::Error>> {
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
        Ok(())
    }
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
    // Begin 32 bytes early so a header-decrypt call at the window start still
    // has its setup context; nothing before `start` is itself a candidate.
    let mut base = start - 32;
    while base < end {
        let len = core::cmp::min(block.len(), (end - base) as usize);
        // Read the leading context separately so every window byte still
        // comes from a read starting inside the window.
        let lead = (start - base.min(start)) as usize;
        if lead != 0 {
            drive::read_memory(t, base, &mut block[..lead]).map_err(Error::Read)?;
        }
        drive::read_memory(t, base + lead as u32, &mut block[lead..len]).map_err(Error::Read)?;
        // Inclusive of `len - 4`: a 4-byte call ending at the window end counts.
        for off in (0..len.saturating_sub(3)).step_by(2) {
            let bytes = &block[off..len];
            let address = base + off as u32;
            if address < start {
                continue;
            }
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
                        #[cfg(all(feature = "image", feature = "enc"))]
                        reference: None,
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
                    if valid_range {
                        drive::read_memory(t, target, &mut routine).map_err(Error::Read)?;
                    }
                    if valid_range && matches(&routine, AES) {
                        let begin = off.saturating_sub(32);
                        candidate = Some(Receiver {
                            identity: mode.clone(),
                            encoding: Encoding::Encrypted,
                            site: Evidence::new(base + begin as u32, &block[begin..off + 4]),
                            transform: Some(Evidence::new(target, &routine)),
                            #[cfg(all(feature = "image", feature = "enc"))]
                            profile: None,
                            #[cfg(all(feature = "image", feature = "enc"))]
                            reference: None,
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
        base += 1024;
    }
    let receiver = found.ok_or(Error::Unknown)?;
    receiver.revalidate(t)?;
    Ok(receiver)
}

#[cfg(all(test, feature = "image", feature = "enc"))]
#[path = "receiver/decoding_corpus_tests.rs"]
mod decoding_corpus_tests;
#[cfg(all(test, feature = "image", feature = "enc"))]
#[path = "receiver/entry_corpus_tests.rs"]
mod entry_corpus_tests;
#[cfg(test)]
mod tests;

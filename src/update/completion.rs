//! Completion evidence shared by Flash and Recovery.

use super::{FlashError, Verified};
use crate::{drive, layout, receiver, INQUIRY_LEN};

/// What protected-region read-back established. Limited verification must be
/// reported as such even when the exact target has started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadbackQuality {
    /// All protected ranges were read and matched.
    Complete(Verified),
    /// Some protected chunks were unreadable; every byte read matched.
    Limited {
        /// Protected bytes compared, all equal.
        checked: usize,
        /// Protected chunks that could not be read in full.
        unverified: usize,
    },
}

/// How strongly the post-write INQUIRY shows that the drive left the firmware
/// it ran before the write. Hosts must consult [`Startup::evidence`]: only
/// [`StartupEvidence::LeftBoot`] and [`StartupEvidence::IdentityChanged`]
/// observe a restart into the target.
///
/// The comparison uses only the operating mode and INQUIRY vendor, product and
/// revision (bytes 8..36) bound before the write. Neither TEST UNIT READY nor
/// a unit-attention sense is restart evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupEvidence {
    /// BOOT answered INQUIRY before the write; the target application answers
    /// now.
    LeftBoot,
    /// The application's INQUIRY identity before the write differed from the
    /// target's, and the drive now reports the target's. Whether old code
    /// could serve INQUIRY from newly programmed flash is not recorded.
    IdentityChanged,
    /// The application already reported the target's vendor, product and
    /// revision before the write, as on a reflash or a same-version build.
    /// INQUIRY cannot tell the old firmware still running apart from the
    /// target having started. Hosts should advise a power cycle and
    /// re-identification before relying on the new firmware.
    Unobserved,
}

/// Post-write identity and stored build metadata that match the selected
/// target, with the strength of the restart evidence. This is confirmed target
/// startup only when [`Startup::evidence`] is not [`StartupEvidence::Unobserved`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Startup {
    inquiry: [u8; INQUIRY_LEN],
    descriptor: [u8; 0x58],
    evidence: StartupEvidence,
}
impl Startup {
    /// Live standard INQUIRY whose vendor, product and revision match the target.
    pub fn inquiry(&self) -> &[u8; INQUIRY_LEN] {
        &self.inquiry
    }
    /// Stored model, revision and build metadata (descriptor bytes `0..0x58`);
    /// all [`layout::DESCRIPTOR`] bytes matched the target. It is read through
    /// READ BUFFER, the same path as read-back, so it shows what was programmed,
    /// not what is running; see [`Startup::evidence`].
    pub fn descriptor(&self) -> &[u8; 0x58] {
        &self.descriptor
    }
    /// Whether the post-write INQUIRY observed a restart into the target.
    pub fn evidence(&self) -> StartupEvidence {
        self.evidence
    }
}

/// A completed operation with target identity evidence and explicit read-back
/// quality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    /// Post-write identity matching the target. Confirmed startup only when
    /// [`Startup::evidence`] is not [`StartupEvidence::Unobserved`].
    pub startup: Startup,
    /// How much of the programmed firmware could be verified by read-back.
    pub readback: ReadbackQuality,
}
impl Completion {
    /// Compatibility with callers that require complete protected read-back
    /// and an observed restart. Limited verification and an unobserved restart
    /// remain errors through the legacy API; limited read-back is reported
    /// first.
    pub(crate) fn into_verified<E>(self) -> Result<Verified, FlashError<E>> {
        let verified = match self.readback {
            ReadbackQuality::Complete(verified) => verified,
            ReadbackQuality::Limited {
                checked,
                unverified,
            } => {
                return Err(FlashError::Incomplete {
                    checked,
                    unverified,
                })
            }
        };
        if self.startup.evidence == StartupEvidence::Unobserved {
            return Err(FlashError::Startup(StartupError::Unobserved));
        }
        Ok(verified)
    }
}

/// Why target startup could not be established or observed.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::update::StartupError<()>) -> u8 { match e { mediatek_optical::update::StartupError::Identity { .. } => 0, mediatek_optical::update::StartupError::Read { .. } => 1, mediatek_optical::update::StartupError::TargetMismatch { .. } => 2, mediatek_optical::update::StartupError::Unobserved { .. } => 3, } }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum StartupError<E> {
    /// Live operating mode/INQUIRY could not be established.
    Identity(receiver::Error<E>),
    /// The target descriptor could not be read completely.
    Read(drive::Error<E>),
    /// BOOT, an old target or different build is still running.
    TargetMismatch,
    /// Read-back and the target identity matched, but the drive reported the
    /// same identity before the write ([`StartupEvidence::Unobserved`]). Only
    /// the legacy `flash` APIs return this; it follows a completed write.
    Unobserved,
}
impl<E: core::fmt::Debug> core::fmt::Display for StartupError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Identity(error) => write!(f, "{error}"),
            Self::Read(error) => write!(f, "{error}"),
            Self::TargetMismatch => {
                f.write_str("live firmware identity or build differs from the selected target")
            }
            Self::Unobserved => f.write_str(
                "readback matched, but the drive reported the same identity before and after \
                 writing, so a restart into the target was not observed",
            ),
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for StartupError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            Self::Read(source) => Some(source),
            Self::TargetMismatch | Self::Unobserved => None,
        }
    }
}

pub(super) fn complete<T: drive::Transport>(
    reads: &mut T,
    image: &[u8],
    result: Result<Verified, FlashError<T::Error>>,
    prior: &receiver::DetectedMode,
) -> Result<Completion, FlashError<T::Error>> {
    let readback = match result {
        Ok(verified) => ReadbackQuality::Complete(verified),
        Err(FlashError::Incomplete {
            checked,
            unverified,
        }) => ReadbackQuality::Limited {
            checked,
            unverified,
        },
        // Transfer failures, programming faults and mismatches are never
        // downgraded by an identity check, and trigger no further commands.
        Err(error) => return Err(error),
    };
    let startup = confirm_startup(reads, image, prior).map_err(FlashError::Startup)?;
    Ok(Completion { startup, readback })
}

fn confirm_startup<T: drive::Transport>(
    reads: &mut T,
    image: &[u8],
    prior: &receiver::DetectedMode,
) -> Result<Startup, StartupError<T::Error>> {
    let expected = layout::DESCRIPTOR
        .of(image)
        .ok_or(StartupError::TargetMismatch)?;
    let mode = receiver::detect_mode(reads).map_err(StartupError::Identity)?;
    if mode.mode() != receiver::Mode::Firmware || mode.inquiry()[8..36] != expected[..28] {
        return Err(StartupError::TargetMismatch);
    }
    let mut descriptor = [0; layout::DESCRIPTOR.len];
    drive::read_memory(reads, layout::DESCRIPTOR.start as u32, &mut descriptor)
        .map_err(StartupError::Read)?;
    if descriptor[..] != expected[..] {
        return Err(StartupError::TargetMismatch);
    }
    Ok(Startup {
        inquiry: *mode.inquiry(),
        descriptor: descriptor[..0x58]
            .try_into()
            .expect("fixed descriptor length"),
        evidence: classify(prior, &mode),
    })
}

/// Restart evidence from the receiver identity bound before the write and the
/// post-write INQUIRY that already matched the target. Infallible; it issues
/// no command.
///
/// Reads only `prior.mode()` and `prior.inquiry()[8..36]`. A receiver built by
/// `reference::Receiver::from_firmware` stores an INQUIRY synthesized from the
/// image (reference.rs: only bytes 0, 4 and 8..36 set). Execution revalidates
/// exactly these fields against the physical INQUIRY before any write on every
/// path: the whole `DetectedMode` for live-code receivers (receiver.rs
/// `revalidate_signature`), and mode plus bytes 8..36 for reference receivers
/// (reference.rs `Binding::read_banner`). No other byte is pre-write evidence.
pub(crate) fn classify(
    prior: &receiver::DetectedMode,
    live: &receiver::DetectedMode,
) -> StartupEvidence {
    if prior.mode() == receiver::Mode::Boot {
        StartupEvidence::LeftBoot
    } else if prior.inquiry()[8..36] != live.inquiry()[8..36] {
        StartupEvidence::IdentityChanged
    } else {
        StartupEvidence::Unobserved
    }
}

#[cfg(test)]
#[path = "completion_tests.rs"]
mod tests;

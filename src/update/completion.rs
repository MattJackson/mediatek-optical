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

/// Exact selected-target startup, established after programming settled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Startup {
    inquiry: [u8; INQUIRY_LEN],
    descriptor: [u8; 0x58],
}
impl Startup {
    /// Live standard INQUIRY whose vendor, product and revision match the target.
    pub fn inquiry(&self) -> &[u8; INQUIRY_LEN] {
        &self.inquiry
    }
    /// Live model, revision and build metadata matched against the target.
    /// The device-written descriptor tail is deliberately excluded.
    pub fn descriptor(&self) -> &[u8; 0x58] {
        &self.descriptor
    }
}

/// A completed operation with exact target startup and explicit read-back quality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    /// Evidence that the selected firmware is now running.
    pub startup: Startup,
    /// How much of the programmed firmware could be verified by read-back.
    pub readback: ReadbackQuality,
}
impl Completion {
    /// Compatibility with callers that require complete protected read-back.
    /// Limited verification remains an error through the legacy API.
    pub(crate) fn into_verified<E>(self) -> Result<Verified, FlashError<E>> {
        match self.readback {
            ReadbackQuality::Complete(verified) => Ok(verified),
            ReadbackQuality::Limited {
                checked,
                unverified,
            } => Err(FlashError::Incomplete {
                checked,
                unverified,
            }),
        }
    }
}

/// Why exact selected-target startup could not be established.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::update::StartupError<()>) -> u8 { match e { mediatek_optical::update::StartupError::Identity { .. } => 0, mediatek_optical::update::StartupError::Read { .. } => 1, mediatek_optical::update::StartupError::TargetMismatch { .. } => 2, } }
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
}
impl<E: core::fmt::Debug> core::fmt::Display for StartupError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Identity(error) => write!(f, "{error}"),
            Self::Read(error) => write!(f, "{error}"),
            Self::TargetMismatch => {
                f.write_str("live firmware identity or build differs from the selected target")
            }
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for StartupError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            Self::Read(source) => Some(source),
            Self::TargetMismatch => None,
        }
    }
}

pub(super) fn complete<T: drive::Transport>(
    reads: &mut T,
    image: &[u8],
    result: Result<Verified, FlashError<T::Error>>,
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
    let startup = confirm_startup(reads, image).map_err(FlashError::Startup)?;
    Ok(Completion { startup, readback })
}

fn confirm_startup<T: drive::Transport>(
    reads: &mut T,
    image: &[u8],
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
    if descriptor[..0x58] != expected[..0x58] {
        return Err(StartupError::TargetMismatch);
    }
    Ok(Startup {
        inquiry: *mode.inquiry(),
        descriptor: descriptor[..0x58]
            .try_into()
            .expect("fixed descriptor length"),
    })
}

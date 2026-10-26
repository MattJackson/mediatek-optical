//! Read-only OEM code-layout contracts. Matches identify instructions and their
//! relationships, never a drive model or filename. Emission remains a caller policy.

mod auth;
mod caller;
mod classic_speed;
mod media;
mod switch;
mod uhd;
mod uhd_di;
mod vid;

pub use auth::{AuthCell, AuthCellVariant};
pub use caller::SavedLink;
pub use classic_speed::ClassicSpeed;
pub use media::{MediaGate, MediaGateVariant};
pub use uhd::{C7Selection, UhdArea, UhdAreaContract, UhdAreas, UhdEdge, UhdHandling, UhdLiteral};
pub use uhd_di::ClassicDi;
pub use vid::{VidGate, VidGateVariant};

#[cfg(test)]
mod classic_speed_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod uhd_tests;

/// A recognition failure; absence and conflicting evidence are distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No supported instruction grammar was found.
    UnknownLayout,
    /// More than one candidate satisfies a required role.
    Ambiguous,
    /// A candidate's instruction or continuation contract failed.
    InvalidContract,
    /// Required bytes or a branch destination lie outside the input.
    Truncated,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::UnknownLayout => "unsupported OEM instruction layout",
            Self::Ambiguous => "ambiguous OEM instruction layout",
            Self::InvalidContract => "OEM instruction contract does not hold",
            Self::Truncated => "truncated OEM instruction evidence",
        })
    }
}

impl std::error::Error for Error {}

fn half(image: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        image.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn conditional(image: &[u8], at: usize, condition: u16) -> Option<usize> {
    let h = half(image, at)?;
    if h & 0xff00 != condition {
        return None;
    }
    let target = (at as i64)
        .checked_add(4)?
        .checked_add(i64::from(h as u8 as i8) * 2)?;
    let target = usize::try_from(target).ok()?;
    (target + 2 <= image.len()).then_some(target)
}

fn matches(image: &[u8], at: usize, pattern: &[(u16, u16)]) -> bool {
    pattern
        .iter()
        .enumerate()
        .all(|(i, (v, mask))| half(image, at + i * 2).is_some_and(|h| h & mask == v & mask))
}

fn unique(image: &[u8], pattern: &[(u16, u16)]) -> Result<usize, Error> {
    let mut found = None;
    for at in (0..image
        .len()
        .saturating_sub(pattern.len() * 2)
        .saturating_add(1))
        .step_by(2)
    {
        if matches(image, at, pattern) {
            if found.is_some() {
                return Err(Error::Ambiguous);
            }
            found = Some(at);
        }
    }
    found.ok_or(Error::UnknownLayout)
}

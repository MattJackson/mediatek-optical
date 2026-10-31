//! Read-only OEM code-layout contracts. Matches identify instructions and their
//! relationships, never a drive model or filename. Emission remains a caller policy.

mod arm;
mod auth;
mod caller;
mod caller_stack;
mod classic_speed;
mod command;
pub use command::CommandDispatch;
mod decoded;
mod dispatch;
mod dispatch_roots;
pub use dispatch::CommandScanner;
mod flow;
mod image;
pub use image::{Diagnostic, ImageAnalysis, Role};
mod ram;
mod ram_fill;
pub use ram::RamReferences;
mod response;
mod response_expr;
mod response_return;
pub use response::{ResponseCommit, ResponseIo};
mod legacy_di;
mod media;
mod switch;
mod uhd;
mod uhd_consumers;
mod uhd_control_tail;
mod uhd_di;
mod uhd_parameter;
mod vid;

pub use auth::{AuthCell, AuthCellVariant};
pub use caller::SavedLink;
pub use classic_speed::ClassicSpeed;
pub use legacy_di::LegacyStackDi;
pub use media::{MediaGate, MediaGateVariant};
pub use uhd::{C7Selection, UhdArea, UhdAreaContract, UhdAreas, UhdEdge, UhdHandling, UhdLiteral};
pub use uhd_consumers::{ClassicConsumer, ClassicConsumerKind};
pub use uhd_control_tail::LegacyControlTail;
pub use uhd_di::ClassicDi;
pub use uhd_parameter::{ClassicParameter, ClassicParameterVariant};
pub use vid::{VidGate, VidGateVariant};

#[cfg(test)]
mod classic_speed_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod uhd_tests;

/// A recognition failure; absence and conflicting evidence are distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::UnknownLayout => "mediatek.analysis.unknown_layout",
            Self::Ambiguous => "mediatek.analysis.ambiguous",
            Self::InvalidContract => "mediatek.analysis.invalid_contract",
            Self::Truncated => "mediatek.analysis.truncated",
        }
    }
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

fn conditional(image: &[u8], at: usize, condition: thumb_asm::Cond) -> Option<usize> {
    let ins = thumb_asm::isa::decode_at(image, at)?;
    if ins.mnemonic != "b" || ins.cond != Some(condition) {
        return None;
    }
    let target = ins.branch_target()? as usize;
    target
        .checked_add(2)
        .filter(|end| *end <= image.len())
        .map(|_| target)
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

mod uhd_position;
pub use uhd_position::ClassicPosition;

mod uhd_calibration;
pub use uhd_calibration::ClassicCalibration;

mod uhd_read_position;
pub use uhd_read_position::ClassicReadPosition;

mod uhd_position_setup;
pub use uhd_position_setup::ClassicPositionSetup;

mod speed_policy;
pub use speed_policy::{NativeSpeedPolicy, RequestedRateClamp};

#[cfg(test)]
mod speed_policy_tests;

mod uhd_completion;
pub use uhd_completion::ClassicReadCompletion;

mod uhd_keys;
pub use uhd_keys::{UhdKeyPath, UhdKeyWrapper};

mod uhd_reverse;
pub use uhd_reverse::LegacyReverse;

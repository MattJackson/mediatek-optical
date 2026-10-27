//! One immutable input and independently retained, lazily evaluated role outcomes.
use super::{
    AuthCell, ClassicSpeed, CommandDispatch, CommandScanner, Error, MediaGate, NativeSpeedPolicy,
    ResponseIo, UhdAreas, VidGate,
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Semantic role of retained recognition evidence; model labels never grant it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// Native consumer of command records and incoming CDB bytes.
    Scanner,
    /// Tables registered into the native scanner input array.
    Commands,
    /// Native response writer and committer.
    Response,
    /// Volume-ID producer and gate.
    Vid,
    /// Authentication scratch and class check.
    Authentication,
    /// Native media discriminator.
    Media,
    /// Native default and requested-rate policy.
    SpeedPolicy,
    /// Classic normalized read-speed selector.
    ClassicSpeed,
}
impl Role {
    /// Stable role key used in reports.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Scanner => "scanner",
            Self::Commands => "commands",
            Self::Response => "response",
            Self::Vid => "vid",
            Self::Authentication => "authentication",
            Self::Media => "media",
            Self::SpeedPolicy => "speed_policy",
            Self::ClassicSpeed => "classic_speed",
        }
    }
}
/// A role failure retained with its semantic context, rather than flattened to
/// a missing address. Its source digest belongs to the enclosing analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostic {
    /// Role whose contract was unavailable or conflicting.
    pub role: Role,
    /// Typed reason, including ambiguity versus absence.
    pub cause: Error,
}
impl core::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.role.key(), self.cause)
    }
}
impl std::error::Error for Diagnostic {}
impl crate::CodedError for Diagnostic {
    fn code(&self) -> &'static str {
        crate::CodedError::code(&self.cause)
    }
}

/// Source-bound analysis of one plaintext image, following the sibling Pioneer
/// model: identity/digest plus independent read-only facts and diagnostics.
/// This object never emits code and never turns marker evidence into permission
/// to modify. Callers still require the exact roles needed by each operation.
pub struct ImageAnalysis<'a> {
    image: &'a [u8],
    digest: [u8; 32],
    identity: OnceLock<Result<crate::image::ChipInfo, crate::image::ChipError>>,
    scanner: OnceLock<Result<CommandScanner, Error>>,
    commands: OnceLock<Result<CommandDispatch<'a>, Error>>,
    response: OnceLock<Result<ResponseIo<'a>, Error>>,
    vid: OnceLock<Result<VidGate<'a>, Error>>,
    auth: OnceLock<Result<AuthCell, Error>>,
    media: OnceLock<Result<MediaGate, Error>>,
    policy: OnceLock<Result<NativeSpeedPolicy, Error>>,
    classic_speed: OnceLock<Result<ClassicSpeed, Error>>,
    uhd: OnceLock<UhdAreas>,
}
impl<'a> ImageAnalysis<'a> {
    /// Retain the immutable source; individual roles are evaluated on demand.
    pub fn inspect(image: &'a [u8]) -> Self {
        Self {
            image,
            digest: Sha256::digest(image).into(),
            identity: OnceLock::new(),
            scanner: OnceLock::new(),
            commands: OnceLock::new(),
            response: OnceLock::new(),
            vid: OnceLock::new(),
            auth: OnceLock::new(),
            media: OnceLock::new(),
            policy: OnceLock::new(),
            classic_speed: OnceLock::new(),
            uhd: OnceLock::new(),
        }
    }
    /// Original plaintext source. Contract accessors never accept replacement bytes.
    pub fn image(&self) -> &'a [u8] {
        self.image
    }
    /// SHA-256 binding every retained outcome to this input.
    pub fn sha256(&self) -> [u8; 32] {
        self.digest
    }
    /// Boot-banner identity, independently retained even when roles are unavailable.
    pub fn identity(&self) -> Result<&crate::image::ChipInfo, &crate::image::ChipError> {
        self.identity
            .get_or_init(|| crate::image::detect_chip(self.image))
            .as_ref()
    }
    /// Connected command-record consumer and incoming CDB operand.
    pub fn scanner(&self) -> Result<&CommandScanner, Diagnostic> {
        outcome(
            self.scanner
                .get_or_init(|| CommandScanner::inspect(self.image)),
            Role::Scanner,
        )
    }
    /// Native registered command table graph, excluding orphan data tables.
    pub fn commands(&self) -> Result<&CommandDispatch<'a>, Diagnostic> {
        outcome(
            self.commands
                .get_or_init(|| CommandDispatch::inspect(self.image)),
            Role::Commands,
        )
    }
    /// Native response I/O and complete return protocol.
    pub fn response(&self) -> Result<&ResponseIo<'a>, Diagnostic> {
        outcome(
            self.response.get_or_init(|| {
                let commands = self
                    .commands
                    .get_or_init(|| CommandDispatch::inspect(self.image))
                    .as_ref()
                    .map_err(|error| *error)?;
                ResponseIo::from_dispatch(commands)
            }),
            Role::Response,
        )
    }
    /// Independently selected Volume-ID gate.
    pub fn vid(&self) -> Result<&VidGate<'a>, Diagnostic> {
        outcome(
            self.vid.get_or_init(|| VidGate::inspect(self.image)),
            Role::Vid,
        )
    }
    /// Native authentication preparation, reusing the retained VID selection.
    pub fn authentication(&self) -> Result<&AuthCell, Diagnostic> {
        outcome(
            self.auth.get_or_init(|| {
                let vid = self
                    .vid
                    .get_or_init(|| VidGate::inspect(self.image))
                    .as_ref()
                    .map_err(|error| *error)?;
                AuthCell::inspect(self.image, vid.producer_entry()?, vid.comparison())
            }),
            Role::Authentication,
        )
    }
    /// Native media role; descriptor candidates retain their limited meaning.
    pub fn media(&self) -> Result<&MediaGate, Diagnostic> {
        outcome(
            self.media.get_or_init(|| MediaGate::inspect(self.image)),
            Role::Media,
        )
    }
    /// Native read-speed producer/consumer policy.
    pub fn speed_policy(&self) -> Result<&NativeSpeedPolicy, Diagnostic> {
        outcome(
            self.policy
                .get_or_init(|| NativeSpeedPolicy::detect(self.image)),
            Role::SpeedPolicy,
        )
    }
    /// Classic read-speed selector.
    pub fn classic_speed(&self) -> Result<&ClassicSpeed, Diagnostic> {
        outcome(
            self.classic_speed
                .get_or_init(|| ClassicSpeed::detect(self.image)),
            Role::ClassicSpeed,
        )
    }
    /// Independent UHD areas, including each missing or conflicting outcome.
    pub fn uhd(&self) -> &UhdAreas {
        self.uhd.get_or_init(|| UhdAreas::inspect(self.image))
    }
}
fn outcome<T>(value: &Result<T, Error>, role: Role) -> Result<&T, Diagnostic> {
    value.as_ref().map_err(|cause| Diagnostic {
        role,
        cause: *cause,
    })
}

//! Stable identifiers for host diagnostics and translation keys.

/// A typed error with a stable, namespaced identifier.
///
/// Codes contain no runtime values. Match the error variant for parameters;
/// `Display` is diagnostic prose and may change. Wrapper errors retain their
/// own stage code; their typed causes describe the underlying failure.
pub trait CodedError {
    /// Stable identifier, such as `mediatek.receiver.changed`.
    fn code(&self) -> &'static str;
}

impl CodedError for crate::protocol::Incomplete {
    fn code(&self) -> &'static str {
        "mediatek.protocol.incomplete"
    }
}

impl CodedError for crate::UnknownChip {
    fn code(&self) -> &'static str {
        "mediatek.chip.unknown_label"
    }
}

#[cfg(feature = "drive")]
impl<E> CodedError for crate::drive::Error<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Transport(_) => "mediatek.drive.transport",
            Self::Short { .. } => "mediatek.drive.short",
            Self::Oversize(_) => "mediatek.drive.oversize",
        }
    }
}

#[cfg(feature = "enc")]
impl CodedError for crate::enc::LengthError {
    fn code(&self) -> &'static str {
        "mediatek.enc.length"
    }
}

#[cfg(feature = "image")]
impl CodedError for crate::image::ChipError {
    fn code(&self) -> &'static str {
        match self {
            Self::Undetectable => "mediatek.image.undetectable_chip",
        }
    }
}

#[cfg(feature = "image")]
impl CodedError for crate::image::cmac::CmacError {
    fn code(&self) -> &'static str {
        match self {
            Self::ImageTooSmall { .. } => "mediatek.cmac.image_too_small",
            Self::BadRange { .. } => "mediatek.cmac.bad_range",
        }
    }
}

#[cfg(feature = "image")]
impl CodedError for crate::update::PrepareError {
    fn code(&self) -> &'static str {
        match self {
            Self::ReceiverEntry => "mediatek.prepare.receiver_entry",
            Self::ReceiverContract => "mediatek.prepare.receiver_contract",
            #[cfg(all(feature = "drive", feature = "enc"))]
            Self::Layout(_) => "mediatek.prepare.layout",
            Self::Size(_) => "mediatek.prepare.size",
            Self::Integrity => "mediatek.prepare.integrity",
            Self::DriveRead => "mediatek.prepare.drive_read",
            Self::UnknownChip => "mediatek.prepare.unknown_chip",
            Self::UnknownDriveChip => "mediatek.prepare.unknown_drive_chip",
            Self::ChipMismatch { .. } => "mediatek.prepare.chip_mismatch",
            Self::InstalledMismatch => "mediatek.prepare.installed_mismatch",
            Self::UnknownInstalledFamily => "mediatek.prepare.unknown_installed_family",
            Self::UnknownTargetFamily => "mediatek.prepare.unknown_target_family",
            Self::FamilyMismatch { .. } => "mediatek.prepare.family_mismatch",
        }
    }
}

#[cfg(all(feature = "image", feature = "enc"))]
impl CodedError for crate::envelope::Error {
    fn code(&self) -> &'static str {
        match self {
            Self::Image(_) => "mediatek.envelope.image",
            Self::UnknownFraming => "mediatek.envelope.unknown_framing",
            Self::Ambiguous => "mediatek.envelope.ambiguous",
        }
    }
}

#[cfg(feature = "oem")]
impl CodedError for crate::oem::RebuildError {
    fn code(&self) -> &'static str {
        match self {
            Self::Size(_) => "mediatek.oem.size",
            Self::Chip(_) => "mediatek.oem.chip",
            Self::NoFactory(_) => "mediatek.oem.no_factory",
            Self::UnknownBootPage(_) => "mediatek.oem.unknown_boot_page",
            Self::Factory(_) => "mediatek.oem.factory",
        }
    }
}

#[cfg(feature = "drive")]
impl<E> CodedError for crate::receiver::Error<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Read(_) => "mediatek.receiver.read",
            Self::InvalidIdentity => "mediatek.receiver.invalid_identity",
            Self::Unknown => "mediatek.receiver.unknown",
            Self::Conflict => "mediatek.receiver.conflict",
            Self::Changed => "mediatek.receiver.changed",
            Self::UnknownEntry => "mediatek.receiver.unknown_entry",
        }
    }
}

#[cfg(all(feature = "drive", feature = "image"))]
impl<E> CodedError for crate::update::FlashError<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Entry(_) => "mediatek.flash.entry",
            Self::Transfer { .. } => "mediatek.flash.transfer",
            Self::Fault { .. } => "mediatek.flash.fault",
            Self::ReadyTimeout(_) => "mediatek.flash.ready_timeout",
            Self::Startup(_) => "mediatek.flash.startup",
            Self::Mismatch { .. } => "mediatek.flash.mismatch",
            Self::Incomplete { .. } => "mediatek.flash.incomplete",
        }
    }
}

#[cfg(all(feature = "drive", feature = "image"))]
impl<E> CodedError for crate::update::StartupError<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Identity(_) => "mediatek.startup.identity",
            Self::Read(_) => "mediatek.startup.read",
            Self::TargetMismatch => "mediatek.startup.target_mismatch",
        }
    }
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
impl<E> CodedError for crate::receiver::ExecuteError<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Receiver(_) => "mediatek.execute.receiver",
            Self::Flash(_) => "mediatek.execute.flash",
        }
    }
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
impl<E> CodedError for crate::receiver::reference::Error<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Analysis(_) => "mediatek.reference.analysis",
            Self::Binding(_) => "mediatek.reference.binding",
        }
    }
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
impl CodedError for crate::receiver::layout::Error {
    fn code(&self) -> &'static str {
        match self {
            Self::Alignment => "mediatek.layout.alignment",
            Self::Range => "mediatek.layout.range",
            Self::Conflict { .. } => "mediatek.layout.conflict",
            Self::MultipleDecryptions { .. } => "mediatek.layout.multiple_decryptions",
            Self::NoProgram => "mediatek.layout.no_program",
            Self::ImageSize => "mediatek.layout.image_size",
        }
    }
}

#[cfg(all(feature = "drive", feature = "image", feature = "enc"))]
impl<E> CodedError for crate::recovery::Error<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Receiver(_) => "mediatek.recovery.receiver",
            Self::Reference(_) => "mediatek.recovery.reference",
            Self::Read(_) => "mediatek.recovery.read",
            Self::Image(_) => "mediatek.recovery.image",
            Self::Flash(_) => "mediatek.recovery.flash",
            Self::Changed => "mediatek.recovery.changed",
            Self::Startup(_) => "mediatek.recovery.startup",
        }
    }
}

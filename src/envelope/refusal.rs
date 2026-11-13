//! Why an image is refused: the one reason vocabulary the codec, the
//! classifier and the planner share (public as `classify::Refusal`).

use crate::envelope::image::Family;
use crate::envelope::layout;
use crate::Chip;

/// Why an update was refused before any device command.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// No complete live entry profile was identified before preparation.
    ReceiverEntry,
    /// Decoder evidence does not yet establish an executable transfer contract,
    /// or the recognized contract does not accept this image (for example a
    /// required descriptor byte differs, or an active integrity range reaches
    /// a region the receiver deliberately preserves). It is also returned when
    /// a user-supplied reference names a different chip than the target image:
    /// that reference's receiver contract refuses the image, whereas a
    /// reference read from the drive reports `ChipMismatch` instead.
    ///
    /// `reason` tells the cases apart and says which input the refusal is
    /// about: the receiver (the live drive's code or the reference it was
    /// built from) or the image.
    ReceiverContract {
        /// Why the contract refused the image.
        reason: ContractReason,
    },
    /// The receiver's transfer layout is contradictory; no firmware was sent.
    #[cfg(all(feature = "drive", feature = "enc"))]
    Layout(LayoutError),
    /// The image is not [`layout::IMAGE_SIZE`] bytes.
    Size(usize),
    /// The image fails its AES-CMAC integrity table (including an entry whose
    /// `enabled` word is unrecognised, see [`crate::envelope::cmac::verify`]), or that table
    /// leaves no protected range that read-back can verify.
    Integrity,
    /// The image is a raw drive read: its boot page is the read-back mirror,
    /// and writing it would store that page in place of the boot page.
    DriveRead,
    /// The image names no supported chip.
    UnknownChip,
    /// The drive's boot banner names no supported chip generation.
    UnknownDriveChip,
    /// The image is for another chip than the drive's.
    ChipMismatch {
        /// The image's chip.
        image: Chip,
        /// The drive's chip.
        drive: Chip,
    },
    /// The installed firmware is not a complete image of the live drive: its
    /// size, identity descriptor or boot banner differ.
    InstalledMismatch,
    /// The installed firmware does not establish a hardware family.
    UnknownInstalledFamily,
    /// The image does not establish a hardware family.
    UnknownTargetFamily,
    /// The image is for other hardware than the installed firmware.
    FamilyMismatch {
        /// Family of the installed firmware.
        installed: Family,
        /// Family of the image.
        target: Family,
    },
}

/// Why [`Refusal::ReceiverContract`] refused an image.
///
/// Hosts must keep a wildcard arm; the set of reasons may grow. An unknown
/// reason blames neither the receiver nor the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContractReason {
    /// The receiver was built from a user-supplied reference whose chip
    /// differs from the image's. The update and recovery chip gates have
    /// already matched the image to the live drive, so the reference is for
    /// another chip than the drive: the reference is at fault.
    ReferenceChip,
    /// The receiver's decoder evidence does not establish an executable
    /// transfer contract (conflicting or incomplete decoder arguments, a
    /// scratch decoder without a recognized mixed contract, or a bulk decoder
    /// this crate cannot bind). This is a fact about the receiver code (the
    /// live drive's, or the reference's), not about the image.
    ReceiverEvidence,
    /// The recognized mixed contract requires a descriptor byte of the image
    /// to be `0xDE` and it is not. The image does not fit the receiver's
    /// contract; that blames the image only when the contract is
    /// authoritative for the drive (live code, or a bound Current reference).
    /// A user-supplied reference's contract comes from a file not matched to
    /// the drive, so either file may be at fault.
    DescriptorByte,
    /// An active integrity range of the image reaches a region the
    /// recognized receiver deliberately preserves. As for
    /// [`Self::DescriptorByte`], this blames the image only when the contract
    /// is authoritative for the drive.
    PreservedRange,
}

impl Refusal {
    /// The hardware-family gate's refusal in operator words: both families
    /// must be known and equal, and nothing overrides it. `None` for every
    /// refusal that is not a family gate.
    pub fn family_gate(&self) -> Option<String> {
        Some(match self {
            Self::FamilyMismatch { installed, target } => format!(
                "family mismatch: installed firmware is family {installed}, target is family \
                 {target} (a different board line; not update-compatible)"
            ),
            Self::UnknownInstalledFamily => "could not determine the installed firmware \
                 family (the pre-flash backup has no hardware configuration record to profile); \
                 flashing requires a known family"
                .to_string(),
            Self::UnknownTargetFamily => "could not determine the target firmware family \
                 (the image has no hardware configuration record to profile); flashing requires a \
                 known family"
                .to_string(),
            _ => return None,
        })
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReceiverEntry => f.write_str(
                "receiver entry profile is unknown; detect the live receiver before preparing",
            ),
            Self::ReceiverContract { .. } => f.write_str(
                "receiver transfer contract is incomplete or does not accept this image; \
                     no firmware was sent",
            ),
            #[cfg(all(feature = "drive", feature = "enc"))]
            Self::Layout(e) => write!(f, "receiver transfer layout is unsupported: {e}"),
            Self::Size(n) => write!(
                f,
                "image is {n} bytes; an update image is exactly {} bytes",
                layout::IMAGE_SIZE
            ),
            Self::Integrity => f.write_str(
                "image fails its AES-CMAC integrity check or has no verifiable protected range",
            ),
            Self::DriveRead => f.write_str(
                "image is a raw drive read (its boot page is the read-back copy), not a \
                 flashable image",
            ),
            Self::UnknownChip => f.write_str("image names no MT1959 or MT1939 chip"),
            Self::UnknownDriveChip => f.write_str(
                "could not read this drive's controller generation (MT1959/MT1939) from its \
                 boot banner",
            ),
            Self::ChipMismatch { image, drive } => write!(
                f,
                "image is {image} firmware but this drive is {drive} silicon — refusing to \
                 flash across chip generations"
            ),
            Self::InstalledMismatch => f.write_str(
                "installed firmware is not a complete image of the live drive (size, identity \
                 descriptor or boot banner differ)",
            ),
            Self::UnknownInstalledFamily => {
                f.write_str("could not determine the installed firmware family")
            }
            Self::UnknownTargetFamily => {
                f.write_str("could not determine the target firmware family")
            }
            Self::FamilyMismatch { installed, target } => write!(
                f,
                "family mismatch: installed firmware is family {installed}, target is family \
                 {target}"
            ),
        }
    }
}

impl std::error::Error for Refusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(all(feature = "drive", feature = "enc"))]
            Self::Layout(source) => Some(source),
            _ => None,
        }
    }
}

/// Contradictory or unsupported receiver operations cannot supply a wire plan.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::classify::LayoutError) -> u8 { match e { mediatek_optical::classify::LayoutError::Alignment { .. } => 0, mediatek_optical::classify::LayoutError::Range { .. } => 1, mediatek_optical::classify::LayoutError::Conflict { .. } => 2, mediatek_optical::classify::LayoutError::MultipleDecryptions { .. } => 3, mediatek_optical::classify::LayoutError::NoProgram { .. } => 4, mediatek_optical::classify::LayoutError::ImageSize { .. } => 5, } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LayoutError {
    /// Canonical images and AES transforms require complete blocks.
    Alignment,
    /// An operation escapes the supplied image or has an empty/reversed range.
    Range,
    /// The same block is required in both ciphertext and plaintext form.
    Conflict {
        /// Byte offset of the conflicting AES block.
        block: usize,
    },
    /// The receiver would decrypt the same block more than once.
    MultipleDecryptions {
        /// Byte offset of the block requiring unsupported nested encoding.
        block: usize,
    },
    /// No program operation was supplied, so there is no installed-image proof.
    NoProgram,
    /// Encoding was requested for a different-sized image.
    ImageSize,
}

impl core::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Alignment => f.write_str("receiver encoding requires complete AES blocks"),
            Self::Range => f.write_str("receiver operation has an empty or out-of-bounds range"),
            Self::Conflict { block } => write!(f, "conflicting wire encodings at {block:#x}"),
            Self::MultipleDecryptions { block } => write!(f, "repeated AES decoding at {block:#x}"),
            Self::NoProgram => f.write_str("receiver layout contains no programming operation"),
            Self::ImageSize => f.write_str("image size differs from the receiver layout"),
        }
    }
}

impl std::error::Error for LayoutError {}

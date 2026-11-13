//! The MT19xx model gate. An image of the drive's own model is admitted as it
//! always has been. Another model (a crossflash) is admitted only when the
//! image and the drive are the same hardware family — [`family`], a content
//! hash of `chip·platform·loader·interface·medium·bd_write` — which the
//! firmware proves is its finest hardware distinction (14x/16x/UHD within a
//! family are firmware limits, not hardware; per-drive calibration lives on the
//! drive and a crossflash does not overwrite it). Nothing here can be switched
//! on by a caller.
//!
//! [`family`]: crate::envelope::family

use crate::envelope::image::{detect_chip, family, ChipError, Family};
use crate::envelope::layout;
use crate::{Identity, Refusal};

/// Length of the boot-banner prefix at [`layout::BANNER`] a crossflash keeps.
pub const BANNER_LEN: usize = 16;

/// The identity descriptor's platform code (`+0x46`, e.g. `JB7`): one of the
/// hardware fields the family hashes, and the one the boot banner does not
/// carry (BU3 and BU9 share a banner). The descriptor holds it, so a crossflash
/// can tell two families apart at the plan without reading the whole firmware.
const DESCRIPTOR_PLATFORM: core::ops::Range<usize> = 0x46..0x4C;

/// The refusal when the pre-flash backup would not re-admit as a crossflash
/// once the target has booted: the crossflash is not reversible.
pub const BACKUP_NOT_FLASHABLE_BACK: &str = "your backup could not be flashed back; refusing";

fn trim_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string()
}

/// Printable ASCII kept, everything else (terminal escapes a drive could
/// return included) shown as `.`.
fn sanitize_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            if ('\u{20}'..='\u{7e}').contains(&c) {
                c
            } else {
                '.'
            }
        })
        .collect()
}

/// What the gates know about one firmware build: an image, a backup, or the
/// live drive's identity descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Build {
    /// Descriptor vendor; empty without a tagged descriptor.
    pub vendor: String,
    /// The model the same-model gate compares.
    pub product: String,
    /// Descriptor revision.
    pub revision: String,
    /// The hardware family, for a complete image or backup. `None` for the
    /// live drive, whose descriptor names its `platform` and `banner` but not
    /// the full family (that needs a complete read).
    pub family: Option<Family>,
    /// The descriptor platform code; empty when there is no descriptor.
    pub platform: String,
    /// The boot-banner prefix.
    pub banner: [u8; BANNER_LEN],
}

impl Build {
    /// The facts of a complete image. `product` is the model the same-model
    /// gate has always compared; `vendor` is empty without a tagged descriptor.
    pub fn of_image(image: &[u8]) -> Result<Self, ChipError> {
        let chip = detect_chip(image)?;
        let mut banner = [0; BANNER_LEN];
        if let Some(bytes) = layout::BANNER.of(image) {
            banner.copy_from_slice(&bytes[..BANNER_LEN]);
        }
        let platform = layout::DESCRIPTOR
            .of(image)
            .map(|d| trim_ascii(&d[DESCRIPTOR_PLATFORM]))
            .unwrap_or_default();
        Ok(Self {
            vendor: if chip.descriptor_present {
                chip.vendor
            } else {
                String::new()
            },
            product: chip.model,
            revision: chip.rev,
            family: family(image),
            platform,
            banner,
        })
    }

    /// The live drive's facts from its identity descriptor. The full family
    /// needs a complete read, so it is `None`; the descriptor's `platform` and
    /// the `banner` carry the hardware fields the plan gates a crossflash on.
    pub fn of_drive(live: &Identity) -> Self {
        let descriptor = live.descriptor_bytes();
        let text = |range: core::ops::Range<usize>| {
            if live.has_descriptor() {
                trim_ascii(&descriptor[range])
            } else {
                String::new()
            }
        };
        let mut banner = [0; BANNER_LEN];
        banner.copy_from_slice(&live.banner_bytes()[..BANNER_LEN]);
        Self {
            vendor: text(0x00..0x08),
            product: live.descriptor_model().to_owned(),
            revision: text(0x18..0x1C),
            family: None,
            platform: text(DESCRIPTOR_PLATFORM),
            banner,
        }
    }

    /// `vendor product revision`, safe to print.
    pub fn label(&self) -> String {
        sanitize_ascii(&format!(
            "{} {} {}",
            self.vendor, self.product, self.revision
        ))
    }

    /// `vendor product`, safe to print.
    pub fn model(&self) -> String {
        sanitize_ascii(&format!("{} {}", self.vendor, self.product))
    }
}

/// What the model gate admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The image is the drive's model: the gate as it has always been.
    SameModel,
    /// Another model of the drive's hardware family.
    Crossflash,
}

/// Why two builds differ in hardware, at the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HardwareDifference {
    /// Both families are known and differ (the drive's, then the image's).
    Family {
        /// The drive's family.
        drive: Family,
        /// The image's family.
        image: Family,
    },
    /// Only the drive's descriptor is known: its platform or boot banner
    /// differs from the image's (the chip is already matched).
    Descriptor {
        /// The image's descriptor platform code.
        image_platform: String,
        /// The image's boot-banner prefix.
        image_banner: [u8; BANNER_LEN],
        /// The drive's descriptor platform code.
        drive_platform: String,
        /// The drive's boot-banner prefix.
        drive_banner: [u8; BANNER_LEN],
    },
}

fn banner_text(banner: &[u8; BANNER_LEN]) -> String {
    sanitize_ascii(String::from_utf8_lossy(banner).trim())
}

impl core::fmt::Display for HardwareDifference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Family { drive, image } => write!(
                f,
                "this image is for a different hardware family ({drive} vs {image}); refusing to flash"
            ),
            Self::Descriptor {
                image_platform,
                image_banner,
                drive_platform,
                drive_banner,
            } => write!(
                f,
                "this image is for a different hardware family than this drive (image platform {:?} \
                 banner {:?} vs drive platform {:?} banner {:?}); refusing to flash",
                image_platform,
                banner_text(image_banner),
                drive_platform,
                banner_text(drive_banner),
            ),
        }
    }
}

/// Why the model gate refused.
///
/// Hosts must keep a wildcard arm; the set of reasons may grow.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelRefusal {
    /// The drive reports no INQUIRY product.
    UnknownDrive,
    /// The image is another model and no crossflash applies.
    WrongModel {
        /// The image's model.
        image_model: String,
        /// The drive's INQUIRY product.
        product: String,
    },
    /// The INQUIRY product and the identity descriptor's model disagree.
    InconsistentIdentity {
        /// The drive's INQUIRY product.
        product: String,
        /// The descriptor's model.
        descriptor_model: String,
    },
    /// A family the crossflash gate needs is unknown.
    UnknownFamily(Refusal),
    /// The plan found different hardware: the update-compatibility refusal a
    /// host reports with both models.
    Hardware {
        /// The drive's INQUIRY product.
        product: String,
        /// The image's model.
        target_model: String,
        /// What differs.
        difference: Box<HardwareDifference>,
    },
    /// The installed and target families differ once the backup is read.
    FamilyMismatch {
        /// The installed (backup) family.
        installed: Family,
        /// The target family.
        target: Family,
    },
    /// The boot banners differ (or are not MT19 banners) once the backup is read.
    BootBanner {
        /// The installed (backup) banner prefix.
        installed: [u8; BANNER_LEN],
        /// The target banner prefix.
        target: [u8; BANNER_LEN],
    },
    /// The backup would not re-admit as a crossflash once the target runs;
    /// the cause, when the reverse decision itself refused.
    NotReversible(Option<Box<ModelRefusal>>),
    /// The backup's identity no longer gives the plan's decision.
    Changed,
}

impl core::fmt::Display for ModelRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownDrive => f.write_str(
                "drive model is unknown (empty INQUIRY product) — refusing to flash \
                 without confirming the image matches this drive",
            ),
            Self::WrongModel {
                image_model,
                product,
            } => write!(
                f,
                "image is built for model {image_model:?} but this drive reports \
                 {product:?} — refusing to flash a wrong-model image (pass \
                 a compatible image)"
            ),
            Self::InconsistentIdentity {
                product,
                descriptor_model,
            } => write!(
                f,
                "drive identity is inconsistent: INQUIRY reports {product:?} but its identity \
                 descriptor reads {:?} — refusing to flash another model",
                sanitize_ascii(descriptor_model)
            ),
            Self::UnknownFamily(refusal) => {
                f.write_str(&refusal.family_gate().unwrap_or_else(|| {
                    "could not determine the firmware family; flashing requires a known family"
                        .to_string()
                }))
            }
            Self::Hardware { difference, .. } => write!(f, "{difference}"),
            Self::FamilyMismatch { installed, target } => write!(
                f,
                "{}",
                HardwareDifference::Family {
                    drive: *installed,
                    image: *target
                }
            ),
            Self::BootBanner { installed, target } => write!(
                f,
                "boot banner differs: installed {:?}, target {:?} — refusing to crossflash across \
                 boot loaders",
                String::from_utf8_lossy(installed),
                String::from_utf8_lossy(target)
            ),
            Self::NotReversible(_) => f.write_str(BACKUP_NOT_FLASHABLE_BACK),
            Self::Changed => f.write_str(
                "drive changed between plan and backup: the backup's identity no longer gives \
                 the plan's model decision — refusing to flash",
            ),
        }
    }
}

impl std::error::Error for ModelRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReversible(Some(cause)) => Some(cause.as_ref()),
            _ => None,
        }
    }
}

/// Today's model test: the image's model contains the drive's product.
fn same_model(image_model: &str, product: &str) -> bool {
    image_model
        .to_ascii_uppercase()
        .contains(&product.to_ascii_uppercase())
}

/// Whether `image_model` is the drive's own model (the same-model fast path).
pub fn is_same_model(image_model: &str, drive_product: &str) -> bool {
    let product = drive_product.trim();
    !product.is_empty() && same_model(image_model, product)
}

/// The model-only decision: an unknown drive model or a different one is
/// refused. Backups use it.
pub fn decide_model(image_model: &str, drive_product: &str) -> Result<(), ModelRefusal> {
    let product = drive_product.trim();
    if product.is_empty() {
        return Err(ModelRefusal::UnknownDrive);
    }
    if same_model(image_model, product) {
        return Ok(());
    }
    Err(ModelRefusal::WrongModel {
        image_model: image_model.to_owned(),
        product: product.to_owned(),
    })
}

/// The image↔drive model decision before any backup, against the live
/// identity descriptor. A crossflash is gated on the hardware family: when the
/// drive's family is known (a backup built it) on family equality, and at the
/// plan — where the drive is only its descriptor — on the family fields the
/// descriptor carries (platform and boot banner; the chip is already matched by
/// [`crate::classify::check`]). The full family is re-checked once the backup
/// is read ([`decide_authorized`]). An unknown drive model, an inconsistent
/// identity, an identity-less image, an unknown or different family is refused.
pub fn decide_plan(
    drive_product: &str,
    live: &Build,
    target: &Build,
) -> Result<Verdict, ModelRefusal> {
    let product = drive_product.trim();
    if product.is_empty() {
        return Err(ModelRefusal::UnknownDrive);
    }
    if same_model(&target.product, product) {
        return Ok(Verdict::SameModel);
    }
    // An identity-less image is refused as a wrong-model image, exactly as
    // before crossflash existed.
    if target.product.is_empty() {
        return Err(ModelRefusal::WrongModel {
            image_model: target.product.clone(),
            product: product.to_owned(),
        });
    }
    // The INQUIRY product and the identity descriptor's model are the same
    // string formatted differently (INQUIRY trims the vendor prefix and
    // padding): the descriptor model contains the INQUIRY product.
    if live.product.is_empty() || !same_model(&live.product, product) {
        return Err(ModelRefusal::InconsistentIdentity {
            product: product.to_owned(),
            descriptor_model: live.product.clone(),
        });
    }
    let Some(image_family) = target.family else {
        return Err(ModelRefusal::UnknownFamily(Refusal::UnknownTargetFamily));
    };
    let hardware = |difference| ModelRefusal::Hardware {
        product: product.to_owned(),
        target_model: target.product.clone(),
        difference: Box::new(difference),
    };
    match live.family {
        Some(drive_family) if drive_family != image_family => {
            return Err(hardware(HardwareDifference::Family {
                drive: drive_family,
                image: image_family,
            }));
        }
        Some(_) => {}
        // Only the descriptor is known: refuse a differing platform or boot
        // banner. A same-platform, same-banner image of a different family is
        // admitted now and caught by the exact family gate once the backup is
        // read.
        None if live.platform != target.platform || live.banner != target.banner => {
            return Err(hardware(HardwareDifference::Descriptor {
                image_platform: target.platform.clone(),
                image_banner: target.banner,
                drive_platform: live.platform.clone(),
                drive_banner: live.banner,
            }));
        }
        None => {}
    }
    Ok(Verdict::Crossflash)
}

/// The same decision once the backup is read, with the backup as the installed
/// build: [`decide_plan`], then both families must be known and equal, and the
/// boot banners equal MT19 banners.
pub fn decide_authorized(
    drive_product: &str,
    installed: &Build,
    target: &Build,
) -> Result<Verdict, ModelRefusal> {
    let verdict = decide_plan(drive_product, installed, target)?;
    if verdict != Verdict::Crossflash {
        return Ok(verdict);
    }
    match (installed.family, target.family) {
        (None, _) => return Err(ModelRefusal::UnknownFamily(Refusal::UnknownInstalledFamily)),
        (_, None) => return Err(ModelRefusal::UnknownFamily(Refusal::UnknownTargetFamily)),
        (Some(installed), Some(target)) if installed != target => {
            return Err(ModelRefusal::FamilyMismatch { installed, target })
        }
        (Some(_), Some(_)) => {}
    }
    if installed.banner != target.banner || !installed.banner.starts_with(b"MT19") {
        return Err(ModelRefusal::BootBanner {
            installed: installed.banner,
            target: target.banner,
        });
    }
    Ok(verdict)
}

/// The backup must stay flashable once the drive runs the target: the
/// decision with the two swapped must re-admit as a crossflash.
pub fn decide_rollback(installed: &Build, target: &Build) -> Result<(), ModelRefusal> {
    let back = decide_authorized(&target.product, target, installed)
        .map_err(|cause| ModelRefusal::NotReversible(Some(Box::new(cause))))?;
    if back != Verdict::Crossflash {
        return Err(ModelRefusal::NotReversible(None));
    }
    Ok(())
}

/// The plan-time verdict must still hold once the backup is read.
pub fn ensure_unchanged(plan: Verdict, now: Verdict) -> Result<(), ModelRefusal> {
    if plan != now {
        return Err(ModelRefusal::Changed);
    }
    Ok(())
}

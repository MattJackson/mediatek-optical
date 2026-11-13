//! The drive's installed firmware as classification evidence.

use crate::envelope::image::{family, Family};
use crate::envelope::layout;
use crate::{Identity, Refusal};

/// The drive's installed firmware, bound to its live identity.
#[derive(Clone, Debug)]
pub struct InstalledFirmware {
    identity: Identity,
    family: Option<Family>,
}

impl InstalledFirmware {
    /// Bind `image`, a complete read of the drive's firmware or the image
    /// rebuilt from one, to the drive's live `identity`.
    ///
    /// Fails with [`Refusal::InstalledMismatch`] unless the image is
    /// [`layout::IMAGE_SIZE`] bytes and holds the identity descriptor (when
    /// the identity has one) and the boot banner (when the identity read one)
    /// the drive reports; at least one of them must be present. All
    /// [`layout::DESCRIPTOR`] bytes must equal the live descriptor: a capture
    /// and the live read come from the same programmed flash, so any
    /// difference, including a short live descriptor that
    /// [`Identity::parse`] zero-pads, is refused.
    pub fn new(identity: Identity, image: &[u8]) -> Result<Self, Refusal> {
        if image.len() != layout::IMAGE_SIZE {
            return Err(Refusal::InstalledMismatch);
        }
        let descriptor = identity
            .has_descriptor()
            .then(|| layout::DESCRIPTOR.of(image) == Some(&identity.descriptor_bytes()[..]));
        let banner = (!identity.banner().is_empty())
            .then(|| layout::BANNER.of(image) == Some(&identity.banner_bytes()[..]));
        match (descriptor, banner) {
            (None, None) | (Some(false), _) | (_, Some(false)) => Err(Refusal::InstalledMismatch),
            _ => Ok(Self {
                family: family(image),
                identity,
            }),
        }
    }

    /// The live identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The installed firmware's hardware family, when it has one.
    pub fn family(&self) -> Option<Family> {
        self.family
    }
}

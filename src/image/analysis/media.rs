use super::{conditional, half, unique, Error};

const EXPLICIT: &[(u16, u16)] = &[
    (0x2801, 0xffff),
    (0xd100, 0xff00),
    (0x79d0, 0xffff),
    (0x2803, 0xffff),
    (0xd100, 0xff00),
    (0x7808, 0xffff),
    (0x2800, 0xffff),
    (0xd100, 0xff00),
    (0x79d0, 0xffff),
    (0x2802, 0xffff),
    (0xd000, 0xff00),
];
const DESCRIPTOR: &[(u16, u16)] = &[
    (0x780a, 0xffff),
    (0x2501, 0xffff),
    (0x4900, 0xff00),
    (0x2a00, 0xffff),
    (0xb080, 0xff80),
    (0xd102, 0xffff),
    (0x798a, 0xffff),
    (0x2a00, 0xffff),
    (0xd000, 0xff00),
];

/// The two positively recognized media-control instruction layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaGateVariant {
    /// Independent native UHD and BD class checks.
    Explicit,
    /// Shared descriptor candidate. Its BD/UHD protocol role is not established.
    Descriptor,
}

/// Source-bound landmarks; finding a media control does not imply an unlocking effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaGate {
    variant: MediaGateVariant,
    anchor: usize,
    bd_site: usize,
    uhd_site: Option<usize>,
    deny: usize,
    frame: Option<u16>,
}

impl MediaGate {
    /// Recognize the explicit layout first, preserving established selection;
    /// ambiguity never falls back to another grammar.
    pub fn inspect(image: &[u8]) -> Result<Self, Error> {
        match unique(image, EXPLICIT) {
            Ok(a) => {
                if conditional(image, a + 2, thumb_asm::Cond::Ne) != Some(a + 10) {
                    return Err(Error::InvalidContract);
                }
                let accept = conditional(image, a + 20, thumb_asm::Cond::Eq)
                    .ok_or(Error::InvalidContract)?;
                if conditional(image, a + 14, thumb_asm::Cond::Ne) != Some(accept) {
                    return Err(Error::InvalidContract);
                }
                let deny =
                    conditional(image, a + 8, thumb_asm::Cond::Ne).ok_or(Error::InvalidContract)?;
                Ok(Self {
                    variant: MediaGateVariant::Explicit,
                    anchor: a,
                    bd_site: a + 16,
                    uhd_site: Some(a + 4),
                    deny,
                    frame: None,
                })
            }
            Err(Error::UnknownLayout) => {
                let a = unique(image, DESCRIPTOR)?;
                if !super::matches(
                    image,
                    a + 0x40,
                    &[(0x2201, 0xffff), (0x216f, 0xffff), (0x2005, 0xffff)],
                ) {
                    return Err(Error::InvalidContract);
                }
                let frame = half(image, a + 8).ok_or(Error::Truncated)?;
                Ok(Self {
                    variant: MediaGateVariant::Descriptor,
                    anchor: a,
                    bd_site: a + 6,
                    uhd_site: None,
                    deny: a + 0x40,
                    frame: Some(frame),
                })
            }
            Err(e) => Err(e),
        }
    }
    /// Recognized OEM grammar.
    pub fn variant(&self) -> MediaGateVariant {
        self.variant
    }
    /// Signature anchor in the original input.
    pub fn anchor(&self) -> usize {
        self.anchor
    }
    /// Whole-instruction native BD-control site, only when that role is proven.
    /// A descriptor-pattern match alone does not establish a BD discriminator.
    pub fn bd_site(&self) -> Option<usize> {
        (self.variant == MediaGateVariant::Explicit).then_some(self.bd_site)
    }
    /// Native UHD-control site, when its separate role is proven.
    pub fn uhd_site(&self) -> Option<usize> {
        self.uhd_site
    }
    /// OEM refuse continuation.
    pub fn deny(&self) -> usize {
        self.deny
    }
    /// Descriptor layout's displaced stack reservation instruction.
    pub fn frame_instruction(&self) -> Option<u16> {
        self.frame
    }
}

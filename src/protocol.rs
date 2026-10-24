//! Validated live MT19 boot signature, separate from update receiver detection.
use crate::{Chip, Identity};
/// Required response bytes were not returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incomplete;
/// A complete boot-banner signature. It does not prove update support or mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    identity: Identity,
}
impl Evidence {
    /// Parse the boot label at the start of a complete 32-byte ROM window.
    /// Bytes after its NUL terminator are firmware instructions, not string padding.
    /// Names and descriptor labels do not select a chip.
    pub fn parse(inquiry: &[u8], banner: &[u8]) -> Result<Option<Self>, Incomplete> {
        if inquiry.len() < crate::INQUIRY_LEN || banner.len() != 32 {
            return Err(Incomplete);
        }
        if inquiry[0] & 0x1f != 5
            || &banner[..4] != b"MT19"
            || &banner[6..12] != b" Boot "
            || Chip::from_digits(banner[4], banner[5]).is_none()
        {
            return Ok(None);
        }
        let end = banner.iter().position(|b| *b == 0).unwrap_or(banner.len());
        if end <= 12 || !banner[..end].iter().all(|b| (0x20..=0x7e).contains(b)) {
            return Ok(None);
        }
        Ok(Some(Self {
            identity: Identity::parse(inquiry, banner, &[]).ok_or(Incomplete)?,
        }))
    }
    /// Parsed identity with a chip established by the boot signature.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

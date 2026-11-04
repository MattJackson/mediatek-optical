//! Source-bound follow-on selector for a legacy controller-word writer.
//! This contract describes code only, without assigning hardware meaning.
use super::{Error, SavedLink, UhdArea, UhdAreaContract, UhdAreas};

/// Original selector and native clear/set continuations for controller bit 10.
#[derive(Debug, Clone)]
pub struct LegacyControlTail {
    /// First replaced operation.
    pub site: usize,
    /// Original operations and conditional branch.
    pub original: Vec<u8>,
    /// Bound media-state byte address.
    pub state: u32,
    /// Native bit-clear continuation.
    pub accept: usize,
    /// Native bit-set continuation.
    pub reject: usize,
    /// Operations preceding the conditional branch, including its CMP and load.
    pub replay: Vec<u16>,
    /// Parent stack/link contract shared with the primary selector.
    pub caller: SavedLink,
}

// A deliberately narrow positive grammar, including all code between the
// concrete R1 base load and the primary selector and both tail destinations.
// Literal contents are checked separately; fixed PC-relative displacements
// and branches are part of this particular observed layout.
const PREFIX: &[u8] = &[
    0x31, 0x49, 0x40, 0x31, 0x0b, 0x6b, 0x01, 0x24, 0x24, 0x06, 0xa3, 0x43, 0x0b, 0x63, 0x2e, 0x4e,
    0x33, 0x68, 0x30, 0x24, 0xa3, 0x43, 0x20, 0x33, 0x33, 0x60, 0x73, 0x68, 0x22, 0x24, 0xa3, 0x43,
    0x73, 0x60, 0x3f, 0x4b, 0x1c, 0x68, 0x01, 0x26, 0x76, 0x04, 0xb4, 0x43, 0x1c, 0x60, 0x24, 0x4d,
    0x2c, 0x78, 0x05, 0x25, 0x2d, 0x04, 0xe4, 0x07, 0x00, 0x2c, 0x1c, 0x68, 0x02, 0xd0, 0xac, 0x43,
    0x75, 0x00, 0x02, 0xe0, 0xac, 0x43, 0x01, 0x25, 0x2d, 0x04, 0x64, 0x19, 0x1c, 0x60, 0x35, 0x4c,
    0x35, 0x4d, 0x00, 0x28, 0x6a, 0xd1, 0x1c, 0x4e, 0x70, 0x68, 0x0d, 0x27, 0xb8, 0x43, 0x70, 0x60,
    0x70, 0x68, 0x28, 0x40, 0x70, 0x60, 0xb0, 0x68, 0x20, 0x40, 0xb0, 0x60, 0x23, 0x4e, 0x37, 0x78,
    0xc8, 0x20, 0xb8, 0x43, 0x5b, 0xd1, 0x08, 0x6b, 0xf0, 0x27, 0xb8, 0x43, 0x6a, 0xe0,
];
const TAIL: &[u8] = &[
    0x30, 0x78, 0x80, 0x09, 0x03, 0x28, 0x04, 0xd1, 0x08, 0x6b, 0xf0, 0x27, 0xb8, 0x43, 0x30, 0x30,
    0x09, 0xe0, 0x30, 0x78, 0x80, 0x09, 0x01, 0x28, 0x96, 0xd0, 0x08, 0x6b, 0xf0, 0x27, 0xb8, 0x43,
    0x40, 0x30, 0xc0, 0x27, 0x38, 0x43, 0x08, 0x63, 0x30, 0x78, 0x80, 0x09, 0x03, 0x28, 0x13, 0xd1,
    0x30, 0x78, 0xc8, 0x26, 0x86, 0x43, 0x01, 0x20, 0x80, 0x02, 0x00, 0x2e, 0x0e, 0x6b, 0x02, 0xd1,
    0x86, 0x43, 0x0e, 0x63, 0x01, 0xe0, 0x30, 0x43, 0x08, 0x63,
];
fn literal(image: &[u8], at: usize) -> Option<u32> {
    let op = u16::from_le_bytes(image.get(at..at + 2)?.try_into().ok()?);
    if op & 0xf800 != 0x4800 {
        return None;
    }
    let p = ((at + 4) & !3).checked_add(usize::from(op & 255) * 4)?;
    Some(u32::from_le_bytes(image.get(p..p + 4)?.try_into().ok()?))
}
impl LegacyControlTail {
    /// Bind only the positively recognized legacy primary and its same-function tail.
    /// Unknown layouts, modified instructions and inconsistent state/base refuse.
    pub fn detect(image: &[u8], primary: &UhdAreaContract, state: u32) -> Result<Self, Error> {
        if primary.area() != UhdArea::ControlField
            || primary.selects_c7() != Some(false)
            || primary.variant() != "classic_register_variant"
        {
            return Err(Error::UnknownLayout);
        }
        if UhdAreas::inspect(image).area(UhdArea::ControlField)? != primary {
            return Err(Error::InvalidContract);
        }
        let gate = primary.selection().ok_or(Error::InvalidContract)?;
        let start = primary.site().checked_sub(0x6c).ok_or(Error::Truncated)?;
        let tail = primary.site().checked_add(0xc2).ok_or(Error::Truncated)?;
        let site = primary.site().checked_add(0xf6).ok_or(Error::Truncated)?;
        if image.get(start..start + PREFIX.len()) != Some(PREFIX)
            || image.get(tail..tail + TAIL.len()) != Some(TAIL)
            || gate.site() != primary.site() + 6
            || gate.accept() != primary.site() + 10
            || literal(image, start) != Some(0x04208200)
            || literal(image, primary.site()) != Some(state)
            || primary.literals().first().map(|v| v.value) != Some(state)
        {
            return Err(Error::InvalidContract);
        }
        let primary_caller = SavedLink::detect(image, gate.site())?;
        let caller = SavedLink::detect(image, site)?;
        if primary_caller.entry() != caller.entry()
            || primary_caller.stack_bytes() != caller.stack_bytes()
        {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            site,
            original: image[site..site + 12].to_vec(),
            state,
            accept: site + 12,
            reject: site + 18,
            replay: vec![0x4386, 0x2001, 0x0280, 0x2e00, 0x6b0e],
            caller,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut image = vec![0xff; 0x40000];
        let part =
            include_bytes!("../../../tests/fixtures/analysis/uhd-control-tail/c88a-033800.bin");
        image[0x33800..0x34000].copy_from_slice(part);
        image
    }
    #[test]
    fn binds_source_tail_and_refuses_mutations() {
        let image = fixture();
        let areas = UhdAreas::inspect(&image);
        let primary = areas.area(UhdArea::ControlField).unwrap();
        let state = 0x01ff9def;
        let x = LegacyControlTail::detect(&image, primary, state).unwrap();
        assert_eq!((x.site, x.accept, x.reject), (0x33b0a, 0x33b16, 0x33b1c));
        assert_eq!(x.replay, [0x4386, 0x2001, 0x0280, 0x2e00, 0x6b0e]);
        for i in [
            0x339a8, 0x33a70, 0x33aa4, 0x33ad6, 0x33b0a, 0x33b16, 0x33b1c,
        ] {
            let mut bad = image.clone();
            bad[i] ^= 1;
            assert!(
                LegacyControlTail::detect(&bad, primary, state).is_err(),
                "mutation {i:x}"
            );
        }
        assert!(LegacyControlTail::detect(&image, primary, state ^ 1).is_err());
    }
}

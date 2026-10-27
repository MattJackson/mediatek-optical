//! Native ARM byte-table switch called from Thumb code.
use super::Error;
use crate::compiler::ARM_BYTE_SWITCH as BODY;
use thumb_asm::isa::decode_at;
/// Volatile registers actually changed by this complete native helper.
/// It consumes r3 and r12; BLX itself replaces LR. Other arguments survive.
pub(super) const SWITCH_CLOBBERS: u16 = (1 << 3) | (1 << 12) | (1 << 14);
pub(super) const ORDINARY_CLOBBERS: u16 =
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 12) | (1 << 14);
pub(super) fn clobbers(is_switch: bool) -> u16 {
    if is_switch {
        SWITCH_CLOBBERS
    } else {
        ORDINARY_CLOBBERS
    }
}
/// Ordered case targets followed by the default, or None for an ordinary call.
pub(super) fn targets(image: &[u8], pc: usize) -> Result<Option<Vec<usize>>, Error> {
    let ins = decode_at(image, pc).ok_or(Error::Truncated)?;
    if ins.mnemonic != "blx" {
        return Ok(None);
    }
    let Some(target) = ins.branch_target().map(|t| t as usize) else {
        return Ok(None);
    };
    if image.get(target..target + BODY.len()) != Some(BODY) {
        return Ok(None);
    }
    let table = pc + ins.len();
    let count = *image.get(table).ok_or(Error::Truncated)? as usize;
    if !(1..=32).contains(&count) {
        return Err(Error::InvalidContract);
    }
    let mut targets = Vec::new();
    for &offset in image
        .get(table + 1..table + count + 2)
        .ok_or(Error::Truncated)?
    {
        let address = ((table | 1) + offset as usize * 2) & !1;
        if address + 2 > image.len() {
            return Err(Error::Truncated);
        }
        targets.push(address);
    }
    Ok(Some(targets))
}

//! Native ARM byte-table switch called from Thumb code.
use super::Error;
use thumb_asm::isa::decode_at;
const BODY: [u8; 24] = [
    0x01, 0xc0, 0x5e, 0xe5, 0x0c, 0x00, 0x53, 0xe1, 0x03, 0x30, 0xde, 0x37, 0x0c, 0x30, 0xde, 0x27,
    0x83, 0xc0, 0x8e, 0xe0, 0x1c, 0xff, 0x2f, 0xe1,
];
/// Ordered case targets followed by the default, or None for an ordinary call.
pub(super) fn targets(image: &[u8], pc: usize) -> Result<Option<Vec<usize>>, Error> {
    let ins = decode_at(image, pc).ok_or(Error::Truncated)?;
    if ins.mnemonic != "blx" {
        return Ok(None);
    }
    let Some(target) = ins.branch_target().map(|t| t as usize) else {
        return Ok(None);
    };
    if image.get(target..target + BODY.len()) != Some(BODY.as_slice()) {
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

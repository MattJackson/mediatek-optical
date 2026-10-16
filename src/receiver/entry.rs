//! Bounded static evidence for BOOT PREPARE handling.
//!
//! This recognizes a fixed Thumb instruction grammar, including operands,
//! literal values and branch destinations. A match establishes flag-copy
//! semantics only: dispatcher reachability, completion and image acceptance
//! must be established separately before authorizing a transfer plan.

/// A mode-1 branch into a proven four-bit CDB-to-MMIO flag copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyCandidate {
    /// Address of the mode-nibble decoder.
    pub decoder: u32,
    /// Address selected by the mode-1 branch.
    pub entry: u32,
    /// First instruction after the validated return.
    pub end: u32,
}

struct Window<'a> {
    bytes: &'a [u8],
    base: u32,
}
impl Window<'_> {
    fn bytes(&self, address: u32, count: usize) -> Option<&[u8]> {
        let start = usize::try_from(address.checked_sub(self.base)?).ok()?;
        self.bytes.get(start..start.checked_add(count)?)
    }
    fn word(&self, address: u32) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(address, 2)?.try_into().ok()?))
    }
    fn literal(&self, address: u32) -> Option<(u16, u32)> {
        let op = self.word(address)?;
        if op & 0xf800 != 0x4800 {
            return None;
        }
        let at = (address.checked_add(4)? & !3).checked_add(u32::from(op & 255) * 4)?;
        Some((
            (op >> 8) & 7,
            u32::from_le_bytes(self.bytes(at, 4)?.try_into().ok()?),
        ))
    }
    fn conditional(&self, address: u32, condition: u16) -> Option<u32> {
        let op = self.word(address)?;
        if op & 0xff00 != condition {
            return None;
        }
        u32::try_from(i64::from(address) + 4 + i64::from(op as u8 as i8) * 2).ok()
    }
}

// Verify the complete local prologue, rather than finding useful bytes in an
// otherwise unconstrained prefix. This also proves r0 is still the CDB pointer
// and whether r7 really carries the bit-zero constant.
fn prologue(w: &Window<'_>, start: u32) -> Option<bool> {
    for distance in [14, 16, 18] {
        let Some(mut p) = start.checked_sub(distance) else {
            continue;
        };
        let Some((0, cdb)) = w.literal(p) else {
            continue;
        };
        if !(0x0200_0000..0x0201_0000).contains(&cdb) {
            continue;
        }
        p += 2;
        if w.word(p) != Some(0xb5f0) || w.word(p + 2) != Some(0x7882) {
            continue;
        }
        p += 4;
        if !matches!(w.word(p), Some(0xb085 | 0xb089)) {
            continue;
        }
        p += 2;
        let mut one = false;
        let mut state = false;
        while p < start.saturating_sub(4) {
            if w.word(p) == Some(0x2701) && !one {
                one = true;
                p += 2;
            } else if let Some((1, address)) = w.literal(p) {
                if state || !(0x0200_0000..0x0201_0000).contains(&address) {
                    break;
                }
                state = true;
                p += 2;
            } else if state && w.word(p) == Some(0x390a) {
                p += 2;
            } else {
                break;
            }
        }
        if state
            && p == start.checked_sub(4)?
            && w.word(p) == Some(0x2a00)
            && w.conditional(p + 2, 0xd100).is_some()
        {
            return Some(one);
        }
    }
    None
}

fn candidate(w: &Window<'_>, start: u32) -> Option<LegacyCandidate> {
    // CDB pointer r0; mode decoder reads/masks/writes byte 1 through r2.
    if w.bytes(start, 10)? != [0x42, 0x78, 0x12, 0x07, 0x12, 0x0f, 0x42, 0x70, 0x42, 0x78] {
        return None;
    }
    let preloaded_one = prologue(w, start)?;
    let mut p = start.checked_add(10)?;
    let mut mmio = w.literal(p);
    if mmio.is_some() {
        p = p.checked_add(2)?;
    }
    if w.word(p)? != 0x2a01 {
        return None;
    }
    let entry = w.conditional(p.checked_add(2)?, 0xd000)?;
    p = entry;
    if let Some(local) = w.literal(p) {
        mmio = Some(local);
        p = p.checked_add(2)?;
    }
    let (base, address) = mmio?;
    if address != 0x0400_2040 || base == 0 {
        return None;
    }
    let mut tmp = w.word(p)? & 7;
    if tmp == 0 || tmp == base {
        return None;
    }
    let load = 0x6800 | (6 << 6) | (base << 3) | tmp;
    let clear = [
        load,
        0x0800 | (4 << 6) | (tmp << 3) | tmp,
        (4 << 6) | (tmp << 3) | tmp,
        0x6000 | (6 << 6) | (base << 3) | tmp,
    ];
    for op in clear {
        if w.word(p)? != op {
            return None;
        }
        p = p.checked_add(2)?;
    }
    for bit in 0..4u16 {
        if bit == 3 {
            tmp = 0;
        }
        if w.word(p)? != 0x7800 | (9 << 6) | tmp
            || w.word(p.checked_add(2)?)? != ((31 - bit) << 6) | (tmp << 3) | tmp
        {
            return None;
        }
        let skip = w.conditional(p.checked_add(4)?, if bit == 0 { 0xd000 } else { 0xd500 })?;
        p = p.checked_add(6)?;
        if w.word(p)? != 0x6800 | (6 << 6) | (base << 3) | tmp {
            return None;
        }
        p = p.checked_add(2)?;
        let op = w.word(p)?;
        let source = if op & 0xf800 == 0x2000 {
            if op & 255 != 1 << bit {
                return None;
            }
            p = p.checked_add(2)?;
            (op >> 8) & 7
        } else if bit == 0 && preloaded_one && base != 7 {
            7
        } else {
            return None;
        };
        if source == tmp || source == base || (source == 0 && bit != 3) {
            return None;
        }
        if w.word(p)? != 0x4300 | (source << 3) | tmp
            || w.word(p.checked_add(2)?)? != 0x6000 | (6 << 6) | (base << 3) | tmp
        {
            return None;
        }
        p = p.checked_add(4)?;
        if p != skip {
            return None;
        }
    }
    if w.word(p)? & 0xff80 != 0xb000 || w.word(p.checked_add(2)?)? & 0xff00 != 0xbd00 {
        return None;
    }
    Some(LegacyCandidate {
        decoder: start,
        entry,
        end: p.checked_add(4)?,
    })
}

/// Inspect a bounded flash-addressed window for a legacy BOOT entry candidate.
/// The window must include referenced literals and the complete flag-copy body.
/// Truncated, unknown and ambiguous windows return `None`. This performs no I/O
/// and grants no permission to issue PREPARE or ignore its result.
pub fn inspect_boot_legacy(bytes: &[u8], address: u32) -> Option<LegacyCandidate> {
    let w = Window {
        bytes,
        base: address,
    };
    let mut found = None;
    for index in (0..bytes.len().saturating_sub(9)).step_by(2) {
        let at = address.checked_add(u32::try_from(index).ok()?)?;
        if at & 1 != 0 {
            continue;
        }
        if let Some(hit) = candidate(&w, at) {
            if found.is_some() {
                return None;
            }
            found = Some(hit);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    // Instruction/literal excerpts from WH16NS58 V9 SHA256 97b28707...,
    // checked against the independent disassembly. No firmware payload needed.
    fn v9_window() -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0xff; 0x600];
        for (address, hex) in [
            (0x352a, "e548f0b5827889b00127e349002a72d142781207120f42704278e04e012a49d0022a01d0062af2d1"),
            (0x35de, "b16909090901b161417ac90702d0b1693943b161417a890703d5b16902221143b161417a490703d5b16904221143b161407a000703d5b06908210843b06109b0f0bd"),
            (0x38c0, "fc0d0002800d000240200004"),
        ] {
            for i in (0..hex.len()).step_by(2) {
                bytes[address - 0x3400 + i / 2] = u8::from_str_radix(&hex[i..i+2], 16).unwrap();
            }
        }
        bytes
    }

    #[test]
    fn actual_v9_entry_has_fixed_operands_and_bounded_literals() {
        let bytes = v9_window();
        assert_eq!(
            inspect_boot_legacy(&bytes, 0x3400),
            Some(LegacyCandidate {
                decoder: 0x353a,
                entry: 0x35de,
                end: 0x3620,
            })
        );
        for length in 0..0x4cc {
            assert!(inspect_boot_legacy(&bytes[..length], 0x3400).is_none());
        }
        for address in [
            0x352e, 0x3532, 0x3536, 0x3546, 0x3548, 0x35de, 0x35e6, 0x35e8, 0x35ea, 0x35ee, 0x361a,
            0x38c8,
        ] {
            let mut changed = bytes.clone();
            changed[address - 0x3400] ^= 1;
            assert!(
                inspect_boot_legacy(&changed, 0x3400).is_none(),
                "{address:#x}"
            );
        }
    }

    #[test]
    fn ambiguity_alignment_and_address_overflow_never_select_a_recipe() {
        let bytes = v9_window();
        let mut doubled = bytes.clone();
        doubled.extend_from_slice(&bytes);
        assert!(inspect_boot_legacy(&doubled, 0x3400).is_none());
        assert!(inspect_boot_legacy(&bytes, 0x3401).is_none());
        assert!(inspect_boot_legacy(&bytes, u32::MAX - 16).is_none());
    }
}

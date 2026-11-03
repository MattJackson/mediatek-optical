//! Bounded static evidence for BOOT PREPARE handling.
//!
//! This recognizes a fixed Thumb instruction grammar, including operands,
//! literal values and branch destinations. A match establishes flag-copy
//! semantics only: dispatcher reachability, completion and image acceptance
//! must be established separately before authorizing a transfer plan.

pub mod application;

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

/// BOOT entry supporting mode 1 and mode 6/buffer 0x67 through the same body.
/// As with [`LegacyCandidate`], this is evidence, not transfer authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualCandidate {
    /// Start of the validated CDB decoder function.
    pub decoder: u32,
    /// Shared entry body.
    pub entry: u32,
    /// Start of stream parameter handling after the entry body.
    pub stream: u32,
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
    fn branch(&self, address: u32) -> Option<u32> {
        let op = self.word(address)?;
        if op & 0xf800 != 0xe000 {
            return None;
        }
        let delta = ((i32::from(op & 0x7ff) << 21) >> 20) as i64;
        u32::try_from(i64::from(address) + 4 + delta).ok()
    }
}

// Verify the complete local prologue, rather than finding useful bytes in an
// otherwise unconstrained prefix. This also proves r0 is still the CDB pointer
// and whether r7 really carries the bit-zero constant. Also returns the
// proven `SUB SP` so the return can be bound to the same frame.
fn prologue(w: &Window<'_>, start: u32) -> Option<(bool, u16)> {
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
        let Some(stack @ (0xb085 | 0xb089)) = w.word(p) else {
            continue;
        };
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
            return Some((one, stack));
        }
    }
    None
}

fn candidate(w: &Window<'_>, start: u32) -> Option<LegacyCandidate> {
    // CDB pointer r0; mode decoder reads/masks/writes byte 1 through r2.
    if w.bytes(start, 10)? != [0x42, 0x78, 0x12, 0x07, 0x12, 0x0f, 0x42, 0x70, 0x42, 0x78] {
        return None;
    }
    let (preloaded_one, stack) = prologue(w, start)?;
    let mut p = start.checked_add(10)?;
    // The first literal runs before `CMP r2,#1`, so it may not clobber the CDB
    // pointer (r0), the compared mode nibble (r2) or the preloaded bit-zero one
    // (r7) that the proof relies on.
    let clobbers = |reg: u16| reg == 0 || reg == 2 || (preloaded_one && reg == 7);
    let mut mmio = w.literal(p);
    if let Some((reg, _)) = mmio {
        if clobbers(reg) {
            return None;
        }
        p = p.checked_add(2)?;
    }
    if w.word(p)? != 0x2a01 {
        return None;
    }
    let entry = w.conditional(p.checked_add(2)?, 0xd000)?;
    p = entry;
    // r7 holds the preloaded one only until a local literal overwrites it; a
    // later bit clause relying on that implicit value is then rejected.
    let mut one_live = preloaded_one;
    if let Some(local) = w.literal(p) {
        // After the branch r0's pointer and r2's compare are dead, but r0 stays
        // reserved; r2 may be the MMIO base and r7 may be rebuilt.
        if local.0 == 0 {
            return None;
        }
        if local.0 == 7 {
            one_live = false;
        }
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
        } else if bit == 0 && one_live {
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
    // The return must unwind exactly the proven frame: ADD SP by the prologue's
    // SUB SP amount, then POP {r4-r7,pc} matching PUSH {r4-r7,lr}.
    if w.word(p)? != 0xb000 | (stack & 0x7f) || w.word(p.checked_add(2)?)? != 0xbdf0 {
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
    match scan_legacy(bytes, address) {
        Scan::Unique(hit) => Some(hit),
        Scan::Absent | Scan::Ambiguous => None,
    }
}

/// Outcome of scanning a window for one grammar.
enum Scan<T> {
    Absent,
    Unique(T),
    Ambiguous,
}

fn scan_legacy(bytes: &[u8], address: u32) -> Scan<LegacyCandidate> {
    let w = Window {
        bytes,
        base: address,
    };
    let mut found = Scan::Absent;
    for index in (0..bytes.len().saturating_sub(9)).step_by(2) {
        let Some(at) = u32::try_from(index)
            .ok()
            .and_then(|index| address.checked_add(index))
        else {
            return Scan::Absent;
        };
        if at & 1 != 0 {
            continue;
        }
        if let Some(hit) = candidate(&w, at) {
            if matches!(found, Scan::Unique(_)) {
                return Scan::Ambiguous;
            }
            found = Scan::Unique(hit);
        }
    }
    found
}

// Two compiler forms of the complete flag-copy body, including out-of-line
// bit-zero/bit-two blocks and their backward branches. Only the first form's
// PC-relative MMIO literal load varies; it is resolved and validated below.
const DUAL_LOCAL: &[u8] = b"\x00\x48\x85\x69\x2d\x09\x2d\x01\x85\x61\x4d\x7a\xed\x07\x10\xd1\x4d\x7a\xad\x07\x02\xd5\x85\x69\x2c\x43\x84\x61\x4c\x7a\x64\x07\x0c\xd4\x49\x7a\x09\x07\x02\xd5\x81\x69\x11\x43\x81\x61\x05\xb0\xf0\xbd\x85\x69\x01\x26\x35\x43\x85\x61\xe9\xe7\x84\x69\x23\x43\x83\x61\xee\xe7";
const DUAL_PRELOADED: &[u8] = b"\xb0\x69\x00\x09\x00\x01\xb0\x61\x48\x7a\xc0\x07\x10\xd1\x48\x7a\x80\x07\x02\xd5\xb0\x69\x20\x43\xb0\x61\x48\x7a\x40\x07\x0b\xd4\x48\x7a\x00\x07\x02\xd5\xb0\x69\x10\x43\xb0\x61\x09\xb0\xf0\xbd\xb0\x69\x38\x43\xb0\x61\xea\xe7\xb0\x69\x18\x43\xb0\x61\xef\xe7";

fn dual_candidate(w: &Window<'_>, start: u32) -> Option<DualCandidate> {
    let (register, cdb) = w.literal(start)?;
    if register != 1 || !(0x0200_0000..0x0201_0000).contains(&cdb) {
        return None;
    }
    let mut p = start.checked_add(2)?;
    for op in [0xb5f0, 0x7848] {
        if w.word(p)? != op {
            return None;
        }
        p = p.checked_add(2)?;
    }
    let stack = w.word(p)?;
    if !matches!(stack, 0xb085 | 0xb089) {
        return None;
    }
    p = p.checked_add(2)?;
    for op in [0x0700, 0x0f00, 0x7048, 0x7848, 0x2208, 0x2304, 0x2402] {
        if w.word(p)? != op {
            return None;
        }
        p = p.checked_add(2)?;
    }
    let preloaded = stack == 0xb089;
    if preloaded {
        if w.word(p)? != 0x2701 || w.literal(p.checked_add(2)?)? != (6, 0x0400_2040) {
            return None;
        }
        p = p.checked_add(4)?;
    }
    if w.word(p)? != 0x2801 {
        return None;
    }
    let entry = w.conditional(p.checked_add(2)?, 0xd000)?;
    p = p.checked_add(4)?;
    let (register, state) = w.literal(p)?;
    if register != 5 || !(0x0200_0000..0x0201_0000).contains(&state) {
        return None;
    }
    p = p.checked_add(2)?;
    if w.word(p)? != 0x3d0a || w.word(p.checked_add(2)?)? != 0x2802 {
        return None;
    }
    p = p.checked_add(4)?;
    if w.conditional(p, 0xd000)? != p.checked_add(6)? {
        return None;
    }
    if w.word(p.checked_add(2)?)? != 0x2806 {
        return None;
    }
    let reject = w.conditional(p.checked_add(4)?, 0xd100)?;
    p = p.checked_add(6)?;
    if w.word(p)? != 0x7848 || w.word(p.checked_add(2)?)? != 0x2806 {
        return None;
    }
    let stream = w.conditional(p.checked_add(4)?, 0xd100)?;
    p = p.checked_add(6)?;
    if w.word(p)? != 0x7888
        || w.word(p.checked_add(2)?)? != 0x2867
        || w.conditional(p.checked_add(4)?, 0xd100)? != stream
    {
        return None;
    }
    p = p.checked_add(6)?;
    if p != entry {
        return None;
    }
    let template = if preloaded {
        DUAL_PRELOADED
    } else {
        DUAL_LOCAL
    };
    if !preloaded && w.literal(entry)? != (0, 0x0400_2040) {
        return None;
    }
    let body = w.bytes(entry, template.len())?;
    let skip = if preloaded { 0 } else { 1 };
    if body[skip..] != template[skip..]
        || entry.checked_add(u32::try_from(template.len()).ok()?)? != stream
    {
        return None;
    }
    // The unsupported-mode branch must reach the state error flag and return,
    // not arbitrary code whose result happened to be ignored by the caller.
    let mut error = w.branch(reject)?;
    if preloaded {
        if w.word(error)? != 0x712f {
            return None;
        } // STRB r7,[r5,#4]
        error = error.checked_add(2)?;
    } else {
        if w.word(error)? != 0x2601 || w.word(error.checked_add(2)?)? != 0x712e {
            return None;
        }
        error = error.checked_add(4)?;
    }
    let return_at = entry.checked_add(if preloaded { 44 } else { 46 })?;
    if w.branch(error)? != return_at {
        return None;
    }
    Some(DualCandidate {
        decoder: start,
        entry,
        stream,
    })
}

/// Inspect the alternate BOOT entry grammar, validating both mode branches,
/// buffer 0x67, MMIO destination and the complete flag-copy control flow.
/// Unknown, truncated or ambiguous windows return `None`; this does no I/O.
pub fn inspect_boot_dual(bytes: &[u8], address: u32) -> Option<DualCandidate> {
    match scan_dual(bytes, address) {
        Scan::Unique(hit) => Some(hit),
        Scan::Absent | Scan::Ambiguous => None,
    }
}

fn scan_dual(bytes: &[u8], address: u32) -> Scan<DualCandidate> {
    let w = Window {
        bytes,
        base: address,
    };
    let mut found = Scan::Absent;
    for index in (0..bytes.len()).step_by(2) {
        let Some(at) = u32::try_from(index)
            .ok()
            .and_then(|index| address.checked_add(index))
        else {
            return Scan::Absent;
        };
        if at & 1 != 0 {
            continue;
        }
        if let Some(hit) = dual_candidate(&w, at) {
            if matches!(found, Scan::Unique(_)) {
                return Scan::Ambiguous;
            }
            found = Scan::Unique(hit);
        }
    }
    found
}

/// True when exactly one BOOT grammar matches (positively accepting mode one).
pub(super) fn boot_grammar_accepted(bytes: &[u8], address: u32) -> bool {
    matches!(
        (scan_legacy(bytes, address), scan_dual(bytes, address)),
        (Scan::Unique(_), Scan::Absent) | (Scan::Absent, Scan::Unique(_))
    )
}

#[cfg(test)]
#[path = "entry_tests.rs"]
mod tests;

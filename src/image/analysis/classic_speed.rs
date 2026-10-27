//! Native read-speed policy, bound to its RMAX producer and OPTM consumer.
use super::{half, Error};
use std::collections::BTreeSet;

/// A pure native read-speed selector whose result is consumed as OPTM.
/// This establishes a code/data contract, not a measured physical read rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassicSpeed {
    /// Native selector entry, derived from a real call/OPTM store.
    pub(super) entry: usize,
    /// Shared `lsls r0,#24; lsrs r0,#24` return normalization.
    pub(super) site: usize,
    /// Read maximum byte written by the native RMAX setter.
    pub(super) maximum_cell: u32,
    /// Current requested/optimum read-speed byte.
    pub(super) optimum_cell: u32,
    /// Media-type byte consumed by the selector.
    pub(super) media_cell: u32,
    /// Native call which stores this selector's result as OPTM.
    pub(super) consumer: usize,
}

fn word(image: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        image.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn ram(value: u32) -> bool {
    (0x01ff0000..0x02010000).contains(&value)
}
fn thumb_literal(image: &[u8], at: usize) -> Option<(usize, u32)> {
    let op = half(image, at)?;
    if op & 0xf800 != 0x4800 {
        return None;
    }
    let register = ((op >> 8) & 7) as usize;
    let value = word(image, ((at + 4) & !3) + (op & 255) as usize * 4)?;
    Some((register, value))
}
fn arm_branch(at: usize, op: u32) -> Option<usize> {
    if op >> 24 != 0xea {
        return None;
    }
    let delta = ((op << 8) as i32 >> 6) as i64;
    usize::try_from(at as i64 + 8 + delta).ok()
}
fn arm_tag(image: &[u8], at: usize, op: u32, tag: &[u8]) -> bool {
    if op & 0xfffff000 != 0xe28f0000 {
        return false;
    }
    let imm = (op & 255).rotate_right(((op >> 8) & 15) * 2);
    let Some(address) = at.checked_add(8).and_then(|a| a.checked_add(imm as usize)) else {
        return false;
    };
    address
        .checked_add(tag.len())
        .and_then(|end| image.get(address..end))
        == Some(tag)
}
// These are complete native ARM setters, including their logger argument roles.
// A string alone, an orphan literal or a missing setter never establishes RMAX.
fn setters(image: &[u8]) -> Vec<(u32, u32)> {
    let mut maximum = Vec::new();
    let mut optimum = Vec::new();
    for at in (0..image.len().saturating_sub(28)).step_by(4) {
        let Some(a) = word(image, at) else {
            continue;
        };
        if a == 0xe1a01000
            && word(image, at + 4).is_some_and(|w| w & 0xfffff000 == 0xe59f0000)
            && word(image, at + 8) == Some(0xe1a0200e)
            && word(image, at + 12) == Some(0xe5c01000)
            && word(image, at + 16) == Some(0xe5d01000)
            && word(image, at + 20).is_some_and(|w| arm_tag(image, at + 20, w, b"RMAX\0"))
        {
            if let (Some(cell), Some(logger)) = (
                word(
                    image,
                    at + 12 + (word(image, at + 4).unwrap() & 4095) as usize,
                ),
                word(image, at + 24).and_then(|w| arm_branch(at + 24, w)),
            ) {
                if ram(cell) && logger + 4 <= image.len() {
                    maximum.push((cell, logger));
                }
            }
        }
        if a & 0xfffff000 == 0xe59f1000
            && word(image, at + 4) == Some(0xe1a0200e)
            && word(image, at + 8) == Some(0xe5c10000)
            && word(image, at + 12).is_some_and(|w| w & 0xfffff000 == 0xe59f0000)
            && word(image, at + 16) == Some(0xe5d01000)
            && word(image, at + 20).is_some_and(|w| arm_tag(image, at + 20, w, b"OPTM\0"))
        {
            if let (Some(cell), Some(read_max), Some(logger)) = (
                word(image, at + 8 + (a & 4095) as usize),
                word(
                    image,
                    at + 20 + (word(image, at + 12).unwrap() & 4095) as usize,
                ),
                word(image, at + 24).and_then(|w| arm_branch(at + 24, w)),
            ) {
                if ram(cell) && ram(read_max) && cell != read_max && logger + 4 <= image.len() {
                    optimum.push((cell, read_max, logger));
                }
            }
        }
    }
    maximum
        .into_iter()
        .flat_map(|(max, logger)| {
            optimum.iter().filter_map(move |&(opt, read_max, log)| {
                (max == read_max && logger == log).then_some((max, opt))
            })
        })
        .collect()
}

fn selector(image: &[u8], entry: usize) -> Option<(usize, u32, BTreeSet<u32>)> {
    let (source, media) = thumb_literal(image, entry)?;
    if source > 2
        || !ram(media)
        || half(image, entry + 2)? != 0x7800 | ((source as u16) << 3)
        || half(image, entry + 4)? != 0x0980
        || half(image, entry + 6)? != 0x2803
    {
        return None;
    }
    let mut pending = vec![(entry, [None; 3], Vec::<usize>::new())];
    let mut seen = BTreeSet::new();
    let mut reads = BTreeSet::new();
    let mut branch_targets = BTreeSet::new();
    let mut tail = None;
    while let Some((pc, mut values, path)) = pending.pop() {
        if pc < entry || pc >= entry.checked_add(128)? || path.contains(&pc) {
            return None;
        }
        if !seen.insert((pc, values)) {
            continue;
        }
        if seen.len() > 256 {
            return None;
        }
        let op = half(image, pc)?;
        if op == 0x4770 {
            if path.len() < 2
                || path[path.len() - 2..] != [pc - 4, pc - 2]
                || half(image, pc - 4)? != 0x0600
                || half(image, pc - 2)? != 0x0e00
                || tail.is_some_and(|previous| previous != pc - 4)
            {
                return None;
            }
            tail = Some(pc - 4);
            continue;
        }
        let mut next_path = path;
        next_path.push(pc);
        if op & 0xf000 == 0xd000 && (op >> 8) & 15 < 14 {
            let target = usize::try_from(pc as i64 + 4 + i64::from(op as u8 as i8) * 2).ok()?;
            branch_targets.insert(target);
            pending.push((target, values, next_path.clone()));
        } else if op & 0xf800 == 0xe000 {
            let delta = ((i32::from(op & 2047) << 21) >> 20) as i64;
            let target = usize::try_from(pc as i64 + 4 + delta).ok()?;
            branch_targets.insert(target);
            pending.push((target, values, next_path));
            continue;
        } else if let Some((r, value)) = thumb_literal(image, pc) {
            if r > 2 || !ram(value) {
                return None;
            }
            values[r] = Some(value);
        } else if op & 0xf800 == 0x7800 {
            let rt = (op & 7) as usize;
            let rn = ((op >> 3) & 7) as usize;
            if rt > 2 || rn > 2 {
                return None;
            }
            let cell = values[rn]?.checked_add(u32::from((op >> 6) & 31))?;
            if !ram(cell) {
                return None;
            }
            reads.insert(cell);
            if reads.len() > 3 {
                return None;
            }
            values[rt] = None;
        } else if op & 0xf800 == 0x2000 {
            let r = ((op >> 8) & 7) as usize;
            if r > 2 {
                return None;
            }
            values[r] = Some(u32::from(op & 255));
        } else if op & 0xf800 == 0x2800 {
            if (op >> 8) & 7 > 2 {
                return None;
            }
        } else if op & 0xf800 == 0 || op & 0xf800 == 0x0800 {
            let rd = (op & 7) as usize;
            let rm = ((op >> 3) & 7) as usize;
            if rd > 2 || rm > 2 {
                return None;
            }
            let shift = u32::from((op >> 6) & 31);
            values[rd] = values[rm].map(|v| {
                if op & 0xf800 == 0 {
                    v.wrapping_shl(shift)
                } else {
                    v.checked_shr(if shift == 0 { 32 } else { shift })
                        .unwrap_or(0)
                }
            });
        } else if op & 0xffc0 == 0x4000 {
            let rd = (op & 7) as usize;
            let rm = ((op >> 3) & 7) as usize;
            if rd > 2 || rm > 2 {
                return None;
            }
            values[rd] = values[rd].zip(values[rm]).map(|(a, b)| a & b);
        } else {
            return None;
        }
        pending.push((pc + 2, values, next_path));
    }
    let tail = tail?;
    (reads.contains(&media)
        && !branch_targets.contains(&(tail + 2))
        && !branch_targets.contains(&(tail + 4)))
    .then_some((tail, media, reads))
}

impl ClassicSpeed {
    /// Native selector entry established by its consumer.
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Exact normalization-tail patch site.
    pub fn site(&self) -> usize {
        self.site
    }
    /// Native read-maximum producer cell.
    pub fn maximum_cell(&self) -> u32 {
        self.maximum_cell
    }
    /// Requested/optimum read-speed cell.
    pub fn optimum_cell(&self) -> u32 {
        self.optimum_cell
    }
    /// Native media-type cell.
    pub fn media_cell(&self) -> u32 {
        self.media_cell
    }
    /// Native call which stores the selected optimum value.
    pub fn consumer(&self) -> usize {
        self.consumer
    }

    /// Find exactly one read-only selector whose native result is stored as OPTM.
    /// Every reachable instruction is checked; calls, stores, loops, unknown
    /// pointer loads and branches that bypass the common return hook are refused.
    pub fn detect(image: &[u8]) -> Result<Self, Error> {
        let roles = setters(image);
        let mut found = None;
        for at in (0..image.len().saturating_sub(8)).step_by(2) {
            if half(image, at + 6) != Some(0x7008) {
                continue;
            }
            let Some((1, optimum_cell)) = thumb_literal(image, at + 4) else {
                continue;
            };
            let Some(entry) = thumb_asm::decode_bl(image, at).map(|v| v as usize) else {
                continue;
            };
            let Some((site, media_cell, reads)) = selector(image, entry) else {
                continue;
            };
            for &(maximum_cell, opt) in &roles {
                if opt != optimum_cell
                    || media_cell == maximum_cell
                    || media_cell == opt
                    || reads.contains(&opt)
                    || reads.len() < 2
                    || (reads.len() == 3 && !reads.contains(&maximum_cell))
                {
                    continue;
                }
                let candidate = Self {
                    entry,
                    site,
                    maximum_cell,
                    optimum_cell,
                    media_cell,
                    consumer: at,
                };
                if let Some(previous) = &found {
                    let previous: &Self = previous;
                    if previous.entry != candidate.entry
                        || previous.maximum_cell != maximum_cell
                        || previous.optimum_cell != opt
                    {
                        return Err(Error::Ambiguous);
                    }
                } else {
                    found = Some(candidate);
                }
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
}

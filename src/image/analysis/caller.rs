//! Source-bound caller stack/LR evidence for a Thumb BL detour.
use super::{half, Error};
use std::collections::{BTreeSet, VecDeque};
use thumb_asm::isa::{decode_at, Operand, Reg};

/// The native function saves the incoming LR and reaches balanced pop-PC exits.
/// Calls retain the native ABI; unknown stack/control-flow operations are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SavedLink {
    /// Native LR-saving entry.
    pub entry: usize,
    /// Detour instruction within that function.
    pub site: usize,
    /// Native stack depth at the detour, relative to function entry.
    pub stack_bytes: usize,
    /// Reachable balanced exits after passing the detour.
    pub returns: Vec<usize>,
}
fn touches_lr(op: Operand) -> bool {
    match op {
        Operand::Reg(Reg::LR) | Operand::RegShifted(Reg::LR, _) => true,
        Operand::RegList(bits) => bits & (1 << 14) != 0,
        Operand::Mem(m) => m.base == Reg::LR || m.index.is_some_and(|(reg, _)| reg == Reg::LR),
        _ => false,
    }
}
impl SavedLink {
    /// Bind an explicit entry and detour using a bounded native control-flow walk.
    /// The detour may clobber LR only until the next native call or pop-PC return.
    pub fn bind(image: &[u8], entry: usize, site: usize) -> Result<Self, Error> {
        if entry >= site || !half(image, entry).is_some_and(|op| op & 0xff00 == 0xb500) {
            return Err(Error::InvalidContract);
        }
        let mut queue = VecDeque::from([(entry, 0i32, false, false)]);
        let mut seen = BTreeSet::new();
        let mut starts = BTreeSet::new();
        let mut second_halves = BTreeSet::new();
        let mut depths = BTreeSet::new();
        let mut returns = BTreeSet::new();
        while let Some((pc, mut depth, mut hooked, mut dirty)) = queue.pop_front() {
            if !seen.insert((pc, depth, hooked, dirty)) {
                continue;
            }
            if seen.len() > 10000
                || pc < entry
                || pc >= entry + 0x1200
                || !(0..=512).contains(&depth)
                || (pc != entry && depth < 4)
            {
                return Err(Error::InvalidContract);
            }
            if second_halves.contains(&pc) {
                return Err(Error::InvalidContract);
            }
            starts.insert(pc);
            let ins = decode_at(image, pc).ok_or(Error::Truncated)?;
            if ins.len() == 4 {
                if !ins.is_call() || starts.contains(&(pc + 2)) {
                    return Err(Error::InvalidContract);
                }
                second_halves.insert(pc + 2);
            }
            if pc == site {
                hooked = true;
                dirty = true;
                depths.insert(depth as usize);
            }
            let call = ins.is_call();
            if dirty && ins.operands.as_slice().any(touches_lr) {
                return Err(Error::InvalidContract);
            }
            match ins.mnemonic {
                "push" | "pop" => {
                    let Some(Operand::RegList(bits)) = ins.operands.get(0) else {
                        return Err(Error::InvalidContract);
                    };
                    let count = bits.count_ones() as i32 * 4;
                    if ins.mnemonic == "push" {
                        depth += count;
                    } else {
                        depth -= count;
                        if bits & (1 << 15) != 0 {
                            if depth != 0 {
                                return Err(Error::InvalidContract);
                            }
                            if hooked {
                                returns.insert(pc);
                            }
                            continue;
                        }
                    }
                }
                "add" | "sub" if ins.operands.get(0) == Some(Operand::Reg(Reg::SP)) => {
                    let Some(Operand::Imm(imm)) = ins.operands.as_slice().last() else {
                        return Err(Error::InvalidContract);
                    };
                    let immediate = i32::try_from(imm).map_err(|_| Error::InvalidContract)?;
                    depth += if ins.mnemonic == "sub" {
                        immediate
                    } else {
                        -immediate
                    };
                }
                "udf" | "svc" | "bkpt" | "hvc" | "smc" | "it" => {
                    return Err(Error::InvalidContract)
                }
                _ if ins.operands.get(0) == Some(Operand::Reg(Reg::SP)) => {
                    return Err(Error::InvalidContract)
                }
                _ => {}
            }
            let next = pc + ins.len();
            if call {
                if ins.cond.is_some() {
                    return Err(Error::InvalidContract);
                }
                dirty = false;
                if let Some(targets) = super::switch::targets(image, pc)? {
                    for target in targets {
                        queue.push_back((target, depth, hooked, dirty));
                    }
                    continue;
                }
                queue.push_back((next, depth, hooked, dirty));
                continue;
            }
            if ins.is_branch() {
                if ins.mnemonic != "b"
                    || ins
                        .operands
                        .as_slice()
                        .any(|v| matches!(v, Operand::Mem(_)))
                {
                    return Err(Error::InvalidContract);
                }
                let target = ins.branch_target().ok_or(Error::InvalidContract)? as usize;
                queue.push_back((target, depth, hooked, dirty));
                if ins.cond.is_some() {
                    queue.push_back((next, depth, hooked, dirty));
                }
            } else {
                queue.push_back((next, depth, hooked, dirty));
            }
        }
        if depths.len() != 1 || returns.is_empty() {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            entry,
            site,
            stack_bytes: *depths.iter().next().unwrap(),
            returns: returns.into_iter().collect(),
        })
    }
    /// Select the nearest preceding LR-saving entry whose complete local graph
    /// proves the detour's stack and link-register lifetime.
    pub fn detect(image: &[u8], site: usize) -> Result<Self, Error> {
        for entry in (site.saturating_sub(0x800)..site).step_by(2).rev() {
            if half(image, entry).is_some_and(|op| op & 0xff00 == 0xb500) {
                if let Ok(bound) = Self::bind(image, entry, site) {
                    return Ok(bound);
                }
            }
        }
        Err(Error::UnknownLayout)
    }
}

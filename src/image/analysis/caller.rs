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
        for entry in (site.saturating_sub(0x1200)..site).step_by(2).rev() {
            if half(image, entry).is_some_and(|op| op & 0xff00 == 0xb500) {
                if let Ok(bound) = Self::bind(image, entry, site) {
                    return Ok(bound);
                }
            }
        }
        Err(Error::UnknownLayout)
    }
}

impl SavedLink {
    /// Require every path reaching this site to execute a validated definition,
    /// without overwriting its saved register afterward. Calls preserve r4-r11.
    /// The caller must validate the definition's operands and resulting value.
    pub fn require_register_definition(
        &self,
        image: &[u8],
        definition: usize,
        definition_end: usize,
        register: u8,
    ) -> Result<(), Error> {
        Self::require_live_definition(
            image,
            self.entry,
            self.site,
            definition,
            definition_end,
            register,
        )
    }

    /// Prove a saved-register definition on every path from a native entry to a read.
    /// Unlike detour binding, this does not impose an LR contract on the function tail.
    pub fn require_live_definition(
        image: &[u8],
        entry: usize,
        site: usize,
        definition: usize,
        definition_end: usize,
        register: u8,
    ) -> Result<(), Error> {
        if entry >= site || !half(image, entry).is_some_and(|op| op & 0xff00 == 0xb500) {
            return Err(Error::InvalidContract);
        }
        if !(4..=11).contains(&register)
            || definition < entry
            || definition_end <= definition
            || definition_end > site
            || definition_end - definition > 8
        {
            return Err(Error::InvalidContract);
        }
        let mut queue = VecDeque::from([(entry, false, 0i32)]);
        let mut seen = BTreeSet::new();
        let mut reached = false;
        let mut starts = BTreeSet::new();
        let mut second_halves = BTreeSet::new();
        while let Some((pc, mut live, mut depth)) = queue.pop_front() {
            if !seen.insert((pc, live, depth)) {
                continue;
            }
            if seen.len() > 10000
                || pc < entry.saturating_sub(0x1200)
                || pc >= entry + 0x1200
                || !(0..=512).contains(&depth)
            {
                return Err(Error::InvalidContract);
            }
            if second_halves.contains(&pc) {
                return Err(Error::InvalidContract);
            }
            starts.insert(pc);
            if pc == site {
                if !live {
                    return Err(Error::InvalidContract);
                }
                reached = true;
                continue;
            }
            if pc == definition {
                queue.push_back((definition_end, true, depth));
                continue;
            }
            let ins = decode_at(image, pc).ok_or(Error::Truncated)?;
            let next = pc + ins.len();
            if ins.len() == 4 {
                if starts.contains(&(pc + 2)) {
                    return Err(Error::InvalidContract);
                }
                second_halves.insert(pc + 2);
            }
            // The native contracts here are Thumb-1 plus calls. Refuse other
            // wide instructions rather than guess their multi-register effects.
            if ins.len() == 4 && !ins.is_call() {
                return Err(Error::InvalidContract);
            }
            for operand in ins.operands.as_slice() {
                match operand {
                    Operand::Text(text) => {
                        let base = text
                            .strip_prefix('r')
                            .and_then(|s| s.strip_suffix('!'))
                            .and_then(|s| s.parse::<u8>().ok())
                            .ok_or(Error::InvalidContract)?;
                        if base == register {
                            live = false;
                        }
                    }
                    Operand::Mem(m)
                        if m.mode != thumb_asm::isa::AddrMode::Offset
                            && m.base.num() == register =>
                    {
                        live = false
                    }
                    _ => {}
                }
            }

            if matches!(ins.mnemonic, "push" | "pop") {
                let Some(Operand::RegList(bits)) = ins.operands.get(0) else {
                    return Err(Error::InvalidContract);
                };
                let count = bits.count_ones() as i32 * 4;
                depth += if ins.mnemonic == "push" {
                    count
                } else {
                    -count
                };
            } else if matches!(ins.mnemonic, "add" | "sub")
                && ins.operands.get(0) == Some(Operand::Reg(Reg::SP))
            {
                let Some(Operand::Imm(imm)) = ins.operands.as_slice().last() else {
                    return Err(Error::InvalidContract);
                };
                let count = i32::try_from(imm).map_err(|_| Error::InvalidContract)?;
                depth += if ins.mnemonic == "sub" { count } else { -count };
            }
            if ins.is_call() {
                if let Some(targets) = super::switch::targets(image, pc)? {
                    queue.extend(targets.into_iter().map(|p| (p, live, depth)));
                } else {
                    queue.push_back((next, live, depth));
                }
                continue;
            }
            if ins.mnemonic == "pop" {
                let Some(Operand::RegList(bits)) = ins.operands.get(0) else {
                    return Err(Error::InvalidContract);
                };
                if bits & (1 << 15) != 0 {
                    continue;
                }
                if bits & (1 << register) != 0 {
                    live = false;
                }
            } else if matches!(ins.mnemonic, "ldm" | "ldmia" | "stm" | "stmia") {
                for operand in ins.operands.as_slice() {
                    if matches!(operand,Operand::Reg(r) if r.num()==register)
                        || (ins.mnemonic.starts_with("ldm")
                            && matches!(operand,Operand::RegList(bits) if bits&(1<<register)!=0))
                    {
                        live = false;
                    }
                }
            } else if !matches!(
                ins.mnemonic,
                "cmp" | "cmn" | "tst" | "teq" | "push" | "b" | "nop"
            ) && !ins.mnemonic.starts_with("str")
                && matches!(ins.operands.get(0),Some(Operand::Reg(r)) if r.num()==register)
            {
                live = false;
            }
            if ins.is_branch() {
                if ins.mnemonic != "b" {
                    return Err(Error::InvalidContract);
                }
                let target = ins.branch_target().ok_or(Error::InvalidContract)? as usize;
                queue.push_back((target, live, depth));
                if ins.cond.is_some() {
                    queue.push_back((next, live, depth));
                }
            } else {
                queue.push_back((next, live, depth));
            }
        }
        if !reached {
            return Err(Error::InvalidContract);
        }
        Ok(())
    }
}

#[cfg(test)]
mod live_definition_tests {
    use super::*;
    fn fixture(middle: &[u16]) -> (Vec<u8>, usize) {
        let mut words = vec![0xb510, 0x4c00];
        words.extend(middle);
        let site = words.len() * 2;
        words.extend([0x7820, 0xbd10]);
        (words.into_iter().flat_map(u16::to_le_bytes).collect(), site)
    }
    #[test]
    fn native_register_definition_rejects_writeback_and_clobber() {
        let (good, site) = fixture(&[0x46c0]);
        assert!(SavedLink::require_live_definition(&good, 0, site, 2, 4, 4).is_ok());
        for middle in [&[0xc401][..], &[0x2400][..], &[0xf844, 0x0b04][..]] {
            let (bad, site) = fixture(middle);
            assert!(SavedLink::require_live_definition(&bad, 0, site, 2, 4, 4).is_err());
        }
    }
}

//! Source-bound caller stack/LR evidence for a Thumb BL detour.
use super::{caller_stack::StackFlow, Error};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thumb_asm::isa::{decode_at, Operand, Reg};

/// The native function saves the incoming LR and reaches balanced pop-PC exits.
/// Calls retain the native ABI; unknown stack/control-flow operations are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SavedLink {
    /// Native LR-saving entry.
    pub(super) entry: usize,
    /// Detour instruction within that function.
    pub(super) site: usize,
    /// Native stack depth at the detour, relative to function entry.
    pub(super) stack_bytes: usize,
    /// Reachable balanced exits after passing the detour.
    pub(super) returns: Vec<usize>,
    source: [u8; 32],
}
fn touches_lr(op: Operand) -> bool {
    match op {
        Operand::Reg(Reg::LR) | Operand::RegShifted(Reg::LR, _) => true,
        Operand::RegList(bits) => bits & (1 << 14) != 0,
        Operand::Mem(m) => m.base == Reg::LR || m.index.is_some_and(|(reg, _)| reg == Reg::LR),
        _ => false,
    }
}
fn saves_link(image: &[u8], at: usize) -> bool {
    decode_at(image, at).is_some_and(|ins| {
        ins.mnemonic == "push"
            && ins.cond.is_none()
            && matches!(ins.operands.get(0), Some(Operand::RegList(bits)) if bits & (1 << 14) != 0)
    })
}
pub(super) fn scalar_operand(
    operand: Option<Operand>,
    constants: &[Option<u32>; 16],
) -> Option<u32> {
    match operand? {
        Operand::Reg(reg) => constants[usize::from(reg.num())],
        Operand::Imm(value) => u32::try_from(value).ok(),
        _ => None,
    }
}
pub(super) fn update_constants(ins: &thumb_asm::isa::Insn, values: &mut [Option<u32>; 16]) {
    if ins.is_call() {
        for reg in [0, 1, 2, 3, 12] {
            values[reg] = None;
        }
        return;
    }
    if matches!(ins.mnemonic, "ldm" | "ldmia" | "stm" | "stmia") {
        if let Some(Operand::Text(text)) = ins.operands.get(0) {
            if let Some(base) = text
                .strip_prefix('r')
                .and_then(|s| s.strip_suffix('!'))
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|r| *r < 16)
            {
                values[base] = None;
            }
        }
        if ins.mnemonic.starts_with("ldm") {
            if let Some(Operand::RegList(mask)) = ins.operands.get(1) {
                for (reg, value) in values.iter_mut().enumerate() {
                    if mask & (1 << reg) != 0 {
                        *value = None;
                    }
                }
            }
        }
        return;
    }
    if ins.mnemonic == "pop" {
        if let Some(Operand::RegList(mask)) = ins.operands.get(0) {
            for (reg, value) in values.iter_mut().enumerate() {
                if mask & (1 << reg) != 0 {
                    *value = None;
                }
            }
        }
        return;
    }
    if matches!(
        ins.mnemonic,
        "cmp" | "cmn" | "tst" | "teq" | "push" | "b" | "nop"
    ) || ins.mnemonic.starts_with("str")
    {
        return;
    }
    let Some(Operand::Reg(dest)) = ins.operands.get(0) else {
        return;
    };
    let value = if ins.mnemonic == "mov" {
        scalar_operand(ins.operands.get(1), values)
    } else if matches!(ins.mnemonic, "add" | "sub" | "lsl" | "lsr" | "and") {
        let (a, b) = if let Some(third) = ins.operands.get(2) {
            (
                scalar_operand(ins.operands.get(1), values),
                scalar_operand(Some(third), values),
            )
        } else {
            (
                values[usize::from(dest.num())],
                scalar_operand(ins.operands.get(1), values),
            )
        };
        a.zip(b).and_then(|(a, b)| match ins.mnemonic {
            "add" => Some(a.wrapping_add(b)),
            "sub" => Some(a.wrapping_sub(b)),
            // Register-specified shifts use only the low byte of the amount.
            "lsl" => a.checked_shl(b & 0xff),
            "lsr" => Some(if b & 0xff >= 32 { 0 } else { a >> (b & 0xff) }),
            "and" => Some(a & b),
            _ => None,
        })
    } else {
        None
    };
    values[usize::from(dest.num())] = value;
}
fn compare_condition(cond: thumb_asm::Cond, a: u32, b: u32) -> Option<bool> {
    use thumb_asm::Cond::*;
    Some(match cond {
        Eq => a == b,
        Ne => a != b,
        Hs => a >= b,
        Lo => a < b,
        Hi => a > b,
        Ls => a <= b,
        Ge => (a as i32) >= (b as i32),
        Lt => (a as i32) < (b as i32),
        Gt => (a as i32) > (b as i32),
        Le => (a as i32) <= (b as i32),
        Al => true,
        _ => return None,
    })
}
impl SavedLink {
    /// Native LR-saving entry.
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Validated detour instruction.
    pub fn site(&self) -> usize {
        self.site
    }
    /// Native stack depth at the detour.
    pub fn stack_bytes(&self) -> usize {
        self.stack_bytes
    }
    /// Balanced exits reached after the detour.
    pub fn returns(&self) -> &[usize] {
        &self.returns
    }
    /// Exact immutable input that supplied the evidence.
    pub fn source_sha256(&self) -> [u8; 32] {
        self.source
    }
    fn require_source(&self, image: &[u8]) -> Result<(), Error> {
        if <[u8; 32]>::from(Sha256::digest(image)) != self.source {
            return Err(Error::InvalidContract);
        }
        Ok(())
    }
}
impl SavedLink {
    /// Bind an explicit entry and detour using a bounded native control-flow walk.
    /// The detour may clobber LR only until the next native call or pop-PC return.
    pub fn bind(image: &[u8], entry: usize, site: usize) -> Result<Self, Error> {
        let (stack_bytes, returns) = Self::frame(image, entry, site)?;
        Ok(Self {
            source: Sha256::digest(image).into(),
            entry,
            site,
            stack_bytes,
            returns,
        })
    }
    /// The bounded walk behind [`Self::bind`]: stack depth and balanced exits.
    fn frame(image: &[u8], entry: usize, site: usize) -> Result<(usize, Vec<usize>), Error> {
        if entry >= site || !saves_link(image, entry) {
            return Err(Error::InvalidContract);
        }
        let entry_ins = decode_at(image, entry).ok_or(Error::Truncated)?;
        let Some(Operand::RegList(saved)) = entry_ins.operands.get(0) else {
            return Err(Error::InvalidContract);
        };
        let frame_bytes = saved.count_ones() as i32 * 4;
        let mut protected = Vec::new();
        let mut slot = -frame_bytes;
        for reg in 0..16 {
            if saved & (1 << reg) != 0 {
                if (4..=11).contains(&reg) || reg == 14 {
                    protected.push(slot);
                }
                slot += 4;
            }
        }
        let mut queue = VecDeque::from([(
            entry,
            0i32,
            false,
            false,
            StackFlow::default(),
            [None; 16],
            None,
        )]);
        let mut seen = BTreeSet::new();
        let mut scalar_history: BTreeMap<(usize, usize), BTreeSet<u32>> = BTreeMap::new();
        let mut starts = BTreeSet::new();
        let mut second_halves = BTreeSet::new();
        let mut depths = BTreeSet::new();
        let mut returns = BTreeSet::new();
        while let Some((
            pc,
            mut depth,
            mut hooked,
            mut dirty,
            mut stack,
            mut constants,
            mut compared,
        )) = queue.pop_front()
        {
            // Widen unrelated native counters instead of enumerating runtime loops.
            // Small exact index loops retain their values; an unknown stack index refuses.
            for (reg, value) in constants.iter_mut().enumerate() {
                let history = scalar_history.entry((pc, reg)).or_default();
                if let Some(value) = *value {
                    history.insert(value);
                }
                if history.len() > 8 {
                    *value = None;
                    compared = None;
                }
            }
            if !seen.insert((pc, depth, hooked, dirty, stack.clone(), constants, compared)) {
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
            let switch_targets = if call {
                super::switch::targets(image, pc)?
            } else {
                None
            };
            let call_clobbers = super::switch::clobbers(switch_targets.is_some());
            stack.observe(&ins, depth, &constants, &protected, call_clobbers)?;
            if ins.mnemonic == "cmp" {
                compared = scalar_operand(ins.operands.get(0), &constants)
                    .zip(scalar_operand(ins.operands.get(1), &constants));
            } else if ins.sets_flags
                || thumb_asm::flags::writes(&ins) != thumb_asm::flags::Flags::NONE
                || ins.is_call()
            {
                compared = None;
            }
            if call {
                for (reg, value) in constants.iter_mut().enumerate() {
                    if call_clobbers & (1 << reg) != 0 {
                        *value = None;
                    }
                }
            } else {
                update_constants(&ins, &mut constants);
            }
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
                if let Some(targets) = switch_targets {
                    for target in targets {
                        queue.push_back((
                            target,
                            depth,
                            hooked,
                            dirty,
                            stack.clone(),
                            constants,
                            compared,
                        ));
                    }
                    continue;
                }
                queue.push_back((
                    next,
                    depth,
                    hooked,
                    dirty,
                    stack.clone(),
                    constants,
                    compared,
                ));
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
                let taken = ins
                    .cond
                    .and_then(|cond| compared.and_then(|(a, b)| compare_condition(cond, a, b)));
                if taken != Some(false) {
                    queue.push_back((
                        target,
                        depth,
                        hooked,
                        dirty,
                        stack.clone(),
                        constants,
                        compared,
                    ));
                }
                if ins.cond.is_some() && taken != Some(true) {
                    queue.push_back((
                        next,
                        depth,
                        hooked,
                        dirty,
                        stack.clone(),
                        constants,
                        compared,
                    ));
                }
            } else {
                queue.push_back((
                    next,
                    depth,
                    hooked,
                    dirty,
                    stack.clone(),
                    constants,
                    compared,
                ));
            }
        }
        if depths.len() != 1 || returns.is_empty() {
            return Err(Error::InvalidContract);
        }
        Ok((
            *depths.iter().next().unwrap(),
            returns.into_iter().collect(),
        ))
    }
    /// Select the nearest preceding LR-saving entry whose complete local graph
    /// proves the detour's stack and link-register lifetime.
    pub fn detect(image: &[u8], site: usize) -> Result<Self, Error> {
        let (entry, (stack_bytes, returns)) = Self::nearest(image, site)?;
        Ok(Self {
            source: Sha256::digest(image).into(),
            entry,
            site,
            stack_bytes,
            returns,
        })
    }
    /// The entry [`Self::detect`] selects, without hashing the input. Callers
    /// that prove many sites of one image use this to stay linear in its size.
    pub(super) fn detect_entry(image: &[u8], site: usize) -> Result<usize, Error> {
        Self::nearest(image, site).map(|(entry, _)| entry)
    }
    fn nearest(image: &[u8], site: usize) -> Result<(usize, (usize, Vec<usize>)), Error> {
        for entry in (site.saturating_sub(0x1200)..site).step_by(2).rev() {
            if saves_link(image, entry) {
                if let Ok(frame) = Self::frame(image, entry, site) {
                    return Ok((entry, frame));
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
        self.require_source(image)?;
        if !(4..=11).contains(&register) {
            return Err(Error::InvalidContract);
        }
        Self::require_live_definition(
            image,
            self.entry,
            self.site,
            definition,
            definition_end,
            register,
        )
    }

    /// Require a caller argument's definition to dominate this call. Calls
    /// invalidate volatile registers; saved-register ABI preservation is explicit.
    pub fn require_argument_definition(
        &self,
        image: &[u8],
        definition: usize,
        end: usize,
        register: u8,
    ) -> Result<(), Error> {
        self.require_source(image)?;
        Self::require_live_definition(image, self.entry, self.site, definition, end, register)
    }

    /// Prove a register definition on every path from a native entry to a read.
    /// Unlike detour binding, this does not impose an LR contract on the function tail.
    pub fn require_live_definition(
        image: &[u8],
        entry: usize,
        site: usize,
        definition: usize,
        definition_end: usize,
        register: u8,
    ) -> Result<(), Error> {
        if entry >= site || !saves_link(image, entry) {
            return Err(Error::InvalidContract);
        }
        if register > 12
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
            // Standalone decoding does not carry an IT block's predicate state.
            // Refuse these paths rather than treating conditional writes as definite.
            if matches!(ins.mnemonic, "it" | "udf" | "svc" | "bkpt" | "hvc" | "smc") {
                return Err(Error::InvalidContract);
            }
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
                let targets = super::switch::targets(image, pc)?;
                if super::switch::clobbers(targets.is_some()) & (1 << register) != 0 {
                    live = false;
                }
                if let Some(targets) = targets {
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
#[path = "caller_live_definition_tests.rs"]
mod live_definition_tests;

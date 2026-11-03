//! Native response I/O, bound to native callers rather than instruction-address rank.
use super::decoded::{constant_definition, exact, instruction, literal_load, memory_is, transfer};
use super::{Error, SavedLink};
use thumb_asm::isa::{decode_at, Insn, Operand, Reg};

const SRAM: core::ops::Range<u32> = 0x02000000..0x02002000;
/// Bytes before a committer call searched for its `r0` constant argument.
const ARGUMENT_WINDOW: usize = 0x60;

/// A `register` constant: a [`constant_definition`] or a bare `mov rN,#imm`.
fn argument_constant(image: &[u8], at: usize, register: u8) -> Option<(u32, usize)> {
    if let Some(found) = constant_definition(image, at, register) {
        return Some(found);
    }
    let ins = instruction(image, at)?;
    match (ins.mnemonic, ins.operands.get(0), ins.operands.get(1)) {
        ("mov", Some(Operand::Reg(dest)), Some(Operand::Imm(value))) if dest.num() == register => {
            Some((u32::try_from(value).ok()?, at + ins.len()))
        }
        _ => None,
    }
}

/// Whether this instruction certainly replaces `r0`'s value.
fn writes_r0(ins: &Insn) -> bool {
    match ins.mnemonic {
        "pop" | "ldm" | "ldmia" | "ldmdb" => ins
            .operands
            .as_slice()
            .any(|op| matches!(op, Operand::RegList(bits) if bits & 1 != 0)),
        "cmp" | "cmn" | "tst" | "teq" | "push" | "nop" => false,
        m if m.starts_with("str") || m.starts_with("stm") => false,
        "mov" if ins.operands.get(1) == Some(Operand::Reg(Reg(0))) => false,
        _ => ins.operands.get(0) == Some(Operand::Reg(Reg(0))),
    }
}

/// Whether `r0`, as left at `from`, may still hold that value at the call at
/// `site`: unless every path from `from` within `from..=site` is shown to
/// write `r0`, call, return, or run past the call, it may.
fn may_reach(image: &[u8], from: usize, site: usize) -> bool {
    let mut pending = vec![from];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(pc) = pending.pop() {
        if pc == site {
            return true;
        }
        // Falling past `site` means this instruction stream skips the call.
        if pc > site || !seen.insert(pc) {
            continue;
        }
        let Some(ins) = decode_at(image, pc) else {
            return true;
        };
        if ins.mnemonic == "it" {
            return true;
        }
        if ins.is_call() {
            // A byte-table switch keeps r0; other calls clobber it.
            if !matches!(super::switch::targets(image, pc), Ok(None)) {
                return true;
            }
            continue;
        }
        if ins.is_branch() {
            let returns = ins.mnemonic == "pop"
                || (ins.mnemonic == "bx" && ins.operands.get(0) == Some(Operand::Reg(Reg::LR)));
            if returns {
                continue;
            }
            match ins.branch_target().map(|target| target as usize) {
                Some(target) if ins.mnemonic == "b" && (from..=site).contains(&target) => {
                    pending.push(target);
                }
                _ => return true,
            }
            if ins.cond.is_some() {
                pending.push(pc + ins.len());
            }
            continue;
        }
        if !writes_r0(&ins) {
            pending.push(pc + ins.len());
        }
    }
    false
}

#[derive(Clone, Copy)]
enum DmaValue {
    Unknown,
    Offset,
    Literal(u32),
    Source,
    Address,
}
/// Native DMA response committer, with source-pointer, DMA destination and
/// transfer-length operands established from decoded instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseCommit {
    entry: usize,
    source_cell: u32,
    length_cell: u32,
    protocol: super::response_return::Protocol,
}
impl ResponseCommit {
    /// Validate the committer grammar at exactly `entry`. This does not prove a
    /// native caller; [`ResponseIo`] binds the entry to the INQUIRY handler's call.
    pub fn at(image: &[u8], entry: usize) -> Result<Self, Error> {
        let (_, source_cell) = literal_load(image, entry).ok_or(Error::UnknownLayout)?;
        if !SRAM.contains(&source_cell) || source_cell & 3 != 0 {
            return Err(Error::InvalidContract);
        }
        let mut values = [DmaValue::Unknown; 16];
        values[0] = DmaValue::Offset;
        let mut pc = entry;
        while pc < entry.saturating_add(0x48) {
            let ins = instruction(image, pc).ok_or(Error::InvalidContract)?;
            if ins.is_branch() || ins.writes_pc() {
                return Err(Error::InvalidContract);
            }
            if let Some((source, memory)) = transfer(image, pc, "str") {
                if source.num() != 0
                    || memory.offset != 0x28
                    || !matches!(values[0], DmaValue::Address)
                    || !matches!(values[usize::from(memory.base.num())], DmaValue::Literal(v) if (0x04000000..0x05000000).contains(&v))
                {
                    return Err(Error::InvalidContract);
                }
                let (length_register, length_cell) =
                    literal_load(image, pc + ins.len()).ok_or(Error::InvalidContract)?;
                let (_, load) =
                    transfer(image, pc + ins.len() + 2, "ldrh").ok_or(Error::InvalidContract)?;
                if !SRAM.contains(&length_cell)
                    || length_cell & 1 != 0
                    || load.base != length_register
                    || load.offset != 0
                {
                    return Err(Error::InvalidContract);
                }
                let protocol =
                    super::response_return::validate(image, entry, source_cell, length_cell)?;
                return Ok(Self {
                    entry,
                    source_cell,
                    length_cell,
                    protocol,
                });
            }
            let first = ins.operands.get(0);
            let second = ins.operands.get(1);
            if let Some((dest, value)) = literal_load(image, pc) {
                values[usize::from(dest.num())] = DmaValue::Literal(value);
            } else if let Some((dest, memory)) = transfer(image, pc, "ldr") {
                values[usize::from(dest.num())] = if memory.offset == 0
                    && matches!(values[usize::from(memory.base.num())], DmaValue::Literal(v) if v == source_cell)
                {
                    DmaValue::Source
                } else {
                    DmaValue::Unknown
                };
            } else if ins.mnemonic == "add" {
                let (Some(Operand::Reg(dest)), Some(Operand::Reg(left)), Some(Operand::Reg(right))) =
                    (first, second, ins.operands.get(2))
                else {
                    return Err(Error::InvalidContract);
                };
                values[usize::from(dest.num())] = match (
                    values[usize::from(left.num())],
                    values[usize::from(right.num())],
                ) {
                    (DmaValue::Source, DmaValue::Offset) | (DmaValue::Offset, DmaValue::Source) => {
                        DmaValue::Address
                    }
                    _ => DmaValue::Unknown,
                };
            } else if ins.mnemonic != "push" {
                return Err(Error::InvalidContract);
            }
            pc += ins.len();
        }
        Err(Error::UnknownLayout)
    }
    /// Inspect all candidates in a code extent; conflicting valid roles refuse.
    pub fn inspect_in(image: &[u8], lo: usize, hi: usize) -> Result<Self, Error> {
        let mut found = None;
        for entry in (lo..hi.min(image.len())).step_by(2) {
            if !literal_load(image, entry).is_some_and(|(_, value)| SRAM.contains(&value)) {
                continue;
            }
            if let Ok(candidate) = Self::at(image, entry) {
                if found.replace(candidate).is_some() {
                    return Err(Error::Ambiguous);
                }
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
    /// Native function entry.
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Proven native writes of the transfer length to the DMA interface.
    pub fn length_writes(&self) -> &[usize] {
        &self.protocol.length_writes
    }
    /// SRAM queue flag set after preparing the transfer.
    pub fn ready_cell(&self) -> u32 {
        self.protocol.ready_cell
    }
    /// Balanced native function exits after preparing and queuing the response.
    pub fn returns(&self) -> &[usize] {
        &self.protocol.returns
    }
    /// Native physical response-buffer pointer cell, shared with the byte writer.
    pub fn source_cell(&self) -> u32 {
        self.source_cell
    }
    /// Native transfer-length SRAM cell.
    pub fn length_cell(&self) -> u32 {
        self.length_cell
    }
}

fn writer_tail(image: &[u8], at: usize) -> Option<(u32, u32)> {
    use Operand::{Imm, Reg as R};
    let r = |value| R(Reg(value));
    if !exact(image, at, "add", &[r(0), r(0), r(2)]) {
        return None;
    }
    let (upper_reg, upper) = literal_load(image, at + 2)?;
    let (lower_reg, lower) = literal_load(image, at + 8)?;
    (upper_reg.num() == 2
        && lower_reg.num() == 2
        && memory_is(image, at + 4, "ldr", 2, 2, 0)
        && exact(image, at + 6, "add", &[r(0), r(2), r(0)])
        && exact(image, at + 10, "lsl", &[r(0), r(0), Imm(8)])
        && memory_is(image, at + 12, "ldr", 2, 2, 0)
        && exact(image, at + 14, "lsr", &[r(0), r(0), Imm(8)])
        && exact(image, at + 16, "add", &[r(0), r(0), r(2)])
        && memory_is(image, at + 18, "strb", 1, 0, 0)
        && exact(image, at + 20, "bx", &[r(14)]))
    .then_some((upper, lower))
}

/// Source-borrowing response I/O witness. The native INQUIRY dispatch record
/// identifies the committer; other proven callers identify its scratch offsets.
#[derive(Debug)]
pub struct ResponseIo<'a> {
    image: &'a [u8],
    writer: usize,
    buffer_offset: u32,
    commit: ResponseCommit,
}
impl<'a> ResponseIo<'a> {
    /// Inspect independently validated native command, caller and writer roles.
    pub fn inspect(image: &'a [u8]) -> Result<Self, Error> {
        let commands = super::CommandDispatch::inspect(image)?;
        Self::from_dispatch(&commands)
    }
    pub(super) fn from_dispatch(commands: &super::CommandDispatch<'a>) -> Result<Self, Error> {
        let image = commands.image();
        let entry = (commands.record(0x12, 7)?.handler & !1) as usize;
        let mut prologue = entry;
        while prologue < entry.saturating_add(8) && literal_load(image, prologue).is_some() {
            prologue += 2;
        }
        if !instruction(image, prologue).is_some_and(|ins| {
            ins.mnemonic == "push"
                && ins
                    .operands
                    .as_slice()
                    .any(|op| matches!(op, Operand::RegList(bits) if bits & (1 << 14) != 0))
        }) {
            return Err(Error::InvalidContract);
        }
        let mut pairs = Vec::new();
        for site in (prologue + 2
            ..entry
                .saturating_add(0x200)
                .min(image.len().saturating_sub(4)))
            .step_by(2)
        {
            let Some(target) = thumb_asm::decode_bl(image, site) else {
                continue;
            };
            let Ok(commit) = ResponseCommit::at(image, target as usize) else {
                continue;
            };
            if SavedLink::bind(image, prologue, site).is_err() {
                continue;
            }
            let mut argument = None;
            for definition in (site.saturating_sub(ARGUMENT_WINDOW).max(prologue)..site).step_by(2)
            {
                let Some((offset, end)) = constant_definition(image, definition, 0) else {
                    continue;
                };
                if end > site
                    || SavedLink::require_live_definition(image, prologue, site, definition, end, 0)
                        .is_err()
                {
                    continue;
                }
                if argument.replace(offset).is_some() {
                    return Err(Error::Ambiguous);
                }
            }
            let Some(offset) = argument else {
                continue;
            };
            if offset == 0 || offset >= 0x01000000 || offset & 3 != 0 {
                return Err(Error::InvalidContract);
            }
            pairs.push((offset, commit));
        }
        pairs.sort_by_key(|(offset, commit)| (*offset, commit.entry));
        pairs.dedup();
        if pairs.len() != 1 {
            return Err(if pairs.is_empty() {
                Error::UnknownLayout
            } else {
                Error::Ambiguous
            });
        }
        let (_, commit) = pairs.pop().ok_or(Error::UnknownLayout)?;
        let mut writers = Vec::new();
        for at in (0..image.len().saturating_sub(22) + 1).step_by(2) {
            let Some((upper, lower)) = writer_tail(image, at) else {
                continue;
            };
            let mut prefix = None;
            for start in [at.checked_sub(2), at.checked_sub(4)].into_iter().flatten() {
                if let Some((offset, end)) = argument_constant(image, start, 2) {
                    if end == at && prefix.replace((start, offset)).is_some() {
                        return Err(Error::Ambiguous);
                    }
                }
            }
            let Some((start, offset)) = prefix else {
                continue;
            };
            if upper != commit.source_cell
                || lower.checked_add(4) != Some(upper)
                || !SRAM.contains(&lower)
            {
                continue;
            }
            writers.push((start, offset));
        }
        // Only writer offsets are consulted, so other caller arguments are
        // not proven.
        let offsets: std::collections::BTreeSet<u32> =
            writers.iter().map(|&(_, offset)| offset).collect();
        let mut buffers = std::collections::BTreeSet::new();
        // Offsets passed by callers whose argument cannot be proven still
        // count as writer candidates, so they refuse instead of disappearing.
        let mut unproven = std::collections::BTreeSet::new();
        for site in (4..image.len().saturating_sub(3)).step_by(2) {
            if thumb_asm::decode_bl(image, site) != Some(commit.entry as u32) {
                continue;
            }
            let parent = SavedLink::detect_entry(image, site).ok();
            for definition in (site.saturating_sub(ARGUMENT_WINDOW)..site).step_by(2) {
                let Some((offset, end)) = argument_constant(image, definition, 0) else {
                    continue;
                };
                // A definition every path overwrites, or that returns or calls
                // before this call, is not its argument.
                if end > site
                    || !offsets.contains(&offset)
                    || buffers.contains(&offset)
                    || !may_reach(image, end, site)
                {
                    continue;
                }
                let live = parent.is_some_and(|entry| {
                    SavedLink::require_live_definition(image, entry, site, definition, end, 0)
                        .is_ok()
                });
                if live {
                    buffers.insert(offset);
                } else {
                    unproven.insert(offset);
                }
            }
        }
        let mut writer = None;
        let mut contested = false;
        let mut selected_offset = 0;
        for (start, offset) in writers {
            if !buffers.contains(&offset) {
                contested |= unproven.contains(&offset);
                continue;
            }
            if offset == 0 || offset >= 0x01000000 || offset & 3 != 0 {
                return Err(Error::InvalidContract);
            }
            if writer.replace(start).is_some() {
                return Err(Error::Ambiguous);
            }
            selected_offset = offset;
        }
        if contested {
            return Err(Error::Ambiguous);
        }
        Ok(Self {
            image,
            writer: writer.ok_or(Error::UnknownLayout)?,
            buffer_offset: selected_offset,
            commit,
        })
    }
    /// Immutable source owning these landmarks; no second-image argument exists.
    pub fn image(&self) -> &'a [u8] {
        self.image
    }
    /// Native byte writer for the command scratch response buffer.
    pub fn writer(&self) -> usize {
        self.writer
    }
    /// Caller-proven buffer offset passed to the native committer.
    pub fn buffer_offset(&self) -> u32 {
        self.buffer_offset
    }
    /// Native response committer.
    pub fn commit(&self) -> &ResponseCommit {
        &self.commit
    }
}

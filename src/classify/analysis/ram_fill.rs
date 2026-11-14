//! Bounded native word-store loops and private loader initialization lifetime.
use super::decoded::{exact, instruction, literal_load, memory_is, transfer};
use super::{arm, conditional};
use thumb_asm::isa::{Operand, Reg};
use thumb_asm::Cond;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Fill {
    pub prefix: usize,
    pub body: usize,
    pub exit: usize,
    pub address: u32,
    pub length: u32,
    pub destination: u8,
    pub counter: u8,
    pub loader_private: bool,
}
fn branch(image: &[u8], at: usize, target: usize) -> bool {
    instruction(image, at).is_some_and(|ins| {
        ins.mnemonic == "b" && ins.cond.is_none() && ins.branch_target() == Some(target as u32)
    })
}
fn step(image: &[u8], at: usize, mnemonic: &str, register: Reg, amount: i64) -> bool {
    use Operand::{Imm, Reg as R};
    exact(
        image,
        at,
        mnemonic,
        &[R(register), R(register), Imm(amount)],
    ) || exact(image, at, mnemonic, &[R(register), Imm(amount)])
}

/// Decoded direct entries, indexed once for the whole image. Raw literal words
/// are not control-flow edges; this does not resolve arbitrary indirect execution.
#[derive(Default)]
pub(super) struct Entries(std::collections::BTreeMap<usize, Vec<usize>>);
impl Entries {
    pub fn inspect(image: &[u8]) -> Self {
        let mut result = Self::default();
        let mut decoder = thumb_asm::isa::Decoder::at(image, 0, 0);
        loop {
            let at = decoder.pos();
            if at + 2 > image.len() {
                break;
            }
            let Some(ins) = decoder.next() else {
                thumb_asm::isa::Decoder::skip(&mut decoder, 2);
                continue;
            };
            if ins
                .operands
                .as_slice()
                .any(|operand| matches!(operand, Operand::Mem(_)))
            {
                continue;
            }
            if let Some(target) = ins.branch_target() {
                result.0.entry((target & !1) as usize).or_default().push(at);
            }
        }
        result
    }
    pub(super) fn closed(&self, prefix: usize, end: usize) -> bool {
        self.0
            .range(prefix + 2..end)
            .all(|(_, entries)| entries.iter().all(|at| *at >= prefix && *at < end))
    }
}

impl Fill {
    #[cfg(test)]
    pub fn at(image: &[u8], at: usize, entries: &Entries) -> Option<Self> {
        let pattern = Self::word_pattern(image, at)?;
        entries.closed(at, pattern.exit).then_some(pattern)
    }
    pub fn word_pattern(image: &[u8], at: usize) -> Option<Self> {
        use Operand::{Imm, Reg as R};
        let (counter, length) = literal_load(image, at)?;
        let (destination, address) = literal_load(image, at + 2)?;
        if counter == destination || length > 0x2000 || !(0x02000000..0x02002000).contains(&address)
        {
            return None;
        }
        let initializer = instruction(image, at + 6).and_then(|ins| {
            if ins.mnemonic != "mov" {
                return None;
            }
            match (ins.operands.get(0), ins.operands.get(1)) {
                (Some(R(reg)), Some(Imm(0))) => Some(reg),
                _ => None,
            }
        });
        let body = at + if initializer.is_some() { 10 } else { 8 };
        let c = counter.num();
        let d = destination.num();
        let (source, memory) = transfer(image, body, "str")?;
        if source == counter
            || source == destination
            || memory.base != destination
            || memory.offset != 0
            || !exact(image, at + 4, "lsr", &[R(counter), R(counter), Imm(2)])
            || initializer.is_some_and(|reg| reg != source)
            || !branch(image, body - 2, body + 6)
            || !step(image, body + 2, "add", destination, 4)
            || !step(image, body + 4, "sub", counter, 1)
            || !exact(image, body + 6, "cmp", &[R(counter), Imm(0)])
            || conditional(image, body + 8, Cond::Ne) != Some(body)
        {
            return None;
        }
        let loader_private = c == 1 && d == 0 && source == Reg(2) && private_initializer(image, at);
        Some(Self {
            prefix: at,
            body,
            exit: body + 10,
            address,
            length: length & !3,
            destination: d,
            counter: c,
            loader_private,
        })
    }
}
/// Byte-counted store loop, including zero-length loops. The incoming branch
/// tests the count before the first store; external body entries invalidate it.
impl Fill {
    #[cfg(test)]
    pub fn byte_at(image: &[u8], at: usize, entries: &Entries) -> Option<Self> {
        let pattern = Self::byte_pattern(image, at)?;
        entries.closed(at, pattern.exit).then_some(pattern)
    }
    pub fn byte_pattern(image: &[u8], at: usize) -> Option<Self> {
        use Operand::{Imm, Reg as R};
        let (destination, address) = literal_load(image, at)?;
        let (counter, length) = literal_load(image, at + 2)?;
        let body = at + 6;
        let (source, memory) = transfer(image, body, "strb")?;
        if counter == destination
            || source == counter
            || source == destination
            || length > 0x2000
            || !(0x02000000..0x02002000).contains(&address)
            || memory.base != destination
            || memory.offset != 0
            || !branch(image, at + 4, body + 6)
            || !step(image, body + 2, "add", destination, 1)
            || !step(image, body + 4, "sub", counter, 1)
            || !exact(image, body + 6, "cmp", &[R(counter), Imm(0)])
            || conditional(image, body + 8, Cond::Ne) != Some(body)
        {
            return None;
        }
        Some(Self {
            prefix: at,
            body,
            exit: body + 10,
            address,
            length,
            destination: destination.num(),
            counter: counter.num(),
            loader_private: false,
        })
    }
}

/// Native word-counted copy. Length comes from its literal definition, not
/// from a guessed iteration count in a local pointer-seeded walk.
#[derive(Debug, Clone, Copy)]
pub(super) struct CopyLoop {
    pub prefix: usize,
    pub body: usize,
    pub exit: usize,
    pub source: (u8, u32),
    pub destination: (u8, u32),
    pub counter: u8,
    pub temporary: u8,
    pub length: u32,
    pub loader_private: bool,
}
impl CopyLoop {
    #[cfg(test)]
    pub fn at(image: &[u8], at: usize, entries: &Entries) -> Option<Self> {
        let pattern = Self::pattern(image, at)?;
        entries.closed(at, pattern.exit).then_some(pattern)
    }
    pub fn pattern(image: &[u8], at: usize) -> Option<Self> {
        use Operand::{Imm, Reg as R};
        let (counter, length) = literal_load(image, at)?;
        let (source, from) = literal_load(image, at + 2)?;
        let (destination, to) = literal_load(image, at + 4)?;
        // Some native application initializers save their frame after loading
        // the copy arguments. PUSH changes SP but none of these low registers.
        let saves_frame = instruction(image, at + 8).is_some_and(|ins| ins.mnemonic == "push");
        let body = at + if saves_frame { 12 } else { 10 };
        let (temporary, read) = transfer(image, body, "ldr")?;
        let (stored, write) = transfer(image, body + 2, "str")?;
        let mut registers = [
            counter.num(),
            source.num(),
            destination.num(),
            temporary.num(),
        ];
        registers.sort_unstable();
        if registers.windows(2).any(|pair| pair[0] == pair[1])
            || length > 0x2000
            || !(0x02000000..0x02002000).contains(&to)
            || read.base != source
            || read.offset != 0
            || write.base != destination
            || write.offset != 0
            || stored != temporary
            || !exact(image, at + 6, "lsr", &[R(counter), R(counter), Imm(2)])
            || !branch(image, body - 2, body + 10)
            || !step(image, body + 4, "add", source, 4)
            || !step(image, body + 6, "add", destination, 4)
            || !step(image, body + 8, "sub", counter, 1)
            || !exact(image, body + 10, "cmp", &[R(counter), Imm(0)])
            || conditional(image, body + 12, Cond::Ne) != Some(body)
        {
            return None;
        }
        let loader_private = !saves_frame
            && Fill::word_pattern(image, body + 14).is_some_and(|fill| fill.loader_private);
        Some(Self {
            prefix: at,
            body,
            exit: body + 14,
            source: (source.num(), from),
            destination: (destination.num(), to),
            counter: counter.num(),
            temporary: temporary.num(),
            length: length & !3,
            loader_private,
        })
    }
}

fn private_initializer(image: &[u8], fill: usize) -> bool {
    use Operand::{Imm, Reg as R};
    let Some(entry) = fill.checked_sub(24) else {
        return false;
    };
    let r = |n| R(Reg(n));
    let end = crate::envelope::layout::BOOT_MIRROR.start;
    if fill + 20 > end {
        return false;
    }
    let Some((Reg(2), length)) = literal_load(image, entry) else {
        return false;
    };
    let Some((Reg(0), source)) = literal_load(image, entry + 2) else {
        return false;
    };
    let Some((Reg(1), destination)) = literal_load(image, entry + 4) else {
        return false;
    };
    if source
        .checked_add(length)
        .map_or(true, |last| last as usize > image.len())
        || !(0x02000000..0x02002000).contains(&destination)
        || !exact(image, entry + 6, "lsr", &[r(2), r(2), Imm(2)])
        || !branch(image, entry + 8, entry + 20)
        || !memory_is(image, entry + 10, "ldr", 3, 0, 0)
        || !memory_is(image, entry + 12, "str", 3, 1, 0)
        || !step(image, entry + 14, "add", Reg(0), 4)
        || !step(image, entry + 16, "add", Reg(1), 4)
        || !step(image, entry + 18, "sub", Reg(2), 1)
        || !exact(image, entry + 20, "cmp", &[r(2), Imm(0)])
        || conditional(image, entry + 22, Cond::Ne) != Some(entry + 10)
        || !exact(image, fill + 18, "bx", &[r(14)])
    {
        return false;
    }
    // Equal numeric table words are potential data, not witnessed execution.
    // Keep actual instruction references and the independent A32 branch check;
    // arbitrary indirect entries are outside this static lifetime observation.
    let references: Vec<_> = thumb_asm::analysis::xrefs(image, entry as u32)
        .into_iter()
        .filter(|reference| reference.kind != thumb_asm::analysis::XrefKind::LiteralPool)
        .collect();
    !references.is_empty()
        && references.iter().all(|reference| reference.at < end)
        && !arm::external_branch(image, entry, end)
}

#[cfg(test)]
#[path = "ram_fill_tests.rs"]
mod tests;

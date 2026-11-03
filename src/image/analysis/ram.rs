//! Static SRAM references, with explicit limits rather than a free-memory claim.
use super::decoded::literal_load;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thumb_asm::isa::{decode_at, Operand};

const LOW: u32 = 0x02000000;
const HIGH: u32 = 0x02002000;

/// Observed static references. Absence is not proof that runtime firmware
/// or a subsequently loaded program cannot use a cell.
#[derive(Debug, Default)]
pub struct RamReferences {
    bytes: BTreeSet<u32>,
    incomplete: BTreeSet<usize>,
    calls: BTreeSet<(usize, u32, u32)>,
    uses: BTreeSet<(usize, u32, u32)>,
    fills: BTreeSet<(usize, u32, u32, bool)>,
}
/// One bit per byte of the inspected SRAM window. Walks revisit the same
/// fills and copies many times, so marking must cost words, not bytes.
type Window = [u64; ((HIGH - LOW) / 64) as usize];

fn mark(window: &mut Window, start: u32, width: u32) {
    let end = start.saturating_add(width).min(HIGH);
    let start = start.max(LOW);
    if end <= start {
        return;
    }
    let (mut at, end) = ((start - LOW) as usize, (end - LOW) as usize);
    while at < end {
        let bit = at % 64;
        let count = (64 - bit).min(end - at);
        window[at / 64] |= (u64::MAX >> (64 - count)) << bit;
        at += count;
    }
}

impl RamReferences {
    /// Include direct data/ARM literal words, then follow decoded Thumb pointer
    /// aliases through connected local flow, rather than a fixed instruction tail.
    pub fn inspect(image: &[u8]) -> Self {
        let mut result = Self::default();
        let mut window: Window = [0; ((HIGH - LOW) / 64) as usize];
        let entries = super::ram_fill::Entries::inspect(image);
        let mut preheaders = Vec::new();
        let fills: BTreeMap<_, _> = (0..image.len().saturating_sub(20))
            .step_by(2)
            .filter_map(|at| {
                let pattern = super::ram_fill::Fill::word_pattern(image, at)
                    .or_else(|| super::ram_fill::Fill::byte_pattern(image, at))?;
                if entries.closed(pattern.prefix, pattern.body) {
                    preheaders.push((pattern.prefix, pattern.body));
                }
                super::ram_fill::Fill::at(image, at, &entries)
                    .or_else(|| super::ram_fill::Fill::byte_at(image, at, &entries))
            })
            .map(|fill| (fill.body, fill))
            .collect();
        let fill_preheaders = preheaders.len();
        let copies: BTreeMap<_, _> = (0..image.len().saturating_sub(24))
            .step_by(2)
            .filter_map(|at| {
                let pattern = super::ram_fill::CopyLoop::pattern(image, at)?;
                if entries.closed(pattern.prefix, pattern.body) {
                    preheaders.push((pattern.prefix, pattern.body));
                }
                super::ram_fill::CopyLoop::at(image, at, &entries)
            })
            .map(|copy| (copy.body, copy))
            .collect();
        // Each segment is ordered by prefix and every preheader is short, so a
        // seed only needs the entries whose span can still reach it.
        let span = preheaders.iter().map(|(prefix, body)| body - prefix).max();
        let (fill_preheaders, copy_preheaders) = preheaders.split_at(fill_preheaders);
        result.fills.extend(
            fills
                .values()
                .map(|fill| (fill.prefix, fill.address, fill.length, fill.loader_private)),
        );
        for bytes in image.chunks_exact(4) {
            let value = u32::from_le_bytes(bytes.try_into().expect("four-byte chunk"));
            if (LOW..HIGH).contains(&value) {
                mark(&mut window, value, 4);
            }
        }
        for seed in (0..image.len().saturating_sub(2)).step_by(2) {
            let Some((reg, base)) = literal_load(image, seed) else {
                continue;
            };
            if !(LOW..HIGH).contains(&base) {
                continue;
            }
            let mut values = [None; 16];
            // A closed straight-line preheader proves the count definition
            // before this pointer literal. Replay it instead of inventing an
            // unknown loop count when starting immediately after the pointer.
            let start = span.and_then(|span| {
                [fill_preheaders, copy_preheaders]
                    .into_iter()
                    .find_map(|segment| {
                        let first = segment.partition_point(|(prefix, _)| prefix + span <= seed);
                        segment[first..]
                            .iter()
                            .take_while(|(prefix, _)| *prefix <= seed)
                            .find_map(|(prefix, body)| (seed < *body).then_some(*prefix))
                    })
            });
            let start = match start {
                Some(prefix) => prefix,
                None => {
                    values[usize::from(reg.num())] = Some(base);
                    seed + 2
                }
            };
            let mut pending = VecDeque::from([(start, values, None::<bool>)]);
            let mut visited = BTreeSet::new();
            while let Some((pc, mut values, mut zero)) = pending.pop_front() {
                if !visited.insert((pc, values, zero)) {
                    continue;
                }
                if visited.len() > 512 || pc < seed.saturating_sub(0x100) || pc >= seed + 0x1200 {
                    result.incomplete.insert(seed);
                    continue;
                }
                if let Some(copy) = copies.get(&pc) {
                    if !copy.loader_private && copy.length != 0 {
                        mark(&mut window, copy.destination.1, copy.length);
                    }
                    // A source in SRAM is still observed as a read, even during startup.
                    mark(&mut window, copy.source.1, copy.length);
                    values[usize::from(copy.source.0)] = copy.source.1.checked_add(copy.length);
                    values[usize::from(copy.destination.0)] =
                        copy.destination.1.checked_add(copy.length);
                    values[usize::from(copy.counter)] = Some(0);
                    values[usize::from(copy.temporary)] = None;
                    pending.push_back((copy.exit, values, Some(true)));
                    continue;
                }
                if let Some(fill) = fills.get(&pc) {
                    if fill.length != 0 && !fill.loader_private {
                        mark(&mut window, fill.address, fill.length);
                    }
                    values[usize::from(fill.destination)] = fill.address.checked_add(fill.length);
                    values[usize::from(fill.counter)] = Some(0);
                    pending.push_back((fill.exit, values, Some(true)));
                    continue;
                }
                let Some(ins) = decode_at(image, pc) else {
                    result.incomplete.insert(seed);
                    continue;
                };
                if ins.mnemonic == "it" || (ins.len() == 4 && !ins.is_call()) {
                    result.incomplete.insert(seed);
                    continue;
                }
                if let Some(Operand::Mem(memory)) = ins.operands.get(1) {
                    if let Some(pointer) = values[usize::from(memory.base.num())] {
                        if (LOW..HIGH).contains(&pointer) {
                            let index = match memory.index {
                                None => Some(0),
                                Some((register, None)) => values[usize::from(register.num())],
                                _ => None,
                            };
                            let width = match ins.mnemonic {
                                "ldrb" | "ldrsb" | "strb" => 1,
                                "ldrh" | "ldrsh" | "strh" => 2,
                                _ => 4,
                            };
                            if memory.mode == thumb_asm::isa::AddrMode::Offset {
                                if let Some(address) = index
                                    .and_then(|v| v.checked_add(memory.offset))
                                    .and_then(|offset| {
                                        if memory.add {
                                            pointer.checked_add(offset)
                                        } else {
                                            pointer.checked_sub(offset)
                                        }
                                    })
                                {
                                    mark(&mut window, address, width);
                                    result.uses.insert((pc, address, width));
                                } else {
                                    result.incomplete.insert(seed);
                                }
                            } else {
                                result.incomplete.insert(seed);
                            }
                        }
                    }
                }
                // 16-bit `stmia rN!` / `ldmia rN{!}` carry their base as a
                // register or writeback text, not `Operand::Mem`.
                let mut written_back = None;
                if let ("stmia" | "ldmia", Some(Operand::RegList(list))) =
                    (ins.mnemonic, ins.operands.get(1))
                {
                    let base = match ins.operands.get(0) {
                        Some(Operand::Reg(reg)) => Some((reg.num(), false)),
                        Some(Operand::Text(text)) => text
                            .strip_prefix('r')
                            .and_then(|text| text.strip_suffix('!'))
                            .and_then(|text| text.parse::<u8>().ok())
                            .filter(|reg| *reg < 16)
                            .map(|reg| (reg, true)),
                        _ => None,
                    };
                    if let Some((base, writeback)) = base {
                        if let Some(pointer) = values[usize::from(base)] {
                            if (LOW..HIGH).contains(&pointer) {
                                let words = list.count_ones();
                                for word in 0..words {
                                    let address = pointer + 4 * word;
                                    mark(&mut window, address, 4);
                                    result.uses.insert((pc, address, 4));
                                }
                                if writeback {
                                    written_back = Some((base, pointer.checked_add(4 * words)));
                                }
                            }
                        }
                    }
                }
                if ins.mnemonic == "cmp" {
                    let scalar = |operand| match operand {
                        Some(Operand::Reg(reg)) => values[usize::from(reg.num())],
                        Some(Operand::Imm(value)) => Some(value as u32),
                        _ => None,
                    };
                    zero = scalar(ins.operands.get(0))
                        .zip(scalar(ins.operands.get(1)))
                        .map(|(left, right)| left == right);
                } else if ins.sets_flags || ins.is_call() || matches!(ins.mnemonic, "tst" | "cmn") {
                    zero = None;
                }
                let switch_targets = if ins.is_call() {
                    match super::switch::targets(image, pc) {
                        Ok(targets) => targets,
                        Err(_) => {
                            result.incomplete.insert(seed);
                            continue;
                        }
                    }
                } else {
                    None
                };
                if ins.is_call() {
                    if let (None, Some(address), Some(length)) =
                        (&switch_targets, values[0], values[1])
                    {
                        if (LOW..HIGH).contains(&address) && length <= HIGH - LOW {
                            // The callee's argument convention must be validated before
                            // treating its second scalar argument as a byte count.
                            result.calls.insert((pc, address, length));
                        }
                    }
                    let clobbers = super::switch::clobbers(switch_targets.is_some());
                    for (reg, value) in values.iter_mut().enumerate() {
                        if clobbers & (1 << reg) != 0 {
                            *value = None;
                        }
                    }
                } else if let Some((reg, value)) = literal_load(image, pc) {
                    values[usize::from(reg.num())] = Some(value);
                } else {
                    super::caller::update_constants(&ins, &mut values);
                }
                if let Some((base, value)) = written_back {
                    values[usize::from(base)] = value;
                }
                let next = pc + ins.len();
                if ins.is_call() {
                    if let Some(targets) = switch_targets {
                        pending.extend(targets.into_iter().map(|target| (target, values, zero)));
                    } else {
                        pending.push_back((next, values, zero));
                    }
                    continue;
                }
                if ins.is_branch() {
                    if ins.mnemonic == "b" {
                        let taken = match ins.cond {
                            None => Some(true),
                            Some(thumb_asm::Cond::Eq) => zero,
                            Some(thumb_asm::Cond::Ne) => zero.map(|value| !value),
                            _ => None,
                        };
                        if taken != Some(false) {
                            if let Some(target) = ins.branch_target() {
                                pending.push_back((target as usize, values, zero));
                            }
                        }
                        if ins.cond.is_some() && taken != Some(true) {
                            pending.push_back((next, values, zero));
                        }
                    } else if !is_return(&ins) {
                        // cbz/cbnz, indirect bx/blx and table branches lose
                        // their successors: the path is not fully observed.
                        // Returns simply end the path.
                        result.incomplete.insert(seed);
                    }
                } else if !ins.writes_pc() {
                    pending.push_back((next, values, zero));
                }
            }
        }
        result.bytes = (0..HIGH - LOW)
            .filter(|offset| window[(offset / 64) as usize] & (1 << (offset % 64)) != 0)
            .map(|offset| LOW + offset)
            .collect();
        result
    }
    /// Byte addresses observed in literal words, decoded accesses and counted
    /// fill/copy loops. Call argument ranges are only potential and are
    /// reported by [`Self::calls`], not included here.
    pub fn bytes(&self) -> &BTreeSet<u32> {
        &self.bytes
    }
    /// Counted store-loop prefix, destination, byte count and loader-private status.
    /// Loader-private startup writes precede application flag initialization.
    pub fn fills(&self) -> &BTreeSet<(usize, u32, u32, bool)> {
        &self.fills
    }
    /// Decoded memory instruction, exact address and access width.
    pub fn uses(&self) -> &BTreeSet<(usize, u32, u32)> {
        &self.uses
    }
    /// Calls with a known SRAM first argument and bounded scalar second argument.
    /// These are potential ranges, not proven byte-count memory operations.
    pub fn calls(&self) -> &BTreeSet<(usize, u32, u32)> {
        &self.calls
    }
    /// Seed locations with an unresolved index, control flow or bounded walk.
    pub fn incomplete(&self) -> &BTreeSet<usize> {
        &self.incomplete
    }
}

/// A PC-writing function return: `pop {.., pc}`, `ldm sp.., {.., pc}`,
/// `mov pc, lr`, `ldr pc, [sp..]` and `bx lr`.
fn is_return(ins: &thumb_asm::isa::Insn) -> bool {
    let reg = |op: Option<Operand>, n: u8| matches!(op, Some(Operand::Reg(r)) if r.num() == n);
    match ins.mnemonic {
        "bx" => reg(ins.operands.get(0), 14),
        "pop" => ins.writes_pc(),
        "mov" => reg(ins.operands.get(0), 15) && reg(ins.operands.get(1), 14),
        "ldr" => {
            reg(ins.operands.get(0), 15)
                && matches!(ins.operands.get(1), Some(Operand::Mem(m)) if m.base.num() == 13)
        }
        "ldm" | "ldmia" | "ldmdb" => ins.writes_pc() && reg(ins.operands.get(0), 13),
        _ => false,
    }
}

#[cfg(test)]
#[path = "ram_tests.rs"]
mod tests;

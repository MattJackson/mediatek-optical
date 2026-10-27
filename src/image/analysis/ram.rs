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
impl RamReferences {
    fn mark(&mut self, start: u32, width: u32) {
        let end = start.saturating_add(width).min(HIGH);
        self.bytes.extend(start.max(LOW)..end);
    }
    /// Include direct data/ARM literal words, then follow decoded Thumb pointer
    /// aliases through connected local flow, rather than a fixed instruction tail.
    pub fn inspect(image: &[u8]) -> Self {
        let mut result = Self::default();
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
        result.fills.extend(
            fills
                .values()
                .map(|fill| (fill.prefix, fill.address, fill.length, fill.loader_private)),
        );
        for bytes in image.chunks_exact(4) {
            let value = u32::from_le_bytes(bytes.try_into().expect("four-byte chunk"));
            if (LOW..HIGH).contains(&value) {
                result.mark(value, 4);
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
            let start = preheaders
                .iter()
                .find_map(|(prefix, body)| (*prefix <= seed && seed < *body).then_some(*prefix));
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
                        result.mark(copy.destination.1, copy.length);
                    }
                    // A source in SRAM is still observed as a read, even during startup.
                    result.mark(copy.source.1, copy.length);
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
                        result.mark(fill.address, fill.length);
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
                                    result.mark(address, width);
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
                    }
                } else if !ins.writes_pc() {
                    pending.push_back((next, values, zero));
                }
            }
        }
        result
    }
    /// Byte addresses observed in references or bounded native call arguments.
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

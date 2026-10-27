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
    let end = crate::layout::BOOT_MIRROR.start;
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
mod tests {
    use super::*;
    use thumb_asm::Asm;

    fn byte_fill(length: u32, external: bool) -> Vec<u8> {
        let mut a = Asm::new();
        let body = a.label();
        let check = a.label();
        a.ldr_lit(1, 0x02000e20).ldr_lit(0, length).b(check);
        a.bind(body).strb_imm(2, 1, 0).adds_imm(1, 1).subs_imm(0, 1);
        a.bind(check).cmp_imm(0, 0).b_cond(Cond::Ne, body).bx(14);
        if external {
            a.b(body);
        }
        a.finish().unwrap()
    }

    #[test]
    fn indexed_entries_agree_with_thumb_asm_reference_queries() {
        let image = byte_fill(0x40, true);
        let entries = Entries::inspect(&image);
        for prefix in (0..image.len()).step_by(2) {
            for end in (prefix + 2..=image.len()).step_by(2) {
                let expected = (prefix + 2..end).step_by(2).all(|target| {
                    thumb_asm::analysis::xrefs(&image, target as u32)
                        .iter()
                        .all(|reference| {
                            reference.kind == thumb_asm::analysis::XrefKind::LiteralPool
                                || (reference.at >= prefix && reference.at < end)
                        })
                });
                assert_eq!(
                    entries.closed(prefix, end),
                    expected,
                    "range {prefix}..{end}"
                );
            }
        }
    }

    #[test]
    fn byte_fill_has_exact_prechecked_extent_and_rejects_external_entry() {
        for length in [0, 1, 0x40] {
            let image = byte_fill(length, false);
            let fill = Fill::byte_at(&image, 0, &Entries::inspect(&image)).unwrap();
            assert_eq!(fill.length, length);
            assert_eq!(fill.address, 0x02000e20);
            let refs = super::super::RamReferences::inspect(&image);
            assert!(!refs.bytes().contains(&0x02000e60));
            assert_eq!(refs.bytes().contains(&0x02000e5f), length == 0x40);
        }
        let external = byte_fill(0, true);
        assert!(Fill::byte_at(&external, 0, &Entries::inspect(&external)).is_none());
    }

    #[test]
    fn implicit_flag_writers_do_not_reuse_an_earlier_compare() {
        use thumb_asm::isa::{Insn, Operands, Width};
        for mnemonic in ["tst", "cmn"] {
            let mut operands = Operands::new();
            operands.push(Operand::Reg(Reg(2)));
            operands.push(Operand::Reg(Reg(2)));
            let instruction = Insn {
                mnemonic,
                encoding: "T1",
                addr: 0,
                width: Width::Narrow,
                cond: None,
                sets_flags: false,
                explicit_width: false,
                operands,
            };
            let bytes = thumb_asm::isa::encode_bytes(&instruction).unwrap();
            let mut a = Asm::new();
            let write = a.label();
            a.ldr_lit(0, 0x02000e20).movs_imm(1, 0).cmp_imm(1, 0);
            a.replay(&bytes).b_cond(Cond::Ne, write).bx(14);
            a.bind(write).strb_imm(3, 0, 31).bx(14);
            let refs = super::super::RamReferences::inspect(&a.finish().unwrap());
            assert!(
                refs.bytes().contains(&0x02000e3f),
                "{mnemonic} must invalidate old Z"
            );
        }
    }

    #[test]
    fn loader_lifetime_uses_real_entries_not_equal_numeric_data_words() {
        let mut a = Asm::new();
        let copy = a.label();
        let copy_check = a.label();
        a.ldr_lit(2, 0x7c).ldr_lit(0, 0x800).ldr_lit(1, 0x02000d80);
        a.lsrs_imm(2, 2, 2).b(copy_check);
        a.bind(copy).ldr_imm(3, 0, 0).str_imm(3, 1, 0);
        a.adds_imm(0, 4).adds_imm(1, 4).subs_imm(2, 1);
        a.bind(copy_check).cmp_imm(2, 0).b_cond(Cond::Ne, copy);
        let fill = a.label();
        let check = a.label();
        a.ldr_lit(1, 0x178)
            .ldr_lit(0, 0x02000dfc)
            .lsrs_imm(1, 1, 2)
            .b(check);
        a.bind(fill).str_imm(2, 0, 0);
        a.adds_imm(0, 4).subs_imm(1, 1);
        a.bind(check).cmp_imm(1, 0).b_cond(Cond::Ne, fill).bx(14);
        let body = a.finish().unwrap();
        let mut image = vec![0; 0x11000];
        image[0x1000..0x1000 + body.len()].copy_from_slice(&body);
        thumb_asm::install_branch(&mut image, 0x200, thumb_asm::BranchKind::Bl, 0x1000).unwrap();
        image[0x10100..0x10104].copy_from_slice(&0x1000u32.to_le_bytes());
        assert!(
            Fill::at(&image, 0x1018, &Entries::inspect(&image))
                .unwrap()
                .loader_private
        );
        thumb_asm::install_branch(&mut image, 0x10040, thumb_asm::BranchKind::Bl, 0x1000).unwrap();
        assert!(
            !Fill::at(&image, 0x1018, &Entries::inspect(&image))
                .unwrap()
                .loader_private
        );
    }

    #[test]
    fn pointer_seed_recovers_a_closed_preheader_without_weakening_entry_checks() {
        // An outside branch into the body prevents whole-loop summarization.
        // Starting from the native preheader still has a known zero count and
        // must skip the store, rather than inventing an unbounded fill.
        let image = byte_fill(0, true);
        assert!(Fill::byte_at(&image, 0, &Entries::inspect(&image)).is_none());
        let refs = super::super::RamReferences::inspect(&image);
        assert!(!refs.bytes().contains(&0x02000e40));

        let mut a = Asm::new();
        let body = a.label();
        let check = a.label();
        a.ldr_lit(2, 0x40).ldr_lit(0, 0x100).ldr_lit(1, 0x02000da8);
        a.lsrs_imm(2, 2, 2).push(0x110).b(check);
        a.bind(body).ldr_imm(3, 0, 0).str_imm(3, 1, 0);
        a.adds_imm(0, 4).adds_imm(1, 4).subs_imm(2, 1);
        a.bind(check)
            .cmp_imm(2, 0)
            .b_cond(Cond::Ne, body)
            .pop(0x110);
        a.b(check); // genuine decoded external edge, retained as a refusal
        let image = a.finish().unwrap();
        assert!(CopyLoop::at(&image, 0, &Entries::inspect(&image)).is_none());
        let refs = super::super::RamReferences::inspect(&image);
        assert!(refs.bytes().contains(&0x02000de7));
        assert!(!refs.bytes().contains(&0x02000de8));
        assert!(!refs.bytes().contains(&0x02000e3c));
    }

    #[test]
    fn word_clear_with_local_zero_initializer_has_a_bounded_extent() {
        let mut a = Asm::new();
        let body = a.label();
        let check = a.label();
        a.ldr_lit(1, 0x40).ldr_lit(0, 0x02000d80).lsrs_imm(1, 1, 2);
        a.movs_imm(4, 0).b(check);
        a.bind(body).str_imm(4, 0, 0).adds_imm(0, 4).subs_imm(1, 1);
        a.bind(check).cmp_imm(1, 0).b_cond(Cond::Ne, body).bx(14);
        let image = a.finish().unwrap();
        assert_eq!(
            Fill::at(&image, 0, &Entries::inspect(&image))
                .unwrap()
                .length,
            0x40
        );
        let refs = super::super::RamReferences::inspect(&image);
        assert!(refs.bytes().contains(&0x02000dbf));
        assert!(!refs.bytes().contains(&0x02000dc0));
    }

    #[test]
    fn word_copy_uses_literal_count_not_pointer_walk_iteration_budget() {
        for (length, frame) in [(0, false), (4, false), (0x7f, false), (0x40, true)] {
            let mut a = Asm::new();
            let body = a.label();
            let check = a.label();
            a.ldr_lit(2, length)
                .ldr_lit(0, 0x100)
                .ldr_lit(1, 0x02000d80);
            a.lsrs_imm(2, 2, 2);
            if frame {
                a.push(0x110);
            }
            a.b(check);
            a.bind(body).ldr_imm(3, 0, 0).str_imm(3, 1, 0);
            a.adds_imm(0, 4).adds_imm(1, 4).subs_imm(2, 1);
            a.bind(check).cmp_imm(2, 0).b_cond(Cond::Ne, body);
            if frame {
                a.pop(0x110);
            } else {
                a.bx(14);
            }
            let image = a.finish().unwrap();
            let copy = CopyLoop::at(&image, 0, &Entries::inspect(&image)).unwrap();
            assert_eq!(copy.length, length & !3);
            let refs = super::super::RamReferences::inspect(&image);
            assert!(!refs.bytes().contains(&0x02000e40));
            assert_eq!(refs.bytes().contains(&0x02000dfb), length == 0x7f);
        }
    }
}

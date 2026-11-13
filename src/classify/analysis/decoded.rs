//! Shared predicates over thumb-asm decoded instructions, not a second decoder.
use thumb_asm::isa::{decode_at, AddrMode, Insn, Mem, Operand, Reg};

pub(super) fn instruction(image: &[u8], at: usize) -> Option<Insn> {
    let ins = decode_at(image, at)?;
    (ins.len() == 2 && ins.cond.is_none()).then_some(ins)
}

pub(super) fn plain(memory: Mem) -> bool {
    memory.mode == AddrMode::Offset && memory.index.is_none() && memory.add
}

pub(super) fn transfer(image: &[u8], at: usize, mnemonic: &str) -> Option<(Reg, Mem)> {
    let ins = instruction(image, at)?;
    let (Some(Operand::Reg(reg)), Some(Operand::Mem(memory))) =
        (ins.operands.get(0), ins.operands.get(1))
    else {
        return None;
    };
    (ins.mnemonic == mnemonic && plain(memory)).then_some((reg, memory))
}

pub(super) fn literal_load(image: &[u8], at: usize) -> Option<(Reg, u32)> {
    let (reg, memory) = transfer(image, at, "ldr")?;
    (memory.base == Reg::PC)
        .then(|| thumb_asm::analysis::literal_value(image, at).map(|value| (reg, value)))?
}

pub(super) fn exact(image: &[u8], at: usize, mnemonic: &str, operands: &[Operand]) -> bool {
    instruction(image, at).is_some_and(|ins| {
        ins.mnemonic == mnemonic && ins.operands.as_slice().eq(operands.iter().copied())
    })
}

pub(super) fn memory_is(
    image: &[u8],
    at: usize,
    mnemonic: &str,
    reg: u8,
    base: u8,
    offset: u32,
) -> bool {
    transfer(image, at, mnemonic)
        .is_some_and(|(r, m)| r.num() == reg && m.base.num() == base && m.offset == offset)
}

pub(super) fn constant_definition(image: &[u8], at: usize, register: u8) -> Option<(u32, usize)> {
    if let Some((dest, value)) = literal_load(image, at) {
        return (dest.num() == register).then_some((value, at + 2));
    }
    let ins = instruction(image, at)?;
    let (Some(Operand::Reg(dest)), Some(Operand::Imm(value))) =
        (ins.operands.get(0), ins.operands.get(1))
    else {
        return None;
    };
    if ins.mnemonic != "mov" || dest.num() != register {
        return None;
    }
    let shift = instruction(image, at + ins.len())?;
    let (Some(Operand::Reg(output)), Some(Operand::Reg(input)), Some(Operand::Imm(amount))) = (
        shift.operands.get(0),
        shift.operands.get(1),
        shift.operands.get(2),
    ) else {
        return None;
    };
    if shift.mnemonic != "lsl" || output != dest || input != dest {
        return None;
    }
    let multiplier = 1u32.checked_shl(u32::try_from(amount).ok()?)?;
    Some((
        u32::try_from(value).ok()?.checked_mul(multiplier)?,
        at + ins.len() + shift.len(),
    ))
}

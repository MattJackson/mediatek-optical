//! Native table-array registration, connected to the scanner's actual callers.
use super::decoded::{exact, instruction, literal_load, memory_is};
use super::{conditional, CommandScanner, Error, SavedLink};
use std::collections::BTreeSet;
use thumb_asm::isa::{decode_at, Operand, Reg};
use thumb_asm::Cond;

fn branch(image: &[u8], at: usize, target: usize) -> bool {
    instruction(image, at).is_some_and(|i| {
        i.mnemonic == "b" && i.cond.is_none() && i.branch_target() == Some(target as u32)
    })
}
fn multiple(image: &[u8], at: usize, mnemonic: &str, base: u8, list: u16) -> bool {
    instruction(image, at).is_some_and(|i| {
        (i.mnemonic == mnemonic
            || (mnemonic == "stm" && i.mnemonic == "stmia")
            || (mnemonic == "ldm" && i.mnemonic == "ldmia"))
            && matches!(i.operands.get(0),Some(Operand::Text(t)) if t==format!("r{base}!"))
            && i.operands.get(1) == Some(Operand::RegList(list))
    })
}

/// This native variadic registrar saves r0-r3, initializes the cache, then copies
/// the original r0 and subsequent arguments into the scanner's array slots 1+.
fn registrar(image: &[u8], at: usize, array: u32) -> bool {
    use Operand::{Imm, Reg as R};
    let r = |n| R(Reg(n));
    let lit = |off, reg, value| literal_load(image, at + off) == Some((Reg(reg), value));
    exact(image,at,"push",&[Operand::RegList(15)])
        && exact(image,at+2,"push",&[Operand::RegList((1<<4)|(1<<5)|(1<<6)|(1<<14))])
        && lit(4,5,array)
        && exact(image,at+6,"mov",&[r(1),Imm(0)])
        && exact(image,at+8,"mov",&[r(2),Imm(0)])
        && multiple(image,at+10,"stm",5,(1<<1)|(1<<2))
        && multiple(image,at+12,"stm",5,(1<<1)|(1<<2))
        && multiple(image,at+14,"stm",5,1<<2)
        && exact(image,at+16,"sub",&[r(5),Imm(20)])
        && literal_load(image,at+18).is_some_and(|(reg,_)|reg==Reg(0))
        && exact(image,at+20,"mov",&[r(1),Imm(0x48)])
        && exact(image,at+22,"add",&[r(4),r(13),Imm(20)])
        && decode_at(image,at+24).is_some_and(|i|i.is_call() && i.len()==4 && i.cond.is_none())
        && literal_load(image,at+28).is_some_and(|(reg,value)|reg==Reg(2) && (0x02000000..0x02002000).contains(&value))
        && exact(image,at+30,"mov",&[r(0),Imm(0)])
        && exact(image,at+32,"mov",&[r(1),Imm(3)])
        && exact(image,at+34,"lsl",&[r(3),r(0),Imm(3)])
        && exact(image,at+36,"add",&[r(3),r(3),r(2)])
        && exact(image,at+38,"add",&[r(0),r(0),Imm(1)])
        && exact(image,at+40,"cmp",&[r(0),Imm(9)])
        && memory_is(image,at+42,"strb",1,3,1)
        && conditional(image,at+44,Cond::Lo)==Some(at+34)
        && exact(image,at+46,"mov",&[r(0),Imm(1)])
        && memory_is(image,at+48,"str",2,5,0)
        && memory_is(image,at+50,"ldr",2,13,16)
        && exact(image,at+52,"mov",&[r(1),r(0)])
        && exact(image,at+54,"lsl",&[r(1),r(1),Imm(2)])
        && instruction(image,at+56).is_some_and(|i|i.mnemonic=="str"
            && i.operands.get(0)==Some(r(2))
            && matches!(i.operands.get(1),Some(Operand::Mem(m)) if m.base==Reg(5) && m.index==Some((Reg(1),None)) && m.offset==0 && m.add && m.mode==thumb_asm::isa::AddrMode::Offset))
        && multiple(image,at+58,"ldm",4,1<<1)
        && exact(image,at+60,"add",&[r(0),r(0),Imm(1)])
        && exact(image,at+62,"cmp",&[r(1),Imm(0)])
        && memory_is(image,at+64,"str",1,13,16)
        && conditional(image,at+66,Cond::Ne)==Some(at+50)
        && exact(image,at+68,"pop",&[Operand::RegList((1<<4)|(1<<5)|(1<<6))])
        && exact(image,at+70,"pop",&[Operand::RegList(1<<3)])
        && exact(image,at+72,"add",&[r(13),Imm(16)])
        && exact(image,at+74,"bx",&[r(3)])
}

fn arrays(image: &[u8], scanner: &CommandScanner) -> Result<BTreeSet<u32>, Error> {
    use Operand::{Imm, Reg as R};
    let mut arrays = BTreeSet::new();
    for site in thumb_asm::find_bl_sites(image, scanner.entry() as u32) {
        let Ok(parent) = SavedLink::detect(image, site) else {
            continue;
        };
        for at in (parent.entry..(site + 0x100).min(image.len().saturating_sub(8))).step_by(2) {
            let Some(shift) = instruction(image, at) else {
                continue;
            };
            let Some(R(index)) = shift.operands.get(1) else {
                continue;
            };
            if !exact(image, at, "lsl", &[R(Reg(0)), R(index), Imm(2)])
                || !exact(image, at + 4, "cmp", &[R(Reg(0)), Imm(0)])
                || conditional(image, at + 6, Cond::Ne) != Some(site)
            {
                continue;
            }
            let Some(load) = instruction(image, at + 2) else {
                continue;
            };
            let Some(Operand::Mem(mem)) = load.operands.get(1) else {
                continue;
            };
            if load.mnemonic != "ldr"
                || load.operands.get(0) != Some(R(Reg(0)))
                || mem.index != Some((Reg(0), None))
                || mem.offset != 0
                || !mem.add
                || mem.mode != thumb_asm::isa::AddrMode::Offset
                || mem.base.num() < 4
            {
                continue;
            }
            for definition in (parent.entry..at).step_by(2) {
                let Some((reg, value)) = literal_load(image, definition) else {
                    continue;
                };
                if reg != mem.base
                    || !(0x02000000..0x02002000).contains(&value)
                    || !exact(image, definition + 2, "mov", &[R(index), Imm(1)])
                    || !branch(image, definition + 4, at)
                {
                    continue;
                }
                if SavedLink::require_live_definition(
                    image,
                    parent.entry,
                    at,
                    definition,
                    definition + 2,
                    reg.num(),
                )
                .is_ok()
                {
                    arrays.insert(value);
                }
            }
        }
    }
    if arrays.is_empty() {
        return Err(Error::UnknownLayout);
    }
    Ok(arrays)
}

pub(super) fn roots(image: &[u8], scanner: &CommandScanner) -> Result<BTreeSet<usize>, Error> {
    let arrays = arrays(image, scanner)?;
    let mut registrars = BTreeSet::new();
    for at in (0..image.len().saturating_sub(76)).step_by(2) {
        if !exact(image, at, "push", &[Operand::RegList(15)]) {
            continue;
        }
        for array in &arrays {
            if registrar(image, at, *array) {
                registrars.insert(at);
            }
        }
    }
    let mut roots = BTreeSet::new();
    for at in (4..image.len().saturating_sub(4)).step_by(2) {
        let Some(ins) = decode_at(image, at) else {
            continue;
        };
        if !ins.is_call()
            || ins.cond.is_some()
            || !ins
                .branch_target()
                .is_some_and(|target| registrars.contains(&(target as usize)))
        {
            continue;
        }
        if !exact(
            image,
            at - 2,
            "mov",
            &[Operand::Reg(Reg(1)), Operand::Imm(0)],
        ) {
            continue;
        }
        let Some((reg, root)) = literal_load(image, at - 4) else {
            continue;
        };
        if reg != Reg(0) || root as usize >= image.len() || root & 3 != 0 {
            continue;
        }
        let Ok(caller) = SavedLink::detect(image, at) else {
            continue;
        };
        if caller
            .require_argument_definition(image, at - 4, at - 2, 0)
            .is_err()
        {
            continue;
        }
        roots.insert(root as usize);
    }
    if roots.is_empty() {
        return Err(Error::UnknownLayout);
    }
    Ok(roots)
}

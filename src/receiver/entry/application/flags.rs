//! Four fixed bit-test/store clauses, with explicit skip/set convergence.
use super::{clear_site, Candidate, Prologue, Window};

/// Complete operand-bound four-bit CDB-to-MMIO flag copy and return.
/// Opcode ownership and command completion are not inferred from this body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagCopy {
    /// First MMIO literal load.
    pub entry: u32,
    /// First address after the matched return.
    pub end: u32,
}

fn jump(w: &Window<'_>, at: u32) -> Option<u32> {
    if w.word(at)? & 0xf800 == 0xe000 {
        w.branch(at)
    } else {
        Some(at)
    }
}

/// Validate all four tests, OR operands, stores, convergence branches and the
/// stack-restoring return. Only a table's proven prelude may supply constants
/// and CDB pointers. This performs no I/O and does not authorize a transfer.
pub fn inspect_flags(
    bytes: &[u8],
    address: u32,
    candidate: &Candidate,
    prelude: &Prologue,
) -> Option<FlagCopy> {
    // Bind every supplied operand to these exact bytes. A stale or manually
    // altered evidence record cannot invent a CDB pointer or constant.
    if super::inspect(bytes, address)? != *candidate
        || super::inspect_prologue(bytes, address, candidate)? != *prelude
    {
        return None;
    }
    let w = Window {
        bytes,
        base: address,
    };
    if clear_site(&w, candidate.entry.checked_add(2)?)? != candidate.entry {
        return None;
    }
    let (base, _) = w.literal(candidate.entry)?;
    let mut p = candidate.entry.checked_add(10)?;
    let mut constants = prelude.constants;
    // Clear-site arithmetic destroys its temporary register.
    let clear_temp = w.word(candidate.entry + 2)? & 7;
    constants[clear_temp as usize] = None;
    constants[base as usize] = None;
    let mut cdb = prelude.cdb_registers & !(1 << base) & !(1 << clear_temp);
    if let Some((reg, literal)) = w.literal(p) {
        if literal != prelude.cdb_address || reg == base {
            return None;
        }
        cdb |= 1 << reg;
        constants[reg as usize] = None;
        p = p.checked_add(2)?;
    }
    for bit in 0..4u16 {
        p = jump(&w, p)?;
        let load = w.word(p)?;
        let temp = load & 7;
        let source = (load >> 3) & 7;
        if load != 0x7800 | (9 << 6) | (source << 3) | temp
            || cdb & (1 << source) == 0
            || temp == base
        {
            return None;
        }
        if w.word(p.checked_add(2)?)? != ((31 - bit) << 6) | (temp << 3) | temp {
            return None;
        }
        constants[temp as usize] = None;
        cdb &= !(1 << temp);
        let branch = p.checked_add(4)?;
        let condition = w.word(branch)? & 0xff00;
        let skip_condition = if bit == 0 { 0xd000 } else { 0xd500 };
        let set_condition = if bit == 0 { 0xd100 } else { 0xd400 };
        let target = w.conditional(branch, condition)?;
        let fallthrough = branch.checked_add(2)?;
        let (mut set, skip) = if condition == skip_condition {
            (fallthrough, target)
        } else if condition == set_condition {
            (target, fallthrough)
        } else {
            return None;
        };
        set = jump(&w, set)?;
        // The set arm must read precisely the MMIO register just cleared.
        let read = w.word(set)?;
        let work = read & 7;
        if read != 0x6980 | (base << 3) | work || work == base {
            return None;
        }
        set = set.checked_add(2)?;
        let before_set = constants;
        let mut after_set = constants;
        after_set[work as usize] = None;
        if w.word(set)? & 0xf800 == 0x2000 {
            let op = w.word(set)?;
            let register = (op >> 8) & 7;
            if register == base || register == work {
                return None;
            }
            after_set[register as usize] = Some(u32::from(op & 255));
            cdb &= !(1 << register);
            set = set.checked_add(2)?;
        }
        let or = w.word(set)?;
        if or & 0xffc0 != 0x4300 {
            return None;
        }
        let destination = or & 7;
        let operand = (or >> 3) & 7;
        let constant = if destination == work {
            operand
        } else if operand == work {
            destination
        } else {
            return None;
        };
        if after_set[constant as usize] != Some(1 << bit) || destination == base {
            return None;
        }
        after_set[destination as usize] = None;
        if w.word(set.checked_add(2)?)? != 0x6180 | (base << 3) | destination {
            return None;
        }
        let next_set = jump(&w, set.checked_add(4)?)?;
        let next_skip = jump(&w, skip)?;
        if next_set != next_skip {
            return None;
        }
        for reg in 0..8 {
            constants[reg] = if before_set[reg] == after_set[reg] {
                before_set[reg]
            } else {
                None
            };
        }
        cdb &= !(1 << work) & !(1 << destination);
        p = next_set;
    }
    p = jump(&w, p)?;
    if w.word(p)? != 0xb000 | (prelude.stack_bytes / 4) || w.word(p.checked_add(2)?)? != 0xbdf0 {
        return None;
    }
    Some(FlagCopy {
        entry: candidate.entry,
        end: p.checked_add(4)?,
    })
}

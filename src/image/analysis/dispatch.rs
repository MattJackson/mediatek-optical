//! Native command-record consumer, recognized by connected decoded operations.
use super::decoded::{exact, instruction, literal_load, memory_is};
use super::{conditional, Error, SavedLink};
use sha2::{Digest, Sha256};
use thumb_asm::isa::{decode_at, Operand, Reg};
use thumb_asm::Cond;

/// Connected native command scanner and its incoming CDB address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandScanner {
    entry: usize,
    cdb: u32,
    source: [u8; 32],
}

impl CommandScanner {
    fn at(image: &[u8], entry: usize) -> Option<Self> {
        use Operand::{Imm, Reg as R};
        let push = instruction(image, entry)?;
        let Some(Operand::RegList(saved)) = push.operands.get(0) else {
            return None;
        };
        if push.mnemonic != "push" || saved & (1 << 14) == 0 {
            return None;
        }
        let (cdb_reg, cdb) = literal_load(image, entry + 2)?;
        if !(0x02000000..0x02002000).contains(&cdb) {
            return None;
        }
        let mov = instruction(image, entry + 4)?;
        let (Some(R(table)), Some(R(Reg(0)))) = (mov.operands.get(0), mov.operands.get(1)) else {
            return None;
        };
        if mov.mnemonic != "mov"
            || !(4..=7).contains(&table.num())
            || saved & (1 << table.num()) == 0
            || cdb_reg == table
            || cdb_reg.num() < 3
        {
            return None;
        }
        let t = table.num();
        let c = cdb_reg.num();
        let r = |n| R(Reg(n));
        let invoke = entry + 20;
        let scan = entry + 6;
        let linked = entry + 0x46;
        if !memory_is(image, scan, "ldrb", 0, t, 1)
            || !exact(image, entry + 8, "cmp", &[r(0), Imm(7)])
            || conditional(image, entry + 10, Cond::Ne) != Some(entry + 26)
            || !memory_is(image, entry + 12, "ldrb", 1, t, 0)
            || !memory_is(image, entry + 14, "ldrb", 2, c, 0)
            || !exact(image, entry + 16, "cmp", &[r(1), r(2)])
            || conditional(image, entry + 18, Cond::Ne) != Some(entry + 26)
            || !memory_is(image, invoke, "ldr", 0, t, 4)
            || !exact(image, entry + 22, "blx", &[r(0)])
            || !memory_is(image, entry + 26, "ldrb", 1, t, 0)
            || !memory_is(image, entry + 28, "ldrb", 2, c, 0)
            || !exact(image, entry + 30, "cmp", &[r(1), r(2)])
            || conditional(image, entry + 32, Cond::Ne) != Some(linked)
            || !memory_is(image, entry + 34, "ldrb", 2, c, 0)
            || !exact(image, entry + 36, "cmp", &[r(2), Imm(0x3c)])
            || conditional(image, entry + 38, Cond::Ne) != Some(linked)
        {
            return None;
        }
        for (n, mode) in [6, 7, 10, 11, 12].into_iter().enumerate() {
            let at = entry + 40 + n * 6;
            if !memory_is(image, at, "ldrb", 2, c, 1)
                || !exact(image, at + 2, "cmp", &[r(2), Imm(mode)])
                || conditional(image, at + 4, Cond::Eq) != Some(invoke)
            {
                return None;
            }
        }
        if !exact(image, linked, "cmp", &[r(0), Imm(4)])
            || conditional(image, linked + 2, Cond::Ne) != Some(linked + 8)
            || !memory_is(image, linked + 4, "ldr", t, t, 4)
            || !branch(image, linked + 6, scan)
            || !exact(image, linked + 8, "cmp", &[r(0), Imm(3)])
            || conditional(image, linked + 10, Cond::Ne) != Some(linked + 16)
            || !exact(image, linked + 12, "mov", &[r(t), Imm(0)])
        {
            return None;
        }
        let ret = instruction(image, entry + 24)?.branch_target()? as usize;
        if !branch(image, entry + 24, ret)
            || !branch(image, linked + 14, ret)
            || !exact(image, ret, "mov", &[r(0), r(t)])
            || !exact(
                image,
                ret + 2,
                "pop",
                &[Operand::RegList((saved & !(1 << 14)) | (1 << 15))],
            )
            || !exact(image, ret + 4, "add", &[r(t), Imm(8)])
            || !branch(image, ret + 6, scan)
            || SavedLink::bind(image, entry, entry + 22).is_err()
        {
            return None;
        }
        Some(Self {
            entry,
            cdb,
            source: Sha256::digest(image).into(),
        })
    }

    /// Require one complete scanner grammar and balanced native call frame.
    pub fn inspect(image: &[u8]) -> Result<Self, Error> {
        let mut found = None;
        for at in (0..image.len().saturating_sub(0x60)).step_by(2) {
            let Some(ins) = decode_at(image, at) else {
                continue;
            };
            if ins.mnemonic != "push" {
                continue;
            }
            if let Some(candidate) = Self::at(image, at) {
                if found.replace(candidate).is_some() {
                    return Err(Error::Ambiguous);
                }
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
    /// Flash table roots registered into the array consumed by native callers.
    pub fn table_roots(&self, image: &[u8]) -> Result<std::collections::BTreeSet<usize>, Error> {
        if <[u8; 32]>::from(Sha256::digest(image)) != self.source {
            return Err(Error::InvalidContract);
        }
        super::dispatch_roots::roots(image, self)
    }
    /// Native scanner entry.
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Incoming command bytes read by the native scanner.
    pub fn cdb(&self) -> u32 {
        self.cdb
    }
}
fn branch(image: &[u8], at: usize, target: usize) -> bool {
    instruction(image, at).is_some_and(|ins| {
        ins.mnemonic == "b" && ins.cond.is_none() && ins.branch_target() == Some(target as u32)
    })
}

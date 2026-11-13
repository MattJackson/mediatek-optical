//! Read-only per-disc initialization anchor for a prospective private U/5 cache.
//! This binds an existing mode clear, not an address for a new RAM allocation.
use super::{
    caller::update_constants, half, Error, LegacyReverse, LegacyStackDi, SavedLink, UhdAreas,
};
use std::collections::{BTreeMap, VecDeque};
use thumb_asm::{
    analysis::literal_value,
    isa::{decode_at, Operand},
};

/// A direct native call to the initializer. An optional caller proof describes
/// the saved link at that call; it does not prove boot/current-disc ordering.
#[derive(Debug, Clone)]
pub struct IdentityResetCall {
    /// Native BL instruction.
    pub site: usize,
    /// Positively bound native saved-link context, when available.
    pub caller: Option<SavedLink>,
}

/// Source-bound existing initializer clear suitable for coordinating a private
/// U/5 cache reset. The caller must separately allocate/check that cache byte,
/// initialize it at boot, and set it only after accepted U/5 DI validation.
#[derive(Debug, Clone)]
pub struct LegacyIdentityReset {
    /// Existing initializer's saved-link entry.
    pub entry: usize,
    /// Four-byte LDR-literal / STRB pair to replace with a detour.
    pub site: usize,
    /// Exact immutable source instructions. The first is PC-relative.
    pub original: Vec<u8>,
    /// First instruction following the displaced pair.
    pub continuation: usize,
    /// Independently bound older mode cell, not a new U marker address.
    pub mode: u32,
    /// Bound DI density-class cell, distinct from mode and media state.
    pub density_class: u32,
    /// Register containing zero at the native store (R1 in this grammar).
    pub zero_register: u8,
    /// Explicit immediate-zero instruction at the initializer entry.
    pub zero_definition: usize,
    /// Native STRB halfword to replay after relocating the LDR literal.
    pub store_instruction: u16,
    /// Register receiving the relocated mode pointer (R0 in this grammar).
    pub literal_register: u8,
    /// Balanced native return-frame proof at `site`. Every terminating path
    /// from the bound initializer entry reaches the clear before returning.
    pub caller: SavedLink,
    /// Boot ordering is not established; callers must initialize the new cache
    /// before native initialization even when the reset detour is installed.
    pub boot_clear_required: bool,
    /// Direct source calls to `entry`; these are reachability observations,
    /// not a proof that every insertion/rearm invokes the initializer.
    pub direct_callers: Vec<IdentityResetCall>,
}

// A joining constant analysis is deliberately separate from SavedLink's shorter
// live-definition walk: this initializer spans several literal islands and
// exceeds 0x1200 bytes. SavedLink still proves the original full return frame.
fn require_zero(image: &[u8], entry: usize, site: usize) -> Result<(), Error> {
    let mut queue = VecDeque::from([(entry, [None; 16])]);
    let mut states: BTreeMap<usize, [Option<u32>; 16]> = BTreeMap::new();
    let mut reached = false;
    while let Some((pc, mut values)) = queue.pop_front() {
        if pc < entry || pc >= entry + 0x4000 || states.len() > 10000 {
            return Err(Error::InvalidContract);
        }
        if let Some(previous) = states.get_mut(&pc) {
            let joined = core::array::from_fn(|r| {
                if previous[r] == values[r] {
                    values[r]
                } else {
                    None
                }
            });
            if *previous == joined {
                continue;
            }
            *previous = joined;
            values = joined;
        } else {
            states.insert(pc, values);
        }
        if pc == site {
            if values[1] != Some(0) {
                return Err(Error::InvalidContract);
            }
            reached = true;
            continue;
        }
        let ins = decode_at(image, pc).ok_or(Error::Truncated)?;
        if matches!(ins.mnemonic, "it" | "udf" | "svc" | "bkpt" | "hvc" | "smc")
            || (ins.len() == 4 && !ins.is_call())
        {
            return Err(Error::InvalidContract);
        }
        let next = pc + ins.len();
        update_constants(&ins, &mut values);
        if ins.is_call() {
            if let Some(targets) = super::switch::targets(image, pc)? {
                // Switch helpers may clobber additional registers.
                let clobbers = super::switch::clobbers(true);
                for (r, value) in values.iter_mut().enumerate() {
                    if clobbers & (1 << r) != 0 {
                        *value = None;
                    }
                }
                queue.extend(targets.into_iter().map(|p| (p, values)));
            } else {
                queue.push_back((next, values));
            }
        } else if ins.mnemonic == "pop"
            && matches!(ins.operands.get(0), Some(Operand::RegList(bits)) if bits & (1 << 15) != 0)
        {
            // A terminating path that bypasses the store would leave a private
            // identity cache stale even though some other paths reset it.
            return Err(Error::InvalidContract);
        } else if ins.is_branch() {
            if ins.mnemonic != "b" {
                return Err(Error::InvalidContract);
            }
            queue.push_back((
                ins.branch_target().ok_or(Error::InvalidContract)? as usize,
                values,
            ));
            if ins.cond.is_some() {
                queue.push_back((next, values));
            }
        } else {
            queue.push_back((next, values));
        }
    }
    if reached {
        Ok(())
    } else {
        Err(Error::InvalidContract)
    }
}

impl LegacyIdentityReset {
    /// Bind the initializer to independent DI/reverse RAM roles. Unknown older
    /// mode layouts (including the earliest bitfield layout) are refused.
    /// The LDR must be re-emitted against `mode`, not copied to a new PC.
    /// No boot-order guarantee or private-byte allocation is implied.
    pub fn detect(image: &[u8]) -> Result<Self, Error> {
        let areas = UhdAreas::inspect(image);
        let reverse = LegacyReverse::detect(image, &areas)?;
        let di = LegacyStackDi::detect(image)?;
        if di.state != reverse.state || di.format_flag == reverse.mode || di.format_flag == di.state
        {
            return Err(Error::InvalidContract);
        }
        let sites: Vec<_> = (0..image.len().saturating_sub(8))
            .step_by(2)
            .filter(|&at| {
                half(image, at).is_some_and(|op| op & 0xff00 == 0x4800)
                    && literal_value(image, at) == Some(reverse.mode)
                    && half(image, at + 2) == Some(0x7001)
                    && half(image, at + 4).is_some_and(|op| op & 0xff00 == 0x4800)
                    && half(image, at + 6) == Some(0x6001)
            })
            .collect();
        let [site] = sites.as_slice() else {
            return Err(if sites.is_empty() {
                Error::UnknownLayout
            } else {
                Error::Ambiguous
            });
        };
        let site = *site;
        let mut callers = Vec::new();
        for entry in (site.saturating_sub(0x4000)..site).step_by(2) {
            // Same native initializer entry grammar across the bound cohort;
            // no filename, absolute RAM constant or donor offset participates.
            if half(image, entry) == Some(0xb5f0)
                && half(image, entry + 2).is_some_and(|op| op & 0xff00 == 0x4800)
                && half(image, entry + 4) == Some(0x2600)
                && half(image, entry + 6) == Some(0xb085)
                && half(image, entry + 8) == Some(0x7006)
            {
                if let Ok(caller) = SavedLink::bind(image, entry, site) {
                    // Prove the detour entry itself dominates returns. A path
                    // entering the displaced STRB directly must also be refused.
                    require_zero(image, entry, site)?;
                    callers.push(caller);
                }
            }
        }
        if callers.len() != 1 {
            return Err(if callers.is_empty() {
                Error::UnknownLayout
            } else {
                Error::Ambiguous
            });
        }
        let caller = callers.remove(0);
        let entry = caller.entry();
        let mut direct_callers = Vec::new();
        for at in (0..image.len().saturating_sub(4)).step_by(2) {
            if half(image, at).is_some_and(|op| op & 0xf800 == 0xf000) {
                if let Some(ins) = decode_at(image, at) {
                    if ins.is_call() && ins.branch_target() == Some(entry as u32) {
                        direct_callers.push(IdentityResetCall {
                            site: at,
                            caller: SavedLink::detect(image, at).ok(),
                        });
                    }
                }
            }
        }
        Ok(Self {
            entry,
            site,
            original: image[site..site + 4].to_vec(),
            continuation: site + 4,
            mode: reverse.mode,
            density_class: di.format_flag,
            zero_register: 1,
            zero_definition: entry + 4,
            store_instruction: 0x7001,
            literal_register: 0,
            caller,
            boot_clear_required: true,
            direct_callers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn fixtures() -> Vec<(bool, Vec<u8>)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/analysis/uhd-identity");
        let cases: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(root.join("sources.json")).unwrap()).unwrap();
        cases
            .into_iter()
            .map(|case| {
                let mut image = vec![0xff; 0x200000];
                for part in case["parts"].as_array().unwrap() {
                    let bytes = std::fs::read(root.join(part["file"].as_str().unwrap())).unwrap();
                    assert_eq!(
                        format!("{:x}", Sha256::digest(&bytes)),
                        part["sha256"].as_str().unwrap()
                    );
                    let at = part["offset"].as_u64().unwrap() as usize;
                    image[at..at + bytes.len()].copy_from_slice(&bytes);
                }
                (case["expected"].as_bool().unwrap(), image)
            })
            .collect()
    }
    #[test]
    fn source_initializers_bind_relocated_store_and_real_return_frame() {
        for (expected, image) in fixtures() {
            let proof = LegacyIdentityReset::detect(&image);
            assert_eq!(proof.is_ok(), expected, "{proof:?}");
            if let Ok(p) = proof {
                assert_eq!(p.caller.entry(), p.entry);
                assert_eq!(p.caller.site(), p.site);
                assert_eq!(p.continuation, p.site + 4);
                assert_eq!(p.original[2..], 0x7001u16.to_le_bytes());
                assert_eq!(literal_value(&image, p.site), Some(p.mode));
                assert_ne!(p.mode, p.density_class);
                assert_eq!(p.direct_callers.len(), 4);
                assert!(
                    p.direct_callers.iter().all(|c| c.caller.is_some()),
                    "{:?}",
                    p.direct_callers
                );
            }
        }
    }
    #[test]
    fn zero_dataflow_field_and_return_frame_mutations_are_refused() {
        for (_, image) in fixtures().into_iter().filter(|r| r.0) {
            let p = LegacyIdentityReset::detect(&image).unwrap();
            let mut initial = image.clone();
            initial[p.zero_definition..p.zero_definition + 2]
                .copy_from_slice(&0x2601u16.to_le_bytes());
            assert!(LegacyIdentityReset::detect(&initial).is_err());
            // Retain the entry's zero definition and all mode/reset grammars,
            // but clobber the final transfer into the store's R1 with one.
            let copies: Vec<_> = (p.site - 0x800..p.site)
                .step_by(2)
                .filter(|&at| half(&image, at) == Some(0x0021))
                .collect();
            assert_eq!(copies.len(), 1);
            let mut clobbered = image.clone();
            clobbered[copies[0]..copies[0] + 2].copy_from_slice(&0x2101u16.to_le_bytes());
            assert!(LegacyIdentityReset::detect(&clobbered).is_err());
            let op = half(&image, p.site).unwrap();
            let pool = ((p.site + 4) & !3) + usize::from(op & 255) * 4;
            let mut wrong = image.clone();
            wrong[pool..pool + 4].copy_from_slice(&(p.mode + 1).to_le_bytes());
            assert!(LegacyIdentityReset::detect(&wrong).is_err());
            let mut frame = image.clone();
            let ret = p.caller.returns()[0];
            assert_eq!(half(&image, ret - 2), Some(0xb005));
            frame[ret - 2..ret].copy_from_slice(&0xb004u16.to_le_bytes());
            assert!(LegacyIdentityReset::detect(&frame).is_err());
            // A balanced early-return path must not bypass the identity clear.
            // SavedLink alone intentionally permits pre-detour exits.
            let mut bypass = image.clone();
            let at = p.site - 8;
            let delta = ((ret - 2) as isize - (at + 4) as isize) / 2;
            assert!((0..=127).contains(&delta));
            bypass[at..at + 2].copy_from_slice(&(0xd000 | delta as u16).to_le_bytes());
            assert!(SavedLink::bind(&bypass, p.entry, p.site).is_ok());
            assert!(LegacyIdentityReset::detect(&bypass).is_err());
            let mut middle = image.clone();
            let delta = ((p.site + 2) - (at + 4)) / 2;
            middle[at..at + 2].copy_from_slice(&(0xd000 | delta as u16).to_le_bytes());
            assert!(SavedLink::bind(&middle, p.entry, p.site).is_ok());
            assert!(LegacyIdentityReset::detect(&middle).is_err());
        }
    }
}

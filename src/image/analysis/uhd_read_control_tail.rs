//! The two later C8 selectors in the classic read-control caller.
//! BE14 7ff91816: 107624/107686; native C7 reference 648a16d0:
//! dc986/dc9f8. These bind software choices, not optical acquisition success.
use super::{
    conditional, half, matches, C7Selection, ClassicConsumer, ClassicConsumerKind, Error, SavedLink,
};
use thumb_asm::{isa::decode_at, Cond};

/// Separately checked native parameter and controller-request choices.
#[derive(Debug, Clone)]
pub struct ClassicReadControlTail {
    /// State load before the parameter selector.
    pub region: usize,
    /// Dense versus ordinary six-argument native parameter call.
    pub parameters: C7Selection,
    /// Dense versus ordinary request/subtype stores.
    pub request: C7Selection,
    /// Native state pointer, held in R5 until the second selector.
    pub state: u32,
    /// Saved LR and balanced exits for each detour.
    pub callers: [SavedLink; 2],
}

fn literal(image: &[u8], at: usize) -> Option<u32> {
    let op = half(image, at)?;
    (op & 0xf800 == 0x4800).then_some(())?;
    let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
    Some(u32::from_le_bytes(
        image.get(pool..pool + 4)?.try_into().ok()?,
    ))
}

// State R5, C8 mask R6, six argument constants and a shared native BL.
const PARAMETERS: &[(u16, u16)] = &[
    (0x4d00, 0xff00),
    (0x7828, 0xffff),
    (0x26c8, 0xffff),
    (0x0031, 0xffff),
    (0x4381, 0xffff),
    (0xd108, 0xffff),
    (0x22e7, 0xffff),
    (0x2113, 0xffff),
    (0x9100, 0xffff),
    (0x9201, 0xffff),
    (0x2217, 0xffff),
    (0x21e9, 0xffff),
    (0x20e3, 0xffff),
    (0x2316, 0xffff),
    (0xe007, 0xffff),
    (0x22fc, 0xffff),
    (0x2100, 0xffff),
    (0x9100, 0xffff),
    (0x9201, 0xffff),
    (0x2200, 0xffff),
    (0x21fc, 0xffff),
    (0x20e3, 0xffff),
    (0x230b, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
];
// R5 and R6 remain callee-saved native operands across the two BLs. R7=2
// is defined here, rather than guessed from a source selector's inputs.
const REQUEST_PREFIX: &[(u16, u16)] = &[
    (0x4800, 0xff00),
    (0x3840, 0xffff),
    (0x6a01, 0xffff),
    (0x2233, 0xffff),
    (0x4391, 0xffff),
    (0x1c49, 0xffff),
    (0x2702, 0xffff),
    (0x4339, 0xffff),
    (0x6201, 0xffff),
    (0x6801, 0xffff),
    (0x0849, 0xffff),
    (0x0049, 0xffff),
    (0x6001, 0xffff),
    (0x0020, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
    (0x7828, 0xffff),
    (0x4c00, 0xff00),
    (0x4386, 0xffff),
    (0x2500, 0xffff),
    (0x4800, 0xff00),
    (0x4900, 0xff00),
    (0x4a00, 0xff00),
    (0x4b00, 0xff00),
    (0x2e00, 0xffff),
    (0x7025, 0xffff),
    (0xd106, 0xffff),
    (0x701f, 0xffff),
    (0x2303, 0xffff),
    (0x7013, 0xffff),
    (0x2222, 0xffff),
    (0x700a, 0xffff),
    (0x4900, 0xff00),
    (0xe006, 0xffff),
    (0x2401, 0xffff),
    (0x701c, 0xffff),
    (0x7014, 0xffff),
    (0x2221, 0xffff),
    (0x700a, 0xffff),
    (0x4900, 0xff00),
    (0x391f, 0xffff),
    (0x8001, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
];

impl ClassicReadControlTail {
    /// Require both exact tails in the already bound read-control function.
    /// Unknown variants and partial matches are refused as a complete unit.
    pub fn inspect(image: &[u8], state: u32) -> Result<Self, Error> {
        let parent = ClassicConsumer::inspect_kind(image, state, ClassicConsumerKind::ReadControl)?;
        let entry = parent.caller.entry();
        let mut found = None;
        for at in (parent.selection.site() + parent.selection.span()
            ..image.len().min(entry + 0x800))
            .step_by(2)
        {
            if !matches(image, at, PARAMETERS) || literal(image, at) != Some(state) {
                continue;
            }
            let call = at + 46;
            let prefix = call + 4;
            if !matches(image, prefix, REQUEST_PREFIX) || literal(image, prefix) != Some(0x04208840)
            {
                return Err(Error::InvalidContract);
            }
            let mut cells = Vec::new();
            for offset in [34, 40, 42, 44, 46] {
                let cell = literal(image, prefix + offset).ok_or(Error::InvalidContract)?;
                if !(0x01ff0000..0x02010000).contains(&cell) || cell == state {
                    return Err(Error::InvalidContract);
                }
                cells.push(cell);
            }
            cells.sort_unstable();
            cells.dedup();
            if cells.len() != 5 || literal(image, prefix + 64) != literal(image, prefix + 78) {
                return Err(Error::InvalidContract);
            }
            let request = prefix + 48;
            let accept = conditional(image, at + 10, Cond::Ne).ok_or(Error::InvalidContract)?;
            if accept != at + 30 || conditional(image, request + 4, Cond::Ne) != Some(request + 20)
            {
                return Err(Error::InvalidContract);
            }
            // Both parameter arms must join the same real native call.
            if decode_at(image, at + 28).and_then(|i| i.branch_target()) != Some(call as u32) {
                return Err(Error::InvalidContract);
            }
            let result = Self {
                region: at,
                state,
                parameters: C7Selection {
                    site: at + 8,
                    replay: vec![0x4381],
                    span: 4,
                    accept: at + 12,
                    reject: at + 30,
                },
                request: C7Selection {
                    site: request,
                    replay: vec![0x2e00, 0x7025],
                    span: 6,
                    accept: request + 6,
                    reject: request + 20,
                },
                callers: [
                    SavedLink::bind(image, entry, at + 8)?,
                    SavedLink::bind(image, entry, request)?,
                ],
            };
            if found.replace(result).is_some() {
                return Err(Error::Ambiguous);
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn private_corpus_binds_both_tails_and_rejects_changed_operands() {
        let Ok(path) = std::env::var("FREEMKV_READ_CONTROL_TAIL_CORPUS") else {
            return;
        };
        let inventory: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut tested = 0;
        for row in inventory["images"].as_array().unwrap() {
            if row["candidates"].as_array().unwrap().is_empty() {
                continue;
            }
            let image = std::fs::read(row["path"].as_str().unwrap()).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&image)), row["sha256"]);
            let state = row["candidates"][0]["state"].as_u64().unwrap() as u32;
            let c = ClassicReadControlTail::inspect(&image, state)
                .unwrap_or_else(|e| panic!("{}: {e:?}", row["sha256"]));
            assert_eq!(
                c.parameters.site(),
                row["candidates"][0]["selection"].as_u64().unwrap() as usize
            );
            assert_eq!(c.callers[0].entry(), c.callers[1].entry());
            assert!(ClassicReadControlTail::inspect(&image, state ^ 4).is_err());
            for at in [c.region + 12, c.request.site() + 8] {
                let mut changed = image.clone();
                changed[at] ^= 1;
                assert!(
                    ClassicReadControlTail::inspect(&changed, state).is_err(),
                    "accepted changed operand at {at:x}"
                );
            }
            tested += 1;
        }
        assert_eq!(
            tested, 29,
            "review corpus changed; inspect its scope before updating this receipt"
        );
    }
}

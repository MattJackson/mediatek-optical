//! Read-only A32 helpers. Thumb decoding and emission remain in thumb-asm.
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::{InstDecoder, Instruction, Opcode, Operand};

pub(super) fn instruction(image: &[u8], at: usize) -> Option<Instruction> {
    if at & 3 != 0 {
        return None;
    }
    let bytes = image.get(at..at.checked_add(4)?)?;
    InstDecoder::armv5()
        .with_thumb_mode(false)
        .decode(&mut U8Reader::new(bytes))
        .ok()
}

pub(super) fn branch_target(image: &[u8], at: usize) -> Option<usize> {
    let ins = instruction(image, at)?;
    let displacement = match (ins.opcode, ins.operands[0]) {
        (Opcode::B | Opcode::BL, Operand::BranchOffset(words)) => i64::from(words) * 4,
        (Opcode::BLX, Operand::BranchThumbOffset(halves)) => 8 + i64::from(halves) * 2,
        _ => return None,
    };
    usize::try_from((at as i64).checked_add(displacement)?).ok()
}

/// A function considered private to a loader extent must have no A32 callers
/// outside it either; Thumb-only cross-reference scans cannot establish this.
pub(super) fn external_branch(image: &[u8], target: usize, end: usize) -> bool {
    (end..image.len().saturating_sub(3))
        .step_by(4)
        .any(|at| branch_target(image, at) == Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a32_native_branches_keep_pc_bias_and_direction() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/analysis/a32");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("sources.json")).unwrap()).unwrap();
        for case in manifest["cases"].as_array().unwrap() {
            let at = case["offset"].as_u64().unwrap() as usize;
            let target = case["target"].as_u64().unwrap() as usize;
            let bytes = std::fs::read(root.join(case["file"].as_str().unwrap())).unwrap();
            let mut image = vec![0xff; 0x200000];
            image[at..at + bytes.len()].copy_from_slice(&bytes);
            assert_eq!(branch_target(&image, at), Some(target), "{}", case["file"]);
            assert!(external_branch(&image, target, at));
            assert!(!external_branch(&image, target, at + 4));
            assert!(instruction(&image, at + 2).is_none());
            assert!(instruction(&image[..at + 3], at).is_none());
        }
    }
}

use super::*;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn held(digest: &str, name: &str) -> Vec<u8> {
    let root = PathBuf::from(std::env::var("MTK_HOARD_ROOT").expect("set MTK_HOARD_ROOT"));
    let bytes = std::fs::read(root.join("originals").join(digest).join(name)).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), digest);
    bytes
}

#[test]
#[ignore = "requires private MTK_HOARD_ROOT"]
fn held_mixed_receivers_bind_flag_header_integrity_and_programming_code() {
    for (digest, name, expected_start, critical) in [
        (
            "c3a18eed17251d1508964647e833ffdfe01b13c28dff9a717dfac6336e7c70e6",
            "BH16NS40_INTM_c3a18eed.bin",
            0x1d0000,
            [
                0x9cdb0, 0x9d48c, 0x9d4bc, 0x9d528, 0x9d584, 0x9d61e, 0x9d658, 0x9d69a,
            ],
        ),
        (
            "29ad302647148e270c15a5a4542aa4796ee9ba25ea9fbf9f2be9465c01c139a7",
            "BU40N_INTM_29ad3026.bin",
            0x1c8000,
            [
                0x9cc2c, 0x9d3e0, 0x9d41c, 0x9d488, 0x9d4e4, 0x9d600, 0x9d638, 0x9d67a,
            ],
        ),
    ] {
        let bytes = held(digest, name);
        let app = &bytes[0x98000..0xb4000];
        let analysis = ApplicationAnalysis::inspect(app, 0x98000).unwrap();
        let candidate = Candidate::inspect(app, 0x98000, &analysis).expect(name);
        let wrapper_start = candidate.wrapper_address as usize;
        let wrapper = &bytes[wrapper_start..wrapper_start + candidate.wrapper_bytes()];
        let program_start = candidate.program_address(wrapper).unwrap() as usize;
        let program = &bytes[program_start..program_start + candidate.program_bytes()];
        let integrity_start = candidate.integrity_address as usize;
        let integrity = &bytes[integrity_start..integrity_start + candidate.integrity_bytes()];
        let contract = candidate.bind(wrapper, integrity, program).unwrap();
        assert_eq!(contract.header_range(), 0x3000..0x3010);
        assert_eq!(
            contract.programmed_ranges(),
            &[0x10000..expected_start, 0x1ec000..0x1f0000]
        );
        assert_eq!(contract.descriptor_byte(), 0x1ec056);
        // Cached discovery cannot license changed flag, AES destination,
        // range, direct signature, CMAC policy, DE check or program mode.
        for address in critical {
            let mut changed = app.to_vec();
            changed[address - 0x98000] ^= 1;
            assert!(
                Candidate::inspect(&changed, 0x98000, &analysis).is_none(),
                "{name}: {address:#x}"
            );
        }
        // Poison each independently significant argument copy/store in the
        // out-of-line wrapper, and both reserved-region skip constants.
        for offset in [2, 4, 6, 0x128, 0x12c, 0x130] {
            let mut changed = wrapper.to_vec();
            changed[offset] ^= 1;
            assert!(
                candidate.bind(&changed, integrity, program).is_none(),
                "wrapper {offset:#x}"
            );
        }
        for offset in [
            candidate.form.skip_start,
            candidate.form.skip_length,
            candidate.form.skip_final,
        ] {
            let mut changed = program.to_vec();
            changed[offset as usize] ^= 1;
            assert!(
                candidate.bind(wrapper, integrity, &changed).is_none(),
                "program {offset:#x}"
            );
        }
        let mut changed = integrity.to_vec();
        changed[0x48] ^= 1;
        assert!(candidate.bind(wrapper, &changed, program).is_none());
        assert!(candidate
            .bind(&wrapper[..wrapper.len() - 1], integrity, program)
            .is_none());
        assert!(candidate
            .bind(wrapper, integrity, &program[..program.len() - 1])
            .is_none());
    }
}

#[test]
fn unaligned_program_loop_target_is_not_handed_out() {
    for form in FORMS.iter() {
        let wrapper: Vec<u8> = form.wrapper.iter().flat_map(|w| w.to_le_bytes()).collect();
        let targets: Vec<Option<u32>> = [0x1000, 0x1002]
            .into_iter()
            .map(|wrapper_address| {
                Candidate {
                    form,
                    wrapper_address,
                    integrity_address: 0,
                }
                .program_address(&wrapper)
            })
            .collect();
        // Moving the wrapper by two bytes moves its relative-branch target
        // by two: exactly one of the two placements is word aligned.
        let aligned = targets
            .iter()
            .filter(|t| matches!(t, Some(a) if a & 3 == 0));
        assert_eq!(aligned.count(), 1, "{targets:?}");
        assert!(
            targets.iter().all(|t| t.map_or(true, |a| a & 3 == 0)),
            "{targets:?}"
        );
    }
}

// Both forms' wrapper and integrity literal pools resolve to the receiver's
// operands (mode-3 MMIO 0x04002240, staging cell) only at addresses 2 mod 4;
// the same halfwords at a word-aligned address load different words.
#[test]
fn wrapper_and_integrity_bind_only_at_their_literal_alignment() {
    for form in FORMS.iter() {
        let wrapper: Vec<u8> = form.wrapper.iter().flat_map(|w| w.to_le_bytes()).collect();
        let integrity: Vec<u8> = form
            .integrity
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let program: Vec<u8> = form.program.iter().flat_map(|w| w.to_le_bytes()).collect();
        let candidate = |wrapper_address, integrity_address| Candidate {
            form,
            wrapper_address,
            integrity_address,
        };
        assert!(candidate(0x1002, 0x2002)
            .program_address(&wrapper)
            .is_some());
        assert!(candidate(0x1002, 0x2002)
            .bind(&wrapper, &integrity, &program)
            .is_some());
        assert!(candidate(0x1000, 0x2002)
            .program_address(&wrapper)
            .is_none());
        assert!(candidate(0x1000, 0x2002)
            .bind(&wrapper, &integrity, &program)
            .is_none());
        assert!(candidate(0x1002, 0x2000)
            .bind(&wrapper, &integrity, &program)
            .is_none());
    }
}

impl MixedContract {
    /// A contract programming exactly `programmed`.
    pub(in crate::receiver) fn testing(programmed: [Range<usize>; 2]) -> Self {
        Self { programmed }
    }
}

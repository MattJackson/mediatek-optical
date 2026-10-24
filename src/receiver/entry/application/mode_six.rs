//! Mode-six buffer guard, including bounded compiler branch trampolines.
use super::{Candidate, Prologue, Window};

/// Positive mode-six guard evidence. Neither variant proves stream/header
/// acceptance or the command-completion wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSix {
    /// Buffer 0x67 enters the same complete flag body as mode one.
    Entry67 {
        /// CDB buffer-id load.
        guard: u32,
        /// Non-0x67 continuation, whose acceptance remains separately proved.
        stream: u32,
    },
    /// Buffer zero continues into stream handling; other ids branch away.
    StreamZero {
        /// CDB buffer-id load.
        guard: u32,
        /// Equal-to-zero continuation.
        stream: u32,
        /// Nonzero-id branch destination. Completion is not inferred.
        nonzero: u32,
    },
}

fn follow(w: &Window<'_>, mut at: u32) -> Option<u32> {
    let mut seen = [0; 3];
    for index in 0..3 {
        if w.word(at)? & 0xf800 != 0xe000 {
            return Some(at);
        }
        if seen[..index].contains(&at) {
            return None;
        }
        seen[index] = at;
        at = w.branch(at)?;
    }
    (w.word(at)? & 0xf800 != 0xe000).then_some(at)
}

/// Bind the mode-six guard to a validated prelude and complete mode-one flag
/// body. Returns `None` for unknown code; absence never means zero-only.
pub fn inspect_mode_six(
    bytes: &[u8],
    address: u32,
    candidate: &Candidate,
    prelude: &Prologue,
) -> Option<ModeSix> {
    super::inspect_flags(bytes, address, candidate, prelude)?;
    let w = Window {
        bytes,
        base: address,
    };
    let mut at = follow(&w, candidate.mode6_target)?;
    let mut cdb = prelude.cdb_registers;
    if let Some((reg, value)) = w.literal(at) {
        if value != prelude.cdb_address {
            return None;
        }
        // The reload must not clobber a constant the flag body relies on.
        if prelude.constants[reg as usize].is_some() {
            return None;
        }
        cdb = 1 << reg;
        at = at.checked_add(2)?;
    }
    let load = w.word(at)?;
    let temp = load & 7;
    let source = (load >> 3) & 7;
    if load != 0x7800 | (2 << 6) | (source << 3) | temp || cdb & (1 << source) == 0 {
        return None;
    }
    let compare = w.word(at.checked_add(2)?)?;
    if compare & 0xff00 != 0x2800 | (temp << 8) {
        return None;
    }
    let other = w.conditional(at.checked_add(4)?, 0xd100)?;
    w.word(other)?;
    let equal = follow(&w, at.checked_add(6)?)?;
    match compare & 255 {
        0x67 if equal == candidate.entry
            && temp != source
            && prelude.constants[temp as usize].is_none()
            && prelude.cdb_registers & (1 << temp) == 0 =>
        {
            Some(ModeSix::Entry67 {
                guard: at,
                stream: other,
            })
        }
        0 if equal != candidate.entry => Some(ModeSix::StreamZero {
            guard: at,
            stream: equal,
            nonzero: other,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_trampolines_are_bounded_and_cycles_are_rejected() {
        // Three forward branches followed by a buffer-id load.
        let bytes = [
            0x00, 0xe0, 0xff, 0xff, 0x00, 0xe0, 0xff, 0xff, 0x00, 0xe0, 0xff, 0xff, 0x83, 0x78,
        ];
        assert_eq!(
            follow(
                &Window {
                    bytes: &bytes,
                    base: 0x1000
                },
                0x1000
            ),
            Some(0x100c)
        );
        let mut fourth = bytes;
        fourth[12..14].copy_from_slice(&[0x00, 0xe0]);
        assert_eq!(
            follow(
                &Window {
                    bytes: &fourth,
                    base: 0x1000
                },
                0x1000
            ),
            None
        );
        let cycle = [0xfe, 0xe7];
        assert_eq!(
            follow(
                &Window {
                    bytes: &cycle,
                    base: 0x1000
                },
                0x1000
            ),
            None
        );
        assert_eq!(
            follow(
                &Window {
                    bytes: &bytes[..1],
                    base: 0x1000
                },
                0x1000
            ),
            None
        );
    }
}

use super::{half, unique, Error};

const VID_GATE_SIG: &[(u16, u16)] = &[
    (0x0400, 0xFFFF), // lsls r0,r0,#16
    (0x0C00, 0xFFFF), // lsrs r0,r0,#16
    (0x1808, 0xFFFF), // adds r0,r1,r0
    (0x4900, 0xFF00), // ldr r1,[pc,#imm]  (SRAM base-ptr cell)
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x6809, 0xFFFF), // ldr r1,[r1]
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x7800, 0xFFFF), // ldrb r0,[r0]      (auth-state byte) — the gate
    (0x2806, 0xFFFF), // cmp r0,#6
    (0xD100, 0xFF00), // bne <skip>
];

const VID_GATE_SIG_NB: &[(u16, u16)] = &[
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x6801, 0xFFC7), // ldr  r1,[rN]      (SRAM base-ptr deref; rN = r5/r6 per build)
    (0x1808, 0xFFFF), // adds r0,r1,r0
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]  (SRAM base-ptr cell)
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x6809, 0xFFFF), // ldr  r1,[r1]
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x7800, 0xFFFF), // ldrb r0,[r0]      (auth-state byte) — the gate
    (0x2806, 0xFFFF), // cmp  r0,#6
    (0xD100, 0xFF00), // bne  <skip>
];

const VID_GATE_SIG_JB8: &[(u16, u16)] = &[
    (0x6809, 0xFFFF), // ldr  r1,[r1]      (round-1 SRAM base-ptr deref)
    (0x0C00, 0xFFFF), // lsrs r0,r0,#0x10
    (0x1808, 0xFFFF), // adds r0,r1,r0
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]  (round-2 SRAM base-ptr cell)
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x6809, 0xFFFF), // ldr  r1,[r1]
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x7800, 0xFFFF), // ldrb r0,[r0]      (auth-state byte) — the gate (match+16)
    (0x2806, 0xFFFF), // cmp  r0,#6
    (0xD100, 0xFF00), // bne  <skip>
];

/// OEM address-computation form feeding the authenticated VID path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VidGateVariant {
    /// Original add/mask form.
    Direct,
    /// Notebook register-allocated address computation.
    Notebook,
    /// Two-round pointer-mask form.
    TwoRound,
}

/// Positive auth-state==6 gate and its enclosing producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VidGate {
    anchor: usize,
    variant: VidGateVariant,
}
impl VidGate {
    /// Select an exact unique grammar; an ambiguous earlier form never falls back.
    pub fn inspect(image: &[u8]) -> Result<Self, Error> {
        let mut found = None;
        for (pattern, variant) in [
            (VID_GATE_SIG, VidGateVariant::Direct),
            (VID_GATE_SIG_NB, VidGateVariant::Notebook),
            (VID_GATE_SIG_JB8, VidGateVariant::TwoRound),
        ] {
            match unique(image, pattern) {
                Ok(anchor) => {
                    if found.replace(Self { anchor, variant }).is_some() {
                        return Err(Error::Ambiguous);
                    }
                }
                Err(Error::UnknownLayout) => {}
                Err(e) => return Err(e),
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
    /// Address-computation signature anchor.
    pub fn anchor(&self) -> usize {
        self.anchor
    }
    /// Auth-state comparison instruction.
    pub fn comparison(&self) -> usize {
        self.anchor + 18
    }
    /// Selected register/address-computation grammar.
    pub fn variant(&self) -> VidGateVariant {
        self.variant
    }
    /// Unique nearest producer prologue preceding this gate.
    pub fn producer(&self, image: &[u8]) -> Result<usize, Error> {
        let mut at = self.anchor + 16;
        let end = at.saturating_sub(0x200);
        while at >= end + 2 {
            at -= 2;
            if half(image, at) == Some(0xb5f0) {
                return Ok(at);
            }
        }
        Err(Error::UnknownLayout)
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    #[test]
    fn distinct_unique_variants_are_ambiguous_together() {
        let bytes = |pattern: &[(u16, u16)]| {
            pattern
                .iter()
                .flat_map(|(op, _)| op.to_le_bytes())
                .collect::<Vec<_>>()
        };
        for alternative in [VID_GATE_SIG_NB, VID_GATE_SIG_JB8] {
            let mut image = bytes(VID_GATE_SIG);
            image.extend([0xff; 16]);
            image.extend(bytes(alternative));
            assert_eq!(VidGate::inspect(&image), Err(Error::Ambiguous));
        }
    }
}

impl VidGate {
    /// Bind the session base to native AGID-byte reads, six-bit extraction and
    /// range checks. Every reachable checked read must have the same live base.
    pub fn agid_base(&self, image: &[u8]) -> Result<u32, Error> {
        let entry = self.producer(image)?;
        let mut base = None;
        for read in (entry..self.comparison()).step_by(2) {
            let op = half(image, read).ok_or(Error::Truncated)?;
            if op & 0xffc0 != 0x7a80 {
                continue;
            }
            let pointer = ((op >> 3) & 7) as u8;
            let value = (op & 7) as u8;
            if pointer < 4 {
                continue;
            }
            let shift = half(image, read + 2).ok_or(Error::Truncated)?;
            if shift & 0xffc0 != 0x0980 || ((shift >> 3) & 7) as u8 != value {
                continue;
            }
            let result = (shift & 7) as u8;
            let mut guard = false;
            for cmp in [read + 4, read + 6, read + 8] {
                if half(image, cmp) == Some(0x2802 | u16::from(result) << 8)
                    && half(image, cmp + 2).is_some_and(|v| matches!(v & 0xff00, 0xd200 | 0xd300))
                {
                    // Only independent literal loads / immediate moves may
                    // separate extraction from its range check. Neither may
                    // overwrite the extracted value being compared.
                    guard = (read + 4..cmp).step_by(2).all(|at| {
                        half(image, at).is_some_and(|op| {
                            matches!(op & 0xf800, 0x2000 | 0x4800)
                                && (op >> 8) & 7 != u16::from(result)
                        })
                    });
                    break;
                }
            }
            if !guard {
                continue;
            }
            let mut definition = None;
            for at in (entry..read).step_by(2) {
                let load = half(image, at).ok_or(Error::Truncated)?;
                if load & 0xff00 != 0x4800 | u16::from(pointer) << 8 {
                    continue;
                }
                let pool = ((at + 4) & !3) + usize::from(load & 255) * 4;
                let Some(bytes) = image.get(pool..pool + 4) else {
                    continue;
                };
                let address = u32::from_le_bytes(bytes.try_into().unwrap());
                if !(0x02000000..0x02002000).contains(&address) {
                    continue;
                }
                if super::SavedLink::require_live_definition(
                    image,
                    entry,
                    read,
                    at,
                    at + 2,
                    pointer,
                )
                .is_ok()
                {
                    if definition.replace(address).is_some() {
                        return Err(Error::Ambiguous);
                    }
                }
            }
            let address = definition.ok_or(Error::InvalidContract)?;
            if base.is_some_and(|old| old != address) {
                return Err(Error::Ambiguous);
            }
            base = Some(address);
        }
        base.ok_or(Error::UnknownLayout)
    }
}

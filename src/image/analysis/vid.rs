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
        for (pattern, variant) in [
            (VID_GATE_SIG, VidGateVariant::Direct),
            (VID_GATE_SIG_NB, VidGateVariant::Notebook),
            (VID_GATE_SIG_JB8, VidGateVariant::TwoRound),
        ] {
            match unique(image, pattern) {
                Ok(anchor) => return Ok(Self { anchor, variant }),
                Err(Error::UnknownLayout) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Error::UnknownLayout)
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

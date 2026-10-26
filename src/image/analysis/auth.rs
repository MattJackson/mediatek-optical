use super::{conditional, half, Error};

/// Register contract at the post-authentication scratch preparation gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCellVariant {
    /// Original r0 check with a preserved r4 state pointer.
    R0StateR4,
    /// Value and literal pointer share r1; the accept path immediately reloads r1.
    R1StateR1,
    /// r1 value read from a separately preserved r4 state pointer.
    R1StateR4,
    /// The literal pointer and shifted state share r0.
    R0StateR0,
    /// r0 value read from a preserved r5 state pointer.
    R0StateR5,
}

/// A state-band check reached from the successful VID preparation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthCell {
    variant: AuthCellVariant,
    site: usize,
    deny: usize,
    state: u32,
}

impl AuthCell {
    /// Derive the VID role from positive OEM instructions before selecting a
    /// state-band contract. This is the entry point for complete firmware images.
    pub fn detect(image: &[u8]) -> Result<Self, Error> {
        let vid = super::VidGate::inspect(image)?;
        Self::inspect(image, vid.producer(image)?, vid.comparison())
    }
    /// Inspect a validated VID producer and its auth==6 discriminator. Follow
    /// the preparation-success branch; never choose a nibble comparison by rank.
    pub fn inspect(image: &[u8], producer: usize, gate: usize) -> Result<Self, Error> {
        if producer > gate
            || gate - producer > 0x200
            || half(image, producer) != Some(0xb5f0)
            || half(image, gate) != Some(0x2806)
        {
            return Err(Error::InvalidContract);
        }
        let reject = conditional(image, gate + 2, 0xd100).ok_or(Error::InvalidContract)?;
        if reject < gate + 12
            || reject - gate > 0x100
            || half(image, reject - 4) != Some(0x2800)
            || thumb_asm::decode_bl(image, reject - 8).is_none()
        {
            return Err(Error::InvalidContract);
        }
        let start = conditional(image, reject - 2, 0xd100).ok_or(Error::InvalidContract)?;
        if start <= reject || start - reject > 0x80 {
            return Err(Error::InvalidContract);
        }
        let mut pc = start;
        let mut rounded = false;
        let mut saved = false;
        let mut agid_read = false;
        let mut agid_shifted = false;
        let mut agid_saved = false;
        let mut sp_base = false;
        let mut literals = [None; 8];
        let mut alignment = [false; 8];
        let mut state_read = None;
        // These are straight-line scratch-setup blocks. Any control transfer
        // before the gate is unknown, including a table embedded in the bytes.
        for _ in 0..32 {
            let hw = half(image, pc).ok_or(Error::Truncated)?;
            if hw == 0x280c || hw == 0x290c {
                let value = ((hw >> 8) & 7) as u8;
                if !rounded || !saved || !agid_saved || pc < start + 6 {
                    return Err(Error::InvalidContract);
                }
                let load = half(image, pc - 4).ok_or(Error::Truncated)?;
                let shift = half(image, pc - 2).ok_or(Error::Truncated)?;
                if shift != 0x0900 | ((value as u16) << 3) | value as u16 {
                    return Err(Error::InvalidContract);
                }
                let variant = match (value, load) {
                    (0, 0x7820) => AuthCellVariant::R0StateR4,
                    (1, 0x7809) => AuthCellVariant::R1StateR1,
                    (1, 0x7821) => AuthCellVariant::R1StateR4,
                    (0, 0x7800) => AuthCellVariant::R0StateR0,
                    (0, 0x7828) => AuthCellVariant::R0StateR5,
                    _ => return Err(Error::UnknownLayout),
                };
                let (read_at, read_register, state) = state_read.ok_or(Error::InvalidContract)?;
                if read_at != pc - 4 || read_register != value {
                    return Err(Error::InvalidContract);
                }
                let state = Some(state);
                let state = state.ok_or(Error::InvalidContract)?;
                if !(0x0100_0000..0x0300_0000).contains(&state) {
                    return Err(Error::InvalidContract);
                }
                let deny = conditional(image, pc + 2, 0xd100).ok_or(Error::InvalidContract)?;
                if deny <= pc + 4 || deny - pc > 0x200 {
                    return Err(Error::InvalidContract);
                }
                // Both reviewed roles leave through an OEM state-store path,
                // with an optional literal load before the store and a narrow B.
                let first = half(image, deny).ok_or(Error::Truncated)?;
                let store = if first & 0xf800 == 0x4800 {
                    deny + 2
                } else {
                    deny
                };
                // Reviewed exits preserve a live byte or materialize status=1.
                // The generated stub branches to this original block unchanged.
                let store_hw = half(image, store).ok_or(Error::Truncated)?;
                let valid_store = matches!(store_hw, 0x7005 | 0x7006 | 0x703e)
                    || (first == 0x2001 && half(image, deny + 2) == Some(0x7038));
                let branch = if first == 0x2001 { deny + 4 } else { store + 2 };
                if !valid_store || half(image, branch).map_or(true, |h| h & 0xf800 != 0xe000) {
                    return Err(Error::InvalidContract);
                }
                if value == 1 && half(image, pc + 4).map_or(true, |h| h & 0xff00 != 0x4900) {
                    return Err(Error::InvalidContract);
                }
                return Ok(Self {
                    variant,
                    site: pc,
                    deny,
                    state,
                });
            }
            let ins = thumb_asm::isa::decode_at(image, pc).ok_or(Error::InvalidContract)?;
            if ins.is_branch() || ins.writes_pc() {
                return Err(Error::InvalidContract);
            }
            // Track literal-register definitions through the straight-line prefix.
            // Stores/compares do not define operand zero; other writes invalidate it.
            let destination = if !ins.mnemonic.starts_with("str")
                && !matches!(ins.mnemonic, "cmp" | "cmn" | "tst")
            {
                ins.operands.as_slice().next().and_then(|o| match o {
                    thumb_asm::Operand::Reg(r) if r.0 < 8 => Some(r.0 as usize),
                    _ => None,
                })
            } else {
                None
            };
            let literal = if hw & 0xf800 == 0x4800 {
                thumb_asm::analysis::literal_value(image, pc)
            } else {
                None
            };
            if hw & 0xf800 == 0x7800 {
                let rn = ((hw >> 3) & 7) as usize;
                let rt = (hw & 7) as u8;
                let offset = (hw >> 6) & 31;
                if offset == 10 && rt == 0 {
                    agid_read =
                        literals[rn].is_some_and(|v| (0x0200_0000..0x0200_2000).contains(&v));
                }
                if offset == 0 {
                    state_read = literals[rn].map(|address| (pc, rt, address));
                }
            }
            agid_shifted |= agid_read && hw == 0x0980;
            sp_base |= hw == 0x466b;
            agid_saved |= agid_shifted && sp_base && hw & 0xf83f == 0x7018;
            if hw & 0xffc0 == 0x0880 {
                alignment[(hw & 7) as usize] = true;
            } else if hw & 0xffc0 == 0x0080 {
                let r = (hw & 7) as usize;
                rounded = alignment[((hw >> 3) & 7) as usize];
                alignment[r] = false;
            } else if let Some(dst) = destination {
                alignment[dst] = false;
            }
            saved |= rounded && hw & 0xf800 == 0x9000;
            if let Some(dst) = destination {
                literals[dst] = literal;
            }
            pc += ins.width.bytes();
        }
        Err(Error::UnknownLayout)
    }
    /// Selected register contract.
    pub fn variant(&self) -> AuthCellVariant {
        self.variant
    }
    /// Original CMP/BNE pair.
    pub fn site(&self) -> usize {
        self.site
    }
    /// Original state-store continuation on failed comparison.
    pub fn deny(&self) -> usize {
        self.deny
    }
    /// State address derived from the live literal load.
    pub fn state_address(&self) -> u32 {
        self.state
    }
}

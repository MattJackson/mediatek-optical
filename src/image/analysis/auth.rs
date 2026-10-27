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
    /// r0 read through r1, interleaved r6 setup; non-C continues to a nibble-4 path.
    R0StateR1Alternate,
}

/// A state-band check reached from the successful VID preparation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthCell {
    variant: AuthCellVariant,
    site: usize,
    deny: usize,
    refusal: usize,
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
        let reject =
            conditional(image, gate + 2, thumb_asm::Cond::Ne).ok_or(Error::InvalidContract)?;
        if reject < gate + 12
            || reject - gate > 0x100
            || half(image, reject - 4) != Some(0x2800)
            || thumb_asm::decode_bl(image, reject - 8).is_none()
        {
            return Err(Error::InvalidContract);
        }
        let start =
            conditional(image, reject - 2, thumb_asm::Cond::Ne).ok_or(Error::InvalidContract)?;
        if start <= reject || start - reject > 0x80 {
            return Err(Error::InvalidContract);
        }
        let mut pc = start;
        let mut flow = super::flow::ScratchFlow::new();
        let mut state_read = None;
        // These are straight-line scratch-setup blocks. Any control transfer
        // before the gate is unknown, including a table embedded in the bytes.
        for _ in 0..32 {
            let hw = half(image, pc).ok_or(Error::Truncated)?;
            if hw == 0x280c || hw == 0x290c {
                let value = ((hw >> 8) & 7) as u8;
                if !flow.complete() || pc < start + 6 {
                    return Err(Error::InvalidContract);
                }
                let alternate = value == 0
                    && pc >= 8
                    && half(image, pc - 8) == Some(0x7808)
                    && half(image, pc - 6).is_some_and(|h| h & 0xff00 == 0x4e00)
                    && half(image, pc - 4) == Some(0x0900)
                    && half(image, pc - 2) == Some(0x1d36);
                let load_at = pc - if alternate { 8 } else { 4 };
                let shift_at = pc - if alternate { 4 } else { 2 };
                let load = half(image, load_at).ok_or(Error::Truncated)?;
                let shift = half(image, shift_at).ok_or(Error::Truncated)?;
                if shift != 0x0900 | ((value as u16) << 3) | value as u16 {
                    return Err(Error::InvalidContract);
                }
                let variant = match (value, load) {
                    (0, 0x7820) => AuthCellVariant::R0StateR4,
                    (1, 0x7809) => AuthCellVariant::R1StateR1,
                    (1, 0x7821) => AuthCellVariant::R1StateR4,
                    (0, 0x7800) => AuthCellVariant::R0StateR0,
                    (0, 0x7828) => AuthCellVariant::R0StateR5,
                    (0, 0x7808) if alternate => AuthCellVariant::R0StateR1Alternate,
                    _ => return Err(Error::UnknownLayout),
                };
                let (read_at, read_register, state) = state_read.ok_or(Error::InvalidContract)?;
                if read_at != load_at || read_register != value {
                    return Err(Error::InvalidContract);
                }
                let state = Some(state);
                let state = state.ok_or(Error::InvalidContract)?;
                if !(0x0100_0000..0x0300_0000).contains(&state) {
                    return Err(Error::InvalidContract);
                }
                let deny = conditional(image, pc + 2, thumb_asm::Cond::Ne)
                    .ok_or(Error::InvalidContract)?;
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
                let mut refusal = deny;
                if alternate {
                    // This continuation is not a denial store: it re-reads the
                    // same byte through still-live r1 and selects a distinct
                    // nibble-4 implementation. Keep that distinction explicit.
                    if !super::matches(
                        image,
                        deny,
                        &[(0x7808, 0xffff), (0x0900, 0xffff), (0x2804, 0xffff)],
                    ) {
                        return Err(Error::InvalidContract);
                    }
                    let exit = conditional(image, deny + 6, thumb_asm::Cond::Ne)
                        .ok_or(Error::InvalidContract)?;
                    if exit <= deny + 8
                        || exit - deny > 0x100
                        || !super::matches(
                            image,
                            exit,
                            &[(0x2001, 0xffff), (0x7038, 0xffff), (0xe000, 0xf800)],
                        )
                    {
                        return Err(Error::InvalidContract);
                    }
                    refusal = exit;
                } else if !valid_store || half(image, branch).map_or(true, |h| h & 0xf800 != 0xe000)
                {
                    return Err(Error::InvalidContract);
                }
                if value == 1 && half(image, pc + 4).map_or(true, |h| h & 0xff00 != 0x4900) {
                    return Err(Error::InvalidContract);
                }
                return Ok(Self {
                    variant,
                    site: pc,
                    deny,
                    refusal,
                    state,
                });
            }
            let ins = thumb_asm::isa::decode_at(image, pc).ok_or(Error::InvalidContract)?;
            if ins.is_branch() || ins.writes_pc() {
                return Err(Error::InvalidContract);
            }
            if let Some((register, address)) = flow.byte_load(image, pc) {
                state_read = Some((pc, register, address));
            }
            flow.step(image, pc)?;
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
    /// Original non-C continuation. The alternate variant retains a nibble-4
    /// implementation rather than going directly to a denial store.
    pub fn deny(&self) -> usize {
        self.deny
    }
    /// Validated native refusal block. Unlike [`Self::deny`], this is not the
    /// alternate nibble-4 implementation on classic firmware. It is reached
    /// before entering either native implementation, with their live registers.
    pub fn refusal(&self) -> usize {
        self.refusal
    }
    /// State address derived from the live literal load.
    pub fn state_address(&self) -> u32 {
        self.state
    }
}

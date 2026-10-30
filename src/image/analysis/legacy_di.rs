//! Stack-buffer DI parser without U recognition, bound to its native continuations.
use super::{conditional, half, matches, switch, Error, SavedLink, UhdArea, UhdAreas};
use thumb_asm::{isa::decode_at, Cond};

/// Legacy recognition in the modern stack-buffer parser. This is code evidence,
/// not physical UHD support or permission to install an incomplete conversion.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LegacyStackDi {
    /// First native attribute-validation instruction; eight bytes are replayable.
    pub prevalidation: usize,
    /// Native branch after those eight instructions' bytes.
    pub replay_continuation: usize,
    /// ROM identifier's existing O-only gate.
    pub identifier_gate: usize,
    /// Native format dispatch, including its original format-five handling.
    pub format: usize,
    /// Native density classification byte.
    pub format_flag: u32,
    /// Native generic layer normalization, retaining this image's arithmetic.
    pub layers: usize,
    /// Shared native media-state store after layer normalization.
    pub layer_store: usize,
    /// First native instruction after generic layer normalization.
    pub after_layers: usize,
    /// Media-state cell independently bound by the reviewed routing roles.
    pub state: u32,
    /// Byte offset of the native DI stack block from caller SP.
    pub stack_block: u8,
    /// Identifier byte offset inside that stack block.
    pub identifier_offset: u8,
    /// Nonvolatile state register; None when each native path loads its own pointer.
    pub state_register: Option<u8>,
    /// Native saved-LR/stack evidence at the proposed prevalidation detour.
    pub caller: SavedLink,
}

fn byte_load(dest: u16, base: u16, offset: u8) -> u16 {
    0x7800 | (u16::from(offset) << 6) | (base << 3) | dest
}
fn branch(image: &[u8], at: usize) -> Result<usize, Error> {
    let ins = decode_at(image, at).ok_or(Error::Truncated)?;
    if ins.mnemonic != "b" || ins.cond.is_some() {
        return Err(Error::InvalidContract);
    }
    let target = ins.branch_target().ok_or(Error::InvalidContract)? as usize;
    (target + 2 <= image.len())
        .then_some(target)
        .ok_or(Error::Truncated)
}
fn literal(image: &[u8], at: usize, register: u8) -> Result<u32, Error> {
    let op = half(image, at).ok_or(Error::Truncated)?;
    if op & 0xff00 != 0x4800 | (u16::from(register) << 8) {
        return Err(Error::InvalidContract);
    }
    let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
    Ok(u32::from_le_bytes(
        image
            .get(pool..pool + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    ))
}
fn unique(mut at: impl Iterator<Item = usize>) -> Result<usize, Error> {
    let first = at.next().ok_or(Error::UnknownLayout)?;
    if at.next().is_some() {
        return Err(Error::Ambiguous);
    }
    Ok(first)
}
fn ram(value: u32) -> bool {
    (0x01ff0000..0x02010000).contains(&value)
}

impl LegacyStackDi {
    /// Bind prefix/attribute gates, format switch, complete layer normalization
    /// and the native caller. Unknown or conflicting relationships are refused.
    pub fn detect(image: &[u8]) -> Result<Self, Error> {
        let areas = UhdAreas::inspect(image);
        let di = areas.area(UhdArea::DiscInformation)?;
        if di.selects_c7() != Some(false) || half(image, di.site()) != Some(0xab10) {
            return Err(Error::UnknownLayout);
        }
        let load = half(image, di.site() + 2).ok_or(Error::Truncated)?;
        if load & 0xf83f != 0x7818 || half(image, di.site() + 4) != Some(0x284f) {
            return Err(Error::InvalidContract);
        }
        let identifier_offset = ((load >> 6) & 31) as u8;
        if !matches!(identifier_offset, 8 | 16) {
            return Err(Error::UnknownLayout);
        }
        let state = areas.state_address()?;
        let validation = [
            (0xab10, 0xffff),
            (byte_load(0, 3, identifier_offset + 1), 0xffff),
            (0x0680, 0xffff),
            (0x0f81, 0xffff),
            (0xd000, 0xff00),
            (0x0f80, 0xffff),
            (0x2801, 0xffff),
            (0xd000, 0xff00),
        ];
        let prevalidation = unique(
            (di.site().saturating_sub(0x200)..di.site())
                .step_by(2)
                .filter(|&at| matches(image, at, &validation)),
        )?;
        let identifier =
            conditional(image, prevalidation + 8, Cond::Eq).ok_or(Error::InvalidContract)?;
        if conditional(image, prevalidation + 14, Cond::Eq) != Some(identifier)
            || !matches(
                image,
                identifier,
                &[
                    (0xab10, 0xffff),
                    (load, 0xffff),
                    (0x2857, 0xffff),
                    (0xd100, 0xff00),
                ],
            )
        {
            return Err(Error::InvalidContract);
        }
        let recordable =
            conditional(image, identifier + 6, Cond::Ne).ok_or(Error::InvalidContract)?;
        if !matches(
            image,
            recordable,
            &[
                (0xab10, 0xffff),
                (load, 0xffff),
                (0x2852, 0xffff),
                (0xd100, 0xff00),
            ],
        ) || conditional(image, recordable + 6, Cond::Ne) != Some(di.site())
        {
            return Err(Error::InvalidContract);
        }
        let prefix = unique(
            (prevalidation.saturating_sub(0x80)..prevalidation)
                .step_by(2)
                .filter(|&at| {
                    matches(
                        image,
                        at,
                        &[
                            (0xab10, 0xffff),
                            (byte_load(0, 3, identifier_offset - 4), 0xffff),
                            (0x2842, 0xffff),
                            (0xd100, 0xff00),
                        ],
                    )
                }),
        )?;
        let bad_prefix = conditional(image, prefix + 6, Cond::Ne).ok_or(Error::InvalidContract)?;
        let mut second = prefix + 8;
        if half(image, second).is_some_and(|op| op & 0xf800 == 0xe000) {
            second = branch(image, second)?;
        }
        if !matches(
            image,
            second,
            &[
                (byte_load(0, 3, identifier_offset - 3), 0xffff),
                (0x2844, 0xffff),
                (0xd000, 0xff00),
            ],
        ) || conditional(image, second + 4, Cond::Eq) != Some(prevalidation)
            || second + 6 != bad_prefix
        {
            return Err(Error::InvalidContract);
        }
        // Both failed prefix and failed attribute checks converge on the same
        // native diagnostic/error block; no failure path is forced successful.
        literal(image, bad_prefix, 0)?;
        literal(image, prevalidation + 16, 0)?;
        if branch(image, bad_prefix + 2)? != branch(image, prevalidation + 18)? {
            return Err(Error::InvalidContract);
        }
        let caller = SavedLink::detect(image, prevalidation)?;
        if prefix < caller.entry() || caller.stack_bytes() < 64 + usize::from(identifier_offset) + 4
        {
            return Err(Error::InvalidContract);
        }
        let format = branch(image, di.site() + di.length() - 2)?;
        if !matches(
            image,
            format,
            &[
                (0xab10, 0xffff),
                (byte_load(3, 3, identifier_offset + 3), 0xffff),
                (0x4800, 0xff00),
            ],
        ) {
            return Err(Error::InvalidContract);
        }
        let format_flag = literal(image, format + 4, 0)?;
        if !ram(format_flag) {
            return Err(Error::InvalidContract);
        }
        let targets = switch::targets(image, format + 6)?.ok_or(Error::InvalidContract)?;
        if targets.len() != 7 {
            return Err(Error::InvalidContract);
        }
        let five = targets[5];
        let density_store = if matches(image, five, &[(0x2120, 0xffff), (0x7001, 0xffff)]) {
            1
        } else if matches(image, five, &[(0x2220, 0xffff), (0x7002, 0xffff)]) {
            2
        } else {
            return Err(Error::InvalidContract);
        };
        let mut layers = five + 4;
        if half(image, layers).is_some_and(|op| op & 0xf800 == 0xe000) {
            layers = branch(image, layers)?;
        }
        if !matches(
            image,
            layers,
            &[
                (0xab10, 0xffff),
                (byte_load(0, 3, identifier_offset + 2), 0xffff),
                (0x21f3, 0xffff),
                (0x0900, 0xffff),
            ],
        ) {
            return Err(Error::InvalidContract);
        }
        let early = density_store == 2;
        let base = if early { 2 } else { 7 };
        let mut cursor = layers + 8;
        let mut conditional_edges = Vec::new();
        let mut store_edges = Vec::new();
        for count in 1..=4u16 {
            if half(image, cursor) != Some(0x2800 | count) {
                return Err(Error::InvalidContract);
            }
            let edge = cursor + 2;
            conditional_edges.push((edge, Cond::Ne));
            cursor += 4;
            if early {
                if literal(image, cursor, 2)? != state {
                    return Err(Error::InvalidContract);
                }
                cursor += 2;
            }
            if half(image, cursor) != Some(byte_load(0, base, 0)) {
                return Err(Error::InvalidContract);
            }
            cursor += 2;
            let ops: &[u16] = match count {
                1 => &[0x4008],
                2 => &[0x4008, 0x1d00],
                3 => &[0x4008, 0x3008],
                _ => &[0x210c, 0x4308],
            };
            for &op in ops {
                if half(image, cursor) != Some(op) {
                    return Err(Error::InvalidContract);
                }
                cursor += 2;
            }
            if count != 4 {
                store_edges.push(cursor);
                cursor += 2;
            }
            if count != 4 && conditional(image, edge, Cond::Ne) != Some(cursor) {
                return Err(Error::InvalidContract);
            }
        }
        let layer_store = cursor;
        if half(image, layer_store) != Some(0x7000 | (base << 3)) {
            return Err(Error::InvalidContract);
        }
        let after_layers = layer_store + 2;
        if store_edges
            .iter()
            .any(|&at| branch(image, at) != Ok(layer_store))
            || conditional(image, conditional_edges[3].0, Cond::Ne) != Some(after_layers)
            || !matches(
                image,
                after_layers,
                &[
                    (0x4800, 0xff00),
                    (0x2100, 0xffff),
                    (0x7001, 0xffff),
                    (0xab10, 0xffff),
                    (byte_load(1, 3, identifier_offset + 1), 0xffff),
                ],
            )
            || !ram(literal(image, after_layers, 0)?)
        {
            return Err(Error::InvalidContract);
        }
        let state_register = if early {
            None
        } else {
            let definitions: Vec<_> = (caller.entry()..prevalidation)
                .step_by(2)
                .filter(|&at| literal(image, at, 7) == Ok(state))
                .collect();
            let definition = unique(definitions.into_iter())?;
            caller.require_register_definition(image, definition, definition + 2, 7)?;
            Some(7)
        };
        Ok(Self {
            prevalidation,
            replay_continuation: prevalidation + 8,
            identifier_gate: di.site(),
            format,
            format_flag,
            layers,
            layer_store,
            after_layers,
            state,
            stack_block: 64,
            identifier_offset,
            state_register,
            caller,
        })
    }
}

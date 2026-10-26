//! Additional source-bound classic C8 consumers paired with explicit modern C7 gates.
//! Names describe code roles, not physical controller behavior or UHD capability.
//! Modern comparison source: 648a16d024eea31ef4901f3ac2180cbfffeda1161d70f9096335d8a6097445bc;
//! regions 32cbe, 33670, 33cae, 414f8, 142826 and 1435e0 respectively.
use super::{conditional, half, matches, C7Selection, Error, SavedLink};

/// Independently located native consumer roles, without model/hash dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicConsumerKind {
    /// Controller word at the live base pointer plus 0x18.
    Control18,
    /// DI initialization mode selection before the native programming call.
    DiMode,
    /// Native read-boundary position reflection.
    ReadBoundary,
    /// Native mode-byte checks for values two and three.
    Mode23,
    /// Native parameter-programming branch.
    ParameterClass,
    /// Native request argument eight versus 0x80000008.
    RequestArgument,
    /// Native stored read-position transformation.
    ReadValue,
    /// Native read-status update branch.
    ReadStatus,
    /// Skip the native parameter-programming call during C7 initialization.
    InitializationBypass,
}
/// A positively bound native gate; no output bytes or capability are implied.
#[derive(Debug, Clone)]
pub struct ClassicConsumer {
    /// Code role independently selected by the grammar.
    pub kind: ClassicConsumerKind,
    /// First instruction in the matched source region.
    pub region: usize,
    /// Original BICS/conditional pair and both native continuations.
    pub selection: C7Selection,
    /// Stack/LR contract of the parent containing the gate.
    pub caller: SavedLink,
    /// PC-relative load displaced with the selector, re-emitted as a literal.
    pub relocated_load: Option<(u8, u32)>,
}
struct Definition {
    kind: ClassicConsumerKind,
    pattern: &'static [(u16, u16)],
    gate: usize,
    target: usize,
    target_accepts: bool,
}
// Reference 40eb760e23f100d55e86e9c061c73428d4087ef712294e4dbfcefa3093837a1a.
// Addresses document provenance only; inspection searches all instruction offsets.
const DEFINITIONS: &[Definition] = &[
    // 0x1530f8..0x153114; modern explicit C7 counterpart 0x143310.
    Definition {
        kind: ClassicConsumerKind::ReadBoundary,
        gate: 10,
        target: 80,
        target_accepts: false,
        pattern: &[
            (0x4a00, 0xff00),
            (0x3020, 0xffff),
            (0x9001, 0xffff),
            (0x7811, 0xffff),
            (0x20c8, 0xffff),
            (0x4388, 0xffff),
            (0xd120, 0xffff),
            (0x4a00, 0xff00),
            (0x9901, 0xffff),
            (0x6810, 0xffff),
            (0x1c40, 0xffff),
            (0x4281, 0xffff),
            (0xd103, 0xffff),
            (0x6810, 0xffff),
        ],
    },
    // 0x10a0c4..0x10a0e4; modern explicit C7 counterpart 0xe079c.
    Definition {
        kind: ClassicConsumerKind::DiMode,
        gate: 6,
        target: 72,
        target_accepts: false,
        pattern: &[
            (0x4c00, 0xff00),
            (0x7820, 0xffff),
            (0x21c8, 0xffff),
            (0x4381, 0xffff),
            (0x4800, 0xff00),
            (0xd11d, 0xffff),
            (0x7822, 0xffff),
            (0x21cc, 0xffff),
            (0x4391, 0xffff),
            (0xd101, 0xffff),
            (0x2115, 0xffff),
            (0xe000, 0xffff),
            (0x211c, 0xffff),
            (0x7001, 0xffff),
            (0xf000, 0xf800),
            (0xd000, 0xd000),
        ],
    },
    // 0x78cc0..0x78cd0; modern C7 counterpart 0x7eb7e..0x7eb92.
    Definition {
        kind: ClassicConsumerKind::InitializationBypass,
        gate: 6,
        target: 16,
        target_accepts: true,
        pattern: &[
            (0x4800, 0xff00),
            (0x7801, 0xffff),
            (0x20c8, 0xffff),
            (0x4388, 0xffff),
            (0xd000, 0xff00),
            (0x2000, 0xffff),
            (0xf000, 0xf800),
            (0xd000, 0xd000),
        ],
    },
    // 0x35ac0..0x35adc
    Definition {
        kind: ClassicConsumerKind::Control18,
        gate: 6,
        target: 58,
        target_accepts: false,
        pattern: &[
            (0x4900, 0xff00),
            (0x780a, 0xffff),
            (0x21c8, 0xffff),
            (0x4391, 0xffff),
            (0xd100, 0xff00),
            (0x69a1, 0xffff),
            (0x4381, 0xffff),
            (0x31ff, 0xffff),
            (0x1c49, 0xffff),
            (0x61a1, 0xffff),
            (0x6820, 0xffff),
            (0x2103, 0xffff),
            (0x4308, 0xffff),
            (0x6020, 0xffff),
        ],
    },
    // 0x360b0..0x360ce
    Definition {
        kind: ClassicConsumerKind::Mode23,
        gate: 6,
        target: 22,
        target_accepts: false,
        pattern: &[
            (0x4f00, 0xff00),
            (0x783c, 0xffff),
            (0x23c8, 0xffff),
            (0x43a3, 0xffff),
            (0xd100, 0xff00),
            (0x780b, 0xffff),
            (0x2b02, 0xffff),
            (0xd000, 0xff00),
            (0x7809, 0xffff),
            (0x2903, 0xffff),
            (0xd000, 0xff00),
            (0x6801, 0xffff),
            (0x0849, 0xffff),
            (0x0049, 0xffff),
            (0x6001, 0xffff),
        ],
    },
    // 0x31e6c..0x31e7e
    Definition {
        kind: ClassicConsumerKind::ParameterClass,
        gate: 8,
        target: 208,
        target_accepts: true,
        pattern: &[
            (0x4c00, 0xff00),
            (0x7822, 0xffff),
            (0x25c8, 0xffff),
            (0x0029, 0xffff),
            (0x4391, 0xffff),
            (0xd000, 0xff00),
            (0x4f00, 0xff00),
            (0x2601, 0xffff),
            (0x0636, 0xffff),
        ],
    },
    // 0x484d6..0x484ec
    Definition {
        kind: ClassicConsumerKind::RequestArgument,
        gate: 6,
        target: 14,
        target_accepts: false,
        pattern: &[
            (0x4900, 0xff00),
            (0x7809, 0xffff),
            (0x20c8, 0xffff),
            (0x4388, 0xffff),
            (0xd100, 0xff00),
            (0x4800, 0xff00),
            (0xe000, 0xf800),
            (0x2008, 0xffff),
            (0xf000, 0xf800),
            (0xd000, 0xd000),
            (0x2002, 0xffff),
        ],
    },
    // 0x19702a..0x197042
    Definition {
        kind: ClassicConsumerKind::ReadValue,
        gate: 6,
        target: 24,
        target_accepts: false,
        pattern: &[
            (0x4900, 0xff00),
            (0x7809, 0xffff),
            (0x20c8, 0xffff),
            (0x4388, 0xffff),
            (0xd100, 0xff00),
            (0x4900, 0xff00),
            (0x6808, 0xffff),
            (0xf000, 0xf800),
            (0xd000, 0xd000),
            (0x4900, 0xff00),
            (0x6008, 0xffff),
            (0xe000, 0xf800),
        ],
    },
    // 0x197e18..0x197e30
    Definition {
        kind: ClassicConsumerKind::ReadStatus,
        gate: 6,
        target: 38,
        target_accepts: false,
        pattern: &[
            (0x4800, 0xff00),
            (0x7800, 0xffff),
            (0x23c8, 0xffff),
            (0x4383, 0xffff),
            (0xd100, 0xff00),
            (0x7808, 0xffff),
            (0x7812, 0xffff),
            (0x4290, 0xffff),
            (0xd100, 0xff00),
            (0x7808, 0xffff),
            (0xf000, 0xf800),
            (0xc000, 0xd001),
        ],
    },
];
fn literal(image: &[u8], at: usize) -> Option<u32> {
    let op = half(image, at)?;
    (op & 0xf800 == 0x4800).then_some(())?;
    let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
    Some(u32::from_le_bytes(
        image.get(pool..pool + 4)?.try_into().ok()?,
    ))
}
impl ClassicConsumer {
    /// Bind every required auxiliary gate to a common media-state cell, native
    /// control flow and a balanced caller. Unknown or duplicate roles refuse.
    pub fn inspect(image: &[u8], state: u32) -> Result<Vec<Self>, Error> {
        if !(0x01ff0000..0x02010000).contains(&state) {
            return Err(Error::InvalidContract);
        }
        let mut result = Vec::new();
        for def in DEFINITIONS {
            let length = def.pattern.len() * 2;
            if image.len() < length {
                return Err(Error::Truncated);
            }
            let mut hit = None;
            for region in (0..=image.len() - length).step_by(2) {
                if !matches(image, region, def.pattern) {
                    continue;
                }
                if literal(image, region) != Some(state) {
                    return Err(Error::InvalidContract);
                }
                let site = region + def.gate;
                let op = half(image, site).ok_or(Error::Truncated)?;
                if op & 0xffc0 != 0x4380 {
                    return Err(Error::InvalidContract);
                }
                let target = conditional(
                    image,
                    site + if def.kind == ClassicConsumerKind::DiMode {
                        4
                    } else {
                        2
                    },
                    if def.target_accepts { 0xd000 } else { 0xd100 },
                )
                .ok_or(Error::InvalidContract)?;
                if (def.kind != ClassicConsumerKind::ReadStatus && target != region + def.target)
                    || target + 4 > image.len()
                {
                    return Err(Error::InvalidContract);
                }
                let (accept, reject) = if def.target_accepts {
                    (target, site + 4)
                } else {
                    (
                        site + if def.kind == ClassicConsumerKind::DiMode {
                            6
                        } else {
                            4
                        },
                        target,
                    )
                };
                let relocated_load = if def.kind == ClassicConsumerKind::DiMode {
                    let value = literal(image, site + 2).ok_or(Error::InvalidContract)?;
                    if !(0x01ff0000..0x02010000).contains(&value)
                        || half(image, target) != Some(0x2107)
                    {
                        return Err(Error::InvalidContract);
                    }
                    Some((0, value))
                } else {
                    None
                };
                // Positive branch semantics beyond the local selector grammar.
                match def.kind {
                    ClassicConsumerKind::ReadBoundary => {
                        if !matches(
                            image,
                            reject,
                            &[
                                (0x7810, 0xffff),
                                (0x21cc, 0xffff),
                                (0x4008, 0xffff),
                                (0x28c4, 0xffff),
                            ],
                        ) {
                            return Err(Error::InvalidContract);
                        }
                    }
                    ClassicConsumerKind::ParameterClass => {
                        if half(image, accept) != Some(0x20b1)
                            || !half(image, accept + 2).is_some_and(|v| v & 0xf800 == 0xf000)
                            || half(image, accept + 6) != Some(0x2002)
                        {
                            return Err(Error::InvalidContract);
                        }
                    }
                    ClassicConsumerKind::RequestArgument => {
                        if literal(image, accept) != Some(0x80000008)
                            || half(image, reject) != Some(0x2008)
                        {
                            return Err(Error::InvalidContract);
                        }
                    }
                    ClassicConsumerKind::ReadStatus => {
                        // A pool/return guard can move this block by two bytes.
                        // Bind its flag cell and native joins instead of adding
                        // a model-specific alternative displacement.
                        let pattern = &[
                            (0x4800, 0xff00),
                            (0x7801, 0xffff),
                            (0x2900, 0xffff),
                            (0xd100, 0xff00),
                            (0x2101, 0xffff),
                            (0xe000, 0xf800),
                        ];
                        let join = conditional(image, region + 16, 0xd100)
                            .ok_or(Error::InvalidContract)?;
                        let tail = thumb_asm::isa::decode_at(image, target + 10)
                            .ok_or(Error::InvalidContract)?;
                        if !(region + 0x24..=region + 0x80).contains(&target)
                            || !matches(image, target, pattern)
                            || literal(image, target) != literal(image, region + 30)
                            || conditional(image, target + 6, 0xd100) != Some(join)
                            || tail.mnemonic != "b"
                            || tail.cond.is_some()
                            || tail.branch_target().map(|v| v as usize) != Some(region + 32)
                        {
                            return Err(Error::InvalidContract);
                        }
                    }
                    _ => {}
                }
                let bound = Self {
                    kind: def.kind,
                    region,
                    selection: C7Selection {
                        site,
                        replay: vec![op],
                        span: if relocated_load.is_some() { 6 } else { 4 },
                        accept,
                        reject,
                    },
                    caller: SavedLink::detect(image, site)?,
                    relocated_load,
                };
                if hit.replace(bound).is_some() {
                    return Err(Error::Ambiguous);
                }
            }
            result.push(hit.ok_or(Error::UnknownLayout)?);
        }
        let initializer = result
            .iter()
            .find(|c| c.kind == ClassicConsumerKind::InitializationBypass)
            .ok_or(Error::InvalidContract)?;
        let parameters = result
            .iter()
            .find(|c| c.kind == ClassicConsumerKind::ParameterClass)
            .ok_or(Error::InvalidContract)?;
        if thumb_asm::decode_bl(image, initializer.selection.reject() + 2)
            != Some(parameters.caller.entry as u32)
        {
            return Err(Error::InvalidContract);
        }
        Ok(result)
    }
}

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
    /// Native read-controller mode bits and position-field programming.
    ReadControl,
    /// Independent media-default mode writer after speed selection.
    MediaDefaults,
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
    // 0x6799a..0x679b4; modern explicit C7 counterpart0x688e6.
    Definition {
        kind: ClassicConsumerKind::MediaDefaults,
        gate: 6,
        target: 228,
        target_accepts: false,
        pattern: &[
            (0x4f00, 0xff00),
            (0x7839, 0xffff),
            (0x26c8, 0xffff),
            (0x438e, 0xffff),
            (0xd100, 0xff00),
            (0x783b, 0xffff),
            (0x21cc, 0xffff),
            (0x4399, 0xffff),
            (0xd101, 0xffff),
            (0x2115, 0xffff),
            (0xe000, 0xf800),
            (0x211c, 0xffff),
            (0xe000, 0xf800),
        ],
    },
    // 0x106a62..0x106a80; modern C7 counterpart 0xdc7ea.
    Definition {
        kind: ClassicConsumerKind::ReadControl,
        gate: 6,
        target: 42,
        target_accepts: false,
        pattern: &[
            (0x4a00, 0xff00),
            (0x7812, 0xffff),
            (0x21c8, 0xffff),
            (0x4391, 0xffff),
            (0x6981, 0xffff),
            (0xd10e, 0xffff),
            (0x2201, 0xffff),
            (0x4311, 0xffff),
            (0x6181, 0xffff),
            (0x69c1, 0xffff),
            (0x0a49, 0xffff),
            (0x0249, 0xffff),
            (0x61c1, 0xffff),
            (0x6a81, 0xffff),
            (0x4311, 0xffff),
        ],
    },
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
const ALTERNATIVES: &[Definition] = &[
    // Source 84fecc29, 0xec170; register allocation/native continuation variant.
    Definition {
        kind: ClassicConsumerKind::DiMode,
        gate: 6,
        target: 80,
        target_accepts: false,
        pattern: &[
            (0x4f00, 0xff00),
            (0x7838, 0xffff),
            (0x21c8, 0xffff),
            (0x4381, 0xffff),
            (0x4800, 0xff00),
            (0xd121, 0xffff),
            (0x783a, 0xffff),
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
    // Source 84fecc29, 0x306da; register allocation/native continuation variant.
    Definition {
        kind: ClassicConsumerKind::Control18,
        gate: 6,
        target: 52,
        target_accepts: false,
        pattern: &[
            (0x4900, 0xff00),
            (0x780a, 0xffff),
            (0x21c8, 0xffff),
            (0x4391, 0xffff),
            (0xd114, 0xffff),
            (0x6981, 0xffff),
            (0x2203, 0xffff),
            (0x0212, 0xffff),
            (0x4391, 0xffff),
            (0x31ff, 0xffff),
            (0x1c49, 0xffff),
            (0x6181, 0xffff),
            (0x6801, 0xffff),
            (0x2203, 0xffff),
            (0x4311, 0xffff),
            (0x6001, 0xffff),
        ],
    },
    // Source 84fecc29, 0x16759e; native inline flag store after the read call.
    Definition {
        kind: ClassicConsumerKind::ReadStatus,
        gate: 6,
        target: 40,
        target_accepts: false,
        pattern: &[
            (0x4800, 0xff00),
            (0x7800, 0xffff),
            (0x23c8, 0xffff),
            (0x4383, 0xffff),
            (0xd10e, 0xffff),
            (0x7808, 0xffff),
            (0x7812, 0xffff),
            (0x4290, 0xffff),
            (0xd110, 0xffff),
            (0x4800, 0xff00),
            (0x8006, 0xffff),
            (0x7808, 0xffff),
            (0xf000, 0xf800),
            (0xc000, 0xd001),
            (0x4800, 0xff00),
            (0x2101, 0xffff),
            (0x7001, 0xffff),
            (0x4800, 0xff00),
            (0x7001, 0xffff),
            (0xe005, 0xffff),
            (0x4900, 0xff00),
            (0x7808, 0xffff),
            (0x2800, 0xffff),
            (0xd101, 0xffff),
            (0x2001, 0xffff),
            (0x7008, 0xffff),
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
    /// Inspect one semantic role independently. Complete conversion callers
    /// still use `inspect`, which requires every role and their cross-links.
    pub fn inspect_kind(
        image: &[u8],
        state: u32,
        kind: ClassicConsumerKind,
    ) -> Result<Self, Error> {
        if !(0x01ff0000..0x02010000).contains(&state) {
            return Err(Error::InvalidContract);
        }
        let mut hit = None;
        for def in DEFINITIONS
            .iter()
            .chain(ALTERNATIVES)
            .filter(|d| d.kind == kind)
        {
            let length = def.pattern.len() * 2;
            if image.len() < length {
                return Err(Error::Truncated);
            }
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
                    site + if matches!(
                        def.kind,
                        ClassicConsumerKind::DiMode | ClassicConsumerKind::ReadControl
                    ) {
                        4
                    } else {
                        2
                    },
                    if def.target_accepts {
                        thumb_asm::Cond::Eq
                    } else {
                        thumb_asm::Cond::Ne
                    },
                )
                .ok_or(Error::InvalidContract)?;
                if (!matches!(
                    def.kind,
                    ClassicConsumerKind::ReadStatus | ClassicConsumerKind::MediaDefaults
                ) && target != region + def.target)
                    || target + 4 > image.len()
                {
                    return Err(Error::InvalidContract);
                }
                let (accept, reject) = if def.target_accepts {
                    (target, site + 4)
                } else {
                    (
                        site + if matches!(
                            def.kind,
                            ClassicConsumerKind::DiMode | ClassicConsumerKind::ReadControl
                        ) {
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
                    ClassicConsumerKind::MediaDefaults => {
                        let branch = |at| -> Option<usize> {
                            let ins = thumb_asm::isa::decode_at(image, at)?;
                            if ins.mnemonic != "b" || ins.cond.is_some() {
                                return None;
                            }
                            ins.branch_target().map(|v| v as usize)
                        };
                        let store = branch(region + 20).ok_or(Error::InvalidContract)?;
                        if branch(region + 24) != Some(store)
                            || half(image, store) != Some(0x7011)
                            || !(region + 26..region + 0x400).contains(&store)
                        {
                            return Err(Error::InvalidContract);
                        }
                        let mut join = reject;
                        for _ in 0..3 {
                            if join == store + 2 {
                                break;
                            }
                            join = branch(join).ok_or(Error::InvalidContract)?;
                        }
                        if join != store + 2 {
                            return Err(Error::InvalidContract);
                        }
                    }
                    ClassicConsumerKind::ReadControl => {
                        if region < 10
                            || literal(image, region - 10) != Some(0x042080c0)
                            || !matches(
                                image,
                                region - 10,
                                &[
                                    (0x4800, 0xff00),
                                    (0x6981, 0xffff),
                                    (0x2212, 0xffff),
                                    (0x4391, 0xffff),
                                    (0x6181, 0xffff),
                                ],
                            )
                        {
                            return Err(Error::InvalidContract);
                        }
                    }
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
                        let join = conditional(image, region + 16, thumb_asm::Cond::Ne)
                            .ok_or(Error::InvalidContract)?;
                        let tail = thumb_asm::isa::decode_at(image, target + 10)
                            .ok_or(Error::InvalidContract)?;
                        let branch_store = matches(image, target, pattern)
                            && literal(image, target) == literal(image, region + 30)
                            && tail.mnemonic == "b"
                            && tail.cond.is_none()
                            && tail.branch_target().map(|v| v as usize) == Some(region + 32);
                        let inline_store = matches(
                            image,
                            target,
                            &[
                                (0x4900, 0xff00),
                                (0x7808, 0xffff),
                                (0x2800, 0xffff),
                                (0xd101, 0xffff),
                                (0x2001, 0xffff),
                                (0x7008, 0xffff),
                            ],
                        ) && matches(
                            image,
                            region + 28,
                            &[
                                (0x4800, 0xff00),
                                (0x2101, 0xffff),
                                (0x7001, 0xffff),
                                (0x4800, 0xff00),
                                (0x7001, 0xffff),
                                (0xe000, 0xf800),
                            ],
                        ) && literal(image, target)
                            == literal(image, region + 34)
                            && thumb_asm::isa::decode_at(image, region + 38).is_some_and(|i| {
                                i.mnemonic == "b"
                                    && i.cond.is_none()
                                    && i.branch_target().map(|v| v as usize) == Some(join)
                            })
                            && join == target + 12;
                        if !(region + 0x24..=region + 0x80).contains(&target)
                            || conditional(image, target + 6, thumb_asm::Cond::Ne) != Some(join)
                            || !(branch_store || inline_store)
                        {
                            return Err(Error::InvalidContract);
                        }
                    }
                    _ => {}
                }
                let caller = SavedLink::detect(image, site)?;
                if def.kind == ClassicConsumerKind::MediaDefaults {
                    let at = caller.entry + 16;
                    if half(image, at).map(|v| v & 0xff00) != Some(0x4a00)
                        || !literal(image, at)
                            .is_some_and(|v| (0x01ff0000..0x02010000).contains(&v))
                    {
                        return Err(Error::InvalidContract);
                    }
                }
                let bound = Self {
                    kind: def.kind,
                    region,
                    selection: C7Selection {
                        site,
                        replay: if def.kind == ClassicConsumerKind::ReadControl {
                            vec![op, 0x6981]
                        } else {
                            vec![op]
                        },
                        span: if relocated_load.is_some()
                            || def.kind == ClassicConsumerKind::ReadControl
                        {
                            6
                        } else {
                            4
                        },
                        accept,
                        reject,
                    },
                    caller,
                    relocated_load,
                };
                if hit.replace(bound).is_some() {
                    return Err(Error::Ambiguous);
                }
            }
        }
        hit.ok_or(Error::UnknownLayout)
    }
    /// Bind every required auxiliary gate to a common media-state cell, native
    /// control flow and a balanced caller. Unknown or duplicate roles refuse.
    pub fn inspect(image: &[u8], state: u32) -> Result<Vec<Self>, Error> {
        if !(0x01ff0000..0x02010000).contains(&state) {
            return Err(Error::InvalidContract);
        }
        let mut result = Vec::new();
        for def in DEFINITIONS {
            result.push(Self::inspect_kind(image, state, def.kind)?);
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

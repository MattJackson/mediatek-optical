//! Independent native disc-recognition/routing contracts. This is code-layout
//! evidence, not a claim that a drive can physically read UHD media.
use super::{half, matches, Error};
use thumb_asm::isa::{decode_at, AddrMode, Operand};

#[path = "uhd_layouts.rs"]
mod layouts;

/// Independently recognized areas; hardware defaults are deliberately read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UhdArea {
    /// Disc-information identifier and format recognition.
    DiscInformation,
    /// State-dependent hardware-control bit selection.
    ControlBit,
    /// State-dependent hardware-control field selection.
    ControlField,
    /// Native forward calculation gate.
    ForwardCalculation,
    /// Native reverse calculation gate.
    ReverseCalculation,
    /// Parameter lookup versus special-case selection; retain the native table.
    ParameterNibble,
    /// Hardware/media defaults, for comparison only. Never conversion patches.
    HardwareDefaults,
}
impl UhdArea {
    /// All separately required inventory roles, in stable order.
    pub const ALL: [Self; 7] = [
        Self::DiscInformation,
        Self::ControlBit,
        Self::ControlField,
        Self::ForwardCalculation,
        Self::ReverseCalculation,
        Self::ParameterNibble,
        Self::HardwareDefaults,
    ];
}

/// Native handling established by a positively recognized code grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UhdHandling {
    /// Older selection/recognition requiring an extension for the new state.
    Legacy,
    /// This region already explicitly handles C7/U.
    ExplicitC7,
    /// Hardware policy is evidence only and must not be converted.
    HardwarePolicy,
}
struct SelectionDefinition {
    offset: usize,
    replay: &'static [u16],
    span: usize,
    reject_offset: Option<usize>,
}
/// Original selector operation and its two native continuations, bound before emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C7Selection {
    pub(super) site: usize,
    pub(super) replay: Vec<u16>,
    pub(super) span: usize,
    pub(super) accept: usize,
    pub(super) reject: usize,
}
impl C7Selection {
    /// First operation replaced by the candidate detour.
    pub fn site(&self) -> usize {
        self.site
    }
    /// Original operations that must execute on both routes. A displaced
    /// PC-relative load inside [`span`](Self::span) cannot be replayed verbatim
    /// and is carried by the owning contract instead
    /// ([`ClassicConsumer::relocated_load`](super::ClassicConsumer::relocated_load)).
    pub fn replay(&self) -> &[u16] {
        &self.replay
    }
    /// Total original operation/branch bytes replaced at [`site`](Self::site),
    /// including any relocated load not present in [`replay`](Self::replay).
    pub fn span(&self) -> usize {
        self.span
    }
    /// Native C8-class continuation.
    pub fn accept(&self) -> usize {
        self.accept
    }
    /// Native other-state continuation.
    pub fn reject(&self) -> usize {
        self.reject
    }
}
struct Definition {
    area: UhdArea,
    name: &'static str,
    pattern: &'static [(u16, u16)],
    handling: UhdHandling,
    selection: Option<SelectionDefinition>,
}

/// A PC-relative literal bound to the actual instruction and destination register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UhdLiteral {
    /// File offset of the load.
    pub instruction: usize,
    /// Low destination register number.
    pub register: u8,
    /// Literal value read from this image, not copied from another model.
    pub value: u32,
}
/// A decoded branch/call edge belonging to a matched region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UhdEdge {
    /// File offset of the branch instruction.
    pub instruction: usize,
    /// Resolved destination inside the supplied image.
    pub target: usize,
}

/// One uniquely selected instruction variant and its source-bound evidence.
/// Fields are read-only through this API; emitters must retain the source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UhdAreaContract {
    area: UhdArea,
    variant: &'static str,
    site: usize,
    length: usize,
    literals: Vec<UhdLiteral>,
    edges: Vec<UhdEdge>,
    coefficient_continuation: Option<usize>,
    handling: UhdHandling,
    selection: Option<C7Selection>,
}
impl UhdAreaContract {
    /// Semantic role, independent of firmware model or chipset label.
    pub fn area(&self) -> UhdArea {
        self.area
    }
    /// Positively recognized instruction variant, not a capability declaration.
    pub fn variant(&self) -> &'static str {
        self.variant
    }
    /// Start of the reviewed instruction region.
    pub fn site(&self) -> usize {
        self.site
    }
    /// Bytes belonging to the matched region (not the complete function).
    pub fn length(&self) -> usize {
        self.length
    }
    /// Literal loads whose source pools have been checked.
    pub fn literals(&self) -> &[UhdLiteral] {
        &self.literals
    }
    /// Decoded in-image branch destinations.
    pub fn edges(&self) -> &[UhdEdge] {
        &self.edges
    }
    /// Actual add/subtract continuation, following the coefficient path across pools.
    pub fn coefficient_continuation(&self) -> Option<usize> {
        self.coefficient_continuation
    }
    /// Whether the native grammar explicitly handles C7. For the explicit-C7
    /// forward and reverse calculations the `cmp r0, #0xc7` test lies at the
    /// first rejection's branch target, outside `site()..site() + length()`.
    /// Hardware defaults intentionally have no conversion meaning.
    pub fn selects_c7(&self) -> Option<bool> {
        match self.handling {
            UhdHandling::HardwarePolicy => None,
            UhdHandling::ExplicitC7 => Some(true),
            UhdHandling::Legacy => Some(false),
        }
    }
    /// Source-bound selector contract; absent means no candidate wrapper is established.
    pub fn selection(&self) -> Option<&C7Selection> {
        self.selection.as_ref()
    }
}

fn word(image: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        image.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn literal(image: &[u8], at: usize) -> Option<UhdLiteral> {
    let h = half(image, at)?;
    if h & 0xf800 != 0x4800 {
        return None;
    }
    Some(UhdLiteral {
        instruction: at,
        register: ((h >> 8) & 7) as u8,
        value: word(image, ((at + 4) & !3) + usize::from(h & 255) * 4)?,
    })
}
pub(super) fn coefficient(image: &[u8], start: usize, reverse: bool) -> Result<usize, Error> {
    let mut pc = start;
    let mut visited = Vec::new();
    let mut constant: Option<u8> = None;
    for _ in 0..40 {
        if visited.contains(&pc) {
            return Err(Error::InvalidContract);
        }
        visited.push(pc);
        let ins = decode_at(image, pc).ok_or(Error::Truncated)?;
        // Only an add/sub that reads the register holding 0x51b1 continues it.
        let reads_constant = |live: u8| {
            let reads = |op: Option<Operand>| matches!(op, Some(Operand::Reg(r) | Operand::RegShifted(r, _)) if r.num() == live);
            reads(ins.operands.get(1))
                || reads(ins.operands.get(2))
                || (ins.operands.get(2).is_none() && reads(ins.operands.get(0)))
        };
        if constant.is_some_and(reads_constant) && matches!(ins.mnemonic, "add" | "sub") {
            return if ins.mnemonic == if reverse { "sub" } else { "add" } {
                Ok(pc)
            } else {
                Err(Error::UnknownLayout)
            };
        }
        // Any other write to the live register, or a call, ends the constant.
        if let Some(live) = constant {
            // `pop` carries its list first; `ldm` carries the base register
            // first and the loaded list second.
            let loads_live = matches!(ins.mnemonic, "pop" | "ldm" | "ldmia" | "ldmdb")
                && ins
                    .operands
                    .as_slice()
                    .any(|op| matches!(op, Operand::RegList(bits) if bits & (1 << live) != 0));
            // Base writeback (`ldmia r1!`, `[r1, #4]!`, `[r1], #4`) also replaces it.
            let writes_back_live = ins.operands.as_slice().any(|op| match op {
                Operand::Text(text) => {
                    text.strip_prefix('r')
                        .and_then(|s| s.strip_suffix('!'))
                        .and_then(|s| s.parse::<u8>().ok())
                        == Some(live)
                }
                Operand::Mem(m) => m.mode != AddrMode::Offset && m.base.num() == live,
                _ => false,
            });
            let writes_live = loads_live
                || writes_back_live
                || match ins.operands.get(0) {
                    Some(Operand::Reg(r)) => {
                        r.num() == live
                            && !ins.mnemonic.starts_with("str")
                            && !matches!(
                                ins.mnemonic,
                                "push" | "stm" | "stmia" | "stmdb" | "cmp" | "cmn" | "tst" | "teq"
                            )
                    }
                    _ => false,
                };
            if writes_live || ins.is_call() {
                constant = None;
            }
        }
        // Only Thumb-1 operations, calls and unconditional branches are
        // modelled. Wide forms can write a second register (`ldrd`, `umull`)
        // and any other PC write leaves the routine: refuse both.
        if (ins.len() == 4 && !ins.is_call() && ins.mnemonic != "b")
            || (ins.is_branch() && !ins.is_call() && ins.mnemonic != "b")
        {
            return Err(Error::InvalidContract);
        }
        if let Some(load) = literal(image, pc).filter(|v| v.value == 0x51b1) {
            constant = Some(load.register);
        }
        // The fall-through CC-mask path skips calls and follows unconditional
        // branches over literal pools. No symbolic state or hardware is guessed.
        if ins.mnemonic == "b" && ins.cond.is_none() {
            pc = ins.branch_target().ok_or(Error::InvalidContract)? as usize;
        } else {
            pc = pc.checked_add(ins.len()).ok_or(Error::Truncated)?;
        }
    }
    Err(Error::InvalidContract)
}
fn bind(image: &[u8], def: &Definition, site: usize) -> Result<UhdAreaContract, Error> {
    let end = site + def.pattern.len() * 2;
    let mut pc = site;
    let mut literals = Vec::new();
    let mut edges = Vec::new();
    while pc < end {
        let ins = decode_at(image, pc).ok_or(Error::InvalidContract)?;
        if pc + ins.len() > end {
            return Err(Error::InvalidContract);
        }
        if half(image, pc).is_some_and(|h| h & 0xf800 == 0x4800) {
            literals.push(literal(image, pc).ok_or(Error::Truncated)?);
        }
        if let Some(target) = ins.is_branch().then(|| ins.branch_target()).flatten() {
            let target = target as usize;
            if target.checked_add(2).map_or(true, |v| v > image.len()) {
                return Err(Error::Truncated);
            }
            edges.push(UhdEdge {
                instruction: pc,
                target,
            });
        }
        pc += ins.len();
    }
    if def.name.starts_with("no_u") {
        let direct_r_failure = (site.saturating_sub(40)..site).step_by(2).any(|prior| {
            half(image, prior).is_some_and(|h| h & 0xf8ff == 0x2852)
                && super::conditional(image, prior + 2, thumb_asm::Cond::Ne) == Some(site)
        });
        if !direct_r_failure {
            return Err(Error::InvalidContract);
        }
    }
    let coefficient_continuation = match def.area {
        UhdArea::ForwardCalculation | UhdArea::ReverseCalculation => Some(coefficient(
            image,
            site,
            def.area == UhdArea::ReverseCalculation,
        )?),
        _ => None,
    };
    // The explicit-C7 calculation grammars hold no C7 test themselves: their
    // first C8-class rejection must land on `cmp r0, #0xc7` over the state
    // byte (forward: r0 already holds it; reverse: r0 still holds the cell).
    if def.handling == UhdHandling::ExplicitC7 {
        let c7_test: Option<(usize, &[(u16, u16)])> = match def.area {
            UhdArea::ForwardCalculation => Some((12, &[(0x28c7, 0xffff)])),
            UhdArea::ReverseCalculation => Some((14, &[(0x7800, 0xffff), (0x28c7, 0xffff)])),
            _ => None,
        };
        if let Some((bne, test)) = c7_test {
            let target = super::conditional(image, site + bne, thumb_asm::Cond::Ne)
                .ok_or(Error::InvalidContract)?;
            if !matches(image, target, test) {
                return Err(Error::InvalidContract);
            }
        }
    }
    let selection = def
        .selection
        .as_ref()
        .map(|selection| {
            let gate = site + selection.offset;
            if !selection
                .replay
                .iter()
                .enumerate()
                .all(|(i, &op)| half(image, gate + i * 2) == Some(op))
            {
                return Err(Error::InvalidContract);
            }
            let reject = super::conditional(
                image,
                gate + selection.replay.len() * 2,
                thumb_asm::Cond::Ne,
            )
            .ok_or(Error::InvalidContract)?;
            let accept = gate + selection.span;
            if let Some(offset) = selection.reject_offset {
                if reject != site + offset {
                    return Err(Error::InvalidContract);
                }
            } else if def.area == UhdArea::ReverseCalculation {
                // The reverse rejection reuses the forward gate's BNE with
                // the current BICS flags. Bind that actual gate and its own
                // restoring epilogue rather than treating it as a new policy.
                let forward_site = reject.checked_sub(12).ok_or(Error::InvalidContract)?;
                let forward_def = layouts::DEFINITIONS
                    .iter()
                    .find(|d| d.area == UhdArea::ForwardCalculation && d.name == "classic")
                    .ok_or(Error::InvalidContract)?;
                if !matches(image, forward_site, forward_def.pattern) {
                    return Err(Error::InvalidContract);
                }
                // This candidate's own coefficient already proved it is a
                // reverse calculation. A shared gate that is not a forward
                // calculation is a broken contract, not "the opposite role".
                let forward = bind(image, forward_def, forward_site).map_err(|e| {
                    if e == Error::UnknownLayout {
                        Error::InvalidContract
                    } else {
                        e
                    }
                })?;
                let gate = forward.selection().ok_or(Error::InvalidContract)?;
                if gate.site() + gate.replay().len() * 2 != reject
                    || forward.literals.first().map(|l| l.value)
                        != literals.first().map(|l| l.value)
                {
                    return Err(Error::InvalidContract);
                }
            } else {
                // The older calculation gate exists in both generations, with
                // different pool placement. Bind its rejection to the native
                // input/flag-restoring epilogue, not a fixed displacement.
                let jump = decode_at(image, reject).ok_or(Error::Truncated)?;
                if jump.mnemonic != "b" || jump.cond.is_some() {
                    return Err(Error::InvalidContract);
                }
                let epilogue = jump.branch_target().ok_or(Error::InvalidContract)? as usize;
                if !half(image, epilogue).is_some_and(|h| h & 0xff00 == 0x9800)
                    || half(image, epilogue + 2) != Some(0x8020)
                    || !literal(image, epilogue + 4).is_some_and(|v| {
                        v.register == 4 && (0x01ff0000..0x02010000).contains(&v.value)
                    })
                    || half(image, epilogue + 6) != Some(0x7820)
                    || !half(image, epilogue + 8).is_some_and(|h| h & 0xff00 == 0x9900)
                {
                    return Err(Error::InvalidContract);
                }
            }
            if accept + 2 > image.len() || selection.span != selection.replay.len() * 2 + 2 {
                return Err(Error::Truncated);
            }
            Ok(C7Selection {
                site: gate,
                replay: selection.replay.to_vec(),
                span: selection.span,
                accept,
                reject,
            })
        })
        .transpose()?;
    Ok(UhdAreaContract {
        area: def.area,
        variant: def.name,
        site,
        length: end - site,
        literals,
        edges,
        coefficient_continuation,
        handling: def.handling,
        selection,
    })
}

/// Inventory matches independently, retaining ambiguity and missing roles. Finding
/// all seven regions alone does not establish a complete UHD conversion plan.
#[derive(Debug, Clone)]
pub struct UhdAreas {
    areas: Vec<(UhdArea, Result<UhdAreaContract, Error>)>,
}
pub(super) fn inspect_role(image: &[u8], area: UhdArea) -> Result<UhdAreaContract, Error> {
    let mut hits = Vec::new();
    let mut invalid = None;
    for def in layouts::DEFINITIONS.iter().filter(|d| d.area == area) {
        let length = def.pattern.len() * 2;
        if image.len() < length {
            continue;
        }
        for site in (0..=image.len() - length).step_by(2) {
            if !matches(image, site, def.pattern) {
                continue;
            }
            match bind(image, def, site) {
                Ok(contract) => hits.push(contract),
                // Forward and reverse prefixes share instructions. A
                // calculation with the opposite operation is not this role.
                Err(Error::UnknownLayout)
                    if matches!(
                        area,
                        UhdArea::ForwardCalculation | UhdArea::ReverseCalculation
                    ) => {}
                Err(error) => invalid = Some(error),
            }
        }
    }
    if let Some(error) = invalid {
        Err(error)
    } else if hits.len() > 1 {
        Err(Error::Ambiguous)
    } else {
        hits.pop().ok_or(Error::UnknownLayout)
    }
}

impl UhdAreas {
    /// Inspect native instruction roles; no model, hash, filename or generation whitelist.
    pub fn inspect(image: &[u8]) -> Self {
        Self {
            areas: UhdArea::ALL
                .into_iter()
                .map(|area| (area, inspect_role(image, area)))
                .collect(),
        }
    }
    /// Independent outcome for this role; no fallback from ambiguity to a chipset guess.
    pub fn area(&self, area: UhdArea) -> Result<&UhdAreaContract, Error> {
        self.areas
            .iter()
            .find(|(key, _)| *key == area)
            .expect("fixed role set")
            .1
            .as_ref()
            .map_err(|e| *e)
    }
    /// Bind the common media-state cell across all directly loading roles.
    /// DI recognition uses its caller's live pointer; it does not establish a new cell.
    pub fn state_address(&self) -> Result<u32, Error> {
        let mut state = None;
        for area in UhdArea::ALL
            .into_iter()
            .filter(|a| *a != UhdArea::DiscInformation)
        {
            let contract = self.area(area)?;
            let value = contract
                .literals
                .first()
                .ok_or(Error::InvalidContract)?
                .value;
            if !(0x01ff0000..0x02010000).contains(&value) || state.is_some_and(|s| s != value) {
                return Err(Error::InvalidContract);
            }
            state = Some(value);
        }
        state.ok_or(Error::UnknownLayout)
    }
}

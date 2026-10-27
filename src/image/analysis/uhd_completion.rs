//! Native controller-field and read-completion boundary selectors.
//! Reference classic 40eb760e / modern 648a16d0; runtime uses instruction roles.
use super::{conditional, half, matches, C7Selection, Error, SavedLink};

/// Remaining read-completion selectors and their source-bound native bodies.
#[derive(Debug, Clone)]
pub struct ClassicReadCompletion {
    /// Complete paired controller-field region.
    pub controller_region: usize,
    /// Native ROM read/recovery dispatch; C7 and C8 already share its branch.
    pub recovery_region: usize,
    /// Continuation after native read-entry result assignment.
    pub recovery_end: usize,
    /// Source-bound state-pointer load before the recovery dispatch.
    pub recovery_state_load: usize,
    /// Native state-pointer and request-pointer registers.
    pub recovery_state_register: u8,
    /// Native request/status structure register.
    pub recovery_request_register: u8,
    /// Native saved flag copied into the request structure.
    pub recovery_flag_register: u8,
    /// Saved native recovery frame.
    pub recovery_caller: SavedLink,
    /// Native read-completion boundary region.
    pub boundary_region: usize,
    /// First instruction after reflected-position calculation and hardware store.
    pub boundary_end: usize,
    /// Native cached layer boundaries used by the reflected-position body.
    pub boundaries: [u32; 3],
    /// Controller timing, controller mode and read boundary, respectively.
    pub selections: [C7Selection; 3],
    /// Saved native parent frames for each selector.
    pub callers: [SavedLink; 3],
}
// Source 0x366d0..0x3673c; counterpart 0x26972..0x26aa6.
const CONTROLLER: &[(u16, u16)] = &[
    (0x4b00, 0xff00),
    (0x781e, 0xffff),
    (0x25c8, 0xffff),
    (0x0028, 0xffff),
    (0x43b0, 0xffff),
    (0x260f, 0xffff),
    (0x2777, 0xffff),
    (0x023f, 0xffff),
    (0x0236, 0xffff),
    (0x2800, 0xffff),
    (0x6810, 0xffff),
    (0xd109, 0xffff),
    (0x43b8, 0xffff),
    (0x2713, 0xffff),
    (0x027f, 0xffff),
    (0x19c0, 0xffff),
    (0x6010, 0xffff),
    (0x6808, 0xffff),
    (0x43b0, 0xffff),
    (0x2203, 0xffff),
    (0x0252, 0xffff),
    (0xe008, 0xffff),
    (0x43b8, 0xffff),
    (0x2705, 0xffff),
    (0x02bf, 0xffff),
    (0x19c0, 0xffff),
    (0x6010, 0xffff),
    (0x6808, 0xffff),
    (0x43b0, 0xffff),
    (0x2207, 0xffff),
    (0x0212, 0xffff),
    (0x1880, 0xffff),
    (0x6008, 0xffff),
    (0x4800, 0xff00),
    (0x3840, 0xffff),
    (0x6b81, 0xffff),
    (0x4a00, 0xff00),
    (0x4011, 0xffff),
    (0x6381, 0xffff),
    (0x7819, 0xffff),
    (0x002a, 0xffff),
    (0x438a, 0xffff),
    (0x2101, 0xffff),
    (0x2603, 0xffff),
    (0x02b6, 0xffff),
    (0x0289, 0xffff),
    (0x2a00, 0xffff),
    (0x6b02, 0xffff),
    (0xd101, 0xffff),
    (0x43b2, 0xffff),
    (0xe001, 0xffff),
    (0x43b2, 0xffff),
    (0x1852, 0xffff),
    (0x6302, 0xffff),
];
// Source 0x197b18..0x197bb2; counterpart 0x143310..0x14339a.
const BOUNDARY: &[(u16, u16)] = &[
    (0x4800, 0xff00),
    (0x7801, 0xffff),
    (0x20c8, 0xffff),
    (0x4388, 0xffff),
    (0xd17a, 0xffff),
    (0x4800, 0xff00),
    (0x9a0a, 0xffff),
    (0x6801, 0xffff),
    (0x1c49, 0xffff),
    (0x428a, 0xffff),
    (0xd10f, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd107, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd003, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd169, 0xffff),
    (0x6801, 0xffff),
    (0x2203, 0xffff),
    (0x0692, 0xffff),
    (0xe014, 0xffff),
    (0x4b00, 0xff00),
    (0x9a0a, 0xffff),
    (0x6819, 0xffff),
    (0x1c49, 0xffff),
    (0x428a, 0xffff),
    (0xd112, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd107, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd003, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd1e8, 0xffff),
    (0x6819, 0xffff),
    (0x2201, 0xffff),
    (0x06d2, 0xffff),
    (0x1a51, 0xffff),
    (0x1e49, 0xffff),
    (0x910a, 0xffff),
    (0xe015, 0xffff),
    (0x4b00, 0xff00),
    (0x9a0a, 0xffff),
    (0x6819, 0xffff),
    (0x1c49, 0xffff),
    (0x428a, 0xffff),
    (0xd112, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd107, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd003, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd1cf, 0xffff),
    (0x6819, 0xffff),
    (0x2201, 0xffff),
    (0x0692, 0xffff),
    (0xe7e5, 0xffff),
    (0x4a00, 0xff00),
    (0x3240, 0xffff),
    (0x6091, 0xffff),
];
const BOUNDARY_VENEER: &[(u16, u16)] = &[
    (0x4800, 0xff00),
    (0x7801, 0xffff),
    (0x20c8, 0xffff),
    (0x4388, 0xffff),
    (0xd179, 0xffff),
    (0x4800, 0xff00),
    (0x9a0a, 0xffff),
    (0x6801, 0xffff),
    (0x1c49, 0xffff),
    (0x428a, 0xffff),
    (0xd110, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd107, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd003, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd168, 0xffff),
    (0x6801, 0xffff),
    (0x2203, 0xffff),
    (0x0692, 0xffff),
    (0xe015, 0xffff),
    (0xe000, 0xf800),
    (0x4b00, 0xff00),
    (0x9a0a, 0xffff),
    (0x6819, 0xffff),
    (0x1c49, 0xffff),
    (0x428a, 0xffff),
    (0xd112, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd107, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd003, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd1e7, 0xffff),
    (0x6819, 0xffff),
    (0x2201, 0xffff),
    (0x06d2, 0xffff),
    (0x1a51, 0xffff),
    (0x1e49, 0xffff),
    (0x910a, 0xffff),
    (0xe015, 0xffff),
    (0x4b00, 0xff00),
    (0x9a0a, 0xffff),
    (0x6819, 0xffff),
    (0x1c49, 0xffff),
    (0x428a, 0xffff),
    (0xd112, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd107, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd003, 0xffff),
    (0x4900, 0xff00),
    (0x7809, 0xffff),
    (0x2900, 0xffff),
    (0xd1ce, 0xffff),
    (0x6819, 0xffff),
    (0x2201, 0xffff),
    (0x0692, 0xffff),
    (0xe7e5, 0xffff),
    (0x4a00, 0xff00),
    (0x3240, 0xffff),
    (0x6091, 0xffff),
];
const RECOVERY: &[(u16, u16)] = &[
    (0x7821, 0xffff),
    (0x0989, 0xffff),
    (0x2903, 0xffff),
    (0xd100, 0xff00),
    (0x7821, 0xffff),
    (0x0949, 0xffff),
    (0x2907, 0xffff),
    (0xd100, 0xff00),
    (0x7821, 0xffff),
    (0x0689, 0xffff),
    (0xd400, 0xff00),
    (0x7821, 0xffff),
    (0x0909, 0xffff),
    (0x2905, 0xffff),
    (0xd100, 0xff00),
    (0x4b00, 0xff00),
    (0x6819, 0xffff),
    (0x2201, 0xffff),
    (0x0312, 0xffff),
    (0x4391, 0xffff),
    (0x6019, 0xffff),
    (0x73a8, 0xffff),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0xe003, 0xffff),
    (0x7ae8, 0xffff),
    (0x73a8, 0xfff8),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x7028, 0xffff),
    (0x7828, 0xffff),
    (0x2800, 0xffff),
    (0xd100, 0xff00),
];
const RECOVERY_R5: &[(u16, u16)] = &[
    (0x7829, 0xffff),
    (0x0989, 0xffff),
    (0x2903, 0xffff),
    (0xd100, 0xff00),
    (0x7829, 0xffff),
    (0x0949, 0xffff),
    (0x2907, 0xffff),
    (0xd100, 0xff00),
    (0x7829, 0xffff),
    (0x0689, 0xffff),
    (0xd400, 0xff00),
    (0x7829, 0xffff),
    (0x0909, 0xffff),
    (0x2905, 0xffff),
    (0xd100, 0xff00),
    (0x4b00, 0xff00),
    (0x6819, 0xffff),
    (0x2201, 0xffff),
    (0x0312, 0xffff),
    (0x4391, 0xffff),
    (0x6019, 0xffff),
    (0x73b0, 0xffff),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0xe003, 0xffff),
    (0x7af0, 0xffff),
    (0x73b0, 0xfff8),
    (0xf000, 0xf800),
    (0xd000, 0xd000),
    (0x7030, 0xffff),
    (0x7830, 0xffff),
    (0x2800, 0xffff),
    (0xd100, 0xff00),
];
fn literal(image: &[u8], at: usize) -> Option<u32> {
    let op = half(image, at)?;
    if op & 0xf800 != 0x4800 {
        return None;
    }
    let at = ((at + 4) & !3) + usize::from(op & 255) * 4;
    Some(u32::from_le_bytes(image.get(at..at + 4)?.try_into().ok()?))
}
fn locate(image: &[u8], pattern: &[(u16, u16)], state: u32) -> Result<usize, Error> {
    let mut found = None;
    for at in (0..image.len().saturating_sub(pattern.len() * 2)).step_by(2) {
        if matches(image, at, pattern) {
            if literal(image, at) != Some(state) {
                return Err(Error::InvalidContract);
            }
            if found.replace(at).is_some() {
                return Err(Error::Ambiguous);
            }
        }
    }
    found.ok_or(Error::UnknownLayout)
}
impl ClassicReadCompletion {
    /// Match the complete native store/calculation bodies, both branch edges,
    /// shared media cell and balanced saved frames. No hardware values change.
    pub fn inspect(image: &[u8], state: u32) -> Result<Self, Error> {
        let controller_region = locate(image, CONTROLLER, state)?;
        let mut recovery = None;
        for (pattern, state_register, request_register) in
            [(RECOVERY, 4u8, 5u8), (RECOVERY_R5, 5u8, 6u8)]
        {
            for at in (0..image.len().saturating_sub(pattern.len() * 2)).step_by(2) {
                if !matches(image, at, pattern) {
                    continue;
                }
                let parent = SavedLink::detect(image, at)?;
                let producers: Vec<_> = (parent.entry..at)
                    .step_by(2)
                    .filter_map(|site| {
                        let Some(op) = half(image, site) else {
                            return None;
                        };
                        if op & 0xff00 != 0x4800 | u16::from(state_register) << 8 {
                            return None;
                        }
                        let Some(mut value) = literal(image, site) else {
                            return None;
                        };
                        let Some(next) = half(image, site + 2) else {
                            return None;
                        };
                        let mut end = site + 2;
                        if next & 0xff00 == 0x3000 | u16::from(state_register) << 8 {
                            let Some(v) = value.checked_add(u32::from(next & 255)) else {
                                return None;
                            };
                            value = v;
                            end = site + 4;
                        } else if next & 0xff00 == 0x3800 | u16::from(state_register) << 8 {
                            let Some(v) = value.checked_sub(u32::from(next & 255)) else {
                                return None;
                            };
                            value = v;
                            end = site + 4;
                        }
                        if next & 0xfe00 == 0x1e00
                            && (next & 7) as u8 == state_register
                            && ((next >> 3) & 7) as u8 == state_register
                        {
                            let Some(v) = value.checked_sub(u32::from((next >> 6) & 7)) else {
                                return None;
                            };
                            value = v;
                            end = site + 4;
                        }
                        (value == state).then_some((site, end))
                    })
                    .collect();
                if producers.len() != 1 {
                    return Err(Error::InvalidContract);
                }
                parent.require_register_definition(
                    image,
                    producers[0].0,
                    producers[0].1,
                    state_register,
                )?;
                if conditional(image, at + 14, 0xd100) != Some(at + 50) {
                    return Err(Error::InvalidContract);
                }
                let join =
                    thumb_asm::isa::decode_at(image, at + 48).ok_or(Error::InvalidContract)?;
                if join.mnemonic != "b"
                    || join.cond.is_some()
                    || join.branch_target().map(|p| p as usize) != Some(at + 58)
                    || thumb_asm::decode_bl(image, at + 54).is_none()
                {
                    return Err(Error::InvalidContract);
                }
                if recovery
                    .replace((
                        at,
                        at + pattern.len() * 2,
                        producers[0].0,
                        state_register,
                        request_register,
                        parent,
                    ))
                    .is_some()
                {
                    return Err(Error::Ambiguous);
                }
            }
        }
        let (
            recovery_region,
            recovery_end,
            recovery_state_load,
            recovery_state_register,
            recovery_request_register,
            recovery_caller,
        ) = recovery.ok_or(Error::UnknownLayout)?;
        let recovery_flag_register =
            (half(image, recovery_region + 52).ok_or(Error::Truncated)? & 7) as u8;
        if recovery_flag_register < 4
            || recovery_flag_register == recovery_state_register
            || recovery_flag_register == recovery_request_register
        {
            return Err(Error::InvalidContract);
        }
        let (boundary_region, boundary_length) = match locate(image, BOUNDARY, state) {
            Ok(at) => (at, BOUNDARY.len() * 2),
            Err(Error::UnknownLayout) => (
                locate(image, BOUNDARY_VENEER, state)?,
                BOUNDARY_VENEER.len() * 2,
            ),
            Err(e) => return Err(e),
        };
        let shift = if boundary_length == BOUNDARY.len() * 2 {
            0
        } else {
            2
        };
        let boundaries = [
            literal(image, boundary_region + 10),
            literal(image, boundary_region + 54 + shift),
            literal(image, boundary_region + 104 + shift),
        ]
        .map(|v| v.ok_or(Error::InvalidContract));
        let boundaries = [boundaries[0]?, boundaries[1]?, boundaries[2]?];
        if boundaries
            .iter()
            .any(|p| !(0x01ff0000..0x02010000).contains(p))
            || boundaries[0] == boundaries[1]
            || boundaries[0] == boundaries[2]
            || boundaries[1] == boundaries[2]
        {
            return Err(Error::InvalidContract);
        }
        let boundary_reject =
            conditional(image, boundary_region + 8, 0xd100).ok_or(Error::InvalidContract)?;
        let specs = [
            (
                controller_region + 0x12,
                controller_region + 0x18,
                controller_region + 0x2c,
                6,
            ),
            (
                controller_region + 0x5c,
                controller_region + 0x62,
                controller_region + 0x66,
                6,
            ),
            (
                boundary_region + 6,
                boundary_region + 10,
                boundary_reject,
                4,
            ),
        ];
        let mut selections = Vec::new();
        let mut callers = Vec::new();
        for (site, accept, reject, span) in specs {
            if conditional(image, site + span - 2, 0xd100) != Some(reject) {
                return Err(Error::InvalidContract);
            }
            selections.push(C7Selection {
                site,
                accept,
                reject,
                span,
                replay: (site..site + span - 2)
                    .step_by(2)
                    .map(|at| half(image, at).unwrap())
                    .collect(),
            });
            callers.push(SavedLink::detect(image, site)?);
        }
        // The boundary rejection skips the reflected-position block; its guard
        // may be a branch veneer but must remain inside the matched parent.
        if half(image, boundary_reject).map(|op| op & 0xf800) != Some(0xe000) {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            controller_region,
            recovery_region,
            recovery_end,
            recovery_state_load,
            recovery_state_register,
            recovery_request_register,
            recovery_flag_register,
            recovery_caller,
            boundary_region,
            boundary_end: boundary_region + boundary_length,
            boundaries,
            selections: selections.try_into().unwrap(),
            callers: callers.try_into().unwrap(),
        })
    }
}

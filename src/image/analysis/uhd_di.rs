//! Classic DI parser entry/continuation contracts, selected from instructions.
use super::{conditional, half, matches, Error, UhdArea, UhdAreas};
use thumb_asm::isa::decode_at;

/// Source-bound classic DI parser landmarks. No code is changed here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassicDi {
    /// Native function entry saving r4-r7 and LR.
    pub entry: usize,
    /// Native balanced add-SP/pop-PC return sequence.
    pub epilogue: usize,
    /// First of MOV r3,SP; LDRB attributes; LSLS; LSRS (eight bytes).
    pub prevalidation: usize,
    /// First branch after the replayed eight bytes.
    pub replay_continuation: usize,
    /// Common format handling reached by the native O recognizer.
    pub format: usize,
    /// Native format classification byte written by the format-five case.
    pub format_flag: u32,
    /// Register initialized to one on the shared native identifier path.
    pub one_register: u8,
    /// Generic native layer-normalization entry; unchanged by conversion.
    pub layers: usize,
    /// Native layer state store, shared by recognized layer counts.
    pub layer_store: usize,
    /// Common state byte independently bound by the other routing roles.
    pub state: u32,
}
fn target(image: &[u8], at: usize) -> Result<usize, Error> {
    let ins = decode_at(image, at).ok_or(Error::Truncated)?;
    if !ins.is_branch() {
        return Err(Error::InvalidContract);
    }
    let value = ins.branch_target().ok_or(Error::InvalidContract)? as usize;
    (value + 2 <= image.len())
        .then_some(value)
        .ok_or(Error::Truncated)
}
fn exactly_one(mut items: impl Iterator<Item = usize>) -> Result<usize, Error> {
    let first = items.next().ok_or(Error::UnknownLayout)?;
    if items.next().is_some() {
        Err(Error::Ambiguous)
    } else {
        Ok(first)
    }
}
impl ClassicDi {
    /// Require a legacy O recognizer, its BD-prefix predecessor, common format
    /// edge, layer grammar, state-pointer load, and matching native stack frame.
    pub fn detect(image: &[u8]) -> Result<Self, Error> {
        let areas = UhdAreas::inspect(image);
        let di = areas.area(UhdArea::DiscInformation)?;
        if di.selects_c7() != Some(false) {
            return Err(Error::UnknownLayout);
        }
        let state = areas.state_address()?;
        let prefix_pattern = [
            (0x466b, 0xffff),
            (0x7b18, 0xffff),
            (0x2500, 0xffff),
            (0x2842, 0xffff),
            (0xd100, 0xff00),
            (0x7b58, 0xffff),
            (0x2844, 0xffff),
            (0xd000, 0xff00),
        ];
        let prefix = exactly_one(
            (di.site().saturating_sub(0x400)..di.site())
                .step_by(2)
                .filter(|&at| matches(image, at, &prefix_pattern)),
        )?;
        let prevalidation = target(image, prefix + 14)?;
        let validation = [
            (0x466b, 0xffff),
            (0x7c58, 0xffff),
            (0x0680, 0xffff),
            (0x0f81, 0xffff),
            (0xd000, 0xff00),
            (0x0f80, 0xffff),
            (0x2801, 0xffff),
            (0xd000, 0xff00),
        ];
        if !matches(image, prevalidation, &validation) {
            return Err(Error::InvalidContract);
        }
        let identifier =
            conditional(image, prevalidation + 8, 0xd000).ok_or(Error::InvalidContract)?;
        if conditional(image, prevalidation + 14, 0xd000) != Some(identifier)
            || half(image, identifier) != Some(0x466b)
        {
            return Err(Error::InvalidContract);
        }
        let one_register = match (half(image, identifier + 2), half(image, identifier + 4)) {
            (Some(0x7c18), Some(0x2101)) => 1,
            (Some(0x7c19), Some(0x2001)) => 0,
            _ => return Err(Error::InvalidContract),
        };
        let format = target(image, di.site() + 26)?;
        if format <= di.site()
            || format > di.site() + 0x100
            || !matches(
                image,
                format,
                &[(0x466b, 0xffff), (0x7cdb, 0xffff), (0x4800, 0xf800)],
            )
        {
            return Err(Error::InvalidContract);
        }
        let format_load = half(image, format + 4).ok_or(Error::Truncated)?;
        if ((format_load >> 8) & 7) as u8 != 1 - one_register {
            return Err(Error::InvalidContract);
        }
        let pool = ((format + 8) & !3) + (format_load & 255) as usize * 4;
        let format_flag = u32::from_le_bytes(
            image
                .get(pool..pool + 4)
                .ok_or(Error::Truncated)?
                .try_into()
                .map_err(|_| Error::Truncated)?,
        );
        if !(0x01ff0000..0x02010000).contains(&format_flag) {
            return Err(Error::InvalidContract);
        }
        let targets = super::switch::targets(image, format + 6)?.ok_or(Error::InvalidContract)?;
        if targets.len() != 7 {
            return Err(Error::InvalidContract);
        }
        let five = targets[5];
        if !matches(
            image,
            five,
            &[
                (0x2220, 0xffff),
                (if one_register == 1 { 0x7002 } else { 0x700a }, 0xffff),
            ],
        ) {
            return Err(Error::InvalidContract);
        }
        let mut layer_pattern = [
            (0x466b, 0xffff),
            (0x7c98, 0xffff),
            (0x22f3, 0xffff),
            (0x0900, 0xffff),
            (0x2801, 0xffff),
            (0xd100, 0xff00),
            (0x7820, 0xffff),
            (0x4010, 0xffff),
            (0xe000, 0xf800),
            (0x2802, 0xffff),
            (0xd100, 0xff00),
            (0x7820, 0xffff),
            (0x4010, 0xffff),
            (0x1d00, 0xffff),
            (0xe000, 0xf800),
            (0x2803, 0xffff),
            (0xd100, 0xff00),
            (0x7820, 0xffff),
            (0x4010, 0xffff),
            (0x3008, 0xffff),
            (0xe000, 0xf800),
            (0x2804, 0xffff),
            (0xd100, 0xff00),
            (0x7820, 0xffff),
            (0x220c, 0xffff),
            (0x4310, 0xffff),
            (0x7020, 0xffff),
        ];
        if one_register == 0 {
            for (op, _) in &mut layer_pattern {
                *op = match *op {
                    0x7c98 => 0x7c99,
                    0x0900 => 0x0909,
                    0x2801 => 0x2901,
                    0x2802 => 0x2902,
                    0x2803 => 0x2903,
                    0x2804 => 0x2904,
                    0x7820 => 0x7821,
                    0x4010 => 0x4011,
                    0x1d00 => 0x1d09,
                    0x3008 => 0x3108,
                    0x4310 => 0x4311,
                    0x7020 => 0x7021,
                    value => value,
                };
            }
        }
        let layers = exactly_one(
            (format..format + 0x80)
                .step_by(2)
                .filter(|&at| matches(image, at, &layer_pattern)),
        )?;
        let layer_store = layers + 52;
        if five + 4 != layers || identifier <= prevalidation + 14 || identifier >= di.site() {
            return Err(Error::InvalidContract);
        }
        for (branch, destination) in [(10, 18), (20, 30), (32, 42), (44, 54)] {
            if conditional(image, layers + branch, 0xd100) != Some(layers + destination) {
                return Err(Error::InvalidContract);
            }
        }
        for branch in [16, 28, 40] {
            if target(image, layers + branch)? != layer_store {
                return Err(Error::InvalidContract);
            }
        }
        let entry = (prefix.saturating_sub(0x800)..prefix)
            .step_by(2)
            .rev()
            .find(|&at| {
                matches(
                    image,
                    at,
                    &[
                        (0xb5f0, 0xffff),
                        (0x4e00, 0xff00),
                        (0x4d00, 0xff00),
                        (0x7834, 0xffff),
                        (0xb085, 0xffff),
                    ],
                )
            })
            .ok_or(Error::UnknownLayout)?;
        let epilogue = exactly_one(
            (entry..entry + 0x100)
                .step_by(2)
                .filter(|&at| matches(image, at, &[(0xb005, 0xffff), (0xbdf0, 0xffff)])),
        )?;
        let state_load = exactly_one((entry..epilogue).step_by(2).filter(|&at| {
            let Some(op) = half(image, at) else {
                return false;
            };
            if op & 0xff00 != 0x4c00 {
                return false;
            }
            let pool = ((at + 4) & !3) + (op & 255) as usize * 4;
            image
                .get(pool..pool + 4)
                .is_some_and(|v| v == state.to_le_bytes())
        }))?;
        if state_load >= prefix || epilogue >= prefix {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            entry,
            epilogue,
            prevalidation,
            replay_continuation: prevalidation + 8,
            format,
            format_flag,
            one_register,
            layers,
            layer_store,
            state,
        })
    }
}

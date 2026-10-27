//! Read-only native media-speed defaults and requested-rate clamp evidence.
use super::{half, Error, UhdArea};

/// An instruction-bound maximum-speed clamp on an incoming requested rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedRateClamp {
    /// Native function entry, including its saved frame.
    pub entry: usize,
    /// CMP of the requested rate and the bound maximum byte.
    pub compare: usize,
    /// First instruction after either native clamp route.
    pub after_clamp: usize,
    /// Register containing min(requested, maximum) at that continuation.
    pub request_register: u8,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    Unknown,
    Request,
    Maximum,
    Address(u32),
}
fn literal(image: &[u8], at: usize) -> Option<u32> {
    let op = half(image, at)?;
    if op & 0xf800 != 0x4800 {
        return None;
    }
    let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
    Some(u32::from_le_bytes(
        image.get(pool..pool + 4)?.try_into().ok()?,
    ))
}
fn byte_address(op: u16, values: &[Value; 8]) -> Option<u32> {
    if op & 0xf800 != 0x7800 {
        return None;
    }
    let Value::Address(base) = values[usize::from((op >> 3) & 7)] else {
        return None;
    };
    base.checked_add(u32::from((op >> 6) & 31))
}
fn clamp(image: &[u8], entry: usize, maximum: u32) -> Option<RequestedRateClamp> {
    if half(image, entry)? != 0xb5f8 {
        return None;
    }
    let mut values = [Value::Unknown; 8];
    values[0] = Value::Request;
    for at in (entry + 2..entry + 32).step_by(2) {
        let op = half(image, at)?;
        if op & 0xffc0 == 0x4280 {
            let request = (op & 7) as usize;
            let limit = ((op >> 3) & 7) as usize;
            let load = half(image, at + 4)?;
            return (values[request] == Value::Request
                && values[limit] == Value::Maximum
                && half(image, at + 2) == Some(0xd900)
                && byte_address(load, &values) == Some(maximum)
                && usize::from(load & 7) == request)
                .then_some(RequestedRateClamp {
                    entry,
                    compare: at,
                    after_clamp: at + 6,
                    request_register: request as u8,
                });
        }
        if op & 0xffc0 == 0 {
            values[usize::from(op & 7)] = values[usize::from((op >> 3) & 7)];
        } else if op & 0xf800 == 0x4800 {
            values[usize::from((op >> 8) & 7)] = Value::Address(literal(image, at)?);
        } else if op & 0xf800 == 0x7800 {
            values[usize::from(op & 7)] = if byte_address(op, &values) == Some(maximum) {
                Value::Maximum
            } else {
                Value::Unknown
            };
        } else if op & 0xf800 == 0x3000 || op & 0xf800 == 0x3800 {
            let register = usize::from((op >> 8) & 7);
            let Value::Address(base) = values[register] else {
                return None;
            };
            values[register] = Value::Address(if op & 0xf800 == 0x3000 {
                base.checked_add(u32::from(op & 255))?
            } else {
                base.checked_sub(u32::from(op & 255))?
            });
        } else if op & 0xfe00 == 0x1c00 || op & 0xfe00 == 0x1e00 {
            let source = usize::from((op >> 3) & 7);
            let destination = usize::from(op & 7);
            let amount = u32::from((op >> 6) & 7);
            let Value::Address(base) = values[source] else {
                return None;
            };
            values[destination] = Value::Address(if op & 0xfe00 == 0x1c00 {
                base.checked_add(amount)?
            } else {
                base.checked_sub(amount)?
            });
        } else {
            return None;
        }
    }
    None
}
impl RequestedRateClamp {
    /// Bind a unique incoming-rate/maximum-byte comparison and both native
    /// continuations through register/address data flow, without model dispatch.
    pub fn detect(image: &[u8], maximum: u32) -> Result<Self, Error> {
        let mut found = None;
        for entry in (0..image.len().saturating_sub(32)).step_by(2) {
            if let Some(contract) = clamp(image, entry, maximum) {
                if found.replace(contract).is_some() {
                    return Err(Error::Ambiguous);
                }
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
}
/// Native media-default stores and the independently bound request clamp.
/// This is evidence only: no speed setting or firmware byte is changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSpeedPolicy {
    /// Positively matched native default-writer grammar.
    pub variant: &'static str,
    /// Default-writer entry.
    pub entry: usize,
    /// Matched instruction prefix length.
    pub length: usize,
    /// Shared media-class byte.
    pub media_cell: u32,
    /// Maximum rate byte, written by defaults and read by the clamp.
    pub maximum_cell: u32,
    /// Native optimum/current-request byte written alongside the maximum.
    pub optimum_cell: u32,
    /// Native hardware-policy byte selecting the pre-existing lower-limit path.
    pub hardware_cell: u32,
    /// Requested-rate clamp sharing the maximum cell.
    pub clamp: RequestedRateClamp,
}
impl NativeSpeedPolicy {
    /// Bind native role operands from the existing default-writer grammar and
    /// require a unique real maximum-byte clamp. Rates are executed, not guessed.
    pub fn detect(image: &[u8]) -> Result<Self, Error> {
        let defaults = super::uhd::inspect_role(image, UhdArea::HardwareDefaults)?;
        let media_cell = defaults
            .literals()
            .first()
            .ok_or(Error::InvalidContract)?
            .value;
        let maximum_cell = media_cell.checked_add(2).ok_or(Error::InvalidContract)?;
        let (pair, hardware) = match defaults.variant() {
            "classic" | "classic_default8" => ([12, 14], 24),
            "modern" => ([10, 18], 14),
            "modern_reader_register_variant" => ([12, 16], 22),
            "slim_fixed6_c7_aware" | "slim_fixed6_no_c7_test" => ([12, 14], 22),
            "slim_early_fixed6" => ([10, 14], 22),
            "desktop_default8_c7_aware" => ([16, 18], 24),
            _ => return Err(Error::UnknownLayout),
        };
        let entry = defaults.site();
        let a = literal(image, entry + pair[0]).ok_or(Error::InvalidContract)?;
        let b = literal(image, entry + pair[1]).ok_or(Error::InvalidContract)?;
        let optimum_cell = if a == maximum_cell && b != maximum_cell {
            b
        } else if b == maximum_cell && a != maximum_cell {
            a
        } else {
            return Err(Error::InvalidContract);
        };
        let hardware_cell = literal(image, entry + hardware).ok_or(Error::InvalidContract)?;
        let cells = [media_cell, maximum_cell, optimum_cell, hardware_cell];
        if cells.iter().any(|c| !(0x01ff0000..0x02010000).contains(c))
            || (0..cells.len()).any(|i| cells[i + 1..].contains(&cells[i]))
        {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            variant: defaults.variant(),
            entry,
            length: defaults.length(),
            media_cell,
            maximum_cell,
            optimum_cell,
            hardware_cell,
            clamp: RequestedRateClamp::detect(image, maximum_cell)?,
        })
    }
}

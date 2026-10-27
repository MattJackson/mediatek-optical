//! Symbolic native DMA addresses and the guarded exclusion-range clamp.
use super::Error;
use std::collections::BTreeSet;
use thumb_asm::Cond;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Expr {
    pub source: i32,
    pub offset: i32,
    pub length: i32,
    pub bias: i64,
}
impl Expr {
    pub const SOURCE: Self = Self {
        source: 1,
        offset: 0,
        length: 0,
        bias: 0,
    };
    pub const OFFSET: Self = Self {
        source: 0,
        offset: 1,
        length: 0,
        bias: 0,
    };
    pub const LENGTH: Self = Self {
        source: 0,
        offset: 0,
        length: 1,
        bias: 0,
    };
    pub const ADDRESS: Self = Self {
        source: 1,
        offset: 1,
        length: 0,
        bias: 0,
    };
    pub const END: Self = Self {
        source: 1,
        offset: 1,
        length: 1,
        bias: 0,
    };
    pub fn constant(value: u32) -> Self {
        Self {
            source: 0,
            offset: 0,
            length: 0,
            bias: i64::from(value),
        }
    }
    pub fn combine(self, other: Self, subtract: bool) -> Result<Self, Error> {
        let sign = if subtract { -1 } else { 1 };
        Ok(Self {
            source: self
                .source
                .checked_add(
                    other
                        .source
                        .checked_mul(sign)
                        .ok_or(Error::InvalidContract)?,
                )
                .ok_or(Error::InvalidContract)?,
            offset: self
                .offset
                .checked_add(
                    other
                        .offset
                        .checked_mul(sign)
                        .ok_or(Error::InvalidContract)?,
                )
                .ok_or(Error::InvalidContract)?,
            length: self
                .length
                .checked_add(
                    other
                        .length
                        .checked_mul(sign)
                        .ok_or(Error::InvalidContract)?,
                )
                .ok_or(Error::InvalidContract)?,
            bias: self
                .bias
                .checked_add(
                    other
                        .bias
                        .checked_mul(i64::from(sign))
                        .ok_or(Error::InvalidContract)?,
                )
                .ok_or(Error::InvalidContract)?,
        })
    }
    pub fn as_constant(self) -> Option<u32> {
        (self.source == 0 && self.offset == 0 && self.length == 0)
            .then(|| u32::try_from(self.bias).ok())
            .flatten()
    }
}

pub(super) type Guards = BTreeSet<(Expr, Cond, Expr)>;

/// The OEM may shorten a response before a reserved range, or skip its source
/// to the range's end. Every required comparison must guard that exact action.
pub(super) fn clamp_allows(guards: &Guards, value: Expr, pointer: bool) -> bool {
    guards.iter().any(|&(left, cond, start)| {
        if left != Expr::END
            || cond != Cond::Hi
            || start.source != 1
            || start.offset != 0
            || start.length != 0
            || start.bias <= 0
        {
            return false;
        }
        guards.iter().any(|&(address, limit, end)| {
            if address != Expr::ADDRESS
                || limit != Cond::Lo
                || end.source != 1
                || end.offset != 0
                || end.length != 0
                || end.bias <= start.bias
                || end.bias >= 0x01000000
            {
                return false;
            }
            if pointer {
                value == end && guards.contains(&(Expr::ADDRESS, Cond::Hs, start))
            } else {
                value
                    == Expr {
                        source: 0,
                        offset: -1,
                        length: 0,
                        bias: start.bias,
                    }
                    && guards.contains(&(Expr::ADDRESS, Cond::Lo, start))
            }
        })
    })
}

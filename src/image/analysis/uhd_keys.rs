//! Source-bound native key routing and extended response contracts.
//! These prove code relationships, never successful authentication or credentials.
use super::{conditional, half, matches, CommandDispatch, Error, SavedLink};
use thumb_asm::{isa::decode_at, Cond};

/// One registered key wrapper and its native AACS continuation.
#[derive(Debug, Clone)]
pub struct UhdKeyWrapper {
    /// Native command handler.
    pub entry: usize,
    /// Native AACS worker.
    pub worker: usize,
    /// Class selection sites lacking class-3 handling. Empty for native routing.
    pub legacy_selectors: Vec<usize>,
}
/// Native REPORT/SEND KEY relationships, independently derived from registration.
#[derive(Debug, Clone)]
pub struct UhdKeyPath {
    /// Incoming command packet address shared by the scanner and both wrappers.
    pub cdb: u32,
    /// REPORT KEY wrapper.
    pub report: UhdKeyWrapper,
    /// SEND KEY wrapper.
    pub send: UhdKeyWrapper,
    /// Native extended-mode byte; absent for the positively matched older worker.
    pub mode: Option<u32>,
    /// Certificate-response worker with native mode-dependent allocation.
    pub certificate: Option<usize>,
}
fn literal(d: &[u8], at: usize, r: u16) -> Result<u32, Error> {
    let op = half(d, at).ok_or(Error::Truncated)?;
    if op & 0xff00 != 0x4800 | (r << 8) {
        return Err(Error::InvalidContract);
    }
    let pool = ((at + 4) & !3) + usize::from(op & 255) * 4;
    Ok(u32::from_le_bytes(
        d.get(pool..pool + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    ))
}
fn call(d: &[u8], at: usize) -> Result<usize, Error> {
    let ins = decode_at(d, at).ok_or(Error::Truncated)?;
    if ins.mnemonic != "bl" {
        return Err(Error::InvalidContract);
    }
    let target = ins.branch_target().ok_or(Error::InvalidContract)? as usize;
    if target + 2 > d.len() {
        return Err(Error::Truncated);
    }
    Ok(target)
}
fn wrapper(d: &[u8], entry: usize, cdb: u32, report: bool) -> Result<UhdKeyWrapper, Error> {
    if half(d, entry) != Some(0xb510)
        || literal(d, entry + 2, 4)? != cdb
        || !matches(
            d,
            entry + 4,
            &[
                (0x79e0, 0xffff),
                (0x2800, 0xffff),
                (0xd100, 0xff00),
                (0x7aa0, 0xffff),
                (0x0680, 0xffff),
                (0x0e80, 0xffff),
                (if report { 0x2808 } else { 0x2806 }, 0xffff),
                (0xd100, 0xff00),
            ],
        )
    {
        return Err(Error::UnknownLayout);
    }
    call(d, entry + 20)?;
    if half(d, entry + 24) != Some(0xbd10) {
        return Err(Error::InvalidContract);
    }
    let mut at = entry + 26;
    if conditional(d, entry + 8, Cond::Ne) != Some(at)
        || conditional(d, entry + 18, Cond::Ne) != Some(at)
    {
        return Err(Error::InvalidContract);
    }
    let mut selectors = Vec::new();
    let mut report_worker = None;
    if report {
        if !matches(d, at, &[(0x79e0, 0xffff), (0x2802, 0xffff)]) {
            return Err(Error::InvalidContract);
        }
        let format = if half(d, at + 4).is_some_and(|h| h & 0xff00 == 0xd000) {
            if !matches(
                d,
                at + 6,
                &[(0x79e0, 0xffff), (0x2803, 0xffff), (0xd100, 0xff00)],
            ) || conditional(d, at + 4, Cond::Eq) != Some(at + 12)
            {
                return Err(Error::InvalidContract);
            }
            at + 12
        } else {
            selectors.push(at + 2);
            if !half(d, at + 4).is_some_and(|h| h & 0xff00 == 0xd100) {
                return Err(Error::InvalidContract);
            }
            at + 6
        };
        if !matches(
            d,
            format,
            &[
                (0x7aa0, 0xffff),
                (0x0680, 0xffff),
                (0x0e80, 0xffff),
                (0x2838, 0xffff),
                (0xd100, 0xff00),
            ],
        ) || half(d, format + 14) != Some(0xbd10)
        {
            return Err(Error::InvalidContract);
        }
        let next = format + 16;
        let reject = if selectors.is_empty() {
            at + 10
        } else {
            at + 4
        };
        if conditional(d, reject, Cond::Ne) != Some(next)
            || conditional(d, format + 8, Cond::Ne) != Some(next)
        {
            return Err(Error::InvalidContract);
        }
        report_worker = Some(call(d, format + 10)?);
        at = next;
    }
    if half(d, at) != Some(0x2001)
        || half(d, at + 6) != Some(0x2800)
        || conditional(d, at + 8, Cond::Eq) != Some(at - 2)
    {
        return Err(Error::InvalidContract);
    }
    call(d, at + 2)?;
    at += 10;
    if !matches(d, at, &[(0x79e0, 0xffff), (0x2802, 0xffff)]) {
        return Err(Error::InvalidContract);
    }
    if half(d, at + 4).is_some_and(|h| h & 0xff00 == 0xd000) {
        if !matches(d, at + 6, &[(0x2803, 0xffff), (0xd100, 0xff00)])
            || conditional(d, at + 4, Cond::Eq) != Some(at + 10)
            || conditional(d, at + 8, Cond::Ne) != Some(entry + 20)
        {
            return Err(Error::InvalidContract);
        }
        at += 10;
    } else {
        if conditional(d, at + 4, Cond::Ne) != Some(entry + 20) {
            return Err(Error::InvalidContract);
        }
        selectors.push(at + 2);
        at += 6;
    }
    // Bind the native status checks before accepting their AACS continuation.
    if literal(d, at, 0).is_err()
        || !matches(
            d,
            at + 2,
            &[(0x7800, 0xffff), (0x09c0, 0xffff), (0xd100, 0xff00)],
        )
    {
        return Err(Error::InvalidContract);
    }
    let target = conditional(d, at + 6, Cond::Ne).ok_or(Error::InvalidContract)?;
    let worker = call(d, target)?;
    if half(d, target + 4) != Some(0xbd10) || report_worker.is_some_and(|w| w != worker) {
        return Err(Error::InvalidContract);
    }
    for &site in &selectors {
        SavedLink::bind(d, entry, site)?;
    }
    Ok(UhdKeyWrapper {
        entry,
        worker,
        legacy_selectors: selectors,
    })
}
impl UhdKeyPath {
    /// Positively bind both wrappers and the worker dispatcher/allocation grammar.
    pub fn inspect(d: &[u8]) -> Result<Self, Error> {
        let dispatch = CommandDispatch::inspect(d)?;
        let cdb = dispatch.scanner().cdb();
        let get = |op| -> Result<usize, Error> {
            let entries: Vec<_> = dispatch
                .records()
                .iter()
                .filter(|r| r.opcode == op && r.flags == 7 && r.handler & 1 != 0)
                .collect();
            if entries.len() != 1 {
                return Err(Error::Ambiguous);
            }
            Ok((entries[0].handler & !1) as usize)
        };
        let report = wrapper(d, get(0xa4)?, cdb, true)?;
        let send = wrapper(d, get(0xa3)?, cdb, false)?;
        let entry = report.worker;
        if !matches(
            d,
            entry + 2,
            &[(0x2000, 0xffff), (0xb510, 0xffff), (0x8008, 0xffff)],
        ) {
            return Err(Error::UnknownLayout);
        }
        let length = literal(d, entry, 1)?;
        let mut io = entry + 8;
        if matches(d, io, &[(0x2101, 0xffff), (0x2003, 0xffff)]) {
            call(d, io + 4)?;
            io += 8;
        }
        if !matches(
            d,
            io,
            &[
                (0x2201, 0xffff),
                (0x0692, 0xffff),
                (0x6810, 0xffff),
                (0x2110, 0xffff),
                (0x4388, 0xffff),
                (0x6010, 0xffff),
            ],
        ) {
            return Err(Error::UnknownLayout);
        }
        let (mode, certificate) = if half(d, io + 12).is_some_and(|h| h & 0xff00 == 0x4900) {
            let mode = literal(d, io + 12, 1)?;
            if !(0x01ff0000..0x02010000).contains(&mode)
                || literal(d, io + 16, 2)? != cdb
                || ![
                    (14, 0x7808),
                    (18, 0x2801),
                    (22, 0x79d0),
                    (24, 0x2803),
                    (28, 0x7808),
                    (30, 0x2800),
                    (34, 0x79d0),
                    (36, 0x2802),
                ]
                .iter()
                .all(|&(k, v)| half(d, io + k) == Some(v))
            {
                return Err(Error::InvalidContract);
            }
            let mut certs = Vec::new();
            for at in (io + 38..io + 180).step_by(2) {
                if half(d, at) != Some(0x2801) {
                    continue;
                }
                let Some(dest) = conditional(d, at + 2, Cond::Eq) else {
                    continue;
                };
                let Ok(worker) = call(d, dest) else {
                    continue;
                };
                if half(d, dest + 4) != Some(0xbd10) {
                    continue;
                }
                for p in (worker..worker + 256).step_by(2) {
                    if literal(d, p, 7) == Ok(mode)
                        && literal(d, p + 8, 0) == Ok(length)
                        && [
                            (2, 0x7839),
                            (4, 0x2901),
                            (6, 0x7a21),
                            (12, 0x7a62),
                            (14, 0x0209),
                            (16, 0x1889),
                            (18, 0x29b4),
                        ]
                        .iter()
                        .all(|&(k, v)| half(d, p + k) == Some(v))
                        && half(d, p + 10).is_some_and(|h| h & 0xff00 == 0xd100)
                        && literal(d, worker + 2, 4) == Ok(cdb)
                    {
                        certs.push(worker);
                    }
                }
            }
            if certs.len() != 1 {
                return Err(Error::InvalidContract);
            }
            (Some(mode), Some(certs[0]))
        } else {
            if literal(d, io + 12, 0)? != cdb {
                return Err(Error::InvalidContract);
            }
            (None, None)
        };
        Ok(Self {
            cdb,
            report,
            send,
            mode,
            certificate,
        })
    }
}

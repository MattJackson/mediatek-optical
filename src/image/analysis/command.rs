//! Command records reached through the native registered table graph.
use super::{CommandScanner, Error};
use std::collections::BTreeSet;
use thumb_asm::CommandRecord;

/// Immutable native dispatch ownership, independently bound to one source.
pub struct CommandDispatch<'a> {
    image: &'a [u8],
    scanner: CommandScanner,
    roots: BTreeSet<usize>,
    records: Vec<CommandRecord>,
}
impl<'a> CommandDispatch<'a> {
    /// Follow only roots supplied by the native registrar to the scanner's array.
    /// Orphan coherent tables do not become candidates.
    pub fn inspect(image: &'a [u8]) -> Result<Self, Error> {
        let scanner = CommandScanner::inspect(image)?;
        let roots = scanner.table_roots(image)?;
        let mut records = Vec::new();
        let mut retained = BTreeSet::new();
        for root in &roots {
            let mut visited = BTreeSet::new();
            let mut at = *root;
            loop {
                if at & 3 != 0 || !visited.insert(at) || visited.len() > 1024 {
                    return Err(Error::InvalidContract);
                }
                let bytes = image
                    .get(at..at.checked_add(8).ok_or(Error::Truncated)?)
                    .ok_or(Error::Truncated)?;
                if bytes[2..4] != [0, 0] || !matches!(bytes[1], 0..=9 | 0x80 | 0x87) {
                    return Err(Error::InvalidContract);
                }
                let handler =
                    u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::Truncated)?);
                if retained.insert(at) {
                    records.push(CommandRecord {
                        off: at,
                        opcode: bytes[0],
                        flags: bytes[1],
                        handler,
                    });
                }
                match bytes[1] {
                    3 => break,
                    4 => {
                        at = handler as usize;
                    }
                    _ => {
                        at = at.checked_add(8).ok_or(Error::Truncated)?;
                    }
                }
            }
        }
        records.sort_by_key(|record| record.off);
        Ok(Self {
            image,
            scanner,
            roots,
            records,
        })
    }
    /// Original plaintext bytes; lookups do not accept replacement input.
    pub fn image(&self) -> &'a [u8] {
        self.image
    }
    /// Validated native record consumer.
    pub fn scanner(&self) -> &CommandScanner {
        &self.scanner
    }
    /// Proven flash roots used by native initialization.
    pub fn roots(&self) -> &BTreeSet<usize> {
        &self.roots
    }
    /// All reached records, including linked and terminal records.
    pub fn records(&self) -> &[CommandRecord] {
        &self.records
    }
    /// Require one reached record with the requested opcode and native flags.
    pub fn record(&self, opcode: u8, flags: u8) -> Result<&CommandRecord, Error> {
        let mut matches = self
            .records
            .iter()
            .filter(|record| record.opcode == opcode && record.flags == flags);
        let first = matches.next().ok_or(Error::UnknownLayout)?;
        if matches.next().is_some() {
            return Err(Error::Ambiguous);
        }
        if first.handler & 1 == 0 || first.handler as usize >= self.image.len() {
            return Err(Error::InvalidContract);
        }
        Ok(first)
    }
}

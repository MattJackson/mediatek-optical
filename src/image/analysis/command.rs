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
    /// Records reached from the initial (`BL`-registered) roots.
    initial: BTreeSet<usize>,
    /// Records reached from each tail-call (media mode) root.
    modes: Vec<BTreeSet<usize>>,
}
impl<'a> CommandDispatch<'a> {
    /// Follow only tables the native code hands to the scanner: roots supplied
    /// by the native registrar to the scanner's array, tail-call (`B`)
    /// registrations that replace that root per media mode, and flash tables
    /// passed to the scanner directly. Orphan coherent tables do not become
    /// candidates.
    ///
    /// Initial roots are walked strictly (zero padding, known flags). Mode
    /// and direct tables are walked as the native scanner reads them: flags 3
    /// ends a table, flags 4 links, anything else advances 8 bytes. A cycle,
    /// an unaligned record or more than 1024 records in one walk is
    /// `InvalidContract`; a walk past the image end is `Truncated`. These
    /// tables are bound only after the initial roots' own evidence.
    pub fn inspect(image: &'a [u8]) -> Result<Self, Error> {
        let scanner = CommandScanner::inspect(image)?;
        let tables = scanner.tables(image)?;
        let roots = tables.initial;
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
        let initial = retained.clone();
        let extra = tables.extra?;
        let mut modes = Vec::new();
        for root in &extra.modes {
            modes.push(native_walk(image, *root, &mut records, &mut retained)?);
        }
        for table in &extra.direct {
            native_walk(image, *table, &mut records, &mut retained)?;
        }
        records.sort_by_key(|record| record.off);
        Ok(Self {
            image,
            scanner,
            roots,
            records,
            initial,
            modes,
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
    /// Proven flash roots registered by native `BL` initialization calls.
    /// Tail-call (media mode) registrations and direct scanner tables are not
    /// included; their records are in [`Self::records`].
    pub fn roots(&self) -> &BTreeSet<usize> {
        &self.roots
    }
    /// Every record reached from a statically modelled table: the initial
    /// roots, tail-call (media mode) roots and flash tables handed to the
    /// scanner directly, including linked and terminal records, by offset.
    ///
    /// The registrar's SRAM lookup cache, which the scanner is also handed,
    /// adds no records: it is assumed to hold only copies of records reached
    /// here (a modelling assumption from one image's disassembly). Not
    /// modelled: whether a tail-call site is live (a tail-merged `r0` could
    /// name another table), writers of the scanner's array or lookup cache
    /// other than the registrar, and indirect registrations.
    pub fn records(&self) -> &[CommandRecord] {
        &self.records
    }
    /// Require one reached record with the requested opcode and native flags.
    /// Another reached ordinary record with the same opcode is ambiguous: the
    /// native scanner does not advance past it, so it can shadow the request.
    /// Link (4) and terminal (3) records are passed over by opcode, except
    /// 0x3c: for CDB modes 6, 7, 10, 11 and 12 the scanner invokes any record
    /// carrying that opcode before testing for a link or terminal.
    ///
    /// Uniqueness is computed over every record in [`Self::records`], so a
    /// media-mode or direct table serving the same opcode makes the lookup
    /// `Ambiguous`. The selected record must also be reached from an initial
    /// root and from every tail-call (media mode) root; otherwise the lookup
    /// is `UnknownLayout`. This only ever refuses lookups the initial roots
    /// alone would accept. The limits listed on [`Self::records`] apply.
    pub fn record(&self, opcode: u8, flags: u8) -> Result<&CommandRecord, Error> {
        let mut matches = self.records.iter().filter(|record| {
            record.opcode == opcode
                && (record.flags == flags || opcode == 0x3c || !matches!(record.flags, 3 | 4))
        });
        let first = matches.next().ok_or(Error::UnknownLayout)?;
        if matches.next().is_some() {
            return Err(Error::Ambiguous);
        }
        if !self.initial.contains(&first.off) || first.flags != flags {
            return Err(Error::UnknownLayout);
        }
        if first.handler & 1 == 0 || first.handler as usize >= self.image.len() {
            return Err(Error::InvalidContract);
        }
        // A media mode whose table never reaches the record would not run it.
        if self.modes.iter().any(|reach| !reach.contains(&first.off)) {
            return Err(Error::UnknownLayout);
        }
        Ok(first)
    }
}

/// Walk one table as the native scanner reads it, which ignores the padding
/// bytes and treats every flags value other than 3 (end) and 4 (link) as an
/// ordinary record. Returns the offsets this walk reaches.
fn native_walk(
    image: &[u8],
    root: usize,
    records: &mut Vec<CommandRecord>,
    retained: &mut BTreeSet<usize>,
) -> Result<BTreeSet<usize>, Error> {
    let mut visited = BTreeSet::new();
    let mut at = root;
    loop {
        if at & 3 != 0 || !visited.insert(at) || visited.len() > 1024 {
            return Err(Error::InvalidContract);
        }
        let bytes = image
            .get(at..at.checked_add(8).ok_or(Error::Truncated)?)
            .ok_or(Error::Truncated)?;
        let handler = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::Truncated)?);
        if retained.insert(at) {
            records.push(CommandRecord {
                off: at,
                opcode: bytes[0],
                flags: bytes[1],
                handler,
            });
        }
        match bytes[1] {
            3 => return Ok(visited),
            4 => at = handler as usize,
            _ => at = at.checked_add(8).ok_or(Error::Truncated)?,
        }
    }
}

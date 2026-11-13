//! Solve wire encoding from ordered receiver operations, not an AES signature.
//!
//! This is an offline proof component. Operations must come from a separately
//! validated, complete receiver path; a layout alone never authorizes I/O.
//! Scratch header decoding and in-place body decoding have different effects.
use core::ops::Range;

const BLOCK: usize = 16;

/// An operation whose inputs, range and order the receiver analyzer established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Decode to temporary storage and compare the result with plaintext.
    /// Staging memory remains unchanged.
    CheckDecrypted(Range<usize>),
    /// Decode staged blocks in place with the transport AES key.
    // No current receiver contract decodes in place; kept as part of the
    // proven layout algebra its tests exercise.
    #[allow(dead_code)]
    DecryptInPlace(Range<usize>),
    /// A signature, descriptor or integrity check consumes plaintext staging.
    CheckPlaintext(Range<usize>),
    /// These staged bytes become the installed image and must be plaintext.
    Program(Range<usize>),
}

pub(crate) use crate::envelope::refusal::LayoutError as Error;

/// Encoding ranges derived from constraints on every observed/programmed block.
/// Unconsumed bytes stay canonical. This does not attest to parser completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    size: usize,
    encrypted: Vec<Range<usize>>,
    programmed: Vec<Range<usize>>,
}

impl Layout {
    /// Contiguous AES-aligned ranges to encrypt once in the outgoing image.
    #[cfg(test)]
    pub fn encrypted_ranges(&self) -> &[Range<usize>] {
        &self.encrypted
    }

    /// Ranges for which the operation sequence establishes plaintext at write.
    #[cfg(test)]
    pub fn programmed_ranges(&self) -> &[Range<usize>] {
        &self.programmed
    }

    /// Create wire bytes without changing the canonical image.
    /// The caller still needs a complete, bound receiver execution contract.
    pub fn encode(&self, image: &[u8]) -> Result<Vec<u8>, Error> {
        if image.len() != self.size {
            return Err(Error::ImageSize);
        }
        let mut wire = image.to_vec();
        for range in &self.encrypted {
            crate::envelope::enc::encrypt(&mut wire[range.clone()])
                .map_err(|_| Error::Alignment)?;
        }
        Ok(wire)
    }
}

fn blocks(range: &Range<usize>, size: usize, aligned: bool) -> Result<Range<usize>, Error> {
    if range.start >= range.end || range.end > size {
        return Err(Error::Range);
    }
    if aligned && (range.start % BLOCK != 0 || range.end % BLOCK != 0) {
        return Err(Error::Alignment);
    }
    Ok(range.start / BLOCK..range.end.div_ceil(BLOCK))
}

/// Derive the initial encoding required by the ordered checks and writes.
/// A scratch decode adds a requirement without altering staging state; an
/// in-place decode changes the requirements of all subsequent consumers.
pub fn analyze(size: usize, operations: &[Operation]) -> Result<Layout, Error> {
    if size == 0 || size % BLOCK != 0 {
        return Err(Error::Alignment);
    }
    let mut decoded = vec![false; size / BLOCK];
    let mut required = vec![None; size / BLOCK];
    let mut programmed = Vec::new();
    for operation in operations {
        let (range, aligned) = match operation {
            Operation::CheckDecrypted(r) | Operation::DecryptInPlace(r) => (r, true),
            Operation::CheckPlaintext(r) | Operation::Program(r) => (r, false),
        };
        for block in blocks(range, size, aligned)? {
            if matches!(operation, Operation::DecryptInPlace(_)) {
                if decoded[block] {
                    return Err(Error::MultipleDecryptions {
                        block: block * BLOCK,
                    });
                }
                decoded[block] = true;
                continue;
            }
            let scratch = matches!(operation, Operation::CheckDecrypted(_));
            if scratch && decoded[block] {
                return Err(Error::MultipleDecryptions {
                    block: block * BLOCK,
                });
            }
            let encrypted = scratch || decoded[block];
            if required[block].is_some_and(|previous| previous != encrypted) {
                return Err(Error::Conflict {
                    block: block * BLOCK,
                });
            }
            required[block] = Some(encrypted);
        }
        if let Operation::Program(range) = operation {
            programmed.push(range.clone());
        }
    }
    if programmed.is_empty() {
        return Err(Error::NoProgram);
    }
    let mut encrypted: Vec<Range<usize>> = Vec::new();
    for (block, value) in required.into_iter().enumerate() {
        if value != Some(true) {
            continue;
        }
        let start = block * BLOCK;
        match encrypted.last_mut() {
            Some(previous) if previous.end == start => previous.end += BLOCK,
            _ => encrypted.push(start..start + BLOCK),
        }
    }
    Ok(Layout {
        size,
        encrypted,
        programmed,
    })
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod tests;

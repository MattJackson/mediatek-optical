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
    DecryptInPlace(Range<usize>),
    /// A signature, descriptor or integrity check consumes plaintext staging.
    CheckPlaintext(Range<usize>),
    /// These staged bytes become the installed image and must be plaintext.
    Program(Range<usize>),
}

/// Contradictory or unsupported receiver operations cannot supply a wire plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Canonical images and AES transforms require complete blocks.
    Alignment,
    /// An operation escapes the supplied image or has an empty/reversed range.
    Range,
    /// The same block is required in both ciphertext and plaintext form.
    Conflict {
        /// Byte offset of the conflicting AES block.
        block: usize,
    },
    /// The receiver would decrypt the same block more than once.
    MultipleDecryptions {
        /// Byte offset of the block requiring unsupported nested encoding.
        block: usize,
    },
    /// No program operation was supplied, so there is no installed-image proof.
    NoProgram,
    /// Encoding was requested for a different-sized image.
    ImageSize,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Alignment => f.write_str("receiver encoding requires complete AES blocks"),
            Self::Range => f.write_str("receiver operation has an empty or out-of-bounds range"),
            Self::Conflict { block } => write!(f, "conflicting wire encodings at {block:#x}"),
            Self::MultipleDecryptions { block } => write!(f, "repeated AES decoding at {block:#x}"),
            Self::NoProgram => f.write_str("receiver layout contains no programming operation"),
            Self::ImageSize => f.write_str("image size differs from the receiver layout"),
        }
    }
}

impl std::error::Error for Error {}

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
    pub fn encrypted_ranges(&self) -> &[Range<usize>] {
        &self.encrypted
    }

    /// Ranges for which the operation sequence establishes plaintext at write.
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
            crate::enc::encrypt(&mut wire[range.clone()]).map_err(|_| Error::Alignment)?;
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
mod tests {
    use super::*;

    const SIZE: usize = 0x20_0000;
    const HEADER: Range<usize> = 0x3000..0x3010;

    #[test]
    fn scratch_decode_does_not_make_programmed_header_plaintext() {
        let operations = [
            Operation::CheckDecrypted(HEADER),
            Operation::Program(0..SIZE),
        ];
        assert_eq!(
            analyze(SIZE, &operations),
            Err(Error::Conflict { block: 0x3000 })
        );
    }

    #[test]
    fn boot_integrity_check_also_prevents_header_only_encoding() {
        let operations = [
            Operation::CheckDecrypted(HEADER),
            Operation::CheckPlaintext(0x1000..0xfff0),
            Operation::Program(0x10000..SIZE),
        ];
        assert_eq!(
            analyze(SIZE, &operations),
            Err(Error::Conflict { block: 0x3000 })
        );
    }

    #[test]
    fn preserved_unchecked_boot_allows_header_only_encoding() {
        let operations = [
            Operation::CheckDecrypted(HEADER),
            Operation::CheckPlaintext(0x10600..0x10608),
            Operation::Program(0x10000..SIZE),
        ];
        let plan = analyze(SIZE, &operations).unwrap();
        assert_eq!(plan.encrypted_ranges(), &[HEADER]);
        let image = vec![0x5a; SIZE];
        let wire = plan.encode(&image).unwrap();
        assert_eq!(wire[..HEADER.start], image[..HEADER.start]);
        assert_ne!(wire[HEADER.clone()], image[HEADER.clone()]);
        assert_eq!(wire[HEADER.end..], image[HEADER.end..]);
        let mut header = wire[HEADER.clone()].to_vec();
        crate::enc::decrypt(&mut header).unwrap();
        assert_eq!(header, image[HEADER]);
    }

    #[test]
    fn full_decode_before_checks_and_programming_requires_full_encryption() {
        let operations = [
            Operation::CheckDecrypted(HEADER),
            Operation::DecryptInPlace(0..SIZE),
            Operation::CheckPlaintext(0x10600..0x10608),
            Operation::Program(0..SIZE),
        ];
        let plan = analyze(SIZE, &operations).unwrap();
        assert_eq!(plan.encrypted_ranges().len(), 1);
        assert_eq!(plan.encrypted_ranges()[0], 0..SIZE);
        let mut reordered = operations.to_vec();
        reordered.swap(1, 2);
        assert_eq!(
            analyze(SIZE, &reordered),
            Err(Error::Conflict { block: 0x10600 })
        );
    }

    #[test]
    fn plaintext_and_body_only_are_distinct_constraints() {
        let plain = analyze(SIZE, &[Operation::Program(0..SIZE)]).unwrap();
        assert!(plain.encrypted_ranges().is_empty());
        let body = analyze(
            SIZE,
            &[
                Operation::CheckPlaintext(HEADER),
                Operation::DecryptInPlace(0x10000..SIZE),
                Operation::Program(0x10000..SIZE),
            ],
        )
        .unwrap();
        assert_eq!(body.encrypted_ranges().len(), 1);
        assert_eq!(body.encrypted_ranges()[0], 0x10000..SIZE);
    }

    #[test]
    fn reject_unbounded_unaligned_repeated_and_incomplete_operations() {
        assert_eq!(
            analyze(SIZE, &[Operation::Program(0..SIZE + 1)]),
            Err(Error::Range)
        );
        assert_eq!(
            analyze(SIZE, &[Operation::CheckDecrypted(1..17)]),
            Err(Error::Alignment)
        );
        assert_eq!(
            analyze(SIZE, &[Operation::CheckPlaintext(HEADER)]),
            Err(Error::NoProgram)
        );
        assert_eq!(
            analyze(
                SIZE,
                &[
                    Operation::DecryptInPlace(HEADER),
                    Operation::CheckDecrypted(HEADER),
                ]
            ),
            Err(Error::MultipleDecryptions { block: 0x3000 })
        );
    }
}

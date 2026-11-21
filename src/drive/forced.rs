//! Current-free flashing: a non-destructive pre-erase encoding probe and a
//! forced-encoding prepare/execute path that does not read receiver code.
//!
//! The usual flow detects the running receiver's wire encoding from its code
//! (`drive::detect_receiver*`), which needs the installed image or a reference
//! as "current". When that is unavailable, [`probe_encoding`] discovers the
//! encoding empirically and safely -- it enters the update session and streams
//! only the first header-bearing chunk, never COMMIT, so no erase can occur --
//! and [`ForcedUpdate`] flashes with the discovered encoding, applying the same
//! chip/family gates as `prepare_without_installed` but skipping receiver-code
//! detection and revalidation.

use crate::drive::flash::{ExecutionMode, Payload};
use crate::drive::{ExecutionRuntime, FlashError, FlashOutcome, FlashTransport};
use crate::envelope::enc;
use crate::envelope::image::Family;
use crate::prepare::receiver::{self, Encoding, TransferEncoding};
use crate::transport::{self, Error, Transport};
use crate::{cdb, DriveClass, Identity, Refusal};

/// Image offset of the 16-byte transport header INFORM validates.
const HEADER: core::ops::Range<usize> = 0x3000..0x3010;
/// Bytes streamed by the probe: one [`cdb::CHUNK`], covering the header.
const PROBE_CHUNK: usize = cdb::CHUNK;

/// Plaintext header + plaintext body (stock factory firmware).
const PP: TransferEncoding = TransferEncoding {
    header: Encoding::Plaintext,
    body: Encoding::Plaintext,
};
/// Encrypted header + encrypted body (whole-image AES, e.g. BU40N INTM).
const EE: TransferEncoding = TransferEncoding {
    header: Encoding::Encrypted,
    body: Encoding::Encrypted,
};
/// Encrypted header + plaintext body (the hybrid "complete path" receiver).
const EP: TransferEncoding = TransferEncoding {
    header: Encoding::Encrypted,
    body: Encoding::Plaintext,
};

/// The wire encodings the probe tries, in order. The order resolves the
/// header-only ambiguity between `EE` and `EP` (their 16-byte headers are
/// identical ciphertext) toward the whole-image encoding when a receiver
/// validates only the header of the first chunk.
pub const CANDIDATE_ENCODINGS: [TransferEncoding; 3] = [PP, EE, EP];

/// Re-encode `buf` (which starts at image offset 0) in place to `encoding`.
/// `buf` must be a whole number of AES blocks and at least the header range long;
/// the probe's chunk and a full update image both satisfy this.
fn apply_encoding(buf: &mut [u8], encoding: TransferEncoding) {
    match (encoding.header, encoding.body) {
        (Encoding::Plaintext, Encoding::Plaintext) => {}
        (Encoding::Encrypted, Encoding::Encrypted) => {
            enc::encrypt(buf).expect("transfer buffer is whole AES blocks");
        }
        (Encoding::Encrypted, Encoding::Plaintext) => {
            enc::encrypt(&mut buf[HEADER]).expect("the header is one AES block");
        }
        // Not a wire encoding that occurs, but defined for totality: body
        // encrypted, header left plaintext.
        (Encoding::Plaintext, Encoding::Encrypted) => {
            enc::encrypt(buf).expect("transfer buffer is whole AES blocks");
            enc::decrypt(&mut buf[HEADER]).expect("the header is one AES block");
        }
    }
}

/// Build the probe's first chunk (`image[0..0x4000]`) encoded per `encoding`.
fn first_chunk(image: &[u8], encoding: TransferEncoding) -> Option<std::vec::Vec<u8>> {
    let mut chunk = image.get(..PROBE_CHUNK)?.to_vec();
    apply_encoding(&mut chunk, encoding);
    Some(chunk)
}

/// The full transfer bytes for `encoding`, or `None` to stream the canonical
/// image unchanged (plaintext).
fn forced_transfer(image: &[u8], encoding: TransferEncoding) -> Option<std::vec::Vec<u8>> {
    if encoding == PP {
        return None;
    }
    let mut transfer = image.to_vec();
    apply_encoding(&mut transfer, encoding);
    Some(transfer)
}

/// Why [`probe_encoding`] could not determine the drive's wire encoding.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProbeError<E> {
    /// A PROBE/TEST UNIT READY/PREPARE or REQUEST SENSE command failed. No
    /// firmware data was committed.
    Transport(Error<E>),
    /// The image is shorter than one [`cdb::CHUNK`]; no header to probe.
    ImageTooShort(usize),
    /// A candidate was rejected with a sense other than the wrong-encoding
    /// `ASC 0xBD`, e.g. the READ BUFFER illegal-field `5/0x24`. Not an
    /// encoding mismatch; probing stops.
    Rejected {
        /// Sense key.
        key: u8,
        /// Additional sense code.
        asc: u8,
        /// Additional sense code qualifier.
        ascq: u8,
    },
    /// REQUEST SENSE returned an unparseable reply.
    UnreadableSense,
    /// No candidate encoding was accepted.
    NoneAccepted,
}

impl<E: core::fmt::Debug> core::fmt::Display for ProbeError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "probe command failed: {e}"),
            Self::ImageTooShort(n) => write!(f, "image is {n} bytes, shorter than one chunk"),
            Self::Rejected { key, asc, ascq } => write!(
                f,
                "probe rejected with sense {key:02X}/{asc:02X}/{ascq:02X}, not a wrong-encoding reject"
            ),
            Self::UnreadableSense => f.write_str("REQUEST SENSE reply did not parse"),
            Self::NoneAccepted => f.write_str("no candidate encoding was accepted by the drive"),
        }
    }
}

impl<E: core::fmt::Debug + 'static> std::error::Error for ProbeError<E> {}

/// Discover the drive's update wire encoding without reading receiver code.
///
/// For each of [`CANDIDATE_ENCODINGS`] this enters the update session and
/// streams exactly one first chunk carrying the header encoded for that
/// candidate, then reads REQUEST SENSE and aborts with TEST UNIT READY. A
/// `NO SENSE` (key `0x00`) reply means the drive accepted that encoding; the
/// wrong-encoding reject `ASC 0xBD` moves to the next candidate; any other
/// sense (such as `5/0x24`) stops with [`ProbeError::Rejected`].
///
/// This is non-destructive: COMMIT is never sent, so the drive stages at most
/// one chunk in RAM and erases nothing. After it returns, flash with
/// [`ForcedUpdate`].
pub fn probe_encoding<T: Transport>(
    t: &mut T,
    image: &[u8],
) -> Result<TransferEncoding, ProbeError<T::Error>> {
    if image.len() < PROBE_CHUNK {
        return Err(ProbeError::ImageTooShort(image.len()));
    }
    for encoding in CANDIDATE_ENCODINGS {
        let chunk = first_chunk(image, encoding).ok_or(ProbeError::ImageTooShort(image.len()))?;
        let sense = transport::probe_first_chunk(t, cdb::Prepare::ModeOne, &chunk)
            .map_err(ProbeError::Transport)?;
        match sense {
            Some(triplet) if triplet.0 == 0x00 => return Ok(encoding),
            Some(triplet) if triplet.1 == 0xBD => continue,
            Some((key, asc, ascq)) => return Err(ProbeError::Rejected { key, asc, ascq }),
            None => return Err(ProbeError::UnreadableSense),
        }
    }
    Err(ProbeError::NoneAccepted)
}

/// An update prepared to flash with an explicitly chosen [`TransferEncoding`]
/// (typically from [`probe_encoding`]), without live receiver-code detection
/// or revalidation. The chip and hardware-family gates of
/// `prepare_without_installed` still apply.
#[derive(Clone, Debug)]
pub struct ForcedUpdate {
    class: DriveClass,
    family: Family,
    image: std::vec::Vec<u8>,
    transfer: Option<std::vec::Vec<u8>>,
    encoding: TransferEncoding,
    prepare: cdb::Prepare,
}

impl ForcedUpdate {
    /// Gate `image` for the live drive `identity` (chip and hardware family,
    /// exactly as `ValidatedUpdate::prepare_without_installed`) and bind the
    /// chosen wire `encoding`. Does no I/O and reads no receiver code.
    pub fn prepare(
        image: &[u8],
        identity: &Identity,
        encoding: TransferEncoding,
    ) -> Result<Self, Refusal> {
        let (class, family) = crate::classify::checked(image, identity)?;
        Ok(Self {
            class,
            family,
            transfer: forced_transfer(image, encoding),
            image: image.to_vec(),
            encoding,
            prepare: cdb::Prepare::ModeOne,
        })
    }

    /// The chosen wire encoding.
    pub fn encoding(&self) -> TransferEncoding {
        self.encoding
    }
    /// The update dialect.
    pub fn class(&self) -> DriveClass {
        self.class
    }
    /// The target hardware family.
    pub fn family(&self) -> Family {
        self.family
    }
    /// The bytes actually streamed to the drive for the chosen encoding.
    pub fn transfer(&self) -> &[u8] {
        self.transfer.as_deref().unwrap_or(&self.image)
    }

    /// Execute the flash with the chosen encoding and require the target
    /// identity afterwards. Binds the live identity read-only (INQUIRY/banner),
    /// not receiver code, so it performs no receiver revalidation.
    pub fn flash_completed<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ForcedError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let prior = receiver::detect_mode(io.reads).map_err(ForcedError::Identity)?;
        Payload {
            class: self.class,
            image: &self.image,
            transfer: self.transfer(),
        }
        .flash_completed(io, runtime, ExecutionMode::Flash, self.prepare, &prior)
        .map_err(ForcedError::Flash)
    }
}

/// A forced-encoding flash failed.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
#[derive(Debug)]
#[non_exhaustive]
pub enum ForcedError<E> {
    /// The live identity could not be read before writing; no firmware sent.
    Identity(receiver::Error<E>),
    /// The shared transfer/verification engine failed.
    Flash(FlashError<E>),
}

impl<E> ForcedError<E> {
    /// Whether firmware data may have reached the drive. `false` for an
    /// identity-read failure and a failed update entry; `true` afterwards.
    pub fn firmware_write_started(&self) -> bool {
        match self {
            Self::Identity(_) => false,
            Self::Flash(error) => error.firmware_write_started(),
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for ForcedError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Identity(e) => write!(f, "identity read failed before writing: {e}"),
            Self::Flash(e) => write!(f, "{e}"),
        }
    }
}

impl<E: core::fmt::Debug + 'static> std::error::Error for ForcedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            Self::Flash(source) => Some(source),
        }
    }
}

#[cfg(test)]
#[path = "forced_tests.rs"]
mod tests;

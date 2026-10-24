//! Validated input framing, independent of the running receiver's wire format.
//!
//! Loading performs no device I/O. A plaintext BIN and its OEM AES transport
//! representation resolve to the same canonical image. Neither representation
//! determines how that image must be sent to a different running receiver.
use sha2::{Digest, Sha256};

use crate::{image, layout, update::PrepareError, Chip};

/// Encoding of the original input bytes, not the required output encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEncoding {
    /// Canonical stored firmware bytes.
    Plaintext,
    /// OEM AES transport representation.
    Encrypted,
}

/// Why an input could not be loaded as a unique validated image.
///
/// Hosts must keep a wildcard arm; the set of variants may grow.
///
/// ```compile_fail,E0004
/// fn f(e: mediatek_optical::envelope::Error) -> u8 { match e { mediatek_optical::envelope::Error::Image { .. } => 0, mediatek_optical::envelope::Error::UnknownFraming { .. } => 1, mediatek_optical::envelope::Error::Ambiguous { .. } => 2, } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Size, integrity, chip or stored-image checks failed.
    Image(PrepareError),
    /// Neither representation has a supported boot banner.
    UnknownFraming,
    /// Both representations validated; choosing either would be a guess.
    Ambiguous,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Image(error) => write!(f, "{error}"),
            Self::UnknownFraming => f.write_str("unrecognized MediaTek image framing"),
            Self::Ambiguous => f.write_str("ambiguous MediaTek image framing"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Image(source) => Some(source),
            Self::UnknownFraming | Self::Ambiguous => None,
        }
    }
}

/// Immutable input and canonical image, validated without authorizing a flash.
#[derive(Clone)]
pub struct Envelope {
    original: Vec<u8>,
    /// `None` when the canonical image is the original bytes (plaintext input).
    canonical: Option<Vec<u8>>,
    encoding: InputEncoding,
    chip: Chip,
    input_hash: [u8; 32],
    image_hash: [u8; 32],
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Envelope")
            .field("length", &self.image().len())
            .field("input_encoding", &self.encoding)
            .field("chip", &self.chip)
            .field("input_sha256", &self.input_hash)
            .field("image_sha256", &self.image_hash)
            .finish_non_exhaustive()
    }
}

fn recognized(bytes: &[u8]) -> bool {
    layout::BANNER
        .of(bytes)
        .and_then(Chip::from_banner)
        .is_some()
}

fn validate(bytes: &[u8]) -> Result<Chip, PrepareError> {
    if !image::cmac::verify(bytes) {
        return Err(PrepareError::Integrity);
    }
    if image::is_drive_read(bytes) {
        return Err(PrepareError::DriveRead);
    }
    image::detect_chip(bytes)
        .map(|info| info.family)
        .map_err(|_| PrepareError::UnknownChip)
}

impl Envelope {
    /// Load exactly one 2 MiB plaintext or OEM encrypted image. Positive boot
    /// framing and a nonempty valid CMAC table are required. Raw captures are
    /// rejected. No model, filename or absence of encryption selects a format.
    pub fn load(input: &[u8]) -> Result<Self, Error> {
        if input.len() != layout::IMAGE_SIZE {
            return Err(Error::Image(PrepareError::Size(input.len())));
        }
        let plain = recognized(input).then(|| validate(input));
        // AES-ECB: a decrypted block depends only on its own ciphertext block,
        // so decrypting the banner blocks alone decides `recognized(decoded)`.
        const _: () = assert!(layout::BANNER.start % crate::enc::BLOCK == 0);
        const _: () = assert!(layout::BANNER.len % crate::enc::BLOCK == 0);
        let mut banner = [0u8; layout::BANNER.len];
        banner.copy_from_slice(
            &input[layout::BANNER.start..layout::BANNER.start + layout::BANNER.len],
        );
        crate::enc::decrypt(&mut banner).expect("banner contains whole AES blocks");
        let decoded = Chip::from_banner(&banner).is_some().then(|| {
            let mut decoded = input.to_vec();
            crate::enc::decrypt(&mut decoded).expect("complete image contains whole AES blocks");
            decoded
        });
        let encrypted = decoded.as_deref().map(validate);
        let (canonical, encoding, chip) = match (plain, encrypted) {
            (Some(Ok(_)), Some(Ok(_))) => return Err(Error::Ambiguous),
            (Some(Ok(chip)), _) => (None, InputEncoding::Plaintext, chip),
            (_, Some(Ok(chip))) => (decoded, InputEncoding::Encrypted, chip),
            (Some(Err(error)), _) | (_, Some(Err(error))) => return Err(Error::Image(error)),
            (None, None) => return Err(Error::UnknownFraming),
        };
        let input_hash: [u8; 32] = Sha256::digest(input).into();
        let image_hash = match &canonical {
            None => input_hash,
            Some(canonical) => Sha256::digest(canonical).into(),
        };
        Ok(Self {
            original: input.to_vec(),
            input_hash,
            image_hash,
            canonical,
            encoding,
            chip,
        })
    }

    /// Original input, retained unchanged for provenance.
    pub fn original(&self) -> &[u8] {
        &self.original
    }
    /// Canonical stored image, used for acceptance and readback verification.
    pub fn image(&self) -> &[u8] {
        self.canonical.as_deref().unwrap_or(&self.original)
    }
    /// Original input encoding; does not select the receiver's transfer mode.
    pub fn input_encoding(&self) -> InputEncoding {
        self.encoding
    }
    /// Controller generation established by canonical image analysis.
    pub fn chip(&self) -> Chip {
        self.chip
    }
    /// SHA-256 of the original bytes.
    pub fn input_sha256(&self) -> &[u8; 32] {
        &self.input_hash
    }
    /// SHA-256 of canonical stored bytes.
    pub fn image_sha256(&self) -> &[u8; 32] {
        &self.image_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{self, BU3};

    #[test]
    fn both_input_formats_have_one_canonical_identity_and_preserve_provenance() {
        let image = fixtures::image(&BU3, 7);
        let plain = Envelope::load(&image).unwrap();
        let mut wire = image.clone();
        crate::enc::encrypt(&mut wire).unwrap();
        let encrypted = Envelope::load(&wire).unwrap();
        assert_eq!(plain.input_encoding(), InputEncoding::Plaintext);
        assert_eq!(encrypted.input_encoding(), InputEncoding::Encrypted);
        assert_eq!(plain.image(), encrypted.image());
        assert_eq!(plain.image_sha256(), encrypted.image_sha256());
        assert_ne!(plain.input_sha256(), encrypted.input_sha256());
        assert_eq!(encrypted.original(), wire);
        assert_eq!(plain.original(), image);
    }

    #[test]
    fn rejects_capture_corruption_empty_integrity_and_unknown_framing() {
        let image = fixtures::image(&BU3, 3);
        assert_eq!(
            Envelope::load(&fixtures::drive_read(&image)).unwrap_err(),
            Error::Image(PrepareError::DriveRead)
        );
        let mut bad = image.clone();
        bad[fixtures::SIGNED.0 as usize] ^= 1;
        assert_eq!(
            Envelope::load(&bad).unwrap_err(),
            Error::Image(PrepareError::Integrity)
        );
        bad = image;
        let table = image::cmac::TABLE_OFFSET;
        bad[table..table + image::cmac::ENTRY_COUNT * image::cmac::ENTRY_SIZE].fill(0xff);
        assert_eq!(
            Envelope::load(&bad).unwrap_err(),
            Error::Image(PrepareError::Integrity)
        );
        assert_eq!(
            Envelope::load(&vec![0; layout::IMAGE_SIZE]).unwrap_err(),
            Error::UnknownFraming
        );
        assert_eq!(
            Envelope::load(&[0; 16]).unwrap_err(),
            Error::Image(PrepareError::Size(16))
        );
    }
}

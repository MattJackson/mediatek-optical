//! The AES-128-ECB `enc` transport envelope.
//!
//! Some update paths stream the image AES-128-ECB encrypted under a fixed,
//! public transport key. This is a transport encoding, not a signature: the
//! drive authenticates the decrypted image by its integrity table
//! ([`crate::image::cmac`]). The flash sequence in [`crate::drive`] sends
//! plaintext; apply [`encrypt`] only for a route that requires `enc`.
//!
//! Requires the `enc` feature.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

/// The public AES-128 transport key.
pub const KEY: [u8; 16] = [
    0x5e, 0x9e, 0x4f, 0x00, 0x94, 0xef, 0x20, 0xab, 0x52, 0xe3, 0x5e, 0x73, 0x6a, 0xcb, 0x23, 0x24,
];

/// AES block size; the envelope covers whole blocks only.
pub const BLOCK: usize = 16;

/// `data` is not a whole number of AES blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthError(pub usize);

impl core::fmt::Display for LengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "enc: length {} is not a multiple of the {BLOCK}-byte AES block",
            self.0
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LengthError {}

fn check(data: &[u8]) -> Result<(), LengthError> {
    if data.len() % BLOCK != 0 {
        return Err(LengthError(data.len()));
    }
    Ok(())
}

/// Encrypt `data` in place.
pub fn encrypt(data: &mut [u8]) -> Result<(), LengthError> {
    check(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    for block in data.chunks_mut(BLOCK) {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    Ok(())
}

/// Decrypt `data` in place.
pub fn decrypt(data: &mut [u8]) -> Result<(), LengthError> {
    check(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    for block in data.chunks_mut(BLOCK) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_partial_blocks() {
        let mut data = [0u8; 32];
        data[0] = 1;
        let original = data;
        encrypt(&mut data).unwrap();
        assert_ne!(data, original);
        // ECB: identical plaintext blocks give identical ciphertext blocks.
        let mut zeros = [0u8; 32];
        encrypt(&mut zeros).unwrap();
        assert_eq!(zeros[..16], zeros[16..]);
        decrypt(&mut data).unwrap();
        assert_eq!(data, original);
        assert_eq!(encrypt(&mut [0u8; 15]), Err(LengthError(15)));
    }
}

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

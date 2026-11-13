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

/// Known-answer vectors computed independently with
/// `openssl enc -aes-128-ecb -K 5e9e4f0094ef20ab52e35e736acb2324 -nopad`;
/// round trips alone cannot detect a wrong key or a swapped codec.
#[test]
fn matches_openssl_known_answers() {
    let mut data = [0u8; 32];
    for (index, byte) in data[16..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let plaintext = data;
    let expected: [u8; 32] = [
        0x61, 0xbe, 0xa3, 0x74, 0xde, 0x74, 0x34, 0xb6, 0xb4, 0x2b, 0x30, 0x7a, 0x5c, 0x58, 0xbe,
        0x72, 0x54, 0x89, 0xa6, 0xe5, 0x22, 0x0e, 0x82, 0x30, 0x0e, 0xe4, 0x24, 0x71, 0x62, 0x53,
        0x3c, 0xd7,
    ];
    encrypt(&mut data).unwrap();
    assert_eq!(data, expected);
    decrypt(&mut data).unwrap();
    assert_eq!(data, plaintext);
}

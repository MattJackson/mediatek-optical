use super::*;
#[test]
fn distinct_unique_variants_are_ambiguous_together() {
    let bytes = |pattern: &[(u16, u16)]| {
        pattern
            .iter()
            .flat_map(|(op, _)| op.to_le_bytes())
            .collect::<Vec<_>>()
    };
    for alternative in [VID_GATE_SIG_NB, VID_GATE_SIG_JB8] {
        let mut image = bytes(VID_GATE_SIG);
        image.extend([0xff; 16]);
        image.extend(bytes(alternative));
        assert_eq!(VidGate::inspect(&image), Err(Error::Ambiguous));
    }
}

#[test]
fn producer_window_matches_the_authentication_gate_window() {
    // AuthCell::inspect refuses producers more than 0x200 bytes before the
    // comparison, so the producer search must not return one either.
    let image = |producer: usize| {
        let mut image = vec![0u8; 0x300];
        for (n, (op, _)) in VID_GATE_SIG.iter().enumerate() {
            image[0x220 + 2 * n..0x222 + 2 * n].copy_from_slice(&op.to_le_bytes());
        }
        image[producer..producer + 2].copy_from_slice(&0xb5f0u16.to_le_bytes());
        image
    };
    let inside = image(0x232 - 0x200);
    let gate = VidGate::inspect(&inside).unwrap();
    assert_eq!(gate.comparison(), 0x232);
    assert_eq!(gate.producer(&inside), Ok(0x32));
    let outside = image(0x232 - 0x202);
    let gate = VidGate::inspect(&outside).unwrap();
    assert_eq!(gate.producer(&outside), Err(Error::UnknownLayout));
}

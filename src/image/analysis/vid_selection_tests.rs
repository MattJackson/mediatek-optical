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

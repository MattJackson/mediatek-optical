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

#[test]
fn checked_agid_reads_through_low_registers_share_the_base() {
    // push {r4-r7,lr}; ldr r4,=0x02000100; ldrb r1,[r4,#10]; lsrs r1,#6;
    // cmp r1,#2; bcs; ldr r2,=second; ldrb r1,[r2,#10]; lsrs r1,#6;
    // cmp r1,#2; bcs; then the auth-state gate. Each bcs targets the next
    // instruction, so both reads are reached with their definitions live.
    let image = |second: u32| {
        let mut image = vec![0u8; 0x48];
        let code = [
            0xb5f0u16, 0x4c0f, 0x7aa1, 0x0989, 0x2902, 0xd2ff, 0x4a0d, 0x7a91, 0x0989, 0x2902,
            0xd2ff,
        ];
        for (n, op) in code.iter().enumerate() {
            image[2 * n..2 * n + 2].copy_from_slice(&op.to_le_bytes());
        }
        for (n, (op, _)) in VID_GATE_SIG.iter().enumerate() {
            image[0x20 + 2 * n..0x22 + 2 * n].copy_from_slice(&op.to_le_bytes());
        }
        // Both gate outcomes (fall-through and the `bne` target) return, so a
        // walk past the reads ends inside the producer.
        let after = 0x20 + 2 * VID_GATE_SIG.len();
        for at in [after, after + 2] {
            image[at..at + 2].copy_from_slice(&0xbdf0u16.to_le_bytes());
        }
        image[0x40..0x44].copy_from_slice(&0x0200_0100u32.to_le_bytes());
        image[0x44..0x48].copy_from_slice(&second.to_le_bytes());
        image
    };
    let same = image(0x0200_0100);
    assert_eq!(
        VidGate::inspect(&same).unwrap().agid_address(),
        Ok(0x0200_0100)
    );
    let other = image(0x0200_0200);
    assert_eq!(
        VidGate::inspect(&other).unwrap().agid_address(),
        Err(Error::Ambiguous)
    );
}

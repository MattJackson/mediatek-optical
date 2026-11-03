use super::CommandScanner;

/// Minimal native scanner (table r4, CDB r3) with `ret` at +96 and the
/// shared `add r4,#8; b scan` advance at +100.
fn scanner() -> Vec<u8> {
    let mut halfwords = vec![
        0xb510, 0x4b19, 0x4604, // push {r4,lr}; ldr r3,=cdb; mov r4,r0
        0x7860, 0x2807, 0xd106, // scan: ldrb r0,[r4,#1]; cmp r0,#7; bne +26
        0x7821, 0x781a, 0x4291, 0xd102, // ldrb r1,[r4]; ldrb r2,[r3]; cmp; bne +26
        0x6860, 0x4780, 0xe022, // invoke: ldr r0,[r4,#4]; blx r0; b ret
        0x7821, 0x781a, 0x4291, 0xd111, // +26: opcode compare; bne linked
        0x781a, 0x2a3c, 0xd10e, // ldrb r2,[r3]; cmp r2,#0x3c; bne linked
    ];
    for (mode, back) in [
        (6u16, 0xf2u16),
        (7, 0xef),
        (10, 0xec),
        (11, 0xe9),
        (12, 0xe6),
    ] {
        halfwords.extend([0x785a, 0x2a00 | mode, 0xd000 | back]);
    }
    halfwords.extend([
        0x2804, 0xd101, 0x6864, 0xe7db, // linked: cmp r0,#4; bne +8; ldr r4,[r4,#4]; b scan
        0x2803, 0xd101, 0x2400, 0xe004, // cmp r0,#3; bne +16; mov r4,#0; b ret
        0x781a, 0x4291, 0xd103, // linked+16: ldrb r2,[r3]; cmp r1,r2; bne ret+4
        0xe000, 0xbf00, // b ret; nop
        0x4620, 0xbd10, 0x3408, 0xe7ce, // ret: mov r0,r4; pop {r4,pc}; add r4,#8; b scan
    ]);
    let mut image: Vec<u8> = halfwords.iter().flat_map(|h| h.to_le_bytes()).collect();
    assert_eq!(image.len(), 104);
    image.extend(0x0200_0100u32.to_le_bytes());
    image.resize(0x100, 0);
    image
}

#[test]
fn scanner_fixture_matches_native_grammar() {
    let image = scanner();
    let scanner = CommandScanner::at(&image, 0).expect("native scanner grammar");
    assert_eq!(scanner.cdb(), 0x0200_0100);
}

#[test]
fn scanner_requires_ordinary_records_to_advance() {
    // Ordinary records that stop (here `b ret`) leave later records unreached,
    // so record traversal by +8 would certify records the native code skips.
    let mut image = scanner();
    image[86..88].copy_from_slice(&0xe003u16.to_le_bytes());
    assert_eq!(CommandScanner::at(&image, 0), None);

    let mut image = scanner();
    image[90..92].copy_from_slice(&0xd101u16.to_le_bytes()); // bne past the advance
    assert_eq!(CommandScanner::at(&image, 0), None);
}

const ARRAY: u32 = 0x0200_0400;

fn put(image: &mut [u8], at: usize, halfwords: &[u16]) {
    for (n, halfword) in halfwords.iter().enumerate() {
        image[at + 2 * n..at + 2 * n + 2].copy_from_slice(&halfword.to_le_bytes());
    }
}
fn put_word(image: &mut [u8], at: usize, word: u32) {
    image[at..at + 4].copy_from_slice(&word.to_le_bytes());
}
fn put_bl(image: &mut [u8], site: usize, target: u32) {
    image[site..site + 4].copy_from_slice(&thumb_asm::encode_bl(site, target).expect("bl"));
}

/// Scanner at 0, variadic registrar at 0x100, array-owning scanner caller at
/// 0x160 and one native registration of the table at 0x1a0 from 0x180.
fn registered() -> Vec<u8> {
    let mut image = scanner();
    image.resize(0x240, 0);
    put(
        &mut image,
        0x100,
        &[
            0xb40f, 0xb570, 0x4d11, 0x2100, 0x2200, 0xc506, 0xc506, 0xc504, 0x3d14, 0x480f, 0x2148,
            0xac05,
        ],
    );
    put_bl(&mut image, 0x118, 0x1f0); // cache initializer
    put(
        &mut image,
        0x11c,
        &[
            0x4a0d, 0x2000, 0x2103, 0x00c3, 0x189b, 0x1c40, 0x2809, 0x7059, 0xd3f9, 0x2001, 0x602a,
            0x9a04, 0x4601, 0x0089, 0x506a, 0xcc02, 0x1c40, 0x2900, 0x9104, 0xd1f6, 0xbc70, 0xbc08,
            0xb004, 0x4718,
        ],
    );
    put_word(&mut image, 0x14c, ARRAY);
    put_word(&mut image, 0x150, 0x0200_0500);
    put_word(&mut image, 0x154, 0x0200_0600);
    // push {r4,lr}; ldr r4,=array; mov r1,#1; b loop
    put(&mut image, 0x160, &[0xb510, 0x4c06, 0x2101, 0xe003]);
    put_bl(&mut image, 0x168, 0);
    // add r1,#1; nop; loop: lsl r0,r1,#2; ldr r0,[r4,r0]; cmp r0,#0; bne site; pop
    put(
        &mut image,
        0x16c,
        &[
            0x3101, 0xbf00, 0x0088, 0x5820, 0x2800, 0xd1f7, 0xbd10, 0xbf00,
        ],
    );
    put_word(&mut image, 0x17c, ARRAY);
    // push {r4,lr}; ldr r0,=root; mov r1,#0; bl registrar; pop {r4,pc}
    put(&mut image, 0x180, &[0xb510, 0x4803, 0x2100]);
    put_bl(&mut image, 0x186, 0x100);
    put(&mut image, 0x18a, &[0xbd10, 0xbf00, 0xbf00]);
    put_word(&mut image, 0x190, 0x1a0);
    image
}

/// A second registration at 0x1c0 whose argument shape is not proven.
fn with_unproven_registration(mut image: Vec<u8>) -> Vec<u8> {
    // push {r4,lr}; ldr r0,=0x1e0; mov r1,#1; bl registrar; pop {r4,pc}
    put(&mut image, 0x1c0, &[0xb510, 0x4803, 0x2101]);
    put_bl(&mut image, 0x1c6, 0x100);
    put(&mut image, 0x1ca, &[0xbd10]);
    put_word(&mut image, 0x1d0, 0x1e0);
    image
}

fn roots(image: &[u8]) -> Result<Vec<usize>, super::Error> {
    let scanner = CommandScanner::at(image, 0).expect("native scanner grammar");
    scanner
        .table_roots(image)
        .map(|roots| roots.into_iter().collect())
}

#[test]
fn registered_fixture_yields_native_root() {
    assert_eq!(roots(&registered()), Ok(vec![0x1a0]));
}

#[test]
fn unproven_registration_refuses_root_set() {
    // Dropping the second registration would report a partial table graph,
    // so a record lookup could be unique only because evidence was missing.
    assert_eq!(
        roots(&with_unproven_registration(registered())),
        Err(super::Error::InvalidContract)
    );
}

#[test]
fn array_pattern_without_bound_definition_refuses() {
    // A second scanner caller indexes an array whose base is not a proven
    // SRAM literal; its registrations must not silently disappear.
    let mut image = registered();
    image.resize(0x260, 0);
    let copy = image[0x160..0x180].to_vec();
    image[0x200..0x220].copy_from_slice(&copy);
    put_bl(&mut image, 0x208, 0);
    put_word(&mut image, 0x21c, 0x0300_0000);
    assert_eq!(roots(&image), Err(super::Error::InvalidContract));
}

/// The scanner fixture with an undefined instruction on a reachable path the
/// grammar does not fix, so its native frame cannot be proven.
fn unproven_scanner() -> Vec<u8> {
    let mut image = scanner();
    put(&mut image, 92, &[0xde00]);
    image
}

#[test]
fn scanner_grammar_with_unproven_frame_refuses() {
    let image = unproven_scanner();
    assert!(CommandScanner::grammar(&image, 0).is_some());
    assert_eq!(CommandScanner::at(&image, 0), None);
    // A complete grammar is a contract violation, not an absent role.
    assert_eq!(
        CommandScanner::inspect(&image),
        Err(super::Error::InvalidContract)
    );
}

#[test]
fn scanner_grammar_with_unproven_frame_makes_role_ambiguous() {
    // A second native scanner must not vanish because its frame is unproven.
    let mut image = scanner();
    image.resize(0x200, 0);
    image[0x100..0x200].copy_from_slice(&unproven_scanner());
    assert_eq!(
        CommandScanner::inspect(&image),
        Err(super::Error::Ambiguous)
    );
}

/// A correctly shaped registration at 0x1c0 in code with no provable frame.
fn with_frameless_registration(mut image: Vec<u8>, root: u32) -> Vec<u8> {
    // ldr r0,=root; mov r1,#0; bl registrar; b .
    put(&mut image, 0x1c0, &[0x4803, 0x2100]);
    put_bl(&mut image, 0x1c4, 0x100);
    put(&mut image, 0x1c8, &[0xe7fe]);
    put_word(&mut image, 0x1d0, root);
    image
}

#[test]
fn frameless_registration_of_new_root_refuses() {
    assert_eq!(
        roots(&with_frameless_registration(registered(), 0x1e0)),
        Err(super::Error::InvalidContract)
    );
}

#[test]
fn frameless_registration_of_proven_root_is_accepted() {
    assert_eq!(
        roots(&with_frameless_registration(registered(), 0x1a0)),
        Ok(vec![0x1a0])
    );
}

#[test]
fn frameless_scanner_caller_refuses() {
    // A scanner caller whose frame cannot be proven could own an array.
    let mut image = registered();
    put_bl(&mut image, 0x1c0, 0);
    put(&mut image, 0x1c4, &[0xe7fe]);
    assert_eq!(roots(&image), Err(super::Error::InvalidContract));
}

/// The registered fixture with `records` at its root (0x1a0), a terminal
/// record after them, and a `push {lr}; pop {pc}` handler body at 0x1c0.
fn with_records(records: &[(u8, u8, u32)]) -> Vec<u8> {
    let mut image = registered();
    let terminal = [(0, 3, 0)];
    for (n, &(opcode, flags, handler)) in records.iter().chain(&terminal).enumerate() {
        let at = 0x1a0 + 8 * n;
        image[at..at + 4].copy_from_slice(&[opcode, flags, 0, 0]);
        put_word(&mut image, at + 4, handler);
    }
    put(&mut image, 0x1c0, &[0xb500, 0xbd00]);
    image
}

#[test]
fn record_refuses_an_earlier_ordinary_record_with_the_same_opcode() {
    use super::super::{CommandDispatch, ResponseIo};
    let unique = with_records(&[(0x12, 7, 0x1c1)]);
    let commands = CommandDispatch::inspect(&unique).expect("native graph");
    assert_eq!(commands.record(0x12, 7).map(|r| r.handler), Ok(0x1c1));
    // The native scanner stops at the first ordinary record carrying the
    // opcode (no `add table,#8` advance), so the flags-7 record is shadowed.
    let shadowed = with_records(&[(0x12, 0, 0x1c1), (0x12, 7, 0x1c1)]);
    let commands = CommandDispatch::inspect(&shadowed).expect("native graph");
    assert_eq!(
        commands.record(0x12, 7).err(),
        Some(super::Error::Ambiguous)
    );
    assert_eq!(
        ResponseIo::inspect(&shadowed).err(),
        Some(super::Error::Ambiguous)
    );
}

#[test]
fn response_uses_the_validated_inquiry_record() {
    use super::super::ResponseIo;
    // An even handler is entered in ARM state by `blx r0`.
    let arm = with_records(&[(0x12, 7, 0x1c0)]);
    assert_eq!(
        ResponseIo::inspect(&arm).err(),
        Some(super::Error::InvalidContract)
    );
    // Two reached INQUIRY records are ambiguous even with one handler.
    let duplicate = with_records(&[(0x12, 7, 0x1c1), (0x12, 7, 0x1c1)]);
    assert_eq!(
        ResponseIo::inspect(&duplicate).err(),
        Some(super::Error::Ambiguous)
    );
}

/// INQUIRY handler at 0x240 passing offset 0x40 to a native committer at
/// 0x280, with byte writers for offsets 0x40 (0x300) and 0x80 (0x340).
fn with_response() -> Vec<u8> {
    let mut image = with_records(&[(0x12, 7, 0x241)]);
    image.resize(0x400, 0);
    // push {lr}; movs r0,#1; lsls r0,#6; bl commit; pop {pc}
    put(&mut image, 0x240, &[0xb500, 0x2001, 0x0180]);
    put_bl(&mut image, 0x246, 0x280);
    put(&mut image, 0x24a, &[0xbd00]);
    put(
        &mut image,
        0x280,
        &[
            0x490d, 0xb510, 0x680a, 0x4c0d, 0x1810, 0x62a0, 0x480c, 0x8801, 0x8801, 0x4b0c, 0x4299,
            0xd102, 0x8801, 0x1e49, 0x8001, 0x8801, 0x07c9, 0xd002, 0x8801, 0x1c49, 0x8001, 0x8801,
            0x4806, 0x6141, 0x4906, 0x2001, 0x7008, 0xbd10,
        ],
    );
    for (n, word) in [
        0x0200_0200,
        0x0403_00c0,
        0x0200_0210,
        0xffff,
        0x0404_2140,
        0x0200_020c,
    ]
    .into_iter()
    .enumerate()
    {
        put_word(&mut image, 0x2b8 + 4 * n, word);
    }
    for (at, shift) in [(0x300, 6u16), (0x340, 7)] {
        // movs r2,#1; lsls r2,#shift; adds r0,r0,r2; ldr r2,=upper; ldr r2,[r2];
        // adds r0,r2,r0; ldr r2,=lower; lsls r0,#8; ldr r2,[r2]; lsrs r0,#8;
        // adds r0,r0,r2; strb r1,[r0]; bx lr
        put(
            &mut image,
            at,
            &[
                0x2201,
                0x0012 | shift << 6,
                0x1880,
                0x4a05,
                0x6812,
                0x1810,
                0x4a04,
                0x0200,
                0x6812,
                0x0a00,
                0x1880,
                0x7001,
                0x4770,
            ],
        );
        put_word(&mut image, at + 0x1c, 0x0200_0200);
        put_word(&mut image, at + 0x20, 0x0200_01fc);
    }
    image
}

#[test]
fn response_writer_with_unproven_caller_is_not_dropped() {
    use super::super::ResponseIo;
    let image = with_response();
    let io = ResponseIo::inspect(&image).expect("native response");
    assert_eq!((io.writer(), io.buffer_offset()), (0x300, 0x40));
    // Both callers pass 0x80 = 1 << 7 to the committer.
    // A second committer caller in a provable frame makes both writers live.
    let mut proven = image.clone();
    put(&mut proven, 0x380, &[0xb500, 0x2001, 0x01c0]);
    put_bl(&mut proven, 0x386, 0x280);
    put(&mut proven, 0x38a, &[0xbd00]);
    assert_eq!(
        ResponseIo::inspect(&proven).err(),
        Some(super::Error::Ambiguous)
    );
    // The same caller without a provable frame must not make the competing
    // 0x80 writer disappear.
    let mut unproven = image;
    put(&mut unproven, 0x380, &[0x2001, 0x01c0]);
    put_bl(&mut unproven, 0x384, 0x280);
    put(&mut unproven, 0x388, &[0xe7fe]);
    assert_eq!(
        ResponseIo::inspect(&unproven).err(),
        Some(super::Error::Ambiguous)
    );
}

#[test]
fn scanner_grammar_at_the_image_tail_makes_role_ambiguous() {
    // A second complete grammar whose last read (its CDB literal) is the final
    // image word must still count as a candidate.
    let mut image = scanner();
    let ret = image.len();
    let entry = ret + 8;
    // ret: mov r0,r4; pop {r4,pc}; add r4,#8; b scan
    let mut tail: Vec<u16> = vec![0x4620, 0xbd10, 0x3408, 0xe002];
    let body: Vec<u16> = scanner()[..0x5c]
        .chunks(2)
        .map(|h| u16::from_le_bytes([h[0], h[1]]))
        .collect();
    tail.extend(body);
    let mut tail: Vec<u8> = tail.iter().flat_map(|h| h.to_le_bytes()).collect();
    let rel = |at: usize| at - ret;
    // Retarget the ret branches backwards and the CDB literal to entry + 0x5c.
    tail[rel(entry + 2)..rel(entry + 4)].copy_from_slice(&0x4b16u16.to_le_bytes());
    tail[rel(entry + 24)..rel(entry + 26)].copy_from_slice(&0xe7eeu16.to_le_bytes());
    tail[rel(entry + 0x54)..rel(entry + 0x56)].copy_from_slice(&0xe7d0u16.to_le_bytes());
    tail[rel(entry + 0x5a)..rel(entry + 0x5c)].copy_from_slice(&0xd1cfu16.to_le_bytes());
    tail.extend(0x0200_0100u32.to_le_bytes());
    image.extend(tail);
    assert_eq!(image.len(), entry + 0x60);
    assert!(CommandScanner::grammar(&image, entry).is_some());
    assert_eq!(
        CommandScanner::inspect(&image),
        Err(super::Error::Ambiguous)
    );
}

#[test]

fn response_writer_with_other_caller_argument_forms_is_not_dropped() {
    use super::super::ResponseIo;
    let image = with_response();
    // A bare `movs r0,#0x80` in a provable frame makes the 0x80 writer live.
    let mut bare = image.clone();
    put(&mut bare, 0x380, &[0xb500, 0x2080]);
    put_bl(&mut bare, 0x384, 0x280);
    put(&mut bare, 0x388, &[0xbd00]);
    // `ldr r0,=0x80; movs r1,#0; bl commit`: the argument is defined before
    // the instruction ahead of the call, in a provable frame...
    let mut early = image.clone();
    put(&mut early, 0x380, &[0xb500, 0x4807, 0x2100]);
    put_bl(&mut early, 0x386, 0x280);
    put(&mut early, 0x38a, &[0xbd00]);
    put_word(&mut early, 0x3a0, 0x80);
    // ...and without one.
    let mut unproven = image;
    put(&mut unproven, 0x380, &[0x4807, 0x2100]);
    put_bl(&mut unproven, 0x384, 0x280);
    put(&mut unproven, 0x388, &[0xe7fe]);
    put_word(&mut unproven, 0x3a0, 0x80);
    let ambiguous = Some(super::Error::Ambiguous);
    assert_eq!(
        [&bare, &early, &unproven].map(|image| ResponseIo::inspect(image).err()),
        [ambiguous, ambiguous, ambiguous]
    );
}

#[test]
fn only_unproven_registrations_refuse_as_invalid_contract() {
    // Shaped registrations that exist but cannot be proven are not absence.
    let mut image = registered();
    put(&mut image, 0x186, &[0xbf00, 0xbf00]);
    assert_eq!(roots(&image), Err(super::Error::UnknownLayout));
    let image = with_frameless_registration(image, 0x1a0);
    assert_eq!(roots(&image), Err(super::Error::InvalidContract));
}

#[test]
fn record_refuses_an_earlier_link_record_with_opcode_0x3c() {
    use super::super::CommandDispatch;
    // For CDB 3c 06/07/0a/0b/0c the native scanner invokes any record whose
    // opcode is 0x3c, including a link record, before following its link.
    let image = with_records(&[(0x3c, 4, 0x1a8), (0x3c, 1, 0x1c1)]);
    let commands = CommandDispatch::inspect(&image).expect("native graph");
    assert_eq!(
        commands.record(0x3c, 1).err(),
        Some(super::Error::Ambiguous)
    );
    // Other opcodes still pass over link records.
    let image = with_records(&[(0x12, 4, 0x1a8), (0x12, 7, 0x1c1)]);
    let commands = CommandDispatch::inspect(&image).expect("native graph");
    assert_eq!(commands.record(0x12, 7).map(|r| r.handler), Ok(0x1c1));
}

#[test]
fn response_with_only_an_unproven_writer_is_ambiguous() {
    use super::super::ResponseIo;
    let mut image = with_response();
    // Remove the proven 0x40 writer; only the 0x80 writer remains, and its
    // offset is passed by a caller whose frame cannot be proven.
    image[0x300..0x324].fill(0);
    put(&mut image, 0x380, &[0x2001, 0x01c0]);
    put_bl(&mut image, 0x384, 0x280);
    put(&mut image, 0x388, &[0xe7fe]);
    assert_eq!(
        ResponseIo::inspect(&image).err(),
        Some(super::Error::Ambiguous)
    );
}

#[test]
fn response_census_ignores_dead_committer_argument_definitions() {
    use super::super::ResponseIo;
    let image = with_response();
    // push {lr}; movs r0,#0x80; movs r0,#0x40; bl commit; pop {pc}
    let mut overwritten = image.clone();
    put(&mut overwritten, 0x380, &[0xb500, 0x2080, 0x2040]);
    put_bl(&mut overwritten, 0x386, 0x280);
    put(&mut overwritten, 0x38a, &[0xbd00]);
    // A previous function's tail `movs r0,#0x80; pop {pc}`, then
    // push {lr}; bl commit; pop {pc}.
    let mut returned = image.clone();
    put(&mut returned, 0x380, &[0x2080, 0xbd00, 0xb500]);
    put_bl(&mut returned, 0x386, 0x280);
    put(&mut returned, 0x38a, &[0xbd00]);
    // push {lr}; movs r0,#0x80; bl other; movs r0,#0x40; bl commit; pop {pc}
    let mut called = image;
    put(&mut called, 0x380, &[0xb500, 0x2080]);
    put_bl(&mut called, 0x384, 0x3f0);
    put(&mut called, 0x388, &[0x2040]);
    put_bl(&mut called, 0x38a, 0x280);
    put(&mut called, 0x38e, &[0xbd00]);
    put(&mut called, 0x3f0, &[0x4770]);
    for image in [&overwritten, &returned, &called] {
        let io = ResponseIo::inspect(image).expect("native response");
        assert_eq!((io.writer(), io.buffer_offset()), (0x300, 0x40));
    }
}

#[test]
fn response_census_keeps_definitions_that_may_reach_the_call() {
    use super::super::ResponseIo;
    // movs r0,#0x80; beq call; movs r0,#0x40; call: bl commit: the taken
    // branch still passes 0x80, so the 0x80 writer is contested.
    let mut image = with_response();
    put(&mut image, 0x380, &[0x2080, 0xd000, 0x2040]);
    put_bl(&mut image, 0x386, 0x280);
    put(&mut image, 0x38a, &[0xe7fe]);
    assert_eq!(
        ResponseIo::inspect(&image).err(),
        Some(super::Error::Ambiguous)
    );
}

#[test]
fn response_writer_with_bare_offset_prefix_is_not_dropped() {
    use super::super::ResponseIo;
    let mut image = with_response();
    // The 0x80 writer loads its offset with nop; movs r2,#0x80...
    put(&mut image, 0x340, &[0xbf00, 0x2280]);
    // ...and a proven caller passes 0x80, so both writers are live.
    put(&mut image, 0x380, &[0xb500, 0x2080]);
    put_bl(&mut image, 0x384, 0x280);
    put(&mut image, 0x388, &[0xbd00]);
    assert_eq!(
        ResponseIo::inspect(&image).err(),
        Some(super::Error::Ambiguous)
    );
}

#[test]
fn response_census_counts_a_committer_call_ending_the_image() {
    use super::super::ResponseIo;
    // movs r0,#1; lsls r0,#7; bl commit as the final image bytes.
    let mut image = with_response();
    put(&mut image, 0x3f8, &[0x2001, 0x01c0]);
    put_bl(&mut image, 0x3fc, 0x280);
    assert_eq!(image.len(), 0x400);
    assert_eq!(
        ResponseIo::inspect(&image).err(),
        Some(super::Error::Ambiguous)
    );
}

#[test]
fn registrar_call_ending_the_image_refuses() {
    let mut image = registered();
    // nop; movs r1,#0; bl registrar as the final image bytes.
    image.resize(0x248, 0);
    put(&mut image, 0x240, &[0xbf00, 0x2100]);
    put_bl(&mut image, 0x244, 0x100);
    assert_eq!(roots(&image), Err(super::Error::InvalidContract));
}

#[test]
fn array_loop_ending_the_image_refuses() {
    // push {r4,lr}; bl scanner; pop {r4,pc}, plus an unbound array loop
    // `lsl r0,r1,#2; ldr r0,[r4,r0]; cmp r0,#0; bne site` as the final bytes.
    let mut image = registered();
    image.resize(0x260, 0);
    put(&mut image, 0x240, &[0xb510]);
    put_bl(&mut image, 0x242, 0);
    put(&mut image, 0x246, &[0xbd10]);
    put(&mut image, 0x258, &[0x0088, 0x5820, 0x2800, 0xd1f0]);
    assert_eq!(roots(&image), Err(super::Error::InvalidContract));
}

#[test]
fn immediate_blx_to_the_thumb_registrar_is_not_a_registration() {
    use thumb_asm::isa::{encode_bytes, Insn, Operand, Width};
    // push {r4,lr}; ldr r0,=0x1e0; mov r1,#0; blx 0x100; pop {r4,pc}: BLX
    // enters ARM state, so the Thumb registrar never runs.
    let mut image = registered();
    put(&mut image, 0x1c0, &[0xb510, 0x4803, 0x2100]);
    let call = Insn {
        mnemonic: "blx",
        encoding: "T2",
        addr: 0x1c6,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands: [Operand::Target(0x100)].into_iter().collect(),
    };
    image[0x1c6..0x1ca].copy_from_slice(&encode_bytes(&call).expect("blx"));
    put(&mut image, 0x1ca, &[0xbd10]);
    put_word(&mut image, 0x1d0, 0x1e0);
    assert_eq!(roots(&image), Ok(vec![0x1a0]));
}

#[test]
fn switch_helper_cut_off_by_the_input_end_is_truncated() {
    use thumb_asm::isa::{encode_bytes, Insn, Operand, Width};
    let body = crate::compiler::ARM_BYTE_SWITCH;
    let call = Insn {
        mnemonic: "blx",
        encoding: "T2",
        addr: 0,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands: [Operand::Target(0x18)].into_iter().collect(),
    };
    let mut image = vec![0; 0x20];
    image[..4].copy_from_slice(&encode_bytes(&call).expect("blx"));
    image[0x18..].copy_from_slice(&body[..8]);
    assert_eq!(
        super::super::switch::targets(&image, 0),
        Err(super::Error::Truncated)
    );
    // Bytes that differ from the helper are an ordinary call.
    image[0x18] ^= 1;
    assert_eq!(super::super::switch::targets(&image, 0), Ok(None));
}

#[test]
fn response_census_sees_an_argument_defined_early() {
    use super::super::ResponseIo;
    // push {lr}; ldr r0,=0x80; nine nops; bl commit; pop {pc}: the argument
    // is defined 0x14 bytes before the call, as the INQUIRY search allows.
    let mut image = with_response();
    put(&mut image, 0x380, &[0xb500, 0x4807]);
    put(&mut image, 0x384, &[0xbf00; 9]);
    put_bl(&mut image, 0x396, 0x280);
    put(&mut image, 0x39a, &[0xbd00]);
    put_word(&mut image, 0x3a0, 0x80);
    assert_eq!(
        ResponseIo::inspect(&image).err(),
        Some(super::Error::Ambiguous)
    );
}

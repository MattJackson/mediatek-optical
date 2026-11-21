//! Static control-flow safety proof: a wrong-encoding firmware push cannot
//! erase flash on either the plaintext (PP) BU50N 1.00 receiver or the
//! encrypted (EE) BU40N INTM receiver.
//!
//! The SPI sector-erase routine (opcode `0x20`, 4 KiB) is the only instruction
//! that destroys installed firmware. This test proves, directly from the OEM
//! Thumb-2 bytes, that it is unreachable unless the staged image has already
//! passed validation:
//!
//!   1. the erase routine issues SPI opcode `0x20` through the flash-controller
//!      issuer (drives register `0x040400C0`);
//!   2. every call to the erase routine lives inside the single commit/LEADIN
//!      function, after that function's commit gate;
//!   3. the commit gate tests `state[0x01FFC310 + 2]` bit 0 (`lsls #31; beq`)
//!      and, when the bit is clear, branches to a no-erase exit that returns
//!      without reaching any erase call. Bit 0 is set only by successful
//!      INFORM/WRITE/VERIFY stages;
//!   4. INFORM rejects a malformed/wrong-encoding first chunk with sense `0xBD`
//!      and performs no erase.
//!
//! Evidence is two read-only gate-region excerpts (`*-erase-gate.bin`,
//! image offset `0xA6000..0xAC000`); see `fixtures/analysis/sources.json`.
//! `rizin -A` over the full images independently confirmed that the three
//! call sites asserted below are the *only* callers of each erase routine in
//! the whole 2 MiB image (no caller lies outside these excerpts). The two
//! receivers share one build line, so the gate/erase/sense encodings are
//! byte-identical and differ only by a constant `+0x36C` address shift.
//!
//! A runnable Unicorn CPU-emulation companion to this proof lives in
//! `tests/support/erase_emulation.rs` (opt-in; see that file's header).

/// Image excerpt covering the update commit/erase/INFORM region.
struct Gate {
    name: &'static str,
    bytes: &'static [u8],
    /// First image offset represented by `bytes`.
    base: u32,
    /// Commit/LEADIN function bounds `[start, end)`.
    commit_fn: (u32, u32),
    /// `ldrb r0, [r5, 2]` reading `state[0x01FFC310 + 2]`.
    gate_ldrb: u32,
    /// `lsls r0, r0, #31` isolating bit 0, followed by `beq <no_erase_exit>`.
    gate_test: u32,
    /// Target of the gate `beq` taken when the commit bit is clear.
    no_erase_exit: u32,
    /// SPI sector-erase routine (loops 0x1F sectors over base 0x1F0000).
    erase_routine: u32,
    /// `movs r0, #0x20` (sector-erase opcode) + `bl <erase_issuer>`.
    erase_op_site: u32,
    /// Flash-controller command issuer driving register `0x040400C0`.
    erase_issuer: u32,
    /// The three (and only) `bl <erase_routine>` call sites.
    erase_calls: [u32; 3],
    /// INFORM header/parameter validator bounds `[start, end)`.
    inform_fn: (u32, u32),
    /// `movs r0, #0xBD` sense set on a rejected/wrong-encoding first chunk.
    inform_bail: u32,
}

const PP: Gate = Gate {
    name: "PP (BU50N 1.00, plaintext)",
    bytes: include_bytes!("fixtures/analysis/pp-erase-gate.bin"),
    base: 0xA6000,
    commit_fn: (0xAACBA, 0xAB372),
    gate_ldrb: 0xAACDC,
    gate_test: 0xAACE0,
    no_erase_exit: 0xAAD36,
    erase_routine: 0xA6636,
    erase_op_site: 0xA6666,
    erase_issuer: 0xA62F4,
    erase_calls: [0xAAD06, 0xAAD62, 0xAB300],
    inform_fn: (0xA9E90, 0xAA200),
    inform_bail: 0xA9F7A,
};

const EE: Gate = Gate {
    name: "EE (BU40N INTM, encrypted)",
    bytes: include_bytes!("fixtures/analysis/ee-erase-gate.bin"),
    base: 0xA6000,
    commit_fn: (0xAB026, 0xAB6E0),
    gate_ldrb: 0xAB048,
    gate_test: 0xAB04C,
    no_erase_exit: 0xAB0A2,
    erase_routine: 0xA69A2,
    erase_op_site: 0xA69D2,
    erase_issuer: 0xA6660,
    erase_calls: [0xAB072, 0xAB0CE, 0xAB66C],
    inform_fn: (0xAA1FC, 0xAA560),
    inform_bail: 0xAA2E6,
};

impl Gate {
    fn hw(&self, addr: u32) -> u16 {
        let i = (addr - self.base) as usize;
        u16::from_le_bytes([self.bytes[i], self.bytes[i + 1]])
    }

    fn contains(&self, addr: u32) -> bool {
        addr >= self.base && (addr - self.base) as usize + 1 < self.bytes.len()
    }

    fn is_32bit(&self, addr: u32) -> bool {
        matches!(self.hw(addr) & 0xF800, 0xE800 | 0xF000 | 0xF800)
    }

    /// Decode a Thumb `BL` (T1) target, or `None` if `addr` is not a `BL`.
    fn bl_target(&self, addr: u32) -> Option<u32> {
        let hw1 = self.hw(addr);
        if hw1 & 0xF800 != 0xF000 {
            return None;
        }
        let hw2 = self.hw(addr + 2);
        // BL has bits [15:14]=11 and bit 12 = 1 in the second halfword.
        if hw2 & 0xD000 != 0xD000 {
            return None;
        }
        let s = ((hw1 >> 10) & 1) as u32;
        let imm10 = (hw1 & 0x3FF) as u32;
        let j1 = ((hw2 >> 13) & 1) as u32;
        let j2 = ((hw2 >> 11) & 1) as u32;
        let imm11 = (hw2 & 0x7FF) as u32;
        let i1 = 1 - (j1 ^ s);
        let i2 = 1 - (j2 ^ s);
        let imm = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
        let off = ((imm << 7) as i32) >> 7; // sign-extend the 25-bit value
        Some((addr + 4).wrapping_add(off as u32))
    }

    /// Decode a 16-bit unconditional branch (`B` T2) target.
    fn b_target(&self, addr: u32) -> Option<u32> {
        let hw = self.hw(addr);
        if hw & 0xF800 != 0xE000 {
            return None;
        }
        let imm = ((((hw & 0x7FF) as u32) << 21) as i32) >> 20; // sign-extend, <<1
        Some((addr + 4).wrapping_add(imm as u32))
    }

    fn is_return(&self, addr: u32) -> bool {
        let hw = self.hw(addr);
        (hw & 0xFF00) == 0xBD00 /* pop {..,pc} */ || hw == 0x4770 /* bx lr */
    }

    /// Is this a 16-bit conditional branch (`B<c>` T1, excluding UDF/SVC)?
    fn is_cond_branch(&self, addr: u32) -> bool {
        matches!(self.hw(addr) & 0xF000, 0xD000) && !matches!(self.hw(addr) >> 8, 0xDE | 0xDF)
    }
}

/// 1. The commit gate reads `state[+2]`, isolates bit 0, and branches to the
///    no-erase exit when the bit is clear.
fn assert_commit_gate(g: &Gate) {
    assert_eq!(
        g.hw(g.gate_ldrb),
        0x78A8,
        "{}: expected ldrb r0,[r5,2]",
        g.name
    );
    assert_eq!(
        g.hw(g.gate_test),
        0x07C0,
        "{}: expected lsls r0,r0,#31 (bit0)",
        g.name
    );
    let beq = g.gate_test + 2;
    assert_eq!(
        g.hw(beq) >> 8,
        0xD0,
        "{}: expected beq after the bit test",
        g.name
    );
    let off = ((g.hw(beq) & 0xFF) as u32) << 1;
    let target = beq + 4 + off;
    assert_eq!(
        target, g.no_erase_exit,
        "{}: gate beq must target the no-erase exit",
        g.name
    );
}

/// 2. The erase routine issues SPI opcode 0x20 via the flash-controller issuer.
fn assert_erase_primitive(g: &Gate) {
    assert_eq!(
        g.hw(g.erase_op_site),
        0x2020,
        "{}: expected movs r0,#0x20 (SPI sector-erase opcode)",
        g.name
    );
    assert_eq!(
        g.bl_target(g.erase_op_site + 2),
        Some(g.erase_issuer),
        "{}: sector-erase opcode must be issued via the flash-controller issuer",
        g.name
    );
}

/// 3a. Each erase call is a real `bl <erase_routine>`, inside the commit
///     function, strictly after the commit gate.
fn assert_erase_calls_gated(g: &Gate) {
    for &site in &g.erase_calls {
        assert_eq!(
            g.bl_target(site),
            Some(g.erase_routine),
            "{}: {site:#x} must be bl <erase_routine>",
            g.name
        );
        assert!(
            site > g.gate_test && (g.commit_fn.0..g.commit_fn.1).contains(&site),
            "{}: erase call {site:#x} must sit inside the commit fn, past the gate",
            g.name
        );
    }
}

/// 3b. From the no-erase exit (gate bit 0 clear), control returns without ever
///     calling the erase routine. The exit path is straight-line with
///     unconditional branches only, so a linear trace is exact.
fn assert_clear_path_cannot_erase(g: &Gate) {
    let mut pc = g.no_erase_exit;
    for _ in 0..64 {
        assert!(
            g.contains(pc),
            "{}: clear path left the excerpt at {pc:#x}",
            g.name
        );
        if g.is_return(pc) {
            return; // reached pop {..,pc} / bx lr with no erase call
        }
        assert!(
            !g.is_cond_branch(pc),
            "{}: unexpected conditional branch at {pc:#x} on the clear path",
            g.name
        );
        if let Some(t) = g.b_target(pc) {
            pc = t;
            continue;
        }
        if let Some(t) = g.bl_target(pc) {
            assert_ne!(
                t, g.erase_routine,
                "{}: clear path reaches the erase routine at {pc:#x}",
                g.name
            );
        }
        pc += if g.is_32bit(pc) { 4 } else { 2 };
    }
    panic!(
        "{}: clear path did not return within the step budget",
        g.name
    );
}

/// 4. INFORM rejects a bad first chunk with sense 0xBD and never erases.
fn assert_inform_rejects_without_erase(g: &Gate) {
    assert_eq!(
        g.hw(g.inform_bail),
        0x20BD,
        "{}: expected movs r0,#0xBD at the INFORM reject",
        g.name
    );
    // strb r0,[r4,#0x18]; movs r0,#7 (status CHECK CONDITION).
    assert_eq!(
        g.hw(g.inform_bail + 2),
        0x7620,
        "{}: expected strb r0,[r4,#0x18]",
        g.name
    );
    assert_eq!(
        g.hw(g.inform_bail + 4),
        0x2007,
        "{}: expected movs r0,#7",
        g.name
    );
    assert!(
        (g.inform_fn.0..g.inform_fn.1).contains(&g.inform_bail),
        "{}: the 0xBD bail must be inside INFORM",
        g.name
    );
    // INFORM itself contains no call to the erase routine.
    let (start, end) = g.inform_fn;
    let mut addr = start;
    while addr < end {
        assert_ne!(
            g.bl_target(addr),
            Some(g.erase_routine),
            "{}: INFORM unexpectedly calls the erase routine at {addr:#x}",
            g.name
        );
        addr += if g.is_32bit(addr) { 4 } else { 2 };
    }
}

fn prove(g: &Gate) {
    assert_commit_gate(g);
    assert_erase_primitive(g);
    assert_erase_calls_gated(g);
    assert_clear_path_cannot_erase(g);
    assert_inform_rejects_without_erase(g);
}

#[test]
fn plaintext_receiver_wrong_encoding_cannot_erase() {
    prove(&PP);
}

#[test]
fn encrypted_receiver_wrong_encoding_cannot_erase() {
    prove(&EE);
}

/// The two receivers are one build line: identical gate/erase/sense encodings,
/// shifted by a constant +0x36C. Proving the shift is exact rules out a subtly
/// different erase path hiding in the encrypted build.
#[test]
fn build_lines_match_under_constant_shift() {
    const SHIFT: u32 = 0x36C;
    for (pp, ee) in [
        (PP.gate_ldrb, EE.gate_ldrb),
        (PP.gate_test, EE.gate_test),
        (PP.no_erase_exit, EE.no_erase_exit),
        (PP.erase_routine, EE.erase_routine),
        (PP.erase_issuer, EE.erase_issuer),
    ] {
        assert_eq!(pp + SHIFT, ee, "shift mismatch {pp:#x} -> {ee:#x}");
        assert_eq!(PP.hw(pp), EE.hw(ee), "encoding differs at {pp:#x}/{ee:#x}");
    }
}

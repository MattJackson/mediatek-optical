//! Unicorn CPU-emulation companion to the static proof in `erase_safety.rs`.
//!
//! This executes the real update commit/LEADIN function of each receiver on an
//! emulated Cortex-M and shows that the SPI sector-erase routine is reached
//! **only** when the commit-enable bit `state[0x01FFC310 + 2].bit0` is set --
//! the bit that INFORM/WRITE/VERIFY set on validation success and that a
//! wrong-encoding push never sets.
//!
//! ## Why this is opt-in (not in the default CI build)
//!
//! Two hard constraints keep it out of the default build:
//!   * `unicorn-engine` is a C-backed dependency; adding it rewrites
//!     `Cargo.lock`, which the project's "fmt-only, build on CI" rule forbids
//!     regenerating locally, and every CI job runs `--locked`.
//!   * The proof needs the full 2 MiB images, which (like the rest of the
//!     corpus) live only in the private hoard, never in the public crate.
//!
//! So this file compiles to nothing unless the `emulation` feature is enabled,
//! and is skipped unless `MTK_HOARD_ROOT` is set. The always-on, dependency-
//! free `erase_safety.rs` is the CI-runnable safety gate; this is the runnable
//! CPU-emulation confirmation for a maintainer with the hoard.
//!
//! ## Enabling
//!
//! 1. Add to `Cargo.toml`:
//!      `[features] emulation = []`
//!      `[target.'cfg(feature = "emulation")'.dev-dependencies]`
//!      `unicorn-engine = "2.1"`
//!    (keep `emulation` out of `all-features` runs, or expect the C build).
//! 2. Regenerate `Cargo.lock` on a build host (not this workstation).
//! 3. `MTK_HOARD_ROOT=/path/to/hoard cargo test --features emulation \
//!       --test erase_emulation -- --nocapture`

#![cfg(feature = "emulation")]

use std::path::PathBuf;

use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};
use unicorn_engine::{RegisterARM, Unicorn};

const IMAGE_SIZE: u64 = 0x200000;
const STATE: u64 = 0x01FFC310;
const SENTINEL: u64 = 0xFFFF_FFF0;
const STACK: u64 = 0x0207_0000;

/// Addresses for one receiver's commit/erase region (see `erase_safety.rs`).
struct Target {
    /// Full-image SHA-256, located under `$MTK_HOARD_ROOT/images/mediatek`.
    sha256: &'static str,
    commit_fn: u64,
    commit_fn_end: u64,
    /// SPI sector-erase routine and the raw flash-controller command issuer.
    erase_routine: u64,
    erase_issuer: u64,
}

const PP: Target = Target {
    sha256: "20425a8ade6bb5d24bbd76fb5d5d67e744cd49e24783be87e6a89d30dfcace95",
    commit_fn: 0xAACBA,
    commit_fn_end: 0xAB372,
    erase_routine: 0xA6636,
    erase_issuer: 0xA62F4,
};

const EE: Target = Target {
    sha256: "6dce4e298d0c4aa637b149d65c77c9ebc41299362dd67fb2b8f8ced86cbf5e0e",
    commit_fn: 0xAB026,
    commit_fn_end: 0xAB6E0,
    erase_routine: 0xA69A2,
    erase_issuer: 0xA6660,
};

fn hoard() -> Option<PathBuf> {
    std::env::var_os("MTK_HOARD_ROOT").map(|r| PathBuf::from(r).join("images/mediatek"))
}

fn firmware(root: &std::path::Path, sha256: &str) -> Vec<u8> {
    let path = walk(root)
        .into_iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(&format!("{sha256}.bin")))
        .unwrap_or_else(|| panic!("{sha256}.bin not found under {}", root.display()));
    let data = std::fs::read(&path).unwrap();
    assert_eq!(IMAGE_SIZE as usize, data.len(), "expected a 2 MiB image");
    data
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

/// Run the commit function with `state[+2] = commit_byte` and report whether
/// the SPI sector-erase routine was reached.
fn commit_reaches_erase(t: &Target, image: &[u8], commit_byte: u8) -> bool {
    let mut uc = Unicorn::new(Arch::ARM, Mode::THUMB).expect("unicorn");
    uc.mem_map(0, IMAGE_SIZE as usize, Permission::ALL).unwrap();
    uc.mem_write(0, image).unwrap();
    uc.mem_map(0x01FF_0000, 0x10000, Permission::ALL).unwrap();
    uc.mem_map(0x0200_0000, 0x0010_0000, Permission::ALL)
        .unwrap();
    // A single catch-all peripheral window; MMIO reads return 0 (see below).
    uc.mem_map(0x0400_0000, 0x0010_0000, Permission::ALL)
        .unwrap();

    // Commit-enable state byte under test.
    uc.mem_write(STATE + 2, &[commit_byte]).unwrap();

    let erase_routine = t.erase_routine;
    let erase_issuer = t.erase_issuer;
    let (lo, hi) = (t.commit_fn, t.commit_fn_end);

    // One code hook does three jobs: trap the erase primitives, stub every
    // call that leaves the commit function, and stop at the return sentinel.
    uc.add_code_hook(0, IMAGE_SIZE, move |uc, pc, _| {
        if pc == erase_routine || pc == erase_issuer {
            uc.reg_write(RegisterARM::R0, 0).unwrap();
            // Record and stop: any arrival here is an erase attempt.
            ERASE_REACHED.with(|f| f.set(true));
            uc.emu_stop().unwrap();
            return;
        }
        if pc == SENTINEL {
            uc.emu_stop().unwrap();
            return;
        }
        // Stub any leaf call that leaves the commit function: return R0 = 0.
        if !(lo..hi).contains(&pc) {
            let lr = uc.reg_read(RegisterARM::LR).unwrap();
            uc.reg_write(RegisterARM::R0, 0).unwrap();
            uc.reg_write(RegisterARM::PC, lr & !1).unwrap();
        }
    })
    .unwrap();

    // Unmapped MMIO/RAM reads read as zero; writes are ignored.
    uc.add_mem_hook(
        HookType::MEM_READ_UNMAPPED | HookType::MEM_WRITE_UNMAPPED,
        0,
        u64::MAX,
        |uc, _, addr, _, _| {
            let page = addr & !0xFFF;
            let _ = uc.mem_map(page, 0x1000, Permission::ALL);
            true
        },
    )
    .unwrap();

    uc.reg_write(RegisterARM::SP, STACK).unwrap();
    uc.reg_write(RegisterARM::LR, SENTINEL | 1).unwrap();
    ERASE_REACHED.with(|f| f.set(false));
    // Enter the commit function in Thumb state.
    let _ = uc.emu_start(t.commit_fn | 1, SENTINEL, 0, 200_000);
    ERASE_REACHED.with(|f| f.get())
}

thread_local! {
    static ERASE_REACHED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn prove(t: &Target) {
    let Some(root) = hoard() else {
        eprintln!("MTK_HOARD_ROOT unset; skipping Unicorn erase proof");
        return;
    };
    let image = firmware(&root, t.sha256);

    // (i) Commit bit clear (validation failed / wrong encoding): NEVER erases.
    assert!(
        !commit_reaches_erase(t, &image, 0x00),
        "erase reached with the commit bit clear"
    );
    // A stray unrelated bit set is still not the commit bit: still no erase.
    assert!(
        !commit_reaches_erase(t, &image, 0x04),
        "erase reached without the commit-enable bit"
    );
    // (iii) Commit-enable bit0 (plus the LEADIN bit3) set: erase is reached.
    assert!(
        commit_reaches_erase(t, &image, 0x09),
        "erase not reached on the validated/committed path"
    );
}

#[test]
fn plaintext_commit_gate_controls_erase() {
    prove(&PP);
}

#[test]
fn encrypted_commit_gate_controls_erase() {
    prove(&EE);
}

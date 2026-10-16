# mediatek-optical

[![CI](https://github.com/MattJackson/mediatek-optical/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MattJackson/mediatek-optical/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/mediatek-optical.svg)](https://crates.io/crates/mediatek-optical)
[![docs.rs](https://img.shields.io/docsrs/mediatek-optical)](https://docs.rs/mediatek-optical)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![MSRV 1.75](https://img.shields.io/badge/MSRV-1.75-blue.svg)](#minimum-supported-rust-version)

The protocol of **MediaTek MT1959 and MT1939 optical drives** (BD/DVD): command
encoding, identity decoding, memory-read and flash sequences over any SCSI
transport, chip detection, the AES-CMAC integrity table, and reconstruction of
the flashable OEM image from a drive read.

```toml
[dependencies]
mediatek-optical = { version = "0.6", features = ["drive", "image"] }
```

| Module | Feature | Contents |
|---|---|---|
| `cdb` | — | CDB constructors and field constants |
| `Identity` | — | Decoded INQUIRY, boot banner and identity descriptor; `chip()`, `class()` |
| `Chip` | — | `Mt1959` / `Mt1939`, from an identity tag or banner |
| `DriveClass` | — | The update dialect: session steps, chunking, readiness timing, read-back floor |
| `layout` | — | 2 MiB image geometry; boot page, boot mirror, drive-written regions |
| `sense` | — | Sense parsing; flash-fault and no-medium classification |
| `drive` | `drive` | `Transport` trait; `identify`, `read_memory`, `feature`, `enter_update` → `Session` |
| `receiver` | `drive` | Read-only `detect_mode`, `detect_encoding`, pre-write `Receiver::revalidate`, and bounded entry-code inspection |
| `image` | `image` | `detect_chip`, `family` / `hardware`, `is_uhd`, `is_drive_read`; `cmac` verify / resign |
| `update` | `image` (+ `drive` to flash) | `PreparedUpdate::prepare` against `InstalledFirmware`; `flash` with a `FlashRuntime` |
| `enc` | `enc` | AES-128-ECB transport envelope |
| `envelope` | `image`, `enc` | Validated input framing, canonical image and original/canonical SHA-256 |
| `oem` | `oem` | `rebuild` with `Catalog`, `Factory`, `content_key`, `Provenance` |

The default build and the `drive` feature are `no_std` and allocation-free.
`image` and `oem` use `std`.

## Drive memory

READ BUFFER mode 6 exposes the 2 MiB flash at file offsets with two
differences from the image that was flashed:

- The boot page `0x0..0x400` reads back as the image's page at `0x10000`. Flash
  stores the boot page in a form that never reads back.
- The drive rewrites four regions at runtime and an update never overwrites
  them: the UHD and BD host revocation lists, the settings page and the
  calibration block (`layout::DRIVE_WRITTEN`).

Across 205 OEM update images of both generations (LG, HP and ASUS), 204 store
the same boot page, and every drive-read difference falls in those five
ranges. `oem::content_key` hashes everything else, so a drive read and the OEM
image it came from share a key.

## Hardware family

`image::family` names the board an image is built for (scheme
`mediatek.hardware.v1`). Every MT19xx build carries a hardware configuration
record in its code area: the MMC feature template the firmware answers GET
CONFIGURATION from, then `55 AA`, `UNIQUE` and ten digits, the `MTEKMT19xx`
tag and the platform code. The family hashes the chip, the record's platform
code (`JB7`, `JB8`, `BU3`, ...), the bootloader the boot banner names, the
Core feature's interface, feature `0x0003` and whether a BD writing profile is
enabled. It reads nothing a drive read changes, so a drive read and the image
it was flashed from share a family.

Across 207 OEM images the definition yields 11 families. One model can span
two: a BH16NS40 1.03 (`JB7`, family `11e7527216405467`) and a BH16NS40 1.05
(`JB8`, family `70f72c46f9603141`) are different boards, and the vendor
updaters refuse to cross them. `None` means the family cannot be
established: a wrong size, no chip, a malformed banner, no or several
records, a record for another chip or platform, or a broken feature template.

## Updates

`envelope::Envelope::load(bytes)` recognizes plaintext and OEM AES input,
validates the canonical image, and retains the original bytes and both hashes.
Corrupt images, empty integrity tables and raw drive captures are rejected.
Its `input_encoding()` describes the file only: the running receiver determines
the required transfer encoding. Loading an envelope performs no drive I/O and
does not authorize writing. Receiver-bound preparation is being migrated to
consume this type; the existing update API below remains available meanwhile.

`update::PreparedUpdate::prepare(image, &installed)` takes the image and the
drive's `InstalledFirmware`: its live `Identity` bound to a complete read of
its firmware (or the image rebuilt from one). It refuses, with no override,
an image that is not 2 MiB, fails its integrity table or is a raw drive read;
an image for another chip; and an image whose family differs from the
installed one, or where either is unknown. `PreparedUpdate::check(image,
&identity)` runs every check that needs no installed firmware, for use before
a backup.

The prepared update carries the drive's `DriveClass`, which owns the session.
`PreparedUpdate::flash` sends PROBE, TEST UNIT READY and PREPARE, the image in
128 STREAM chunks and COMMIT on the write transport, then TEST UNIT READY and
REQUEST SENSE, polls TEST UNIT READY for up to 120 s while the drive programs,
reads REQUEST SENSE again and reads back every chunk, comparing the
integrity-protected bytes above the boot area. A flash-fault sense, a drive
that never settles, a differing or unreadable protected byte all fail.
Progress and diagnostics go through a `FlashRuntime`.

The 120 s readiness bound covers the OEM updaters' 100 s per-command
timeout (they wait without a total bound) plus margin, so a drive still
programming is never declared failed early.

## OEM reconstruction

`oem::rebuild` turns a complete drive read into a flashable image:

- **Exact**: the read's content key matches a cataloged OEM build. The result
  is byte-identical to that vendor file.
- **Chip default**: an unknown build (a revision the catalog lacks, or a
  modified image) gets its chip generation's default factory contents. Regions
  the drive left erased stay erased. The result carries no per-unit data but
  is a reconstruction, reported as such in `Provenance`.

A boot page that is neither the stored page nor the mirror of a drive read is
refused: no image is produced whose stored boot page is unknown. The crate
ships no catalog; build one from OEM images with `oem::Factory::from_image`
and `oem::content_key`.

## Example

```rust,ignore
use mediatek_optical::{drive, update};

struct Sg(/* your pass-through */);

impl drive::Transport for Sg {
    type Error = std::io::Error;
    fn exec(&mut self, cdb: &[u8], data: drive::Data<'_>) -> Result<usize, Self::Error> {
        /* issue `cdb`; fill or send `data` */
    }
    fn sense(&self) -> Option<(u8, u8, u8)> { /* last sense */ }
}

let id = drive::identify(&mut reads)?;
let installed = update::InstalledFirmware::new(id, &backup)?;
let prepared = update::PreparedUpdate::prepare(&image, &installed)?;
let verified = prepared.flash(
    update::FlashTransport { reads: &mut reads, writes: &mut writes },
    &mut runtime, // your update::FlashRuntime: clock, sleep, progress
)?;
```

## Command set

Flash-sequence CDBs are 12 bytes, exactly as the OEM update tool issues them.
Offsets are 24-bit big-endian.

| Command | Constructor | CDB |
|---|---|---|
| Memory read | `cdb::read_memory(off, len)` | `3C 06 00 <off> <len> 00` |
| Identity / feature | `cdb::inquiry(n)`, `cdb::get_configuration(code, n)` | `12 …`, `46 02 <code> …` |
| Probe | `cdb::probe()` | `3C 06 00 1E C0 00 00 01 00 00 00 00` |
| Ready | `cdb::test_unit_ready()` | `00 × 12` |
| Enter update | `cdb::enter_update()` | `3B 01 00 00 00 00 00 00 00 0B 00 00` |
| Write chunk | `cdb::transfer(off, len)` | `3B 06 00 <off> 00 <len16> 00 00 00` |
| Commit | `cdb::finish()` | `3B 07 00 00 00 00 00 00 00 00 1B 12` |
| Status | `cdb::request_sense()` | `03 00 00 00 10 80 00 00 00 00 00 00` |

The drive erases and programs flash when the last chunk of a complete 2 MiB
image lands. The commit is a trailing handshake.

## Safety

An update session writes drive firmware. A wrong image, or an interrupted
session, can leave the drive unusable. Verify an image with `image::cmac`
before flashing, and flash through `update::PreparedUpdate`, which refuses
an image for other hardware. The identity, feature and memory-read commands
are read-only.

## Minimum supported Rust version

1.75.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).

## Receiver encoding detection

With `drive`, `receiver::detect_mode(&mut transport)` identifies BOOT versus
running firmware from INQUIRY. Pass that result to
`receiver::detect_encoding(&mut transport, &mode)` to inspect the active
receiver's code and obtain `Encoding::Plaintext` or `Encoding::Encrypted`.
Call `Receiver::revalidate` immediately before writing. The caller owns flash
policy and applies `PreparedUpdate::encrypted()` when required.

Detection sends only INQUIRY and READ BUFFER mode 6. It recognizes positive
Thumb instruction sequences in the audited MT1939/MT1959 receiver ranges;
unknown or conflicting signatures never default to plaintext. BOOT and
application are evaluated independently, including images whose two receivers
expect different formats. Read failures can prevent detection on a live drive;
static corpus coverage does not establish physical-device read accessibility.

Explicit `recovery::PreparedRecovery::flash` reports a failed PREPARE through
`FlashRuntime::recovery_entry_failed` and proceeds once to the selected image.
This is recovery host policy, not a claim that the receiver always rejects
PREPARE. Normal `PreparedUpdate::flash` remains strict. STREAM failures stop
both paths, no firmware writes retry, and recovery still requires readback
verification and confirmed application startup. Physical recovery remains
unvalidated.

`receiver::entry::inspect_boot_legacy(window, flash_address)` and
`inspect_boot_dual(window, flash_address)` inspect PREPARE flag-copy grammars
with checked operands, literals and branch targets. The latter binds mode 1
and mode 6/buffer 0x67 to the same body and validates the unsupported-mode error
path. Results are entry evidence, not transfer authorization: completion,
dispatcher binding and image acceptance still need separate proof. All 136
published images match exactly one grammar (98 legacy, 38 dual entry). The full
1024-image hoard has 102 legacy and 38 dual-entry matches; 884 other images
remain unresolved. No error-continuation policy is inferred from these matches.

`receiver::entry::application::inspect` binds an application command table to
the unique MMIO update-flag clearing block. All 136 published images match:
25 inline Thumb tables and 111 compiler-helper tables, with 18 mode-1 targets
reaching the block through one branch. Helper candidates require a separate
bounded read checked by `matches_helper`. These bindings do not prove entry
guards, complete flag-copy semantics, opcode dispatch or completion behavior,
and do not authorize a transfer.

`application::ModeBufferGuard` recognizes the complete 40-byte mode/buffer
exclusion helper present in 73 published images. Its return value permits
mode 1/buffer 0; 63 images have no pre-table guard call in the independent
census. Helper matching alone does not prove the caller's argument setup or
rejection branch, and does not establish a receiver entry contract.

`application::inspect_prologue` binds the caller's mode/buffer arguments,
guard-result branch, CDB pointer and preloaded constants. `inspect_flags`
revalidates those inputs against the supplied bytes and checks every bit test,
OR operand, MMIO store, branch convergence and stack-restoring return. All 136
published images match both grammars; 3,280 instruction mutations are rejected.
These remain entry-body evidence: command dispatcher ownership, completion,
mode-6 alternatives and acceptance/programming rules need their own proofs.

`application::inspect_mode_six` binds the CDB buffer guard through up to three
compiler trampolines. In 38 images, buffer 0x67 reaches the same complete flag
writer as mode one; 98 images have a positively matched zero-buffer stream
guard. All 136 cases and 408 guard mutations are checked against the independent
census. This establishes the alternate entry body, not stream acceptance or
command completion.

`application::inspect_registration` binds a unique aligned WRITE BUFFER/type-1
record to the handler's Thumb pointer. All 136 published images match the
independent opcode/callback census. This is static table evidence; initializer,
lookup execution, pre-dispatch predicates and completion remain separate proofs.

The private website corpus test replays both receiver modes for every package:

```sh
MTK_RECEIVER_AUDIT=/path/to/website-transfer-audit.json \
MTK_HOARD_ROOT=/path/to/firmware-extractor \
cargo test --all-features --test receiver_corpus -- --ignored --nocapture
```

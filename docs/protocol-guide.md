# Protocol and firmware guide

Detailed protocol surfaces, firmware evidence and scope for developers using
`mediatek-optical`. Start with the [README](../README.md) for integration.

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
does not authorize writing.

`update::InstalledFirmware::new(identity, bytes)` binds captured installed bytes
to live identity. `receiver::detect` establishes the active entry and encoding
contract; `Receiver::prepare(&envelope, &installed)` checks target integrity,
controller generation and hardware family, then constructs an immutable transfer
plan. Unknown or conflicting receiver contracts fail before any write. File
encoding never chooses transfer encoding; header and body can require different
representations.

`receiver::PreparedUpdate::flash` requires complete protected-region readback.
`flash_completed` also confirms exact target startup but returns a `Completion`
whose `ReadbackQuality` explicitly distinguishes complete and limited readback.
Every readable mismatch and every failed data write remains an error. Neither
readiness nor a matching model name alone establishes target startup. The
120-second readiness bound accommodates the OEM command window.

When installed bytes are genuinely unavailable, the explicit
`prepare_without_installed` path retains target/chip/receiver checks but cannot
establish installed-family equality. The caller must obtain the corresponding
consent; the library never invents installed bytes from the target. A Current
firmware reference may supply offline receiver evidence, with explicit provenance
and physical metadata binding; post-write verification still uses live reads.

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

## Receiver-bound updates

Enable `drive`, `image` and `enc`. Identify the physical drive, bind the captured
installed image, detect the receiver, load the target `envelope::Envelope`, then
prepare and execute. Both read and write transports must address the same drive,
with exclusive access held for the entire operation.

[examples/flash.rs](../examples/flash.rs) is a compiled generic host integration
example using `Transport`, `FlashRuntime` and `FlashTransport`. It returns the
structured completion result; its `main` does not access hardware. The low-level
`drive::Session` is a protocol primitive and supplies no compatibility or
completion guarantee.

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
before flashing, and flash through `receiver::PreparedUpdate`, which refuses
an image for other hardware. The identity, feature and memory-read commands
are read-only.

## Minimum supported Rust version

1.75.

## License

MIT. See [LICENSE-MIT](../LICENSE-MIT).

## Receiver encoding detection

With `drive`, `receiver::detect_mode(&mut transport)` identifies BOOT versus
running firmware from INQUIRY. Pass that result to
`receiver::detect_encoding(&mut transport, &mode)` to inspect the active
receiver's code and obtain `Encoding::Plaintext` or `Encoding::Encrypted`.
For execution, use `receiver::detect` and receiver-bound preparation, which
selects wire encoding and automatically revalidates before writing. The caller
owns host policy; no manual encrypted/plaintext override is provided.

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

For executable operations, use `receiver::detect(transport, &mode)`. It binds
encoding, the complete entry prelude/body, mode-six guard, compiler helper and
WRITE BUFFER registration to bounded live reads. Unknown entry code fails
closed. Encrypted applications with a proven shared 0x67 entry select that
dialect; the other recognized receivers select the proven mode-one path.
Both Flash and explicit Recovery store the resulting command in the same
immutable `TransferPlan`, revalidate its code/table snapshots before writing,
and execute through the shared transfer/readback engine. `detect_encoding`
remains a read-only encoding probe and cannot supply an executable plan.

The private website corpus test replays both receiver modes for every package:

```sh
MTK_RECEIVER_AUDIT=/path/to/website-transfer-audit.json \
MTK_HOARD_ROOT=/path/to/firmware-extractor \
cargo test --all-features --test receiver_corpus -- --ignored --nocapture
```

## Error codes

Typed errors implement `mediatek_optical::CodedError`. `error.code()` returns a
stable identifier such as `mediatek.receiver.changed`, independent of runtime
values. Match typed variants for parameters and use codes for translation keys;
English `Display` messages are diagnostic prose. Wrapper errors preserve their
own stage code and expose typed causes through `std::error::Error::source` when
`std` is enabled. Handle unknown future identifiers with a generic message.

# Changelog

## 1.2.0 — Unreleased

- Table and response analysis no longer drops or invents evidence at the edges: `ResponseIo` ignores committer-argument definitions that every path overwrites, or that return or call before the committer call (instead of reporting `Ambiguous`), counts writers whose offset is a bare `movs r2,#imm` and a committer call in the last 4 bytes of the image; `CommandScanner::table_roots` ignores an immediate `BLX` to the Thumb registrar (it enters ARM state) and examines a registrar call and an array loop ending the image; a call to a switch helper cut off by the end of the input is `Truncated` rather than an ordinary call.
- Analysis refuses more partial evidence: `RequestedRateClamp::detect` also counts a clamp in the last 32 bytes of the image (`Ambiguous`); `AuthCell` requires the auth==6 fall-through to reach the preparation call through straight-line code and direct `BL` calls; `ResponseIo` reports `Ambiguous` when a writer's buffer offset is passed by a committer caller whose argument cannot be proven, including when no proven writer exists, and also counts committer callers that pass a bare `movs r0,#imm` or define `r0` up to 0x60 bytes before the call; `VidGate::agid_base` also binds checked AGID reads through `r0`-`r3`.
- `ClassicCalibration::detect` and `ClassicConsumer::inspect` report an image shorter than their routine as `UnknownLayout` rather than `Truncated`; `image::hardware` (and so the family) refuses a boot banner with a further word after the loader token (`MT1959 Boot JB8 A`) instead of keying it as loader `JB8`.
- Analysis refuses more partial evidence: `RequestedRateClamp::detect` also counts a clamp in the last 32 bytes of the image (`Ambiguous`); `AuthCell` requires the auth==6 fall-through to reach the preparation call through straight-line code and direct `BL` calls; `ResponseIo` reports `Ambiguous` when a writer's buffer offset is passed by a committer caller whose argument cannot be proven, including when no proven writer exists, and also counts committer callers that pass a bare `movs r0,#imm` or define `r0` up to 16 bytes before the call; `VidGate::agid_base` also binds checked AGID reads through `r0`-`r3`.
- `ApplicationAnalysis` no longer reports a scratch decoder established only by a trace starting inside a 32-bit Thumb-2 instruction; such a call is withheld from `scratch_decoders()` and sets `conflicting_arguments()`, matching the bulk-header rule.
- Analysis refuses more partial evidence: `RequestedRateClamp::detect` also counts a clamp in the last 32 bytes of the image (`Ambiguous`); `AuthCell` requires the auth==6 fall-through to reach the preparation call through straight-line code and direct `BL` calls; `ResponseIo` reports `Ambiguous` when a writer's buffer offset is passed by a committer caller whose argument cannot be proven; `VidGate::agid_base` also binds checked AGID reads through `r0`-`r3`.
- `analysis::UhdHandling` is no longer exported: no public API produced or accepted it; `UhdAreaContract::selects_c7()` remains the public view.
- `SavedLink::bind` and `detect` (and the scanner, command, response, VID, speed and UHD roles built on them) share one stack model between queued successor states and stop recording widened register values, so a crafted switch fan-out no longer holds a stack-model copy per queued state (peak memory stays proportional to the 10000-state cap).
- `SavedLink::bind` (and roles built on it) refuses a walk that spills more than 256 bytes of stack pointers onto the stack with `InvalidContract`, instead of exhausting memory on looping pointer spills.
- `SavedLink::require_live_definition` (and `require_argument_definition` / `require_register_definition`, used by the response, VID, scanner and UHD completion roles) keeps walking past the read site, so a path that loops back to the read without re-executing the definition is refused with `InvalidContract` instead of proven.
- Receiver detection fails closed on more partial evidence: `detect_encoding` examines a header-decrypt call ending exactly at the search-window end; `ApplicationAnalysis::conflicting_arguments()` is set when a proven in-place body decode has no header call (instead of reporting no bulk decoder); the compiler-helper command table refuses an UNDEFINED `BLX` suffix with bit 0 set; `PrepareError::Integrity` is also documented (and displayed) as covering an image with no verifiable protected range.
- `FlashError::Startup` now takes its `IssueKind` from the `StartupError` it wraps: `TargetMismatch` is `Verification`, `Read` is `Connection` and `Identity` is `Update`. `ExecuteError` delegates its kind to its cause, so receiver refusals are reported as `ReceiverMismatch`, `Connection` and so on instead of `IssueKind::Update`.
- `analysis::Error` codes now carry a host category: `unknown_layout` and `ambiguous` are `UnsupportedFirmware`, `invalid_contract` and `truncated` are `InvalidFirmware` (previously `Unexpected`). `reference::Error::Analysis` reports offline identity or read failures in the supplied Current file as `InvalidFirmware` instead of `Connection`.
- Add `CmacError::CircularTable`; `cmac::resign` now refuses tables with more than one active table-covering entry, or an active entry whose range covers its own digest bytes.
- `image::family::hardware` takes the chip only from the banner's leading `MT19xx` field and refuses a bootloader token longer than eight characters instead of truncating it.
- `Chip::from_banner` (and so `Identity::chip`, `image::detect_chip` and the update and recovery chip gates) takes the chip only from the banner's leading `MT19xx` field at byte 0; a supported label elsewhere in the banner no longer names the chip. `cmac::resign` reports an inverted or out-of-bounds active range as `BadRange` before checking for circular coverage.
- `analysis::Diagnostic::source()` now returns the underlying cause.
- `AuthCell` refusal stores must go through the register their literal load defines; an `r0`-based store without a literal load is refused.
- `RamReferences` also follows a tracked SRAM pointer used as the index of a `[Rn, Rm]` access: with a known base the exact address is recorded in `uses()`/`bytes()`, otherwise the seed is reported in `incomplete()` instead of being dropped silently. `bytes()` is documented to leave out loader-private fill and copy destinations.
- `RamReferences::incomplete()` now includes seeds whose path reaches an unmodelled branch (`cbz`/`cbnz`, table branches, indirect `bx`); function returns still end a path normally, and an indirect `blx` is treated as a call that returns.
- Tighten analysis grammars: `TST`/`CMN`/`TEQ` invalidate cached comparisons; a UHD coefficient continuation must read the register holding `0x51b1` and any other write to it or a call ends the constant; scans now include the last offset; missing literal evidence no longer matches; register-specified shifts in caller analysis use only the low byte of the shift amount, so branch pruning no longer drops live paths.
- `RamReferences` now records 16-bit `stmia`/`ldmia` accesses through a tracked SRAM pointer (and follows their base writeback), and no longer takes quadratic or per-byte time on images with many fill or copy loops.
- Command and response analysis refuse more false evidence: the scanner grammar must advance ordinary records to the next record; direct (`BL`/`BLX`) registrar calls and array-owning scanner callers that cannot be proven fail the table graph instead of being dropped (an unproven call that repeats a proven root is still accepted); tail-call (`B`) registrations and direct-table scanner calls are not yet modelled; the committer's DMA length write must follow the length normalization on the same path, using a length loaded after it.
- `CommandScanner::inspect` refuses a complete scanner grammar whose native frame cannot be proven (`InvalidContract`, or `Ambiguous` beside another scanner) instead of ignoring it. Table-root analysis no longer hashes the whole image once per scanner or registrar call site, so images with many such calls no longer take minutes.
- UHD analysis: `ClassicPosition`, `ClassicPositionSetup` and `ClassicReadPosition` report an image shorter than their routine as `UnknownLayout` rather than `Truncated`. `ClassicReadPosition` requires the range gates' status load to name the same cell as `status`; the `ReadStatus` consumer join requires its fall-through flag load to define `r0`; read completion refuses an image with both boundary grammars as `Ambiguous` and accepts a 3-bit `ADDS` state-pointer adjustment; a reverse calculation whose shared gate is not a forward calculation is `InvalidContract`; an `LDM` that reloads the `0x51b1` register ends the coefficient constant; the desktop hardware-defaults grammar no longer pins a call-displacement bit. The coefficient walk follows `b.w`, refuses returns and other PC writes and unmodelled wide instructions, and ends the constant on base writeback; the modern forward/reverse calculations claim explicit C7 handling only when their first rejection tests `0xc7`; read completion reports a conflicting veneer boundary instead of `UnknownLayout` when the plain boundary is absent.
- The legacy BOOT grammar's return must unwind exactly the proven frame (`ADD SP` matching the prologue's `SUB SP`, then `POP {r4-r7,pc}`). Mixed scratch-header contracts require the integrity walker at its literal-pool alignment. Read-back verification no longer compares a reply that reports a full transfer without filling the buffer against the previous chunk's bytes; it is a mismatch.
- `detect_encoding` propagates read failures instead of choosing an encoding from partial evidence. `Chip::from_banner` ignores bytes after the first NUL. Ambiguous BOOT grammars are refused, unaligned programming-loop targets are rejected, and recovery identification reports a malformed identity as `InvalidIdentity`.
- Receiver detection refuses a second WRITE BUFFER/type-1 registration for any handler (`UnknownEntry`); a bulk decoder's header call must be traced from a start that is not the second half of a 32-bit instruction, otherwise `conflicting_arguments()` is set; `inspect_mode_three_wrapper` also checks the setup-failure restoring exit.
- `CommandDispatch::record` refuses a lookup as `Ambiguous` when another reached ordinary record shares the opcode (the native scanner stops there), and `ResponseIo` selects its INQUIRY handler through it, so an even (ARM-state) handler is `InvalidContract` and duplicate INQUIRY records are `Ambiguous`. `VidGate::producer` searches the same 0x200 bytes before the comparison that `AuthCell` accepts.
- `CommandDispatch::record(0x3c, _)` also counts reached link and terminal records with opcode 0x3c (the scanner invokes them for CDB modes 6/7/10/11/12), `CommandScanner::inspect` counts a scanner grammar ending at the image tail, table roots whose only registrations are unproven fail as `InvalidContract` instead of `UnknownLayout`, and `ClassicSpeed::detect` no longer takes quadratic time on many consumers of one selector times many setters of one OPTM cell.

- Restrict boot-mirror readback detection to complete 2 MiB MT19xx images; older 512 KiB OEM firmware and partial fragments are not raw MT19xx captures.

- Add immutable, source-bound image analysis with cached role outcomes and typed
  diagnostics. Bind command records to native table registration and linked-table
  traversal; reject orphan tables, cycles and mismatched source images.
- Bind response-buffer writers and committers to native caller arguments, exact
  DMA expressions, guarded normalization and native return frames.
- Preserve actual compiler-switch register effects during saved-frame analysis,
  including pointer aliases and spilled frame references.
- Report static SRAM references through decoded aliases and bounded native bulk
  loops, with unresolved flow exposed separately from observed bytes. Use the
  existing A32 decoder for ARM boot-branch evidence; Thumb decoding remains in
  thumb-asm. Static reference absence is not a runtime free-memory guarantee.

- Bind classic read-completion controller fields, boundary reflection and native ROM recovery dispatch through source instructions, shared state and saved frames. Cover the compiler register and branch-veneer variants without model/hash dispatch.

- Add read-only native speed-policy contracts binding maximum/optimum defaults to the requested-rate clamp through register and address flow. Real source excerpts cover eight default grammars and reject changed clamp branches or maximum bindings; firmware rates are unchanged.

- Add independent DI-recognition and C7-routing contracts with typed native
  handling, common state-cell validation, original replay instructions and bound
  continuations. Inventory hardware defaults separately; no UHD capability claim.
  Bind eleven additional classic controller/read selectors and their saved native
  callers; recognize moved read-status blocks through their flag cell and joins.
  Bind DI mode selection and read-boundary reflection; expose displaced literal
  loads for relocation. Classify complete native parameter getters as
  media-selected or state-independent, preserving their own calibration tables.
  Bind the complete paired position-scaling routine and startup calibration
  lookup to native speed indices and the independently matched parameter getter.
  Bind the complete native read-position decoder, first-layer reflection mask
  and both range selectors to shared state cells and saved native frames.
  Bind native read-controller programming, paired position setup and the
  independent media-default mode writer, including displaced loads/native joins.

- Expose the validated native authentication refusal separately from an alternate
  implementation continuation, preserving the classic nibble-4 path contract.
- Bind classic read-speed selectors to native RMAX/OPTM setter and consumer
  roles, rejecting impure, ambiguous or disconnected leaf paths.

- Validate all three native CMAC helper bodies and hardware operands at their
  decoded call targets, allowing proven call relocations across the same
  implementation while rejecting a wrong helper role or changed helper body.
- Bind the shared mode-three wrapper's source/destination/length stores to its
  exact native programming loop and page-helper status structure. Check the
  complete native integrity-walker grammar and shared staging pointer so hosts
  can evaluate a bounded allocation-coverage change without model/hash rules.
- Pair receiver state saves/restores with the checked command frame and actual
  stack-restoring epilogue, following bounded unconditional return chains.
  This is component evidence; intervening overwrites and control flow remain
  separate obligations before authorizing a transfer or changing allocation.
- Follow explicit forward joins when binding boot/application integrity results.
  Associate bulk decoder argument evidence with its exact range selection and
  reuse the checked programming-tail grammar. These are read-only components;
  intervening control flow and called-helper semantics remain separate checks.
- Derive programming-tail pointer registers and saved-state slots from operands;
  follow the common post-call continuation across literal pools. Reject pointer
  clobbers and mismatched skip/completion joins instead of assuming one frame.
- Recognize the shared compact and wide programming loops with role-checked relocated RAM
  cells. Evidence exposes source/destination, staging and remaining-length cells
  plus selected spans; it does not authorize a transfer or change receiver
  encoding, allocation or integrity policy.
- Add opt-in read-only OEM hook analysis, with evidence-selected media and VID
  grammars and six auth-cell register contracts. Resolve the VID preparation
  success path before selecting a state-band check; derive literal addresses,
  validate stack preparation and retain original failure continuations.
- Reuse the existing two-round VID grammar for MT1939 classic. Recognize its
  interleaved r6 setup and preserve the distinct non-C/nibble-4 continuation;
  recognition alone does not establish UHD support or enable host emission.
- Keep descriptor-pattern candidates distinct from proven native BD controls;
  their protocol role must not be inferred from matching registers or sense bytes.
- Keep the transport-only default build free of image analysis and decoding.

## 1.1.2

- Expose matching allocation-free `ProductIdentity` APIs for vendor, drive model, product suffix, raw product and revision. OEM context such as `PP-100` no longer needs to be mistaken for the drive model by host display code.


All notable changes to `mediatek-optical` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [1.1.0] - Unreleased

- Faster envelope loading, AES transport encoding, family detection and lower peak
  memory; results unchanged.
- Recognize real MT1939/MT1959 boot windows containing instructions after the
  terminated boot label. Retain complete-read, optical-device and chip-signature
  checks; recognition still does not authorize an update.
- Expose protocol-neutral operation phases, component labels, measured byte progress
  and waiting states, matching the sister optical package's host contract.
- Report writing, restart and firmware verification through the shared progress
  callback without changing update command ordering or byte comparisons.
- Add structured error categories alongside stable diagnostic codes. Recovery and
  reference wrappers preserve the underlying cause's category for localized hosts.

- Fixed: the receiver-code recognizers no longer reject valid compiler output: a legacy BOOT local literal may target r2 (or r7 unless bit zero relies on the preloaded r7), and a mode-six CDB reload is rejected only when it overwrites a bit constant (1, 2, 4 or 8) the flag body uses.
- Breaking: `receiver::Error`, `recovery::Error`, `envelope::Error`,
  `update::StartupError`, `receiver::ExecuteError`, `receiver::layout::Error` and
  `receiver::reference::Error` are now `#[non_exhaustive]`; freemkv-flash and other
  hosts must add wildcard arms to exhaustive matches.
- Breaking: `recovery::Error::Startup` now carries the `update::StartupError`, and a
  recovery whose target never starts is reported as `Startup` instead of `Flash`.
- Add `update::PrepareError::Layout` (code `mediatek.prepare.layout`) preserving the
  receiver layout cause instead of the unit `ReceiverContract`.
- `protocol::Incomplete` now implements `Display`, `std::error::Error` and `CodedError`
  (`mediatek.protocol.incomplete`).
- Refuse before any write an image whose integrity table leaves no protected
  region to read back, and never report a zero-range readback as complete.
- `cmac::resign` orders entries that overlap any part of the integrity table, so a
  re-signed image verifies.
- Receiver-code recognizers reject register reuse that breaks the proven
  data flow (entry literal loads, flag read-modify-write, mode-6 CDB reload,
  plain-signature length register).
- Corpus tests that need external firmware are reported as ignored when it is not
  configured, instead of passing without running.

## [1.0.1] - 2026-10-23

- Add `protocol::Evidence::parse` for complete live boot signatures, independent
  of INQUIRY branding, matching the Pioneer protocol-evidence API pattern.
- Recovery uses the same structured signature rather than vendor-name exclusions;
  transport errors remain errors instead of becoming non-matches.
- Preserve existing Identity and receiver APIs; recognition alone grants no writer.

## [1.0.0] - 2026-10-21

- Expose `DriveClass::can_read()` so hosts request a Current firmware file for
  stock MediaTek update flows instead of offering unreliable automatic reads.

- Establish the stable 1.0 public API alongside the sister optical library.
- Validate every distinct feature configuration, doctests, all-feature packaging,
  Rust 1.75 and bare-metal `no_std` builds in CI before publication.
- Correct optional-feature documentation and test/example feature requirements;
  add a compiled receiver-bound host integration example and update API guidance.
- Add stable namespaced `CodedError` identifiers and standard error source chains;
  give receiver layout failures `Display` and `std::error::Error` implementations.
- Repair the default/drive test builds and plaintext flash simulation without AES.

- Derive header and body transfer encoding separately. Recognize the two held
  INTM scratch-header receiver forms, encrypt only their header block and use
  their boot-preserving command policy. Unknown or conflicting contracts refuse.
- Reuse cached receiver analysis and expose known programmed/preserved ranges.
- Capture each receiver code window once for encoding and entry analysis;
  preserve physical signature checks and complete pre-write revalidation.
- Bind validated targets to the receiver's captured controller generation,
  refusing a target validated for another chip before issuing commands.
- Add explicit Current-reference provenance and physical metadata revalidation;
  execution and verification always read the physical transport.
- Confirm the selected target identity and build after programming, retaining
  complete versus limited protected-region readback in the completion result.
- Represent unavailable installed firmware explicitly, without substituting
  target bytes. Support offline preparation of later stages before any writes.
- Add receiver, mutation, completion and held-corpus regressions. Instruction
  execution evidence remains conditional on the opaque verifier and hardware.

## [0.8.0] - 2026-10-16

- Require receiver-bound executable preparation. The former unbound
  `update::PreparedUpdate::flash` and manual `encrypted` selector are retired;
  callers use `receiver::detect`, `Receiver::prepare` and the immutable plan.

- Add live receiver-derived PREPARE selection, encoding and immutable transfer
  plans shared by normal Flash and explicit Recovery. Unknown entry grammars
  refuse preparation; code/table bindings are revalidated before writing.
- Recognize mode-one and shared mode-six/buffer-0x67 entry bodies. Validate
  272 BOOT/application selections across all 136 published unique images.
- Preserve zero-length PREPARE data-out direction. Explicit Recovery reports a
  PREPARE failure and continues once under host recovery policy; normal Flash
  remains strict. Stream failures never retry. Hardware validation is pending.

- Reject an MT19xx hardware record when its tag or platform bytes would reach
  into the drive-written UHD-revocation region. Hardware identity is now
  derived wholly from immutable code bytes.
- Add hash-pinned integrity/encoding tests for 124 MT19xx corpus images, including
  71 with OEM installer provenance, using stored tags and independent OpenSSL
  expectations. Cover inclusive CMAC ranges, signing order, exact stock rebuilds,
  mirrored-readback rejection, and AES transport encoding.
- Add 73 small OEM CMAC known-answer records for CI without external firmware.

## [0.7.0] - 2026-10-14

### Changed (breaking)
- **The chip generation (MT1959 vs MT1939) is now decided by the boot loader
  banner at `0x3000` and by nothing else.** The `MTEKMT19xx` identity string in
  the descriptor is a stale vendor label: it is retained only as an optional
  display field and drives no logic — no detection, no fallback, no gate, no
  family-hash input. Evidence: across a 119-image corpus of clean OEM images the
  banner agrees with the actual code generation 119/119, while the identity tag
  is wrong for the JB8/JBC6/JBP6/BUP1 builds (LG WH16NS58/WH16NS60/BH16NS40..NS50,
  tag `MTEKMT1939` but an MT1959 boot loader and MT1959 code).
  - `image::detect_chip` / `ChipInfo`: `family` now comes from `Chip::from_banner`
    over the boot banner. The old `confidence` field and the `Confidence` enum
    (`TagString` / `BannerFallback`) are removed — there is a single source now.
    The matched identity string is kept as `ChipInfo::identity_tag: Option<String>`
    (display/audit only; was `tag_string`). `ChipInfo` is now `#[non_exhaustive]`.
  - `ChipError` is reduced to `Undetectable` (the banner names no supported
    MT19xx generation); the tag-derived `Unsupported` / `Conflicting` variants are
    gone.
  - `Identity::chip()` reads the drive's boot banner only (was descriptor tag,
    else banner).
  - `image::family` / `image::hardware`: the family hash's `chip` component now
    comes from the banner. **This changes the family hash of the affected
    tag-1939/banner-1959 builds** (their key flips `chip=MT1939` → `chip=MT1959`);
    KAT/corpus expectations are updated to match. The hardware record's tag is
    still checked structurally (must name a supported generation) but is no longer
    required to equal the banner chip.
  - `update`: the drive's chip is read from its boot banner only; the
    `PrepareError::DriveDescriptor` variant is removed.

### Fixed
- `image::family` searches for the hardware record from the end of the remapped
  boot area (`0x1000`) instead of the end of the boot page (`0x400`), so the
  sector a drive read serves remapped can no longer contribute to the key.

### Added
- `tests/hoard_chip.rs`: an env-gated corpus test (`MEDIATEK_OPTICAL_HOARD`) that
  runs `detect_chip` over every non-patched, non-fragment MediaTek image in the
  hoard and asserts each image's reported chip equals its boot-banner chip.

## [0.6.0] - 2026-10-11

### Added
- `image::family` and `image::hardware`: the hardware family of an image
  (`FAMILY_SCHEME` = `mediatek.hardware.v1`), from the hardware
  configuration record in its code area. Same-model images built for
  different board lines have different families. A drive read has the family
  of the image it came from.
- `DriveClass` and `Identity::class`: the update dialect, owning the session
  steps, chunking, readiness timing and read-back floor
  (`layout::BOOT_AREA`).
- `update`: `PreparedUpdate::prepare(image, &InstalledFirmware)` refuses a
  wrong size, a failed integrity table, a raw drive read, another chip, and
  an unknown or different hardware family, with no override.
  `PreparedUpdate::check` runs the checks that need no installed firmware.
  With `drive`, `PreparedUpdate::flash` runs the session, post-commit status,
  readiness polling and read-back verification, reporting through
  `FlashRuntime`.
- `Chip` implements `FromStr` for its label.

### Changed
- `cdb::request_sense` sends `03 00 00 00 10 80`, as the OEM updaters do:
  allocation length `0x10` in byte 4 and `0x80` in the control byte (was
  `03 00 00 10 80 00`).
- Post-burn readiness is bounded at 120 s (flasher-side 45 s before): the
  OEM updaters give each command 100 s and wait without a total bound.

## [0.5.0] - 2026-10-10

### Added
- `cdb`: READ/WRITE BUFFER, INQUIRY, GET CONFIGURATION and the 12-byte OEM
  flash sequence (`probe`, `test_unit_ready`, `enter_update`, `transfer`,
  `finish`, `request_sense`).
- `Identity` (INQUIRY, boot banner, identity descriptor) and `Chip`
  (`Mt1959`, `Mt1939`), decided by the `MTEKMT19xx` tag before the banner.
- `layout`: image geometry, the boot page and its read-back mirror at
  `0x10000`, and the four drive-written regions.
- `sense`: sense parsing, flash-fault and no-medium classification.
- `drive` feature: `Transport`, `identify`, `read_memory`, `feature`,
  `test_unit_ready`, `request_sense`, and `enter_update` → `Session`.
- `image` feature: `detect_chip`, `is_uhd`, `is_drive_read`, and the AES-CMAC
  integrity table (`cmac::verify`, `cmac::resign`).
- `enc` feature: the AES-128-ECB transport envelope.
- `oem` feature: `rebuild` a flashable image from a drive read using a
  `Catalog` of OEM builds keyed by `content_key`, with per-chip defaults and a
  `Provenance` report.

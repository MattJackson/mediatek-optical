# Changelog

## 1.2.0 — Unreleased

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

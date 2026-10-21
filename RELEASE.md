# Coordinated 1.0.0 release audit

Date: 2026-10-21. Repositories: `MattJackson/pioneer-optical` and
`MattJackson/mediatek-optical`. Both use `dev` → `qa` → `main`; local work remains
on `dev`. Superseded worktrees and local branches were removed after preserving
complete Git bundles inside each repository's `.git/cleanup-backups` directory.

## Shared developer contract

Both provide a dependency-free, allocation-free `no_std` core, caller-owned
`drive::Transport` adapters, immutable firmware evidence, receiver-bound update
preparation, explicit recovery, terminal data-write failures, and stable
namespaced `CodedError` identifiers. `flash` requires complete relevant readback;
`flash_completed` requires target startup and exposes limited verification.
Readiness alone never confirms the selected target. See
[the sibling API map](docs/sibling-api.md) for protocol-specific types and methods.

The READMEs share an integration-first structure. Their Rust examples compile as
doctests; generic host integration examples compile under their declared feature
sets. Detailed firmware research remains in [the protocol guide](docs/protocol-guide.md).

## Release checks

Each library has sixteen distinct feature configurations after expanding feature
dependencies. Unit/integration tests and warning-free documentation run for all
sixteen; Rust 1.75 checks the library in all sixteen configurations. Default and
`drive` builds also target `thumbv7em-none-eabi` to verify actual `no_std` support.
Formatting, all-target/all-feature Clippy with warnings denied, doctests, workflow
lint and dependency advisory audits are release checks. The advisory audit on the
release date found zero vulnerabilities and zero warnings in both lockfiles.

Publication waits for the reusable CI workflow, including verification of the
all-feature packaged crate. Registry lookup checks the exact version: HTTP 200
skips an existing release, 404 permits publication, and every other status fails.
Publication workflows are serialized to avoid overlapping main/tag uploads.

## Firmware and regression evidence

Pioneer:

- 290 hash-pinned Kernel file cases, 324 Normal file cases, and 231 placement
  cases passed (845 external-corpus cases).
- The full hoard contains 475 distinct Kernel/Normal pairs. The continuous,
  authenticated rebuild audit checks 386 pairs: 23 template-free exact,
  307 template-free signature-modulo-exact, with the remainder rebuilding behind
  supplied headers. There were zero in-scope failures.
- The 89 exclusions are explicit: 81 legacy/non-SAT layouts, two spliced files,
  and six absent-signature reconstruction placeholders. Both spliced files and
  all six placeholders still require byte-exact lossless repacking. Separate
  fresh-signature/raw-key properties passed for 392 pairs (83 excluded).
- The release audit exposed and fixed rejection of equivalent reverse rotations
  for self-inverse raw keys. A synthetic regression reproduces the failure and
  covers zero, sixteen and distinct one-bit rotations.
- Complete-operation tests cover migration, restoration, receiver/target binding,
  full versus limited readback, and terminal write failures. The strict `flash`
  default and explicit `flash_completed` result have dedicated regressions.

MediaTek:

- All 124 hash-pinned integrity/encoding/reconstruction cases passed. Only 71
  inputs carry OEM installer provenance. Of the 53 supplementary inputs, two are
  known generated freemkv outputs, **not OEM evidence**. Their exact historical
  bytes were hash-verified from local Git LFS objects into a private test overlay;
  the canonical hoard was not changed. See [MediaTek OEM_FACTS](https://github.com/MattJackson/mediatek-optical/blob/main/tests/OEM_FACTS.md).
- Four decoding-corpus tests, five entry-corpus tests, and the published-envelope
  corpus passed. The held set covers 136 unique images and 272 BOOT/application
  states, with both Flash and Recovery plans, positive instruction evidence and
  mutation rejection. The envelope test validates 136 canonical inputs and their
  136 encrypted representations.
- The legacy receiver test passed for 120 binaries / 240 receiver states.
  The current chip/banner check read 831 images (138 recognized, 693 with no
  recognized banner, zero unreadable).
- The historical 298-file family research dataset is unavailable locally. Its
  optional no-op is not counted as historical-dataset validation. Current unit
  and available-corpus checks remain enabled; family hashing was not changed.
- Default/drive tests, the plaintext simulation without AES, and missing feature
  requirements were repaired. Errors now retain stable codes and typed standard
  source chains; receiver-layout errors implement `Display` and `Error`.

## Bounded fuzzing and coverage

Both existing firmware fuzz targets ran with nightly Rust, libFuzzer and Address
Sanitizer for 61 seconds without a crash: 131,907 runs for Pioneer and 301,587 for
MediaTek, with a maximum input length of 131,072 bytes. These are bounded smoke
runs, not exhaustive search. Reproduce with:

```sh
cargo +nightly fuzz run firmware -- -max_total_time=60 -max_len=131072
```

Coverage is measured over Rust tests and the available external corpus. It does
not imply physical-device coverage. Machine-local logs, corpus overlays and
coverage profiles remain under `.git/release-audit` and `target`.

## Evidence limits

Offline firmware analysis, independent known answers, simulated transports and
fuzzing establish software behavior within the tested scope. They do not certify
physical erase/program timing, every USB bridge, power-loss recovery, all cross-
model combinations, or behavior of unsupported firmware. No physical firmware
writes were performed during this release audit. Mathematical signature validity
is not manufacturer provenance or proof that a physical receiver trusts a key.

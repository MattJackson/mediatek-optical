# Receiver decoding evidence

The dated development checkpoints below retain the evidence and limitations
from the investigation. See **Production integration** at the end for the current
implementation; earlier statements that production preparation is unchanged
describe those earlier checkpoints, not the present code.

## Independent firmware observations

Addresses below are image-relative instruction addresses from disassembly, not
production lookup keys. The real-image tests check the input SHA-256 before using
these expected values.

| Receiver | SHA-256 | Header call | Full-image call |
| --- | --- | --- | --- |
| BH16NS40 INTM application | `c3a18eed17251d1508964647e833ffdfe01b13c28dff9a717dfac6336e7c70e6` | `0x9d48e -> 0x9b024`, 16 bytes, staging `+0x3000` to stack `+0x14` | No second direct call found; complete-path analysis remains required |
| Same INTM boot receiver | same image | `0x35d2 -> 0x5500` | `0x36ac -> 0x5500`, staging in place, length `0x200000` |
| BU40N INTM application | `29ad302647148e270c15a5a4542aa4796ee9ba25ea9fbf9f2be9465c01c139a7` | `0x9d3ee -> 0x9ae04`, 16 bytes, staging `+0x3000` to stack `+0x1c` | No second direct call found; complete-path analysis remains required |
| WH16NS58 1.V9 application | `97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061` | `0x9d768 -> 0x9b11e` | `0x9d836 -> 0x9b11e`, staging plus selected start, length `0x200000` |

## INTM cannot be enabled by changing just an encoding flag

The BH16NS40 application compares the decoded header byte at index six with
`0x20` at `0x9d4ae`. For the held `MT1959 Boot JB8 ` banner that byte is a space;
the branch to `0x9d4e2` skips clearing update flag bit zero. It is incorrect to
assume that matching chip banners necessarily clear that bit.

The selected range at `0x9d522..0x9d54a` starts at zero when bit zero is set,
and at `0x10000` otherwise. Boot CMAC is likewise conditional on this bit at
`0x9d618..0x9d626`. A header encrypted only on the wire remains encrypted in
staging after the scratch check. It conflicts with a later plaintext boot CMAC
or a write that includes the header. A safe mixed-format plan therefore requires
proof of both the integrity-check selection and the programmed range. Selecting
different PREPARE flags is not yet implemented or authorized by these facts.

The 1.V9 bulk call uses length `0x200000` even when its start is `0x10000`.
Do not silently clip that instruction's memory footprint to the uploaded image.
The layout solver currently rejects out-of-image operations; the analyzer must
account explicitly for any extra staging memory read by a real receiver.

The INTM programming wrapper's mode-3 path (`0x140b64..0x140b98`) forwards the
three selected cells to `0x17000`. That routine additionally skips offsets
`0x1d0000..0x1ec000` at `0x17078..0x17098`, and skips the final `0x10000` bytes
when it reaches `0x1f0000` at `0x1709a..0x170b4`. Requested range therefore is not
the same as programmed range. These are disassembled observations, not yet a
complete production-recognized programming grammar.

## Current implementation

- `receiver::analysis::ApplicationAnalysis` is now constructed once from the
  application's already-read code snapshot during live profile detection and
  retained by `Receiver`. Queries return references to cached range selections,
  direct-signature evidence, integrity selections and argument-traced scratch
  decoder calls. It makes no additional device reads. Missing or conflicting
  evidence remains explicit; this object does not yet authorize a wire layout.
  The 272-case private live-detection test passes with this integration and
  finds exactly two scratch-header/direct-signature application variants.

- `receiver::decoding` traces actual arguments through supported Thumb
  instructions and direct trampolines. It rejects unknown inputs/instructions,
  conditional flow, cycles, truncation and overflow. Incoming register and memory
  facts still need a separate control-flow proof.
- `receiver::layout` derives initial AES block constraints from ordered scratch
  checks, in-place decryptions, plaintext checks and program operations. It rejects
  inconsistent requirements and never conflates scratch output with staging.
- `receiver::programming` validates both arms of the legacy application's range
  selection, including MMIO, branch destinations, distinct RAM cells, subtraction
  and join. The real INTM test follows those cells into call `0x9d69c` to
  `0x140a5a`: r0 and r1 are the selected start, r2 is `0x200000 - start`, and r3
  is mode 3. The wrapper forwards those cells to its flash routine at `0x17000`;
  its complete effects and the intervening control flow still require proof.
  It also checks the complete conditional boot-CMAC/application-CMAC selection
  block at `0x9d618`, binding calls `0x140886` and `0x1408a4`, application mask
  one, and both success/error continuations. Operand/branch mutations are tested
  against the real image.
  The shared-load range-selection compiler form also matches 1.V9. Both held
  INTM applications match the legacy form. `inspect_plain_signature` binds the
  range-selection join through every instruction of the direct staged signature
  loop, including bounds guards, RAM cells, installed address, eight-byte loop
  and mismatch continuation. It proves no decoder intervenes in that specific
  segment; earlier stream effects remain a separate obligation. It matches 16
  images in the current inventory.
- `decoding_corpus` checks real INTM/V9 call arguments and inventories every file
  under `images/mediatek`, retaining all rows without hash deduplication. Its AES
  call counts are discovery evidence, not encoding-combination support counts.

## Offline INTM candidate result

The mixed candidate test encrypts only `0x3000..0x3010` of the held 1.V9 image.
The scratch header matches held INTM; staged signature, tag and marker match;
the DE byte is present; application CMAC passes. Applying the two disassembled
program spans to the held INTM image preserves boot and reserved areas and
produces an image whose application CMAC and retained boot CMAC pass.

The candidate's staged boot CMAC fails, as expected: boot preservation is a
necessary part of this candidate, not an optional optimization. Adding boot
validation to the layout constraints rejects it at block `0x3000`. This test
does not emulate the complete receiver and does not authorize production use.

The held BH16NS40 entry test additionally binds the flag-copy grammar and
mode-six stream guard to the registered WRITE BUFFER callback `0x9cd6c`.
Changing the flag CDB-byte load invalidates that evidence independently of the
decoder. The complete stream-to-header and completion paths still need proof.

## Independent instruction execution

The header path now executes `0x9d478..0x9d4f4`, substituting only the AES
primitive (OpenSSL) and diagnostic output. All four header/body combinations
are tested under both flag values. Only an encrypted 16-byte header is accepted;
the source staging bytes remain unchanged. For the actual banner, both `0x0b`
and `0x0a` remain unchanged by the header path, confirming that the space at
index six skips boot-bit clearing. This is eight header-path cases, not eight
supported receiver formats or evidence of whole-hoard acceptance.

`tests/support/emulate_intm.py` executes the actual held INTM Thumb instructions
with Unicorn 2.1.4. It reads hash-checked fixtures from `MTK_HOARD_ROOT`; OpenSSL
constructs the ciphertext independently of the Rust encoder and its SHA-256 must
match the original failed upload. Run it in a Python environment with Unicorn:

```sh
MTK_HOARD_ROOT=/path/to/hoard python tests/support/emulate_intm.py
```

The range-selection/signature segment rejects full ciphertext at `0x9d602` with
either flag value (`0x0b` or `0x0a`). The mixed candidate reaches `0x139938` in both
cases. Execution stops there, before the opaque verifier; this is deliberately
not reported as acceptance. Earlier header handling is outside this run.

A second execution runs the wrapper `0x139938`, its actual staging-relative
copy helper `0xa2178`, and its big-endian word writer `0xa1f72` until secure
dispatch `0xca62c`. The staged descriptor at `0x10610` supplies payload offset
`0x14000` and length `0xc00`. The wrapper copies that payload to staging
`+0x220010`, and 40 bytes at `0x10618` to staging `+0x230000`; it writes the length
and metadata-next pointer into the request at staging `+0x220000` and dispatches
service `0x72`. Both request payload and metadata are byte-identical for held
INTM and the mixed 1.V9 candidate. The script compares independently executed
request buffers, not just host-selected source ranges. The service dispatcher
eventually enters an encrypted code region; its implementation and return value
are not emulated or assumed successful by this test.

The real programming-loop arithmetic executes with diagnostic/watchdog and
hardware erase/program operations summarized. It produces 33 writes from zero,
or 32 from `0x10000`, preserving exactly the two observed reserved regions.
Both mutated skip thresholds violate the independently expected write spans.
The output artifact is `target/intm-execution-evidence.json`. This is stronger
than a host-side range reconstruction but is not full device emulation.

`inspect_reserved_skips` now operand-checks every instruction in the two skip
branches. Its r7/r6/r5 pointer bindings and r4=64KiB precondition remain explicit
obligations; the component alone never authorizes a transfer.

Current discovery inventory: 2,048 physical files, comprising 1,024 metadata
files and 1,024 binary images. Of the binaries, 179 are within the two-megabyte
discovery scope and 845 are outside it. No complete receiver-contract count or
production-supported encoding-combination count is asserted by this inventory.

## Remaining completion gates

### Latest verification checkpoint

Website baseline reconciliation: the current marketing finder builder returns
exactly 100 MediaTek model/version listings. Its MediaTek catalog contains 130
distinct packages with 136 distinct binary members; every package and member
is represented in the private receiver census. The emitted baseline artifact
is `target/website-mtk-baseline.json`, including all package/member hashes.
The public finder also currently displays 100 MediaTek listings. These are
different counting units, not lost support or newly added firmware.

The combined `acceptance_path` execution covers header handling through the
programming call. It executes the real CMAC-table iteration and boot-CMAC
selection, tag/marker comparison and DE-byte branch. AES/CMAC primitives use
OpenSSL; hardware setup and diagnostics have explicit summaries. The opaque
verifier return is a test parameter, exercised as both failure and success:

| Upload | Boot flag | Secure verifier | Outcome |
| --- | --- | --- | --- |
| Full ciphertext | Either | Either | Signature rejection at `0x9d602` |
| Mixed | Either | Failure | Rejection at `0x9d602` |
| Mixed | Write boot | Success | Boot CMAC rejection at `0x9d632` |
| Mixed | Preserve boot | Success | Four application CMAC checks pass; mode-3 programming call receives start `0x10000`, length `0x1f0000` |

This is conditional execution evidence, not a fabricated success result for the
encrypted verifier or proof that unmodeled hardware setup is irrelevant.

Input validation now runs on every one of the 1,024 binary files, with hash/name
binding and an individual result in `target/decoding-discovery.json`:

- 136 valid plaintext input envelopes.
- 3 drive captures, refused as installable input.
- 40 unsupported framing (37 MT1869, 2 MT1839, 1 MT1939 by hoard directory).
- 845 unsupported sizes; retained explicitly, not omitted or counted as passes.

These input-format counts are distinct from receiver transfer combinations.
All 110 unit tests and the nonignored integration/doc tests pass; the three
private decoding-corpus tests pass when run explicitly. Clippy passes with
warnings denied. Production transfer preparation remains unchanged.

1. Bind argument evidence to reachable WRITE BUFFER handlers and complete paths.
2. Establish all decoder ranges/keys, validation order, update flags and write
   ranges, including both boot policies and compiler variations in the hoard.
3. Derive operations once in the loaded receiver and retain their code evidence.
4. Make Flash and Recovery use the resulting plan and revalidate its binding.
5. Replace tests that accept header-only evidence for whole-image encryption.
6. Audit all normalized firmware and account separately for metadata, source
   containers, unsupported architectures and analysis failures. Report actual
   proven combinations, not combinations inferred from AES call counts.
7. Run crate/application gates. Hardware behavior remains a separate verification
   boundary; no drive has been flashed by this work.

## Follow-up: branch islands and executor boot policy

The published UH12NS40 1.03 receiver (eeb1c948…765ba) has a literal island
between range-selection arms: selection 0xa773c, alternate 0xa77c8, join
0xa77d6, body AES call 0xa77ec. Selection recognition now follows the checked
conditional/unconditional branch destinations. A public synthetic regression
covers adjacent and split arms, changed branch destinations/stores/subtraction,
and arbitrary non-executable island bytes. The stronger private live-detection
suite passes all 272 published receiver/mode cases: 15 application receivers
have independently traced bulk AES calls and 2 have scratch-header evidence.
These are decoder evidence counts, not complete-contract counts.

PREPARE now represents boot-preserving variants of both entry dialects (byte
nine 0x0a). Shared executor tests cover both policies, both modes, and refused
PREPARE; Recovery continues once while Flash stops. Automatic plan selection
has NOT enabled either preserving variant or mixed encoding yet.

Latest validation: 112 library unit tests pass; all-target/all-feature Clippy
passes with warnings denied. No hardware I/O was performed.

### Programming-wrapper execution binding

The offline programming test now enters the actual wrapper at 0x140a5a with
r0/r1 = selected start, r2 = selected length, and r3 = mode 3. Destination,
source and length cells begin poisoned (0xdeadbeef). Actual wrapper instructions
must initialize them before reaching 0x17000; the test checks all three there.
The real loop then loads its own pointers and block size. Both start-zero and
boot-preserving paths retain the previously established spans (33/32 writes).
Six mutations to wrapper argument copies/stores are rejected, in addition to
the two reserved-threshold mutations. IRQ/hardware setup, device-present probe,
flash-loop hardware initialization, diagnostic/watchdog and erase/program I/O
remain explicit summaries; this is not full hardware emulation. The latest
emulation run passes and records those summaries in intm-execution-evidence.json.

### Cached acceptance continuation

`programming::inspect_acceptance_tail` now validates the exact success-path
instructions and branches from integrity success through the mode-three call:
nonzero tag helper, staged 0x1ec056 == 0xDE, nonzero marker helper, failure-state
byte guard, selected length/start loads, source via r4, and mode-three argument.
The common error continuation and helper targets are retained. The analysis
caches a unique matching tail against its selection/signature facts; conflicting
matches mark ambiguous evidence. Actual INTM resolves to tag 0x9ccba, marker
0x9cc90, program call 0x9d69c -> 0x140a5a, error 0x9d094. Mutations to each checked
branch/operand reject the tail. This does not yet prove helper semantics,
incoming r4/r7 binding, or reachability from the signature-success continuation;
those obligations remain explicit, and it does not authorize mixed transfers.


## Production integration

Flash and Recovery now use the same receiver-bound transfer plan. The plan
exposes header and body encodings separately. Application whole-image AES
requires positive argument-bound scratch-header and in-place-body calls;
header-only evidence cannot select whole-image encryption.

The two held INTM application compiler forms use a bounded complete-handler
instruction signature plus explicit flag-copy/registration binding. Their
programming wrapper, conditional boot-CMAC helper, programming loop and raw
staging-byte copy helper are checked as well. These are instruction signatures,
not model/version/filename or firmware-hash decisions. Unknown or changed
forms fail closed. Receiver-specific programmed ranges are derived from the
matched skip operands: one form preserves from 0x1d0000, the other from
0x1c8000, both resuming at 0x1ec000 and stopping at 0x1f0000.

A mixed plan encrypts exactly 0x3000..0x3010 and selects PREPARE byte nine 0x0a.
Its active CMAC intervals must lie in programmed ranges and remain plaintext.
The required descriptor marker must already be DE; no blanket marker rewrite
is introduced. The held V9 target 97b28707… has DE already. The source Envelope
and canonical image remain unchanged. Flash retains strict PREPARE errors;
Recovery logs and continues once, with no retry or alternative encoding.

Public receiver APIs now accept explicit metadata-bound Current references and
can prepare the next stage from a loaded Envelope before the first stage is
written. Reference provenance and SHA-256 are retained; physical INQUIRY,
banner and descriptor are revalidated at execution. Reference code never
replaces physical post-write reads. An explicit unavailable-installed path
retains chip/input checks without inventing installed bytes from the target.

Both execution paths require exact target startup and return full/limited
readback quality. Ready status alone, BOOT, old INTM, a different build, or
unreadable startup metadata cannot produce a completed target result. A data
write failure or mismatching readback triggers no subsequent startup probes.

The secure service remains opaque, and hardware programming is not emulated.
These bounds are not a claim that every target is accepted or that a physical
INTM-to-V9 update has succeeded. The real-image regression establishes the
actual prepared bytes for the held target, and the independent instruction
execution retains its explicit secure-return/hardware summaries.

The published receiver gate now passes all 136 binary members in both BOOT and
application mode (272 receiver states), constructing **both Flash and Recovery**
plans for each. Actual combinations: 234 plaintext header/plaintext body, 36
AES header/AES body, and two AES header/plaintext body. No plaintext-header/AES-
body receiver was found in this held published set. Individual SHA-256/mode/
format/PREPARE records are written to `target/receiver-transfer-coverage.json`.
This preserves the 100 website model/version listings; listing, package, binary,
and receiver-state counts are intentionally different units.

Remaining bulk-AES evidence boundary: the application plan checks the traced
start-zero in-place decoder's exact 2 MiB arguments and selects PREPARE 0x0b.
The held-image preparation census is not a proof that every arbitrary
cross-image header branch leaves bit zero set. The recorded boot-preserving
bulk call starts at 0x10000 with a 2 MiB footprint; this work does not silently
clip or claim that alternative path is supported. No failing held pair has
been demonstrated for this residual general-acceptance question.

### Final regression checkpoint

- All ordinary all-target/all-feature tests, doc tests, Clippy with warnings
  denied, rustfmt, and no-default feature combinations pass.
- The four private decoding tests, five entry-corpus tests, published-envelope
  corpus, 124 hash-pinned OEM facts, legacy receiver corpus, and hoard chip check
  pass. The private mixed-form mutation test passes for both held INTM variants.
- The historical 298-file `family_corpus` dataset is unavailable locally. That
  optional test and its expectations are unchanged; its default no-op is not
  counted as historical-corpus evidence. Family code was not modified here.
- The legacy `receiver_corpus` report stores paths beginning with `hoard/`, so
  its `MTK_HOARD_ROOT` must name the firmware-extractor repository. The newer
  decoding corpus uses the hoard directory itself. An initial combined run hit
  this fixture-root difference; the legacy suite passed with its correct root.

### Capture reuse and receiver chip binding

The encoding detector and entry analyzer now consume the same immutable code
window captured once. Finishing detection checks physical INQUIRY and the small
matched signature; it does not immediately repeat the full snapshot capture.
Execution still re-reads every snapshot from the physical transport before any
update-session command. The temporary analysis source cannot escape into the
stored Receiver or execution. The application test fixture now performs 560
one-KiB code/table reads during detection, with no extra 1088-byte scan; the
mandatory execution check performs those 560 reads again.

The captured boot banner supplies the receiver chip as well. Even an update
already validated against another drive cannot bind across MT1939/MT1959.
Regressions cover read counts, a changed signature during capture, a changed
byte at the end of the registration snapshot, and cross-chip prepared binding.

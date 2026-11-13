# Moving between the optical libraries

Both libraries use the same workflow: identify the device, inspect its installed
firmware, prepare a target against that evidence, execute through a caller-owned
transport, and inspect the verification result. Each library owns its vendor's
protocol; host applications own device discovery, backups, consent, tray policy,
exclusive access and durable reporting.

| Developer task | Pioneer | MediaTek |
| --- | --- | --- |
| Core protocol | `cdb`, `Identity`, `DriveClass` | `cdb`, `Identity`, `DriveClass`, `Chip` |
| Structured product identity | `ProductIdentity` | `ProductIdentity` |
| Report progress and categories | `operation::{IssueKind, Phase, Component, Progress}` | `operation::{IssueKind, Phase, Component, Progress}` |
| Enable the update workflow | features `drive` + `envelope` | features `drive` + `envelope` |
| Connect an adapter | `drive::Transport`, `drive::Data` | `drive::Transport`, `drive::Data` |
| Read live identity | `drive::identify` | `drive::identify` |
| Read memory | `drive::read_memory` (returns bytes read; short reads allowed) | `drive::read_memory` (exact; a short read is `Error::Short`) |
| Load firmware | `envelope::Envelope::load` | `envelope::Envelope::load` |
| Read a receiver from a firmware file (no I/O) | `Receiver::from_firmware` | `Receiver::from_firmware` |
| Bind installed evidence | `Receiver::from_installed` with a captured Kernel/Normal pair | `InstalledFirmware::new`, `drive::detect_receiver` (live code) or `drive::detect_receiver_with_current` (Current reference) |
| Check hardware family | `Receiver::check_family` | `classify::check`, `InstalledFirmware::family` |
| Prepare an update | `Receiver::prepare` → `PreparationError` | `Receiver::prepare` → `PreparationError` |
| Check a plan before consent (no I/O) | `PreparedUpdate::check_plan(mode)`, `PreparedNormal::check_plan` → `PlanError` | — (`Receiver::prepare` / `drive::RecoveryReceiver::prepare` refuse; a prepared value has passed every I/O-free check) |
| Execute with complete verification | `PreparedUpdate::flash` | — (use `flash_completed`) |
| Execute with explicit limited readback | `PreparedUpdate::flash_completed` → `FlashOutcome`, `ExecutionError` | `PreparedUpdate::flash_completed` → `FlashOutcome`, `ExecutionError` |
| Supply read/write transports | `drive::` | `drive::` |
| Supply timing and host callbacks | `drive::` | `drive::` |
| Report unreadable readback | `ExecutionRuntime::verification_unavailable` | `ExecutionRuntime::verification_unavailable` |
| Select explicit recovery | `execute(..., ExecutionMode::Recovery)` | `drive::PreparedRecovery` |
| Route typed errors | Root `CodedError`, `pioneer.*` codes | Root `CodedError`, `mediatek.*` codes |

The transport trait has the same `exec` and `sense` signatures in both crates.
An application that supports both can adapt one underlying SCSI pass-through to
the two traits without putting operating-system code into either library.
Identity accessors use the same `vendor`, `product`, `revision` and raw-response
conventions. Firmware formats differ: Pioneer normally updates separate Kernel
and Normal components; MediaTek validates one complete 2 MiB image.

Error codes are `<crate>.<group>.<variant>` with the verb groups `prepare`,
`execute` and `flash` in both crates. `kind()` on every error is the
`CodedError` `IssueKind`; a typed refusal rule is a `reason` (`PlanReason`,
`ContractReason`). Execution wrappers report their cause's code, so the same
failure has the same code whether it is reached directly or through execution.
Public error enums are `#[non_exhaustive]`; handle unknown future codes.

Pioneer `flash` requires complete relevant readback. A Normal-only Pioneer update does
not write or verify a Kernel. MediaTek has one execution entry point:
`flash_completed` requires the target
identity after the write and reports restart evidence through
`Startup::evidence()`, which hosts must check (`Unobserved` is not confirmed
startup); it retains limited readback explicitly; every readable mismatch and failed
firmware write remains an error. Readiness alone is insufficient. Callers must
report the qualification and must not retry firmware writes automatically.

Pioneer chooses the execution mode at execute time and defers some plan-level
checks, so `check_plan` lets a host decide admissibility before backup or
consent. A MediaTek prepared value has already passed every I/O-free check and
its mode is fixed at construction; there is nothing left to check without I/O.

File decoding never authorizes a device write. Unknown or conflicting receiver
evidence fails closed, and executable preparation is bound to installed evidence.
Explicit recovery or unavailable-installed paths do not establish facts that
could not be observed. The libraries expose these differences through types and
results rather than treating a model string or input filename as authority.

Both repositories share the README outline, compiled integration examples,
feature-matrix checker, MSRV/no_std checks, package verification and publication
gates. See each repository's README, protocol guide and release audit for details.

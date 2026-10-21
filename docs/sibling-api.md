# Moving between the optical libraries

Both libraries use the same workflow: identify the device, inspect its installed
firmware, prepare a target against that evidence, execute through a caller-owned
transport, and inspect the verification result. Each library owns its vendor's
protocol; host applications own device discovery, backups, consent, tray policy,
exclusive access and durable reporting.

| Developer task | Pioneer | MediaTek |
| --- | --- | --- |
| Core protocol | `cdb`, `Identity`, `DriveClass` | `cdb`, `Identity`, `DriveClass`, `Chip` |
| Connect an adapter | `drive::Transport`, `drive::Data` | `drive::Transport`, `drive::Data` |
| Read live identity | `drive::identify` | `drive::identify` |
| Read memory | `drive::read_memory` | `drive::read_memory` |
| Load firmware | `envelope::Envelope::load` | `envelope::Envelope::load` |
| Bind installed evidence | `Receiver::from_installed` with a captured Kernel/Normal pair | `InstalledFirmware::new` and `receiver::detect` against live code |
| Prepare an update | `Receiver::prepare` | `Receiver::prepare` |
| Execute with complete verification | `PreparedUpdate::flash` | `PreparedUpdate::flash` |
| Execute with explicit limited readback | `PreparedUpdate::flash_completed` → `FlashOutcome` | `PreparedUpdate::flash_completed` → `Completion` |
| Supply read/write transports | `receiver::FlashTransport` | `update::FlashTransport` |
| Supply timing and host callbacks | `receiver::ExecutionRuntime` | `update::FlashRuntime` |
| Select explicit recovery | `execute(..., ExecutionMode::Recovery)` | `recovery::PreparedRecovery` |
| Route typed errors | Root `CodedError`, `pioneer.*` codes | Root `CodedError`, `mediatek.*` codes |

The transport trait has the same `exec` and `sense` signatures in both crates.
An application that supports both can adapt one underlying SCSI pass-through to
the two traits without putting operating-system code into either library.
Identity accessors use the same `vendor`, `product`, `revision` and raw-response
conventions. Firmware formats differ: Pioneer normally updates separate Kernel
and Normal components; MediaTek validates one complete 2 MiB image.

`flash` requires complete relevant readback. A Normal-only Pioneer update does
not write or verify a Kernel. `flash_completed` requires confirmed target startup
and retains limited readback explicitly; every readable mismatch and failed
firmware write remains an error. Readiness alone is insufficient. Callers must
report the qualification and must not retry firmware writes automatically.

File decoding never authorizes a device write. Unknown or conflicting receiver
evidence fails closed, and executable preparation is bound to installed evidence.
Explicit recovery or unavailable-installed paths do not establish facts that
could not be observed. The libraries expose these differences through types and
results rather than treating a model string or input filename as authority.

Both repositories share the README outline, compiled integration examples,
feature-matrix checker, MSRV/no_std checks, package verification and publication
gates. See each repository's README, protocol guide and release audit for details.

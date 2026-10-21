# mediatek-optical

[![CI](https://github.com/MattJackson/mediatek-optical/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MattJackson/mediatek-optical/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/mediatek-optical.svg)](https://crates.io/crates/mediatek-optical)
[![docs.rs](https://img.shields.io/docsrs/mediatek-optical)](https://docs.rs/mediatek-optical)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

A Rust library for working with **MediaTek MT1959/MT1939 BD/DVD optical drives**
and their firmware. It encodes vendor SCSI commands, decodes drive identity,
checks firmware integrity, reconstructs OEM images from drive reads, and
prepares and executes receiver-bound firmware updates.

Use it to build drive utilities, firmware inspection tools, backup workflows,
or update applications. You provide the operating-system SCSI transport; the
library supplies protocol logic and typed results.

Its sister library, [`pioneer-optical`](https://github.com/MattJackson/pioneer-optical),
uses the same transport conventions and development workflow. See the
[sibling API map](docs/sibling-api.md) when moving between them. Both have a
**dependency-free `no_std` core**, an allocation-free `drive` feature, optional
firmware analysis, and typed update preparation and verification.

## Install

```toml
[dependencies]
mediatek-optical = { version = "1.0", features = ["drive"] }
```

Rust **1.75 or newer** is required. The default build has no enabled features.
Enable `drive` for live commands, or select the analysis features below for
working with files without connecting a drive.

## Identify a drive

Pass an existing transport to `drive::identify`. This example reads identity
without entering update mode or changing settings:

```rust,no_run
use mediatek_optical::{drive, Identity};

pub fn identify<T: drive::Transport>(
    transport: &mut T,
) -> Result<Identity, drive::Error<T::Error>> {
    let identity = drive::identify(transport)?;
    println!("{} {} {}", identity.vendor(), identity.product(), identity.revision());
    Ok(identity)
}
```

Implement `drive::Transport` for your SCSI pass-through adapter. Its `exec`
method receives the command bytes and a `drive::Data` value describing the data
phase, then returns the actual transferred byte count. `sense` exposes the
most recent failed command's sense triplet. Preserve `Data::None`, `Data::In`
and `Data::Out` exactly, including zero-length data-out commands. Do not retry
firmware writes automatically.

The library handles command construction and bounded transfers. Your application
opens the device, supplies timeouts and exclusive access, and persists backups.
`drive::read_memory` reads into a caller-owned buffer; firmware-derived layouts
and protocol bounds determine which addresses are meaningful.

## Choose features

| Feature | Use it for | Environment |
| --- | --- | --- |
| none | `cdb`, `Identity`, controller types and protocol constants | `no_std`, no allocation |
| `drive` | Identification, reads and command sequences over `Transport` | `no_std`, no allocation |
| `image` | Controller detection, hardware families and AES-CMAC integrity | `std` |
| `enc` | Low-level AES-128-ECB transport encoding | `no_std`, no allocation |
| `oem` | Reconstruct OEM images from drive reads with byte provenance | `std`; includes `image` |
| `std` | Standard-library error integration without firmware features | `std` |

Enable both `image` and `enc` for `envelope`; add `drive` for receiver-bound
execution and recovery. Operational controller detection uses the boot banner;
identity tags are retained as labels and never override that result.

## Inspect firmware files

Enable `image` and `enc`. Loading recognizes plaintext or encrypted input,
checks integrity and retains the original and canonical-image hashes:

```rust,no_run
use mediatek_optical::envelope::{Envelope, Error};

pub fn inspect(bytes: &[u8]) -> Result<(), Error> {
    let envelope = Envelope::load(bytes)?;
    println!("{}: {} bytes", envelope.chip(), envelope.image().len());
    Ok(())
}
```

The supported image is exactly 2 MiB with a recognized controller banner and a
nonempty valid AES-CMAC table. Raw drive reads need reconstruction before they
can be loaded as stored update images. With `oem`, `oem::rebuild` uses a
caller-supplied factory catalog and reports the provenance of substituted bytes.
Loading or reconstruction does not authorize a device write.

## Prepare and execute an update

Enable `drive`, `image` and `enc`. Bind captured **installed** firmware to live
identity, detect the active receiver, then prepare the target separately:

```rust,no_run
use mediatek_optical::{drive, envelope::Envelope, receiver, update::InstalledFirmware};

pub fn prepare<T: drive::Transport>(
    transport: &mut T, current_image: &[u8], target_image: &[u8],
) -> Result<receiver::PreparedUpdate, Box<dyn std::error::Error>>
where T::Error: 'static,
{
    let identity = drive::identify(transport)?;
    let installed = InstalledFirmware::new(identity, current_image)?;
    let mode = receiver::detect_mode(transport)?;
    let receiver = receiver::detect(transport, &mode)?;
    let target = Envelope::load(target_image)?;
    Ok(receiver.prepare(&target, &installed)?)
}
```

Detection reads the receiver. Preparation validates integrity, controller and
hardware-family compatibility without writing, and builds an immutable entry and
encoding plan. Execution revalidates before writes; file encoding never chooses
the transfer encoding. Unknown or conflicting contracts are errors.

`PreparedUpdate::flash` requires complete protected-region readback.
`flash_completed` returns a `Completion` with exact target-startup evidence and
explicit complete or limited `ReadbackQuality`. Every readable mismatch and
failed data write remains an error. `recovery::PreparedRecovery` is the explicit
recovery path and still requires confirmed target startup.

[examples/flash.rs](examples/flash.rs) provides a compiled host integration with
`FlashRuntime` and `FlashTransport`. Its executable does not access hardware.
Low-level `drive::Session` is a protocol primitive and does not supply the
complete update procedure. Explicit unavailable-installed and Current-reference
paths retain their evidence limitations; see the [protocol guide](docs/protocol-guide.md).

Before execution, the host must capture a backup, obtain the required consent,
check tray conditions, and ensure both transports address the same physical
drive exclusively. Interrupted or incompatible firmware writes can make a drive
unusable. No hardware writes are performed by the examples or test suite.

## Handle errors

Import `mediatek_optical::CodedError` for stable machine-readable identifiers:

```rust
use mediatek_optical::CodedError;
use mediatek_optical::drive::Error;

let error = Error::<()>::Short { expected: 36, actual: 8 };
assert_eq!(error.code(), "mediatek.drive.short");
```

Use codes for translation or routing, match typed variants for parameters, and
preserve nested causes in diagnostics. English `Display` wording is not a
parsing contract. Handle unknown future codes and non-exhaustive enums.

## Develop and test

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
python3 .github/scripts/check-features.py test
python3 .github/scripts/check-features.py doc
```

The Python checks require Python 3.11+. CI exercises every distinct feature
configuration, Rust 1.75 library builds, bare-metal `no_std`, doctests and packaged
sources before publication. README Rust examples are compiled by doctests with
their required features enabled.

Firmware corpus tests require external, hash-pinned files; skipped or unavailable
inputs are not counted as passes. See [tests/OEM_FACTS.md](tests/OEM_FACTS.md), the
[protocol guide](docs/protocol-guide.md), and [release audit](RELEASE.md) for
reproduction and evidence limits. Simulated transports and offline firmware
analysis do not certify physical programming or power-loss recovery.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).

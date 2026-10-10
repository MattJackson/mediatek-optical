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
mediatek-optical = { version = "0.1", features = ["drive"] }
```

| Module | Feature | Contents |
|---|---|---|
| `cdb` | — | CDB constructors and field constants |
| `Identity` | — | Decoded INQUIRY, boot banner and identity descriptor; `chip()` |
| `Chip` | — | `Mt1959` / `Mt1939`, from an identity tag or banner |
| `layout` | — | 2 MiB image geometry; boot page, boot mirror, drive-written regions |
| `sense` | — | Sense parsing; flash-fault and no-medium classification |
| `drive` | `drive` | `Transport` trait; `identify`, `read_memory`, `feature`, `enter_update` → `Session` |
| `image` | `image` | `detect_chip`, `is_uhd`, `is_drive_read`; `cmac` verify / resign |
| `enc` | `enc` | AES-128-ECB transport envelope |
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
use mediatek_optical::{cdb, drive};

struct Sg(/* your pass-through */);

impl drive::Transport for Sg {
    type Error = std::io::Error;
    fn exec(&mut self, cdb: &[u8], data: drive::Data<'_>) -> Result<usize, Self::Error> {
        /* issue `cdb`; fill or send `data` */
    }
    fn sense(&self) -> Option<(u8, u8, u8)> { /* last sense */ }
}

let id = drive::identify(&mut t)?;
let chip = id.chip().expect("not an MT19xx drive");
let mut session = drive::enter_update(&mut t)?;
for (i, chunk) in image.chunks(cdb::CHUNK).enumerate() {
    session.write((i * cdb::CHUNK) as u32, chunk)?;
}
session.finish()?;
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
| Status | `cdb::request_sense()` | `03 00 00 10 80 00 00 00 00 00 00 00` |

The drive erases and programs flash when the last chunk of a complete 2 MiB
image lands. The commit is a trailing handshake.

## Safety

An update session writes drive firmware. A wrong image, or an interrupted
session, can leave the drive unusable. Verify an image with `image::cmac`
before flashing. The identity, feature and memory-read commands are read-only.

## Minimum supported Rust version

1.75.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).

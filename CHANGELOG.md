# Changelog

All notable changes to `mediatek-optical` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

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

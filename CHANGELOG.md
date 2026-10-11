# Changelog

All notable changes to `mediatek-optical` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

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

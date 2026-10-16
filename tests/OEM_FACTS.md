# Firmware-derived regression evidence

These tests use firmware bytes and OpenSSL, not this crate's generated output,
as their expected results. No firmware is flashed. No full firmware is bundled.

## Sources and limits

`support/oem_manifest.json` pins 124 complete 2 MiB images from the local hoard's
MT1939/MT1959 directories, excluding entries marked patched or fragmented.
Each row includes the image SHA-256, relative path, and source provenance.
71 have an OEM installer (`.exe`) in their extraction provenance; 53 are
supplementary standalone images, **not independently established OEM originals**.
Directory labels alone are not accepted as hardware evidence.

The image `961b6e23a0d110039529602a0a6783e89ae7913688c27c21cf11b808bf81a879`
has the literal banner `12B2S  Boot Code`, not MT1939/MT1959, and an enabled CMAC
record with start=end=0xffffffff. Detection and integrity verification must
reject it under this library's MT19xx format. It is not evidence of broken
firmware; the format is outside the supported interpretation.

Three standalone images (`40118f8171daf03e…`, `5e2ec51fb3559623…`,
`d286c5a7ea4a4d07…`) have identical bytes at 0..0x400 and 0x10000..0x10400.
The WH16NS60 provenance explicitly includes a drive dump. These exercise the
mirrored-readback/factory-template rejection path, not stock-file acceptance.
A valid CMAC does not establish a stored factory boot page.

## Added coverage

* 124 individually named corpus tests; missing input is an error when invoked.
* Raw boot banners and descriptor records, hash-pinned before use.
* Every active table record at 0x10400 (16 records, `<III16s`, 28 bytes each):
  enabled flag, inclusive start/end, and stored tag. 493 valid tags and one
  invalid range. Tags are checked against both OEM bytes and OpenSSL output.
* First/last authenticated bytes must affect the digest; adjacent outside bytes
  must not. This catches inclusive-end and wrong-span errors.
* Re-signing each of 123 valid images is byte-exact. A changed data range is
  independently re-signed using OpenSSL, data tags before table-covering tags;
  the entire resulting SHA-256 is pinned. This tests ordering and byte order.
* Full-image AES-128-ECB encryption matches OpenSSL, and decryption restores
  all bytes. This establishes the codec under the documented transport key;
  it does **not** establish which drives require encrypted transport.
* Cataloging/rebuilding an unchanged stored image preserves every byte.
  Mirrored images cannot supply a factory template. This does not simulate
  or prove drive-read remapping or per-unit preservation on hardware.
* 73 unique small OEM integrity-table/data records are checked in as hex known
  answers, with source image hashes and offsets. They contain no executable
  firmware. Their stored OEM tags are checked without a corpus dependency;
  changing every individual byte must invalidate its tag.

The independent script uses standard OpenSSL AES-CMAC over each OEM range with
16-byte blocks reversed, then reverses the output tag. Agreement with **stored**
tags is the evidence for that recipe. It does not call this Rust library.

## Reproduce

```sh
python3 tests/support/audit_oem.py "$HOARD" tests/support/oem_manifest.json
cargo test --all-features --test oem_cmac_vectors
MEDIATEK_OEM_HOARD="$HOARD" cargo test --all-features --test oem_facts -- --ignored
```

The audit script is for explicit evidence regeneration, not an automatic golden
update during tests. Review manifest changes against source provenance.

## Remaining evidence gaps

Existing command and simulated flash tests cover CDB bytes and error paths.
This change adds no claim that those simulations prove erase/program timing,
power-loss recovery, per-unit-region preservation, or encrypted-route selection.
Those require an independently captured OEM transaction/drive read pair or
receiver control-flow proof. Likewise, family/crossflash safety cannot be proved
merely from matching names, boot banners, or hashes. Wrong-sized, patched,
fragmented, and other chipset images are outside this new integrity corpus.

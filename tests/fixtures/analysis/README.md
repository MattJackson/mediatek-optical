# OEM instruction excerpts

Small read-only instruction/literal-pool excerpts for the shared hook recognizers.
These are not complete firmware or flashable backups. `sources.json` records the
original full-image SHA-256, source offset and leading padding. Padding preserves
the source PC alignment so Thumb literal addressing remains unchanged.

The full source images are held in the firmware-extractor hoard; BU40N 1.00 and
WH16NS58 1.V9 also have committed full-image integration fixtures in
freemkv-firmware. Register variants are selected by code evidence, never these
filenames or hashes.

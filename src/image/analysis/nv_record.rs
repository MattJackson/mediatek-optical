//! Native sixteen-byte NV-record copy. No write policy or settings allocation.
use super::{matches, Error, SavedLink};
use thumb_asm::analysis::literal_value;

/// A native flash record copied through two DRAM-window cells.
#[derive(Debug, Clone)]
pub struct NvRecordCopy {
    /// Native LR-saving routine entry.
    pub entry: usize,
    /// Flash address loaded into the source register.
    pub record: u32,
    /// Constant destination offset added to the live window offset.
    pub destination_offset: u32,
    /// SRAM cell containing the DRAM base.
    pub base_cell: u32,
    /// SRAM cell containing the live DRAM-window offset.
    pub offset_cell: u32,
    /// Source-bound native frame and balanced return proof.
    pub caller: SavedLink,
}
impl NvRecordCopy {
    /// Recognize the complete native copy loop and bind its source/destination.
    /// Refuse ambiguous copies, unknown pointers and altered loop semantics.
    pub fn detect(image: &[u8]) -> Result<Self, Error> {
        let pattern = [
            (0xb5f0, 0xffff),
            (0x4f00, 0xff00),
            (0x4e00, 0xff00),
            (0x4d00, 0xff00),
            (0x4c00, 0xff00),
            (0x2000, 0xffff),
            (0x5c32, 0xffff),
            (0x682b, 0xffff),
            (0x19c1, 0xffff),
            (0x1859, 0xffff),
            (0x6823, 0xffff),
            (0x0209, 0xffff),
            (0x0a09, 0xffff),
            (0x1c40, 0xffff),
            (0x0600, 0xffff),
            (0x18c9, 0xffff),
            (0x0e00, 0xffff),
            (0x2810, 0xffff),
            (0x700a, 0xffff),
            (0xd3f1, 0xffff),
            (0xbdf0, 0xffff),
        ];
        let mut found = None;
        for entry in (0..image.len().saturating_sub(42)).step_by(2) {
            if !matches(image, entry, &pattern) {
                continue;
            }
            let read = |at| literal_value(image, at).ok_or(Error::InvalidContract);
            let destination_offset = read(entry + 2)?;
            let record = read(entry + 4)?;
            let offset_cell = read(entry + 6)?;
            let base_cell = read(entry + 8)?;
            if record as usize + 16 > image.len()
                || (record as usize) < image.len().saturating_sub(0x40000)
                || record & 0xfff != 0x4b0
                || !(0x01ff0000..0x02010000).contains(&base_cell)
                || offset_cell != base_cell + 4
                || base_cell & 3 != 0
                || destination_offset >= 0x1000000
            {
                continue;
            }
            let caller = SavedLink::detect(image, entry + 12)?;
            if caller.entry() != entry || caller.stack_bytes() != 20 {
                return Err(Error::InvalidContract);
            }
            let value = Self {
                entry,
                record,
                destination_offset,
                base_cell,
                offset_cell,
                caller,
            };
            if found.replace(value).is_some() {
                return Err(Error::Ambiguous);
            }
        }
        found.ok_or(Error::UnknownLayout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut b = vec![255; 0x200000];
        b[0x196c00..0x196d00].copy_from_slice(include_bytes!(
            "../../../tests/fixtures/analysis/nv-record-copy-3f436c31.bin"
        ));
        b
    }
    #[test]
    fn native_record_copy_binds_populated_record_without_default_tag() {
        let mut b = fixture();
        b[0x1ea4b0..0x1ea4b3].copy_from_slice(&[1, 4, 4]);
        let c = NvRecordCopy::detect(&b).unwrap();
        assert_eq!(
            (c.entry, c.record, c.destination_offset),
            (0x196c24, 0x1ea4b0, 0xc5a0)
        );
        assert_eq!((c.base_cell, c.offset_cell), (0x02000df0, 0x02000df4));
        let mut bad = b.clone();
        bad[c.entry + 34] ^= 1;
        assert!(NvRecordCopy::detect(&bad).is_err());
        let mut bad = b.clone();
        bad[0x196ca4..0x196ca8].copy_from_slice(&0x1ea4b1u32.to_le_bytes());
        assert!(NvRecordCopy::detect(&bad).is_err());
        let mut duplicate = b;
        let code = duplicate[0x196c00..0x196d00].to_vec();
        duplicate[0x196e00..0x196f00].copy_from_slice(&code);
        assert!(matches!(
            NvRecordCopy::detect(&duplicate),
            Err(Error::Ambiguous)
        ));
    }
}

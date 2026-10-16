//! Static opcode/callback records, separate from executable lookup evidence.

/// Unique static WRITE BUFFER/type-one registration for a Thumb handler.
/// This alone does not prove registration initialization or dispatcher use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    /// Address of the eight-byte descriptor/function-pointer record.
    pub record: u32,
    /// Even address of the Thumb callback.
    pub callback: u32,
}

/// Find exactly one aligned record containing opcode 0x3B/type 1 and the
/// supplied Thumb callback. Unknown types, non-Thumb pointers, duplicates,
/// truncated records and address overflow never supply a registration.
pub fn inspect_registration(bytes: &[u8], address: u32, callback: u32) -> Option<Registration> {
    if callback & 1 != 0 {
        return None;
    }
    let pointer = callback.checked_add(1)?.to_le_bytes();
    let mut found = None;
    for offset in 0..bytes.len().saturating_sub(7) {
        let at = address.checked_add(u32::try_from(offset).ok()?)?;
        if at & 3 != 0 {
            continue;
        }
        at.checked_add(8)?;
        if bytes[offset..offset + 4] == [0x3b, 1, 0, 0] && bytes[offset + 4..offset + 8] == pointer
        {
            if found.is_some() {
                return None;
            }
            found = Some(Registration {
                record: at,
                callback,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_v1_record_binds_opcode_type_and_thumb_pointer_uniquely() {
        let record = [0x3b, 1, 0, 0, 3, 0xca, 9, 0];
        assert_eq!(
            inspect_registration(&record, 0x155ba8, 0x9ca02),
            Some(Registration {
                record: 0x155ba8,
                callback: 0x9ca02
            })
        );
        for i in 0..8 {
            let mut bad = record;
            bad[i] ^= 1;
            assert!(inspect_registration(&bad, 0x155ba8, 0x9ca02).is_none());
            assert!(inspect_registration(&record[..i], 0x155ba8, 0x9ca02).is_none());
        }
        let mut duplicate = record.to_vec();
        duplicate.extend_from_slice(&record);
        assert!(inspect_registration(&duplicate, 0x155ba8, 0x9ca02).is_none());
        assert!(inspect_registration(&record, 0x155ba9, 0x9ca02).is_none());
        assert!(inspect_registration(&record, u32::MAX - 3, 0x9ca02).is_none());
        assert!(inspect_registration(&record, 0x155ba8, 0x9ca03).is_none());
    }
}

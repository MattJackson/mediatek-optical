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

/// Find exactly one aligned opcode 0x3B/type 1 record and require it to name
/// the supplied Thumb callback. A second 0x3B/type 1 record for any handler
/// leaves dispatcher selection ambiguous. Unknown types, non-Thumb pointers,
/// duplicates, truncated records and address overflow never supply a
/// registration.
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
        if bytes[offset..offset + 4] == [0x3b, 1, 0, 0] {
            if found.is_some() {
                return None;
            }
            found = Some(at);
        }
    }
    let record = found?;
    let offset = usize::try_from(record - address).ok()?;
    (bytes[offset + 4..offset + 8] == pointer).then_some(Registration { record, callback })
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;

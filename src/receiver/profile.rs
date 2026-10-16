//! Live entry selection from the same bounded grammars used by corpus tests.
use super::{entry, Encoding, Error, Mode, Receiver};
use crate::{
    cdb,
    drive::{self, Transport},
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    address: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Profile {
    pub(super) prepare: cdb::Prepare,
    snapshots: Vec<Snapshot>,
}

fn read<T: Transport>(t: &mut T, address: u32, length: usize) -> Result<Snapshot, Error<T::Error>> {
    let mut bytes = vec![0; length];
    for (index, chunk) in bytes.chunks_mut(1024).enumerate() {
        drive::read_memory(t, address + (index * 1024) as u32, chunk).map_err(Error::Read)?;
    }
    Ok(Snapshot { address, bytes })
}

impl Profile {
    pub(super) fn detect<T: Transport>(
        t: &mut T,
        receiver: &Receiver,
    ) -> Result<Self, Error<T::Error>> {
        let mut snapshots = Vec::new();
        let prepare = match receiver.mode() {
            Mode::Boot => {
                let code = read(t, 0x3400, 0x600)?;
                let legacy = entry::inspect_boot_legacy(&code.bytes, code.address);
                let dual = entry::inspect_boot_dual(&code.bytes, code.address);
                if legacy.is_some() == dual.is_some() {
                    return Err(Error::UnknownEntry);
                }
                snapshots.push(code);
                // Both recognized BOOT grammars positively accept mode one.
                cdb::Prepare::ModeOne
            }
            Mode::Firmware => {
                let code = read(t, 0x98000, 0x1c000)?;
                let candidate = entry::application::inspect(&code.bytes, code.address)
                    .ok_or(Error::UnknownEntry)?;
                let prelude =
                    entry::application::inspect_prologue(&code.bytes, code.address, &candidate)
                        .ok_or(Error::UnknownEntry)?;
                let mode_six = entry::application::inspect_mode_six(
                    &code.bytes,
                    code.address,
                    &candidate,
                    &prelude,
                )
                .ok_or(Error::UnknownEntry)?;
                if let Some(address) = candidate.helper {
                    let helper = read(t, address, entry::application::HELPER_BYTES)?;
                    if !entry::application::matches_helper(&helper.bytes) {
                        return Err(Error::UnknownEntry);
                    }
                    snapshots.push(helper);
                }
                let registrations = read(t, 0x140000, 0x70000)?;
                entry::application::inspect_registration(
                    &registrations.bytes,
                    registrations.address,
                    prelude.start,
                )
                .ok_or(Error::UnknownEntry)?;
                snapshots.push(code);
                snapshots.push(registrations);
                match (receiver.encoding(), mode_six) {
                    (Encoding::Encrypted, entry::application::ModeSix::Entry67 { .. }) => {
                        cdb::Prepare::ModeSix67
                    }
                    _ => cdb::Prepare::ModeOne,
                }
            }
        };
        Ok(Self { prepare, snapshots })
    }

    pub(super) fn revalidate<T: Transport>(&self, t: &mut T) -> Result<(), Error<T::Error>> {
        for snapshot in &self.snapshots {
            let current = read(t, snapshot.address, snapshot.bytes.len())?;
            if current != *snapshot {
                return Err(Error::Changed);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn testing() -> Self {
        Self {
            prepare: cdb::Prepare::ModeOne,
            snapshots: Vec::new(),
        }
    }
}

/// Detect encoding and the accepted entry recipe from the running receiver.
/// All reads are bounded code/table evidence, never a backup or a write.
pub fn detect<T: Transport>(
    t: &mut T,
    mode: &super::DetectedMode,
) -> Result<Receiver, Error<T::Error>> {
    let mut receiver = super::detect_encoding(t, mode)?;
    receiver.profile = Some(Profile::detect(t, &receiver)?);
    receiver.revalidate(t)?;
    Ok(receiver)
}

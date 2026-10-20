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
    pub(super) chip: crate::Chip,
    pub(super) prepare: cdb::Prepare,
    pub(super) application: Option<super::analysis::ApplicationAnalysis>,
    pub(super) mixed: Option<super::mixed::MixedContract>,
    snapshots: Vec<Snapshot>,
}

fn read<T: Transport>(t: &mut T, address: u32, length: usize) -> Result<Snapshot, Error<T::Error>> {
    let mut bytes = vec![0; length];
    for (index, chunk) in bytes.chunks_mut(1024).enumerate() {
        drive::read_memory(t, address + (index * 1024) as u32, chunk).map_err(Error::Read)?;
    }
    Ok(Snapshot { address, bytes })
}

// Supplemental evidence reuses bytes already captured by a broader snapshot.
// Each newly read range is retained exactly once for pre-write revalidation.
fn evidence<T: Transport>(
    t: &mut T,
    snapshots: &mut Vec<Snapshot>,
    address: u32,
    length: usize,
) -> Result<Vec<u8>, Error<T::Error>> {
    for snapshot in snapshots.iter() {
        if let Some(offset) = address.checked_sub(snapshot.address).map(|x| x as usize) {
            if let Some(end) = offset.checked_add(length) {
                if let Some(bytes) = snapshot.bytes.get(offset..end) {
                    return Ok(bytes.to_vec());
                }
            }
        }
    }
    let snapshot = read(t, address, length)?;
    let bytes = snapshot.bytes.clone();
    snapshots.push(snapshot);
    Ok(bytes)
}

impl Profile {
    fn detect<T: Transport>(
        t: &mut T,
        receiver: &Receiver,
        code: Snapshot,
    ) -> Result<Self, Error<T::Error>> {
        let mut snapshots = Vec::new();
        let banner = read(
            t,
            crate::layout::BANNER.start as u32,
            crate::layout::BANNER.len,
        )?;
        let chip = crate::Chip::from_banner(&banner.bytes).ok_or(Error::Unknown)?;
        snapshots.push(banner);
        let mut application = None;
        let mut mixed = None;
        let prepare = match receiver.mode() {
            Mode::Boot => {
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
                application =
                    super::analysis::ApplicationAnalysis::inspect(&code.bytes, code.address);
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
                let mixed_candidate = application.as_ref().and_then(|analysis| {
                    super::mixed::Candidate::inspect(&code.bytes, code.address, analysis)
                });
                snapshots.push(code);
                snapshots.push(registrations);
                if let Some(candidate) = mixed_candidate {
                    let wrapper = evidence(
                        t,
                        &mut snapshots,
                        candidate.wrapper_address,
                        candidate.wrapper_bytes(),
                    )?;
                    if let Some(program_address) = candidate.program_address(&wrapper) {
                        let integrity = evidence(
                            t,
                            &mut snapshots,
                            candidate.integrity_address,
                            candidate.integrity_bytes(),
                        )?;
                        let program = evidence(
                            t,
                            &mut snapshots,
                            program_address,
                            candidate.program_bytes(),
                        )?;
                        mixed = candidate.bind(&wrapper, &integrity, &program);
                    }
                }
                match (receiver.encoding(), mode_six) {
                    (Encoding::Encrypted, entry::application::ModeSix::Entry67 { .. }) => {
                        cdb::Prepare::ModeSix67
                    }
                    _ => cdb::Prepare::ModeOne,
                }
            }
        };
        Ok(Self {
            chip,
            prepare,
            application,
            mixed,
            snapshots,
        })
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
            chip: crate::Chip::Mt1959,
            prepare: cdb::Prepare::ModeOne,
            application: None,
            mixed: None,
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
    let (address, length) = match mode.mode() {
        Mode::Boot => (0x3400, 0x600),
        Mode::Firmware => (0x98000, 0x1c000),
    };
    let code = read(t, address, length)?;
    let mut receiver = super::detect_encoding(
        &mut CodeSource {
            physical: t,
            code: &code,
        },
        mode,
    )?;
    receiver.profile = Some(Profile::detect(t, &receiver, code)?);
    receiver.revalidate_signature(t)?;
    Ok(receiver)
}

// Short-lived detector input, never stored in Receiver or passed to execution.
// Encoding and entry analysis consume one captured code window. INQUIRY and
// any helper outside that window still come from the physical transport.
struct CodeSource<'a, T> {
    physical: &'a mut T,
    code: &'a Snapshot,
}
impl<T: Transport> Transport for CodeSource<'_, T> {
    type Error = T::Error;
    fn sense(&self) -> Option<(u8, u8, u8)> {
        self.physical.sense()
    }
    fn exec(&mut self, command: &[u8], data: drive::Data<'_>) -> Result<usize, Self::Error> {
        if let drive::Data::In(out) = data {
            if command.len() == 10 && command[..3] == cdb::read_memory(0, 0)[..3] {
                let address = u32::from_be_bytes([0, command[3], command[4], command[5]]);
                if let Some(offset) = address.checked_sub(self.code.address).map(|n| n as usize) {
                    if let Some(bytes) = offset
                        .checked_add(out.len())
                        .and_then(|end| self.code.bytes.get(offset..end))
                    {
                        out.copy_from_slice(bytes);
                        return Ok(out.len());
                    }
                }
            }
            self.physical.exec(command, drive::Data::In(out))
        } else {
            self.physical.exec(command, data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{drive::Data, envelope::Envelope, fixtures, layout, update, Identity, INQUIRY_LEN};
    use std::collections::BTreeMap;
    struct Device {
        image: Vec<u8>,
        reads: BTreeMap<(u32, usize), usize>,
        writes: usize,
        change_after_capture: bool,
    }
    impl Transport for Device {
        type Error = &'static str;
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            let Data::In(out) = data else {
                self.writes += 1;
                return Err("write forbidden");
            };
            if command[0] == 0x12 {
                out.fill(0);
                out[0] = 5;
                out[4] = 31;
                out[8..36].copy_from_slice(
                    &self.image[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28],
                );
            } else {
                let address = u32::from_be_bytes([0, command[3], command[4], command[5]]);
                *self.reads.entry((address, out.len())).or_default() += 1;
                out.copy_from_slice(&self.image[address as usize..address as usize + out.len()]);
                if self.change_after_capture && address == 0x1afc00 {
                    self.image[0x9a300] ^= 1;
                }
            }
            Ok(out.len())
        }
    }
    fn device() -> Device {
        let mut image = fixtures::image(&fixtures::BU3, 7);
        for (i, &byte) in crate::receiver::PLAIN_APP.iter().enumerate() {
            image[0x9a300 + i] = if byte == crate::receiver::ANY {
                0
            } else {
                byte as u8
            };
        }
        Device {
            image: fixtures::sign(image),
            reads: BTreeMap::new(),
            writes: 0,
            change_after_capture: false,
        }
    }
    struct Runtime;
    impl update::FlashRuntime<&'static str> for Runtime {
        fn elapsed(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
        fn sleep(&mut self, _: std::time::Duration) {
            panic!("unexpected wait")
        }
    }
    #[test]
    fn detection_captures_once_but_execution_revalidates_every_snapshot() {
        let mut live = device();
        let mode = crate::receiver::detect_mode(&mut live).unwrap();
        let receiver = detect(&mut live, &mode).unwrap();
        for address in (0x98000..0xb4000)
            .step_by(1024)
            .chain((0x140000..0x1b0000).step_by(1024))
        {
            assert_eq!(live.reads.get(&(address, 1024)), Some(&1));
        }
        assert!(
            !live.reads.keys().any(|(_, length)| *length == 1088),
            "encoding must reuse the code capture"
        );
        let image = live.image.clone();
        let identity = Identity::parse(
            &[0; INQUIRY_LEN],
            layout::BANNER.of(&image).unwrap(),
            layout::DESCRIPTOR.of(&image).unwrap(),
        )
        .unwrap();
        let update = update::PreparedUpdate::prepare_without_installed(&image, &identity).unwrap();
        let prepared = receiver.bind_prepared(&update).unwrap();
        // Mutation outside the small encoding signature must be caught before
        // PROBE/PREPARE/STREAM, by physical snapshot validation at execution.
        live.image[0x1affff] ^= 1;
        let mut writes = device();
        let result = prepared.flash_completed(
            update::FlashTransport {
                reads: &mut live,
                writes: &mut writes,
            },
            &mut Runtime,
        );
        assert!(matches!(
            result,
            Err(crate::receiver::ExecuteError::Receiver(Error::Changed))
        ));
        assert_eq!(writes.writes, 0);
        assert!(writes.reads.is_empty());
        assert_eq!(live.reads.get(&(0x1afc00, 1024)), Some(&2));
    }
    #[test]
    fn detection_still_checks_live_signature_after_capture() {
        let mut live = device();
        live.change_after_capture = true;
        let mode = crate::receiver::detect_mode(&mut live).unwrap();
        assert!(matches!(detect(&mut live, &mode), Err(Error::Changed)));
        assert_eq!(live.writes, 0);
    }
    #[test]
    fn validated_target_cannot_bind_to_a_receiver_of_another_chip() {
        let mut live = device();
        let mode = crate::receiver::detect_mode(&mut live).unwrap();
        let receiver = detect(&mut live, &mode).unwrap();
        let image = fixtures::image(&fixtures::JB7, 1);
        let identity = Identity::parse(
            &[0; INQUIRY_LEN],
            layout::BANNER.of(&image).unwrap(),
            layout::DESCRIPTOR.of(&image).unwrap(),
        )
        .unwrap();
        let validated =
            update::PreparedUpdate::prepare_without_installed(&image, &identity).unwrap();
        assert!(matches!(
            receiver.bind_prepared(&validated),
            Err(update::PrepareError::ChipMismatch {
                image: crate::Chip::Mt1939,
                drive: crate::Chip::Mt1959
            })
        ));
        assert!(matches!(
            receiver.prepare_without_installed(&Envelope::load(&image).unwrap(), &identity),
            Err(update::PrepareError::ChipMismatch { .. })
        ));
        assert_eq!(live.writes, 0);
    }
}

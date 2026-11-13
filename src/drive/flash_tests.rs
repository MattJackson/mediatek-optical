//! The shared flash engine against a simulated drive.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::drive::{
    ExecutionRuntime, FlashError, FlashTransport, ReadbackQuality, Stage, Status, Verified,
};
use crate::envelope::image::cmac;
use crate::transport::Error;
use crate::transport::{Data, Transport};
use core::time::Duration;

/// Which transport a command came through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    Reads,
    Writes,
}

/// A drive that programs a streamed image when its last chunk lands.
#[derive(Default)]
struct Drive {
    /// What READ BUFFER returns.
    flash: Vec<u8>,
    /// Streamed bytes.
    pending: Vec<u8>,
    /// Decrypt the streamed transfer before programming (the `enc` route).
    decrypts: bool,
    /// Every command: transport, CDB and data length.
    log: Vec<(Via, Vec<u8>, usize)>,
    /// Refuse this exact CDB.
    refuse: Option<Vec<u8>>,
    /// Multiple independent command failures for recovery boundary tests.
    refuse_commands: Vec<Vec<u8>>,
    /// TEST UNIT READY failures left once COMMIT was sent.
    busy: usize,
    /// Sense replies, in order; afterwards a clean `70 .. 00`.
    sense: Vec<Vec<u8>>,
    /// Flip this byte on read-back.
    corrupt: Option<usize>,
    /// Answer the read of the chunk at this offset short.
    short_at: Option<usize>,
    short_after_commit: bool,
    /// Report a full read of the chunk at this offset without filling it.
    unfilled_at: Option<usize>,
    committed: bool,
    inquiry_revision: Option<[u8; 4]>,
    /// INQUIRY reports revision `BOOT` until COMMIT (a BOOT receiver).
    boot_until_commit: bool,
    /// INQUIRY keeps answering the identity stored before programming, as
    /// old firmware that is still running would.
    stale_inquiry: bool,
    /// The identity programming replaced, kept for `stale_inquiry`.
    replaced_identity: Option<Vec<u8>>,
}

impl Drive {
    fn running(image: &[u8]) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            flash: fixtures::drive_read(image),
            pending: vec![0xFF; layout::IMAGE_SIZE],
            ..Self::default()
        }))
    }

    fn program(&mut self) {
        let mut image = self.pending.clone();
        if self.decrypts {
            #[cfg(feature = "enc")]
            crate::envelope::enc::decrypt(&mut image).unwrap();
            #[cfg(not(feature = "enc"))]
            panic!("encrypted test transport requires the enc feature");
        }
        let identity = layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28;
        self.replaced_identity
            .get_or_insert_with(|| self.flash[identity].to_vec());
        let mirror = image[layout::BOOT_MIRROR.start..layout::BOOT_MIRROR.end()].to_vec();
        image[..layout::BOOT_PAGE.len].copy_from_slice(&mirror);
        // The drive keeps its own per-unit regions.
        for range in layout::DRIVE_WRITTEN {
            image[range.start..range.end()].copy_from_slice(&self.flash[range.start..range.end()]);
        }
        self.flash = image;
    }

    fn exec(&mut self, via: Via, cdb: &[u8], data: Data<'_>) -> Result<usize, &'static str> {
        if [
            crate::cdb::Prepare::ModeOne,
            crate::cdb::Prepare::ModeSix67,
            crate::cdb::Prepare::ModeOnePreserveBoot,
            crate::cdb::Prepare::ModeSix67PreserveBoot,
        ]
        .iter()
        .any(|prepare| cdb == prepare.command())
        {
            assert!(
                matches!(&data, Data::Out(bytes) if bytes.is_empty()),
                "PREPARE must retain zero-length data-out"
            );
        }
        let len = match &data {
            Data::None => 0,
            Data::In(buf) => buf.len(),
            Data::Out(bytes) => bytes.len(),
        };
        self.log.push((via, cdb.to_vec(), len));
        if self.refuse.as_deref() == Some(cdb) || self.refuse_commands.iter().any(|c| c == cdb) {
            return Err("refused");
        }
        match (cdb[0], data) {
            (0x12, Data::In(buf)) => {
                let mut inquiry = [0; crate::INQUIRY_LEN];
                inquiry[0] = 5;
                inquiry[4] = (crate::INQUIRY_LEN - 5) as u8;
                inquiry[8..36].copy_from_slice(
                    &self.flash[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28],
                );
                if let (true, Some(old)) = (self.stale_inquiry, &self.replaced_identity) {
                    inquiry[8..36].copy_from_slice(old);
                }
                if let Some(revision) = self.inquiry_revision {
                    inquiry[32..36].copy_from_slice(&revision);
                }
                if self.boot_until_commit && !self.committed {
                    inquiry[32..36].copy_from_slice(b"BOOT");
                }
                buf.copy_from_slice(&inquiry[..buf.len()]);
                Ok(buf.len())
            }
            (0x00, _) if self.committed && self.busy > 0 => {
                self.busy -= 1;
                Err("not ready")
            }
            (0x3B, Data::Out(bytes)) if cdb[1] == 0x06 => {
                let off = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]) as usize;
                self.pending[off..off + bytes.len()].copy_from_slice(bytes);
                if off + bytes.len() == layout::IMAGE_SIZE {
                    self.program();
                }
                Ok(bytes.len())
            }
            (0x3B, _) if cdb[1] == 0x07 => {
                self.committed = true;
                Ok(0)
            }
            (0x3C, Data::In(buf)) => {
                let off = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]) as usize;
                if self.unfilled_at == Some(off) {
                    return Ok(buf.len());
                }
                let n =
                    if self.short_at == Some(off) && (self.committed || !self.short_after_commit) {
                        buf.len() - 1
                    } else {
                        buf.len()
                    };
                buf[..n].copy_from_slice(&self.flash[off..off + n]);
                if let Some(at) = self.corrupt {
                    if (off..off + n).contains(&at) {
                        buf[at - off] ^= 0x40;
                    }
                }
                Ok(n)
            }
            (0x03, Data::In(buf)) => {
                let reply = if self.sense.is_empty() {
                    let mut clean = vec![0; 18];
                    clean[0] = 0x70;
                    clean
                } else {
                    self.sense.remove(0)
                };
                let n = reply.len().min(buf.len());
                buf[..n].copy_from_slice(&reply[..n]);
                Ok(n)
            }
            (_, Data::Out(bytes)) => Ok(bytes.len()),
            _ => Ok(0),
        }
    }
}

struct Handle(Rc<RefCell<Drive>>, Via);

impl Transport for Handle {
    type Error = &'static str;

    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        self.0.borrow_mut().exec(self.1, cdb, data)
    }

    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}

/// A fake clock that records every runtime event.
#[derive(Default)]
struct Clock {
    now: Duration,
    events: Vec<String>,
    progress: Vec<usize>,
    operation_progress: Vec<crate::operation::Progress>,
}

impl ExecutionRuntime<&'static str> for Clock {
    fn operation_progress(&mut self, progress: crate::operation::Progress) {
        self.operation_progress.push(progress);
    }
    fn elapsed(&self) -> Duration {
        self.now
    }
    fn sleep(&mut self, duration: Duration) {
        self.now += duration;
    }
    fn starting(&mut self, bytes: usize) {
        self.events.push(format!("starting {bytes}"));
    }
    fn progress(&mut self, written: usize, total: usize) {
        assert_eq!(total, layout::IMAGE_SIZE);
        self.progress.push(written);
    }
    fn commit_failed(&mut self, error: &Error<&'static str>) {
        self.events.push(format!("commit failed {error}"));
    }
    fn recovery_entry_failed(&mut self, error: &Error<&'static str>) {
        self.events.push(format!("recovery PREPARE failed {error}"));
    }
    fn commit_not_ready(&mut self, error: &Error<&'static str>) {
        self.events.push(format!("commit not ready {error}"));
    }
    fn status(&mut self, stage: Stage, status: Status<'_, &'static str>) {
        let status = match status {
            Status::Sense(t) => format!("sense {:02x}/{:02x}/{:02x}", t.0, t.1, t.2),
            Status::Unparseable(n) => format!("unparseable {n}"),
            Status::Failed(e) => format!("failed {e}"),
        };
        self.events.push(format!("{stage:?} {status}"));
    }
    fn uploaded(&mut self, bytes: usize) {
        self.events.push(format!("uploaded {bytes}"));
    }
    fn poll_failed(&mut self, _elapsed: Duration, _error: &Error<&'static str>) {
        self.events.push("poll failed".into());
    }
    fn verifying(&mut self) {
        self.events.push("verifying".into());
    }
    fn verification_unavailable(
        &mut self,
        offset: usize,
        length: usize,
        error: &Error<&'static str>,
    ) {
        self.events.push(format!(
            "verification_unavailable {offset:#x} {length:#x} {error}"
        ));
    }
}

const PROTECTED: usize = (fixtures::SIGNED.1 - fixtures::SIGNED.0 + 1) as usize;

fn run(
    drive: &Rc<RefCell<Drive>>,
    update: &ValidatedUpdate,
    clock: &mut Clock,
) -> Result<ReadbackQuality, FlashError<&'static str>> {
    let (mut reads, mut writes) = (
        Handle(drive.clone(), Via::Reads),
        Handle(drive.clone(), Via::Writes),
    );
    update.flash(
        FlashTransport {
            reads: &mut reads,
            writes: &mut writes,
        },
        clock,
    )
}

fn setup() -> (Rc<RefCell<Drive>>, ValidatedUpdate, Vec<u8>) {
    let running = fixtures::image(&JB7, 1);
    let target = fixtures::image(&JB7, 2);
    let update = prepare(&target, &running).unwrap();
    (Drive::running(&running), update, target)
}

/// The complete verification a successful flash must report.
fn full(result: Result<ReadbackQuality, FlashError<&'static str>>) -> Verified {
    match result.unwrap() {
        ReadbackQuality::Complete(verified) => verified,
        limited => panic!("expected complete read-back, got {limited:?}"),
    }
}

fn sense(key: u8, asc: u8) -> Vec<u8> {
    let mut s = vec![0; 18];
    s[0] = 0x70;
    s[2] = key;
    s[12] = asc;
    s
}

#[test]
fn flash_sends_the_oem_session_then_verifies() {
    let (drive, update, target) = setup();
    let mut clock = Clock::default();
    let verified = full(run(&drive, &update, &mut clock));
    use crate::operation::Phase;
    for phase in [
        Phase::Preparing,
        Phase::Writing,
        Phase::Restarting,
        Phase::Verifying,
    ] {
        assert!(clock.operation_progress.iter().any(|p| p.phase == phase));
    }
    let waiting = clock
        .operation_progress
        .iter()
        .find(|p| p.phase == Phase::Restarting)
        .unwrap();
    assert_eq!((waiting.done, waiting.total), (None, None));
    let last = clock.operation_progress.last().unwrap();
    assert_eq!(last.phase, Phase::Verifying);
    assert_eq!(
        (last.done, last.total),
        (Some(layout::IMAGE_SIZE), Some(layout::IMAGE_SIZE))
    );
    assert_eq!(
        verified,
        Verified {
            checked: PROTECTED,
            ranges: 1
        }
    );
    let log = drive.borrow().log.clone();
    let mut want: Vec<(Via, Vec<u8>, usize)> = vec![
        (Via::Writes, cdb::probe().to_vec(), 0x100),
        (Via::Writes, cdb::test_unit_ready().to_vec(), 0),
        (Via::Writes, cdb::enter_update().to_vec(), 0),
    ];
    for i in 0..128u32 {
        want.push((
            Via::Writes,
            cdb::transfer(i * 0x4000, 0x4000).to_vec(),
            0x4000,
        ));
    }
    want.extend([
        (Via::Writes, cdb::finish().to_vec(), 0),
        (Via::Reads, cdb::test_unit_ready().to_vec(), 0),
        (Via::Reads, cdb::request_sense().to_vec(), 16),
        (Via::Reads, cdb::test_unit_ready().to_vec(), 0),
        (Via::Reads, cdb::request_sense().to_vec(), 16),
    ]);
    for i in 0..128u32 {
        want.push((
            Via::Reads,
            cdb::read_memory(i * 0x4000, 0x4000).to_vec(),
            0x4000,
        ));
    }
    assert_eq!(log, want);
    assert_eq!(
        clock.events,
        [
            "starting 2097152",
            "Commit sense 00/00/00",
            "uploaded 2097152",
            "Settled sense 00/00/00",
            "verifying"
        ]
    );
    assert_eq!(clock.progress.len(), 128);
    assert_eq!(clock.progress[0], 0x4000);
    assert_eq!(*clock.progress.last().unwrap(), layout::IMAGE_SIZE);
    // What the drive stores outside its boot page and per-unit regions.
    assert_eq!(
        drive.borrow().flash[0x1000..0x1D_8000],
        target[0x1000..0x1D_8000]
    );
}

#[test]
fn a_failed_entry_sends_no_firmware() {
    let (drive, update, _) = setup();
    drive.borrow_mut().refuse = Some(cdb::enter_update().to_vec());
    let error = run(&drive, &update, &mut Clock::default()).unwrap_err();
    assert!(matches!(
        error,
        FlashError::Entry(Error::Transport("refused"))
    ));
    assert!(!drive
        .borrow()
        .log
        .iter()
        .any(|(_, c, _)| c[0] == 0x3B && c[1] == 0x06));
}

fn run_recovery_payload(
    drive: &Rc<RefCell<Drive>>,
    update: &ValidatedUpdate,
    clock: &mut Clock,
) -> Result<ReadbackQuality, FlashError<&'static str>> {
    let (mut reads, mut writes) = (
        Handle(drive.clone(), Via::Reads),
        Handle(drive.clone(), Via::Writes),
    );
    crate::drive::flash::Payload {
        class: update.class(),
        image: &update.image,
        transfer: update.transfer(),
    }
    .flash(
        FlashTransport {
            reads: &mut reads,
            writes: &mut writes,
        },
        clock,
        crate::drive::flash::ExecutionMode::Recovery,
        cdb::Prepare::ModeOne,
    )
}

#[test]
fn recovery_reports_failed_prepare_once_then_streams_and_verifies() {
    let (drive, update, _) = setup();
    drive.borrow_mut().refuse = Some(cdb::enter_update().to_vec());
    let mut clock = Clock::default();
    let verified = full(run_recovery_payload(&drive, &update, &mut clock));
    assert!(verified.checked > 0);
    assert_eq!(
        clock
            .events
            .iter()
            .filter(|e| e.starts_with("recovery PREPARE failed"))
            .count(),
        1
    );
    let d = drive.borrow();
    assert_eq!(d.log[0].1, cdb::enter_update());
    assert_eq!(d.log[1].1, cdb::transfer(0, cdb::CHUNK as u16));
    assert_eq!(
        d.log
            .iter()
            .filter(|(_, c, _)| c == &cdb::enter_update())
            .count(),
        1
    );
    assert!(!d.log.iter().any(|(_, c, _)| c == &cdb::probe()));
}

#[test]
fn prepare_dialects_and_boot_policies_keep_flash_strict_and_recovery_single_attempt() {
    use crate::drive::flash::{ExecutionMode, Payload};
    for prepare in [
        cdb::Prepare::ModeOne,
        cdb::Prepare::ModeSix67,
        cdb::Prepare::ModeOnePreserveBoot,
        cdb::Prepare::ModeSix67PreserveBoot,
    ] {
        for recovery in [false, true] {
            for refused in [false, true] {
                let (drive, update, _) = setup();
                if refused {
                    drive.borrow_mut().refuse = Some(prepare.command().to_vec());
                }
                let (mut reads, mut writes) = (
                    Handle(drive.clone(), Via::Reads),
                    Handle(drive.clone(), Via::Writes),
                );
                let mut clock = Clock::default();
                let result = Payload {
                    class: update.class(),
                    image: update.image(),
                    transfer: update.transfer(),
                }
                .flash(
                    FlashTransport {
                        reads: &mut reads,
                        writes: &mut writes,
                    },
                    &mut clock,
                    if recovery {
                        ExecutionMode::Recovery
                    } else {
                        ExecutionMode::Flash
                    },
                    prepare,
                );
                let log = &drive.borrow().log;
                assert_eq!(
                    log.iter()
                        .filter(|(_, cmd, _)| cmd == &prepare.command())
                        .count(),
                    1
                );
                if refused && !recovery {
                    assert!(matches!(result, Err(FlashError::Entry(_))));
                    assert!(!log
                        .iter()
                        .any(|(_, cmd, _)| cmd == &cdb::transfer(0, cdb::CHUNK as u16)));
                } else {
                    assert!(full(result).checked > 0);
                }
                assert_eq!(
                    clock
                        .events
                        .iter()
                        .filter(|e| e.starts_with("recovery PREPARE failed"))
                        .count(),
                    usize::from(refused && recovery)
                );
            }
        }
    }
}

#[test]
fn recovery_prepare_exception_never_ignores_or_retries_a_failed_chunk() {
    let (drive, update, _) = setup();
    let failed_chunk = cdb::transfer(0x4000, 0x4000).to_vec();
    drive.borrow_mut().refuse_commands = vec![cdb::enter_update().to_vec(), failed_chunk.clone()];
    let error = run_recovery_payload(&drive, &update, &mut Clock::default()).unwrap_err();
    assert!(matches!(error, FlashError::Transfer { offset: 0x4000, .. }));
    let d = drive.borrow();
    assert_eq!(
        d.log.iter().filter(|(_, c, _)| c == &failed_chunk).count(),
        1
    );
    assert!(!d.log.iter().any(|(_, c, _)| c == &cdb::finish()));
    assert_eq!(d.log.last().unwrap().1, failed_chunk);
}

#[test]
fn a_failed_chunk_stops_before_commit() {
    let (drive, update, _) = setup();
    drive.borrow_mut().refuse = Some(cdb::transfer(0x8000, 0x4000).to_vec());
    let error = run(&drive, &update, &mut Clock::default()).unwrap_err();
    assert!(matches!(
        error,
        FlashError::Transfer {
            offset: 0x8000,
            length: 0x4000,
            ..
        }
    ));
    let log = &drive.borrow().log;
    assert_eq!(log.last().unwrap().1, cdb::transfer(0x8000, 0x4000));
    assert!(!log.iter().any(|(_, c, _)| *c == cdb::finish()));
}

#[test]
fn a_commit_error_goes_on_to_the_checks() {
    let (drive, update, _) = setup();
    drive.borrow_mut().refuse = Some(cdb::finish().to_vec());
    let mut clock = Clock::default();
    full(run(&drive, &update, &mut clock));
    assert_eq!(
        clock.events[1],
        "commit failed transport error: \"refused\""
    );
}

#[test]
fn a_fault_sense_fails_after_commit_and_after_settling() {
    let (drive, update, _) = setup();
    drive.borrow_mut().sense = vec![sense(0x04, 0x44)];
    let error = run(&drive, &update, &mut Clock::default()).unwrap_err();
    assert!(matches!(
        error,
        FlashError::Fault {
            stage: Stage::Commit,
            sense: (0x04, 0x44, 0)
        }
    ));

    let (drive, update, _) = setup();
    drive.borrow_mut().sense = vec![sense(0x06, 0x29), sense(0x03, 0x0C)];
    let mut clock = Clock::default();
    let error = run(&drive, &update, &mut clock).unwrap_err();
    assert!(matches!(
        error,
        FlashError::Fault {
            stage: Stage::Settled,
            sense: (0x03, 0x0C, 0)
        }
    ));
    assert!(clock.events.contains(&"Commit sense 06/29/00".to_string()));
}

#[test]
fn unreadable_sense_is_reported_and_verification_decides() {
    let (drive, update, _) = setup();
    drive.borrow_mut().sense = vec![vec![0x12; 5]];
    let mut clock = Clock::default();
    full(run(&drive, &update, &mut clock));
    assert!(clock.events.contains(&"Commit unparseable 5".to_string()));

    let (drive, update, _) = setup();
    drive.borrow_mut().refuse = Some(cdb::request_sense().to_vec());
    let mut clock = Clock::default();
    full(run(&drive, &update, &mut clock));
    let failed = "failed transport error: \"refused\"";
    assert!(clock.events.contains(&format!("Commit {failed}")));
    assert!(clock.events.contains(&format!("Settled {failed}")));
}

/// A drive that stays busy for 110 s, longer than the old 45 s bound but
/// within one OEM command window, is not failed.
#[test]
fn readiness_waits_through_an_oem_command_window() {
    let (drive, update, _) = setup();
    // One failure for the post-commit check, then 220 polls of 0.5 s.
    drive.borrow_mut().busy = 221;
    let mut clock = Clock::default();
    full(run(&drive, &update, &mut clock));
    assert_eq!(clock.now, Duration::from_secs(110));
    assert_eq!(
        clock.events[1],
        "commit not ready transport error: \"not ready\""
    );
    assert_eq!(
        clock.events.iter().filter(|e| *e == "poll failed").count(),
        220
    );
}

#[test]
fn readiness_gives_up_after_the_bound() {
    let (drive, update, _) = setup();
    drive.borrow_mut().busy = usize::MAX;
    let mut clock = Clock::default();
    let error = run(&drive, &update, &mut clock).unwrap_err();
    assert!(matches!(
        error,
        FlashError::ReadyTimeout(Error::Transport("not ready"))
    ));
    assert_eq!(clock.now, Duration::from_secs(120));
    assert_eq!(DriveClass::Mt19.ready_timeout(), Duration::from_secs(120));
    assert!(DriveClass::Mt19.ready_timeout() >= Duration::from_secs(100));
    // No read-back of a drive that never settled.
    assert!(!drive
        .borrow()
        .log
        .iter()
        .any(|(_, c, _)| c[..] == cdb::read_memory(0, 0x4000)));
}

#[test]
fn a_protected_difference_fails() {
    let (drive, update, _) = setup();
    drive.borrow_mut().corrupt = Some(0x2_0010);
    let error = run(&drive, &update, &mut Clock::default()).unwrap_err();
    assert!(matches!(
        error,
        FlashError::Mismatch {
            address: 0x2_0010,
            differing: 1,
            checked: PROTECTED,
            ..
        }
    ));
}

#[test]
fn differences_outside_the_protected_ranges_pass() {
    for at in [0x800, 0x5_0000, layout::CALIBRATION.start + 4] {
        let (drive, update, _) = setup();
        drive.borrow_mut().corrupt = Some(at);
        full(run(&drive, &update, &mut Clock::default()));
    }
}

#[test]
fn an_unreadable_protected_chunk_is_incomplete() {
    let (drive, update, _) = setup();
    drive.borrow_mut().short_at = Some(0x1_4000);
    let mut clock = Clock::default();
    let readback = run(&drive, &update, &mut clock).unwrap();
    assert!(matches!(
        readback,
        ReadbackQuality::Limited {
            unverified: 1,
            checked
        } if checked == PROTECTED - 0x4000
    ));
    assert!(clock.events.contains(
        &"verification_unavailable 0x14000 0x4000 short transfer: expected 16384 bytes, got 16383"
            .to_string()
    ));

    let (drive, update, _) = setup();
    drive.borrow_mut().short_at = Some(0x4_0000);
    full(run(&drive, &update, &mut Clock::default()));
}

#[test]
fn a_full_count_without_data_never_verifies_stale_bytes() {
    // 0x2_4000 and 0x2_8000 hold identical protected bytes; a read of the
    // second that reports a full count but writes nothing must not be counted
    // as matching the previous chunk's read-back.
    let (drive, update, target) = setup();
    assert!(target[0x2_4000..0x2_8000] == target[0x2_8000..0x2_C000]);
    drive.borrow_mut().unfilled_at = Some(0x2_8000);
    let error = run(&drive, &update, &mut Clock::default()).unwrap_err();
    assert!(
        matches!(
            error,
            FlashError::Mismatch {
                address: 0x2_8000,
                ..
            }
        ),
        "{error:?}"
    );
}

#[cfg(feature = "enc")]
#[test]
fn an_encrypted_transfer_verifies_the_plaintext() {
    let (drive, update, target) = setup();
    let update = update.encrypted();
    assert_ne!(update.transfer(), &target[..]);
    assert_eq!(update.image(), &target[..]);
    drive.borrow_mut().decrypts = true;
    full(run(&drive, &update, &mut Clock::default()));
    let first = drive.borrow().pending[..16].to_vec();
    assert_eq!(first, update.transfer()[..16]);
}

#[test]
fn unreadable_chunk_before_protected_ranges_does_not_invalidate_later_reads() {
    let (drive, update, _) = setup();
    drive.borrow_mut().short_at = Some(0x4000);
    let mut clock = Clock::default();
    let verified = full(run(&drive, &update, &mut clock));
    assert_eq!(verified.checked, PROTECTED);
    assert!(!clock
        .events
        .iter()
        .any(|event| event.starts_with("verification_unavailable")));
}

fn run_completed(
    drive: &Rc<RefCell<Drive>>,
    update: &ValidatedUpdate,
    mode: crate::drive::flash::ExecutionMode,
) -> Result<crate::drive::FlashOutcome, FlashError<&'static str>> {
    let mut reads = Handle(drive.clone(), Via::Reads);
    let mut writes = Handle(drive.clone(), Via::Writes);
    // The receiver identity bound before the write, as execution revalidates it.
    let prior = crate::prepare::receiver::detect_mode(&mut reads).unwrap();
    drive.borrow_mut().log.clear();
    crate::drive::flash::Payload {
        class: update.class(),
        image: update.image(),
        transfer: update.transfer(),
    }
    .flash_completed(
        FlashTransport {
            reads: &mut reads,
            writes: &mut writes,
        },
        &mut Clock::default(),
        mode,
        cdb::Prepare::ModeOne,
        &prior,
    )
}

type Setup = fn() -> (Rc<RefCell<Drive>>, ValidatedUpdate, Vec<u8>);

/// Builds 1 and 2 of [`JB7`] with the target's revision changed to `1.04`,
/// so INQUIRY identity differs before and after the write.
fn setup_identity_change() -> (Rc<RefCell<Drive>>, ValidatedUpdate, Vec<u8>) {
    let running = fixtures::image(&JB7, 1);
    let mut target = fixtures::image(&JB7, 2);
    let d = layout::DESCRIPTOR.start;
    target[d + 0x18..d + 0x1C].copy_from_slice(b"1.04");
    let target = fixtures::sign(target);
    let update = prepare(&target, &running).unwrap();
    (Drive::running(&running), update, target)
}

/// Every command after COMMIT, which today's sequence fixes: TEST UNIT READY,
/// REQUEST SENSE, the readiness poll, REQUEST SENSE, read-back of every chunk,
/// then exactly one INQUIRY and one descriptor READ BUFFER.
fn after_commit(drive: &Rc<RefCell<Drive>>) -> Vec<(Via, Vec<u8>, usize)> {
    let log = &drive.borrow().log;
    let commit = log
        .iter()
        .position(|(_, c, _)| *c == cdb::finish())
        .expect("COMMIT sent");
    log[commit + 1..].to_vec()
}

fn expected_after_commit() -> Vec<(Via, Vec<u8>, usize)> {
    let mut want = vec![
        (Via::Reads, cdb::test_unit_ready().to_vec(), 0),
        (Via::Reads, cdb::request_sense().to_vec(), 16),
        (Via::Reads, cdb::test_unit_ready().to_vec(), 0),
        (Via::Reads, cdb::request_sense().to_vec(), 16),
    ];
    for i in 0..128u32 {
        want.push((
            Via::Reads,
            cdb::read_memory(i * 0x4000, 0x4000).to_vec(),
            0x4000,
        ));
    }
    want.push((
        Via::Reads,
        cdb::inquiry(crate::INQUIRY_LEN as u16).to_vec(),
        crate::INQUIRY_LEN,
    ));
    want.push((
        Via::Reads,
        cdb::read_memory(
            layout::DESCRIPTOR.start as u32,
            layout::DESCRIPTOR.len as u32,
        )
        .to_vec(),
        layout::DESCRIPTOR.len,
    ));
    want
}

#[test]
fn same_identity_completion_is_unobserved_for_flash_and_recovery() {
    use crate::drive::{flash::ExecutionMode, StartupEvidence};
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        // Builds 1 and 2 both report "1.03": INQUIRY cannot tell the old
        // firmware still running apart from the target having started.
        let (drive, update, _) = setup();
        let completed = run_completed(&drive, &update, mode).unwrap();
        assert_eq!(completed.startup.evidence(), StartupEvidence::Unobserved);
        assert!(matches!(completed.readback, ReadbackQuality::Complete(_)));
    }
}

#[test]
fn stale_old_firmware_with_same_identity_is_never_confirmed() {
    use crate::drive::{flash::ExecutionMode, StartupEvidence};
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let (drive, update, target) = setup();
        drive.borrow_mut().stale_inquiry = true;
        let completed = run_completed(&drive, &update, mode).unwrap();
        assert_eq!(completed.startup.evidence(), StartupEvidence::Unobserved);
        // The premise: the stale answer is the old firmware's identity, and it
        // is byte-identical to the target's, so it is indistinguishable from
        // `same_identity_completion_is_unobserved_for_flash_and_recovery`.
        let d = layout::DESCRIPTOR.start;
        assert_eq!(
            drive.borrow().replaced_identity.as_deref(),
            Some(&target[d..d + 28])
        );
        assert_eq!(&completed.startup.inquiry()[8..36], &target[d..d + 28]);
    }
}

#[test]
fn identity_change_is_observed() {
    use crate::drive::{flash::ExecutionMode, StartupError, StartupEvidence};
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let (drive, update, _) = setup_identity_change();
        let completed = run_completed(&drive, &update, mode).unwrap();
        assert_eq!(
            completed.startup.evidence(),
            StartupEvidence::IdentityChanged
        );
        assert_eq!(&completed.startup.inquiry()[32..36], b"1.04");
        assert!(matches!(completed.readback, ReadbackQuality::Complete(_)));
        // Old firmware still answering with its own identity is refused.
        let (drive, update, _) = setup_identity_change();
        drive.borrow_mut().stale_inquiry = true;
        assert!(matches!(
            run_completed(&drive, &update, mode),
            Err(FlashError::Startup(StartupError::TargetMismatch))
        ));
    }
}

#[test]
fn boot_to_target_is_left_boot() {
    use crate::drive::{flash::ExecutionMode, StartupEvidence};
    let (drive, update, _) = setup();
    drive.borrow_mut().boot_until_commit = true;
    let completed = run_completed(&drive, &update, ExecutionMode::Recovery).unwrap();
    assert_eq!(completed.startup.evidence(), StartupEvidence::LeftBoot);
    assert!(matches!(completed.readback, ReadbackQuality::Complete(_)));
}

#[test]
fn startup_evidence_adds_no_command() {
    use crate::drive::{flash::ExecutionMode, StartupEvidence};
    let cases: [(Setup, bool, _); 3] = [
        (setup, false, StartupEvidence::Unobserved),
        (
            setup_identity_change,
            false,
            StartupEvidence::IdentityChanged,
        ),
        (setup, true, StartupEvidence::LeftBoot),
    ];
    for (build, boot, evidence) in cases {
        let (drive, update, _) = build();
        drive.borrow_mut().boot_until_commit = boot;
        let completed = run_completed(&drive, &update, ExecutionMode::Recovery).unwrap();
        assert_eq!(completed.startup.evidence(), evidence);
        assert_eq!(after_commit(&drive), expected_after_commit());
    }
    for build in [setup as Setup, setup_identity_change] {
        let (drive, update, _) = build();
        run_completed(&drive, &update, ExecutionMode::Flash).unwrap();
        assert_eq!(after_commit(&drive), expected_after_commit());
    }
}

#[test]
fn limited_readback_is_reported_alongside_an_unobserved_restart() {
    use crate::drive::{flash::ExecutionMode, ReadbackQuality, StartupEvidence};
    let (drive, update, _) = setup();
    drive.borrow_mut().short_at = Some(0x14000);
    let completed = run_completed(&drive, &update, ExecutionMode::Flash).unwrap();
    assert!(matches!(
        completed.readback,
        ReadbackQuality::Limited { unverified: 1, .. }
    ));
    assert_eq!(completed.startup.evidence(), StartupEvidence::Unobserved);
}

#[test]
fn completion_requires_the_target_running_for_flash_and_recovery() {
    use crate::drive::{flash::ExecutionMode, ReadbackQuality, StartupError, StartupEvidence};
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let (drive, update, target) = setup();
        let completed = run_completed(&drive, &update, mode).unwrap();
        // This fixture pair shares its INQUIRY identity: matching identity
        // and descriptor alone are not an observed restart.
        assert_eq!(completed.startup.evidence(), StartupEvidence::Unobserved);
        assert!(matches!(
            completed.readback,
            ReadbackQuality::Complete(Verified {
                checked: PROTECTED,
                ..
            })
        ));
        assert_eq!(
            completed.startup.descriptor(),
            &target[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 0x58]
        );
        for revision in [*b"INTM", *b"BOOT"] {
            let (drive, update, _) = setup();
            drive.borrow_mut().inquiry_revision = Some(revision);
            assert!(matches!(
                run_completed(&drive, &update, mode),
                Err(FlashError::Startup(StartupError::TargetMismatch))
            ));
            assert!(
                drive.borrow().committed,
                "the bytes were transferred; readiness alone cannot prove startup"
            );
        }
    }
}

#[test]
fn limited_readback_requires_target_startup_and_remains_qualified() {
    use crate::drive::{flash::ExecutionMode, ReadbackQuality, StartupError};
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let (drive, update, _) = setup();
        drive.borrow_mut().short_at = Some(0x14000);
        let completed = run_completed(&drive, &update, mode).unwrap();
        assert!(
            matches!(completed.readback, ReadbackQuality::Limited { checked, unverified: 1 } if checked < PROTECTED)
        );
        let (drive, update, _) = setup();
        drive.borrow_mut().short_at = Some(0x14000);
        drive.borrow_mut().inquiry_revision = Some(*b"INTM");
        assert!(matches!(
            run_completed(&drive, &update, mode),
            Err(FlashError::Startup(StartupError::TargetMismatch))
        ));
    }
}

#[test]
fn completion_rejects_same_revision_with_wrong_build_and_unreadable_descriptor() {
    use crate::drive::{flash::ExecutionMode, StartupError};
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let (drive, update, _) = setup();
        // Outside the fixture's CMAC range: startup must independently compare build metadata.
        drive.borrow_mut().corrupt = Some(layout::DESCRIPTOR.start + 0x30);
        assert!(matches!(
            run_completed(&drive, &update, mode),
            Err(FlashError::Startup(StartupError::TargetMismatch))
        ));
        let (drive, update, _) = setup();
        drive.borrow_mut().short_at = Some(layout::DESCRIPTOR.start);
        drive.borrow_mut().short_after_commit = true;
        let result = run_completed(&drive, &update, mode);
        assert!(
            matches!(result, Err(FlashError::Startup(StartupError::Read(_)))),
            "{result:?}"
        );
    }
}

#[test]
fn completion_rejects_descriptor_tail_mismatch() {
    use crate::drive::{flash::ExecutionMode, StartupError};
    let descriptor_read = |cdb: &[u8], len: usize| {
        cdb[0] == 0x3C
            && u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]) as usize == layout::DESCRIPTOR.start
            && len == layout::DESCRIPTOR.len
    };
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        // Control: the untouched target starts and reports its metadata.
        let (drive, update, target) = setup();
        let completed = run_completed(&drive, &update, mode).unwrap();
        assert_eq!(
            completed.startup.descriptor(),
            &target[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 0x58]
        );
        // A descriptor tail byte outside the fixture's CMAC ranges: only startup sees it.
        let (drive, update, _) = setup();
        drive.borrow_mut().corrupt = Some(layout::DESCRIPTOR.start + 0x80);
        assert!(matches!(
            run_completed(&drive, &update, mode),
            Err(FlashError::Startup(StartupError::TargetMismatch))
        ));
        let d = drive.borrow();
        assert!(d.committed);
        let at = d
            .log
            .iter()
            .rposition(|(_, cdb, len)| descriptor_read(cdb, *len))
            .expect("startup read the descriptor");
        assert!(
            !d.log[at..].iter().any(|(_, cdb, _)| cdb[0] == 0x3B),
            "no write or commit follows the startup descriptor read"
        );
        assert_eq!(
            at,
            d.log.len() - 1,
            "no further commands after the mismatch"
        );
    }
}

#[test]
fn completion_never_probes_startup_after_partial_write_or_corrupt_readback() {
    use crate::drive::flash::ExecutionMode;
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let (drive, update, _) = setup();
        drive.borrow_mut().refuse =
            Some(cdb::transfer(0x4000, update.class().chunk() as u16).to_vec());
        assert!(matches!(
            run_completed(&drive, &update, mode),
            Err(FlashError::Transfer { .. })
        ));
        assert!(!drive.borrow().log.iter().any(|(_, cdb, _)| cdb[0] == 0x12));
        let (drive, update, _) = setup();
        drive.borrow_mut().corrupt = Some(fixtures::SIGNED.0 as usize);
        assert!(matches!(
            run_completed(&drive, &update, mode),
            Err(FlashError::Mismatch { .. })
        ));
        assert!(!drive.borrow().log.iter().any(|(_, cdb, _)| cdb[0] == 0x12));
    }
}

fn zero_range_image(board: &fixtures::Board) -> Vec<u8> {
    let mut img = fixtures::image(board, 1);
    let at = cmac::TABLE_OFFSET;
    img[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
    img[at + 8..at + 12].copy_from_slice(&0xFFFu32.to_le_bytes());
    let img = cmac::resign(&img).unwrap();
    assert!(cmac::verify(&img));
    img
}

#[test]
fn zero_range_readback_is_never_complete() {
    let img = zero_range_image(&JB7);
    let class = crate::DriveClass::of(crate::Chip::Mt1939);
    assert!(class.verification_ranges(&img).is_empty());
    let drive = Drive::running(&img);
    let (mut reads, mut writes) = (
        Handle(drive.clone(), Via::Reads),
        Handle(drive.clone(), Via::Writes),
    );
    let result = crate::drive::flash::Payload {
        class,
        image: &img,
        transfer: &img,
    }
    .flash(
        FlashTransport {
            reads: &mut reads,
            writes: &mut writes,
        },
        &mut Clock::default(),
        crate::drive::flash::ExecutionMode::Flash,
        cdb::Prepare::ModeOne,
    );
    assert!(matches!(
        result,
        Ok(ReadbackQuality::Limited { checked: 0, .. })
    ));
}

impl crate::prepare::update::ValidatedUpdate {
    /// Write the update and prove it: PROBE, TEST UNIT READY, PREPARE, the
    /// transfer in STREAM chunks, COMMIT, TEST UNIT READY and REQUEST SENSE;
    /// then poll TEST UNIT READY until the drive has programmed, REQUEST SENSE
    /// again, and read back every chunk, comparing the integrity-protected
    /// ranges with the image.
    ///
    /// First capture a backup, enforce tray and consent policy and exclude
    /// other users of the drive. A failure stops at once; nothing is retried.
    pub(crate) fn flash<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<ReadbackQuality, FlashError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        crate::drive::flash::Payload {
            class: self.class,
            image: &self.image,
            transfer: self.transfer(),
        }
        .flash(
            io,
            runtime,
            crate::drive::flash::ExecutionMode::Flash,
            crate::cdb::Prepare::ModeOne,
        )
    }
}

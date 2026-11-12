//! Shared transfer and verification over a caller's transport.

use core::time::Duration;

use crate::drive::{self, Error, Transport};
use crate::sense::{self, Triplet};
use crate::{cdb, layout};

/// The two transports a flash uses, both addressing the drive the update was
/// prepared for. Prevent any other access to the drive throughout.
pub struct FlashTransport<'a, R, W> {
    /// Readiness polls, sense reads and read-back.
    pub reads: &'a mut R,
    /// The update session: PROBE, TEST UNIT READY, PREPARE, STREAM and
    /// COMMIT. Must never retry a write.
    pub writes: &'a mut W,
}

/// When a sense reply was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Right after COMMIT.
    Commit,
    /// Once the drive answered TEST UNIT READY again.
    Settled,
}

/// A REQUEST SENSE outcome that does not fail the flash.
///
/// Hosts must keep a wildcard arm; the set of outcomes may grow.
///
/// ```compile_fail,E0004
/// fn f(s: mediatek_optical::update::Status<'_, ()>) -> u8 { use mediatek_optical::update::Status::*; match s { Sense(_) => 0, Unparseable(_) => 1, Failed(_) => 2 } }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum Status<'a, E> {
    /// A parsed sense that proves no programming failure.
    Sense(Triplet),
    /// A reply of this many bytes that does not parse as sense data.
    Unparseable(usize),
    /// The command failed; read-back verification decides.
    Failed(&'a Error<E>),
}

/// Host timing and progress for receiver-bound update execution.
pub trait ExecutionRuntime<E> {
    /// Structured progress mirrored by the other optical protocol libraries.
    fn operation_progress(&mut self, _progress: crate::operation::Progress) {}
    /// Monotonic time from a fixed origin; must advance across
    /// [`ExecutionRuntime::sleep`].
    fn elapsed(&self) -> Duration;
    /// Wait at least `duration`.
    fn sleep(&mut self, duration: Duration);
    /// The session is about to start; `bytes` will be streamed.
    fn starting(&mut self, _bytes: usize) {}
    /// A STREAM write completed.
    fn progress(&mut self, _written: usize, _total: usize) {}
    /// Explicit Recovery only: PREPARE failed, was not retried, and recovery
    /// proceeds to the selected image. Hosts should persist the full error.
    /// Normal Flash never invokes this callback and aborts on entry failure.
    fn recovery_entry_failed(&mut self, _error: &Error<E>) {}
    /// COMMIT failed. The drive programmed when the last chunk landed and may
    /// answer COMMIT while it reinitializes, so the flash goes on to its
    /// checks.
    fn commit_failed(&mut self, _error: &Error<E>) {}
    /// TEST UNIT READY right after COMMIT failed; expected while programming.
    /// Reported only: neither this failure nor a later unit-attention sense is
    /// counted as restart evidence.
    fn commit_not_ready(&mut self, _error: &Error<E>) {}
    /// A REQUEST SENSE outcome that does not fail the flash.
    fn status(&mut self, _stage: Stage, _status: Status<'_, E>) {}
    /// The upload is complete; readiness polling starts.
    fn uploaded(&mut self, _bytes: usize) {}
    /// A readiness poll failed after `elapsed` of polling. Reported only;
    /// readiness gates read-back and never confers success, which needs
    /// read-back plus the post-write INQUIRY and descriptor checks.
    fn poll_failed(&mut self, _elapsed: Duration, _error: &Error<E>) {}
    /// Read-back verification starts.
    fn verifying(&mut self) {}
    /// A chunk holding protected bytes could not be read back in full.
    fn verification_unavailable(&mut self, _offset: usize, _length: usize, _error: &Error<E>) {}
}

/// What read-back verification proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Protected bytes compared, all equal.
    pub checked: usize,
    /// Protected ranges in the image; always at least one, as verification
    /// without a protected range is refused.
    pub ranges: usize,
}

/// A failed flash. Every variant after [`FlashError::Entry`] may leave the
/// drive holding partial or unverified firmware; nothing is retried or rolled
/// back.
#[derive(Debug)]
#[non_exhaustive]
pub enum FlashError<E> {
    /// PROBE, TEST UNIT READY or PREPARE failed; no firmware data was sent. If
    /// PREPARE was reached the drive may be in update mode.
    Entry(Error<E>),
    /// A STREAM write failed.
    Transfer {
        /// Offset of the failed chunk.
        offset: usize,
        /// Its length.
        length: usize,
        /// The command failure.
        source: Error<E>,
    },
    /// REQUEST SENSE reported a programming failure.
    Fault {
        /// When the sense was read.
        stage: Stage,
        /// The sense.
        sense: Triplet,
    },
    /// The drive did not answer TEST UNIT READY within
    /// [`crate::DriveClass::ready_timeout`]; the last poll's error.
    ReadyTimeout(Error<E>),
    /// Readiness/read-back completed, but the selected target was not confirmed running.
    Startup(super::StartupError<E>),
    /// A protected byte read back differently.
    Mismatch {
        /// Offset of the first differing byte.
        address: usize,
        /// The byte read back.
        read: u8,
        /// The byte written.
        wrote: u8,
        /// Protected bytes that differ.
        differing: usize,
        /// Protected bytes compared.
        checked: usize,
    },
}

// Used by the receiver-bound and recovery execution errors (`enc`).
#[cfg(feature = "enc")]
impl<E> FlashError<E> {
    /// Firmware data may have been sent: every variant after
    /// [`FlashError::Entry`].
    pub(crate) fn firmware_write_started(&self) -> bool {
        !matches!(self, Self::Entry(_))
    }

    /// The boundary which failed; see `receiver::ExecutionError::phase`.
    pub(crate) fn phase(&self) -> &'static str {
        match self {
            Self::Entry(_) => "update entry",
            Self::Transfer { .. } | Self::Fault { .. } => "firmware transfer",
            Self::ReadyTimeout(_) | Self::Startup(_) => "target startup",
            Self::Mismatch { .. } => "readback",
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for FlashError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Entry(e) => write!(f, "update entry failed before any firmware data: {e}"),
            Self::Transfer {
                offset,
                length,
                source,
            } => write!(
                f,
                "firmware write at {offset:#x}, length {length}: {source}"
            ),
            Self::Fault { stage, sense } => write!(
                f,
                "{stage:?} sense {:02X}/{:02X}/{:02X} reports a flash fault",
                sense.0, sense.1, sense.2
            ),
            Self::ReadyTimeout(e) => write!(f, "drive did not settle after the burn: {e}"),
            Self::Startup(error) => write!(f, "target startup was not confirmed: {error}"),
            Self::Mismatch {
                address,
                read,
                wrote,
                differing,
                checked,
            } => write!(
                f,
                "read-back differs at {address:#08x} (read {read:#04x}, wrote {wrote:#04x}); \
                 {differing} of {checked} protected bytes differ"
            ),
        }
    }
}

impl<E: core::fmt::Debug + 'static> std::error::Error for FlashError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Entry(source) | Self::ReadyTimeout(source) => Some(source),
            Self::Transfer { source, .. } => Some(source),
            Self::Startup(source) => Some(source),
            _ => None,
        }
    }
}

/// REQUEST SENSE as the OEM sequence issues it: the reply length and its
/// parse.
fn request_sense<T: Transport>(t: &mut T) -> Result<(usize, Option<Triplet>), Error<T::Error>> {
    let mut buf = [0; cdb::REQUEST_SENSE_LEN];
    let n = drive::read(t, &cdb::request_sense(), &mut buf, 0)?;
    Ok((n, sense::parse(&buf[..n])))
}

/// REQUEST SENSE at `stage`: a flash fault fails, anything else is reported.
fn status<T: Transport, H: ExecutionRuntime<T::Error>>(
    t: &mut T,
    runtime: &mut H,
    stage: Stage,
) -> Result<(), FlashError<T::Error>> {
    match request_sense(t) {
        Ok((_, Some(sense))) if sense::is_flash_fault(sense.0) => {
            Err(FlashError::Fault { stage, sense })
        }
        Ok((_, Some(sense))) => {
            runtime.status(stage, Status::Sense(sense));
            Ok(())
        }
        Ok((n, None)) => {
            runtime.status(stage, Status::Unparseable(n));
            Ok(())
        }
        Err(error) => {
            runtime.status(stage, Status::Failed(&error));
            Ok(())
        }
    }
}

/// Shared transfer and verification implementation; recovery supplies no family policy.
pub(crate) struct Payload<'a> {
    pub(crate) class: crate::DriveClass,
    pub(crate) image: &'a [u8],
    pub(crate) transfer: &'a [u8],
}

/// Host policy is separate from receiver encoding and entry-command evidence.
/// Only the corresponding public prepared operation selects this mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionMode {
    Flash,
    Recovery,
}
impl Payload<'_> {
    pub(crate) fn flash<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        mode: ExecutionMode,
        prepare: cdb::Prepare,
    ) -> Result<super::ReadbackQuality, FlashError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let transfer = self.transfer;
        runtime.starting(transfer.len());
        runtime.operation_progress(crate::operation::Progress::waiting(
            crate::operation::Phase::Preparing,
            crate::operation::Component::Firmware,
        ));
        let mut session = match mode {
            ExecutionMode::Recovery => {
                drive::enter_recovery_reporting(io.writes, prepare, |error| {
                    runtime.recovery_entry_failed(error)
                })
            }
            ExecutionMode::Flash => {
                drive::enter_update_command(io.writes, prepare).map_err(FlashError::Entry)?
            }
        };
        let chunk = self.class.chunk();
        for (index, piece) in transfer.chunks(chunk).enumerate() {
            let offset = index * chunk;
            session
                .write(offset as u32, piece)
                .map_err(|source| FlashError::Transfer {
                    offset,
                    length: piece.len(),
                    source,
                })?;
            runtime.progress(offset + piece.len(), transfer.len());
            runtime.operation_progress(crate::operation::Progress::bytes(
                crate::operation::Phase::Writing,
                crate::operation::Component::Firmware,
                offset + piece.len(),
                transfer.len(),
            ));
        }
        if let Err(error) = session.finish() {
            runtime.commit_failed(&error);
        }
        if let Err(error) = drive::test_unit_ready(io.reads) {
            runtime.commit_not_ready(&error);
        }
        status(io.reads, runtime, Stage::Commit)?;

        runtime.uploaded(transfer.len());
        runtime.operation_progress(crate::operation::Progress::waiting(
            crate::operation::Phase::Restarting,
            crate::operation::Component::Firmware,
        ));
        let start = runtime.elapsed();
        while let Err(error) = drive::test_unit_ready(io.reads) {
            let waited = runtime.elapsed().saturating_sub(start);
            runtime.poll_failed(waited, &error);
            if waited >= self.class.ready_timeout() {
                return Err(FlashError::ReadyTimeout(error));
            }
            runtime.sleep(self.class.poll_interval());
        }
        status(io.reads, runtime, Stage::Settled)?;

        runtime.verifying();
        self.verify(io.reads, runtime)
    }

    /// Execute and retain read-back quality, then require the target identity
    /// and classify restart evidence against `prior`, the receiver identity
    /// revalidated immediately before the write.
    pub(crate) fn flash_completed<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        mode: ExecutionMode,
        prepare: cdb::Prepare,
        prior: &crate::receiver::DetectedMode,
    ) -> Result<super::FlashOutcome, FlashError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let result = self.flash(
            FlashTransport {
                reads: io.reads,
                writes: io.writes,
            },
            runtime,
            mode,
            prepare,
        );
        super::completion::complete(io.reads, self.image, result, prior)
    }

    /// Read back every chunk and compare the protected bytes. Unreadable
    /// protected chunks, or no protected range at all, are limited
    /// verification, never complete.
    fn verify<R: Transport, H: ExecutionRuntime<R::Error>>(
        &self,
        reads: &mut R,
        runtime: &mut H,
    ) -> Result<super::ReadbackQuality, FlashError<R::Error>> {
        let ranges = self.class.verification_ranges(self.image);
        let protected = |at: usize| ranges.iter().any(|r| r.contains(&at));
        let (mut checked, mut differing, mut unverified) = (0, 0, 0);
        let mut first: Option<(usize, u8, u8)> = None;
        let chunk = self.class.chunk();
        let mut buf = vec![0; chunk];
        for (index, piece) in self.image.chunks(chunk).enumerate() {
            runtime.operation_progress(crate::operation::Progress::bytes(
                crate::operation::Phase::Verifying,
                crate::operation::Component::Firmware,
                index * chunk,
                self.image.len(),
            ));
            let offset = index * chunk;
            let got = &mut buf[..piece.len()];
            // Poison with values that cannot match, so a reply that reports a
            // full count without filling the buffer is a mismatch rather than
            // a comparison against the previous chunk's read-back.
            for (slot, &wrote) in got.iter_mut().zip(piece) {
                *slot = !wrote;
            }
            match drive::read_memory(reads, offset as u32, got) {
                Ok(()) => {
                    for (i, (&read, &wrote)) in got.iter().zip(piece).enumerate() {
                        if !protected(offset + i) {
                            continue;
                        }
                        checked += 1;
                        if read != wrote {
                            differing += 1;
                            first.get_or_insert((offset + i, read, wrote));
                        }
                    }
                }
                Err(error) => {
                    if (offset..offset + piece.len()).any(protected) {
                        unverified += 1;
                        runtime.verification_unavailable(offset, piece.len(), &error);
                    }
                }
            }
        }
        runtime.operation_progress(crate::operation::Progress::bytes(
            crate::operation::Phase::Verifying,
            crate::operation::Component::Firmware,
            self.image.len(),
            self.image.len(),
        ));
        if let Some((address, read, wrote)) = first {
            return Err(FlashError::Mismatch {
                address,
                read,
                wrote,
                differing,
                checked,
            });
        }
        if ranges.is_empty() || unverified > 0 {
            return Ok(super::ReadbackQuality::Limited {
                checked,
                unverified,
            });
        }
        debug_assert_eq!(self.image.len(), layout::IMAGE_SIZE);
        Ok(super::ReadbackQuality::Complete(Verified {
            checked,
            ranges: ranges.len(),
        }))
    }
}

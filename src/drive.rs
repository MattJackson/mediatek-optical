//! Command sequences over a caller-supplied [`Transport`]: identify, memory
//! read and the flash session.
//!
//! ```no_run
//! # use mediatek_optical::{cdb, drive};
//! # fn run<T: drive::Transport>(t: &mut T, image: &[u8]) -> Result<(), drive::Error<T::Error>> {
//! let id = drive::identify(t)?;
//! assert!(id.is_mt19());
//! let mut session = drive::enter_update(t)?;
//! for (i, chunk) in image.chunks(cdb::CHUNK).enumerate() {
//!     session.write((i * cdb::CHUNK) as u32, chunk)?;
//! }
//! session.finish()?;
//! # Ok(()) }
//! ```
//!
//! Requires the `drive` feature.

use crate::{cdb, layout, Identity, INQUIRY_LEN};

/// Largest offset a CDB can encode (24 bits).
const FIELD_MAX: usize = 0xFF_FFFF;

/// The data phase of one command.
#[derive(Debug)]
pub enum Data<'a> {
    /// No data phase.
    None,
    /// Device to host: the drive fills up to `len()` bytes.
    In(&'a mut [u8]),
    /// Host to device: the drive receives every byte.
    Out(&'a [u8]),
}

/// A SCSI pass-through.
pub trait Transport {
    /// Transport error.
    type Error: core::fmt::Debug;

    /// Execute one CDB. Returns the number of bytes transferred (`0` for
    /// [`Data::None`]).
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error>;

    /// Sense `(key, asc, ascq)` of the most recent failed command, if any.
    fn sense(&self) -> Option<(u8, u8, u8)>;
}

/// Errors from the command sequences.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
    /// The transport failed.
    Transport(E),
    /// The drive returned fewer bytes than required.
    Short {
        /// Bytes required.
        expected: usize,
        /// Bytes received.
        actual: usize,
    },
    /// An offset or length does not fit its CDB field.
    Oversize(usize),
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug> std::error::Error for Error<E> {}

impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::Short { expected, actual } => {
                write!(f, "short transfer: expected {expected} bytes, got {actual}")
            }
            Self::Oversize(n) => write!(f, "{n:#x} exceeds the CDB field"),
        }
    }
}

fn exec<T: Transport>(t: &mut T, cdb: &[u8], data: Data<'_>) -> Result<usize, Error<T::Error>> {
    t.exec(cdb, data).map_err(Error::Transport)
}

/// Execute a data-in `cdb` that must return at least `min` bytes.
fn read<T: Transport>(
    t: &mut T,
    cdb: &[u8],
    buf: &mut [u8],
    min: usize,
) -> Result<usize, Error<T::Error>> {
    let n = exec(t, cdb, Data::In(buf))?.min(buf.len());
    if n < min {
        return Err(Error::Short {
            expected: min,
            actual: n,
        });
    }
    Ok(n)
}

/// Execute a data-out `cdb` that must transfer every byte of `data`.
fn write<T: Transport>(t: &mut T, cdb: &[u8], data: &[u8]) -> Result<(), Error<T::Error>> {
    let n = exec(t, cdb, Data::Out(data))?;
    if n < data.len() {
        return Err(Error::Short {
            expected: data.len(),
            actual: n,
        });
    }
    Ok(())
}

fn field<E>(n: usize, max: usize) -> Result<u32, Error<E>> {
    if n > max {
        return Err(Error::Oversize(n));
    }
    Ok(n as u32)
}

/// Read the drive's [`Identity`]: INQUIRY, boot banner and identity
/// descriptor. Changes no drive state.
///
/// Only INQUIRY is required. A drive that refuses the banner or descriptor
/// read still identifies, with those fields empty; [`Identity::is_mt19`] then
/// reports `false`.
pub fn identify<T: Transport>(t: &mut T) -> Result<Identity, Error<T::Error>> {
    let mut inquiry = [0; cdb::INQUIRY_ALLOC as usize];
    read(
        t,
        &cdb::inquiry(cdb::INQUIRY_ALLOC),
        &mut inquiry,
        INQUIRY_LEN,
    )?;
    let mut banner = [0; layout::BANNER.len];
    let banner_len =
        read_exact(t, layout::BANNER.start as u32, &mut banner).map_or(0, |_| banner.len());
    let mut descriptor = [0; layout::DESCRIPTOR.len];
    let descriptor_len = read_exact(t, layout::DESCRIPTOR.start as u32, &mut descriptor)
        .map_or(0, |_| descriptor.len());
    Identity::parse(
        &inquiry,
        &banner[..banner_len],
        &descriptor[..descriptor_len],
    )
    .ok_or(Error::Short {
        expected: INQUIRY_LEN,
        actual: 0,
    })
}

fn read_exact<T: Transport>(t: &mut T, off: u32, buf: &mut [u8]) -> Result<(), Error<T::Error>> {
    let len = field(buf.len(), FIELD_MAX)?;
    field::<T::Error>(off as usize, FIELD_MAX)?;
    let n = buf.len();
    read(t, &cdb::read_memory(off, len), buf, n).map(|_| ())
}

/// Read `buf.len()` bytes of flash at file offset `off`. A short reply is
/// [`Error::Short`]: a partial region is never returned as complete.
///
/// The boot page reads back as [`layout::BOOT_MIRROR`]; see the crate docs.
pub fn read_memory<T: Transport>(
    t: &mut T,
    off: u32,
    buf: &mut [u8],
) -> Result<(), Error<T::Error>> {
    read_exact(t, off, buf)
}

/// Read the GET CONFIGURATION reply for the single feature `code` into `buf`;
/// returns the bytes received. The reply needs at least its 12-byte header.
pub fn feature<T: Transport>(
    t: &mut T,
    code: u16,
    buf: &mut [u8],
) -> Result<usize, Error<T::Error>> {
    let alloc = field(buf.len(), u16::MAX as usize)? as u16;
    read(t, &cdb::get_configuration(code, alloc), buf, 12)
}

/// TEST UNIT READY. An empty tray fails with sense `02/3A`; see
/// [`crate::sense::is_no_medium`].
pub fn test_unit_ready<T: Transport>(t: &mut T) -> Result<(), Error<T::Error>> {
    exec(t, &cdb::test_unit_ready(), Data::None).map(|_| ())
}

/// REQUEST SENSE as the OEM sequence issues it; the parsed `(key, asc, ascq)`,
/// or `None` for an unparseable reply.
pub fn request_sense<T: Transport>(
    t: &mut T,
) -> Result<Option<crate::sense::Triplet>, Error<T::Error>> {
    let mut buf = [0; cdb::REQUEST_SENSE_LEN];
    let n = read(t, &cdb::request_sense(), &mut buf, 0)?;
    Ok(crate::sense::parse(&buf[..n]))
}

/// An open flash session, returned by [`enter_update`].
///
/// The drive programs flash when the last chunk of a complete image lands,
/// before [`finish`](Self::finish). Dropping the session sends nothing and
/// does not roll back earlier writes.
pub struct Session<'a, T: Transport> {
    t: &'a mut T,
}

impl<T: Transport> core::fmt::Debug for Session<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl<T: Transport> Session<'_, T> {
    /// Write `data` at file offset `off`. `off` must fit in 24 bits and
    /// `data.len()` in 16; the OEM sequence uses [`cdb::CHUNK`].
    pub fn write(&mut self, off: u32, data: &[u8]) -> Result<(), Error<T::Error>> {
        let len = field(data.len(), u16::MAX as usize)? as u16;
        field::<T::Error>(off as usize, FIELD_MAX)?;
        write(self.t, &cdb::transfer(off, len), data)
    }

    /// Send the commit handshake. The drive may answer with a transient CHECK
    /// CONDITION while it reinitializes; callers verify the outcome with
    /// [`test_unit_ready`], [`request_sense`] and a read-back.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        write(self.t, &cdb::finish(), &[])
    }
}

/// Enter the flash session: PROBE (a [`cdb::PROBE_LEN`]-byte descriptor
/// read), TEST UNIT READY, then PREPARE. Any failure stops before PREPARE.
pub fn enter_update<T: Transport>(t: &mut T) -> Result<Session<'_, T>, Error<T::Error>> {
    let mut probe = [0; cdb::PROBE_LEN];
    read(t, &cdb::probe(), &mut probe, cdb::PROBE_LEN)?;
    test_unit_ready(t)?;
    write(t, &cdb::enter_update(), &[])?;
    Ok(Session { t })
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod tests;

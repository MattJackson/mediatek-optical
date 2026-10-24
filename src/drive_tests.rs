use super::*;
use std::{vec, vec::Vec};

/// A transport that answers reads from a flash image and records every CDB.
struct Mock {
    flash: Vec<u8>,
    cdbs: Vec<Vec<u8>>,
    written: Vec<(u32, Vec<u8>)>,
    fail_opcode: Option<u8>,
    short_by: usize,
}

impl Mock {
    fn new() -> Self {
        let mut flash = vec![0u8; layout::IMAGE_SIZE];
        flash[0x3000..0x300F].copy_from_slice(b"MT1939 Boot JB7");
        flash[0x1E_C034..0x1E_C03E].copy_from_slice(b"MTEKMT1939");
        Self {
            flash,
            cdbs: Vec::new(),
            written: Vec::new(),
            fail_opcode: None,
            short_by: 0,
        }
    }
}

impl Transport for Mock {
    type Error = &'static str;

    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        self.cdbs.push(cdb.to_vec());
        if self.fail_opcode == Some(cdb[0]) {
            return Err("refused");
        }
        match data {
            Data::In(buf) => {
                let n = buf.len() - self.short_by.min(buf.len());
                match cdb[0] {
                    0x12 => {
                        buf[..36].fill(b' ');
                        buf[0] = 5;
                        buf[8..16].copy_from_slice(b"HL-DT-ST");
                        buf[16..30].copy_from_slice(b"BD-RE BE14NU40");
                    }
                    0x3C => {
                        let off = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]) as usize;
                        buf[..n].copy_from_slice(&self.flash[off..off + n]);
                    }
                    0x03 => {
                        buf.fill(0);
                        buf[0] = 0x70;
                        buf[2] = 0x02;
                        buf[12] = 0x3A;
                    }
                    _ => {}
                }
                Ok(n)
            }
            Data::Out(bytes) => {
                if cdb[0] == 0x3B && cdb[1] == 0x06 {
                    let off = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]);
                    self.written.push((off, bytes.to_vec()));
                }
                Ok(bytes.len())
            }
            Data::None => Ok(0),
        }
    }

    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}

#[test]
fn identify_reads_inquiry_banner_and_descriptor() {
    let mut t = Mock::new();
    let id = identify(&mut t).unwrap();
    assert_eq!(id.product(), "BD-RE BE14NU40");
    assert_eq!(id.banner(), "MT1939 Boot JB7");
    assert_eq!(id.chip(), Some(crate::Chip::Mt1939));
    assert_eq!(t.cdbs.len(), 3);
    assert_eq!(t.cdbs[1], cdb::read_memory(0x3000, 0x20));
    assert_eq!(t.cdbs[2], cdb::read_memory(0x1E_C000, 0x100));
}

#[test]
fn identify_survives_refused_rom_reads() {
    let mut t = Mock::new();
    t.fail_opcode = Some(0x3C);
    let id = identify(&mut t).unwrap();
    assert!(!id.is_mt19());
    assert_eq!(id.chip(), None);
}

#[test]
fn read_memory_requires_every_byte() {
    let mut t = Mock::new();
    let mut buf = [0u8; 15];
    read_memory(&mut t, 0x3000, &mut buf).unwrap();
    assert_eq!(&buf, b"MT1939 Boot JB7");
    t.short_by = 1;
    assert!(matches!(
        read_memory(&mut t, 0x3000, &mut buf),
        Err(Error::Short {
            expected: 15,
            actual: 14
        })
    ));
    assert!(matches!(
        read_memory(&mut t, 0x100_0000, &mut buf),
        Err(Error::Oversize(0x100_0000))
    ));
}

#[test]
fn flash_session_issues_the_oem_sequence() {
    let mut t = Mock::new();
    let image = vec![0xA5u8; 3 * cdb::CHUNK];
    let mut session = enter_update(&mut t).unwrap();
    for (i, chunk) in image.chunks(cdb::CHUNK).enumerate() {
        session.write((i * cdb::CHUNK) as u32, chunk).unwrap();
    }
    session.finish().unwrap();
    assert_eq!(t.cdbs[0], cdb::probe());
    assert_eq!(t.cdbs[1], cdb::test_unit_ready());
    assert_eq!(t.cdbs[2], cdb::enter_update());
    assert_eq!(t.cdbs[3], cdb::transfer(0, 0x4000));
    assert_eq!(t.cdbs[5], cdb::transfer(0x8000, 0x4000));
    assert_eq!(t.cdbs[6], cdb::finish());
    assert_eq!(t.written.len(), 3);
    assert_eq!(t.written[2].0, 0x8000);
}

#[test]
fn failed_ready_check_stops_before_prepare() {
    let mut t = Mock::new();
    t.fail_opcode = Some(0x00);
    assert!(matches!(
        enter_update(&mut t),
        Err(Error::Transport("refused"))
    ));
    assert!(!t.cdbs.iter().any(|c| *c == cdb::enter_update()));
}

#[test]
fn session_rejects_oversize_chunks_and_reports_sense() {
    let mut t = Mock::new();
    {
        let mut session = enter_update(&mut t).unwrap();
        assert!(matches!(
            session.write(0, &[0u8; 0x1_0000]),
            Err(Error::Oversize(0x1_0000))
        ));
    }
    // The refusal happened before any WRITE BUFFER was issued.
    assert!(t.written.is_empty());
    assert_eq!(
        t.cdbs,
        [cdb::probe(), cdb::test_unit_ready(), cdb::enter_update()]
    );
    assert_eq!(request_sense(&mut t).unwrap(), Some((0x02, 0x3A, 0x00)));
    test_unit_ready(&mut t).unwrap();
}

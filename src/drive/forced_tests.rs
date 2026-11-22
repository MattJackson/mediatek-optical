//! Probe classification and forced-encoding wire selection against a mock
//! transport. No real drive or firmware image is needed for the probe tests.

use super::*;
use crate::envelope::enc;
use crate::transport::{Data, Transport};

const CHUNK: usize = crate::cdb::CHUNK;

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A drive that knows its own wire encoding and validates the whole first
/// chunk (header and body). It accepts only a chunk encoded with `truth` and
/// rejects anything else with `reject` sense. COMMIT makes it panic.
struct MockDrive {
    truth: Option<TransferEncoding>,
    plain_chunk: Vec<u8>,
    reject: (u8, u8, u8),
    last_sense: (u8, u8, u8),
    log: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct Rejected;

impl MockDrive {
    fn new(truth: Option<TransferEncoding>) -> Self {
        Self {
            truth,
            plain_chunk: plaintext(CHUNK),
            reject: (5, 0xBD, 0),
            last_sense: (0, 0, 0),
            log: Vec::new(),
        }
    }

    /// Reverse `encoding` (the inverse of `super::apply_encoding`).
    fn decode(encoding: TransferEncoding, chunk: &[u8]) -> Vec<u8> {
        let mut d = chunk.to_vec();
        match (encoding.header, encoding.body) {
            (Encoding::Plaintext, Encoding::Plaintext) => {}
            (Encoding::Encrypted, Encoding::Encrypted) => enc::decrypt(&mut d).unwrap(),
            (Encoding::Encrypted, Encoding::Plaintext) => {
                enc::decrypt(&mut d[0x3000..0x3010]).unwrap()
            }
            (Encoding::Plaintext, Encoding::Encrypted) => {
                enc::decrypt(&mut d).unwrap();
                enc::encrypt(&mut d[0x3000..0x3010]).unwrap();
            }
        }
        d
    }

    fn prepares(&self) -> usize {
        self.log
            .iter()
            .filter(|c| c.len() >= 2 && c[0] == 0x3B && c[1] == 0x01)
            .count()
    }

    fn sent_finish(&self) -> bool {
        self.log
            .iter()
            .any(|c| c.len() >= 2 && c[0] == 0x3B && c[1] == 0x07)
    }
}

impl Transport for MockDrive {
    type Error = Rejected;

    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        self.log.push(cdb.to_vec());
        match (cdb[0], data) {
            // READ BUFFER (PROBE) and READ: return zeros.
            (0x3C, Data::In(buf)) => {
                buf.fill(0);
                Ok(buf.len())
            }
            // REQUEST SENSE: fixed-format sense from the last transfer.
            (0x03, Data::In(buf)) => {
                for b in buf.iter_mut() {
                    *b = 0;
                }
                buf[0] = 0x70;
                buf[2] = self.last_sense.0;
                buf[7] = 8;
                buf[12] = self.last_sense.1;
                buf[13] = self.last_sense.2;
                Ok(buf.len().min(16))
            }
            // TEST UNIT READY.
            (0x00, _) => Ok(0),
            // WRITE BUFFER family.
            (0x3B, data) => match cdb[1] {
                0x01 => Ok(0), // PREPARE
                0x06 => {
                    // STREAM: judge the chunk.
                    let Data::Out(chunk) = data else {
                        return Ok(0);
                    };
                    let accepted = self
                        .truth
                        .is_some_and(|truth| Self::decode(truth, chunk) == self.plain_chunk);
                    if accepted {
                        self.last_sense = (0, 0, 0);
                        Ok(chunk.len())
                    } else {
                        self.last_sense = self.reject;
                        Err(Rejected)
                    }
                }
                0x07 => panic!("COMMIT (finish) must never be sent during a probe"),
                _ => Ok(0),
            },
            _ => Ok(0),
        }
    }

    fn sense(&self) -> Option<(u8, u8, u8)> {
        Some(self.last_sense)
    }
}

#[test]
fn probe_detects_each_encoding() {
    let image = plaintext(CHUNK);
    for truth in CANDIDATE_ENCODINGS {
        let mut drive = MockDrive::new(Some(truth));
        let found = probe_encoding(&mut drive, &image).unwrap();
        assert_eq!(
            found, truth,
            "probe should report the drive's true encoding"
        );
        assert!(!drive.sent_finish(), "probe must not COMMIT");
    }
}

#[test]
fn probe_order_is_pp_ee_ep() {
    let image = plaintext(CHUNK);
    // PP is first, so a PP drive is found after a single entry.
    let mut pp = MockDrive::new(Some(super::PP));
    assert_eq!(probe_encoding(&mut pp, &image).unwrap(), super::PP);
    assert_eq!(pp.prepares(), 1);
    // EE is second; EP is third and last.
    let mut ee = MockDrive::new(Some(super::EE));
    assert_eq!(probe_encoding(&mut ee, &image).unwrap(), super::EE);
    assert_eq!(ee.prepares(), 2);
    let mut ep = MockDrive::new(Some(super::EP));
    assert_eq!(probe_encoding(&mut ep, &image).unwrap(), super::EP);
    assert_eq!(ep.prepares(), 3);
    // Each candidate ends its session with an abort TEST UNIT READY, no COMMIT.
    assert!(!ep.sent_finish());
}

#[test]
fn probe_none_accepted_when_all_reject_with_bd() {
    let image = plaintext(CHUNK);
    let mut drive = MockDrive::new(None); // rejects every candidate with 0xBD
    assert!(matches!(
        probe_encoding(&mut drive, &image),
        Err(ProbeError::NoneAccepted)
    ));
    assert_eq!(drive.prepares(), CANDIDATE_ENCODINGS.len());
    assert!(!drive.sent_finish());
}

#[test]
fn probe_distinguishes_illegal_field_from_wrong_encoding() {
    let image = plaintext(CHUNK);
    let mut drive = MockDrive::new(None);
    drive.reject = (5, 0x24, 0); // READ BUFFER illegal-field, not 0xBD
    match probe_encoding(&mut drive, &image) {
        Err(ProbeError::Rejected {
            key: 5,
            asc: 0x24,
            ascq: 0,
        }) => {}
        other => panic!("expected a 5/0x24 Rejected, got {other:?}"),
    }
    // Stopped at the first candidate; did not keep trying.
    assert_eq!(drive.prepares(), 1);
}

#[test]
fn probe_rejects_a_short_image() {
    let mut drive = MockDrive::new(Some(super::PP));
    assert!(matches!(
        probe_encoding(&mut drive, &plaintext(CHUNK - 16)),
        Err(ProbeError::ImageTooShort(_))
    ));
    assert_eq!(drive.prepares(), 0);
}

/// EP (BH16NS40/WH16NS58 "complete path"): the first chunk carries an AES
/// header at 0x3000 with a plaintext body, and only the EP drive accepts it;
/// a PP or EE drive rejects it pre-erase with sense 0xBD.
#[test]
fn probe_covers_ep_wire_and_reject() {
    let image = plaintext(CHUNK);

    // The EP candidate's wire: 16-byte header at 0x3000 encrypted, body plaintext.
    let chunk = super::first_chunk(&image, super::EP).unwrap();
    let mut encrypted_header = image[0x3000..0x3010].to_vec();
    enc::encrypt(&mut encrypted_header).unwrap();
    assert_eq!(
        &chunk[0x3000..0x3010],
        &encrypted_header[..],
        "EP header encrypted"
    );
    assert_eq!(
        &chunk[..0x3000],
        &image[..0x3000],
        "EP body before header plaintext"
    );
    assert_eq!(
        &chunk[0x3010..],
        &image[0x3010..],
        "EP body after header plaintext"
    );

    // An EP drive accepts the EP chunk...
    let ep_drive = MockDrive::new(Some(super::EP));
    assert_eq!(MockDrive::decode(super::EP, &chunk), ep_drive.plain_chunk);
    // ...while PP and EE drives reject that same EP chunk (header/body mismatch),
    // which the probe reads as the wrong-encoding 0xBD and skips.
    for other in [super::PP, super::EE] {
        let d = MockDrive::new(Some(other));
        assert_ne!(
            MockDrive::decode(other, &chunk),
            d.plain_chunk,
            "{other:?} rejects EP"
        );
    }

    // End to end: an EP drive is detected (after PP and EE are tried and 0xBD'd).
    let mut drive = MockDrive::new(Some(super::EP));
    assert_eq!(probe_encoding(&mut drive, &image).unwrap(), super::EP);
    assert_eq!(drive.prepares(), 3, "PP, then EE, then EP");
    assert!(!drive.sent_finish());
}

#[test]
fn apply_encoding_round_trips() {
    for encoding in [super::PP, super::EE, super::EP] {
        let plain = plaintext(CHUNK);
        let mut wire = plain.clone();
        super::apply_encoding(&mut wire, encoding);
        // Reversing the encoding restores the plaintext.
        assert_eq!(MockDrive::decode(encoding, &wire), plain, "{encoding:?}");
        if encoding != super::PP {
            assert_ne!(wire, plain, "{encoding:?} must change the bytes");
        }
    }
}

#[test]
fn forced_wire_selection_matches_the_encoding() {
    let image = plaintext(CHUNK * 2);
    let header = &image[0x3000..0x3010];
    let mut encrypted_header = header.to_vec();
    enc::encrypt(&mut encrypted_header).unwrap();
    let mut whole = image.clone();
    enc::encrypt(&mut whole).unwrap();

    // PP streams the canonical image unchanged.
    assert!(super::forced_transfer(&image, super::PP).is_none());

    // EE is the whole-image envelope.
    assert_eq!(super::forced_transfer(&image, super::EE).unwrap(), whole);

    // EP encrypts only the 16-byte header; the body stays plaintext.
    let ep = super::forced_transfer(&image, super::EP).unwrap();
    assert_eq!(&ep[0x3000..0x3010], &encrypted_header[..]);
    assert_eq!(&ep[..0x3000], &image[..0x3000]);
    assert_eq!(&ep[0x3010..], &image[0x3010..]);
}

#[test]
fn forced_prepare_binds_the_chosen_encoding() {
    use crate::fixtures::{self, BU3};
    use crate::{envelope::layout, Identity, INQUIRY_LEN};

    let image = fixtures::image(&BU3, 1);
    let id = Identity::parse(
        &[0; INQUIRY_LEN],
        layout::BANNER.of(&image).unwrap(),
        layout::DESCRIPTOR.of(&image).unwrap(),
    )
    .unwrap();

    // PP: the transfer is the canonical image.
    let pp = ForcedUpdate::prepare(&image, &id, super::PP).unwrap();
    assert_eq!(pp.encoding(), super::PP);
    assert_eq!(pp.transfer(), &image[..]);

    // EE: the transfer is the whole-image AES envelope.
    let ee = ForcedUpdate::prepare(&image, &id, super::EE).unwrap();
    let mut whole = image.clone();
    enc::encrypt(&mut whole).unwrap();
    assert_eq!(ee.encoding(), super::EE);
    assert_eq!(ee.transfer(), &whole[..]);
}

#[test]
fn forced_prepare_rejects_a_non_image() {
    use crate::Identity;
    let id = Identity::parse(&[0; crate::INQUIRY_LEN], b"", b"").unwrap();
    // A buffer that is not a full image fails the chip/family gate.
    assert!(ForcedUpdate::prepare(&[0u8; 1024], &id, super::EE).is_err());
}

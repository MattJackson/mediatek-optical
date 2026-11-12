use super::*;
use crate::update::StartupError;

#[test]
fn unconfirmed_startup_maps_to_startup_error() {
    let e = from_execute::<&'static str>(receiver::ExecutionError::Flash(FlashError::Startup(
        StartupError::TargetMismatch,
    )));
    assert!(matches!(e, Error::Startup(StartupError::TargetMismatch)));
    // The same failure has the same code through either execution path.
    assert_eq!(
        crate::CodedError::code(&e),
        "mediatek.startup.target_mismatch"
    );
    let through_receiver = receiver::ExecutionError::<&'static str>::Flash(FlashError::Startup(
        StartupError::TargetMismatch,
    ));
    assert_eq!(
        crate::CodedError::code(&through_receiver),
        crate::CodedError::code(&e)
    );
    assert_eq!(e.phase(), through_receiver.phase());
    assert_eq!(e.phase(), "target startup");
    assert!(e.firmware_write_started() && through_receiver.firmware_write_started());
    let entry = receiver::ExecutionError::<&'static str>::Flash(FlashError::Entry(
        crate::drive::Error::Transport("prepare"),
    ));
    assert_eq!(entry.phase(), "update entry");
    assert!(!entry.firmware_write_started());
    assert_eq!(from_execute(entry).phase(), "update entry");
}

/// One physical drive behind both transports: reads serve the stored image,
/// and the streamed transfer replaces it when its last chunk lands.
struct Sim {
    image: Vec<u8>,
    pending: Vec<u8>,
    log: Vec<(Vec<u8>, usize)>,
}
impl Sim {
    fn exec(&mut self, cdb: &[u8], data: drive::Data<'_>) -> Result<usize, &'static str> {
        use drive::Data;
        let len = match &data {
            Data::None => 0,
            Data::In(buf) => buf.len(),
            Data::Out(bytes) => bytes.len(),
        };
        self.log.push((cdb.to_vec(), len));
        match (cdb[0], data) {
            (0x12, Data::In(out)) => {
                out.fill(0);
                out[0] = 5;
                out[4] = 31;
                out[8..36].copy_from_slice(
                    &self.image[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28],
                );
                Ok(out.len())
            }
            (0x3C, Data::In(out)) => {
                let at = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]) as usize;
                out.copy_from_slice(&self.image[at..at + out.len()]);
                Ok(out.len())
            }
            (0x03, Data::In(out)) => {
                out.fill(0);
                out[0] = 0x70;
                Ok(out.len())
            }
            (0x3B, Data::Out(bytes)) if cdb[1] == 0x06 && !bytes.is_empty() => {
                let at = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]) as usize;
                self.pending[at..at + bytes.len()].copy_from_slice(bytes);
                if at + bytes.len() == layout::IMAGE_SIZE {
                    self.image = self.pending.clone();
                }
                Ok(bytes.len())
            }
            (_, Data::Out(bytes)) => Ok(bytes.len()),
            _ => Ok(0),
        }
    }
}
struct Handle(std::rc::Rc<std::cell::RefCell<Sim>>);
impl drive::Transport for Handle {
    type Error = &'static str;
    fn exec(&mut self, cdb: &[u8], data: drive::Data<'_>) -> Result<usize, Self::Error> {
        self.0.borrow_mut().exec(cdb, data)
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}
struct Clock;
impl crate::update::ExecutionRuntime<&'static str> for Clock {
    fn elapsed(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    fn sleep(&mut self, _: std::time::Duration) {
        panic!("the simulated drive is ready at once")
    }
}

/// A live-code BU3 application receiver whose stored image is `image`.
fn live_drive(image: &[u8]) -> std::rc::Rc<std::cell::RefCell<Sim>> {
    std::rc::Rc::new(std::cell::RefCell::new(Sim {
        image: image.to_vec(),
        pending: vec![0xFF; layout::IMAGE_SIZE],
        log: Vec::new(),
    }))
}
fn live_image() -> Vec<u8> {
    // The plaintext application receiver excerpt (receiver.rs PLAIN_APP),
    // masked bytes zeroed, as profile_tests.rs stamps it.
    const PLAIN_APP: [u8; 24] = [
        0x03, 0x20, 0x00, 0x49, 0x00, 0x03, 0x20, 0x18, 0x09, 0x68, 0x00, 0x02, 0x00, 0x0a, 0x40,
        0x18, 0x00, 0xa9, 0x09, 0x5d, 0x00, 0x78, 0x88, 0x42,
    ];
    let mut image = crate::fixtures::image(&crate::fixtures::BU3, 7);
    image[0x9a300..0x9a300 + PLAIN_APP.len()].copy_from_slice(&PLAIN_APP);
    crate::fixtures::sign(image)
}

#[test]
fn recovery_reports_an_unobserved_restart_as_evidence_not_confirmed_startup() {
    // Reflashing the installed build: INQUIRY reports the same vendor,
    // product and revision before and after the write, so it cannot tell the
    // old firmware still running apart from the target having started.
    let image = live_image();
    let drive = live_drive(&image);
    let identified = Receiver::identify(&mut Handle(drive.clone()))
        .unwrap()
        .unwrap();
    let prepared = identified.prepare(&image).unwrap();
    let completion = prepared
        .flash_completed(
            FlashTransport {
                reads: &mut Handle(drive.clone()),
                writes: &mut Handle(drive.clone()),
            },
            &mut Clock,
        )
        .unwrap();
    assert!(
        drive
            .borrow()
            .log
            .iter()
            .any(|(cdb, _)| cdb[..2] == [0x3B, 0x07]),
        "the write completed"
    );
    assert_eq!(
        completion.startup.evidence(),
        crate::update::StartupEvidence::Unobserved
    );
    assert!(matches!(
        completion.readback,
        crate::update::ReadbackQuality::Complete(_)
    ));
}

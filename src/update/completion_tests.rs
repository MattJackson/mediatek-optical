use super::*;
use crate::drive::{Data, Transport};
use crate::receiver::{self, DetectedMode};

struct Inquiry([u8; INQUIRY_LEN]);
impl Transport for Inquiry {
    type Error = &'static str;
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        assert_eq!(cdb[0], 0x12);
        let Data::In(out) = data else {
            panic!("INQUIRY only")
        };
        out.copy_from_slice(&self.0[..out.len()]);
        Ok(out.len())
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}

/// A detected identity with `revision`; `extra` fills the bytes outside
/// vendor, product and revision.
fn mode(revision: &[u8; 4], extra: u8) -> DetectedMode {
    let mut inquiry = [extra; INQUIRY_LEN];
    inquiry[0] = 5;
    inquiry[4] = 31;
    inquiry[8..16].copy_from_slice(b"HL-DT-ST");
    inquiry[16..32].copy_from_slice(b"BD-RE  BU40N    ");
    inquiry[32..36].copy_from_slice(revision);
    receiver::detect_mode(&mut Inquiry(inquiry)).unwrap()
}

#[test]
fn classify_uses_only_prior_mode_and_identity_bytes() {
    let live = mode(b"1.04", 0);
    for (prior, want) in [
        (mode(b"BOOT", 0), StartupEvidence::LeftBoot),
        (mode(b"BOOT", 7), StartupEvidence::LeftBoot),
        (mode(b"1.03", 0), StartupEvidence::IdentityChanged),
        (mode(b"1.03", 7), StartupEvidence::IdentityChanged),
        (mode(b"1.04", 0), StartupEvidence::Unobserved),
        // Bytes outside 8..36 may be synthesized for reference receivers and
        // are not revalidated; they never count as a change.
        (mode(b"1.04", 7), StartupEvidence::Unobserved),
    ] {
        assert_eq!(classify(&prior, &live), want, "{:?}", prior.inquiry());
    }
}

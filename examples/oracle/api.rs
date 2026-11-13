//! The API-facing half of the oracle: what one image observes through the
//! public API. Rewritten per API generation; its output must not change.

use mediatek_optical::drive::{Data, Transport};
use mediatek_optical::image::analysis as analysis;
use mediatek_optical::{envelope, image, receiver, recovery, update, CodedError, Identity};
use serde_json::{json, Value};

use crate::{debug_sha, digest};

fn fail<E: core::fmt::Display + CodedError>(e: &E) -> Value {
    json!({ "error": e.to_string(), "code": e.code() })
}

fn shown<E: core::fmt::Display>(e: &E) -> Value {
    json!({ "error": e.to_string() })
}

/// A drive whose flash is `image`, answering INQUIRY with its descriptor's
/// identity: the receiver and recovery detectors run over it as over a drive.
struct ImageDrive<'a> {
    image: &'a [u8],
    inquiry: [u8; 36],
}

impl<'a> ImageDrive<'a> {
    fn new(image: &'a [u8]) -> Self {
        let mut inquiry = [0; 36];
        inquiry[0] = 5;
        inquiry[4] = 31;
        if let Some(d) = image.get(0x1E_C000..0x1E_C000 + 28) {
            inquiry[8..36].copy_from_slice(d);
        }
        Self { image, inquiry }
    }
}

impl Transport for ImageDrive<'_> {
    type Error = String;
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, String> {
        let Data::In(bytes) = data else {
            return Err("read-only".into());
        };
        match cdb[0] {
            0x12 => {
                let n = bytes.len().min(36);
                bytes[..n].copy_from_slice(&self.inquiry[..n]);
                Ok(n)
            }
            0x3C => {
                let at = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
                let src = self.image.get(at..at + bytes.len()).ok_or("outside")?;
                bytes.copy_from_slice(src);
                Ok(bytes.len())
            }
            op => Err(format!("unsupported opcode {op:#04x}")),
        }
    }
}

fn plan(plan: &receiver::TransferPlan) -> Value {
    let steps: String = plan
        .steps()
        .iter()
        .map(|s| format!("{} {:02x?} {:?} {}\n", s.label, s.cdb, s.direction, s.length))
        .collect();
    json!({
        "receiver": format!(
            "{:?} {:?} {:#x} {:?} {:?}",
            plan.receiver().mode(),
            plan.receiver().encoding(),
            plan.receiver().signature_address(),
            plan.receiver().provenance(),
            plan.receiver().reference_sha256().map(|d| digest(d)),
        ),
        "class": format!("{:?}", plan.class()),
        "encoding": format!("{:?}", plan.encoding()),
        "prepare_command": format!("{:?}", plan.prepare_command()),
        "programmed": format!("{:x?}", plan.programmed_ranges()),
        "preserved": format!("{:x?}", plan.preserved_ranges()),
        "image": digest(plan.image()),
        "transfer": digest(plan.transfer()),
        "steps": digest(steps.as_bytes()),
    })
}

fn identity_of(image: &[u8]) -> Identity {
    Identity::parse(
        &[0; mediatek_optical::INQUIRY_LEN],
        mediatek_optical::layout::BANNER.of(image).unwrap_or_default(),
        mediatek_optical::layout::DESCRIPTOR.of(image).unwrap_or_default(),
    )
    .unwrap()
}

fn analyses(image: &[u8]) -> Value {
    let a = analysis::ImageAnalysis::inspect(image);
    let d = |r: Result<String, String>| match r {
        Ok(s) => json!(s),
        Err(e) => json!({ "error": e }),
    };
    json!({
        "identity": d(a.identity().map(|v| debug_sha(v)).map_err(|e| e.to_string())),
        "scanner": d(a.scanner().map(|v| debug_sha(v)).map_err(|e| format!("{e:?}"))),
        "commands": d(a.commands().map(|v| debug_sha(&(v.scanner(), v.roots(), v.records()))).map_err(|e| format!("{e:?}"))),
        "response": d(a.response().map(|v| debug_sha(v)).map_err(|e| format!("{e:?}"))),
        "vid": d(a.vid().map(|v| debug_sha(v)).map_err(|e| format!("{e:?}"))),
        "authentication": d(a.authentication().map(|v| debug_sha(v)).map_err(|e| format!("{e:?}"))),
        "media": d(a.media().map(|v| debug_sha(v)).map_err(|e| format!("{e:?}"))),
        "speed_policy": d(a.speed_policy().map(|v| debug_sha(v)).map_err(|e| format!("{e:?}"))),
        "classic_speed": d(a.classic_speed().map(|v| debug_sha(v)).map_err(|e| format!("{e:?}"))),
        "uhd": debug_sha(a.uhd()),
        "ram": debug_sha(&analysis::RamReferences::inspect(image)),
        "legacy_stack_di": d(analysis::LegacyStackDi::detect(image).map(|v| debug_sha(&v)).map_err(|e| format!("{e:?}"))),
        "classic_di": d(analysis::ClassicDi::detect(image).map(|v| debug_sha(&v)).map_err(|e| format!("{e:?}"))),
        "nv_record_copy": d(analysis::NvRecordCopy::detect(image).map(|v| debug_sha(&v)).map_err(|e| format!("{e:?}"))),
        "legacy_identity_reset": d(analysis::LegacyIdentityReset::detect(image).map(|v| debug_sha(&v)).map_err(|e| format!("{e:?}"))),
    })
}

pub(crate) fn image(bytes: &[u8]) -> Value {
    let chip = match image::detect_chip(bytes) {
        Ok(info) => json!(format!("{info:?}")),
        Err(e) => fail(&e),
    };
    let cmac = match image::cmac::verify_detailed(bytes) {
        Ok(v) => json!(v
            .iter()
            .map(|e| format!("{}:{:#x}-{:#x}:{}", e.entry.index, e.entry.start, e.entry.end, e.matches))
            .collect::<Vec<_>>()),
        Err(e) => fail(&e),
    };
    let resign = match image::cmac::resign(bytes) {
        Ok(v) => json!(digest(&v)),
        Err(e) => fail(&e),
    };
    let mut encrypted = bytes.to_vec();
    let enc = match mediatek_optical::enc::encrypt(&mut encrypted) {
        Ok(()) => json!(digest(&encrypted)),
        Err(e) => fail(&e),
    };
    let loaded = envelope::Envelope::load(bytes);
    let env = match &loaded {
        Ok(e) => json!(format!(
            "{:?} {:?} {} {}",
            e.input_encoding(),
            e.chip(),
            digest(e.image()),
            digest(e.original())
        )),
        Err(e) => fail(e),
    };
    // The encrypted form must load back to the same canonical image.
    let env_encrypted = match envelope::Envelope::load(&encrypted) {
        Ok(e) => json!(format!("{:?} {:?} {}", e.input_encoding(), e.chip(), digest(e.image()))),
        Err(e) => fail(&e),
    };
    let live = identity_of(bytes);
    let check = match update::ValidatedUpdate::check(bytes, &live) {
        Ok(f) => json!(f.to_string()),
        Err(e) => fail(&e),
    };
    let installed = update::InstalledFirmware::new(live.clone(), bytes);
    let validated = match &installed {
        Ok(i) => update::ValidatedUpdate::prepare(bytes, i),
        Err(e) => Err(e.clone()),
    };
    let validated_json = match &validated {
        Ok(v) => json!({
            "class": format!("{:?}", v.class()),
            "family": v.family().to_string(),
            "image": digest(v.image()),
            "transfer": digest(v.transfer()),
            "verify": format!("{:x?}", v.verification_ranges()),
        }),
        Err(e) => fail(e),
    };
    let without = match update::ValidatedUpdate::prepare_without_installed(bytes, &live) {
        Ok(v) => json!(digest(v.transfer())),
        Err(e) => fail(&e),
    };
    // Receiver bound from this image as Current firmware (offline reference).
    let reference = match &loaded {
        Ok(env) => match receiver::Receiver::from_firmware(env) {
            Ok(r) => {
                let bound = match &validated {
                    Ok(v) => match r.bind_prepared(v) {
                        Ok(p) => plan(p.plan()),
                        Err(e) => fail(&e),
                    },
                    Err(e) => fail(e),
                };
                json!({
                    "receiver": format!("{:?} {:?} {:#x}", r.mode(), r.encoding(), r.signature_address()),
                    "analysis": r.application_analysis().map(|a| debug_sha(a)),
                    "plan": bound,
                })
            }
            Err(e) => fail(&e),
        },
        Err(_) => Value::Null,
    };
    // The same receiver detected live, over a drive whose flash is this image.
    let mut drive = ImageDrive::new(bytes);
    let live_receiver = match receiver::detect_mode(&mut drive) {
        Ok(mode) => match receiver::detect(&mut drive, &mode) {
            Ok(r) => {
                let encoding = receiver::detect_encoding(&mut drive, &mode)
                    .map(|e| format!("{:?}", e.encoding()))
                    .unwrap_or_else(|e| e.to_string());
                let bound = match &validated {
                    Ok(v) => match r.bind_prepared(v) {
                        Ok(p) => plan(p.plan()),
                        Err(e) => fail(&e),
                    },
                    Err(e) => fail(e),
                };
                json!({
                    "mode": format!("{:?}", mode.mode()),
                    "receiver": format!("{:?} {:?} {:#x}", r.mode(), r.encoding(), r.signature_address()),
                    "encoding": encoding,
                    "plan": bound,
                })
            }
            Err(e) => fail(&e),
        },
        Err(e) => fail(&e),
    };
    // Recovery against the same drive, with this image as its reference.
    let recovery = match &loaded {
        Ok(env) => match recovery::Receiver::identify_reference(&mut ImageDrive::new(bytes), env) {
            Ok(r) => match r.prepare(bytes) {
                Ok(p) => json!({
                    "chip": format!("{:?}", r.chip()),
                    "plan": plan(p.plan()),
                }),
                Err(e) => fail(&e),
            },
            Err(e) => fail(&e),
        },
        Err(_) => Value::Null,
    };
    json!({
        "len": bytes.len(),
        "chip": chip,
        "family": image::family(bytes).map(|f| f.to_string()),
        "hardware": image::hardware(bytes).map(|h| h.key()),
        "is_drive_read": image::is_drive_read(bytes),
        "is_uhd": image::is_uhd(bytes),
        "content_key": mediatek_optical::oem::content_key(bytes).map(|k| digest(&k)),
        "cmac": cmac,
        "cmac_ok": image::cmac::verify(bytes),
        "resign": resign,
        "enc": enc,
        "envelope": env,
        "envelope_encrypted": env_encrypted,
        "check": check,
        "installed": installed.as_ref().map(|i| i.family().map(|f| f.to_string())).map_err(shown).map_or_else(|e| e, |v| json!(v)),
        "prepare": validated_json,
        "prepare_without_installed": without,
        "reference": reference,
        "live": live_receiver,
        "recovery": recovery,
        "analysis": analyses(bytes),
    })
}

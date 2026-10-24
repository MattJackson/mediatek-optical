//! Stable code classification; additions must carry an explicit host category.

pub(super) fn kind_for_code(code: &str) -> crate::operation::IssueKind {
    use crate::operation::IssueKind;
    match code {
        "mediatek.chip.unknown_label"
        | "mediatek.drive.oversize"
        | "mediatek.enc.length"
        | "mediatek.image.undetectable_chip"
        | "mediatek.cmac.image_too_small"
        | "mediatek.cmac.bad_range"
        | "mediatek.prepare.receiver_entry"
        | "mediatek.prepare.receiver_contract"
        | "mediatek.prepare.size"
        | "mediatek.prepare.integrity"
        | "mediatek.prepare.drive_read"
        | "mediatek.prepare.unknown_chip"
        | "mediatek.envelope.image"
        | "mediatek.envelope.ambiguous"
        | "mediatek.oem.size"
        | "mediatek.oem.chip"
        | "mediatek.oem.factory"
        | "mediatek.reference.analysis"
        | "mediatek.layout.alignment"
        | "mediatek.layout.range"
        | "mediatek.layout.conflict"
        | "mediatek.layout.multiple_decryptions"
        | "mediatek.layout.no_program"
        | "mediatek.layout.image_size" => IssueKind::InvalidFirmware,
        "mediatek.drive.transport"
        | "mediatek.drive.short"
        | "mediatek.receiver.read"
        | "mediatek.receiver.invalid_identity"
        | "mediatek.startup.read"
        | "mediatek.recovery.read" => IssueKind::Connection,
        "mediatek.prepare.unknown_drive_chip"
        | "mediatek.prepare.unknown_installed_family"
        | "mediatek.prepare.unknown_target_family"
        | "mediatek.envelope.unknown_framing"
        | "mediatek.oem.no_factory"
        | "mediatek.oem.unknown_boot_page"
        | "mediatek.receiver.unknown"
        | "mediatek.receiver.conflict"
        | "mediatek.receiver.unknown_entry" => IssueKind::UnsupportedFirmware,
        "mediatek.prepare.chip_mismatch" | "mediatek.prepare.family_mismatch" => {
            IssueKind::HardwareMismatch
        }
        "mediatek.prepare.installed_mismatch"
        | "mediatek.receiver.changed"
        | "mediatek.reference.binding"
        | "mediatek.recovery.changed" => IssueKind::ReceiverMismatch,
        "mediatek.flash.entry"
        | "mediatek.flash.transfer"
        | "mediatek.flash.fault"
        | "mediatek.flash.ready_timeout"
        | "mediatek.flash.startup"
        | "mediatek.startup.identity"
        | "mediatek.execute.receiver"
        | "mediatek.execute.flash"
        | "mediatek.recovery.receiver"
        | "mediatek.recovery.reference"
        | "mediatek.recovery.image"
        | "mediatek.recovery.flash"
        | "mediatek.recovery.startup" => IssueKind::Update,
        "mediatek.flash.mismatch"
        | "mediatek.flash.incomplete"
        | "mediatek.startup.target_mismatch" => IssueKind::Verification,
        _ => IssueKind::Unexpected,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_declared_code_has_a_deliberate_host_category() {
        for source in [include_str!("error_codes.rs")] {
            for code in source.split('"').filter(|s| {
                s.starts_with("mediatek.")
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_')
            }) {
                assert_ne!(
                    super::kind_for_code(code),
                    crate::operation::IssueKind::Unexpected,
                    "unclassified error code: {code}"
                );
            }
        }
    }
}

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

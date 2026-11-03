#[test]
fn every_declared_code_has_a_deliberate_host_category() {
    for source in [include_str!("error_codes.rs")] {
        let codes: Vec<&str> = source
            .split('"')
            .filter(|s| s.starts_with("mediatek.") && !s.contains(char::is_whitespace))
            .collect();
        assert!(!codes.is_empty(), "no error codes extracted");
        for code in codes {
            assert_ne!(
                super::kind_for_code(code),
                crate::operation::IssueKind::Unexpected,
                "unclassified error code: {code}"
            );
        }
    }
}

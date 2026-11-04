use super::*;
#[test]
fn product_context_does_not_replace_the_drive_model() {
    let id = ProductIdentity::from_id("PIONEER BDR-206PA PP-100", "2.02").unwrap();
    assert_eq!(id.vendor, "PIONEER");
    assert_eq!(id.model, Some("BDR-206PA"));
    assert_eq!(id.product_suffix, "PP-100");
    assert_eq!(id.product, "BDR-206PA PP-100");
    assert_eq!(
        ProductIdentity::from_id("PIONEER BDR-206PB PP-100", "2.02")
            .unwrap()
            .model,
        Some("BDR-206PB")
    );
}
#[test]
fn archived_oem_product_grammars_keep_the_actual_drive_model() {
    for (raw, model) in [
        ("AOPEN 8X8 DVD Dual APP", "APP"),
        ("Optiarc BD ROM BC-5100S", "BC-5100S"),
        ("PIONEER DVD RW DVR-106D", "DVR-106D"),
        ("PLEXTOR DVDR PX-608CU", "PX-608CU"),
        ("PLEXTOR DVDR PX-810SA", "PX-810SA"),
        ("PLEXTOR BD-R PX-B940SA", "PX-B940SA"),
        ("Memorex DVD+/-RW True-8X", "True-8X"),
        ("PIONEER BDE-PR1EP PP100", "BDE-PR1EP"),
        ("PIONEER BDR-PR1EPA PP100", "BDR-PR1EPA"),
    ] {
        assert_eq!(
            ProductIdentity::from_id(raw, "").unwrap().model,
            Some(model),
            "{raw}"
        );
    }
    let missing_vendor = ProductIdentity::from_id("DVD RW DVR-MCC", "").unwrap();
    assert_eq!(missing_vendor.vendor, "");
    assert_eq!(missing_vendor.model, Some("DVR-MCC"));
}

#[test]
fn media_prefixes_and_variant_suffixes_are_preserved_separately() {
    for (raw, model, suffix) in [
        ("BD-RW   BDR-212U", "BDR-212U", ""),
        ("BDRE BU40N", "BU40N", ""),
        ("BD-RE BH16NS40", "BH16NS40", ""),
        ("BC-12B1ST b", "BC-12B1ST", "b"),
    ] {
        let id = ProductIdentity::from_fields("vendor", raw, "1.00");
        assert_eq!(id.model, Some(model));
        assert_eq!(id.product_suffix, suffix);
        assert_eq!(id.product, raw);
    }
    assert_eq!(
        ProductIdentity::from_fields("vendor", " BD-RW ", "").model,
        None
    );
    assert_eq!(ProductIdentity::from_fields("vendor", "", "").model, None);
    assert!(ProductIdentity::from_id("missing-separator", "").is_none());
}

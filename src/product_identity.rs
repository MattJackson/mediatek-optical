//! Structured product identity shared by live INQUIRY and firmware metadata.

/// A borrowed, display-oriented view of an optical product identity.
/// Raw vendor/product/revision values are preserved; parsing never changes flash compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductIdentity<'a> {
    /// Raw manufacturer/vendor identification.
    pub vendor: &'a str,
    /// Raw product identification, including media class and any OEM suffix.
    pub product: &'a str,
    /// Drive model: the first product token after any standard media-class prefixes.
    pub model: Option<&'a str>,
    /// Remaining product context, such as `PP-100` or a board variant letter.
    pub product_suffix: &'a str,
    /// Raw firmware revision.
    pub revision: &'a str,
}

fn product_prefix(word: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "BDRE",
        "BD-RE",
        "BDRW",
        "BD-RW",
        "BDROM",
        "BD-ROM",
        "BDDVDRW",
        "BDDVDW",
        "DVDRW",
        "DVD-RW",
        "DVDROM",
        "DVD-ROM",
        "DVDRAM",
        "DVD-RAM",
        "DVD+RW",
        "CDDVDW",
        "CDRW",
        "CD-RW",
        "BD",
        "DVD",
        "CD",
        "ROM",
        "RW",
        "R/RW",
        "DVDR",
        "BD-R",
        "DVD+/-RW",
        "DVD-R/RW",
        "DUAL",
        "MULTI",
        "COMBO",
        "BD-MLT",
        "DVD-MLT",
        "DVD-MULTI",
    ];
    PREFIXES
        .iter()
        .any(|prefix| prefix.eq_ignore_ascii_case(word))
        || (word.bytes().any(|b| b == b'x' || b == b'X')
            && word.bytes().any(|b| b.is_ascii_digit())
            && word
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'x' || b == b'X'))
}

impl<'a> ProductIdentity<'a> {
    /// Interpret separate INQUIRY/descriptor fields without filename heuristics.
    pub fn from_fields(vendor: &'a str, product: &'a str, revision: &'a str) -> Self {
        let mut rest = product.trim();
        let model = loop {
            if rest.is_empty() {
                break None;
            }
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let word = &rest[..end];
            rest = rest[end..].trim_start();
            if !product_prefix(word) {
                break Some(word);
            }
        };
        Self {
            vendor,
            product,
            model,
            product_suffix: rest,
            revision,
        }
    }

    /// Interpret a firmware `ID` field containing vendor followed by product.
    /// A missing separator remains unknown rather than inventing a vendor/model split.
    pub fn from_id(id: &'a str, revision: &'a str) -> Option<Self> {
        let (vendor, product) = id.trim().split_once(char::is_whitespace)?;
        if product_prefix(vendor) {
            Some(Self::from_fields("", id.trim(), revision))
        } else {
            Some(Self::from_fields(vendor, product.trim_start(), revision))
        }
    }
}

#[cfg(test)]
mod tests {
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
}

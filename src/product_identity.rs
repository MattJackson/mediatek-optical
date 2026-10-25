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

impl<'a> ProductIdentity<'a> {
    /// Interpret separate INQUIRY/descriptor fields without filename heuristics.
    pub fn from_fields(vendor: &'a str, product: &'a str, revision: &'a str) -> Self {
        const MEDIA: &[&str] = &[
            "BDRE", "BD-RE", "BDRW", "BD-RW", "BDROM", "BD-ROM", "BDDVDRW", "BDDVDW", "DVDRW",
            "DVD-RW", "DVDROM", "DVD-ROM", "DVDRAM", "DVD-RAM", "DVD+RW", "CDDVDW", "CDRW",
            "CD-RW",
        ];
        let mut rest = product.trim();
        let model = loop {
            if rest.is_empty() {
                break None;
            }
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let word = &rest[..end];
            rest = rest[end..].trim_start();
            if !MEDIA.iter().any(|prefix| prefix.eq_ignore_ascii_case(word)) {
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
        Some(Self::from_fields(vendor, product.trim_start(), revision))
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

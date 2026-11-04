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
#[path = "product_identity_tests.rs"]
mod tests;

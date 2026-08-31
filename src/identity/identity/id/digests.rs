//! The digest identities: [`TreeDigest`] and [`ReleaseDigest`] — exactly 64
//! lowercase hex characters (sha256), the exact form
//! [`crate::digest::sha256_bytes`] produces. Any other string — empty,
//! short, long, uppercase, non-hex, or prefixed — is rejected at the domain
//! boundary.

use super::id_newtype;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A valid sha256 digest: exactly 64 lowercase hex characters (the exact form
/// [`crate::digest::sha256_bytes`] produces). Any other string — empty, short,
/// long, uppercase, non-hex, or prefixed — is rejected.
pub(crate) fn valid_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

id_newtype!(
    ReleaseDigest,
    valid_hex_digest,
    "A release digest: exactly 64 lowercase hex characters (sha256) — the \
     exact form [`crate::digest::sha256_bytes`] produces."
);

id_newtype!(
    TreeDigest,
    valid_hex_digest,
    "A tree digest: exactly 64 lowercase hex characters (sha256) — the exact \
     form [`crate::digest::sha256_bytes`] produces."
);

impl ReleaseDigest {
    /// Raw constructor from an ALREADY-VALIDATED digest string — identity
    /// internal only: [`crate::identity::release_id::ReleaseId::digest`]
    /// rebuilds the digest from a string stripped off a valid release id
    /// (which is, by construction, exactly 64 lowercase hex). Production
    /// code must construct through the validated [`parse`].
    pub(crate) fn from_validated_string(s: String) -> Self {
        ReleaseDigest(s)
    }
}

/// A deterministic 64-lowercase-hex sha256 digest derived from a tag.
#[cfg(test)]
pub(crate) fn test_sha256_hex(tag: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tag.hash(&mut h);
    let r = h.finish();
    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    (tag, r).hash(&mut h2);
    let r2 = h2.finish();
    format!("{r:016x}{r2:016x}{r:016x}{r2:016x}")
}

#[cfg(test)]
pub(crate) fn test_tree_digest(tag: &str) -> TreeDigest {
    TreeDigest::parse(&test_sha256_hex(tag)).expect("canonical test digest")
}

/// A deterministic valid [`crate::identity::BehaviorDigest`] derived from a tag
/// (test fixtures only: a behavior digest in a mutation input must be a valid
/// 64-lowercase-hex digest).
#[cfg(test)]
pub(crate) fn test_behavior_digest(tag: &str) -> crate::identity::BehaviorDigest {
    crate::identity::BehaviorDigest::parse(&test_sha256_hex(tag)).expect("canonical test digest")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// The digest identities require exactly 64 lowercase hex characters.
    #[test]
    fn digests_require_64_lowercase_hex() {
        let d = test_tree_digest("ok");
        assert_eq!(TreeDigest::parse(d.as_str()).expect("canonical"), d);
        assert_eq!(
            ReleaseDigest::parse(d.as_str()).expect("canonical"),
            ReleaseDigest::parse(d.as_str()).expect("canonical")
        );
        for bad in [
            "",
            "abc",
            &DIGEST.to_uppercase(),
            &format!("sha256-{DIGEST}"),
            &format!("{DIGEST}ff"),
            &DIGEST[..63],
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            TreeDigest::parse(bad).expect_err("invalid tree digest rejected");
            ReleaseDigest::parse(bad).expect_err("invalid release digest rejected");
        }
    }
}

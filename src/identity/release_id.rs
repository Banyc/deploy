//! The release identity: [`ReleaseId`] — EXACTLY `rel-sha256-<64 lowercase
//! hex>`, the canonical form [`ReleaseId::from_digest`] produces. The loose
//! bare-digest and `rel-` forms are rejected at the domain boundary: a
//! `ReleaseId` can only be built through the validated [`ReleaseId::parse`]
//! (or `FromStr`/`TryFrom`/`from_digest`), so a malformed release id can
//! never exist in a durable record. The CLI accepts a bare 64-hex digest as
//! an input convenience via [`crate::cli::parse_release_input`], which
//! converts it to the full form BEFORE the domain parse.

use super::digests::{ReleaseDigest, valid_hex_digest};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Release identifier: EXACTLY `rel-sha256-<64 lowercase hex>` — the canonical
/// form [`ReleaseId::from_digest`] produces. The loose bare-digest and `rel-`
/// forms are REJECTED at the domain boundary: a `ReleaseId` can only be built
/// through the validated [`ReleaseId::parse`] (or `FromStr`/`TryFrom`/
/// `from_digest`), so a malformed release id can never exist in a durable
/// record. The CLI accepts a bare 64-hex digest as an input convenience via
/// [`crate::cli::parse_release_input`], which converts it to the full form
/// BEFORE the domain parse.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ReleaseId(String);

impl ReleaseId {
    /// UNCHECKED constructor — TEST FIXTURES ONLY (mirrors the
    /// [`id_newtype!`] contract). Production code must construct through
    /// [`ReleaseId::parse`] (or `FromStr`/`TryFrom`/`from_digest`), so an
    /// invalid release id can never be built outside tests.
    #[cfg(test)]
    pub fn new(s: impl Into<String>) -> Self {
        ReleaseId(s.into())
    }
    pub fn from_digest(d: &ReleaseDigest) -> Self {
        ReleaseId(format!("rel-sha256-{}", d.as_str()))
    }
    /// Validate `s` against the EXACT `rel-sha256-<64 lowercase hex>` rule
    /// and construct the identity. The loose bare-digest and `rel-` forms
    /// are rejected HERE, at the domain boundary.
    pub fn parse(s: &str) -> Result<ReleaseId> {
        if let Some(rest) = s.strip_prefix("rel-sha256-")
            && valid_hex_digest(rest)
        {
            return Ok(ReleaseId(s.to_string()));
        }
        Err(Error::config(format!("invalid ReleaseId value {:?}", s)))
    }
    pub fn digest(&self) -> ReleaseDigest {
        ReleaseDigest::from_validated_string(self.0.trim_start_matches("rel-sha256-").to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReleaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ReleaseId {
    type Err = Error;
    fn from_str(s: &str) -> Result<ReleaseId> {
        ReleaseId::parse(s)
    }
}

impl TryFrom<&str> for ReleaseId {
    type Error = Error;
    fn try_from(s: &str) -> Result<ReleaseId> {
        ReleaseId::parse(s)
    }
}

impl<'de> Deserialize<'de> for ReleaseId {
    /// Wire strings go through the validated parse: an invalid wire release
    /// id fails deserialization (fail closed — a record that carries a
    /// malformed release id is never silently accepted).
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ReleaseId::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A deterministic canonical `rel-sha256-<64-hex>` release id derived from a
/// tag (the canonical form [`ReleaseId::from_digest`] produces — the only
/// form the strict [`ReleaseId::parse`] accepts).
#[cfg(test)]
pub(crate) fn test_release_id(tag: &str) -> ReleaseId {
    ReleaseId::from_digest(
        &ReleaseDigest::parse(&super::digests::test_sha256_hex(tag))
            .expect("canonical test digest"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_id_round_trip() {
        let d = "7b278acf5041d50a9704392ac9fac4c6c02ca2cf3be9e5aee61668c8070526d2";
        let rid = ReleaseId::from_digest(&ReleaseDigest::parse(d).expect("64 hex parses"));
        assert_eq!(rid.as_str(), format!("rel-sha256-{d}"));
        assert_eq!(
            rid,
            ReleaseId::from_digest(&ReleaseDigest::parse(d).expect("64 hex parses"))
        );
    }
}

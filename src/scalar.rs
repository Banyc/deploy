//! Validated scalar value types.
//!
//! The domain model carries a set of small values whose validity is part of
//! their meaning: an identifier must be a non-empty name, a behavior digest
//! must be a sha256 digest, an on-server `deploy_dir` must be an absolute
//! path, a batch size must be nonzero, a capacity percent must fit 0..=100,
//! and a recorded timestamp must parse as RFC 3339. Each such value is
//! wrapped in a NEWTYPE whose CONSTRUCTION validates the invariant (a
//! private inner value, reachable only through [`parse`]-style constructors
//! and read-only accessors) — an invalid value cannot be constructed, so the
//! domain never has to re-check what it holds.
//!
//! The raw/wire layers keep the bare forms (strings, integers, paths) and
//! the raw -> domain / wire -> domain conversions (in `crate::config` and
//! `crate::records`) parse them into these scalars, REJECTING invalid input
//! with a config/integrity error (fail closed). A scalar is deliberately NOT
//! introduced for a plain string that carries no invariant ("do not overdo
//! one-line wrappers when they carry no invariant") — only the fields below
//! get a type.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use jiff::Timestamp as JiffTimestamp;

use crate::error::{Error, Result};

/// A valid 64-lowercase-hex sha256 digest, shared by test fixtures that need
/// a well-formed behavior digest.
#[cfg(test)]
pub(crate) const DIGEST_TEST_HEX_1: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The name rule shared by the identifier-like scalars: non-empty after
/// trimming, no surrounding whitespace (a name is exactly what was written,
/// never silently trimmed), and no control characters.
fn valid_name(s: &str) -> bool {
    !s.trim().is_empty() && s.trim() == s && !s.chars().any(|c| c.is_control())
}

macro_rules! name_scalar {
    ($name:ident, $doc:expr, $rule:expr) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validate `s` and construct the scalar. The invariant is
            /// enforced HERE: any invalid value is rejected before a value
            /// of this type can exist.
            pub fn parse(s: &str) -> Result<$name> {
                if !$rule(s) {
                    return Err(Error::config(format!(
                        "invalid {} value {:?}",
                        stringify!($name),
                        s
                    )));
                }
                Ok($name(s.to_string()))
            }

            /// The validated value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<$name> {
                $name::parse(s)
            }
        }
    };
}

impl AsRef<std::path::Path> for Identifier {
    /// Identifiers are used directly as filesystem path segments (the
    /// per-server remote directory is named by the server id), so a
    /// validated identifier doubles as a path segment.
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

name_scalar!(
    Identifier,
    "A validated identifier (a server, slot, target, or variant name): \
     non-empty, no surrounding whitespace, no control characters. Used for \
     the id-bearing domain fields that have no dedicated id type; fields \
     with a dedicated type (DeploymentId, PlacementSlotId, ServerId, \
     ReleaseId, ...) keep it.",
    valid_name
);

name_scalar!(
    ApplicationName,
    "The deployment application name: a validated NON-EMPTY name. The \
    application has no format rule beyond non-emptiness (a deployment tool \
    name may be any non-empty string).",
    |s: &str| !s.trim().is_empty()
);

name_scalar!(
    GroupName,
    "A rollout group name, validated per the config rules: non-empty and \
    well-formed (no surrounding whitespace, no control characters). \
    DUPLICATE group names are a separate STRUCTURAL rule enforced by the \
    config conversion (a duplicate adds no membership yet would change the \
    release identity), not by this scalar.",
    valid_name
);

/// A sha256 behavior digest: exactly 64 lowercase hex characters (the exact
/// form [`crate::digest::sha256_bytes`] produces). Any other string — empty,
/// short, long, uppercase, non-hex, or prefixed — is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BehaviorDigest(String);

impl BehaviorDigest {
    /// Validate `s` as a sha256 digest and construct a [`BehaviorDigest`].
    pub fn parse(s: &str) -> Result<BehaviorDigest> {
        let ok = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return Err(Error::config(format!(
                "invalid behavior digest {:?}: expected 64 lowercase hex characters",
                s
            )));
        }
        Ok(BehaviorDigest(s.to_string()))
    }

    /// The validated digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BehaviorDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for BehaviorDigest {
    type Err = Error;
    fn from_str(s: &str) -> Result<BehaviorDigest> {
        BehaviorDigest::parse(s)
    }
}

/// An ABSOLUTE on-server directory. Construction requires an absolute path;
/// a relative or empty path is rejected (the scheduler never deploys into a
/// location relative to an unspecified working directory).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AbsoluteDeployDir(std::path::PathBuf);

impl AbsoluteDeployDir {
    /// Validate that `s` is an absolute path and construct an
    /// [`AbsoluteDeployDir`].
    pub fn parse(s: &str) -> Result<AbsoluteDeployDir> {
        let path = Path::new(s);
        if !path.is_absolute() {
            return Err(Error::config(format!(
                "invalid deploy_dir {:?}: must be an absolute path on the server",
                s
            )));
        }
        Ok(AbsoluteDeployDir(path.to_path_buf()))
    }

    /// The validated absolute path.
    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

impl fmt::Display for AbsoluteDeployDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string_lossy())
    }
}

impl FromStr for AbsoluteDeployDir {
    type Err = Error;
    fn from_str(s: &str) -> Result<AbsoluteDeployDir> {
        AbsoluteDeployDir::parse(s)
    }
}

/// A NONZERO rollout batch size: how many slots a target advances per
/// rollout batch. Zero is rejected — a zero batch would stall the rollout
/// without ever progressing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BatchSize(u64);

impl BatchSize {
    /// Construct a batch size, rejecting zero (the only invalid value).
    pub fn new(v: u64) -> Result<BatchSize> {
        if v == 0 {
            return Err(Error::config(
                "invalid batch size 0: a rollout batch must advance at least one slot",
            ));
        }
        Ok(BatchSize(v))
    }

    /// The nonzero batch size.
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl Default for BatchSize {
    fn default() -> Self {
        BatchSize(1)
    }
}

impl fmt::Display for BatchSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for BatchSize {
    type Err = Error;
    fn from_str(s: &str) -> Result<BatchSize> {
        let v: u64 = s.parse().map_err(|_| {
            Error::config(format!(
                "invalid batch size {s:?}: expected a nonzero integer"
            ))
        })?;
        BatchSize::new(v)
    }
}

/// A validated capacity percentage: the percent of the destination
/// filesystem's TOTAL size a deployment must keep free (0..=100).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CapacityPercent(u8);

impl CapacityPercent {
    /// Construct a capacity percent, rejecting any value outside 0..=100.
    pub fn new(v: u8) -> Result<CapacityPercent> {
        if v > 100 {
            return Err(Error::config(format!(
                "invalid capacity percent {v}: must be within 0..=100"
            )));
        }
        Ok(CapacityPercent(v))
    }

    /// The validated percentage (0..=100).
    pub fn get(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for CapacityPercent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CapacityPercent {
    type Err = Error;
    fn from_str(s: &str) -> Result<CapacityPercent> {
        let v: u8 = s.parse().map_err(|_| {
            Error::config(format!(
                "invalid capacity percent {s:?}: expected an integer"
            ))
        })?;
        CapacityPercent::new(v)
    }
}

/// A parsed RFC3339 timestamp ([`jiff::Timestamp`]): the canonical form for
/// every recorded moment (`attempted_at`, `recorded_at`). Construction
/// parses the string strictly, so an unparseable timestamp can never enter
/// the domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(JiffTimestamp);

impl Timestamp {
    /// Parse `s` as an RFC3339 timestamp and construct a [`Timestamp`].
    /// Uses the merged jiff parser (`jiff::Timestamp::from_str`), so any
    /// RFC3339 form — `2026-01-01T00:00:00Z`, offsets, fractional seconds —
    /// is accepted and anything else is rejected.
    pub fn parse(s: &str) -> Result<Timestamp> {
        let t = JiffTimestamp::from_str(s)
            .map_err(|_| Error::config(format!("invalid RFC3339 timestamp {s:?}")))?;
        Ok(Timestamp(t))
    }

    /// The parsed jiff timestamp.
    pub fn inner(&self) -> &JiffTimestamp {
        &self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Timestamp {
    type Err = Error;
    fn from_str(s: &str) -> Result<Timestamp> {
        Timestamp::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn identifier_accepts_valid_rejects_invalid() {
        for ok in ["s1", "production", "wave-1", "α", "x y", "a"] {
            let id = Identifier::parse(ok).expect("valid identifier parses");
            assert_eq!(id.as_str(), ok);
            assert_eq!(id.to_string(), ok);
            assert_eq!(ok.parse::<Identifier>().expect("from_str"), id);
        }
        for bad in ["", "   ", " x", "x ", "\u{0}", "a\nb"] {
            Identifier::parse(bad).expect_err("invalid identifier must be rejected");
            assert!(bad.parse::<Identifier>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn application_name_requires_non_empty() {
        for ok in ["app", "my app", "α", " x"] {
            let name = ApplicationName::parse(ok).expect("non-empty name parses");
            assert_eq!(name.as_str(), ok);
        }
        for bad in ["", "   ", "\n"] {
            ApplicationName::parse(bad).expect_err("empty application name rejected");
        }
    }

    #[test]
    fn group_name_accepts_valid_rejects_invalid() {
        for ok in ["canary", "wave-1", "α"] {
            let g = GroupName::parse(ok).expect("valid group parses");
            assert_eq!(g.as_str(), ok);
        }
        for bad in ["", "   ", " x", "x ", "\u{0}"] {
            GroupName::parse(bad).expect_err("invalid group name rejected");
        }
    }

    #[test]
    fn behavior_digest_requires_64_lowercase_hex() {
        let d = BehaviorDigest::parse(DIGEST).expect("64 lowercase hex parses");
        assert_eq!(d.as_str(), DIGEST);
        assert_eq!(d.to_string(), DIGEST);
        // Every invalid class: wrong length, uppercase, non-hex, empty,
        // prefixed.
        for bad in [
            "",
            DIGEST.trim_end_matches('5'),
            &format!("{DIGEST}ff"),
            &DIGEST.to_uppercase(),
            &format!("sha256-{DIGEST}"),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            BehaviorDigest::parse(bad).expect_err("invalid digest rejected");
        }
    }

    #[test]
    fn absolute_deploy_dir_requires_absolute_path() {
        for ok in ["/srv/p1", "/", "/srv/deploy/app"] {
            let d = AbsoluteDeployDir::parse(ok).expect("absolute path parses");
            assert!(d.as_path().is_absolute());
            assert_eq!(d.as_path(), std::path::Path::new(ok));
        }
        for bad in ["", "srv/p1", "relative", "./x", "../x"] {
            AbsoluteDeployDir::parse(bad).expect_err("relative deploy_dir rejected");
        }
    }

    #[test]
    fn batch_size_requires_nonzero() {
        for ok in [1u64, 42, u64::MAX] {
            let b = BatchSize::new(ok).expect("nonzero batch parses");
            assert_eq!(b.get(), ok);
            assert_eq!(ok.to_string().parse::<BatchSize>().expect("valid"), b);
        }
        assert_eq!(BatchSize::default().get(), 1);
        for bad in ["0", "-1", "abc"] {
            assert!(bad.parse::<BatchSize>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn capacity_percent_requires_0_to_100() {
        for ok in [0u8, 42, 100] {
            let c = CapacityPercent::new(ok).expect("in-range percent parses");
            assert_eq!(c.get(), ok);
            assert_eq!(ok.to_string().parse::<CapacityPercent>().expect("valid"), c);
        }
        assert_eq!(CapacityPercent::default().get(), 0);
        for bad in [101u8, 200, u8::MAX] {
            CapacityPercent::new(bad).expect_err("out-of-range percent rejected");
        }
        for bad in ["101", "-1", "abc"] {
            assert!(bad.parse::<CapacityPercent>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn timestamp_parses_rfc3339_and_rejects_invalid() {
        for ok in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.123+02:00",
            "2024-02-29T12:00:00Z",
        ] {
            let t = Timestamp::parse(ok).expect("RFC3339 parses");
            // jiff normalizes offset forms to their canonical UTC instant;
            // the canonical form must itself re-parse (round-trip stable).
            let canonical = t.inner().to_string();
            Timestamp::parse(&canonical).expect("canonical form re-parses");
        }
        for bad in [
            "",
            "yesterday",
            "2026-01-01",
            "2026-01-01T00:00:00",
            "not-a-time",
            "2026-13-01T00:00:00Z",
        ] {
            Timestamp::parse(bad).expect_err("unparseable timestamp rejected");
        }
    }
}

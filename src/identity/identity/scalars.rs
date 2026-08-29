//! Validated scalar value types.
//!
//! The domain model carries a set of small values whose validity is part of
//! their meaning: an identifier must be a non-empty name, a behavior digest
//! must be a sha256 digest, an on-server `deploy_dir` must be an absolute
//! TRAVERSAL-FREE path with at least one normal component below the root,
//! a batch size must be nonzero, a capacity percent
//! must fit 0..=100, and a recorded timestamp must parse as RFC 3339. The
//! application name is ONE safe identifier ([`ApplicationStoreKey`]): a
//! single normal filesystem component used for BOTH display (messages and
//! rendering) and storage (the one filesystem component that names the
//! local store directory). Each
//! such value is
//! wrapped in a NEWTYPE whose CONSTRUCTION validates the invariant (a
//! private inner value, reachable only through `parse`-style constructors
//! and read-only accessors) — an invalid value cannot be constructed, so the
//! domain never has to re-check what it holds.
//!
//! The raw/wire layers keep the bare forms (strings, integers, paths) and
//! the raw -> domain / wire -> domain conversions (in `crate::config` and
//! `crate::ledger`) parse them into these scalars, REJECTING invalid input
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
pub(crate) const DIGEST_TEST_HEX_1: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The name rule shared by the identifier-like scalars AND the identity
/// newtypes in [`crate::identity::segments`] (ServerId, SlotId, TargetName,
/// VariantName): non-empty after trimming, no surrounding
/// whitespace (a name is exactly what was written, never silently trimmed),
/// no control characters, and no path separators or traversal components — a
/// name is a SINGLE safe path segment. Names become directory components on a
/// server (the per-server remote directory is named by the server id), so a
/// name must never smuggle a separator (`/`, `\`) or a `.`/`..` traversal
/// component out of the forced namespace.
pub(crate) fn valid_name(s: &str) -> bool {
    !s.trim().is_empty()
        && s.trim() == s
        && !s.chars().any(|c| c.is_control())
        && !s.contains('/')
        && !s.contains('\\')
        && s != "."
        && s != ".."
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
     with a dedicated type (DeploymentId, SlotId, ServerId, \
     ReleaseId, ...) keep it.",
    valid_name
);

name_scalar!(
    Host,
    "A validated SSH host: the address of an SSH server. Non-empty, no \
    surrounding whitespace, no control characters, and no path separators or \
    traversal components — a host is a single safe token (a DNS name, an IP, \
    or a bracketed IPv6 literal), never a path. The pathless local marker \
    (the separate [`crate::config::ServerConnection::Local`] connection kind, \
    whose root is the slot's deploy_dir) is NOT a host: a host can never \
    smuggle a path out of the SSH namespace.",
    valid_name
);

name_scalar!(
    SshUser,
    "A validated SSH deployment account: the `user` of an SSH connection. \
    Non-empty, no surrounding whitespace, no control characters, and no path \
    separators or traversal components — a user is a single safe token, never \
    a path.",
    valid_name
);

name_scalar!(
    ApplicationStoreKey,
    "The application identifier: THE single safe name from the config's \
    `application` field, used for BOTH display (messages and rendering) and \
    storage (the single filesystem component that names the application's \
    local store directory, `<data>/simple-deploy/<key>`). EXACTLY ONE \
    NORMAL FILESYSTEM COMPONENT: non-empty, no `/` or `\\`, not `.`/`..`, \
    no surrounding whitespace or control characters — the same \
    single-safe-segment rule as the other path-segment scalars. The store \
    path is built ONLY from a validated key ([`crate::store::local::LocalStore::new`] \
    takes the key, never a raw string), so an application name can never \
    escape the store base.",
    valid_name
);

impl AsRef<std::path::Path> for ApplicationStoreKey {
    /// The store key is used directly as the single filesystem component of
    /// the store path (`<data>/simple-deploy/<key>`), so a validated store
    /// key doubles as a path segment.
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

name_scalar!(
    RolloutGroupName,
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

/// An ABSOLUTE on-server directory. Construction requires an absolute,
/// TRAVERSAL-FREE path with AT LEAST ONE NORMAL COMPONENT below the root:
/// a relative or empty path is rejected (the scheduler never deploys into a
/// location relative to an unspecified working directory), so is ANY path
/// with a `.` or `..` component at any position (a traversal component
/// could escape the intended namespace), and so is the FILESYSTEM ROOT
/// itself (`/`, or any form that normalizes to it — `//`, `/./`, `/../`) —
/// a deploy_dir of `/` would make the deployment cleanup (rotation/
/// retention deleting stale generations, the GC sweep) operate on the
/// system root. The canonical form is NORMALIZED: rebuilt from the path
/// components, so doubled separators and a trailing slash are folded away.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AbsoluteDeployDir(std::path::PathBuf);

impl AbsoluteDeployDir {
    /// Validate that `s` is an absolute, traversal-free path with at least
    /// one normal component below the root, and construct an
    /// [`AbsoluteDeployDir`] holding the normalized canonical form.
    pub fn parse(s: &str) -> Result<AbsoluteDeployDir> {
        let path = Path::new(s);
        if !path.is_absolute() {
            return Err(Error::config(format!(
                "invalid deploy_dir {:?}: must be an absolute path on the server",
                s
            )));
        }
        // Reject ANY traversal component (`.` or `..`) at ANY position, then
        // rebuild the canonical form from the raw `/`-separated segments
        // (empty segments — doubled separators, a trailing slash — are
        // normalized away). `Path::components()` skips `.` segments, so the
        // raw split is used to catch them.
        let mut canonical = std::path::PathBuf::from("/");
        let mut normal_components = 0usize;
        for segment in s.split('/') {
            match segment {
                "" => {}
                "." | ".." => {
                    return Err(Error::config(format!(
                        "invalid deploy_dir {:?}: traversal components (`.`/`..`) are not allowed",
                        s
                    )));
                }
                _ => {
                    canonical.push(segment);
                    normal_components += 1;
                }
            }
        }
        // The FILESYSTEM ROOT is rejected: a deploy_dir of `/` (or any form
        // that normalizes to it — `//`, `/./`, `/../`) would make the
        // deployment cleanup (rotation/retention deleting stale generations,
        // the GC sweep) operate on the system root. The deploy_dir must have
        // at least one normal path component below the root.
        if normal_components == 0 {
            return Err(Error::config(format!(
                "invalid deploy_dir {:?}: the deploy_dir must have at least one normal path component below the root",
                s
            )));
        }
        Ok(AbsoluteDeployDir(canonical))
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
    use crate::remote::transport::LocalTransport;
    use crate::store::local::{LocalStore, default_base};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn identifier_accepts_valid_rejects_invalid() {
        for ok in ["s1", "production", "wave-1", "α", "x y", "a", "a..b", "a.b"] {
            let id = Identifier::parse(ok).expect("valid identifier parses");
            assert_eq!(id.as_str(), ok);
            assert_eq!(id.to_string(), ok);
            assert_eq!(ok.parse::<Identifier>().expect("from_str"), id);
        }
        for bad in [
            "", "   ", " x", "x ", "\u{0}", "a\nb", "a/b", "a\\b", ".", "..", "../x", "x/..",
        ] {
            Identifier::parse(bad).expect_err("invalid identifier must be rejected");
            assert!(bad.parse::<Identifier>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn application_store_key_requires_safe_single_segment() {
        for ok in ["app", "my app", "α", "a..b"] {
            let name = ApplicationStoreKey::parse(ok).expect("safe name parses");
            assert_eq!(name.as_str(), ok);
        }
        for bad in [
            "", "   ", "\n", " x", "x ", "a/b", "a\\b", ".", "..", "\u{0}",
        ] {
            ApplicationStoreKey::parse(bad).expect_err("unsafe application store key rejected");
        }
    }

    #[test]
    fn rollout_group_name_accepts_valid_rejects_invalid() {
        for ok in ["canary", "wave-1", "α", "a..b"] {
            let g = RolloutGroupName::parse(ok).expect("valid group parses");
            assert_eq!(g.as_str(), ok);
        }
        for bad in [
            "", "   ", " x", "x ", "\u{0}", "a/b", "a\\b", ".", "..", "../x",
        ] {
            RolloutGroupName::parse(bad).expect_err("invalid group name rejected");
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
    fn absolute_deploy_dir_requires_absolute_traversal_free_path() {
        for ok in ["/srv/p1", "/srv", "/srv/deploy/app"] {
            let d = AbsoluteDeployDir::parse(ok).expect("absolute path parses");
            assert!(d.as_path().is_absolute());
            assert_eq!(d.as_path(), std::path::Path::new(ok));
        }
        // A trailing slash is harmless but normalized away; the canonical
        // form is a parse fixed point.
        let d = AbsoluteDeployDir::parse("/srv/").expect("trailing slash normalizes");
        assert_eq!(d.as_path(), std::path::Path::new("/srv"));
        assert_eq!(
            AbsoluteDeployDir::parse("/srv").expect("canonical re-parses"),
            d
        );
        let d = AbsoluteDeployDir::parse("/srv/app/").expect("trailing slash normalizes");
        assert_eq!(d.as_path(), std::path::Path::new("/srv/app"));
        for bad in [
            "",
            "srv/p1",
            "relative",
            "./x",
            "../x",
            "/srv/../etc",
            "/srv/./x",
            "/../etc",
            "/etc/..",
            "/./x",
            "/srv/..",
            // The filesystem root (and any form that normalizes to it) is
            // rejected: a deploy_dir must have at least one normal
            // component below the root, so deployment cleanup can never
            // operate on `/`.
            "/",
            "//",
            "/./",
            "/../",
        ] {
            AbsoluteDeployDir::parse(bad)
                .expect_err("traversal, relative, or root deploy_dir rejected");
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

    // -------------------------------------------------------------------
    // THE TRAVERSAL PROPERTY: over ARBITRARY name/path values (with `..`,
    // `.`, `/`, `\`, empty, whitespace, control characters, unicode, and
    // absolute/relative mixes), each scalar accepts EXACTLY the
    // traversal-free, single-segment values and rejects everything else.
    // Bounded 16 cases, fixed seed 0x5EED_5EED per house style.
    // -------------------------------------------------------------------

    /// The independent characterization of the name rule: a value is a safe
    /// single path segment iff it is non-empty, unpadded, control-free, has
    /// no path separator, and is not a `.`/`..` traversal component.
    fn is_safe_segment(s: &str) -> bool {
        !s.is_empty()
            && s.trim() == s
            && !s.chars().any(|c| c.is_control())
            && !s.contains('/')
            && !s.contains('\\')
            && s != "."
            && s != ".."
    }

    /// Arbitrary name/path-segment values covering every traversal class:
    /// `..`, `.`, `/`, `\`, empty, whitespace, control characters, unicode,
    /// and clean single segments.
    fn arbitrary_segment_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                ".".to_string(),
                "..".to_string(),
                "...".to_string(),
                "/".to_string(),
                "\\".to_string(),
                "a/b".to_string(),
                "a\\b".to_string(),
                "../x".to_string(),
                "x/..".to_string(),
                "./x".to_string(),
                "x/.".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "x y".to_string(),
                "\u{0}".to_string(),
                "a\nb".to_string(),
                "α".to_string(),
                "s1".to_string(),
                "wave-1".to_string(),
                "a..b".to_string(),
                "a.b".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..12).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: the three name scalars (Identifier, RolloutGroupName,
        // ApplicationStoreKey) accept EXACTLY the safe single-segment values —
        // every traversal class (`..`, `.`, `/`, `\`, padding, control
        // chars) is rejected, every clean single segment is accepted.
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
        // failure persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn name_scalars_accept_exactly_safe_single_segments(s in arbitrary_segment_text()) {
            let expected = is_safe_segment(&s);
            assert_eq!(
                Identifier::parse(&s).is_ok(),
                expected,
                "Identifier must accept exactly safe single segments: {s:?}"
            );
            assert_eq!(
                RolloutGroupName::parse(&s).is_ok(),
                expected,
                "RolloutGroupName must accept exactly safe single segments: {s:?}"
            );
            assert_eq!(
                ApplicationStoreKey::parse(&s).is_ok(),
                expected,
                "ApplicationStoreKey must accept exactly safe single segments: {s:?}"
            );
        }
    }

    // -------------------------------------------------------------------
    // THE STORE-KEY PROPERTY: over ARBITRARY application-name strings (with
    // `/`, `\`, `..`, `.`, empty, whitespace, unicode, and control
    // characters), the store-key parse accepts EXACTLY the single-normal-
    // component values; `LocalStore::new` with a valid key places the store
    // under `<base>/<key>/` (exactly ONE component appended). The key IS
    // the config's application identifier (one safe name for display and
    // storage), so an unsafe application name can never reach the store
    // construction. Bounded 16 cases, fixed seed 0x5EED_5EED per house
    // style.
    // -------------------------------------------------------------------

    #[test]
    fn store_key_property_places_store_under_base_plus_single_component() {
        // The property constructs REAL stores via `LocalStore::new_in`, so
        // the store base is resolved from a hermetic SNAPSHOT (a temp-root
        // `XDG_DATA_HOME`) — no process-global env, no lock, no cross-test
        // interference; the closure-form proptest runs all 16 cases in this
        // thread.
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let env = crate::env::SysEnv::from_map(std::collections::BTreeMap::from([(
            std::ffi::OsString::from("XDG_DATA_HOME"),
            dir.path().join("store-root").into_os_string(),
        )]));
        proptest!(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        }, |(s in arbitrary_segment_text())| {
            let expected = is_safe_segment(&s);
            assert_eq!(
                ApplicationStoreKey::parse(&s).is_ok(),
                expected,
                "ApplicationStoreKey must accept exactly safe single segments: {s:?}"
            );
            if let Ok(key) = ApplicationStoreKey::parse(&s) {
                // The store path is default_base(env).join(key): EXACTLY ONE
                // component appended — the key is a single safe segment, so
                // the store can never escape the base. A safe-but-
                // filesystem-incompatible key (a character the local
                // filesystem refuses, e.g. some unicode) fails the store
                // open with a STORE error — fail closed, never an escape.
                match LocalStore::new_in(&env, &key) {
                    Ok(store) => {
                        assert_eq!(
                            store.base().parent(),
                            Some(default_base(&env).as_path()),
                            "the store must sit directly under the base: {s:?}"
                        );
                        assert_eq!(
                            store.base().file_name(),
                            Some(std::ffi::OsStr::new(key.as_str())),
                            "exactly one component (the key) is appended: {s:?}"
                        );
                    }
                    Err(e) => assert!(
                        matches!(e, Error::Store(_)),
                        "a safe key's store open failure must be a store error, never an escape: {e}"
                    )}
            }
        });
    }

    /// The independent characterization of the deploy_dir rule: an absolute
    /// path whose every non-empty `/`-separated segment is a normal name
    /// (no `.`/`..` component at any position) AND that has at least one
    /// normal component below the root (the filesystem root itself is not a
    /// valid deploy_dir — deployment cleanup must never operate on `/`).
    fn is_valid_deploy_dir(s: &str) -> bool {
        Path::new(s).is_absolute()
            && s.split('/')
                .all(|seg| seg.is_empty() || (seg != "." && seg != ".."))
            && s.split('/')
                .any(|seg| !seg.is_empty() && seg != "." && seg != "..")
    }

    /// Arbitrary path values covering every traversal class: absolute with
    /// `..`/`.` at any position, doubled separators, trailing slashes, the
    /// root, relative paths, empty, whitespace, and unicode.
    fn arbitrary_path_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                "/srv/p1".to_string(),
                "/".to_string(),
                "//".to_string(),
                "/./".to_string(),
                "/../".to_string(),
                "/srv/".to_string(),
                "//srv//deploy//".to_string(),
                "/srv/../etc".to_string(),
                "/srv/./x".to_string(),
                "/../etc".to_string(),
                "/etc/..".to_string(),
                "/./x".to_string(),
                "/srv/..".to_string(),
                "/srv/deploy/app".to_string(),
                "srv/p1".to_string(),
                "relative".to_string(),
                "./x".to_string(),
                "../x".to_string(),
                String::new(),
                " ".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..12).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: AbsoluteDeployDir accepts EXACTLY the
        // traversal-free absolute paths with at least one normal component
        // below the root — every `.`/`..` component at any position, every
        // relative/empty path, and the filesystem root itself (including
        // forms that normalize to it) are rejected, and the accepted
        // canonical form is normalized (no trailing slash, no doubled
        // separators) and a parse fixed point. The transport construction
        // refuses the root too (defense in depth). Bounded 16 cases, fixed
        // seed 0x5EED_5EED (house style), no failure persistence — the
        // identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn absolute_deploy_dir_accepts_exactly_traversal_free_absolute_paths(
            s in arbitrary_path_text(),
        ) {
            let expected = is_valid_deploy_dir(&s);
            assert_eq!(
                AbsoluteDeployDir::parse(&s).is_ok(),
                expected,
                "AbsoluteDeployDir must accept exactly traversal-free absolute paths with ≥1 normal component below the root: {s:?}"
            );
            if let Ok(dir) = AbsoluteDeployDir::parse(&s) {
                let canonical = dir.as_path().to_string_lossy();
                assert!(
                    !canonical.ends_with('/'),
                    "canonical form must not carry a trailing slash: {canonical:?}"
                );
                assert_eq!(
                    AbsoluteDeployDir::parse(&canonical).expect("canonical form re-parses"),
                    dir,
                    "the canonical form must be a parse fixed point: {canonical:?}"
                );
            }
            // Defense in depth: the transport construction refuses the root
            // too — a transport whose root has no normal component below
            // the root (the filesystem root) can never be built, so
            // deployment cleanup can never operate on `/` even if the
            // scalar check were bypassed.
            let root_only = !Path::new(&s)
                .components()
                .any(|c| matches!(c, std::path::Component::Normal(_)));
            assert_eq!(
                LocalTransport::new(&crate::testutil::fixture_env(), std::path::PathBuf::from(&s)).is_ok(),
                !root_only,
                "LocalTransport must refuse a root deploy_dir: {s:?}"
            );
        }
    }
}

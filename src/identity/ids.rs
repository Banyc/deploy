//! The uuid-v7 event identities: [`DeploymentId`], [`GenerationId`],
//! [`OperationId`]. Opaque collision-resistant IDs (UUIDv7 in schema
//! version 1) that identify events — an attempted push, one slot's durable
//! generation record, one operation — and are NEVER used as content
//! identity. The exact canonical form is `deploy-`/`gen-`/`op-` + a
//! canonical hyphenated UUIDv7 string; the version nibble is enforced (v7
//! only), so a hand-written v4 UUID or any other malformed suffix is
//! rejected.

use super::id_newtype;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

fn new_uuid_v7() -> String {
    Uuid::now_v7().to_string()
}

/// A valid `deploy-`/`gen-`/`op-` prefixed UUIDv7 identity: the exact form
/// [`new_uuid_v7`] produces (a canonical hyphenated UUIDv7 string). The
/// hyphenated shape is required (the generator never emits the simple form)
/// and the version nibble is enforced (v7 only), so a hand-written v4 UUID or
/// any other malformed suffix is rejected.
fn valid_uuid_v7_id(s: &str, prefix: &str) -> bool {
    let Some(rest) = s.strip_prefix(prefix) else {
        return false;
    };
    let b = rest.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && Uuid::parse_str(rest)
            .map(|u| u.get_version() == Some(uuid::Version::SortRand))
            .unwrap_or(false)
}

fn valid_deployment_id(s: &str) -> bool {
    valid_uuid_v7_id(s, "deploy-")
}

fn valid_generation_id(s: &str) -> bool {
    valid_uuid_v7_id(s, "gen-")
}

fn valid_operation_id(s: &str) -> bool {
    valid_uuid_v7_id(s, "op-")
}

id_newtype!(
    DeploymentId,
    valid_deployment_id,
    "A deployment identity: `deploy-<uuid-v7>` (the exact form \
     [`DeploymentId::generate`] produces)."
);
id_newtype!(
    GenerationId,
    valid_generation_id,
    "A generation identity: `gen-<uuid-v7>` (the exact form \
     [`GenerationId::generate`] produces)."
);
id_newtype!(
    OperationId,
    valid_operation_id,
    "An operation identity: `op-<uuid-v7>` (the exact form \
     [`OperationId::generate`] produces)."
);

impl DeploymentId {
    pub fn generate() -> Self {
        DeploymentId(format!("deploy-{}", new_uuid_v7()))
    }
}

impl GenerationId {
    pub fn generate() -> Self {
        GenerationId(format!("gen-{}", new_uuid_v7()))
    }
}

impl OperationId {
    pub fn generate() -> Self {
        OperationId(format!("op-{}", new_uuid_v7()))
    }
}

/// Deterministic canonical test identities: fixtures that ROUND-TRIP through
/// the wire (ledger/observed records) must carry format-valid ids, so these
/// helpers derive a canonical `deploy-<uuid-v7>` / `gen-<uuid-v7>` /
/// `op-<uuid-v7>` / 64-hex-digest from a fixture tag. Deterministic per tag:
/// the same tag yields the same id everywhere, so a fixture can write and
/// assert the same value.
#[cfg(test)]
pub(crate) fn test_uuid_v7(tag: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tag.hash(&mut h);
    let r = h.finish();
    let mut bytes = [0u8; 16];
    // Fixed 48-bit timestamp (2024-01-01T00:00:00Z ≈ 0x018F_0000_0000 ms).
    let ts: u64 = 0x018F_0000_0000;
    bytes[0..6].copy_from_slice(&ts.to_be_bytes()[2..8]);
    // Version 7 nibble + rand_a (12 bits) from the tag hash.
    bytes[6] = 0x70 | ((r >> 8) & 0x0F) as u8;
    bytes[7] = (r & 0xFF) as u8;
    // Variant 10 + rand_b (58 bits) from the tag hash.
    bytes[8] = 0x80 | ((r >> 56) & 0x3F) as u8;
    bytes[9..16].copy_from_slice(&r.to_be_bytes()[1..8]);
    Uuid::from_bytes(bytes).to_string()
}

#[cfg(test)]
pub(crate) fn test_deployment_id(tag: &str) -> DeploymentId {
    DeploymentId::parse(&format!("deploy-{}", test_uuid_v7(tag))).expect("canonical test id")
}

#[cfg(test)]
pub(crate) fn test_generation_id(tag: &str) -> GenerationId {
    GenerationId::parse(&format!("gen-{}", test_uuid_v7(tag))).expect("canonical test id")
}

#[cfg(test)]
pub(crate) fn test_operation_id(tag: &str) -> OperationId {
    OperationId::parse(&format!("op-{}", test_uuid_v7(tag))).expect("canonical test id")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::digests::{ReleaseDigest, TreeDigest, test_tree_digest};
    use crate::identity::scalars::RolloutGroupName;
    use crate::identity::segments::{ServerId, SlotId, TargetName, VariantName};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn newtypes_parse_and_eq() {
        let a = test_tree_digest("a");
        let b = test_tree_digest("b");
        assert_eq!(a, a);
        assert_ne!(a, b);
        assert_eq!(
            test_generation_id("x").as_str(),
            format!("gen-{}", test_uuid_v7("x"))
        );
    }

    /// The canonical format of each uuid-v7 identity parses; every invalid
    /// class (empty, bare prefix, wrong prefix, malformed uuid, v4 uuid,
    /// padding, trailing junk) is rejected.
    #[test]
    fn uuid_v7_ids_accept_canonical_reject_invalid() {
        let dep = test_deployment_id("ok");
        assert_eq!(DeploymentId::parse(dep.as_str()).expect("canonical"), dep);
        let gid = test_generation_id("ok");
        assert_eq!(GenerationId::parse(gid.as_str()).expect("canonical"), gid);
        let op = test_operation_id("ok");
        assert_eq!(OperationId::parse(op.as_str()).expect("canonical"), op);
        for bad in [
            "",
            "deploy-",
            "gen-",
            "op-",
            "deploy",
            "deploy-0192a3b4c5d6e7f8a9b0c1d2e3f4a5b6", // simple form, no hyphens
            "deploy-0192a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b6", // v4
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6 ", // trailing space
            " deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6", // leading space
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6x", // trailing junk
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5", // too short
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6-7", // too long
        ] {
            DeploymentId::parse(bad).expect_err("invalid deployment id rejected");
            GenerationId::parse(bad).expect_err("invalid generation id rejected");
            OperationId::parse(bad).expect_err("invalid operation id rejected");
        }
        // A valid uuid under the WRONG prefix is rejected for that type.
        let u = test_uuid_v7("x");
        DeploymentId::parse(&format!("gen-{u}")).expect_err("wrong prefix rejected");
        GenerationId::parse(&format!("deploy-{u}")).expect_err("wrong prefix rejected");
        OperationId::parse(&format!("deploy-{u}")).expect_err("wrong prefix rejected");
    }

    /// Wire strings go through the validated parse: an invalid wire identity
    /// fails deserialization, a valid one round-trips.
    #[test]
    fn deserialize_validates_wire_strings() {
        let dep = test_deployment_id("wire");
        let json = serde_json::to_string(&dep).expect("serializes");
        assert_eq!(
            serde_json::from_str::<DeploymentId>(&json).expect("valid wire parses"),
            dep
        );
        for bad in [
            "\"\"",
            "\"deploy-1\"",
            "\"gen-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6\"",
            "\"p1/..\"",
        ] {
            serde_json::from_str::<DeploymentId>(bad).expect_err("invalid wire rejected");
        }
        serde_json::from_str::<SlotId>("\"p1\"").expect("valid slot wire parses");
        serde_json::from_str::<SlotId>("\"../x\"").expect_err("traversal wire rejected");
        serde_json::from_str::<TreeDigest>(&format!("\"{DIGEST}\""))
            .expect("valid digest wire parses");
        serde_json::from_str::<TreeDigest>("\"t1\"").expect_err("short digest wire rejected");
    }

    // -------------------------------------------------------------------
    // THE IDENTITY PROPERTY: over ARBITRARY strings (empty, whitespace,
    // separators, wrong prefixes, wrong hex, unicode, control characters),
    // each identity's parse accepts EXACTLY its format-valid values and
    // rejects everything else, and a wire string that fails the parse fails
    // deserialization. Bounded 16 cases, fixed seed 0x5EED_5EED per house
    // style.
    // -------------------------------------------------------------------

    /// The independent characterization of the uuid-v7 id rule: the exact
    /// canonical hyphenated UUIDv7 shape under the prefix.
    fn is_valid_uuid_v7_id(s: &str, prefix: &str) -> bool {
        let Some(rest) = s.strip_prefix(prefix) else {
            return false;
        };
        let b = rest.as_bytes();
        b.len() == 36
            && b[8] == b'-'
            && b[13] == b'-'
            && b[18] == b'-'
            && b[23] == b'-'
            && b[14] == b'7'
            && matches!(b[19], b'8' | b'9' | b'a' | b'b')
            && b.iter()
                .enumerate()
                .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
    }

    fn is_valid_hex_digest(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    fn is_safe_segment(s: &str) -> bool {
        !s.is_empty()
            && s.trim() == s
            && !s.chars().any(|c| c.is_control())
            && !s.contains('/')
            && !s.contains('\\')
            && s != "."
            && s != ".."
    }

    /// Arbitrary identity strings covering every invalid class: empty,
    /// whitespace, separators, wrong prefixes, malformed uuids, wrong hex,
    /// unicode, control characters, and clean canonical values.
    fn arbitrary_identity_text() -> impl Strategy<Value = String> {
        let u = test_uuid_v7("prop");
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                " ".to_string(),
                "deploy-".to_string(),
                "gen-".to_string(),
                "op-".to_string(),
                "deploy".to_string(),
                format!("deploy-{u}"),
                format!("gen-{u}"),
                format!("op-{u}"),
                format!("deploy-{}", u.to_uppercase()),
                "deploy-0192a3b4c5d6e7f8a9b0c1d2e3f4a5b6".to_string(),
                "deploy-0192a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b6".to_string(),
                "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6 ".to_string(),
                " deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6".to_string(),
                "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6x".to_string(),
                "t1".to_string(),
                "tree-1".to_string(),
                "abc123".to_string(),
                DIGEST.to_string(),
                format!("sha256-{DIGEST}"),
                DIGEST.to_uppercase(),
                "p1".to_string(),
                "s1".to_string(),
                "standard".to_string(),
                "a/b".to_string(),
                "a\\b".to_string(),
                "..".to_string(),
                ".".to_string(),
                "../x".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "\u{0}".to_string(),
                "a\nb".to_string(),
                "α".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..48).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: each identity's parse accepts EXACTLY its
        // format-valid values — every invalid class (empty, whitespace,
        // separators, wrong prefixes, wrong hex, unicode, control chars) is
        // rejected, every canonical value is accepted — and a wire string
        // that fails the parse fails deserialization. Bounded 16 cases,
        // fixed seed 0x5EED_5EED (house style), no failure persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn identity_parses_accept_exactly_format_valid_values(s in arbitrary_identity_text()) {
            let expected_dep = is_valid_uuid_v7_id(&s, "deploy-");
            let expected_gen = is_valid_uuid_v7_id(&s, "gen-");
            let expected_op = is_valid_uuid_v7_id(&s, "op-");
            let expected_digest = is_valid_hex_digest(&s);
            let expected_segment = is_safe_segment(&s);
            assert_eq!(
                DeploymentId::parse(&s).is_ok(),
                expected_dep,
                "DeploymentId: {s:?}"
            );
            assert_eq!(
                GenerationId::parse(&s).is_ok(),
                expected_gen,
                "GenerationId: {s:?}"
            );
            assert_eq!(
                OperationId::parse(&s).is_ok(),
                expected_op,
                "OperationId: {s:?}"
            );
            assert_eq!(
                TreeDigest::parse(&s).is_ok(),
                expected_digest,
                "TreeDigest: {s:?}"
            );
            assert_eq!(
                ReleaseDigest::parse(&s).is_ok(),
                expected_digest,
                "ReleaseDigest: {s:?}"
            );
            assert_eq!(
                ServerId::parse(&s).is_ok(),
                expected_segment,
                "ServerId: {s:?}"
            );
            assert_eq!(
                SlotId::parse(&s).is_ok(),
                expected_segment,
                "SlotId: {s:?}"
            );
            assert_eq!(
                TargetName::parse(&s).is_ok(),
                expected_segment,
                "TargetName: {s:?}"
            );
            assert_eq!(
                RolloutGroupName::parse(&s).is_ok(),
                expected_segment,
                "RolloutGroupName: {s:?}"
            );
            assert_eq!(
                VariantName::parse(&s).is_ok(),
                expected_segment,
                "VariantName: {s:?}"
            );
            // A wire string that fails the parse fails deserialization.
            let json = serde_json::to_string(&s).expect("string serializes");
            assert_eq!(
                serde_json::from_str::<DeploymentId>(&json).is_ok(),
                expected_dep,
                "DeploymentId wire: {s:?}"
            );
            assert_eq!(
                serde_json::from_str::<TreeDigest>(&json).is_ok(),
                expected_digest,
                "TreeDigest wire: {s:?}"
            );
            assert_eq!(
                serde_json::from_str::<SlotId>(&json).is_ok(),
                expected_segment,
                "SlotId wire: {s:?}"
            );
        }
    }
}

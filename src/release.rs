//! Release identity derivation.
//!
//! The canonical release ID is derived from a versioned canonical identity
//! payload containing the frozen mapping digest, the name-sorted per-variant
//! slot declaration digest, all declared `variant -> tree digest` bindings,
//! and the activation and verification contract digest. It explicitly
//! excludes the resulting release ID, creation time, display name, and
//! provenance, avoiding a circular hash. The per-variant slot declarations
//! (rebind a server, move a `deploy_dir`, retarget) are part of the identity;
//! per-server capacity policy is not.

use crate::config::{ActivationConfig, Mapping, SlotDef, VerificationConfig};
use crate::digest::sha256_bytes;
use crate::model::{
    BehaviorContract, CanonicalReleasePayload, CanonicalSlot, CanonicalSlots, Provenance,
    ReleaseDigest, ReleaseId, ReleaseRecord, TreeDigest, VariantName,
};
use chrono::Utc;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Canonical digest of the frozen mapping set.
pub fn mapping_digest(mappings: &[Mapping]) -> String {
    let v = serde_json::to_vec(mappings).expect("mappings serialize");
    sha256_bytes(&v)
}

/// Canonical digest of the activation + verification contract.
pub fn behavior_digest(activation: &ActivationConfig, verification: &VerificationConfig) -> String {
    let act = serde_json::to_value(activation).expect("activation serializes");
    let ver = serde_json::to_value(verification).expect("verification serializes");
    let payload = serde_json::json!({ "activation": act, "verification": ver });
    sha256_bytes(&serde_json::to_vec(&payload).expect("payload serializes"))
}

/// Canonical digest of a resolved [`BehaviorContract`].
pub fn behavior_contract_digest(contract: &BehaviorContract) -> String {
    behavior_digest(&contract.activation, &contract.verification)
}

/// Reconstruct a [`BehaviorContract`] from serialized JSON bytes.
pub fn behavior_contract_from_json(
    bytes: &[u8],
) -> std::result::Result<BehaviorContract, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Canonical digest over name-sorted per-variant mapping sets. Two releases
/// share this digest only when every declared variant materializes the same
/// mappings.
pub fn variant_mappings_digest(mappings: &BTreeMap<String, Vec<Mapping>>) -> String {
    let value = serde_json::to_vec(mappings).expect("variant mappings serialize");
    sha256_bytes(&value)
}

/// Canonical digest over name-sorted per-variant behavior contracts. Two
/// releases share this digest only when every declared variant's activation and
/// verification behavior is identical.
pub fn variant_behaviors_digest(contracts: &BTreeMap<String, BehaviorContract>) -> String {
    let value = serde_json::to_vec(contracts).expect("variant behaviors serialize");
    sha256_bytes(&value)
}

/// Reconstruct the name-keyed per-variant behavior map from serialized JSON.
pub fn behavior_contracts_from_json(
    bytes: &[u8],
) -> std::result::Result<BTreeMap<String, BehaviorContract>, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Lexically normalize an on-server `deploy_dir` into its canonical string
/// form: collapse repeated slashes, resolve `.` and `..` components
/// lexically (no filesystem access), and strip any trailing slash. Two
/// declarations naming the same directory therefore hash identically. The
/// config validator already requires `deploy_dir` to be absolute; relative
/// paths are still cleaned defensively.
pub fn normalize_deploy_dir(path: &Path) -> String {
    let mut out = PathBuf::new();
    if path.is_absolute() {
        out.push(Path::new("/"));
    }
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    let s = out.to_string_lossy().into_owned();
    if s.len() > 1 {
        s.trim_end_matches('/').to_string()
    } else {
        s
    }
}

/// Canonicalize a variant's declared `[[slots]]` into the sorted, normalized
/// identity form: exactly the four identity-bearing fields of [`SlotDef`]
/// (`id`, `server`, `deploy_dir` as a lexically-normalized absolute path
/// string, `target`), sorted by slot id. Server-level policy (user, address,
/// port, capacity) is deliberately absent — it is not release identity.
pub fn canonicalize_slots(slots: &[SlotDef]) -> CanonicalSlots {
    let mut out: Vec<CanonicalSlot> = slots
        .iter()
        .map(|s| CanonicalSlot {
            id: s.id.clone(),
            server: s.server.clone(),
            deploy_dir: normalize_deploy_dir(&s.deploy_dir),
            target: s.target.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    CanonicalSlots { slots: out }
}

/// Canonical digest over name-sorted per-variant slot declarations. Each
/// variant's slots are canonicalized (the four identity fields, `deploy_dir`
/// lexically normalized) and sorted by slot id; the variants are name-sorted
/// by the `BTreeMap`. Two releases share this digest only when every declared
/// variant declares the same slots — a rebind, `deploy_dir` move, or retarget
/// changes it, while a reordering of slot declarations (or of variants) does
/// not. Server-level policy (user/address/port/capacity) is not part of it.
pub fn variant_slots_digest(slots: &BTreeMap<String, Vec<SlotDef>>) -> String {
    let canonical: BTreeMap<String, CanonicalSlots> = slots
        .iter()
        .map(|(v, defs)| (v.clone(), canonicalize_slots(defs)))
        .collect();
    let value = serde_json::to_vec(&canonical).expect("variant slots serialize");
    sha256_bytes(&value)
}

/// Derive the release digest from the canonical payload.
pub fn release_digest(
    mapping_sha: &str,
    behavior_sha: &str,
    slots_sha: &str,
    variants: &BTreeMap<String, String>,
) -> ReleaseDigest {
    let payload = CanonicalReleasePayload {
        schema_version: 2,
        mapping_sha256: mapping_sha.to_string(),
        behavior_sha256: behavior_sha.to_string(),
        slots_digest: slots_sha.to_string(),
        variants: variants.clone(),
    };
    let bytes = serde_json::to_vec(&payload).expect("payload serializes");
    ReleaseDigest::new(sha256_bytes(&bytes))
}

/// Compute the current Git revision of `root`, if available.
pub fn git_revision(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    }
}

/// Build a complete, immutable release record for the given variant bindings.
/// The per-variant slot declarations are canonicalized and frozen into the
/// record (as the slot snapshot) and folded into the release identity digest,
/// so a slot-only change produces a new [`ReleaseId`].
pub fn build_release(
    mapping_sha: &str,
    behavior_sha: &str,
    variants: &BTreeMap<VariantName, TreeDigest>,
    variant_slots: &BTreeMap<String, Vec<SlotDef>>,
    root: &Path,
) -> ReleaseRecord {
    let bindings: BTreeMap<String, String> = variants
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
        .collect();
    let slots_digest = variant_slots_digest(variant_slots);
    let slots: BTreeMap<String, CanonicalSlots> = variant_slots
        .iter()
        .map(|(v, defs)| (v.clone(), canonicalize_slots(defs)))
        .collect();
    let digest = release_digest(mapping_sha, behavior_sha, &slots_digest, &bindings);
    let id = ReleaseId::from_digest(&digest);
    ReleaseRecord {
        release_schema_version: 1,
        release_id: id.as_str().to_string(),
        release_sha256: digest.as_str().to_string(),
        created_at: Utc::now().to_rfc3339(),
        provenance: Provenance {
            git_revision: git_revision(root),
            mapping_sha256: mapping_sha.to_string(),
            behavior_sha256: behavior_sha.to_string(),
        },
        variants: bindings,
        slots,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdef(id: &str, server: &str, deploy_dir: &str, target: &str) -> SlotDef {
        SlotDef {
            id: id.to_string(),
            server: server.to_string(),
            deploy_dir: PathBuf::from(deploy_dir),
            target: target.to_string(),
        }
    }

    /// Two variants with the same slot declarations written in different file
    /// orders and with lexically equivalent (but textually different)
    /// deploy_dir strings hash identically.
    #[test]
    fn variant_slots_digest_is_order_independent() {
        let mut a: BTreeMap<String, Vec<SlotDef>> = BTreeMap::new();
        a.insert(
            "standard".to_string(),
            vec![
                sdef("p2", "s2", "/srv/deploy/p2", "production"),
                sdef("p1", "s1", "/srv/deploy/p1", "production"),
            ],
        );
        a.insert(
            "canary".to_string(),
            vec![sdef("c1", "s3", "/srv/edge/c1", "edge")],
        );

        // Same declarations: per-variant file order reversed (p1 before p2), a
        // textually different but lexically identical deploy_dir (double slash,
        // trailing slash), and the variants inserted in the opposite order.
        let mut b: BTreeMap<String, Vec<SlotDef>> = BTreeMap::new();
        b.insert(
            "canary".to_string(),
            vec![sdef("c1", "s3", "/srv/edge/c1", "edge")],
        );
        b.insert(
            "standard".to_string(),
            vec![
                sdef("p1", "s1", "/srv/deploy//p1/", "production"),
                sdef("p2", "s2", "/srv/deploy/p2", "production"),
            ],
        );
        assert_eq!(
            variant_slots_digest(&a),
            variant_slots_digest(&b),
            "slot declaration order must not affect the digest"
        );
    }

    /// Changing any of the four identity fields changes the digest; server
    /// policy fields are not part of the input at all.
    #[test]
    fn variant_slots_digest_is_sensitive_to_each_field() {
        let base: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let base_sha = variant_slots_digest(&base);
        for variant in [
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p2", "server-01", "/srv/deploy/example", "production")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p1", "server-02", "/srv/deploy/example", "production")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p1", "server-01", "/srv/elsewhere", "production")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p1", "server-01", "/srv/deploy/example", "edge")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![
                    sdef("p1", "server-01", "/srv/deploy/example", "production"),
                    sdef("p9", "server-09", "/srv/deploy/example", "production"),
                ],
            )]),
        ] {
            assert_ne!(
                variant_slots_digest(&variant),
                base_sha,
                "every slot field change must alter the digest"
            );
        }
    }

    /// `deploy_dir` canonicalization collapses slashes, resolves `.`/`..`
    /// lexically, and keeps the absolute root.
    #[test]
    fn normalize_deploy_dir_is_lexical() {
        assert_eq!(
            normalize_deploy_dir(Path::new("/srv/deploy/example")),
            "/srv/deploy/example"
        );
        assert_eq!(
            normalize_deploy_dir(Path::new("//srv/deploy//example/")),
            "/srv/deploy/example"
        );
        assert_eq!(
            normalize_deploy_dir(Path::new("/srv/deploy/../deploy/example")),
            "/srv/deploy/example"
        );
        assert_eq!(normalize_deploy_dir(Path::new("/")), "/");
    }

    /// A slot-only change yields a different release digest while the tree
    /// bindings stay identical.
    #[test]
    fn slot_only_change_changes_release_digest() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let bindings: BTreeMap<String, String> = variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let slot_a: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let slot_b: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-02", "/srv/deploy/example", "production")],
        )]);
        let da = release_digest("m", "b", &variant_slots_digest(&slot_a), &bindings);
        let db = release_digest("m", "b", &variant_slots_digest(&slot_b), &bindings);
        assert_ne!(
            da.as_str(),
            db.as_str(),
            "a slot-only change must produce a new release digest"
        );
        // The release record persists the canonical slot snapshot it was built
        // from.
        let rec_a = build_release("m", "b", &variants, &slot_a, Path::new("."));
        let rec_b = build_release("m", "b", &variants, &slot_b, Path::new("."));
        assert_eq!(rec_a.slots["standard"].slots[0].server, "server-01");
        assert_eq!(rec_b.slots["standard"].slots[0].server, "server-02");
        assert_eq!(rec_a.variants, rec_b.variants, "trees unchanged");
        assert_ne!(rec_a.release_sha256, rec_b.release_sha256);
    }

    /// The release digest is sensitive to EVERY canonical identity input —
    /// mapping set, behavior contract set, per-variant tree bindings, and
    /// canonical slot declarations — and to nothing else: an identical payload
    /// always produces the identical digest. Server-level policy (user,
    /// address, port, capacity) is not even an input to the digest function.
    #[test]
    fn release_digest_sensitivity_matrix() {
        let base_slots: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let base_variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("tree-1"))]);
        let bindings: BTreeMap<String, String> = base_variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let base = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&base_slots),
            &bindings,
        );

        // Identical payload -> identical digest.
        assert_eq!(
            release_digest(
                "mapping-sha",
                "behavior-sha",
                &variant_slots_digest(&base_slots),
                &bindings
            )
            .as_str(),
            base.as_str()
        );

        // Mapping change -> new digest.
        let m = release_digest(
            "mapping-sha-2",
            "behavior-sha",
            &variant_slots_digest(&base_slots),
            &bindings,
        );
        assert_ne!(base.as_str(), m.as_str(), "mapping change must re-digest");

        // Behavior contract change -> new digest.
        let b = release_digest(
            "mapping-sha",
            "behavior-sha-2",
            &variant_slots_digest(&base_slots),
            &bindings,
        );
        assert_ne!(base.as_str(), b.as_str(), "behavior change must re-digest");

        // Tree-binding change -> new digest.
        let t_variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("tree-2"))]);
        let t_bindings: BTreeMap<String, String> = t_variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let tb = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&base_slots),
            &t_bindings,
        );
        assert_ne!(
            base.as_str(),
            tb.as_str(),
            "tree-binding change must re-digest"
        );

        // Canonical-slot change -> new digest (already asserted per-field by
        // `variant_slots_digest_is_sensitive_to_each_field`, folded into the
        // full digest here).
        let s2: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-02", "/srv/deploy/example", "production")],
        )]);
        let sb = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&s2),
            &bindings,
        );
        assert_ne!(
            base.as_str(),
            sb.as_str(),
            "canonical-slot change must re-digest"
        );

        // The built release record follows the digest: identical inputs build
        // the identical ReleaseId, any single changed input builds a new one.
        let rec = build_release(
            "mapping-sha",
            "behavior-sha",
            &base_variants,
            &base_slots,
            Path::new("."),
        );
        assert_eq!(rec.release_sha256, base.as_str());
        assert_eq!(rec.release_id, format!("rel-sha256-{}", base.as_str()));
        let rec_m = build_release(
            "mapping-sha-2",
            "behavior-sha",
            &base_variants,
            &base_slots,
            Path::new("."),
        );
        assert_ne!(rec.release_id, rec_m.release_id);
    }
}

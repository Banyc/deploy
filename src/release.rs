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
use crate::error::{Error, Result};
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
/// string, `targets` SORTED and DEDUPLICATED), sorted by slot id. The
/// `targets` dedup is defensive: a duplicate name adds no membership, so a
/// record that slipped past validation (or predates it) must still
/// canonicalize to the same identity as the deduplicated list — duplicate
/// noise never shifts the digest. Server-level policy (user, address, port,
/// capacity) is deliberately absent — it is not release identity.
pub fn canonicalize_slots(slots: &[SlotDef]) -> CanonicalSlots {
    let mut out: Vec<CanonicalSlot> = slots
        .iter()
        .map(|s| CanonicalSlot {
            id: s.id.clone(),
            server: s.server.clone(),
            deploy_dir: normalize_deploy_dir(&s.deploy_dir),
            targets: {
                let mut t = s.targets.clone();
                t.sort();
                t.dedup();
                t
            },
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    CanonicalSlots { slots: out }
}

/// Canonical digest over name-sorted per-variant slot declarations. Each
/// variant's slots are canonicalized (the four identity fields, `deploy_dir`
/// lexically normalized, `targets` sorted and deduplicated) and sorted by
/// slot id; the variants are name-sorted by the `BTreeMap`. Two releases
/// share this digest only when every declared variant declares the same
/// slots — a rebind, `deploy_dir` move, or target-membership change alters
/// it, while a reordering of slot declarations (or of variants, or of a
/// slot's `targets` list, or duplicate names in it — deduplicated away) does
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

/// Recompute the canonical release digest from a stored record's OWN content:
/// the per-variant canonical slot snapshot, the `variant -> tree digest`
/// bindings, and the provenance digests — exactly the inputs `build_release`
/// folds into the identity. Returns `None` when the record carries no
/// canonical slot snapshot (empty `slots` map): such a record's slot
/// declarations were not persisted, so the digest cannot be recomputed from
/// the record alone. Verification (`verify_release_identity`) treats that
/// `None` as an integrity failure — an empty slot snapshot is rejected, with
/// no legacy escape hatch.
pub fn recompute_release_digest(rec: &ReleaseRecord) -> Option<ReleaseDigest> {
    if rec.slots.is_empty() {
        return None;
    }
    // Rebuild the per-variant slot declarations from the record's canonical
    // snapshot (the four identity fields map 1:1 onto `SlotDef`) and re-run
    // the same component digest `build_release` uses, so any change to the
    // canonical slot digest inputs merges mechanically.
    let slots: BTreeMap<String, Vec<SlotDef>> = rec
        .slots
        .iter()
        .map(|(v, cs)| {
            (
                v.clone(),
                cs.slots
                    .iter()
                    .map(|s| SlotDef {
                        id: s.id.clone(),
                        server: s.server.clone(),
                        deploy_dir: PathBuf::from(&s.deploy_dir),
                        targets: s.targets.clone(),
                    })
                    .collect(),
            )
        })
        .collect();
    let slots_digest = variant_slots_digest(&slots);
    Some(release_digest(
        &rec.provenance.mapping_sha256,
        &rec.provenance.behavior_sha256,
        &slots_digest,
        &rec.variants,
    ))
}

/// Verify that a release record's stored identity — BOTH `release_sha256` and
/// the `release_id` (`rel-sha256-<digest>`) — matches the canonical digest
/// recomputed from the record's own content. The digest is never trusted from
/// the stored fields: a tampered record whose content was edited while the
/// digest fields were left unchanged fails closed with an integrity error
/// naming the release and the expected vs recomputed digest.
///
/// An EMPTY canonical slot snapshot is rejected outright: a current-format
/// release record must carry its own slot declarations, without which the
/// identity cannot be recomputed from the record — accepting one would let a
/// tampered record whose `slots` map was emptied bypass verification
/// entirely. There is deliberately NO legacy escape hatch:
/// `release_schema_version` is 1 for both current and pre-snapshot records,
/// so an empty snapshot cannot be proven "genuinely legacy" and is treated
/// as tampering (fail closed).
pub fn verify_release_identity(rec: &ReleaseRecord) -> Result<()> {
    // Reject an empty slot snapshot before anything else: a record that
    // carries no canonical slot declarations cannot be verified from its own
    // content, so its identity is not trustworthy.
    let recomputed = recompute_release_digest(rec).ok_or_else(|| {
        Error::integrity(format!(
            "release {} carries an empty canonical slot snapshot: a release record must persist its slot declarations to be verifiable (fail closed)",
            rec.release_id
        ))
    })?;
    let expected_id = ReleaseId::from_digest(&recomputed);
    if rec.release_sha256 != recomputed.as_str() || rec.release_id != expected_id.as_str() {
        return Err(Error::integrity(format!(
            "release {} identity mismatch: stored release_sha256 {} / release_id {} do not match the digest {} recomputed from the record content",
            rec.release_id,
            rec.release_sha256,
            rec.release_id,
            recomputed.as_str()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdef(id: &str, server: &str, deploy_dir: &str, target: &str) -> SlotDef {
        SlotDef {
            id: id.to_string(),
            server: server.to_string(),
            deploy_dir: PathBuf::from(deploy_dir),
            targets: vec![target.to_string()],
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

    /// The `targets` membership list is part of the identity: adding a target
    /// to a slot's list changes the digest, while REORDERING the list does
    /// not (the canonical form sorts it).
    #[test]
    fn variant_slots_digest_is_sensitive_to_targets_list() {
        let base: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                targets: vec!["production".to_string()],
            }],
        )]);
        let base_sha = variant_slots_digest(&base);

        // Adding a second target to the list changes the digest.
        let added: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                targets: vec!["production".to_string(), "staging".to_string()],
            }],
        )]);
        assert_ne!(
            variant_slots_digest(&added),
            base_sha,
            "a target-membership change must alter the digest"
        );

        // Reordering the same list canonicalizes identically.
        let reordered: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                targets: vec!["staging".to_string(), "production".to_string()],
            }],
        )]);
        assert_eq!(
            variant_slots_digest(&reordered),
            variant_slots_digest(&added),
            "targets list order must not affect the digest"
        );
    }

    /// Duplicate names in a slot's `targets` list add no membership, so the
    /// canonical form DEDUPS them: `["t1","t1"]` and `["t1"]` produce the
    /// SAME digest (a record that slipped past validation, or predates it,
    /// must not shift release identity), while a change that DOES alter
    /// membership (adding a distinct target) still changes the digest.
    #[test]
    fn variant_slots_digest_dedups_duplicate_targets() {
        let single: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                targets: vec!["t1".to_string()],
            }],
        )]);
        let duplicated: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                targets: vec!["t1".to_string(), "t1".to_string()],
            }],
        )]);
        assert_eq!(
            variant_slots_digest(&single),
            variant_slots_digest(&duplicated),
            "a duplicated target name must not change the digest (membership is unchanged)"
        );

        // A change that DOES alter membership still changes the digest.
        let added: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                targets: vec!["t1".to_string(), "t2".to_string()],
            }],
        )]);
        assert_ne!(
            variant_slots_digest(&single),
            variant_slots_digest(&added),
            "a target-membership change must still alter the digest"
        );
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

        // Target-membership change -> new digest: a slot-only change to the
        // `targets` list creates a new ReleaseId.
        let s3: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                targets: vec!["production".to_string(), "staging".to_string()],
            }],
        )]);
        let st = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&s3),
            &bindings,
        );
        assert_ne!(
            base.as_str(),
            st.as_str(),
            "a targets-list change must re-digest"
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

    /// `verify_release_identity` recomputes the canonical digest from the
    /// record's OWN content and checks it against BOTH stored identity fields:
    /// a pristine record verifies, a record whose slot declaration or variant
    /// binding was edited while the digest fields were retained fails closed
    /// with an integrity error naming the mismatch, and a record whose slot
    /// snapshot was EMPTIED fails closed (no legacy escape hatch).
    #[test]
    fn verify_release_identity_recomputes_from_content() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));

        // Pristine: the recomputed digest matches both stored fields.
        verify_release_identity(&rec).expect("pristine record verifies");

        // Tampered slot declaration (deploy_dir moved) with the digest fields
        // retained -> Err naming the stored vs recomputed digest.
        let mut tampered = rec.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        let err = verify_release_identity(&tampered)
            .expect_err("tampered slot content must fail verification");
        let msg = err.to_string();
        assert!(
            msg.contains("identity mismatch"),
            "error must name the mismatch, got: {msg}"
        );
        assert!(
            msg.contains(&rec.release_sha256),
            "error must name the stored digest, got: {msg}"
        );

        // Tampered variant binding with the digest fields retained -> Err.
        let mut tampered2 = rec.clone();
        tampered2
            .variants
            .insert("standard".to_string(), "tree-2".to_string());
        let err2 = verify_release_identity(&tampered2)
            .expect_err("tampered variant binding must fail verification");
        assert!(err2.to_string().contains("identity mismatch"));

        // Empty slot snapshot: rejected outright (fail closed) — a record
        // whose `slots` map was emptied cannot be verified from its own
        // content, and there is no legacy escape hatch.
        let mut empty_slots = rec.clone();
        empty_slots.slots.clear();
        let err = verify_release_identity(&empty_slots)
            .expect_err("an empty slot snapshot must fail verification");
        let msg = err.to_string();
        assert!(
            msg.contains("slot snapshot"),
            "error must name the empty slot snapshot, got: {msg}"
        );
        assert!(
            msg.contains("fail closed"),
            "error must explain the fail-closed rejection, got: {msg}"
        );
    }

    /// A current-format record whose slot snapshot was EMPTIED while the
    /// digest fields were left unchanged (the classic empty-snapshot bypass)
    /// must fail verification with an integrity error: the digest fields are
    /// re-derived from the record content, and the emptied snapshot makes the
    /// record unverifiable.
    #[test]
    fn verify_release_identity_rejects_empty_slot_snapshot_even_with_retained_digests() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));
        verify_release_identity(&rec).expect("pristine record verifies");

        // Tamper: empty the slots map but RETAIN the stored digest fields.
        let mut tampered = rec.clone();
        tampered.slots.clear();
        assert_eq!(
            tampered.release_sha256, rec.release_sha256,
            "digest retained"
        );
        assert_eq!(tampered.release_id, rec.release_id, "release id retained");
        let err = verify_release_identity(&tampered)
            .expect_err("an emptied slot snapshot must fail verification");
        assert!(
            err.to_string().contains("fail closed"),
            "error must explain the fail-closed rejection, got: {err}"
        );
    }
}

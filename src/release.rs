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
    RELEASE_PAYLOAD_SCHEMA_VERSION, RELEASE_RECORD_SCHEMA_VERSION, ReleaseDigest, ReleaseId,
    ReleaseRecord, TreeDigest, VariantName,
};
use jiff::Timestamp;
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

/// Canonical digest over the PER-RELEASE, PER-VARIANT behavior index an
/// attempt is bound to ([`crate::records::BehaviorIndex`]: release id ->
/// variant name -> contract). An attempt whose slots reference several
/// releases (a partial snapshot spans groups) carries ONE snapshot-wide
/// behavior digest over the whole index; two attempts share it only when
/// every referenced release's every declared variant behavior is identical.
/// `serde_json` serializes `BTreeMap`s in sorted key order, so the digest is
/// canonical (name-sorted, deterministic).
pub fn behavior_index_digest(
    index: &BTreeMap<ReleaseId, BTreeMap<String, BehaviorContract>>,
) -> String {
    let value = serde_json::to_vec(index).expect("behavior index serializes");
    sha256_bytes(&value)
}

/// Reconstruct the name-keyed per-variant behavior map from serialized JSON.
pub fn behavior_contracts_from_json(
    bytes: &[u8],
) -> std::result::Result<BTreeMap<String, BehaviorContract>, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Verify a serialized `behavior.json` payload against the canonical digest
/// recorded in a release's provenance (`behavior_sha256`), which is itself
/// part of the release identity (`release_sha256`). The payload is parsed and
/// the canonical digest recomputed over the name-sorted per-variant contract
/// map ([`variant_behaviors_digest`]); an UNPARSEABLE payload fails closed
/// with an integrity error, and so does a payload whose recomputed digest
/// differs from the provenance — a tampered `behavior.json` never yields a
/// historical contract that does not match the release it is stored under.
/// Only a payload that PARSES TO THE SAME canonical contract set (e.g. JSON
/// key reordering that deserializes identically, or any change that leaves
/// the contract set equal) passes — that is the "unless the canonical
/// behavior digest remains equal" clause. On success the parsed contracts
/// are returned so callers never parse twice.
pub fn verify_behavior_json(
    bytes: &[u8],
    release_id: &str,
    expected_digest: &str,
) -> Result<BTreeMap<String, BehaviorContract>> {
    let contracts = behavior_contracts_from_json(bytes).map_err(|e| {
        Error::integrity(format!(
            "release {release_id} behavior.json is malformed: {e}"
        ))
    })?;
    let recomputed = variant_behaviors_digest(&contracts);
    if recomputed != expected_digest {
        return Err(Error::integrity(format!(
            "release {release_id} behavior.json digest mismatch: stored provenance behavior_sha256 {expected_digest} does not match the digest {recomputed} recomputed from the behavior contracts (fail closed)"
        )));
    }
    Ok(contracts)
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
/// identity form: the identity-bearing fields of [`SlotDef`] (`id`, `server`,
/// `deploy_dir` as a lexically-normalized absolute path string, the ONE
/// owning `target` verbatim, `groups` SORTED and DEDUPLICATED), sorted by
/// slot id. The `groups` dedup is defensive: a duplicate name adds no
/// membership, so a record that slipped past validation (or predates it)
/// must still canonicalize to the same identity as the deduplicated list —
/// duplicate noise never shifts the digest. Server-level policy (user,
/// address, port, capacity) is deliberately absent — it is not release
/// identity.
///
/// The sort is a TOTAL ORDER over the identity fields (id, then server,
/// then deploy_dir, then target, then groups), not a stable id-only sort: a
/// STABLE sort over the id alone would let the DECLARATION ORDER of
/// duplicate-id slots leak into the canonical form, making the digest
/// asymmetric for two logically-identical declaration orders (the
/// identity-gap class of bug). A total order makes the canonical form a pure
/// function of the declared slot set — the same slots written in any order
/// canonicalize identically, even for the degenerate duplicate-id
/// declarations a record that slipped past validation can carry.
pub fn canonicalize_slots(slots: &[SlotDef]) -> CanonicalSlots {
    let mut out: Vec<CanonicalSlot> = slots
        .iter()
        .map(|s| CanonicalSlot {
            id: s.id.clone(),
            server: s.server.clone(),
            deploy_dir: normalize_deploy_dir(&s.deploy_dir),
            target: s.target.clone(),
            groups: {
                let mut g = s.groups.clone();
                g.sort();
                g.dedup();
                g
            },
        })
        .collect();
    out.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.server.cmp(&b.server))
            .then_with(|| a.deploy_dir.cmp(&b.deploy_dir))
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.groups.cmp(&b.groups))
    });
    CanonicalSlots { slots: out }
}

/// Canonical digest over name-sorted per-variant slot declarations. Each
/// variant's slots are canonicalized (the identity fields, `deploy_dir`
/// lexically normalized, `groups` sorted and deduplicated) and sorted by
/// the total order over those fields (id, server, deploy_dir, target,
/// groups — the content tie-break keeps the canonical form order-independent
/// even for duplicate-id declarations); the variants are name-sorted by the
/// `BTreeMap`. Two releases
/// share this digest only when every declared variant declares the same
/// slots — a rebind, `deploy_dir` move, owning-target change, or group
/// membership change alters it, while a reordering of slot declarations (or
/// of variants, or of a slot's `groups` list, or duplicate names in it —
/// deduplicated away) does not. Server-level policy (user/address/port/
/// capacity) is not part of it.
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
        schema_version: RELEASE_PAYLOAD_SCHEMA_VERSION,
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
        release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
        release_id: id.as_str().to_string(),
        release_sha256: digest.as_str().to_string(),
        created_at: Timestamp::now().to_string(),
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
                        target: s.target.clone(),
                        groups: s.groups.clone(),
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
/// The record's `release_schema_version` is checked FIRST and must be
/// exactly [`RELEASE_RECORD_SCHEMA_VERSION`]: a record carrying any other
/// version is refused outright (fail closed, naming the version) before any
/// digest work — only the current record format is ever interpreted. The
/// identity payload version ([`RELEASE_PAYLOAD_SCHEMA_VERSION`]) is enforced
/// implicitly by the recompute below, which re-derives the digest with
/// exactly that payload version: a release whose identity was derived from
/// any other payload version fails the recompute-and-verify check.
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
    // The record format version must be exactly the canonical constant: a
    // record from any other version is refused before any digest work.
    if rec.release_schema_version != RELEASE_RECORD_SCHEMA_VERSION {
        return Err(Error::integrity(format!(
            "release {} carries unsupported release_schema_version {} (expected {RELEASE_RECORD_SCHEMA_VERSION}): only RELEASE_RECORD_SCHEMA_VERSION is accepted",
            rec.release_id, rec.release_schema_version
        )));
    }
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
            target: target.to_string(),
            groups: Vec::new(),
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
                target: "production".to_string(),
                groups: Vec::new(),
            }],
        )]);
        let base_sha = variant_slots_digest(&base);

        // Changing the slot's ONE owning target changes the digest.
        let retargeted: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                target: "staging".to_string(),
                groups: Vec::new(),
            }],
        )]);
        assert_ne!(
            variant_slots_digest(&retargeted),
            base_sha,
            "an owning-target change must alter the digest"
        );

        // Reordering the same list canonicalizes identically.
        let reordered: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                target: "staging".to_string(),
                groups: Vec::new(),
            }],
        )]);
        assert_eq!(
            variant_slots_digest(&reordered),
            variant_slots_digest(&retargeted),
            "the owning target must not affect the digest when unchanged"
        );
    }

    /// Duplicate names in a slot's `groups` list add no membership, so the
    /// canonical form DEDUPS them: `["canary","canary"]` and `["canary"]`
    /// produce the SAME digest (a record that slipped past validation, or
    /// predates it, must not shift release identity), while a change that
    /// DOES alter membership (changing the owning target) still changes the
    /// digest.
    #[test]
    fn variant_slots_digest_dedups_duplicate_groups() {
        let single: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                target: "t1".to_string(),
                groups: vec!["canary".to_string()],
            }],
        )]);
        let duplicated: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                target: "t1".to_string(),
                groups: vec!["canary".to_string(), "canary".to_string()],
            }],
        )]);
        assert_eq!(
            variant_slots_digest(&single),
            variant_slots_digest(&duplicated),
            "a duplicated group name must not change the digest (membership is unchanged)"
        );

        // A change that DOES alter membership still changes the digest.
        let retargeted: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                target: "t2".to_string(),
                groups: vec!["canary".to_string()],
            }],
        )]);
        assert_ne!(
            variant_slots_digest(&single),
            variant_slots_digest(&retargeted),
            "an owning-target change must still alter the digest"
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

        // Owning-target change -> new digest: a slot-only change to the
        // `target` field creates a new ReleaseId.
        let s3: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotDef {
                id: "p1".to_string(),
                server: "server-01".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/example"),
                target: "staging".to_string(),
                groups: Vec::new(),
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
            "an owning-target change must re-digest"
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
    /// A tampered behavior.json whose canonical digest does not match the
    /// provenance `behavior_sha256` fails closed, while a payload that parses
    /// to the SAME canonical contract set (JSON key reordering) passes.
    #[test]
    fn verify_behavior_json_matches_provenance_digest() {
        let mut contracts: BTreeMap<String, BehaviorContract> = BTreeMap::new();
        contracts.insert(
            "standard".to_string(),
            BehaviorContract {
                activation: crate::config::ActivationConfig {
                    adapter: "systemd".to_string(),
                    scope: crate::config::ActivationScope::System,
                    reconcile_managed_units: true,
                    units: vec![crate::config::UnitDef {
                        name: "app.service".to_string(),
                        artifact_path: "integration/systemd/app.service".to_string(),
                        enable: true,
                        restart: true,
                    }],
                },
                verification: crate::config::VerificationConfig {
                    adapter: "command".to_string(),
                    argv: vec!["true".to_string()],
                    timeout_seconds: 30,
                    attempts: 2,
                    interval_seconds: 1,
                },
            },
        );
        let sha = variant_behaviors_digest(&contracts);
        let canonical = serde_json::to_vec(&contracts).unwrap();

        // The canonical payload verifies.
        verify_behavior_json(&canonical, "rel-x", &sha).expect("canonical payload verifies");

        // Key reordering in the raw bytes parses to the SAME contract set, so
        // the digest stays equal and verification passes (the "unless the
        // canonical behavior digest remains equal" clause).
        let reordered = br#"{"standard":{"verification":{"adapter":"command","argv":["true"],"timeout_seconds":30,"attempts":2,"interval_seconds":1},"activation":{"adapter":"systemd","scope":"system","reconcile_managed_units":true,"units":[{"name":"app.service","artifact_path":"integration/systemd/app.service","enable":true,"restart":true}]}}}"#;
        verify_behavior_json(reordered, "rel-x", &sha).expect("reordered JSON passes");

        // Every identity-bearing change alters the digest -> fail closed.
        let mutations: Vec<serde_json::Value> = vec![
            serde_json::json!({"standard": {"activation": {"adapter": "none", "scope": "system", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["false"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 31, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "user", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"canary": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({}),
        ];
        for (i, m) in mutations.iter().enumerate() {
            let bytes = serde_json::to_vec(m).unwrap();
            let err = verify_behavior_json(&bytes, "rel-x", &sha)
                .expect_err("every contract change must fail verification");
            assert!(
                err.to_string().contains("digest mismatch"),
                "mutation {i} must name the digest mismatch, got: {err}"
            );
        }

        // Unparseable bytes fail closed as malformed.
        let err = verify_behavior_json(b"{ not json", "rel-x", &sha)
            .expect_err("malformed bytes must fail closed");
        assert!(err.to_string().contains("malformed"));
    }
    /// The schema-version property for the RELEASE RECORD: generate arbitrary
    /// `u32` `release_schema_version` values; ONLY
    /// `RELEASE_RECORD_SCHEMA_VERSION` verifies, every other version fails
    /// closed with an integrity error naming the version (checked BEFORE any
    /// digest work — never a panic, never silent acceptance).
    #[test]
    fn verify_release_identity_accepts_only_record_schema_version() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));
        verify_release_identity(&rec).expect("the canonical version verifies");
        // Representative arbitrary-u32 set: 0, version - 1, version,
        // version + 1, 3, u32::MAX (duplicates harmless).
        let versions = [
            0u32,
            RELEASE_RECORD_SCHEMA_VERSION.wrapping_sub(1),
            RELEASE_RECORD_SCHEMA_VERSION,
            RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1),
            3,
            u32::MAX,
        ];
        for v in versions {
            let mut r = rec.clone();
            r.release_schema_version = v;
            if v == RELEASE_RECORD_SCHEMA_VERSION {
                verify_release_identity(&r).expect("the canonical version verifies");
            } else {
                let err = verify_release_identity(&r)
                    .expect_err("a record from any other version must fail closed");
                let msg = err.to_string();
                assert!(
                    msg.contains("release_schema_version"),
                    "error must name the version field, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{v}")),
                    "error must name the stored version {v}, got: {msg}"
                );
                assert!(
                    msg.contains("RELEASE_RECORD_SCHEMA_VERSION"),
                    "error must name the accepted version, got: {msg}"
                );
            }
        }
    }

    /// The schema-version property for the RELEASE IDENTITY PAYLOAD: the
    /// payload version is FROZEN into the release digest, so a release whose
    /// identity was derived with any `u32` version other than
    /// `RELEASE_PAYLOAD_SCHEMA_VERSION` fails the recompute-and-verify check
    /// (the stored digest never matches the digest re-derived with the
    /// canonical payload version). Only the canonical version produces a
    /// self-consistent, verifiable release.
    #[test]
    fn verify_release_identity_accepts_only_payload_schema_version() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let bindings: BTreeMap<String, String> = variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));
        let slots_digest = variant_slots_digest(&slots);
        // Representative arbitrary-u32 set over the payload version.
        let versions = [
            0u32,
            RELEASE_PAYLOAD_SCHEMA_VERSION.wrapping_sub(1),
            RELEASE_PAYLOAD_SCHEMA_VERSION,
            RELEASE_PAYLOAD_SCHEMA_VERSION.wrapping_add(1),
            3,
            u32::MAX,
        ];
        let mut digest_by_version: BTreeMap<u32, String> = BTreeMap::new();
        for v in versions {
            // Simulate a release whose identity was derived from a payload
            // carrying version `v` (the digest is the sha256 of the payload).
            let payload = CanonicalReleasePayload {
                schema_version: v,
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
                slots_digest: slots_digest.clone(),
                variants: bindings.clone(),
            };
            let digest = sha256_bytes(&serde_json::to_vec(&payload).expect("payload serializes"));
            let mut r = rec.clone();
            r.release_sha256 = digest.clone();
            r.release_id = format!("rel-sha256-{digest}");
            if v == RELEASE_PAYLOAD_SCHEMA_VERSION {
                verify_release_identity(&r).expect("a payload with the canonical version verifies");
            } else {
                let err = verify_release_identity(&r).expect_err(
                    "a payload from any other version must fail the recompute-and-verify check",
                );
                let msg = err.to_string();
                assert!(
                    msg.contains("identity mismatch"),
                    "error must name the recompute-and-verify mismatch, got: {msg}"
                );
                assert!(
                    msg.contains(&r.release_sha256),
                    "error must name the stored (payload-derived) digest, got: {msg}"
                );
            }
            // Every version in the set produces a DISTINCT identity digest:
            // the payload version is part of the hash, so each arbitrary
            // version is distinguishable from the canonical one.
            digest_by_version.insert(v, digest);
        }
        // All digests distinct across the representative set.
        let canonical = &digest_by_version[&RELEASE_PAYLOAD_SCHEMA_VERSION];
        for (v, d) in &digest_by_version {
            if *v == RELEASE_PAYLOAD_SCHEMA_VERSION {
                continue;
            }
            assert_ne!(
                d, canonical,
                "payload version {v} must produce a different digest than the canonical version"
            );
        }
    }

    // -------------------------------------------------------------------
    // Release-identity digest contract (property tests)
    // -------------------------------------------------------------------
    //
    // The property covers the FULL identity contract of
    // `build_release` + `recompute_release_digest` + `verify_release_identity`
    // over generated release components:
    //
    // 1. ROUND-TRIP: a built release's stored `release_sha256` / `release_id`
    //    are exactly what the recompute path (which `verify` uses) re-derives
    //    from the record's own content, and verification passes.
    // 2. MUTATION SENSITIVITY: every identity field — mapping digest, behavior
    //    digest, every variant's tree digest, the variant→tree binding, every
    //    slot's id/server/deploy_dir/targets, the self-referential output
    //    fields (`release_sha256`, `release_id`), and the schema versions —
    //    is tamper-evident: mutating it makes the recompute disagree (for
    //    content fields) and ALWAYS fails verification with an integrity
    //    error. The intentionally non-identity fields (`created_at`, the
    //    `git_revision` provenance) are whitelisted: mutating them must NOT
    //    change the digest and must NOT break verification. (There is no
    //    display-name field on `ReleaseRecord`; the docs' exclusion is
    //    realized by `created_at` + provenance.)
    // 3. CANONICAL ORDER-INDEPENDENCE: the same logical release written with
    //    differently-ordered slot declarations, differently-ordered target
    //    lists, duplicate targets, or textually-different-but-lexically-
    //    equivalent `deploy_dir` spellings canonicalizes to the SAME digest.

    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    /// One generated release component set: the frozen mapping digest, the
    /// behavior digest, the `variant -> tree digest` bindings, and the raw
    /// per-variant slot declarations. The shapes are adversarial: slot ids
    /// come from a small pool (slots SHARE ids across variants, and may
    /// collide within a variant), `targets` lists are generated unsorted with
    /// duplicates, `deploy_dir`s include `..`/`//`/trailing-slash/relative
    /// spellings, and variant names include empty and odd strings.
    #[derive(Clone, Debug)]
    struct ReleaseComponents {
        mapping_sha256: String,
        behavior_sha256: String,
        /// `variant -> tree digest` bindings (name-sorted map).
        variants: BTreeMap<String, String>,
        /// Raw per-variant slot declarations, pre-canonicalization.
        variant_slots: BTreeMap<String, Vec<SlotDef>>,
    }

    fn variant_name_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "standard".to_string(),
            "canary".to_string(),
            "".to_string(),
            "v".to_string(),
            "Variant-2".to_string(),
            "edge/blue-green".to_string(),
        ])
    }

    fn slot_id_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec!["p1".to_string(), "p2".to_string(), "s1".to_string()])
    }

    fn server_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "server-01".to_string(),
            "server-02".to_string(),
            "edge-1".to_string(),
        ])
    }

    fn deploy_dir_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "/srv/deploy/example".to_string(),
            "//srv//deploy/example/".to_string(),
            "/srv/deploy/../deploy/example".to_string(),
            "/srv/deploy/example/..".to_string(),
            "/srv/./deploy/example".to_string(),
            "/".to_string(),
            "..".to_string(),
            "./srv/deploy/example".to_string(),
            "/srv/deploy/example//".to_string(),
            "/srv/../srv/deploy/example".to_string(),
        ])
    }

    fn target_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "production".to_string(),
            "staging".to_string(),
            "edge".to_string(),
        ])
    }

    fn group_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "canary".to_string(),
            "wave-1".to_string(),
            "wave-2".to_string(),
        ])
    }

    fn slot_strategy() -> impl Strategy<Value = SlotDef> {
        (
            slot_id_strategy(),
            server_strategy(),
            deploy_dir_strategy(),
            target_strategy(),
            prop::collection::vec(group_strategy(), 0..3),
        )
            .prop_map(|(id, server, deploy_dir, target, groups)| SlotDef {
                id,
                server,
                deploy_dir: PathBuf::from(deploy_dir),
                target,
                groups,
            })
    }

    /// The component grammar: 1..4 `(variant name, tree seed, slots)` groups.
    /// Variant names are deduplicated keeping the FIRST occurrence (so the
    /// bindings and the slot declarations share exactly the same key set), the
    /// tree digest is the hex of a random 16-byte seed, and each variant
    /// carries 1..2 slots drawn from the adversarial slot grammar.
    fn release_components_strategy() -> impl Strategy<Value = ReleaseComponents> {
        (
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            prop::collection::vec(
                (
                    variant_name_strategy(),
                    any::<[u8; 16]>(),
                    prop::collection::vec(slot_strategy(), 1..3),
                ),
                1..4,
            ),
        )
            .prop_map(|(mapping_seed, behavior_seed, groups)| {
                let mut components = ReleaseComponents {
                    mapping_sha256: hex::encode(mapping_seed),
                    behavior_sha256: hex::encode(behavior_seed),
                    variants: BTreeMap::new(),
                    variant_slots: BTreeMap::new(),
                };
                for (name, tree_seed, slots) in groups {
                    if components.variants.contains_key(&name) {
                        continue;
                    }
                    components
                        .variants
                        .insert(name.clone(), hex::encode(tree_seed));
                    components.variant_slots.insert(name, slots);
                }
                components
            })
    }

    /// Three textual spellings of the same canonical directory `n`: the form
    /// itself, a doubled-slash + trailing-slash form, and a `<last>/../<last>`
    /// round-trip form. All three lexically normalize back to `n`. The
    /// degenerate forms (`""`, `"/"`, and relative paths) have no
    /// textually-different equivalent spelling, so all three spellings are
    /// `n` itself.
    fn equivalent_dir_spellings(n: &str) -> [String; 3] {
        if n.is_empty() || n == "/" || !n.starts_with('/') {
            return [n.to_string(), n.to_string(), n.to_string()];
        }
        let (prefix, last) = n.rsplit_once('/').expect("absolute path has a slash");
        [
            n.to_string(),
            format!("{prefix}//{last}/"),
            format!("{n}/../{last}"),
        ]
    }

    /// A record whose CONTENT was mutated (a field that feeds the recompute)
    /// must re-digest differently AND fail verification with an integrity
    /// error. The recompute is allowed to refuse an emptied slot snapshot
    /// (`None` — which is itself a recompute != original, since the original
    /// recomputes to `Some`); in every other case the recomputed digest must
    /// differ from the stored one.
    fn assert_content_mutation(original: &ReleaseRecord, mutated: &ReleaseRecord, label: &str) {
        if let Some(recomputed) = recompute_release_digest(mutated) {
            assert_ne!(
                recomputed.as_str(),
                original.release_sha256,
                "{label}: mutating an identity content field must change the recomputed digest"
            );
        }
        let err = verify_release_identity(mutated).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "{label}: tampering must fail with an integrity error, got: {err}"
        );
    }

    /// A record whose self-referential OUTPUT field was mutated
    /// (`release_sha256`, `release_id`, or a schema version) is detected by
    /// verification — the stored field is checked against the recompute —
    /// even though the recompute itself is unaffected (those fields are not
    /// digest inputs).
    fn assert_output_mutation(original: &ReleaseRecord, mutated: &ReleaseRecord, label: &str) {
        let recomputed = recompute_release_digest(mutated)
            .expect("output-field mutations never touch the slot snapshot");
        assert_eq!(
            recomputed.as_str(),
            original.release_sha256,
            "{label}: output fields are not digest inputs"
        );
        let err = verify_release_identity(mutated).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "{label}: a tampered output field must fail with an integrity error, got: {err}"
        );
    }

    /// A record whose WHITELISTED (intentionally non-identity) field was
    /// mutated — `created_at`, the `git_revision` provenance — must digest
    /// IDENTICALLY and still verify: the field is excluded from the identity
    /// contract, so changing it is not tampering.
    fn assert_whitelist_mutation(original: &ReleaseRecord, mutated: &ReleaseRecord, label: &str) {
        let recomputed = recompute_release_digest(mutated)
            .expect("whitelist mutations never touch the slot snapshot");
        assert_eq!(
            recomputed.as_str(),
            original.release_sha256,
            "{label}: whitelisted fields must not enter the digest"
        );
        verify_release_identity(mutated)
            .expect("{label}: a whitelisted-field change must not break verification");
    }

    /// The three-part contract for one generated component set.
    fn run_release_identity_contract(c: &ReleaseComponents) {
        let variants: BTreeMap<VariantName, TreeDigest> = c
            .variants
            .iter()
            .map(|(name, digest)| {
                (
                    VariantName::new(name.clone()),
                    TreeDigest::new(digest.clone()),
                )
            })
            .collect();
        let rec = build_release(
            &c.mapping_sha256,
            &c.behavior_sha256,
            &variants,
            &c.variant_slots,
            Path::new("."),
        );

        // (1) ROUND-TRIP: build and the recompute path `verify` uses agree on
        // the exact field partition — the stored digest/id are exactly what
        // the record's own content re-derives, and verification passes.
        let recomputed = recompute_release_digest(&rec)
            .expect("a built release always carries its canonical slot snapshot");
        assert_eq!(
            recomputed.as_str(),
            rec.release_sha256,
            "recompute must reproduce the digest build derived"
        );
        assert_eq!(
            ReleaseId::from_digest(&recomputed).as_str(),
            rec.release_id,
            "recompute must reproduce the release id build derived"
        );
        verify_release_identity(&rec).expect("a freshly built release verifies");

        // (2) MUTATION SENSITIVITY — content fields that feed the recompute.
        // Mapping digest.
        let mut r = rec.clone();
        r.provenance.mapping_sha256 = format!("{}!tampered", r.provenance.mapping_sha256);
        assert_content_mutation(&rec, &r, "mapping_sha256");
        // Behavior digest.
        let mut r = rec.clone();
        r.provenance.behavior_sha256 = format!("{}!tampered", r.provenance.behavior_sha256);
        assert_content_mutation(&rec, &r, "behavior_sha256");
        // The first variant's tree digest (the variant->tree binding value).
        let first_variant = rec
            .variants
            .keys()
            .next()
            .cloned()
            .expect("the grammar always yields at least one variant");
        let mut r = rec.clone();
        r.variants.insert(
            first_variant.clone(),
            format!("{}!tampered", rec.variants[&first_variant]),
        );
        assert_content_mutation(&rec, &r, "variant tree digest");
        // The variant->tree BINDING: adding a variant key changes the map.
        let mut r = rec.clone();
        let mut extra_name = "zzz-extra-variant".to_string();
        while rec.variants.contains_key(&extra_name) {
            extra_name.push('x');
        }
        r.variants.insert(extra_name, "tree-extra".to_string());
        assert_content_mutation(&rec, &r, "variant binding addition");
        // ... and removing a variant key changes the map.
        let mut r = rec.clone();
        r.variants.remove(&first_variant);
        assert_content_mutation(&rec, &r, "variant binding removal");
        // EVERY slot field of EVERY slot of EVERY variant is identity.
        for (variant, cs) in &rec.slots {
            for (i, slot) in cs.slots.iter().enumerate() {
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].id = format!("{}!tampered", slot.id);
                assert_content_mutation(&rec, &r, "slot id");

                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].server =
                    format!("{}!tampered", slot.server);
                assert_content_mutation(&rec, &r, "slot server");

                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].deploy_dir =
                    format!("{}!tampered", slot.deploy_dir);
                assert_content_mutation(&rec, &r, "slot deploy_dir");

                let mut r = rec.clone();
                let mut groups = slot.groups.clone();
                groups.push("tampered".to_string());
                r.slots.get_mut(variant).unwrap().slots[i].groups = groups;
                assert_content_mutation(&rec, &r, "slot groups");
            }
        }
        // Removing a slot changes the digest; clearing a variant's slots does
        // too (the snapshot keeps the variant key).
        let mut r = rec.clone();
        let (any_variant, any_cs) = rec.slots.iter().next().expect("at least one variant");
        if any_cs.slots.len() > 1 {
            r.slots.get_mut(any_variant).unwrap().slots.remove(0);
        } else {
            r.slots.get_mut(any_variant).unwrap().slots.clear();
        }
        assert_content_mutation(&rec, &r, "slot removal");
        // Emptying the ENTIRE slot snapshot: recompute refuses (None) and
        // verification fails closed (no legacy escape hatch).
        let mut r = rec.clone();
        r.slots.clear();
        assert!(
            recompute_release_digest(&r).is_none(),
            "an emptied slot snapshot must be refused by recompute"
        );
        let err = verify_release_identity(&r).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "an emptied slot snapshot must fail with an integrity error, got: {err}"
        );

        // (2) MUTATION SENSITIVITY — self-referential OUTPUT fields. The
        // stored digest, stored id, and record schema version are checked by
        // verification against the recompute, not trusted as inputs.
        let mut r = rec.clone();
        r.release_sha256 = "tampered-digest".to_string();
        assert_output_mutation(&rec, &r, "release_sha256");
        let mut r = rec.clone();
        r.release_id = "rel-sha256-tampered".to_string();
        assert_output_mutation(&rec, &r, "release_id");
        let mut r = rec.clone();
        r.release_schema_version = RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1);
        assert_output_mutation(&rec, &r, "release_schema_version");
        // The PAYLOAD schema version is frozen into the digest: a release
        // whose identity was derived from any other payload version fails the
        // recompute-and-verify check (the recompute always uses the canonical
        // payload version).
        let raw_slots: BTreeMap<String, Vec<SlotDef>> = rec
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
                            target: s.target.clone(),
                            groups: s.groups.clone(),
                        })
                        .collect(),
                )
            })
            .collect();
        let slots_digest = variant_slots_digest(&raw_slots);
        for v in [
            0u32,
            RELEASE_PAYLOAD_SCHEMA_VERSION.wrapping_add(1),
            u32::MAX,
        ] {
            let mut r = rec.clone();
            let payload = CanonicalReleasePayload {
                schema_version: v,
                mapping_sha256: rec.provenance.mapping_sha256.clone(),
                behavior_sha256: rec.provenance.behavior_sha256.clone(),
                slots_digest: slots_digest.clone(),
                variants: rec.variants.clone(),
            };
            let digest = sha256_bytes(&serde_json::to_vec(&payload).expect("payload serializes"));
            r.release_sha256 = digest.clone();
            r.release_id = format!("rel-sha256-{digest}");
            assert_output_mutation(&rec, &r, &format!("payload schema version {v}"));
        }

        // (2) WHITELIST — the intentionally non-identity fields. Mutating
        // `created_at` or the `git_revision` provenance must NOT change the
        // digest and must NOT break verification.
        let mut r = rec.clone();
        r.created_at = "2099-12-31T23:59:59Z".to_string();
        assert_whitelist_mutation(&rec, &r, "created_at");
        let mut r = rec.clone();
        r.provenance.git_revision = Some("deadbeef".to_string());
        assert_whitelist_mutation(&rec, &r, "git_revision set");
        let mut r = rec.clone();
        r.provenance.git_revision = None;
        assert_whitelist_mutation(&rec, &r, "git_revision removed");

        // (3) CANONICAL ORDER-INDEPENDENCE: the same LOGICAL release written
        // differently canonicalizes to the SAME digest.
        //
        // B: each variant's slot declarations reversed, each slot's `targets`
        // reversed, and each `deploy_dir` respelled textually-differently but
        // lexically-equivalently. C: each slot's `targets` list gets its first
        // name appended again (a duplicate — deduplicated away by the
        // canonical form).
        let b_slots: BTreeMap<String, Vec<SlotDef>> = c
            .variant_slots
            .iter()
            .map(|(v, defs)| {
                let mut out: Vec<SlotDef> = defs.iter().rev().cloned().collect();
                for (i, s) in out.iter_mut().enumerate() {
                    s.groups.reverse();
                    let n = normalize_deploy_dir(&s.deploy_dir);
                    s.deploy_dir = PathBuf::from(equivalent_dir_spellings(&n)[i % 3].clone());
                }
                (v.clone(), out)
            })
            .collect();
        let c_slots: BTreeMap<String, Vec<SlotDef>> = c
            .variant_slots
            .iter()
            .map(|(v, defs)| {
                let out: Vec<SlotDef> = defs
                    .iter()
                    .map(|s| {
                        let mut dup = s.clone();
                        if let Some(first) = dup.groups.first().cloned() {
                            dup.groups.push(first);
                        }
                        dup
                    })
                    .collect();
                (v.clone(), out)
            })
            .collect();
        let rec_b = build_release(
            &c.mapping_sha256,
            &c.behavior_sha256,
            &variants,
            &b_slots,
            Path::new("."),
        );
        let rec_c = build_release(
            &c.mapping_sha256,
            &c.behavior_sha256,
            &variants,
            &c_slots,
            Path::new("."),
        );
        assert_eq!(
            rec_b.release_sha256, rec.release_sha256,
            "reordered/reshuffled slot declarations must canonicalize to the same digest"
        );
        assert_eq!(
            rec_c.release_sha256, rec.release_sha256,
            "duplicated target names must dedup to the same digest"
        );
        assert_eq!(rec_b.release_id, rec.release_id, "reshuffled release id");
        assert_eq!(rec_c.release_id, rec.release_id, "deduplicated release id");
        assert_eq!(
            rec_b.slots, rec.slots,
            "the frozen canonical slot snapshot must be identical across spellings"
        );
        assert_eq!(
            rec_c.slots, rec.slots,
            "the frozen canonical slot snapshot must be identical after dedup"
        );
        verify_release_identity(&rec_b).expect("the reshuffled release verifies");
        verify_release_identity(&rec_c).expect("the deduplicated release verifies");
    }

    proptest! {
        // Main property: ORDINARY RANDOMIZED SEEDS with FAILURE PERSISTENCE
        // (proptest's defaults) — a failing vector writes to
        // `proptest-regressions/release.txt` and is replayed on the next run
        // (commit it so CI keeps reproducing the regression until fixed). The
        // case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn release_identity_digest_contract(components in release_components_strategy()) {
            run_release_identity_contract(&components);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION: the deterministic floor for CI. The same
        // generator under the pinned 0x5EED_5EED seed with no persistence runs
        // the IDENTICAL vectors on every invocation, so the suite stays
        // reproducible even when no failure has ever been persisted by the
        // main test. The case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn release_identity_digest_contract_fixed_seed_regression(
            components in release_components_strategy(),
        ) {
            run_release_identity_contract(&components);
        }
    }
}

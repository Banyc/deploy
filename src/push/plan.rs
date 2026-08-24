//! Deployment planning: resolve the desired per-slot assignment from a push
//! reference.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::history::{PushRef, resolve_snapshot};
use crate::model::{
    ArtifactRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, ServerId, TreeDigest,
    VariantName,
};
use crate::records::{PhysicalBinding, PlanSource};
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, BTreeSet};

/// The plan for one placement slot: exactly the canonical slot→artifact
/// assignment ([`PlacementSlotAssignment`]), reused rather than re-declared.
pub type PlannedAssignment = PlacementSlotAssignment;

/// Resolve the desired assignment for each slot of `target_name` given the
/// push reference. Returns the assignments, the release the attempt is bound
/// to, and the plan source.
pub fn plan_assignments(
    target_name: &str,
    pref: &PushRef,
    local_release_id: &ReleaseId,
    variant_trees: &BTreeMap<String, TreeDigest>,
    store: &LocalStore,
    config: &Config,
) -> Result<(Vec<PlannedAssignment>, ReleaseId, PlanSource)> {
    if !config.targets.contains_key(target_name) {
        return Err(Error::not_found(format!("target '{target_name}'")));
    }
    let members = config.target_slots(target_name)?;
    let slot_ids: Vec<PlacementSlotId> = members
        .iter()
        .map(|(slot, _)| PlacementSlotId::new(slot.id.clone()))
        .collect();

    match pref {
        PushRef::Head => {
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                // The slot's variant is the variant file that declares it (the
                // declaring file is the binding; there is no per-slot `variant`
                // field).
                let variant_name = config.slot_variant(&slot.id)?;
                let variant = VariantName::new(variant_name.to_string());
                let tree = variant_trees.get(variant_name).cloned().ok_or_else(|| {
                    Error::plan(format!("variant '{variant_name}' not materialized"))
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: ArtifactRef {
                        release: local_release_id.clone(),
                        variant,
                        tree,
                    },
                });
            }
            Ok((out, local_release_id.clone(), PlanSource::Head))
        }
        PushRef::Fleet {
            target: ft,
            index,
            current_variant,
        } => {
            let entry = resolve_snapshot(store, ft, *index)?;
            let recorded: BTreeSet<String> =
                entry.slots.keys().map(|s| s.as_str().to_string()).collect();
            let current: BTreeSet<String> =
                slot_ids.iter().map(|s| s.as_str().to_string()).collect();
            if recorded != current {
                return Err(Error::rollback(
                    "target membership changed; exact fleet rollback requires identical stable placement-slot set",
                ));
            }
            // Every member's COMPLETE physical binding — the server AND the
            // on-server deploy_dir — must match the one recorded in the
            // snapshot: the generation is mapped to a slot by SLOT ID, so a
            // slot rebound to a different server, or moved to a different
            // deploy_dir on the SAME server, would otherwise silently roll
            // the historical assignment onto the wrong host/location. A
            // missing recorded binding (legacy pre-feature snapshot) is
            // unverifiable and refuses for the same reason.
            for (slot, sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                let current = PhysicalBinding {
                    server: ServerId::new(sdef.id.clone()),
                    deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                };
                let recorded = entry.bindings.get(&slot_id).ok_or_else(|| {
                    Error::rollback(format!(
                        "slot '{slot_id}' has no recorded physical binding in {ft}@f{index}; exact rollback cannot verify the deployment location"
                    ))
                })?;
                if recorded != &current {
                    return Err(Error::rollback(format!(
                        "slot '{slot_id}' was bound to server '{}' at '{}' in {ft}@f{index}, now bound to '{}' at '{}'; exact rollback would deploy to the wrong host",
                        recorded.server, recorded.deploy_dir, current.server, current.deploy_dir
                    )));
                }
            }
            // The release the snapshot's generations came from (a coherent
            // fleet snapshot carries one release across its slots).
            let release = entry
                .slots
                .values()
                .next()
                .map(|g| g.assignment.artifact.release.clone())
                .unwrap_or_else(|| local_release_id.clone());
            // With the `:current` suffix each slot keeps its CURRENT
            // configured variant, so the per-slot TREE resolves from the
            // release's own variant→tree bindings (the release record must be
            // locally available), not from the snapshot's historical
            // artifact. Without it, the exact historical artifact
            // (variant + tree together) is restored.
            let rec = if *current_variant {
                Some(store.read_release(&release).map_err(|_| {
                    Error::rollback(format!(
                        "release {release} not available locally; `:current` needs its variant→tree bindings"
                    ))
                })?)
            } else {
                None
            };
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                let (variant, tree) = if *current_variant {
                    // `:current`: the variant is the slot's CURRENT declared
                    // variant (the current config's declaring file), never the
                    // snapshot's historical one; the tree still comes from the
                    // referenced release's own bindings.
                    let rec = rec.as_ref().expect("release record resolved above");
                    let variant = config.slot_variant(&slot.id)?;
                    let tree = rec.variants.get(variant).cloned().ok_or_else(|| {
                        Error::rollback(format!(
                            "release {release} lacks variant '{variant}' required by `:current` (current config assigns slot '{slot_id}' to it)"
                        ))
                    })?;
                    (VariantName::new(variant.to_string()), TreeDigest::new(tree))
                } else {
                    // Exact rollback: the variant AND tree come together from
                    // the historical snapshot, not the current slot binding.
                    let g = entry.slots.get(&slot_id).ok_or_else(|| {
                        Error::rollback(format!("slot {slot_id} missing in fleet snapshot"))
                    })?;
                    (
                        g.assignment.artifact.variant.clone(),
                        g.assignment.artifact.tree.clone(),
                    )
                };
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: ArtifactRef {
                        release: release.clone(),
                        variant,
                        tree,
                    },
                });
            }
            Ok((out, release, PlanSource::FleetRef(*index)))
        }
        PushRef::Release {
            release,
            current_variant,
        } => {
            let rec = store
                .read_release(release)
                .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                // WITHOUT `:current`, the variant comes from the release's OWN
                // stored slot snapshot: a historical release resolves each
                // slot's slot→variant binding against the slots it was
                // materialized from, never the caller's current variant files.
                // A record written before the canonical slot snapshot existed
                // (empty `rec.slots`) falls back to the current configuration's
                // declaring file. WITH `:current`, the variant ALWAYS comes
                // from the caller's current configuration — "assign each
                // current server its configured variant" — while the tree
                // still comes from the release's own per-variant bindings.
                // Note this slot declaration snapshot is distinct from a fleet
                // snapshot's slot→SERVER bindings (the exact-rollback
                // physical-host check): those remain a per-target deployment
                // concern.
                let variant_name = if *current_variant {
                    config.slot_variant(&slot.id)?.to_string()
                } else if rec.slots.is_empty() {
                    // Legacy record: fall back to the current declaring file.
                    config.slot_variant(&slot.id)?.to_string()
                } else {
                    rec.slots
                        .iter()
                        .find_map(|(v, cs)| {
                            cs.slots
                                .iter()
                                .any(|s| s.id == slot_id.as_str())
                                .then(|| v.clone())
                        })
                        .ok_or_else(|| {
                            Error::rollback(format!(
                                "release {release} declares no slot '{slot_id}'"
                            ))
                        })?
                };
                let variant = VariantName::new(variant_name.clone());
                let tree = rec.variants.get(&variant_name).cloned().ok_or_else(|| {
                    let mut msg = format!("release {release} lacks variant '{variant_name}'");
                    if *current_variant {
                        msg.push_str(" required by `:current` (current config assigns slot '");
                        msg.push_str(slot_id.as_str());
                        msg.push_str("' to it)");
                    }
                    Error::rollback(msg)
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: ArtifactRef {
                        release: release.clone(),
                        variant,
                        tree: TreeDigest::new(tree),
                    },
                });
            }
            Ok((
                out,
                release.clone(),
                PlanSource::ReleaseRef(release.clone()),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactRef, CanonicalSlot, CanonicalSlots, DeploymentId, GenerationId, GenerationRef,
        Provenance, RELEASE_RECORD_SCHEMA_VERSION, ReleaseRecord, ServerId, TargetName, TreeDigest,
        VariantName,
    };
    use crate::records::{DeploymentSnapshot, PhysicalBinding};

    const DEPLOY_TOML: &str = r#"
schema_version = 1
application = "plan"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    /// The `standard` variant file declares slot `p1` on server `s1` for
    /// target `t1`: the declaring file is the slot's CURRENT variant binding.
    const VARIANT_TOML: &str = r#"
[[slots]]
id = "p1"
server = "s1"
targets = ["t1"]
deploy_dir = "/srv/plan"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    fn project_with_config() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, DEPLOY_TOML).unwrap();
        let config = Config::load(&p).unwrap();
        (dir, config)
    }

    /// A release record in the pre-snapshot SHAPE: an EMPTY `slots` map (the
    /// shape written before the slots-into-identity refactor, and what
    /// `#[serde(default)]` yields for records without a `slots` member). The
    /// store now REJECTS empty slot snapshots at write and read (an empty
    /// snapshot cannot be verified from content), so fixtures that need a
    /// WRITABLE record must fill `slots` and recompute the identity with
    /// [`consistent`]. The bare empty-snapshot record is used directly only
    /// when a test needs the on-disk legacy shape. It still carries the
    /// per-variant tree bindings.
    fn legacy_record(id: &str, tree: &str) -> ReleaseRecord {
        ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: id.to_string(),
            release_sha256: format!("sha256-{id}"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                git_revision: None,
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
            },
            variants: BTreeMap::from([("standard".to_string(), tree.to_string())]),
            slots: BTreeMap::new(),
        }
    }

    /// Recompute a release record's stored identity from its own content so
    /// `read_release`'s recompute-and-verify passes: the digest is derived
    /// from the record's slot snapshot, bindings, and provenance digests
    /// exactly as `build_release` derives it. Returns the record's release id
    /// (the digest form, which is also the store directory key).
    fn consistent(rec: &mut ReleaseRecord) -> ReleaseId {
        let digest = crate::release::recompute_release_digest(rec)
            .expect("consistent record must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::model::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        ReleaseId::new(rec.release_id.clone())
    }

    /// A `PushRef::Release` resolution against a release record that carries
    /// its OWN stored canonical snapshot: each slot's variant binding resolves
    /// from the snapshot, the tree from the record's own per-variant
    /// bindings, and the assignment keeps the release's identity and resolves
    /// as `ReleaseRef`. (Empty-snapshot records are now REJECTED at the store
    /// boundary — see `empty_slot_snapshot_record_fails_closed_at_read` — so
    /// every writable release record carries its snapshot.)
    #[test]
    fn release_snapshot_resolves_variant_and_tree() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        // The release's OWN snapshot declares p1 -> `standard` (matching the
        // current config's declaring file, `config.slot_variant`); the tree
        // comes from the record's own bindings.
        let mut rec = legacy_record("unused", "tree-legacy");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    targets: vec!["t1".to_string()],
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();
        // The current config declares p1 inside the `standard` variant file.
        assert_eq!(config.slot_variant("p1").unwrap(), "standard");

        let (assignments, desired, source) = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &ReleaseId::new("unused-local".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("snapshot-carrying release resolves");

        assert_eq!(assignments.len(), 1);
        let a = &assignments[0];
        assert_eq!(a.placement_slot, PlacementSlotId::new("p1"));
        assert_eq!(
            a.artifact.variant.as_str(),
            "standard",
            "the variant must come from the release's OWN stored snapshot"
        );
        assert_eq!(
            a.artifact.tree.as_str(),
            "tree-legacy",
            "the tree must come from the release's own variant bindings"
        );
        assert_eq!(a.artifact.release, release);
        assert_eq!(desired, release);
        assert_eq!(source, PlanSource::ReleaseRef(release));
    }

    /// An on-disk record with an EMPTY stored slot snapshot (the pre-snapshot
    /// legacy shape) fails closed at the STORE: `read_release` refuses it
    /// (an empty snapshot cannot be recomputed into an identity), so a
    /// `PushRef::Release` ref pointing at it surfaces as the release-rollback
    /// error and can never silently fall back to the caller's current
    /// configuration.
    #[test]
    fn empty_slot_snapshot_record_fails_closed_at_read() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let release = ReleaseId::new("rel-sha256-legacy".to_string());
        // `write_release` refuses empty-snapshot records, so install the
        // legacy-shaped record directly (as pre-refactor on-disk data would
        // appear).
        let rec = legacy_record(release.as_str(), "tree-legacy");
        let dir = store.release_dir(&release);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("release.json"),
            serde_json::to_vec_pretty(&rec).unwrap(),
        )
        .unwrap();

        let err = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &ReleaseId::new("unused-local".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("an empty-slot-snapshot release must fail closed at read");
        assert!(
            err.to_string().contains("not available locally"),
            "the refusal must surface as the release-resolution rollback error, got: {err}"
        );
    }

    /// A NON-legacy release record whose stored slot snapshot does NOT declare
    /// a member slot must fail closed (rollback error naming the slot) rather
    /// than guessing a variant — the stored snapshot is authoritative for
    /// records that carry one.
    #[test]
    fn release_snapshot_missing_slot_fails_rollback() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let mut rec = legacy_record("unused", "tree-x");
        // A stored snapshot that declares a DIFFERENT slot (not the target's
        // member p1).
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "pX".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/other".to_string(),
                    targets: vec!["t1".to_string()],
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let err = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a stored snapshot that lacks a member slot must refuse");
        assert!(
            err.to_string().contains("declares no slot 'p1'"),
            "error must name the unresolved slot, got: {err}"
        );
    }

    /// The TREE must come from the release record's own variant bindings: a
    /// release whose bindings lack the snapshot-resolved variant fails closed
    /// with a rollback error naming the release.
    #[test]
    fn release_missing_variant_tree_fails_rollback() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    targets: vec!["t1".to_string()],
                }],
            },
        )]);
        rec.variants.clear(); // no variant bindings at all
        // Recompute the identity from the ACTUAL stored content (empty
        // bindings + snapshot) so the record verifies on write and read.
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let err = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a release without the resolved variant's tree must refuse");
        assert!(
            err.to_string().contains("lacks variant 'standard'"),
            "error must name the missing variant tree, got: {err}"
        );
    }

    /// The stored slot snapshot is authoritative for NON-legacy records even
    /// when it contradicts the current config: the slot's variant binding
    /// resolves from the snapshot, never `config.slot_variant`. (Contrast
    /// with `legacy_empty_slots_snapshot_falls_back_to_current_config_variant`.)
    #[test]
    fn release_snapshot_binding_wins_over_current_config() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        // Current config declares p1 under `standard`; the stored snapshot
        // instead records p1 under `other` (as if the slot later moved).
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "other".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    targets: vec!["t1".to_string()],
                }],
            },
        )]);
        rec.variants = BTreeMap::from([
            ("standard".to_string(), "tree-standard".to_string()),
            ("other".to_string(), "tree-other".to_string()),
        ]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let (assignments, _, _) = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("snapshot-declared release resolves");
        assert_eq!(
            assignments[0].artifact.variant.as_str(),
            "other",
            "the stored slot snapshot must win over the current config's declaring file"
        );
        assert_eq!(
            assignments[0].artifact.tree.as_str(),
            "tree-other",
            "the tree must pair with the snapshot-resolved variant"
        );
    }

    /// The `:current` suffix on a RELEASE ref keeps each slot's CURRENT
    /// configured variant (the declaring file in the caller's current config)
    /// while the TREE still comes from the referenced release's own per-variant
    /// bindings — "assign each current server its configured variant from that
    /// release". The bare `release/<id>` form uses the release's OWN stored
    /// slot snapshot instead. A release that ships BOTH variants proves the
    /// difference: the stored snapshot binds p1 to `other`, while the current
    /// config declares p1 in `standard`.
    #[test]
    fn release_ref_current_suffix_uses_current_config_variant() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        // Stored slot snapshot: p1 was bound to `other` at materialization.
        // Current config: p1 is declared by `standard` (slot_variant = standard).
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "other".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    targets: vec!["t1".to_string()],
                }],
            },
        )]);
        rec.variants = BTreeMap::from([
            ("standard".to_string(), "tree-standard".to_string()),
            ("other".to_string(), "tree-other".to_string()),
        ]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();
        assert_eq!(config.slot_variant("p1").unwrap(), "standard");

        // Bare ref: the release's OWN stored snapshot wins (p1 -> `other`).
        let (bare, desired, source) = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("bare release ref resolves");
        assert_eq!(bare[0].artifact.variant.as_str(), "other");
        assert_eq!(bare[0].artifact.tree.as_str(), "tree-other");
        assert_eq!(bare[0].artifact.release, release);
        assert_eq!(desired, release);
        assert_eq!(source, PlanSource::ReleaseRef(release.clone()));

        // `:current` ref: the CURRENT config's declaring file wins (p1 ->
        // `standard`), the tree comes from the release's OWN bindings.
        let (cur, desired, source) = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: true,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("current-variant release ref resolves");
        assert_eq!(
            cur[0].artifact.variant.as_str(),
            "standard",
            "`:current` must assign the slot's CURRENT configured variant"
        );
        assert_eq!(
            cur[0].artifact.tree.as_str(),
            "tree-standard",
            "the tree must come from the release's own binding for the current variant"
        );
        assert_eq!(cur[0].artifact.release, release);
        assert_eq!(desired, release);
        assert_eq!(source, PlanSource::ReleaseRef(release));
    }

    /// `release/<id>:current` fails closed when the release does NOT ship the
    /// slot's current configured variant — a variant renamed AFTER the release
    /// was materialized (the current config declares `new`, the release only
    /// ships `old`). The bare form still resolves the stored snapshot binding.
    #[test]
    fn release_ref_current_suffix_missing_current_variant_fails_closed() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        // The release ships ONLY `other`; the current config declares p1 in
        // `standard` (which the release never shipped).
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "other".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    targets: vec!["t1".to_string()],
                }],
            },
        )]);
        rec.variants = BTreeMap::from([("other".to_string(), "tree-other".to_string())]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let err = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: true,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a release lacking the current variant must refuse the `:current` ref");
        let msg = err.to_string();
        assert!(
            msg.contains("lacks variant 'standard'") && msg.contains(":current"),
            "error must name the missing current variant and the `:current` ref, got: {msg}"
        );

        // The bare ref still resolves against the stored snapshot.
        let (bare, _, _) = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("bare release ref still resolves");
        assert_eq!(bare[0].artifact.variant.as_str(), "other");
        assert_eq!(bare[0].artifact.tree.as_str(), "tree-other");
    }

    /// The `:current` suffix on a FLEET ref keeps each slot's CURRENT
    /// configured variant too (sourcing the tree from the snapshot release's
    /// own per-variant bindings), while the bare `@fN` form restores the exact
    /// historical artifact (variant + tree together). A variant rename with
    /// both variants shipped proves the difference.
    #[test]
    fn fleet_ref_current_suffix_uses_current_config_variant() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // The CURRENT config declares p1 inside the `new` variant file.
        std::fs::write(release_dir.join("new.toml"), VARIANT_TOML).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML).unwrap();
        let config = Config::load(&cfg_path).unwrap();
        assert_eq!(config.slot_variant("p1").unwrap(), "new");
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The snapshot's release ships BOTH the historical variant `old` and
        // the current variant `new`; its slot snapshot records p1 under `old`.
        let mut rec = legacy_record("unused", "tree-x");
        rec.variants = BTreeMap::from([
            ("old".to_string(), "tree-old".to_string()),
            ("new".to_string(), "tree-new".to_string()),
        ]);
        rec.slots = BTreeMap::from([(
            "old".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    targets: vec!["t1".to_string()],
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();
        let snapshot = DeploymentSnapshot {
            index: 0,
            deployment_id: DeploymentId::new("deploy-fleet-curvar".to_string()),
            target: TargetName::new("t1".to_string()),
            behavior_sha256: "sha256-aa".to_string(),
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new("gen-old".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: release.clone(),
                            variant: VariantName::new("old".to_string()),
                            tree: TreeDigest::new("tree-old".to_string()),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/plan".to_string(),
                },
            )]),
        };
        store.append_snapshot("t1", &snapshot).unwrap();

        // Bare fleet ref: exact rollback restores the historical artifact
        // (variant `old` + tree tree-old together).
        let (bare, desired, source) = plan_assignments(
            "t1",
            &PushRef::Fleet {
                target: TargetName::new("t1".to_string()),
                index: 0,
                current_variant: false,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("bare fleet ref resolves");
        assert_eq!(bare[0].artifact.variant.as_str(), "old");
        assert_eq!(bare[0].artifact.tree.as_str(), "tree-old");
        assert_eq!(bare[0].artifact.release, release);
        assert_eq!(desired, release);
        assert_eq!(source, PlanSource::FleetRef(0));

        // `:current` fleet ref: the CURRENT config's declaring file wins
        // (p1 -> `new`), the tree comes from the release's own bindings.
        let (cur, desired, source) = plan_assignments(
            "t1",
            &PushRef::Fleet {
                target: TargetName::new("t1".to_string()),
                index: 0,
                current_variant: true,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("current-variant fleet ref resolves");
        assert_eq!(
            cur[0].artifact.variant.as_str(),
            "new",
            "`:current` must assign the slot's CURRENT configured variant"
        );
        assert_eq!(cur[0].artifact.tree.as_str(), "tree-new");
        assert_eq!(cur[0].artifact.release, release);
        assert_eq!(desired, release);
        assert_eq!(source, PlanSource::FleetRef(0));
    }

    /// A LEGACY fleet snapshot (no `bindings` map — the pre-feature shape)
    /// makes exact rollback unverifiable: `plan_assignments` must REFUSE the
    /// `@fN` ref with a rollback error naming the slot, rather than guessing
    /// the host/location. The integration tests cover binding MISMATCH
    /// (`rollback_refuses_rebound_slot` / `rollback_refuses_moved_deploy_dir`);
    /// this pins the MISSING-binding refusal (the `#[serde(default)]` empty
    /// map path).
    #[test]
    fn fleet_ref_without_recorded_bindings_refuses_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML).unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // A snapshot whose `slots` record the generation but whose `bindings`
        // map is EMPTY (legacy pre-feature line).
        let snapshot = DeploymentSnapshot {
            index: 0,
            deployment_id: DeploymentId::new("deploy-legacy-fleet".to_string()),
            target: TargetName::new("t1".to_string()),
            behavior_sha256: "sha256-aa".to_string(),
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new("gen-legacy".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new("rel-sha256-legacy".to_string()),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-legacy".to_string()),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::new(),
        };
        store.append_snapshot("t1", &snapshot).unwrap();

        let err = plan_assignments(
            "t1",
            &PushRef::Fleet {
                target: TargetName::new("t1".to_string()),
                index: 0,
                current_variant: false,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a fleet ref whose snapshot recorded no physical binding must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("no recorded physical binding") && msg.contains("p1"),
            "error must name the unverifiable slot and the missing binding, got: {msg}"
        );
        assert!(
            msg.contains("f0") || msg.contains("exact rollback"),
            "error must explain the exact-rollback verification failure, got: {msg}"
        );
    }
}

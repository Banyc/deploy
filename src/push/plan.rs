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
        PushRef::Snapshot { target: ft, index } => {
            let entry = resolve_snapshot(store, ft, *index)?;
            let recorded: BTreeSet<String> =
                entry.slots.keys().map(|s| s.as_str().to_string()).collect();
            let current: BTreeSet<String> =
                slot_ids.iter().map(|s| s.as_str().to_string()).collect();
            if recorded != current {
                return Err(Error::rollback(
                    "target membership changed; exact rollback requires identical stable placement-slot set",
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
                        "slot '{slot_id}' has no recorded physical binding in snapshot s{index} of target '{ft}'; exact rollback cannot verify the deployment location"
                    ))
                })?;
                if recorded != &current {
                    return Err(Error::rollback(format!(
                        "slot '{slot_id}' was bound to server '{}' at '{}' in snapshot s{index} of target '{ft}', now bound to '{}' at '{}'; exact rollback would deploy to the wrong host",
                        recorded.server, recorded.deploy_dir, current.server, current.deploy_dir
                    )));
                }
            }
            // The release the snapshot's generations came from (a coherent
            // snapshot carries one release across its slots).
            let release = entry
                .slots
                .values()
                .next()
                .map(|g| g.assignment.artifact.release.clone())
                .unwrap_or_else(|| local_release_id.clone());
            // EXACT rollback always restores the snapshot's OWN historical
            // artifact (variant + tree together), never the caller's current
            // configuration: a variant renamed or re-declared after the
            // snapshot was taken must not change what the rollback deploys.
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                let g = entry.slots.get(&slot_id).ok_or_else(|| {
                    Error::rollback(format!("slot {slot_id} missing in snapshot"))
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: g.assignment.artifact.clone(),
                });
            }
            Ok((out, release, PlanSource::SnapshotRef(*index)))
        }
        PushRef::Release { release } => {
            let rec = store
                .read_release(release)
                .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                // The variant ALWAYS comes from the release's OWN stored slot
                // snapshot: a historical release resolves each slot's
                // slot→variant binding against the slots it was materialized
                // from, never the caller's current variant files. Note this
                // slot declaration snapshot is distinct from a deployment
                // snapshot's slot→SERVER bindings (the exact-rollback
                // physical-host check): those remain a per-target deployment
                // concern.
                let variant_name = if rec.slots.is_empty() {
                    // A record without a canonical slot snapshot is
                    // unverifiable; the store rejects such records at read,
                    // so this is a belt-and-braces refusal rather than a
                    // reachable fallback to the current configuration.
                    return Err(Error::rollback(format!(
                        "release {release} carries no stored slot snapshot; cannot resolve slot '{slot_id}'"
                    )));
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
                    Error::rollback(format!("release {release} lacks variant '{variant_name}'"))
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
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    const DEPLOY_TOML: &str = r#"
schema_version = 1
application = "plan"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.deployment]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    /// Two-target fixture for the direct-release property: `t1` is the
    /// SOURCE (it carries the snapshot that recorded the old physical
    /// binding), `t2` the DESTINATION with NO snapshot history (the release
    /// was built/pushed elsewhere). Both declare the same slot `p1`.
    const DEPLOY_TOML_TWO: &str = r#"
schema_version = 1
application = "plan"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.deployment]
protect_deployments = 1

[targets.t2.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t2.rotation.deployment]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[targets.t2]
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

    /// The direct-release property's variant: slot `p1` bound to server `s1`
    /// at `/srv/plan` for BOTH targets `t1` (source) and `t2` (destination).
    const VARIANT_TOML_TWO: &str = r#"
[[slots]]
id = "p1"
server = "s1"
targets = ["t1", "t2"]
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

    /// EXACT SNAPSHOT ROLLBACK ALWAYS RESTORES THE SNAPSHOT'S OWN HISTORICAL
    /// VARIANT — never the caller's current config. Variant-renamed scenario:
    /// the snapshot's release ships BOTH the historical variant `old` (which
    /// declares p1 at snapshot time) and the current `new` variant, and the
    /// CURRENT config declares p1 inside `new.toml`. A `PushRef::Snapshot`
    /// ref must still plan `old` + its tree, not the current declaring file.
    #[test]
    fn snapshot_ref_restores_historical_variant_after_rename() {
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
            deployment_id: DeploymentId::new("deploy-snapshot-histvar".to_string()),
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

        // Exact rollback restores the historical artifact (variant `old` +
        // tree-old together) even though the current config declares p1 in
        // `new` and the release also ships it.
        let (assignments, desired, source) = plan_assignments(
            "t1",
            &PushRef::Snapshot {
                target: TargetName::new("t1".to_string()),
                index: 0,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("snapshot ref resolves");
        assert_eq!(assignments[0].artifact.variant.as_str(), "old");
        assert_eq!(assignments[0].artifact.tree.as_str(), "tree-old");
        assert_eq!(assignments[0].artifact.release, release);
        assert_eq!(desired, release);
        assert_eq!(source, PlanSource::SnapshotRef(0));
    }

    /// A LEGACY snapshot (no `bindings` map — the pre-feature shape)
    /// makes exact rollback unverifiable: `plan_assignments` must REFUSE the
    /// `sN` ref with a rollback error naming the slot, rather than guessing
    /// the host/location. The integration tests cover binding MISMATCH
    /// (`rollback_refuses_rebound_slot` / `rollback_refuses_moved_deploy_dir`);
    /// this pins the MISSING-binding refusal (the `#[serde(default)]` empty
    /// map path).
    #[test]
    fn snapshot_ref_without_recorded_bindings_refuses_rollback() {
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
            deployment_id: DeploymentId::new("deploy-legacy-snapshot".to_string()),
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
            &PushRef::Snapshot {
                target: TargetName::new("t1".to_string()),
                index: 0,
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a snapshot ref whose snapshot recorded no physical binding must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("no recorded physical binding") && msg.contains("p1"),
            "error must name the unverifiable slot and the missing binding, got: {msg}"
        );
        assert!(
            msg.contains("s0") || msg.contains("exact rollback"),
            "error must explain the exact-rollback verification failure, got: {msg}"
        );
    }

    // ---------------------------------------------------------------------
    // DIRECT-RELEASE PROPERTY: `release:<id>` plans where a snapshot ref
    // cannot — changed physical bindings, or a destination with no snapshot
    // history — while snapshot refs RETAIN their exact-binding checks.
    // ---------------------------------------------------------------------

    /// A generated change to a slot's physical binding between the source
    /// deployment and now: either the slot was REBOUND to a different server
    /// (same deploy_dir), or MOVED to a different deploy_dir on the SAME
    /// server. Returns the binding the source deployment's snapshot recorded
    /// (the OLD one); the current config binds the slot to `s1` at
    /// `/srv/plan`, so the two always differ in at least one dimension.
    fn old_binding_strategy() -> impl Strategy<Value = (String, String)> {
        prop_oneof![
            // Rebound: recorded on a different server, same deploy_dir.
            (
                "[a-z0-9]{6,16}".prop_map(|s: String| format!("srv-{s}")),
                Just("/srv/plan".to_string()),
            ),
            // Moved: same server, a different deploy_dir.
            (
                Just("s1".to_string()),
                "[a-z0-9]{2,10}".prop_map(|s: String| format!("/srv/{s}/old")),
            ),
        ]
    }

    /// Build the direct-release property fixture: a project with source
    /// target `t1` and destination target `t2` (no history), a release
    /// record whose OWN stored slot snapshot declares `p1` -> `standard`
    /// (tree `tree-direct`), and a snapshot on `t1` that records `old` as
    /// p1's physical binding at deployment time — the binding the CURRENT
    /// config no longer has.
    fn direct_release_fixture(
        old_binding: &(String, String),
    ) -> (tempfile::TempDir, Config, LocalStore, ReleaseId) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML_TWO).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML_TWO).unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN stored slot-variant snapshot: p1 -> `standard`.
        let mut rec = legacy_record("unused", "tree-direct");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    targets: vec!["t1".to_string(), "t2".to_string()],
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        // The SOURCE deployment's snapshot records the OLD binding.
        let snapshot = DeploymentSnapshot {
            index: 0,
            deployment_id: DeploymentId::new("deploy-source".to_string()),
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
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-direct".to_string()),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new(old_binding.0.clone()),
                    deploy_dir: old_binding.1.clone(),
                },
            )]),
        };
        store.append_snapshot("t1", &snapshot).unwrap();

        (dir, config, store, release)
    }

    // The required direct-release property: for a generated changed
    // physical binding (a slot REBOUND to a different server, or MOVED to a
    // different deploy_dir) — and for a source/destination pair whose
    // destination `t2` has NO snapshot history — `release:<id>` (resolved
    // to [`PushRef::Release`]) plans successfully against the CURRENT
    // target's slots from the release's OWN stored slot snapshot, while the
    // equivalent SNAPSHOT ref retains its exact physical-binding refusal
    // (a snapshot that recorded the old binding fails closed; on the
    // no-history destination the snapshot-family refs cannot even resolve).
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn direct_release_plans_where_snapshot_ref_refuses(
            old_binding in old_binding_strategy(),
            cross_target in prop::bool::ANY,
        ) {
            let (_dir, config, store, release) = direct_release_fixture(&old_binding);
            let release_ref = PushRef::Release {
                release: release.clone(),
            };

            // DIRECT: plans successfully on the CURRENT target's slots (the
            // source `t1` AND the no-history destination `t2` alike), the
            // variant per slot from the release's OWN stored snapshot and the
            // tree from its own bindings — never the caller's config, never
            // any snapshot chain, regardless of the changed binding.
            for dest in ["t1", "t2"] {
                let (assignments, desired, source) = plan_assignments(
                    dest,
                    &release_ref,
                    &ReleaseId::new("unused-local".to_string()),
                    &BTreeMap::new(),
                    &store,
                    &config,
                )
                .unwrap_or_else(|e| panic!("release:<id> must plan on target {dest}: {e}"));
                assert_eq!(assignments.len(), 1, "one slot per target");
                let a = &assignments[0];
                assert_eq!(a.placement_slot, PlacementSlotId::new("p1"));
                assert_eq!(
                    a.artifact.variant.as_str(),
                    "standard",
                    "the variant must come from the release's OWN stored snapshot"
                );
                assert_eq!(
                    a.artifact.tree.as_str(),
                    "tree-direct",
                    "the tree must come from the release's own variant bindings"
                );
                assert_eq!(a.artifact.release, release);
                assert_eq!(desired, release);
                assert_eq!(source, PlanSource::ReleaseRef(release.clone()));
            }

            // The SNAPSHOT ref RETAINS the exact physical-binding checks: on
            // the source `t1`, the snapshot recorded the generated OLD
            // binding (rebound or moved), which no longer matches the current
            // config, so rollback refuses with the exact-rollback error — the
            // same refusal as before this feature.
            let err = plan_assignments(
                "t1",
                &PushRef::Snapshot {
                    target: TargetName::new("t1".to_string()),
                    index: 0,
                },
                &ReleaseId::new("unused".to_string()),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .expect_err("a snapshot ref whose recorded binding changed must refuse");
            let msg = err.to_string();
            assert!(
                msg.contains("exact rollback would deploy to the wrong host") && msg.contains("p1"),
                "snapshot ref must keep the exact-binding refusal naming the slot, got: {msg}"
            );

            // Cross-target branch: the destination `t2` has ZERO snapshot
            // history — the release was built/pushed elsewhere. The snapshot-
            // family refs cannot even RESOLVE there (no chain to step, no
            // snapshot referencing the release), while the direct form works.
            if cross_target {
                for token in ["@-", "s0", "parent(@, 1)"] {
                    crate::history::resolve_push_ref(token, "t2", &store)
                        .expect_err(&format!("{token} on the no-history destination must fail"));
                }
                crate::history::resolve_push_ref(
                    &format!("parent({release}, 0)"),
                    "t2",
                    &store,
                )
                .expect_err("no snapshot references the release on t2; the refid must fail");
            }
        }
    }
}

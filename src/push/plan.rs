//! Deployment planning: resolve the desired per-slot assignment from a push
//! reference.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::history::{PushRef, resolve_deployment};
use crate::model::{
    ArtifactRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, ReleaseRecord, ServerId,
    TreeDigest, VariantName,
};
use crate::records::{PhysicalBinding, PlanSource};
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, BTreeSet};

/// The plan for one placement slot: exactly the canonical slot→artifact
/// assignment ([`PlacementSlotAssignment`]), reused rather than re-declared.
pub type PlannedAssignment = PlacementSlotAssignment;

/// DIRECT-RELEASE MEMBERSHIP VALIDATION (before any remote access): a
/// `release:<id>` push deploys onto the CURRENT target's slots, so the
/// release's OWN canonical slot snapshot must freeze EXACTLY the slot-id set
/// the target currently has.
///
/// The expected set is the union over every variant in the record's snapshot
/// of the slots whose `targets` list contains the destination target
/// (variants share slots, so the union is deduplicated by slot id; the
/// membership is a set). The comparison is LOGICAL membership only: physical
/// bindings (server / deploy_dir) are intentionally allowed to differ —
/// unlike the exact-rollback `Snapshot` branch, which also demands identical
/// physical bindings. A target whose membership DRIFTED since the release
/// was built — a slot added, removed, or renamed — is refused, before any
/// assignment is built and before any remote access, rather than deploying
/// to the wrong slot set.
///
/// Runs at TWO sites: the engine's early gate in `push()` — immediately
/// after the ref is parsed/resolved, BEFORE any lock and BEFORE the remote
/// factory is invoked, in both real and dry-run modes — and here, in the
/// `PushRef::Release` plan branch (the second line of defense protecting the
/// direct-`push_inner` test entry points). `current_slot_ids` is the target's
/// CURRENT member slot-id set, derived from the caller's config exactly as
/// [`plan_assignments`] derives it (`config.target_slots`, in deterministic
/// order), so both gates compare the SAME sets.
pub(crate) fn validate_direct_release_membership(
    target_name: &str,
    release: &ReleaseId,
    rec: &ReleaseRecord,
    current_slot_ids: &[PlacementSlotId],
) -> Result<()> {
    let expected: BTreeSet<String> = rec
        .slots
        .values()
        .flat_map(|cs| cs.slots.iter())
        .filter(|s| s.targets.iter().any(|t| t == target_name))
        .map(|s| s.id.clone())
        .collect();
    let current: BTreeSet<String> = current_slot_ids
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    if expected != current {
        return Err(Error::rollback(format!(
            "release {release} targets slots [{}] but target '{target_name}' currently has [{}]; direct release membership drift is rejected before remote access",
            expected.iter().cloned().collect::<Vec<_>>().join(", "),
            current.iter().cloned().collect::<Vec<_>>().join(", "),
        )));
    }
    Ok(())
}

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
        PushRef::Deployment {
            target: ft,
            deployment_id,
        } => {
            let entry = resolve_deployment(store, ft, deployment_id)?;
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
                let current_binding = PhysicalBinding {
                    server: ServerId::new(sdef.id.clone()),
                    deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                };
                let recorded = entry.bindings.get(&slot_id).ok_or_else(|| {
                    Error::rollback(format!(
                        "slot '{slot_id}' has no recorded physical binding in deployment '{deployment_id}' of target '{ft}'; exact rollback cannot verify the deployment location"
                    ))
                })?;
                if recorded != &current_binding {
                    return Err(Error::rollback(format!(
                        "slot '{slot_id}' was bound to server '{}' at '{}' in deployment '{deployment_id}' of target '{ft}', now bound to '{}' at '{}'; exact rollback would deploy to the wrong host",
                        recorded.server,
                        recorded.deploy_dir,
                        current_binding.server,
                        current_binding.deploy_dir
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
            Ok((
                out,
                release,
                PlanSource::DeploymentRef(deployment_id.clone()),
            ))
        }
        PushRef::Release { release } => {
            let rec = store
                .read_release(release)
                .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
            // DIRECT-RELEASE MEMBERSHIP CHECK (before any remote access) — see
            // [`validate_direct_release_membership`]. The engine's `push()`
            // ALSO runs this gate before the remote factory is ever invoked
            // (real AND dry-run modes); this plan-time call is the second line
            // of defense, protecting the direct-`push_inner` test entry points.
            validate_direct_release_membership(target_name, release, &rec, &slot_ids)?;
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
        Provenance, RELEASE_RECORD_SCHEMA_VERSION, ReleaseRecord, SCHEMA_VERSION, ServerId,
        TargetName, TreeDigest, VariantName,
    };
    use crate::records::{
        DeploymentStatus, LedgerIntent, LedgerRollback, LedgerTerminal, PhysicalBinding,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    const DEPLOY_TOML: &str = r#"
schema_version = 1
application = "plan"
release = "v1"

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
    /// target `t1`: the declaring file is the slot's CURRENT variant binding
    /// and owns the slot's ONE retention policy.
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

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
protect_deployments = 1

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
    /// The owning variant file carries the slot's single retention policy.
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

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
protect_deployments = 1

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

    /// Seed a SUCCESSFUL ledger entry for `t1` (intent + `Successful`
    /// terminal carrying the rollback payload), mirroring the old
    /// `append_snapshot` test helper. The rollback payload carries the
    /// snapshot's `slots`/`bindings`; the release is derived from the first
    /// slot's artifact (a coherent deployment carries one release across its
    /// slots).
    fn append_successful_snapshot(
        store: &LocalStore,
        deployment_id: &str,
        behavior_sha256: &str,
        slots: BTreeMap<PlacementSlotId, GenerationRef>,
        bindings: BTreeMap<PlacementSlotId, PhysicalBinding>,
    ) {
        let id = DeploymentId::new(deployment_id.to_string());
        let target = TargetName::new("t1".to_string());
        let release = slots
            .values()
            .next()
            .map(|g| g.assignment.artifact.release.clone())
            .expect("a snapshot records at least one slot");
        store
            .append_intent(
                "t1",
                &LedgerIntent {
                    deployment_schema_version: SCHEMA_VERSION,
                    deployment_id: id.clone(),
                    target: target.clone(),
                    slot_ids: slots.keys().cloned().collect(),
                    behavior_sha256: behavior_sha256.to_string(),
                    attempted_at: "2026-01-01T00:00:00Z".to_string(),
                    desired: BTreeMap::new(),
                    pre_push: BTreeMap::new(),
                    slots: BTreeMap::new(),
                },
            )
            .unwrap();
        store
            .append_terminal(
                "t1",
                &LedgerTerminal {
                    deployment_id: id,
                    target,
                    status: DeploymentStatus::Successful,
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    outcomes: BTreeMap::new(),
                    rollback: Some(LedgerRollback {
                        behavior_sha256: behavior_sha256.to_string(),
                        release,
                        slots,
                        bindings,
                    }),
                    reason: None,
                },
            )
            .unwrap();
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

    /// A NON-legacy release record whose stored slot snapshot does NOT
    /// declare the current target's member slot must fail closed with the
    /// MEMBERSHIP-DRIFT refusal before any remote access: the release froze a
    /// DIFFERENT slot set (here a renamed slot `pX` where the current config
    /// has `p1`) — the stored snapshot is authoritative, so direct release
    /// planning refuses rather than deploying to the wrong slot set.
    #[test]
    fn release_snapshot_missing_slot_refuses_drift() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let mut rec = legacy_record("unused", "tree-x");
        // A stored snapshot that declares a DIFFERENT slot (not the target's
        // member p1): renamed-slot drift.
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
        .expect_err("a stored snapshot whose slot set drifts from the target must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("release") && msg.contains("drift"),
            "error must be the membership-drift refusal, got: {msg}"
        );
        assert!(
            msg.contains("pX") && msg.contains("p1"),
            "error must name the expected vs current slot sets, got: {msg}"
        );
        assert!(
            msg.contains("before remote access"),
            "error must explain the refusal happens before remote access, got: {msg}"
        );
    }

    /// MISSING-SLOT drift: the current target has a slot `p2` the release's
    /// stored snapshot does not declare — direct release planning refuses
    /// with the membership-drift error (expected [p1] vs current [p1, p2]).
    #[test]
    fn release_membership_drift_missing_slot_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Current config: TWO slots for t1 (p1 and p2, distinct servers).
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"
[[slots]]
id = "p1"
server = "s1"
targets = ["t1"]
deploy_dir = "/srv/plan"

[[slots]]
id = "p2"
server = "s2"
targets = ["t1"]
deploy_dir = "/srv/plan-2"

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
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        // A second server entry so slot p2's server exists.
        std::fs::write(
            &cfg_path,
            DEPLOY_TOML.replace(
                "[[servers]]\nid = \"s1\"",
                "[[servers]]\nid = \"s2\"\naddress = \"a2\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[[servers]]\nid = \"s1\"",
            ),
        )
        .unwrap();
        let config = Config::load(&cfg_path).unwrap();
        assert_eq!(config.target_slot_ids("t1").unwrap(), ["p1", "p2"]);
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's own snapshot pins ONLY p1 (p2 was added to the target
        // after the release was built elsewhere).
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
        .expect_err("a release whose snapshot lacks a current member slot must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("membership") && msg.contains("[p1]") && msg.contains("[p1, p2]"),
            "drift error must name expected [p1] vs current [p1, p2], got: {msg}"
        );
    }

    /// EXTRA-SLOT drift: the release's own snapshot pins a slot `p2` the
    /// current target does not have — direct release refuses (expected
    /// [p1, p2] vs current [p1]).
    #[test]
    fn release_membership_drift_extra_slot_refuses() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let mut rec = legacy_record("unused", "tree-x");
        // The release pins p1 AND a p2 the current t1 has no member for.
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![
                    CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/plan".to_string(),
                        targets: vec!["t1".to_string()],
                    },
                    CanonicalSlot {
                        id: "p2".to_string(),
                        server: "s2".to_string(),
                        deploy_dir: "/srv/plan-2".to_string(),
                        targets: vec!["t1".to_string()],
                    },
                ],
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
        .expect_err("a release whose snapshot pins a slot the target lacks must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("membership") && msg.contains("[p1, p2]") && msg.contains("[p1]"),
            "error must name expected [p1, p2] vs current [p1], got: {msg}"
        );
    }

    /// LOGICAL-ONLY: a slot whose PHYSICAL binding changed (different server,
    /// same id) but whose id stays is still a member — the membership check
    /// compares slot IDs only, so a slot rebound to another server plans
    /// (contrast with the exact-rollback Snapshot branch, which refuses).
    #[test]
    fn release_membership_physical_binding_drift_plans() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // CURRENT config: p1 rebound to server s2 at a moved deploy_dir.
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"
[[slots]]
id = "p1"
server = "s2"
targets = ["t1"]
deploy_dir = "/srv/moved"

[[artifact.mappings]]
from = "src/artifacts/build/output/"
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
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            DEPLOY_TOML.replace(
                "[[servers]]\nid = \"s1\"",
                "[[servers]]\nid = \"s2\"\naddress = \"a2\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[[servers]]\nid = \"s1\"",
            ),
        )
        .unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN snapshot froze p1 at its ORIGINAL physical
        // binding (s1, /srv/plan) — the membership set is unchanged, so the
        // direct release plans onto the current (moved) binding.
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
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let (assignments, desired, source) = plan_assignments(
            "t1",
            &PushRef::Release {
                release: release.clone(),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("physical binding drift must not block logical-membership planning");
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].placement_slot, PlacementSlotId::new("p1"));
        assert_eq!(desired, release);
        assert_eq!(source, PlanSource::ReleaseRef(release));
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
    /// CURRENT config declares p1 inside `new.toml`. A `PushRef::Deployment`
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
        append_successful_snapshot(
            &store,
            "deploy-snapshot-histvar",
            "sha256-aa",
            BTreeMap::from([(
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
            BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/plan".to_string(),
                },
            )]),
        );

        // Exact rollback restores the historical artifact (variant `old` +
        // tree-old together) even though the current config declares p1 in
        // `new` and the release also ships it.
        let (assignments, desired, source) = plan_assignments(
            "t1",
            &PushRef::Deployment {
                target: TargetName::new("t1".to_string()),
                deployment_id: DeploymentId::new("deploy-snapshot-histvar".to_string()),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("deployment ref resolves");
        assert_eq!(assignments[0].artifact.variant.as_str(), "old");
        assert_eq!(assignments[0].artifact.tree.as_str(), "tree-old");
        assert_eq!(assignments[0].artifact.release, release);
        assert_eq!(desired, release);
        assert_eq!(
            source,
            PlanSource::DeploymentRef(DeploymentId::new("deploy-snapshot-histvar".to_string()))
        );
    }

    /// A LEGACY snapshot (no `bindings` map — the pre-feature shape)
    /// makes exact rollback unverifiable: `plan_assignments` must REFUSE the
    /// deployment ref with a rollback error naming the slot, rather than guessing
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
        append_successful_snapshot(
            &store,
            "deploy-legacy-snapshot",
            "sha256-aa",
            BTreeMap::from([(
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
            BTreeMap::new(),
        );

        let err = plan_assignments(
            "t1",
            &PushRef::Deployment {
                target: TargetName::new("t1".to_string()),
                deployment_id: DeploymentId::new("deploy-legacy-snapshot".to_string()),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a deployment ref whose snapshot recorded no physical binding must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("no recorded physical binding") && msg.contains("p1"),
            "error must name the unverifiable slot and the missing binding, got: {msg}"
        );
        assert!(
            msg.contains("exact rollback"),
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
    ///
    /// The record's canonical slot carries the SAME `targets` list as the
    /// current config's `p1` (`["t1", "t2"]`), so the release-versioned
    /// membership and the CURRENT membership both reduce to the set `{p1}`
    /// on every target — the planning-succeeds side of the direct-release
    /// membership rule (only the PHYSICAL binding differs, which is
    /// intentionally allowed).
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
        append_successful_snapshot(
            &store,
            "deploy-source",
            "sha256-aa",
            BTreeMap::from([(
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
            BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new(old_binding.0.clone()),
                    deploy_dir: old_binding.1.clone(),
                },
            )]),
        );

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
    // The membership rule is satisfied on both targets: the record's
    // snapshot and the current config bind the same slot set `{p1}`, so the
    // direct form passes its logical-membership check; only the physical
    // binding differs, which the direct form intentionally allows.
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
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: DeploymentId::new("deploy-source".to_string()),
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
            // history — the release was built/pushed elsewhere. The
            // deployment-history refs cannot even RESOLVE there (no chain to
            // step — the source deployment id is not a t2 deployment), while
            // the direct form works.
            if cross_target {
                for token in ["@-", "parent(@, 1)"] {
                    crate::history::resolve_ref_expr(
                        &crate::history::parse_ref_expr(token).expect("family tokens must parse"),
                        "t2",
                        &store,
                    )
                    .expect_err(&format!("{token} on the no-history destination must fail"));
                }
                crate::history::resolve_ref_expr(
                    &crate::history::parse_ref_expr("deploy-source")
                        .expect("deployment id must parse"),
                    "t2",
                    &store,
                )
                .expect_err("no snapshot for the deployment on t2; the deployment id must fail");
                // The removed release-refid / sN forms are rejected at parse.
                for token in ["s0", &format!("parent({release}, 0)")] {
                    crate::history::parse_ref_expr(token)
                        .expect_err(&format!("legacy form '{token}' must be rejected"));
                }
            }
        }
    }

    // The slot universe + fixed members the membership property draws from:
    // `p1`/`p2`/`p3` are the generated COMMON members (declared for BOTH
    // targets), `iso` is a `t2`-ONLY member (cross-target isolation: it must
    // never leak into t1's derived membership), and `phys` is a constant
    // member whose PHYSICAL binding (server) the fixture may drift while its
    // id stays (logical-only comparison). Each slot owns a distinct server so
    // the config's per-target server-uniqueness validation passes for every
    // generated membership.
    const SLOT_UNIVERSE: [&str; 3] = ["p1", "p2", "p3"];

    /// Build the membership-drift property fixture from two generated
    /// membership sets: `release_inc[i]` says whether universe slot `i` is
    /// frozen in the release record's OWN canonical slot snapshot (targets
    /// `t1`+`t2`); `current_inc[i]` says whether it is declared in the
    /// CURRENT config for both targets. `iso` (t2-only) and `phys`
    /// (t1+t2) are constant members of BOTH the record and the config;
    /// `physical_drift` rebinds `phys` to a different server in the config
    /// only (its id stays — logical membership unchanged). Returns the
    /// fixture plus the written record (so the test can cross-check the
    /// realized physical drift against the canonical binding).
    fn membership_drift_fixture(
        release_inc: [bool; 3],
        current_inc: [bool; 3],
        physical_drift: bool,
    ) -> (
        tempfile::TempDir,
        Config,
        LocalStore,
        ReleaseId,
        ReleaseRecord,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();

        // Current variant file: one slot entry per generated current member,
        // plus the constant `iso` (t2-only) and `phys` (rebound when
        // `physical_drift`).
        let mut variant = String::new();
        let add_slot = |variant: &mut String, id: &str, server: &str, targets: &str, dir: &str| {
            variant.push_str(&format!(
                "[[slots]]\nid = \"{id}\"\nserver = \"{server}\"\ntargets = [{targets}]\ndeploy_dir = \"{dir}\"\n\n"
            ));
        };
        for (i, inc) in current_inc.iter().enumerate() {
            if *inc {
                let id = SLOT_UNIVERSE[i];
                add_slot(
                    &mut variant,
                    id,
                    &format!("s{}", i + 1),
                    "\"t1\", \"t2\"",
                    &format!("/srv/{id}"),
                );
            }
        }
        add_slot(&mut variant, "iso", "s4", "\"t2\"", "/srv/iso");
        add_slot(
            &mut variant,
            "phys",
            if physical_drift { "s6" } else { "s5" },
            "\"t1\", \"t2\"",
            "/srv/phys",
        );
        variant.push_str(
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n[rotation.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n[rotation.deployment]\nprotect_deployments = 1\n\n[activation]\nadapter = \"none\"\n\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
        std::fs::write(release_dir.join("standard.toml"), variant).unwrap();

        let mut servers = String::new();
        for i in 1..=6 {
            servers.push_str(&format!(
                "[[servers]]\nid = \"s{i}\"\naddress = \"a{i}\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n"
            ));
        }
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "schema_version = 1\napplication = \"plan\"\nrelease = \"v1\"\n\n\
                 {servers}\
                 [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n\n\
                 [targets.t2]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen canonical snapshot: the generated
        // membership (targets t1+t2) plus the constant phys (t1+t2, at its
        // ORIGINAL server s5) and iso (t2-only), exactly mirroring the
        // current config's targets lists.
        let mut rec = legacy_record("unused", "tree-x");
        let mut canonical: Vec<CanonicalSlot> = Vec::new();
        for (i, id) in SLOT_UNIVERSE.iter().enumerate() {
            if release_inc[i] {
                canonical.push(CanonicalSlot {
                    id: id.to_string(),
                    server: format!("s{}", i + 1),
                    deploy_dir: format!("/srv/{id}"),
                    targets: vec!["t1".to_string(), "t2".to_string()],
                });
            }
        }
        canonical.push(CanonicalSlot {
            id: "phys".to_string(),
            server: "s5".to_string(),
            deploy_dir: "/srv/phys".to_string(),
            targets: vec!["t1".to_string(), "t2".to_string()],
        });
        canonical.push(CanonicalSlot {
            id: "iso".to_string(),
            server: "s4".to_string(),
            deploy_dir: "/srv/iso".to_string(),
            targets: vec!["t2".to_string()],
        });
        canonical.sort_by(|a, b| a.id.cmp(&b.id));
        rec.slots = BTreeMap::from([("standard".to_string(), CanonicalSlots { slots: canonical })]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        (dir, config, store, release, rec)
    }

    // THE REQUIRED DIRECT-RELEASE MEMBERSHIP PROPERTY: for generated
    // release-versioned and current membership sets, direct release planning
    // onto the destination target SUCCEEDS iff the two slot-ID sets match
    // EXACTLY (logical equality) and REFUSES with the membership-drift error
    // otherwise — the drift refusal lands at PLAN time, before any remote
    // access. Also: cross-target isolation (t2's extra `iso` member never
    // disturbs t1's derived membership) and logical-only comparison (phys's
    // SERVER rebind with an unchanged id still plans).
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn direct_release_membership_must_match_release_record(
            release_inc in prop::array::uniform3(prop::bool::ANY),
            current_inc in prop::array::uniform3(prop::bool::ANY),
            physical_drift in prop::bool::ANY,
        ) {
            let (_dir, config, store, release, rec) =
                membership_drift_fixture(release_inc, current_inc, physical_drift);
            let release_ref = PushRef::Release {
                release: release.clone(),
            };
            let expected: BTreeSet<String> = SLOT_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| release_inc[*i])
                .map(|(_, id)| id.to_string())
                .collect();
            let current: BTreeSet<String> = SLOT_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| current_inc[*i])
                .map(|(_, id)| id.to_string())
                .collect();

            if expected == current {
                // Membership match: the direct release plans on BOTH targets.
                // Cross-target isolation: t2's extra `iso` member (frozen in
                // the record AND declared in the config) must not disturb
                // t1's derived membership — t1 plans exactly its own set.
                for dest in ["t1", "t2"] {
                    let (assignments, desired, source) = plan_assignments(
                        dest,
                        &release_ref,
                        &ReleaseId::new("unused-local".to_string()),
                        &BTreeMap::new(),
                        &store,
                        &config,
                    )
                    .unwrap_or_else(|e| {
                        panic!("release:<id> must plan on target {dest} when the membership matches: {e}")
                    });
                    let mut want: Vec<String> = expected.iter().cloned().collect();
                    want.push("phys".to_string());
                    if dest == "t2" {
                        want.push("iso".to_string());
                    }
                    want.sort();
                    let mut got: Vec<String> = assignments
                        .iter()
                        .map(|a| a.placement_slot.as_str().to_string())
                        .collect();
                    got.sort();
                    assert_eq!(
                        got, want,
                        "target {dest} must plan exactly its frozen membership"
                    );
                    for a in &assignments {
                        assert_eq!(a.artifact.variant.as_str(), "standard");
                        assert_eq!(a.artifact.release, release);
                    }
                    assert_eq!(desired, release);
                    assert_eq!(source, PlanSource::ReleaseRef(release.clone()));
                }
                // LOGICAL-ONLY: when the fixture realized a physical binding
                // change (phys's server rebound), planning still succeeded
                // above — the membership check compares slot IDs only, never
                // server or deploy_dir. Cross-check the fixture actually
                // drifted (config server differs from the record's frozen
                // canonical binding) so the assertion is meaningful.
                if physical_drift {
                    let rec_phys = rec
                        .slots["standard"]
                        .slots
                        .iter()
                        .find(|s| s.id == "phys")
                        .expect("phys is frozen in the record");
                    let bindings = config.target_slot_bindings("t1").unwrap();
                    let cfg_phys = bindings
                        .get(&PlacementSlotId::new("phys"))
                        .expect("phys is a member of t1");
                    assert_ne!(
                        cfg_phys.server.as_str(),
                        rec_phys.server,
                        "the fixture must realize the physical drift: config server {} vs record server {}",
                        cfg_phys.server,
                        rec_phys.server
                    );
                    assert_eq!(
                        cfg_phys.deploy_dir, rec_phys.deploy_dir,
                        "only the server drifted; deploy_dir stays put"
                    );
                }
            } else {
                // Membership drift (missing / extra / renamed slots): REFUSED
                // at plan time, on every target, with the drift error naming
                // the release, the expected vs current slot sets, and the
                // before-remote-access clause.
                for dest in ["t1", "t2"] {
                    let err = plan_assignments(
                        dest,
                        &release_ref,
                        &ReleaseId::new("unused-local".to_string()),
                        &BTreeMap::new(),
                        &store,
                        &config,
                    )
                    .expect_err("membership drift must refuse direct release planning");
                    let msg = err.to_string();
                    assert!(
                        msg.contains("release")
                            && msg.contains("drift")
                            && msg.contains("before remote access"),
                        "refusal must be the membership-drift error, got: {msg}"
                    );
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // DEPLOYMENT-KEYED ROLLBACK PROPERTY: `deploy push <target> <id>` plans
    // EXACTLY the snapshot recorded for that deployment (the user's
    // requirement — the plan's slots/behavior/release equal the stored
    // payload, keyed by deployment id).
    // ---------------------------------------------------------------------

    // THE DEPLOYMENT-KEYED ROLLBACK PROPERTY: for generated deployment
    // histories, `PushRef::Deployment { deployment_id }` (the resolution of
    // `deploy push <target> <deployment-id>`) plans EXACTLY the snapshot
    // recorded for that deployment — each slot's artifact (release, variant,
    // tree) equals the snapshot's stored generation ref, the plan's release
    // is the snapshot's release, and the source is `DeploymentRef(id)`.
    // The plan runs the exact-binding checks (membership + physical
    // bindings) against the CURRENT config, so the generated snapshot is
    // bound to the config's own member slot (`p1` on server `s1` at
    // `/srv/plan`); a deployment id with NO snapshot never plans.
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn deployment_ref_plans_exactly_the_recorded_snapshot(
            tree in "[a-f0-9]{6,16}",
            generation in "[a-z0-9]{4,10}",
            behavior in "[a-f0-9]{4,16}",
        ) {
            let (_dir, config) = project_with_config();
            let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
            let deployment_id = DeploymentId::new("deploy-prop-plan".to_string());
            let snapshot_release = ReleaseId::new(format!("rel-sha256-{tree}"));
            let slots = BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new(format!("gen-{generation}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: snapshot_release.clone(),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new(tree.clone()),
                        },
                    },
                },
            )]);
            append_successful_snapshot(
                &store,
                deployment_id.as_str(),
                &format!("sha256-{behavior}"),
                slots.clone(),
                BTreeMap::from([(
                    PlacementSlotId::new("p1".to_string()),
                    PhysicalBinding {
                        server: ServerId::new("s1".to_string()),
                        deploy_dir: "/srv/plan".to_string(),
                    },
                )]),
            );

            let (assignments, desired, source) = plan_assignments(
                "t1",
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: deployment_id.clone(),
                },
                &ReleaseId::new("unused-local".to_string()),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .unwrap_or_else(|e| panic!("the deployment id must plan its stored state: {e}"));

            // EXACTLY the stored state: one slot, its artifact (variant +
            // tree + release) byte-identical to the snapshot's recorded
            // GenerationRef.
            assert_eq!(assignments.len(), 1, "one member slot");
            let a = &assignments[0];
            let stored = &slots[&PlacementSlotId::new("p1")];
            assert_eq!(a.placement_slot, PlacementSlotId::new("p1"));
            assert_eq!(a.artifact, stored.assignment.artifact, "the planned artifact must equal the snapshot's stored artifact");
            assert_eq!(desired, snapshot_release, "the rollout release is the snapshot's release");
            assert_eq!(
                source,
                PlanSource::DeploymentRef(deployment_id.clone()),
                "the plan source records the deployment key"
            );

            // A deployment id with NO snapshot never plans (failed / unknown
            // ids fail closed at the plan boundary too).
            let missing = DeploymentId::new("deploy-prop-missing".to_string());
            let err = plan_assignments(
                "t1",
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: missing.clone(),
                },
                &ReleaseId::new("unused".to_string()),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .expect_err("an unknown deployment id must refuse to plan");
            assert!(
                err.to_string().contains(missing.as_str())
                    || err.to_string().contains("deployment"),
                "the refusal must name the missing deployment, got: {err}"
            );
        }
    }
}

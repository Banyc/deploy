//! The "Everything up to date" no-op detection (A1 deployment semantics) and
//! the no-op path's hidden maintenance wiring (A7).
//!
//! [`check_up_to_date`] runs on the push spine ([`crate::deploy::push`])
//! between planning and intent persistence: a HEAD push whose every selected
//! slot already runs the COMPLETE desired [`ArtifactRef`] — release, variant,
//! and tree (two variants can share a release AND the same tree bytes yet
//! carry DIFFERENT behavior contracts, so matching only tree+release would
//! falsely report "Everything up to date") — is verified PER SLOT against the
//! DESIRED variant's behavior contract and reported as a no-op without
//! creating any record.
//!
//! The no-op's verification renders the EXISTING generation's identities —
//! deployment_id/generation_id/artifact from the running generation's
//! assignment — never the NEW deployment/generation ids (A7 "no-op
//! verification renders EXISTING generation identities, never fabricated
//! ones": the no-op creates no records, so the new ids would be fabricated).
//!
//! The no-op path SILENTLY runs the post-commit maintenance the real push's
//! step 17 would have serviced (A7 "no-op push silently runs:
//! deferred-retention retry, pending-sweep retry, observed refresh, per-slot
//! verification"); the shared maintenance wiring itself lives in
//! [`crate::deploy::maintenance`].

use crate::config::{ProjectConfig, ServerDef, SlotConfig};
use crate::deploy::plan::PlannedAssignment;
use crate::error::Result;
use crate::identity::{DeploymentId, OperationId, SlotId};
use crate::ledger::{BehaviorIndex, Observation, ObservedSlot, ObservedState, PushRef};
use crate::remote::helper::{GenerationAssignment, RemoteHelper, RemoteStatus};
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use crate::verify::command::run_verification;
use std::collections::{BTreeMap, HashMap};

use super::maintenance::{
    maintenance_warning, refresh_observed, retry_deferred_retentions, retry_pending_sweep,
};
use super::push::{PushReport, slot_vars};

/// The early "Everything up to date" check for HEAD pushes, run BEFORE
/// persisting any plan/status record so an up-to-date no-op leaves no
/// dangling `in_progress` deployment behind. Returns `Ok(Some(report))` when
/// every selected slot already runs the desired artifact AND passes its
/// per-slot verification — with the no-op path's post-commit maintenance
/// (deferred-retention retry, pending-sweep retry, observed refresh) already
/// serviced — and `Ok(None)` to fall through to a real push.
// 12 parameters: the full no-op check context (data: pref, store, config,
// target_name, members, assignments, statuses, helpers, remotes,
// behavior_index, op_id, deployment_id); bundling them would obscure the
// per-slot verification contract this signature enforces, so the allow
// documents the deliberate choice rather than a band-aid (mirrors
// `push_inner`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_up_to_date(
    pref: &PushRef,
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    members: &[(&SlotConfig, &ServerDef)],
    assignments: &[PlannedAssignment],
    statuses: &HashMap<SlotId, RemoteStatus>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    remotes: &HashMap<SlotId, Box<dyn Remote>>,
    behavior_index: &BehaviorIndex,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
) -> Result<Option<PushReport>> {
    if !matches!(pref, PushRef::Head) {
        return Ok(None);
    }
    // Retain the CURRENT generation assignment for every matching slot: the
    // no-op verification below renders the EXISTING generation's identities
    // (deployment_id/generation_id/artifact) — the running service was
    // deployed with those, and the no-op creates no records, so the NEW
    // deployment/generation ids would be fabricated.
    let mut existing: BTreeMap<SlotId, GenerationAssignment> = BTreeMap::new();
    let mut all_match = true;
    for a in assignments {
        let st = statuses.get(&a.placement_slot).expect("status present");
        let matches = st
            .current_generation
            .as_ref()
            .map(|g| {
                helpers[&a.placement_slot]
                    .read_assignment(g.as_str())
                    .map(|asn| {
                        // COMPLETE ArtifactRef equality (release + variant
                        // + tree). Two variants can share a release AND the
                        // same tree bytes (identical artifact mappings) yet
                        // carry DIFFERENT behavior contracts; matching only
                        // tree+release would falsely report "Everything up to
                        // date" when the slot's variant changes, leaving the
                        // service claimed verified under the new contract
                        // without ever running it.
                        let ok = asn.artifact == a.artifact;
                        if ok {
                            existing.insert(a.placement_slot.clone(), asn);
                        }
                        ok
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !matches {
            all_match = false;
            break;
        }
    }
    if all_match {
        // Verify the running services to confirm true up-to-date state. The
        // template vars render the EXISTING generation's identities from
        // the retained assignment (deployment_id/generation_id/artifact) —
        // the no-op creates no records, so the NEW deployment/generation ids
        // would be fabricated. The behavior contract to verify against stays
        // the DESIRED variant's contract: in a true no-op the existing
        // generation's variant equals the desired one (the comparison above
        // already proved complete ArtifactRef equality, variant included).
        let mut verified = true;
        for a in assignments {
            let remote = remotes[&a.placement_slot].as_ref();
            // PER-ASSIGNMENT behavior resolution: the slot's contract is
            // its OWN artifact binding's (release, variant) — a partial
            // snapshot can carry slots from DIFFERENT releases.
            let Some(variant_behavior) = behavior_index
                .get(&a.artifact.release)
                .and_then(|m| m.get(a.artifact.variant.as_str()))
            else {
                // Coverage was validated before any remote mutation; a miss
                // means the up-to-date claim cannot be established. Fall
                // through to a real push rather than panicking.
                verified = false;
                break;
            };
            let Some(asn) = existing.get(&a.placement_slot) else {
                // A matching slot must have retained its assignment above; a
                // miss means the up-to-date claim cannot be established.
                // Fall through to a real push rather than panicking.
                verified = false;
                break;
            };
            let vars = slot_vars(
                members,
                config,
                target_name,
                &a.placement_slot,
                &asn.artifact,
                Some(&asn.deployment_id),
                Some(&asn.generation_id),
            )?;
            if run_verification(remote, &variant_behavior.verification, &vars).is_err() {
                verified = false;
                break;
            }
        }
        if verified {
            // Post-commit maintenance hook for the no-op path: a no-op push
            // creates no records and skips step 17, so any retention debt
            // left by an earlier push would never be serviced here — retry
            // it explicitly before reporting "Everything up to date".
            // Best-effort: a failure stays as the marker and surfaces as a
            // warning; the no-op report itself is unchanged. The retry is
            // NON-FALLIBLE (post-commit maintenance): every debt read/write
            // failure is collected into the returned warnings, never an
            // `Err` — the no-op report stays "Everything up to date".
            let deferred = retry_deferred_retentions(
                store,
                config,
                target_name,
                helpers,
                op_id,
                deployment_id,
            );
            // Refresh observed state on the NO-OP path (the same
            // [`refresh_observed`] helper and projection as the real-push
            // path). A crash-window push — one that aborted AFTER the
            // remote advanced but BEFORE the observed refresh (e.g. a
            // faulted `write_results`) — was finalized by the reconcile
            // above and now matches here as "Everything up to date";
            // without this refresh the shared slot's observed projection
            // would stay stale/absent in every member target. The
            // projections are rebuilt from the EXISTING generation's
            // assignment (the no-op creates no records), so after ANY
            // completed or recovered mutation every member target's
            // observed projection equals the remote assignment. Best-effort
            // per the post-commit lifecycle: a refresh failure warns but
            // never converts the no-op into an error — the report below
            // stays "Everything up to date".
            let mut observed_servers: BTreeMap<SlotId, ObservedSlot> = BTreeMap::new();
            for (slot_id, asn) in &existing {
                observed_servers.insert(
                    slot_id.clone(),
                    ObservedSlot {
                        observation: Observation::Known(ObservedState {
                            generation: asn.generation_id.clone(),
                            artifact: asn.artifact.clone(),
                            last_deployment: asn.deployment_id.clone(),
                        }),
                    },
                );
            }
            let mut observed_warnings: Vec<String> = Vec::new();
            refresh_observed(
                store,
                target_name,
                members,
                &observed_servers,
                &mut observed_warnings,
            );
            let mut maintenance = deferred;
            // The store-global PENDING SWEEP (deferred by an earlier
            // checkpoint whose sweep did not complete) is also
            // POST-COMMIT MAINTENANCE: a no-op push creates no records
            // and skips step 17, so the sweep debt would never be
            // serviced here — retry it explicitly before reporting
            // "Everything up to date". Best-effort: a failure stays as
            // the marker and surfaces as a warning; the no-op report
            // itself is unchanged. NON-FALLIBLE (post-commit
            // maintenance): every debt read/write failure is collected
            // into the returned warnings, never an `Err`.
            maintenance.extend(retry_pending_sweep(store, config, deployment_id.as_str()));
            maintenance.extend(observed_warnings);
            let warning = maintenance_warning(&maintenance);
            return Ok(Some(PushReport {
                status: None,
                attempt: None,
                message: "Everything up to date".to_string(),
                warning,
                dry_run: false,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProjectConfig;
    use crate::deploy::push::{PushOptions, push};
    use crate::deploy::testsupport::{
        NONE_TOML, RecordingRemote, RecoveryHarness, known_artifact, push_clean, push_main_with_id,
        snapshot_files,
    };
    use crate::identity::{SlotId, test_deployment_id};
    use crate::ledger::{DeploymentStatus, Observation};
    use crate::remote::helper::GenerationAssignment;
    use crate::remote::layout;
    use crate::remote::transport::{LocalTransport, Remote};
    use crate::store::local::LocalStore;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// The no-op must leave the ENTIRE per-target store byte-for-byte
    /// untouched: no attempt, no transition, no snapshot, `observed.json`
    /// unchanged — the up-to-date detection runs before any record is
    /// persisted.
    #[test]
    fn no_op_push_leaves_store_untouched() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-noop-baseline");
        let r1 = push_main_with_id(&h, &id).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));

        let target_dir = h.store.target_dir("t1");
        let before = snapshot_files(&target_dir);

        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "no-op push creates no attempt");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no new attempt may be recorded by the no-op"
        );
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "no new snapshot may be appended by the no-op"
        );

        let after = snapshot_files(&target_dir);
        assert_eq!(
            before, after,
            "the no-op push must not touch any store file (attempts, transitions, observed, refs)"
        );
        // Observed still reflects the successful push.
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let Observation::Known(obs_state) = &observed.slots[&SlotId::new("p1")].observation else {
            panic!("observed p1 must be a successful read");
        };
        assert_eq!(
            Some(obs_state.generation.clone()),
            r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")].generation
        );
    }

    /// A variant whose verification argv renders the per-deployment identity
    /// templates (`{{ deployment_id }}` / `{{ generation }}` / `{{ tree }}`)
    /// so a no-op push's verification can be captured and asserted.
    const VERIFY_IDENTITY_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true", "{{ deployment_id }}", "{{ generation }}", "{{ tree }}"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// A no-op push's verification must render the EXISTING generation's
    /// identities — deployment_id, generation_id, and tree from the running
    /// generation's assignment — never the NEW deployment/generation ids: the
    /// no-op creates no records, so those would be fabricated. The rendered
    /// argv is captured via a recording remote wrapper and asserted to equal
    /// the first push's assignment; the no-op must create no records at all
    /// (no attempt, no transition, no snapshot, `refs/last-successful` and
    /// `observed.json` unchanged).
    #[test]
    fn no_op_verification_renders_existing_generation_identities() {
        let h = RecoveryHarness::with_variant(VERIFY_IDENTITY_VARIANT);
        let executed: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let rf = h.remotes_base.clone();
        let recorded = executed.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(RecordingRemote::new(
                rf.join(s.id.as_str()),
                recorded.clone(),
            )?))
        };

        // Push 1: a real push. Its verification argv renders the NEW
        // deployment's identities (those records ARE created), so it is not
        // the subject here — the no-op's argv is captured separately below.
        let r1 = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let first_attempt = r1.attempt.as_ref().expect("attempt recorded");

        // The EXISTING generation's assignment: what the running service was
        // actually deployed with — the ground truth the no-op must render.
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        let cur = status
            .current_generation
            .expect("first push must leave a current generation");
        let assignment: GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &layout::generations()
                        .join(cur.as_str())
                        .join("assignment.json"),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            assignment.deployment_id, first_attempt.deployment_id,
            "the generation assignment must carry the deployment that created it"
        );
        assert_eq!(
            assignment.generation_id.as_str(),
            cur.as_str(),
            "the assignment must be the current generation's"
        );

        // Push 2: the no-op. Capture ONLY the no-op's verification argv.
        let target_dir = h.store.target_dir("t1");
        let before = snapshot_files(&target_dir);
        executed.lock().unwrap().clear();
        let r2 = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(r2.status, None, "no-op push creates no attempt");
        assert_eq!(r2.message, "Everything up to date");

        let recorded = executed.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "the no-op runs verification exactly once, got: {recorded:?}"
        );
        let argv = &recorded[0];
        // argv = ["true", "<deployment_id>", "<generation>", "<tree>"]
        assert_eq!(argv.len(), 4, "argv: {argv:?}");
        assert_eq!(
            argv[1],
            assignment.deployment_id.as_str(),
            "the no-op verification must render the EXISTING generation's deployment id, not a fabricated one"
        );
        assert_eq!(
            argv[2],
            assignment.generation_id.as_str(),
            "the no-op verification must render the EXISTING generation id, not a fabricated one"
        );
        assert_eq!(
            argv[3],
            assignment.artifact.tree.as_str(),
            "the no-op verification must render the EXISTING generation's tree"
        );
        drop(recorded);

        // The no-op creates NO records: no new attempt, no new transition, no
        // new snapshot, `refs/last-successful` unchanged, observed.json
        // unchanged (the whole per-target store is byte-for-byte identical).
        let after = snapshot_files(&target_dir);
        assert_eq!(
            before, after,
            "the no-op push must not touch any store file (attempts, transitions, observed, refs)"
        );
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no new attempt may be recorded by the no-op"
        );
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "no new snapshot may be appended by the no-op"
        );
        assert_eq!(
            h.store.read_last_successful("t1").unwrap(),
            first_attempt.deployment_id.as_str(),
            "refs/last-successful must be unchanged"
        );
        assert_eq!(
            h.store
                .read_transitions(first_attempt.deployment_id.as_str())
                .unwrap()
                .len(),
            1,
            "no new terminal event may be appended to the first deployment"
        );
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let Observation::Known(obs_state) = &observed.slots[&SlotId::new("p1")].observation else {
            panic!("observed p1 must be a successful read");
        };
        assert_eq!(
            Some(&obs_state.generation),
            Some(&assignment.generation_id),
            "observed.json must be unchanged"
        );
    }

    /// Two variants with IDENTICAL artifact mappings (and identical source
    /// content) -> the SAME tree digest, but DIFFERENT verification
    /// contracts: `standard` runs `["true"]`, `other` runs
    /// `["true", "{{ variant }}"]` so the recording remote proves WHICH
    /// contract actually ran.
    #[test]
    fn variant_switch_same_tree_no_op_comparison() {
        const STD_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
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
        const OTHER_VARIANT_NO_SLOTS: &str = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true", "{{ variant }}"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        const OTHER_VARIANT_WITH_SLOTS: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true", "{{ variant }}"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        const STD_VARIANT_NO_SLOTS: &str = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
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

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), STD_VARIANT).unwrap();
        std::fs::write(release_dir.join("other.toml"), OTHER_VARIANT_NO_SLOTS).unwrap();
        std::fs::write(project.join("deploy.toml"), NONE_TOML).unwrap();
        let artifacts_dir = release_dir.join("artifacts");
        for (p, c) in [
            ("build/output/app/server", "v1\n"),
            ("deployment/common/README", "common\n"),
        ] {
            let fp = artifacts_dir.join(p);
            std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
            std::fs::write(&fp, c).unwrap();
        }

        let cfg_path = project.join("deploy.toml");
        let config = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(config.slot_variant("p1").unwrap(), "standard");
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let executed: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let rf = remotes_base.clone();
        let recorded = executed.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(RecordingRemote::new(
                rf.join(s.id.as_str()),
                recorded.clone(),
            )?))
        };

        // Push 1: slot p1 on variant `standard`. Successful; the verification
        // contract that ran is standard's `["true"]`.
        let r1 = push(
            &cfg_path,
            &store,
            &factory,
            "t1",
            &config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let first_attempt = r1.attempt.as_ref().expect("attempt recorded");
        let first_slot = &first_attempt.slots[&SlotId::new("p1")];
        assert_eq!(known_artifact(first_slot).variant.as_str(), "standard");
        let first_tree = known_artifact(first_slot).tree.clone();
        let first_gen = first_slot.generation.clone().expect("generation minted");
        let argv1 = executed.lock().unwrap().clone();
        assert_eq!(argv1.len(), 1, "push 1 runs verification once: {argv1:?}");
        assert_eq!(
            argv1[0],
            vec!["true".to_string()],
            "push 1 must run the standard contract: {argv1:?}"
        );

        // Switch the slot binding: `standard.toml` loses the slot
        // declaration, `other.toml` gains it (identical server/deploy_dir,
        // IDENTICAL artifact mappings + source content). The SAME slot id now
        // resolves to variant `other` with the SAME tree bytes as `standard`.
        std::fs::write(release_dir.join("standard.toml"), STD_VARIANT_NO_SLOTS).unwrap();
        std::fs::write(release_dir.join("other.toml"), OTHER_VARIANT_WITH_SLOTS).unwrap();
        let config2 = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(config2.slot_variant("p1").unwrap(), "other");

        // Push 2: the variant changed (standard -> other) even though the
        // tree bytes are identical. The up-to-date comparison must compare
        // the COMPLETE ArtifactRef (variant included): this must be a REAL
        // push — a new generation minted, a new attempt recorded, a new
        // snapshot — and verification must run under `other`'s contract
        // (`["true", "{{ variant }}"]` rendering `other`). A tree+release
        // comparison would falsely report "Everything up to date" and leave
        // the service claimed verified under the new contract without ever
        // running it.
        executed.lock().unwrap().clear();
        let r2 = push(
            &cfg_path,
            &store,
            &factory,
            "t1",
            &config2,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_ne!(
            r2.message, "Everything up to date",
            "a variant switch with an identical tree must not no-op"
        );
        assert_eq!(r2.status, Some(DeploymentStatus::Successful));
        let second_attempt = r2.attempt.as_ref().expect("attempt recorded");
        let second_slot = &second_attempt.slots[&SlotId::new("p1")];
        assert_eq!(known_artifact(second_slot).variant.as_str(), "other");
        assert_eq!(
            known_artifact(second_slot).tree,
            first_tree,
            "both variants materialize the SAME tree bytes; only the variant differs"
        );
        let second_gen = second_slot.generation.clone().expect("generation minted");
        assert_ne!(
            second_gen, first_gen,
            "the switch must mint a NEW generation, never reuse the standard one"
        );
        assert_eq!(
            second_attempt.desired[&SlotId::new("p1")]
                .assignment
                .artifact
                .variant
                .as_str(),
            "other",
            "the attempt's desired assignment must carry the other variant"
        );

        // Verification ran under `other`'s contract: the recording remote
        // captured `["true", "{{ variant }}"]` with the variant rendered.
        let argv2 = executed.lock().unwrap().clone();
        assert_eq!(argv2.len(), 1, "push 2 runs verification once: {argv2:?}");
        assert_eq!(
            argv2[0],
            vec!["true".to_string(), "other".to_string()],
            "push 2 must run the OTHER variant's contract with {{ variant }} rendered: {argv2:?}"
        );

        // A REAL push means fresh durable records: a second attempt, a second
        // snapshot, and the remote advanced to the new generation whose stored
        // assignment carries variant `other`.
        assert_eq!(store.read_attempts("t1").unwrap().len(), 2);
        assert_eq!(store.read_snapshots("t1").unwrap().len(), 2);
        let remote = LocalTransport::new(remotes_base.join("s1")).unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        let cur = status
            .current_generation
            .expect("push 2 must advance the remote");
        assert_eq!(cur.as_str(), second_gen.as_str());
        let asn: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &layout::generations()
                        .join(cur.as_str())
                        .join("assignment.json"),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(asn.artifact.variant.as_str(), "other");
        assert_eq!(asn.artifact.tree, first_tree);

        // The reverse stays true: a push with NO change at all still no-ops
        // ("Everything up to date", no new attempt).
        let r3 = push(
            &cfg_path,
            &store,
            &factory,
            "t1",
            &config2,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(r3.status, None, "an unchanged push is a no-op");
        assert_eq!(r3.message, "Everything up to date");
        assert_eq!(
            store.read_attempts("t1").unwrap().len(),
            2,
            "the no-op must not record a third attempt"
        );
    }
}

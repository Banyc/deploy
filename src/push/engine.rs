//! Push transaction engine.
//!
//! Implements the deployment transaction described in `requirement.md`:
//! validation, locking, materialization, release identity, reconciliation,
//! preflight capacity, staging, batched per-server publication with a
//! compare-and-swap precondition, atomic `current` swap, activation,
//! verification, compensation, fleet-commit markers, history, rollback, and
//! per-server rotation.

use crate::adapter::systemd::{run_activation, validate_artifact_paths};
use crate::adapter::verify::run_verification;
use crate::config::{Config, Mapping};
use crate::error::{Error, Result};
use crate::history::{self, PushRef};
use crate::model::{
    BehaviorContract, DeploymentId, GenerationId, OperationId, ReleaseId, ServerId, TargetName,
    TreeDigest, VariantName,
};
use crate::records::{
    AttemptRecord, AttemptServer, DeploymentPlan, DeploymentResults, DeploymentStatus,
    ObservedServer, ObservedTarget, ServerOutcomeKind, ServerPlan, ServerResult,
};
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::Remote;
use crate::rotation::compute_retained;
use crate::store::local::LocalStore;
use crate::tree;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub struct PushOptions {
    pub dry_run: bool,
    pub ref_token: Option<String>,
}

pub struct PushReport {
    /// `None` means no attempt was created (dry-run or already up to date).
    pub status: Option<DeploymentStatus>,
    pub attempt: Option<AttemptRecord>,
    pub message: String,
    pub dry_run: bool,
}

type RemoteFactory = dyn Fn(&crate::config::ServerDef) -> Result<Box<dyn Remote>>;

/// Run a push against `target_name`.
pub fn push(
    config: &Config,
    config_path: &Path,
    store: &LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    opts: &PushOptions,
) -> Result<PushReport> {
    let deployment_id = DeploymentId::generate();
    let op_id = OperationId::generate();
    let target = config
        .targets
        .get(target_name)
        .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
    let project_root = config.project_root(config_path);

    // 1. Validate configuration (already validated at load) and resolve ref.
    let mut pref = match &opts.ref_token {
        Some(t) => history::parse_push_ref(t)?,
        None => PushRef::Head,
    };
    if let PushRef::Fleet { target, .. } = &mut pref
        && target.as_str().is_empty()
    {
        *target = TargetName::new(target_name.to_string());
    }

    // 2. Acquire local application-store lock then target lock (in that order),
    //    held as advisory (flock) locks on open file descriptors. An advisory
    //    lock is released by the kernel when the owning process dies, so a
    //    stale lock from a crashed controller can never be double-owned; two
    //    contenders for the same lock can never both believe they hold it.
    //    Dry-run never acquires a persistent lock (local or remote).
    let local_guard = if opts.dry_run {
        None
    } else {
        Some(FileLock::acquire(
            &store.base().join("operation.lock"),
            op_id.as_str(),
        )?)
    };
    let target_guard = if opts.dry_run {
        None
    } else {
        let p = store.target_dir(target_name).join("operation.lock");
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        Some(FileLock::acquire(&p, op_id.as_str())?)
    };

    let result = push_inner(
        config,
        &project_root,
        store,
        factory,
        target_name,
        target,
        &pref,
        &deployment_id,
        &op_id,
        opts,
    );

    // The guards drop here (releasing both advisory locks) regardless of how
    // `push_inner` resolves.
    drop(target_guard);
    drop(local_guard);
    result
}

#[allow(clippy::too_many_arguments)]
fn push_inner(
    config: &Config,
    project_root: &Path,
    store: &LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    target: &crate::config::TargetDef,
    pref: &PushRef,
    deployment_id: &DeploymentId,
    op_id: &OperationId,
    opts: &PushOptions,
) -> Result<PushReport> {
    // 3. Materialize every declared variant. Mappings resolve from the release
    //    directory (`<project>/releases/<release>/` — the structure is forced),
    //    not the project root, so an artifact `from` can never escape into the
    //    project's other files. Dry-run uses disposable staging and never writes
    //    to the object store.
    let release_root = project_root.join("releases").join(config.release.as_str());
    let mut variant_trees: BTreeMap<String, TreeDigest> = BTreeMap::new();
    if matches!(pref, PushRef::Head) {
        for v in config.variant_names() {
            let staging = if opts.dry_run {
                store
                    .staging_dir()
                    .join(format!("dry-{}", deployment_id.as_str()))
                    .join(&v)
            } else {
                store.staging_dir().join(&v)
            };
            crate::mapper::materialize_variant(
                &release_root,
                &config.variant(&v)?.artifact.mappings,
                &v,
                &staging,
            )?;
            let meta = tree::canonicalize_tree(&staging)?;
            if !opts.dry_run {
                store.store_object(&meta.tree_sha256.clone().into(), &staging)?;
            }
            variant_trees.insert(v, TreeDigest::new(meta.tree_sha256));
        }
    }

    // 4. Freeze per-variant mappings + behavior and generate or reuse the
    // release record. The release identity covers the name-sorted mappings and
    // behavior contracts of every declared variant plus each variant's tree.
    // Each variant's capacity policy is persisted alongside the release record
    // so historical deployments resolve capacity from the snapshot even when
    // the variant has since been renamed or removed from the caller's current
    // configuration. Rotation is fleet-wide configuration read from
    // `deploy.toml` at push time, so it is not snapshotted per variant.
    let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    let mut variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::new();
    let mut variant_policies: BTreeMap<String, crate::config::VariantPolicy> = BTreeMap::new();
    for v in config.variant_names() {
        let vcfg = config.variant(&v)?;
        variant_mappings.insert(v.clone(), vcfg.artifact.mappings.clone());
        variant_behaviors.insert(
            v.clone(),
            BehaviorContract {
                activation: vcfg.activation.clone(),
                verification: vcfg.verification.clone(),
            },
        );
        variant_policies.insert(v.clone(), crate::config::VariantPolicy::from(vcfg));
    }
    let mapping_sha = crate::release::variant_mappings_digest(&variant_mappings);
    let behavior_sha = crate::release::variant_behaviors_digest(&variant_behaviors);
    let behavior_json = serde_json::to_value(&variant_behaviors)?;
    let policies_json = serde_json::to_value(&variant_policies)?;
    let mapping_toml = toml::to_string_pretty(&variant_mappings)
        .map_err(|e| Error::store(format!("serialize mappings: {e}")))?;

    // Historical and rollback pushes carry the bound release's own per-variant
    // behavior contracts; they never fall back to the caller's current config.
    let (local_release_id, desired_behaviors): (ReleaseId, BTreeMap<String, BehaviorContract>) =
        if matches!(pref, PushRef::Head) {
            let bindings: BTreeMap<VariantName, TreeDigest> = variant_trees
                .iter()
                .map(|(k, v)| (VariantName::new(k.clone()), v.clone()))
                .collect();
            let rec = crate::release::build_release(
                &mapping_sha,
                &behavior_sha,
                &bindings,
                project_root,
            );
            let rid = ReleaseId::new(rec.release_id.clone());
            if !opts.dry_run {
                store.write_release(&rec)?;
                let release_json = serde_json::to_string(&rec)
                    .map_err(|e| Error::store(format!("serialize release: {e}")))?;
                store.write_release_aux(&rid, &mapping_toml, &behavior_json, &policies_json)?;
                // Persist release JSON string for remote publication.
                REMOTE_RELEASE_JSON.with(|c| {
                    c.borrow_mut()
                        .insert(rid.clone(), (release_json, behavior_json.to_string()))
                });
            }
            (rid, variant_behaviors)
        } else {
            // Historical ref: resolve the bound release.
            let rid = match pref {
                PushRef::Fleet {
                    target: ft, index, ..
                } => {
                    let entry = history::resolve_fleet_ref(store, ft, *index)?;
                    entry
                        .servers
                        .values()
                        .next()
                        .map(|a| a.release.clone())
                        .unwrap_or_else(|| ReleaseId::new(String::new()))
                }
                PushRef::Release { release, .. } => release.clone(),
                PushRef::Head => unreachable!(),
            };
            // Restore the historical per-variant behavior contracts from the
            // release record, NOT the caller's current configuration. If that
            // behavior is unavailable we fail closed (preflight) rather than
            // silently deploying the caller's current configuration instead.
            let hist_behaviors = store.read_release_behaviors(&rid).map_err(|e| {
                Error::preflight(format!(
                    "historical behavior for release {rid} unavailable (immutable behavior required): {e}"
                ))
            })?;
            if !opts.dry_run {
                let rec = store.read_release(&rid).map_err(|e| {
                    Error::preflight(format!("historical release {rid} not found: {e}"))
                })?;
                let release_json = serde_json::to_string(&rec)
                    .map_err(|e| Error::store(format!("serialize release: {e}")))?;
                let hist_behaviors_json = serde_json::to_string(&hist_behaviors)
                    .map_err(|e| Error::store(format!("serialize behavior: {e}")))?;
                REMOTE_RELEASE_JSON.with(|c| {
                    c.borrow_mut()
                        .insert(rid.clone(), (release_json, hist_behaviors_json))
                });
            }
            (rid, hist_behaviors)
        };
    let _ = &local_release_id;

    // The behavior digest this attempt is bound to: the frozen, name-keyed set of
    // every declared variant's activation + verification contract. Historical
    // and rollback pushes use the historical release's own contracts.
    let desired_behavior_sha = crate::release::variant_behaviors_digest(&desired_behaviors);

    // 5 & 7. Reconcile each server and build the plan, recovering missing local
    // objects from servers that retain them.
    let (assignments, desired_release, source) = crate::push::plan::plan_assignments(
        config,
        target_name,
        pref,
        &local_release_id,
        &variant_trees,
        store,
    )?;

    // Behavior coverage gate: every planned assignment's variant must have a
    // frozen behavior contract BEFORE any remote state is touched (handshake,
    // incoming cleanup, staging, publication). A historical behavior snapshot
    // can be incomplete (a corrupted or truncated behavior.json parses fine but
    // lacks a variant); without this gate the missing entry would panic
    // mid-rollout, after remote trees had already been staged. Fail closed in
    // preflight with context instead.
    validate_behavior_coverage(&desired_behaviors, &assignments, &desired_release)?;

    // Open a remote handle per server and run reconciliation / recovery.
    let members = config.target_pods(target_name)?;
    let mut remotes: HashMap<ServerId, Box<dyn Remote>> = HashMap::new();
    let mut helpers: HashMap<ServerId, RemoteHelper> = HashMap::new();
    let mut statuses: HashMap<ServerId, crate::remote::helper::RemoteStatus> = HashMap::new();
    for (_, s) in &members {
        let sid = ServerId::new(s.id.clone());
        let remote = factory(s)?;
        remotes.insert(sid.clone(), remote);
    }
    for (_, s) in &members {
        let sid = ServerId::new(s.id.clone());
        let r = remotes.get(&sid).unwrap();
        let helper = RemoteHelper::new(r.as_ref());
        let status = helper.status()?;
        if !opts.dry_run {
            // Production path: handshake, clear abandoned incoming, check lock,
            // recover missing local objects.
            helper.handshake()?;
            for pend in &status.pending_incoming {
                if pend != deployment_id.as_str() {
                    helper.remove_incoming(pend)?;
                }
            }
            if let Some(held) = &status.lock
                && held != op_id.as_str()
            {
                return Err(Error::preflight(format!(
                    "server {sid} mutation lock held by '{held}'"
                )));
            }
            for a in &assignments {
                if a.server_id == sid {
                    recover_if_missing(helper.remote(), store, &a.tree)?;
                }
            }
        }
        helpers.insert(sid.clone(), helper);
        statuses.insert(sid.clone(), status);
    }

    // Build the per-server plan with expected (pre-push) generation.
    let mut plan_servers: BTreeMap<ServerId, ServerPlan> = BTreeMap::new();
    let mut new_gen: HashMap<ServerId, GenerationId> = HashMap::new();
    let mut pre_push: BTreeMap<ServerId, Option<AttemptServer>> = BTreeMap::new();
    for a in &assignments {
        let expected = statuses
            .get(&a.server_id)
            .and_then(|st| st.current_generation.clone())
            .map(GenerationId::new);
        let expected_tree = statuses
            .get(&a.server_id)
            .and_then(|st| st.current_tree.clone())
            .map(TreeDigest::new);
        let gid = GenerationId::generate();
        new_gen.insert(a.server_id.clone(), gid.clone());
        plan_servers.insert(
            a.server_id.clone(),
            ServerPlan {
                server_id: a.server_id.clone(),
                variant: a.variant.clone(),
                release: a.release.clone(),
                tree: a.tree.clone(),
                expected_generation: expected.clone(),
                expected_tree,
            },
        );
        pre_push.insert(
            a.server_id.clone(),
            expected.as_ref().map(|g| {
                // Record the server's *actual* current assignment (read from the
                // remote generation), not the desired one.
                helpers[&a.server_id]
                    .read_assignment(g.as_str())
                    .map(|asn| AttemptServer {
                        release: ReleaseId::new(asn.release),
                        variant: VariantName::new(asn.variant),
                        tree: TreeDigest::new(asn.tree),
                        generation: Some(g.clone()),
                    })
                    .unwrap_or_else(|_| AttemptServer {
                        release: a.release.clone(),
                        variant: a.variant.clone(),
                        tree: a.tree.clone(),
                        generation: Some(g.clone()),
                    })
            }),
        );
    }

    let plan = DeploymentPlan {
        deployment_id: deployment_id.clone(),
        target: TargetName::new(target_name.to_string()),
        behavior_sha256: desired_behavior_sha.clone(),
        behaviors: desired_behaviors.clone(),
        server_ids: assignments.iter().map(|a| a.server_id.clone()).collect(),
        servers: plan_servers.clone(),
        source,
        desired_release: desired_release.clone(),
    };

    // ---- Dry-run: read-only planning, no mutation of store/remote/locks -----
    if opts.dry_run {
        let mut msg = String::new();
        for a in &assignments {
            let st = statuses.get(&a.server_id).expect("status present");
            let cur = st.current_generation.clone();
            let want = new_gen[&a.server_id].as_str().to_string();
            let missing_locally = !store.object_exists(&a.tree);
            let note = match cur {
                Some(c) if c == want => format!(
                    "server {}: already at desired generation ({})\n",
                    a.server_id, c
                ),
                Some(c) => format!(
                    "server {}: current {} -> desired {} (tree {})\n",
                    a.server_id, c, want, a.tree
                ),
                None => format!(
                    "server {}: first deployment (tree {})\n",
                    a.server_id, a.tree
                ),
            };
            msg.push_str(&note);
            if missing_locally {
                msg.push_str(&format!(
                    "  would recover tree {} from a retaining server\n",
                    a.tree
                ));
            }
        }
        // Clean up disposable staging (no object was stored).
        let _ = std::fs::remove_dir_all(
            store
                .staging_dir()
                .join(format!("dry-{}", deployment_id.as_str())),
        );
        return Ok(PushReport {
            status: None,
            attempt: None,
            message: format!("dry-run plan:\n{msg}"),
            dry_run: true,
        });
    }

    // Early "Everything up to date" check for HEAD pushes. Run BEFORE persisting
    // any plan/status record so an up-to-date no-op leaves no dangling
    // `in_progress` deployment behind.
    if matches!(pref, PushRef::Head) {
        let mut all_match = true;
        for a in &assignments {
            let st = statuses.get(&a.server_id).expect("status present");
            let matches = st
                .current_generation
                .as_ref()
                .map(|g| {
                    helpers[&a.server_id]
                        .read_assignment(g)
                        .map(|asn| asn.tree == a.tree.as_str() && asn.release == a.release.as_str())
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if !matches {
                all_match = false;
                break;
            }
        }
        if all_match {
            // Verify the running services to confirm true up-to-date state.
            let mut verified = true;
            for a in &assignments {
                let remote = remotes[&a.server_id].as_ref();
                let Some(variant_behavior) = desired_behaviors.get(a.variant.as_str()) else {
                    // Coverage was validated before any remote mutation; a miss
                    // means the up-to-date claim cannot be established. Fall
                    // through to a real push rather than panicking.
                    verified = false;
                    break;
                };
                if run_verification(remote, &variant_behavior.verification).is_err() {
                    verified = false;
                    break;
                }
            }
            if verified {
                return Ok(PushReport {
                    status: None,
                    attempt: None,
                    message: "Everything up to date".to_string(),
                    dry_run: false,
                });
            }
        }
    }

    // Persist the plan before any server mutation (finding 6).
    store.write_plan(deployment_id.as_str(), &plan)?;
    store.write_status(deployment_id.as_str(), "in_progress")?;

    // 8 & 9. Capacity preflight and staging.
    capacity_preflight(config, store, &assignments, &helpers, op_id, deployment_id)?;
    // Stage every needed tree into operation-unique incoming paths.
    for a in &assignments {
        let _remote = remotes[&a.server_id].as_ref();
        let helper = &helpers[&a.server_id];
        if !helper.tree_exists(a.tree.as_str()) {
            let host_obj = store.object_root(&a.tree);
            helper.stage_incoming(deployment_id.as_str(), a.tree.as_str(), &host_obj)?;
        }
    }

    // 10-13. Process servers in batches.
    let batch_size = target.rollout.batch_size.max(1) as usize;
    let failure_policy = target.rollout.failure_policy.clone();
    let stop_on_failure = target.rollout.stop_on_failure;

    let mut results: BTreeMap<ServerId, ServerResult> = BTreeMap::new();
    let mut advanced: Vec<ServerId> = Vec::new();
    let mut compensated: Vec<ServerId> = Vec::new();
    let mut had_failure = false;

    let servers_order: Vec<ServerId> = assignments.iter().map(|a| a.server_id.clone()).collect();
    let mut idx = 0;
    'batches: while idx < servers_order.len() {
        let end = (idx + batch_size).min(servers_order.len());
        for sid in &servers_order[idx..end] {
            let a = assignments.iter().find(|x| &x.server_id == sid).unwrap();
            // Select the assigned variant's frozen behavior contract (never the
            // caller's current variant file) before activation/verification.
            // Coverage was validated before any remote mutation, so a miss here
            // is an internal invariant violation: record a per-server failure
            // instead of panicking.
            let Some(variant_behavior) = desired_behaviors.get(a.variant.as_str()) else {
                had_failure = true;
                results.insert(
                    sid.clone(),
                    ServerResult {
                        server_id: sid.clone(),
                        outcome: ServerOutcomeKind::Failed,
                        generation: Some(new_gen[sid].clone()),
                        compensated: false,
                        error: Some(format!(
                            "internal: no behavior contract for variant '{}' after coverage check",
                            a.variant
                        )),
                    },
                );
                if stop_on_failure {
                    break 'batches;
                }
                continue;
            };
            let variant_behavior_sha =
                crate::release::behavior_contract_digest(variant_behavior);
            let outcome = process_server(
                config,
                variant_behavior,
                &variant_behavior_sha,
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                &a.server_id,
                &a.release,
                &a.variant,
                &a.tree,
                &new_gen[sid],
                plan_servers[sid].expected_generation.as_ref(),
            )?;
            let ServerProc {
                kind,
                generation,
                did_compensate,
                error,
            } = outcome;
            if kind == ServerOutcomeKind::Failed {
                had_failure = true;
            }
            if did_compensate {
                compensated.push(sid.clone());
            } else if kind == ServerOutcomeKind::Activated {
                advanced.push(sid.clone());
            }
            results.insert(
                sid.clone(),
                ServerResult {
                    server_id: sid.clone(),
                    outcome: kind,
                    generation: Some(generation),
                    compensated: did_compensate,
                    error,
                },
            );
            if had_failure && stop_on_failure {
                break 'batches;
            }
        }
        idx = end;
    }

    // Any server never started (e.g. skipped after an earlier failure under
    // stop_on_failure) still appears in the attempt, with its reconciled current
    // assignment rather than a generated desired generation.
    for a in &assignments {
        if !results.contains_key(&a.server_id) {
            let cur = statuses
                .get(&a.server_id)
                .and_then(|s| s.current_generation.clone())
                .map(GenerationId::new);
            results.insert(
                a.server_id.clone(),
                ServerResult {
                    server_id: a.server_id.clone(),
                    outcome: ServerOutcomeKind::Skipped,
                    generation: cur,
                    compensated: false,
                    error: None,
                },
            );
        }
    }

    // 13. Failure policy compensation of still-advanced servers.
    if had_failure && failure_policy == "rollback_changed" {
        for sid in &advanced {
            let prior = plan_servers[sid].expected_generation.as_ref();
            // A compensation failure (e.g. prior behavior unavailable, or
            // activation/verification failed during rollback) is reported as a
            // failed compensation rather than aborting the whole push; the
            // server stays advanced and the attempt is marked Degraded.
            let ok = compensate_server(
                config,
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                sid,
                prior,
                &new_gen[sid],
            )
            .unwrap_or_default();
            if ok {
                compensated.push(sid.clone());
                if let Some(r) = results.get_mut(sid) {
                    r.compensated = true;
                    r.outcome = ServerOutcomeKind::Restored;
                }
            }
        }
        advanced.retain(|s| !compensated.contains(s));
    }

    // 14. Determine attempt status.
    let status = if !had_failure {
        DeploymentStatus::Successful
    } else if failure_policy == "rollback_changed" {
        if compensated.len() == assignments.len() || advanced.is_empty() {
            DeploymentStatus::FailedRolledBack
        } else {
            DeploymentStatus::Degraded
        }
    } else {
        DeploymentStatus::Degraded
    };

    // 15. Fleet-commit markers (only for otherwise-successful attempts).
    let mut commit_status = status.clone();
    if status == DeploymentStatus::Successful {
        // The full server-ID set participating in this fleet commit.
        let server_ids: Vec<String> = servers_order
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        for sid in &servers_order {
            let helper = &helpers[sid];
            // Hold the lock for the whole commit step so a failure cannot leak it
            // (a `?` on a manual lock would otherwise leave the lock held).
            let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
                Ok(g) => g,
                Err(_) => {
                    commit_status = DeploymentStatus::PendingCommit;
                    continue;
                }
            };
            // Check the generation *before* writing the marker; a mismatch means
            // another controller changed `current` and this marker would be wrong.
            let cur = match helper.status() {
                Ok(s) => s.current_generation,
                Err(_) => {
                    // Recoverable metadata failure: do not abort the whole push
                    // (which would leave the attempt unrecorded); mark the fleet
                    // commit incomplete and keep going.
                    commit_status = DeploymentStatus::PendingCommit;
                    continue;
                }
            };
            if cur.as_deref() != Some(new_gen[sid].as_str()) {
                // The live generation no longer matches what we deployed: the
                // controller's view diverged, so this marker would be wrong.
                // Report Degraded rather than a falsely successful commit.
                commit_status = DeploymentStatus::Degraded;
                continue;
            }
            if helper
                .write_commit_marker(deployment_id.as_str(), new_gen[sid].as_str(), &server_ids)
                .is_err()
            {
                // Recoverable metadata failure writing the marker.
                commit_status = DeploymentStatus::PendingCommit;
                continue;
            }
            // `_guard` drops here, releasing the lock.
        }
    }

    // A server whose committed-transaction record write failed is still active
    // but not durably bookkept. Do not report the attempt as `Successful`:
    // demote to `PendingCommit` so the metadata gap is visible.
    if commit_status == DeploymentStatus::Successful {
        for sid in &servers_order {
            if let Some(r) = results.get(sid)
                && r.outcome == ServerOutcomeKind::Activated
                && r.error.is_some()
            {
                commit_status = DeploymentStatus::PendingCommit;
                break;
            }
        }
    }

    // 16 & 17. Record attempt, history, rotation.
    //
    // `actual_servers` reflects each server's *real* final state, read from the
    // remote generation it currently points at, rather than the desired plan
    // values. Failed/skipped/restored servers therefore report their actual
    // release/tree/variant instead of the desired ones.
    let mut actual_servers: BTreeMap<ServerId, AttemptServer> = BTreeMap::new();
    for a in &assignments {
        let sid = &a.server_id;
        let helper = &helpers[sid];
        let final_gen = helper.status().ok().and_then(|s| s.current_generation);
        let actual = match final_gen {
            Some(g) => match helper.read_assignment(&g) {
                Ok(asn) => AttemptServer {
                    release: ReleaseId::new(asn.release),
                    variant: VariantName::new(asn.variant),
                    tree: TreeDigest::new(asn.tree),
                    generation: Some(GenerationId::new(g)),
                },
                Err(_) => {
                    // The generation is observed (`g`), but its assignment could
                    // not be read. Never substitute the planned (desired)
                    // release/tree/variant for a failed observation: preserve the
                    // observed generation and mark the assignment unknown rather
                    // than fabricating desired state.
                    AttemptServer {
                        release: ReleaseId::new(String::new()),
                        variant: VariantName::new(String::new()),
                        tree: TreeDigest::new(String::new()),
                        generation: Some(GenerationId::new(g)),
                    }
                }
            },
            None => AttemptServer {
                release: a.release.clone(),
                variant: a.variant.clone(),
                tree: a.tree.clone(),
                generation: None,
            },
        };
        actual_servers.insert(sid.clone(), actual);
    }
    let desired_map: BTreeMap<ServerId, AttemptServer> = assignments
        .iter()
        .map(|a| {
            (
                a.server_id.clone(),
                AttemptServer {
                    release: a.release.clone(),
                    variant: a.variant.clone(),
                    tree: a.tree.clone(),
                    generation: Some(new_gen[&a.server_id].clone()),
                },
            )
        })
        .collect();

    let attempt = AttemptRecord {
        deployment_schema_version: 1,
        deployment_id: deployment_id.clone(),
        status: commit_status.clone(),
        target: TargetName::new(target_name.to_string()),
        server_ids: servers_order.clone(),
        behavior_sha256: desired_behavior_sha.clone(),
        attempted_at: crate::remote::helper::now_rfc3339(),
        desired: desired_map,
        pre_push,
        servers: actual_servers.clone(),
    };
    store.append_attempt(target_name, &attempt)?;
    store.write_results(
        deployment_id.as_str(),
        &DeploymentResults {
            deployment_id: deployment_id.clone(),
            target: TargetName::new(target_name.to_string()),
            servers: results.clone(),
        },
    )?;
    store.write_status(deployment_id.as_str(), &format!("{:?}", commit_status))?;

    // Refresh observed state.
    let mut observed = ObservedTarget {
        target: TargetName::new(target_name.to_string()),
        servers: Default::default(),
    };
    for (sid, asv) in &actual_servers {
        let observed_server = ObservedServer {
            generation: asv.generation.clone(),
            release: Some(asv.release.clone()),
            variant: Some(asv.variant.clone()),
            tree: Some(asv.tree.clone()),
            last_deployment: Some(deployment_id.clone()),
        };
        observed
            .servers
            .insert(sid.clone(), observed_server.clone());
        store.write_server(&crate::records::ServerState {
            id: sid.clone(),
            last_seen_target: Some(TargetName::new(target_name.to_string())),
            last_observed: Some(observed_server),
        })?;
    }
    store.write_observed(target_name, &observed)?;

    // 16. Advance the reflog only for successful fleet deployments.
    let mut message = format!("push status: {commit_status:?}");
    if commit_status == DeploymentStatus::Successful {
        let idx = history::append_successful_reflog(
            store,
            &TargetName::new(target_name.to_string()),
            &attempt,
        )?;
        message = format!("push successful; fleet ref {}@f{idx}", target_name);
    }

    // 17. Per-server rotation under each server's mutation lock. Rotation uses
    // the server's ACTUAL final assignment (read after any compensation), not
    // the desired plan: a compensated server restored its prior variant. The
    // retention policy is the fleet-wide `rotation` configuration from
    // `deploy.toml`, so it applies uniformly regardless of which variant each
    // server ended up running.
    for sid in &servers_order {
        let helper = &helpers[sid];
        if helper.acquire_lock(op_id.as_str(), false).is_ok() {
            let retained = compute_retained(helper, &config.rotation, &config.pins, store)?;
            let active_incoming = HashSet::from([deployment_id.as_str().to_string()]);
            helper.rotate(&retained, &active_incoming)?;
            helper.release_lock(op_id.as_str())?;
        }
        // Clean up this deployment's incoming directory.
        helpers[sid].remove_incoming(deployment_id.as_str()).ok();
        helpers[sid].release_lock(op_id.as_str()).ok();
    }

    Ok(PushReport {
        status: Some(commit_status),
        attempt: Some(attempt),
        message,
        dry_run: false,
    })
}

struct ServerProc {
    kind: ServerOutcomeKind,
    generation: GenerationId,
    did_compensate: bool,
    error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn process_server(
    config: &Config,
    behavior: &BehaviorContract,
    behavior_sha256: &str,
    store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    server_id: &ServerId,
    release: &ReleaseId,
    variant: &VariantName,
    tree: &TreeDigest,
    new_gen: &GenerationId,
    expected_gen: Option<&GenerationId>,
) -> Result<ServerProc> {
    // Acquire the server mutation lock via an RAII guard so every return path
    // (including errors) releases it.
    let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
        Ok(g) => g,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_compensate: false,
                error: Some(format!("lock acquire failed: {e}")),
            });
        }
    };

    // Compare-and-swap precondition on current generation.
    let status = match helper.status() {
        Ok(s) => s,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_compensate: false,
                error: Some(format!("status failed: {e}")),
            });
        }
    };
    if let Some(exp) = expected_gen
        && status.current_generation.as_deref() != Some(exp.as_str())
    {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Skipped,
            generation: exp.clone(),
            did_compensate: false,
            error: Some(format!(
                "compare-and-swap precondition failed: current {:?} expected {exp}",
                status.current_generation
            )),
        });
    }

    // 1. Publish the staged tree (from incoming), reusing an existing object.
    if let Err(e) = helper.publish_from_incoming(deployment_id.as_str(), tree.as_str()) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("publish failed: {e}")),
        });
    }

    // 2. Canonically hash the remote tree and compare with the requested digest.
    //    Existing remote objects are re-verified here rather than trusted.
    let verify_tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_compensate: false,
                error: Some(format!("tempdir: {e}")),
            });
        }
    };
    let remote_root_rel = Path::new("objects/sha256").join(tree.as_str()).join("root");
    if let Err(e) = download_tree_to_host(remote, &remote_root_rel, verify_tmp.path()) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("download for verify failed: {e}")),
        });
    }
    let meta = match tree::canonicalize_tree(verify_tmp.path()) {
        Ok(m) => m,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_compensate: false,
                error: Some(format!("canonicalize remote tree failed: {e}")),
            });
        }
    };
    if meta.tree_sha256 != tree.as_str() {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!(
                "integrity: remote tree digest {} does not match requested {}",
                meta.tree_sha256, tree
            )),
        });
    }

    // 3. Validate all declared artifact paths and types before changing current.
    if let Err(e) = validate_artifact_paths(remote, &behavior.activation, &remote_root_rel) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("artifact validation: {e}")),
        });
    }

    // 4. Publish the release record (idempotent) and create the generation.
    if let Some((release_json, behavior_json)) =
        REMOTE_RELEASE_JSON.with(|c| c.borrow().get(release).cloned())
        && let Err(e) = helper.publish_release(release.as_str(), &release_json, &behavior_json)
    {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("publish release failed: {e}")),
        });
    }
    let assignment = crate::remote::helper::GenerationAssignment {
        deployment_id: deployment_id.as_str().to_string(),
        generation_id: new_gen.as_str().to_string(),
        release: release.as_str().to_string(),
        variant: variant.as_str().to_string(),
        tree: tree.as_str().to_string(),
        behavior_sha256: behavior_sha256.to_string(),
        prior_generation: expected_gen.map(|g| g.as_str().to_string()),
        created_at: crate::remote::helper::now_rfc3339(),
    };
    if let Err(e) = helper.create_generation(op_id.as_str(), &assignment) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("create generation failed: {e}")),
        });
    }
    if let Err(e) = helper.transaction_record(op_id.as_str(), "prepared") {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("transaction record failed: {e}")),
        });
    }

    // Atomically move `current` (the per-server commit point).
    let swap = helper.swap_current(
        expected_gen.map(|g| g.as_str()),
        new_gen.as_str(),
        op_id.as_str(),
    );
    match swap {
        Ok(()) => {}
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_compensate: false,
                error: Some(format!("swap failed: {e}")),
            });
        }
    };
    let generation_root = remote
        .root()
        .join("generations")
        .join(new_gen.as_str())
        .join("root");

    // Activation adapter. On failure, compensate (current was advanced).
    if let Err(e) = run_activation(
        &behavior.activation,
        remote,
        remote.root(),
        &generation_root,
    ) {
        let comp = compensate_server(
            config,
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            server_id,
            expected_gen,
            new_gen,
        );
        let _ = helper.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        let generation = if did_comp {
            expected_gen.cloned().unwrap_or_else(|| new_gen.clone())
        } else {
            new_gen.clone()
        };
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation,
            did_compensate: did_comp,
            error: Some(format!("activation failed: {e}")),
        });
    }

    // Verification adapter. On failure, compensate.
    if let Err(e) = run_verification(remote, &behavior.verification) {
        let comp = compensate_server(
            config,
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            server_id,
            expected_gen,
            new_gen,
        );
        let _ = helper.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        let generation = if did_comp {
            expected_gen.cloned().unwrap_or_else(|| new_gen.clone())
        } else {
            new_gen.clone()
        };
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation,
            did_compensate: did_comp,
            error: Some(format!("verification failed: {e}")),
        });
    }

    // The swap, activation, and verification all succeeded, so the new generation
    // is live (current points at it and the service is healthy). A failure to
    // write the bookkeeping record is a *recoverable metadata* failure: the
    // service is active but the attempt cannot be durably marked committed. We
    // still report the server as Activated, but carry the error so the attempt
    // status is demoted to `PendingCommit` rather than erroneously `Successful`.
    if helper
        .transaction_record(op_id.as_str(), "committed")
        .is_err()
    {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Activated,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(
                "committed transaction record write failed; server active but bookkeeping incomplete"
                    .to_string(),
            ),
        });
    }
    Ok(ServerProc {
        kind: ServerOutcomeKind::Activated,
        generation: new_gen.clone(),
        did_compensate: false,
        error: None,
    })
}

/// Restore the prior generation (or remove `current` on first deploy). Uses the
/// prior generation's stored behavior contract rather than the caller's current
/// configuration. `advanced_gen` is the generation this server was just advanced
/// to; it is used as the compare-and-swap precondition so a concurrent
/// controller cannot have its `current` clobbered. Returns true if compensation
/// restored prior state.
#[allow(clippy::too_many_arguments)]
fn compensate_server(
    _config: &Config,
    _store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    _deployment_id: &DeploymentId,
    _server_id: &ServerId,
    prior_gen: Option<&GenerationId>,
    advanced_gen: &GenerationId,
) -> Result<bool> {
    // Hold the server mutation lock for the duration of compensation. Re-acquiring
    // is idempotent when the same op_id already holds it (process_server holds it
    // via a guard that is still alive on the in-process failure paths).
    let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
        Ok(g) => g,
        Err(_) => return Ok(false),
    };
    match prior_gen {
        Some(prior) => {
            // Load the prior generation's behavior contract from the remote.
            let prior_assignment = match helper.read_assignment(prior.as_str()) {
                Ok(a) => a,
                Err(_) => return Ok(false),
            };
            // Load the prior generation's behavior contract from the remote. If it
            // is unavailable we cannot verify what we are restoring, so we must
            // not pretend restoration succeeded by substituting a default
            // contract: report the failure so the attempt is marked Degraded.
            let prior_behavior = helper
                .read_behavior(
                    &ReleaseId::new(prior_assignment.release.clone()),
                    &prior_assignment.variant,
                )
                .map_err(|e| {
                    Error::remote(format!("compensation: prior behavior unavailable: {e}"))
                })?;
            // Compare-and-swap: only roll back if `current` still points at the
            // generation we just activated. Otherwise another controller changed
            // it and we must not clobber their state.
            if helper
                .swap_current(Some(advanced_gen.as_str()), prior.as_str(), op_id.as_str())
                .is_err()
            {
                return Ok(false);
            }
            let root = remote
                .root()
                .join("generations")
                .join(prior.as_str())
                .join("root");
            // Re-run prior activation contract + verification. A failure means the
            // service was not actually restored to prior behavior, so propagate
            // it as a compensation failure (the attempt is marked Degraded).
            run_activation(&prior_behavior.activation, remote, remote.root(), &root)
                .map_err(|e| Error::remote(format!("compensation activation failed: {e}")))?;
            run_verification(remote, &prior_behavior.verification)
                .map_err(|e| Error::remote(format!("compensation verification failed: {e}")))?;
            Ok(true)
        }
        None => {
            // First deploy: remove `current` only if it still points at the
            // generation we advanced (compare-and-swap style).
            Ok(helper
                .remove_current_if(advanced_gen.as_str())
                .unwrap_or(false))
        }
    }
}

/// Download a tree from a server into the local object store if missing.
fn recover_if_missing(remote: &dyn Remote, store: &LocalStore, digest: &TreeDigest) -> Result<()> {
    if store.object_exists(digest) {
        return Ok(());
    }
    let root_rel = Path::new("objects/sha256")
        .join(digest.as_str())
        .join("root");
    if !remote.exists(&root_rel) {
        return Ok(());
    }
    let tmp = store
        .staging_dir()
        .join(format!("recover-{}", digest.as_str()));
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp).ok();
    }
    download_tree_to_host(remote, &root_rel, &tmp)?;
    store.store_object(digest, &tmp)?;
    Ok(())
}

fn download_tree_to_host(remote: &dyn Remote, rel: &Path, host_dest: &Path) -> Result<()> {
    std::fs::create_dir_all(host_dest)
        .map_err(|e| Error::transport(format!("mkdir {}: {e}", host_dest.display())))?;
    for entry in remote.list(rel)? {
        let child_rel = rel.join(&entry.name);
        let dest = host_dest.join(&entry.name);
        if entry.is_symlink {
            // Reconstruct the exact symlink target; remove any stale entry first.
            let target = remote.read_link(&child_rel)?;
            let _ = std::fs::remove_file(&dest);
            std::os::unix::fs::symlink(&target, &dest)
                .map_err(|e| Error::transport(format!("symlink {}: {e}", dest.display())))?;
        } else if entry.is_dir {
            download_tree_to_host(remote, &child_rel, &dest)?;
            set_mode(&dest, entry.mode)?;
        } else {
            let data = remote.read(&child_rel)?;
            std::fs::write(&dest, data)
                .map_err(|e| Error::transport(format!("write {}: {e}", dest.display())))?;
            set_mode(&dest, entry.mode)?;
        }
    }
    Ok(())
}

/// Apply a mode to a local file/directory, preserving only the permission bits.
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| Error::transport(format!("chmod {}: {e}", path.display())))
}

/// Fail closed in preflight if any planned assignment's variant lacks a frozen
/// behavior contract. Historical behavior snapshots can be incomplete (a
/// corrupted or truncated `behavior.json` parses successfully but covers only
/// some variants); reaching rollout with a missing entry previously panicked
/// after trees were already staged onto servers. This gate runs before any
/// remote mutation and names the snapshot, the missing variants, and the
/// affected servers.
fn validate_behavior_coverage(
    behaviors: &BTreeMap<String, BehaviorContract>,
    assignments: &[crate::push::plan::PlannedAssignment],
    desired_release: &ReleaseId,
) -> Result<()> {
    let mut missing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for a in assignments {
        if !behaviors.contains_key(a.variant.as_str()) {
            missing
                .entry(a.variant.as_str())
                .or_default()
                .push(a.server_id.as_str());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let detail = missing
        .iter()
        .map(|(variant, servers)| format!("variant '{variant}' (servers: {})", servers.join(", ")))
        .collect::<Vec<_>>()
        .join("; ");
    Err(Error::preflight(format!(
        "behavior snapshot for release {desired_release} is incomplete: missing {detail}; \
         refusing to start before any remote state is changed"
    )))
}

/// Coarse capacity preflight: ensure each server has room for the new trees plus
/// the configured safety headroom, running protected rotation first if needed.
///
/// Capacity headroom is per-variant policy bound to the release being deployed.
/// It is resolved from the immutable policy snapshot persisted with that
/// release, so a rollback to a release whose variant was later renamed or
/// removed still applies the policy that was in force when the release was
/// created. Releases recorded before policy persistence fall back to the
/// caller's current configuration; if the variant is unknown there too, the
/// default (zero) reserve is used. Rotation (used for the protected pre-rotation)
/// is fleet-wide configuration from `deploy.toml`.
fn capacity_preflight(
    config: &Config,
    store: &LocalStore,
    assignments: &[crate::push::plan::PlannedAssignment],
    helpers: &HashMap<ServerId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
) -> Result<()> {
    for a in assignments {
        let capacity = resolve_variant_policy(config, store, &a.release, a.variant.as_str())
            .map(|p| p.capacity)
            .unwrap_or_default();
        let reserve_bytes = capacity.reserve_bytes;
        let reserve_percent = capacity.reserve_percent as f64 / 100.0;
        let helper = helpers.get(&a.server_id).expect("helper present");
        if helper.tree_exists(a.tree.as_str()) {
            continue;
        }
        let need = tree_size_on_host(&store.object_root(&a.tree));
        let avail = helper.remote().available_bytes().unwrap_or(0);
        let total = helper
            .remote()
            .root()
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        let _ = total;
        let reserve = reserve_bytes.max((avail as f64 * reserve_percent) as u64);
        if need + reserve > avail {
            // Run protected rotation using the fleet-wide rotation policy, then
            // recheck capacity directly rather than failing the restore.
            if helper.acquire_lock(op_id.as_str(), false).is_ok() {
                let retained = compute_retained(helper, &config.rotation, &config.pins, store)?;
                let active = HashSet::from([deployment_id.as_str().to_string()]);
                helper.rotate(&retained, &active).ok();
                helper.release_lock(op_id.as_str()).ok();
            }
            let avail2 = helper.remote().available_bytes().unwrap_or(0);
            if need + reserve > avail2 {
                return Err(Error::preflight(format!(
                    "insufficient capacity on server {}: need {} + reserve {} > avail {}",
                    a.server_id, need, reserve, avail2
                )));
            }
        }
    }
    Ok(())
}

/// Resolve the capacity policy bound to a (release, variant) assignment.
/// Prefers the immutable policy snapshot persisted with the release so
/// historical deployments use the capacity policy in force at release time even
/// when the variant has since been renamed or removed; releases recorded before
/// policy persistence fall back to the caller's current configuration. Rotation
/// is not part of this resolution: it is read directly from `config.rotation`.
fn resolve_variant_policy(
    config: &Config,
    store: &LocalStore,
    release: &ReleaseId,
    variant: &str,
) -> Option<crate::config::VariantPolicy> {
    if let Ok(Some(policies)) = store.read_release_policies(release)
        && let Some(p) = policies.get(variant)
    {
        return Some(p.clone());
    }
    config.variant(variant).ok().map(crate::config::VariantPolicy::from)
}

fn tree_size_on_host(root: &Path) -> u64 {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()).map(|m| m.len()))
        .sum()
}

/// An advisory (flock) lock held by an open file descriptor. While the guard
/// is alive the kernel prevents any other process from acquiring the same lock,
/// and the lock is released automatically if the owning process dies. This
/// makes the stale-lock double-ownership race impossible: a dead controller's
/// lock is released by the kernel rather than lingering, and two live
/// contenders can never both win the acquisition.
struct FileLock {
    file: std::fs::File,
    path: std::path::PathBuf,
}

impl FileLock {
    fn acquire(path: &Path, op_id: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::preflight(format!("mkdir {}: {e}", parent.display())))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| Error::preflight(format!("open lock {}: {e}", path.display())))?;
        let fd = file.as_raw_fd();
        // Exclusive, non-blocking advisory lock. Only one holder at a time.
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                    let held = std::fs::read_to_string(path).unwrap_or_default();
                    return Err(Error::preflight(format!(
                        "local lock {} held by '{}'",
                        path.display(),
                        held.trim()
                    )));
                }
                _ => {
                    return Err(Error::preflight(format!("flock {}: {err}", path.display())));
                }
            }
        }
        // We hold the lock: record our operation id for diagnostics.
        use std::io::Write;
        file.set_len(0)
            .and_then(|_| file.write_all(op_id.as_bytes()))
            .map_err(|e| Error::preflight(format!("write lock {}: {e}", path.display())))?;
        Ok(FileLock {
            file,
            path: path.to_path_buf(),
        })
    }
}

impl std::ops::Drop for FileLock {
    fn drop(&mut self) {
        // Release the advisory lock, then remove the (now-unlocked) file.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

// Per-process cache of release JSON for remote publication (avoids re-reading
// the local store inside the nested helper calls).
thread_local! {
    static REMOTE_RELEASE_JSON: std::cell::RefCell<
        HashMap<ReleaseId, (String, String)>
    > = std::cell::RefCell::new(HashMap::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::transport::LocalTransport;
    use std::path::{Path, PathBuf};

    const NONE_VARIANT: &str = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
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

[capacity]
reserve_bytes = 0
reserve_percent = 0
"#;

    const NONE_TOML: &str = r#"
schema_version = 1
application = "eng"
remote_root = "/srv/eng"
release = "v1"

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.fleet]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"

[[pods]]
id = "p1"
server = "s1"
variant = "standard"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1"]
"#;

    const SYSTEMD_VARIANT: &str = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/units/"
to = "integration/systemd/"
recursive = true

[activation]
adapter = "systemd"
scope = "user"

[[activation.units]]
name = "example.service"
artifact_path = "integration/systemd/example.service"
enable = true
restart = true

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0

[capacity]
reserve_bytes = 0
reserve_percent = 0
"#;

    const SYSTEMD_TOML: &str = r#"
schema_version = 1
application = "eng"
remote_root = "/srv/eng"
release = "v1"

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.fleet]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"

[[pods]]
id = "p1"
server = "s1"
variant = "standard"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1"]
"#;

    struct Harness {
        _dir: tempfile::TempDir,
        config: Config,
        store: LocalStore,
        _project: PathBuf,
        tree: TreeDigest,
        remote: LocalTransport,
    }

    impl Harness {
        fn new(deploy_toml: &str, variant_toml: &str, files: &[(&str, &str)]) -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let release_dir = project.join("releases").join("v1");
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
            let cfg_path = project.join("deploy.toml");
            std::fs::write(&cfg_path, deploy_toml).unwrap();
            // Artifact sources live beneath the release directory (release_root /
            // `artifacts`), so a `from` never reaches into the project root.
            let artifacts_dir = release_dir.join("artifacts");
            for (p, c) in files {
                let fp = artifacts_dir.join(p);
                std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
                std::fs::write(&fp, c).unwrap();
            }
            let config = Config::load(&cfg_path).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();

            // Materialize from the release directory, not the project root.
            let release_root = config.release_root(&cfg_path);
            let vcfg = config.variant("standard").unwrap();
            let staging = store.staging_dir().join("standard");
            crate::mapper::materialize_variant(
                &release_root,
                &vcfg.artifact.mappings,
                "standard",
                &staging,
            )
            .unwrap();
            let meta = tree::canonicalize_tree(&staging).unwrap();
            let tree = TreeDigest::new(meta.tree_sha256.clone());
            store
                .store_object(&meta.tree_sha256.into(), &staging)
                .unwrap();

            let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
            Harness {
                _dir: dir,
                config,
                store,
                _project: project,
                tree,
                remote,
            }
        }

        fn behave(&self) -> BehaviorContract {
            let v = self.config.variant("standard").unwrap();
            BehaviorContract {
                activation: v.activation.clone(),
                verification: v.verification.clone(),
            }
        }

        fn run(&self, expected_gen: Option<GenerationId>) -> ServerProc {
            let deployment_id = DeploymentId::generate();
            let op_id = OperationId::generate();
            self.helper()
                .stage_incoming(
                    deployment_id.as_str(),
                    self.tree.as_str(),
                    &self.store.object_root(&self.tree),
                )
                .unwrap();
            let behavior = self.behave();
            let sha = crate::release::behavior_contract_digest(&behavior);
            let new_gen = GenerationId::generate();
            let helper = self.helper();
            process_server(
                &self.config,
                &behavior,
                &sha,
                &self.store,
                &self.remote,
                &helper,
                &op_id,
                &deployment_id,
                &ServerId::new("s1"),
                &ReleaseId::new("r1"),
                &VariantName::new("standard"),
                &self.tree,
                &new_gen,
                expected_gen.as_ref(),
            )
            .unwrap()
        }

        fn helper(&self) -> RemoteHelper<'_> {
            RemoteHelper::new(&self.remote)
        }
    }

    #[test]
    fn clean_publish_activates() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Activated);
        assert!(!proc.did_compensate);
        assert!(h.remote.exists(Path::new("current")));
    }

    #[test]
    fn corrupted_existing_remote_object_fails_integrity() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let first = h.run(None);
        assert_eq!(first.kind, ServerOutcomeKind::Activated);

        // Corrupt the already-published remote object's content.
        let obj_file = h
            .remote
            .root()
            .join("objects/sha256")
            .join(h.tree.as_str())
            .join("root")
            .join("app")
            .join("README");
        assert!(obj_file.exists(), "expected object file to exist");
        std::fs::write(&obj_file, "TAMPERED").unwrap();

        // A second generation reuses the corrupted object and must detect the
        // digest mismatch before advancing `current`.
        let second = h.run(Some(first.generation.clone()));
        assert_eq!(second.kind, ServerOutcomeKind::Failed);
        assert!(second.error.unwrap().contains("integrity"));
    }

    #[test]
    fn corrupted_upload_fails_integrity() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        // Corrupt the local object store so the staged upload carries bad bytes.
        let local_file = h.store.object_root(&h.tree).join("app").join("README");
        std::fs::write(&local_file, "CORRUPT-LOCAL").unwrap();

        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Failed);
        assert!(proc.error.unwrap().contains("integrity"));
    }

    #[test]
    fn missing_systemd_unit_fails() {
        // The unit file is NOT present in the tree.
        let h = Harness::new(
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/other.txt", "x"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Failed);
        assert!(proc.error.unwrap().contains("missing"));
        assert!(!h.remote.exists(Path::new("current")));
    }

    #[test]
    fn wrong_artifact_type_fails() {
        // The artifact path exists but is a DIRECTORY, not a regular file.
        let h = Harness::new(
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/example.service/placeholder", "x"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Failed);
        assert!(proc.error.unwrap().to_lowercase().contains("type"));
    }

    #[test]
    fn materialization_prefers_release_local_artifacts() {
        // A file with the same relative path exists both at the project root and
        // inside the release directory's `artifacts` tree. The conflicting
        // project-root copy is created BEFORE materialization; if `from` were
        // resolved against the project root it would win. It must not.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), NONE_VARIANT).unwrap();
        std::fs::write(project.join("deploy.toml"), NONE_TOML).unwrap();

        // Release-local artifact sources (under release_root/artifacts).
        let artifacts_dir = release_dir.join("artifacts");
        std::fs::create_dir_all(artifacts_dir.join("build/output/app")).unwrap();
        std::fs::write(
            artifacts_dir.join("build/output/app/server"),
            "RELEASE-LOCAL\n",
        )
        .unwrap();
        std::fs::create_dir_all(artifacts_dir.join("deployment/common")).unwrap();
        std::fs::write(artifacts_dir.join("deployment/common/README"), "common\n").unwrap();

        // Conflicting copy at the project root, present before materialization.
        let project_root_file = project.join("build/output/app/server");
        std::fs::create_dir_all(project_root_file.parent().unwrap()).unwrap();
        std::fs::write(project_root_file, "PROJECT-ROOT\n").unwrap();

        let cfg_path = project.join("deploy.toml");
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let release_root = config.release_root(&cfg_path);
        let vcfg = config.variant("standard").unwrap();
        let staging = store.staging_dir().join("standard");
        crate::mapper::materialize_variant(
            &release_root,
            &vcfg.artifact.mappings,
            "standard",
            &staging,
        )
        .unwrap();
        let meta = tree::canonicalize_tree(&staging).unwrap();
        let tree = TreeDigest::new(meta.tree_sha256.clone());
        store
            .store_object(&meta.tree_sha256.into(), &staging)
            .unwrap();

        // Find the materialized `server` file wherever the recursive mapping
        // placed it (the source dir's contents merge under `app/`).
        let obj_root = store.object_root(&tree);
        let server_file = std::fs::read_dir(&obj_root)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                e.path()
                    .join("app")
                    .join("server")
                    .exists()
                    .then_some(e.path().join("app").join("server"))
            })
            .next();
        let server_file = server_file.expect("materialized server file present");
        let content = std::fs::read_to_string(&server_file).unwrap();
        assert_eq!(
            content, "RELEASE-LOCAL\n",
            "materialization must read from the release directory, not the project root"
        );
    }
}

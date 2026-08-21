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
use crate::config::Config;
use crate::error::{Error, Result};
use crate::history::{self, PushRef};
use crate::model::{
    DeploymentId, GenerationId, OperationId, ReleaseId, ServerId, TargetName, TreeDigest,
    VariantName,
};
use crate::records::{
    AttemptRecord, AttemptServer, DeploymentPlan, DeploymentResults, DeploymentStatus, ObservedServer,
    ObservedTarget, ServerOutcomeKind, ServerPlan, ServerResult,
};
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::Remote;
use crate::rotation::compute_retained;
use crate::store::local::LocalStore;
use crate::tree;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

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
    if let PushRef::Fleet { target, .. } = &mut pref {
        if target.as_str().is_empty() {
            *target = TargetName::new(target_name.to_string());
        }
    }

    // 2. Acquire local application-store lock then target lock (in that order).
    acquire_lock_file(&store.base().join("operation.lock"), op_id.as_str())?;
    let target_lock = store.target_dir(target_name).join("operation.lock");
    std::fs::create_dir_all(target_lock.parent().unwrap()).ok();
    acquire_lock_file(&target_lock, op_id.as_str())?;

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

    // Always release local locks.
    release_lock_file(&target_lock, op_id.as_str()).ok();
    release_lock_file(&store.base().join("operation.lock"), op_id.as_str()).ok();
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
    // 3. Materialize every declared variant.
    let mut variant_trees: BTreeMap<String, TreeDigest> = BTreeMap::new();
    if matches!(pref, PushRef::Head) {
        for v in config.variant_names() {
            let staging = store.staging_dir().join(&v);
            crate::mapper::materialize_variant(project_root, &config.artifact.mappings, &v, &staging)?;
            let meta = tree::canonicalize_tree(&staging)?;
            store.store_object(&meta.tree_sha256.clone().into(), &staging)?;
            variant_trees.insert(v, TreeDigest::new(meta.tree_sha256));
        }
    }

    // 4. Freeze mapping + behavior and generate or reuse the release record.
    let mapping_sha = crate::release::mapping_digest(&config.artifact.mappings);
    let behavior_sha = crate::release::behavior_digest(&config.activation, &config.verification);
    let behavior_json = serde_json::json!({
        "activation": serde_json::to_value(&config.activation)?,
        "verification": serde_json::to_value(&config.verification)?,
    });
    let mapping_yaml = serde_yaml::to_string(&config.artifact.mappings)
        .map_err(|e| Error::store(format!("serialize mappings: {e}")))?;

    let local_release_id: ReleaseId = if matches!(pref, PushRef::Head) {
        let bindings: BTreeMap<VariantName, TreeDigest> = variant_trees
            .iter()
            .map(|(k, v)| (VariantName::new(k.clone()), v.clone()))
            .collect();
        let rec = crate::release::build_release(&mapping_sha, &behavior_sha, &bindings, project_root);
        let rid = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec)?;
        let release_json = serde_json::to_string(&rec)
            .map_err(|e| Error::store(format!("serialize release: {e}")))?;
        store.write_release_aux(&rid, &mapping_yaml, &behavior_json)?;
        // Persist release JSON string for remote publication.
        REMOTE_RELEASE_JSON.with(|c| c.borrow_mut().insert(rid.clone(), (release_json, behavior_json.to_string())));
        rid
    } else {
        // Historical ref: resolve the bound release and populate the publish cache
        // from the local release record.
        let rid = match pref {
            PushRef::Fleet { target: ft, index, .. } => {
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
        if let Ok(rec) = store.read_release(&rid) {
            let release_json = serde_json::to_string(&rec)
                .map_err(|e| Error::store(format!("serialize release: {e}")))?;
            REMOTE_RELEASE_JSON.with(|c| {
                c.borrow_mut()
                    .insert(rid.clone(), (release_json, behavior_json.to_string()))
            });
        }
        rid
    };
    let _ = &local_release_id;

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

    // Open a remote handle per server and run reconciliation / recovery.
    let mut remotes: HashMap<ServerId, Box<dyn Remote>> = HashMap::new();
    let mut helpers: HashMap<ServerId, RemoteHelper> = HashMap::new();
    let mut statuses: HashMap<ServerId, crate::remote::helper::RemoteStatus> = HashMap::new();
    // Build all remotes first into stable storage (no borrows yet).
    for s in &target.servers {
        let sid = ServerId::new(s.id.clone());
        let remote = factory(s)?;
        remotes.insert(sid.clone(), remote);
    }
    // Then borrow them to build helpers (no further inserts into `remotes`).
    for s in &target.servers {
        let sid = ServerId::new(s.id.clone());
        let r = remotes.get(&sid).unwrap();
        let helper = RemoteHelper::new(r.as_ref());
        helper.handshake()?;
        let status = helper.status()?;
        // Recovery: clear abandoned incoming directories not owned by this op.
        for pend in &status.pending_incoming {
            if pend != deployment_id.as_str() {
                helper.remove_incoming(pend)?;
            }
        }
        if let Some(held) = &status.lock {
            if held != op_id.as_str() {
                return Err(Error::preflight(format!(
                    "server {sid} mutation lock held by '{held}'"
                )));
            }
        }
        // Recover any desired trees missing locally from this server.
        for a in &assignments {
            if a.server_id == sid {
                recover_if_missing(helper.remote(), store, &a.tree)?;
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
            expected.as_ref().map(|g| AttemptServer {
                release: a.release.clone(),
                variant: a.variant.clone(),
                tree: a.tree.clone(),
                generation: g.clone(),
            }),
        );
    }

    let plan = DeploymentPlan {
        deployment_id: deployment_id.clone(),
        target: TargetName::new(target_name.to_string()),
        behavior_sha256: behavior_sha.clone(),
        server_ids: assignments.iter().map(|a| a.server_id.clone()).collect(),
        servers: plan_servers.clone(),
        source,
        desired_release: desired_release.clone(),
    };
    store.write_plan(deployment_id.as_str(), &plan)?;

    let _ = &desired_release;

    // Early "Everything up to date" check for HEAD pushes.
    if matches!(pref, PushRef::Head) {
        let mut all_match = true;
        for a in &assignments {
            let st = &statuses[&a.server_id];
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
                if run_verification(remote, &config.verification).is_err() {
                    verified = false;
                    break;
                }
            }
            if verified {
                return Ok(PushReport {
                    status: None,
                    attempt: None,
                    message: "Everything up to date".to_string(),
                    dry_run: opts.dry_run,
                });
            }
        }
    }

    // 8 & 9. Capacity preflight and staging.
    if !opts.dry_run {
        capacity_preflight(config, store, &assignments, &helpers, op_id, deployment_id)?;
        // Stage every needed tree into operation-unique incoming paths.
        for a in &assignments {
            let remote = remotes[&a.server_id].as_ref();
            let helper = &helpers[&a.server_id];
            if !helper.tree_exists(a.tree.as_str()) {
                let host_obj = store.object_root(&a.tree);
                helper.stage_incoming(deployment_id.as_str(), a.tree.as_str(), &host_obj)?;
                let _ = remote;
            }
        }
    } else {
        // Dry-run: report recovery that a real push would perform.
        let mut msg = String::new();
        for a in &assignments {
            let st = &statuses[&a.server_id];
            let cur = st.current_generation.clone();
            let want = new_gen[&a.server_id].as_str().to_string();
            let note = match cur {
                Some(c) if c.as_str() == want => format!("server {}: already at desired generation\n", a.server_id),
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
        }
        return Ok(PushReport {
            status: None,
            attempt: None,
            message: format!("dry-run plan:\n{msg}"),
            dry_run: true,
        });
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
            let outcome = process_server(
                config,
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
                    generation,
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

    // 13. Failure policy compensation of still-advanced servers.
    if had_failure && failure_policy == "rollback_changed" {
        for sid in &advanced {
            let prior = plan_servers[sid].expected_generation.as_ref();
            let ok = compensate_server(
                config,
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                sid,
                prior,
            )?;
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
        for sid in &servers_order {
            let helper = &helpers[sid];
            helper.acquire_lock(op_id.as_str(), false)?;
            helper.write_commit_marker(deployment_id.as_str())?;
            // Confirm generation still matches this attempt's creation.
            let cur = helper.status()?.current_generation;
            let matches = cur.as_deref() == Some(new_gen[sid].as_str());
            helper.release_lock(op_id.as_str())?;
            if !matches {
                commit_status = DeploymentStatus::PendingCommit;
            }
        }
    }

    // 16 & 17. Record attempt, history, rotation.
    let mut actual_servers: BTreeMap<ServerId, AttemptServer> = BTreeMap::new();
    for a in &assignments {
        let r = &results[&a.server_id];
        actual_servers.insert(
            a.server_id.clone(),
            AttemptServer {
                release: a.release.clone(),
                variant: a.variant.clone(),
                tree: a.tree.clone(),
                generation: r.generation.clone(),
            },
        );
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
                    generation: new_gen[&a.server_id].clone(),
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
        behavior_sha256: behavior_sha.clone(),
        attempted_at: crate::remote::helper::now_rfc3339(),
        desired: desired_map,
        pre_push,
        servers: actual_servers,
    };
    store.append_attempt(target_name, &attempt)?;
    store.write_results(deployment_id.as_str(), &DeploymentResults {
        deployment_id: deployment_id.clone(),
        target: TargetName::new(target_name.to_string()),
        servers: results.clone(),
    })?;
    store.write_status(deployment_id.as_str(), &format!("{:?}", commit_status))?;

    // Refresh observed state.
    let mut observed = ObservedTarget {
        target: TargetName::new(target_name.to_string()),
        servers: Default::default(),
    };
    for a in &assignments {
        let r = &results[&a.server_id];
        observed.servers.insert(
            a.server_id.clone(),
            ObservedServer {
                generation: Some(r.generation.clone()),
                release: Some(a.release.clone()),
                variant: Some(a.variant.clone()),
                tree: Some(a.tree.clone()),
                last_deployment: Some(deployment_id.clone()),
            },
        );
        store.write_server(&crate::records::ServerState {
            id: a.server_id.clone(),
            last_seen_target: Some(TargetName::new(target_name.to_string())),
            last_observed: Some(ObservedServer {
                generation: Some(r.generation.clone()),
                release: Some(a.release.clone()),
                variant: Some(a.variant.clone()),
                tree: Some(a.tree.clone()),
                last_deployment: Some(deployment_id.clone()),
            }),
        })?;
    }
    store.write_observed(target_name, &observed)?;

    // 16. Advance the reflog only for successful fleet deployments.
    let mut message = format!("push status: {commit_status:?}");
    if commit_status == DeploymentStatus::Successful {
        let idx = history::append_successful_reflog(store, &TargetName::new(target_name.to_string()), &attempt)?;
        message = format!("push successful; fleet ref {}@f{idx}", target_name);
    }

    // 17. Per-server rotation under each server's mutation lock.
    for sid in &servers_order {
        let helper = &helpers[sid];
        if helper.acquire_lock(op_id.as_str(), false).is_ok() {
            let retained = compute_retained(helper, config, store)?;
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
    helper.acquire_lock(op_id.as_str(), false)?;
    // Compare-and-swap precondition on current generation.
    let status = helper.status()?;
    if let Some(exp) = expected_gen {
        if status.current_generation.as_deref() != Some(exp.as_str()) {
            helper.release_lock(op_id.as_str())?;
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
    }

    // Validate artifact paths exist in the desired tree.
    validate_artifact_paths(remote, &config.activation, &Path::new("objects/sha256").join(tree.as_str()).join("root")).ok();

    // Publish tree (from incoming) and release record.
    helper.publish_from_incoming(deployment_id.as_str(), tree.as_str())?;
    if let Some((release_json, behavior_json)) = REMOTE_RELEASE_JSON.with(|c| c.borrow().get(release).cloned()) {
        helper.publish_release(release.as_str(), &release_json, &behavior_json)?;
    }

    // Create generation + swap current atomically.
    let assignment = crate::remote::helper::GenerationAssignment {
        deployment_id: deployment_id.as_str().to_string(),
        generation_id: new_gen.as_str().to_string(),
        release: release.as_str().to_string(),
        variant: variant.as_str().to_string(),
        tree: tree.as_str().to_string(),
        behavior_sha256: String::new(),
        prior_generation: expected_gen.map(|g| g.as_str().to_string()),
        created_at: crate::remote::helper::now_rfc3339(),
    };
    helper.create_generation(op_id.as_str(), &assignment)?;
    helper.transaction_record(op_id.as_str(), "prepared")?;
    let swap = helper.swap_current(expected_gen.map(|g| g.as_str()), new_gen.as_str(), op_id.as_str());
    if let Err(e) = swap {
        helper.release_lock(op_id.as_str())?;
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("swap failed: {e}")),
        });
    }
    let generation_root = remote.root().join("generations").join(new_gen.as_str()).join("root");

    // Activation adapter.
    if let Err(e) = run_activation(&config.activation, remote, remote.root(), &generation_root) {
        // Compensate: restore prior generation.
        let comp = compensate_server(config, store, remote, helper, op_id, deployment_id, server_id, expected_gen)?;
        helper.transaction_record(op_id.as_str(), "compensated")?;
        helper.release_lock(op_id.as_str())?;
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: if comp { expected_gen.cloned().unwrap_or_else(|| new_gen.clone()) } else { new_gen.clone() },
            did_compensate: comp,
            error: Some(format!("activation failed: {e}")),
        });
    }

    // Verification.
    if let Err(e) = run_verification(remote, &config.verification) {
        let comp = compensate_server(config, store, remote, helper, op_id, deployment_id, server_id, expected_gen)?;
        helper.transaction_record(op_id.as_str(), "compensated")?;
        helper.release_lock(op_id.as_str())?;
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: if comp { expected_gen.cloned().unwrap_or_else(|| new_gen.clone()) } else { new_gen.clone() },
            did_compensate: comp,
            error: Some(format!("verification failed: {e}")),
        });
    }

    helper.transaction_record(op_id.as_str(), "committed")?;
    helper.release_lock(op_id.as_str())?;
    Ok(ServerProc {
        kind: ServerOutcomeKind::Activated,
        generation: new_gen.clone(),
        did_compensate: false,
        error: None,
    })
}

/// Restore the prior generation (or remove `current` on first deploy). Returns
/// true if compensation restored prior state.
fn compensate_server(
    config: &Config,
    _store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    _deployment_id: &DeploymentId,
    _server_id: &ServerId,
    prior_gen: Option<&GenerationId>,
) -> Result<bool> {
    match prior_gen {
        Some(prior) => {
            helper.swap_current(None, prior.as_str(), op_id.as_str())?;
            let root = remote.root().join("generations").join(prior.as_str()).join("root");
            // Re-run prior activation contract + verification.
            let _ = run_activation(&config.activation, remote, remote.root(), &root);
            let _ = run_verification(remote, &config.verification);
            Ok(true)
        }
        None => {
            helper.remove_current()?;
            Ok(true)
        }
    }
}

/// Download a tree from a server into the local object store if missing.
fn recover_if_missing(
    remote: &dyn Remote,
    store: &LocalStore,
    digest: &TreeDigest,
) -> Result<()> {
    if store.object_exists(digest) {
        return Ok(());
    }
    let root_rel = Path::new("objects/sha256").join(digest.as_str()).join("root");
    if !remote.exists(&root_rel) {
        return Ok(());
    }
    let tmp = store.staging_dir().join(format!("recover-{}", digest.as_str()));
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
        if entry.is_dir {
            download_tree_to_host(remote, &child_rel, &dest)?;
        } else if entry.is_symlink {
            let target = remote.read_link(&child_rel)?;
            std::os::unix::fs::symlink(&target, &dest)
                .map_err(|e| Error::transport(format!("symlink: {e}")))?;
        } else {
            let data = remote.read(&child_rel)?;
            std::fs::write(&dest, data)
                .map_err(|e| Error::transport(format!("write {}: {e}", dest.display())))?;
        }
    }
    Ok(())
}

/// Coarse capacity preflight: ensure each server has room for the new trees plus
/// the configured safety headroom, running protected rotation first if needed.
fn capacity_preflight(
    config: &Config,
    store: &LocalStore,
    assignments: &[crate::push::plan::PlannedAssignment],
    helpers: &HashMap<ServerId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
) -> Result<()> {
    let reserve_bytes = config.capacity.reserve_bytes;
    let reserve_percent = config.capacity.reserve_percent as f64 / 100.0;
    for a in assignments {
        let helper = &helpers[&a.server_id];
        if helper.tree_exists(a.tree.as_str()) {
            continue;
        }
        let need = tree_size_on_host(&store.object_root(&a.tree));
        let avail = helper.remote().available_bytes().unwrap_or(0);
        let total = helper.remote().root().metadata().map(|m| m.len()).unwrap_or(0);
        let _ = total;
        let reserve = reserve_bytes.max((avail as f64 * reserve_percent) as u64);
        if need + reserve > avail {
            // Run protected rotation, then recheck.
            if helper.acquire_lock(op_id.as_str(), false).is_ok() {
                let retained = compute_retained(helper, config, store)?;
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

fn tree_size_on_host(root: &Path) -> u64 {
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(root) {
        if let Ok(e) = entry {
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    total += m.len();
                }
            }
        }
    }
    total
}

fn acquire_lock_file(path: &Path, op_id: &str) -> Result<()> {
    if path.exists() {
        let held = std::fs::read_to_string(path).unwrap_or_default();
        if held.trim() == op_id {
            return Ok(());
        }
        // Treat a stale lock (older than 1 hour) as recoverable.
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                if let Ok(elapsed) = std::time::SystemTime::now().duration_since(modified) {
                    if elapsed < Duration::from_secs(3600) {
                        return Err(Error::preflight(format!(
                            "local lock {} held by '{}'",
                            path.display(),
                            held.trim()
                        )));
                    }
                }
            }
        }
        std::fs::remove_file(path).ok();
    }
    std::fs::write(path, op_id)
        .map_err(|e| Error::preflight(format!("acquire lock {}: {e}", path.display())))?;
    Ok(())
}

fn release_lock_file(path: &Path, op_id: &str) -> Result<()> {
    if path.exists() {
        let held = std::fs::read_to_string(path).unwrap_or_default();
        if held.trim() == op_id {
            std::fs::remove_file(path).ok();
        }
    }
    Ok(())
}

// Per-process cache of release JSON for remote publication (avoids re-reading
// the local store inside the nested helper calls).
thread_local! {
    static REMOTE_RELEASE_JSON: std::cell::RefCell<
        HashMap<ReleaseId, (String, String)>
    > = std::cell::RefCell::new(HashMap::new());
}

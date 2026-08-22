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
    if let PushRef::Fleet { target, .. } = &mut pref
        && target.as_str().is_empty()
    {
        *target = TargetName::new(target_name.to_string());
    }

    // 2. Acquire local application-store lock then target lock (in that order).
    //    Dry-run never acquires a persistent lock (local or remote).
    let local_lock = if opts.dry_run {
        None
    } else {
        Some(store.base().join("operation.lock"))
    };
    if let Some(p) = &local_lock {
        acquire_lock_file(p, op_id.as_str())?;
    }
    let target_lock = if opts.dry_run {
        None
    } else {
        let p = store.target_dir(target_name).join("operation.lock");
        std::fs::create_dir_all(p.parent().unwrap()).ok();
        Some(p)
    };
    if let Some(p) = &target_lock {
        acquire_lock_file(p, op_id.as_str())?;
    }

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
    if let Some(p) = &target_lock {
        release_lock_file(p, op_id.as_str()).ok();
    }
    if let Some(p) = &local_lock {
        release_lock_file(p, op_id.as_str()).ok();
    }
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
    // 3. Materialize every declared variant. Dry-run uses disposable staging and
    //    never writes to the object store.
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
                project_root,
                &config.artifact.mappings,
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
        let rec =
            crate::release::build_release(&mapping_sha, &behavior_sha, &bindings, project_root);
        let rid = ReleaseId::new(rec.release_id.clone());
        if !opts.dry_run {
            store.write_release(&rec)?;
            let release_json = serde_json::to_string(&rec)
                .map_err(|e| Error::store(format!("serialize release: {e}")))?;
            store.write_release_aux(&rid, &mapping_yaml, &behavior_json)?;
            // Persist release JSON string for remote publication.
            REMOTE_RELEASE_JSON.with(|c| {
                c.borrow_mut()
                    .insert(rid.clone(), (release_json, behavior_json.to_string()))
            });
        }
        rid
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
        if !opts.dry_run
            && let Ok(rec) = store.read_release(&rid)
        {
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

    // The behavior contract this attempt is bound to. A historical or rollback
    // push loads the historical contract from the release instead of using the
    // caller's current configuration.
    let desired_behavior: BehaviorContract = if !opts.dry_run {
        store
            .read_release_behavior(&local_release_id)
            .unwrap_or_else(|_| BehaviorContract {
                activation: config.activation.clone(),
                verification: config.verification.clone(),
            })
    } else {
        BehaviorContract {
            activation: config.activation.clone(),
            verification: config.verification.clone(),
        }
    };
    let desired_behavior_sha = crate::release::behavior_contract_digest(&desired_behavior);

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
    for s in &target.servers {
        let sid = ServerId::new(s.id.clone());
        let remote = factory(s)?;
        remotes.insert(sid.clone(), remote);
    }
    for s in &target.servers {
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
            expected.as_ref().map(|g| AttemptServer {
                release: a.release.clone(),
                variant: a.variant.clone(),
                tree: a.tree.clone(),
                generation: Some(g.clone()),
            }),
        );
    }

    let plan = DeploymentPlan {
        deployment_id: deployment_id.clone(),
        target: TargetName::new(target_name.to_string()),
        behavior_sha256: desired_behavior_sha.clone(),
        behavior: desired_behavior.clone(),
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

    // Persist the plan before any server mutation (finding 6).
    store.write_plan(deployment_id.as_str(), &plan)?;
    store.write_status(deployment_id.as_str(), "in_progress")?;

    // Early "Everything up to date" check for HEAD pushes.
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
                if run_verification(remote, &plan.behavior.verification).is_err() {
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
            let outcome = process_server(
                config,
                &plan.behavior,
                &plan.behavior_sha256,
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
            let ok = compensate_server(
                config,
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                sid,
                prior,
                true,
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
        let r = results.get(&a.server_id).expect("result present");
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
        servers: actual_servers,
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
    for a in &assignments {
        let r = results.get(&a.server_id).expect("result present");
        observed.servers.insert(
            a.server_id.clone(),
            ObservedServer {
                generation: r.generation.clone(),
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
                generation: r.generation.clone(),
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
        let idx = history::append_successful_reflog(
            store,
            &TargetName::new(target_name.to_string()),
            &attempt,
        )?;
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
    let advanced = match swap {
        Ok(()) => true,
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
            advanced,
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
            advanced,
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

    if let Err(e) = helper.transaction_record(op_id.as_str(), "committed") {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("transaction commit record failed: {e}")),
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
/// configuration. Returns true if compensation restored prior state.
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
    _advanced: bool,
) -> Result<bool> {
    match prior_gen {
        Some(prior) => {
            // Load the prior generation's behavior contract from the remote.
            let prior_assignment = match helper.read_assignment(prior.as_str()) {
                Ok(a) => a,
                Err(_) => return Ok(false),
            };
            let prior_behavior = helper
                .read_behavior(&prior_assignment.release)
                .unwrap_or_else(|_| BehaviorContract {
                    activation: crate::config::ActivationConfig::default(),
                    verification: crate::config::VerificationConfig::default(),
                });
            helper.swap_current(None, prior.as_str(), op_id.as_str())?;
            let root = remote
                .root()
                .join("generations")
                .join(prior.as_str())
                .join("root");
            // Re-run prior activation contract + verification.
            let _ = run_activation(&prior_behavior.activation, remote, remote.root(), &root);
            let _ = run_verification(remote, &prior_behavior.verification);
            Ok(true)
        }
        None => {
            helper.remove_current()?;
            Ok(true)
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
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()).map(|m| m.len()))
        .sum()
}

fn acquire_lock_file(path: &Path, op_id: &str) -> Result<()> {
    if path.exists() {
        let held = std::fs::read_to_string(path).unwrap_or_default();
        if held.trim() == op_id {
            return Ok(());
        }
        // Treat a stale lock (older than 1 hour) as recoverable.
        if let Ok(meta) = std::fs::metadata(path)
            && let Ok(modified) = meta.modified()
            && let Ok(elapsed) = std::time::SystemTime::now().duration_since(modified)
            && elapsed < Duration::from_secs(3600)
        {
            return Err(Error::preflight(format!(
                "local lock {} held by '{}'",
                path.display(),
                held.trim()
            )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::transport::LocalTransport;
    use std::path::{Path, PathBuf};

    const NONE_YAML: &str = r#"
schema_version: 1
application: eng
remote_root: /srv/eng
variants: { standard: {} }
artifact:
  mappings:
    - from: build/output/
      to: app/
      recursive: true
    - from: deployment/common/
      to: app/
      recursive: true
activation: { adapter: none }
verification: { adapter: command, argv: ["true"], timeout_seconds: 5, attempts: 1, interval_seconds: 0 }
capacity: { reserve_bytes: 0, reserve_percent: 0 }
rotation: { per_server: { keep_distinct_artifacts: 1, keep_days: 0, protect_previous: true }, fleet: { protect_deployments: 1 } }
targets:
  t1:
    rollout: { batch_size: 1, stop_on_failure: true, failure_policy: rollback_changed }
    servers:
      - id: s1
        address: a
        user: u
        variant: standard
"#;

    const SYSTEMD_YAML: &str = r#"
schema_version: 1
application: eng
remote_root: /srv/eng
variants: { standard: {} }
artifact:
  mappings:
    - from: build/output/
      to: app/
      recursive: true
    - from: deployment/common/
      to: app/
      recursive: true
    - from: units/
      to: integration/systemd/
      recursive: true
activation:
  adapter: systemd
  scope: user
  units:
    - name: example.service
      artifact_path: integration/systemd/example.service
      enable: true
      restart: true
verification: { adapter: command, argv: ["true"], timeout_seconds: 5, attempts: 1, interval_seconds: 0 }
capacity: { reserve_bytes: 0, reserve_percent: 0 }
rotation: { per_server: { keep_distinct_artifacts: 1, keep_days: 0, protect_previous: true }, fleet: { protect_deployments: 1 } }
targets:
  t1:
    rollout: { batch_size: 1, stop_on_failure: true, failure_policy: rollback_changed }
    servers:
      - id: s1
        address: a
        user: u
        variant: standard
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
        fn new(yaml: &str, files: &[(&str, &str)]) -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let cfg_path = project.join("deploy.yaml");
            std::fs::write(&cfg_path, yaml).unwrap();
            for (p, c) in files {
                let fp = project.join(p);
                std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
                std::fs::write(&fp, c).unwrap();
            }
            let config = Config::load(&cfg_path).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();

            let staging = store.staging_dir().join("standard");
            crate::mapper::materialize_variant(
                &project,
                &config.artifact.mappings,
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
            BehaviorContract {
                activation: self.config.activation.clone(),
                verification: self.config.verification.clone(),
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
            NONE_YAML,
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
            NONE_YAML,
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
            NONE_YAML,
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
            SYSTEMD_YAML,
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
            SYSTEMD_YAML,
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
}

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
use crate::layout;
use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, GenerationRef, OperationId,
    PlacementSlotId, ReleaseId, TargetName, TreeDigest, VariantName,
};
use crate::records::{
    AttemptServer, DeploymentAttempt, DeploymentPlan, DeploymentResults, DeploymentStatus,
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
    pub attempt: Option<DeploymentAttempt>,
    pub message: String,
    pub dry_run: bool,
}

type RemoteFactory =
    dyn Fn(&crate::config::ServerDef, &crate::config::SlotDef) -> Result<Box<dyn Remote>>;

/// Build the template context for one placement slot from the live
/// configuration. `variant` is the variant whose contract is being rendered —
/// the desired variant during activation, or the PRIOR variant when
/// compensating (compensation overrides it via `TemplateVars::with_variant`).
///
/// `deployment_id`/`generation`/`tree` are the per-deployment identity,
/// available only in the per-server activation/verification path; sites that
/// do not know them (e.g. the reconciliation loop) pass `None`, and a
/// template referencing such a variable there fails loudly.
fn slot_vars(
    members: &[(&crate::config::SlotDef, &crate::config::ServerDef)],
    config: &Config,
    target_name: &str,
    slot_id: &PlacementSlotId,
    variant: &str,
    deployment_id: Option<&DeploymentId>,
    generation: Option<&GenerationId>,
    tree: Option<&TreeDigest>,
) -> Result<crate::template::TemplateVars> {
    let (slot, server) = members
        .iter()
        .find(|(s, _)| s.id == slot_id.as_str())
        .ok_or_else(|| {
            Error::internal(format!(
                "slot '{}' not found among target members",
                slot_id.as_str()
            ))
        })?;
    Ok(crate::template::TemplateVars::slot(
        &slot.deploy_dir,
        variant,
        &config.application,
        config.release.as_str(),
        target_name,
        &server.id,
    )
    .with_server(&server.user, &server.address, server.port)
    .with_slot_id(&slot.id)
    .with_deployment(deployment_id, generation, tree))
}

/// Run a push against `target_name`.
///
/// Dry-run gating: `opts.dry_run` short-circuits every mutating stage of
/// [`push_inner`] — no local or remote locks, no handshake or recovery, no
/// object persistence (disposable staging only), no plan/status/results
/// records, and it returns before capacity preflight — so a dry run never
/// checks disk headroom. Any new mutating stage added to `push_inner` MUST sit
/// behind the same gate; the dry-run branch is the single place that defines
/// what "touch nothing" means.
pub fn push(
    config_path: &Path,
    store: &LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    config: &Config,
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
        &project_root,
        store,
        factory,
        target_name,
        &pref,
        &deployment_id,
        &op_id,
        config,
        target,
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
    project_root: &Path,
    store: &LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    pref: &PushRef,
    deployment_id: &DeploymentId,
    op_id: &OperationId,
    config: &Config,
    target: &crate::config::TargetDef,
    opts: &PushOptions,
) -> Result<PushReport> {
    // 3. Materialize every declared variant. Mappings resolve from the release
    //    directory (`<project>/releases/<release>/` — the structure is forced),
    //    not the project root, so an artifact `from` can never escape into the
    //    project's other files. Dry-run uses disposable staging and never writes
    //    to the object store.
    let release_root = project_root.join("releases").join(config.release.as_str());
    let mut variant_trees: BTreeMap<String, TreeDigest> = BTreeMap::new();
    // Dry-run staging is disposable. The guard's Drop removes the whole
    // `dry-<deployment>` tree (on error, `?`, or unwind); the guard must
    // outlive the Head-materialization block because the dry-run branch below
    // performs an explicit FALLIBLE cleanup (reporting errors instead of
    // silently swallowing them) and empties the guard first, keeping the Drop
    // as a fallback only. A non-dry-run push stages into the persistent
    // per-variant staging dirs and stores objects, so no guard.
    let mut staging_guard = if opts.dry_run && matches!(pref, PushRef::Head) {
        Some(StagingCleanup(Some(
            store
                .staging_dir()
                .join(format!("dry-{}", deployment_id.as_str())),
        )))
    } else {
        None
    };
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
                &crate::template::TemplateVars::mapping(
                    &config.application,
                    config.release.as_str(),
                    &v,
                ),
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
    // Capacity is NOT part of the release: it is a per-server policy resolved
    // from the caller's current `deploy.toml` at preflight time (servers have
    // no per-release history), so a server-capacity change never produces a
    // new release. Rotation is fleet-wide configuration read from
    // `deploy.toml` at push time, so it is not snapshotted per variant either.
    let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    let mut variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::new();
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
    }
    let mapping_sha = crate::release::variant_mappings_digest(&variant_mappings);
    let behavior_sha = crate::release::variant_behaviors_digest(&variant_behaviors);
    let behavior_json = serde_json::to_value(&variant_behaviors)?;
    let mapping_toml = toml::to_string_pretty(&variant_mappings)
        .map_err(|e| Error::store(format!("serialize mappings: {e}")))?;

    // Historical and rollback pushes carry the bound release's own per-variant
    // behavior contracts; they never fall back to the caller's current config.
    let (local_release_id, desired_behaviors): (ReleaseId, BTreeMap<String, BehaviorContract>) = if matches!(
        pref,
        PushRef::Head
    ) {
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
            store.write_release_aux(&rid, &mapping_toml, &behavior_json)?;
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
                let entry = history::resolve_snapshot(store, ft, *index)?;
                entry
                    .slots
                    .values()
                    .next()
                    .map(|g| g.assignment.artifact.release.clone())
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

    // The behavior digest this attempt is bound to: the frozen, name-keyed set of
    // every declared variant's activation + verification contract. Historical
    // and rollback pushes use the historical release's own contracts.
    let desired_behavior_sha = crate::release::variant_behaviors_digest(&desired_behaviors);

    // 5 & 7. Reconcile each server and build the plan, recovering missing local
    // objects from servers that retain them.
    let (assignments, desired_release, source) = crate::push::plan::plan_assignments(
        target_name,
        pref,
        &local_release_id,
        &variant_trees,
        store,
        config,
    )?;

    // Behavior coverage gate: every planned assignment's variant must have a
    // frozen behavior contract BEFORE any remote state is touched (handshake,
    // incoming cleanup, staging, publication). A historical behavior snapshot
    // can be incomplete (a corrupted or truncated behavior.json parses fine but
    // lacks a variant); without this gate the missing entry would panic
    // mid-rollout, after remote trees had already been staged. Fail closed in
    // preflight with context instead.
    validate_behavior_coverage(&desired_behaviors, &assignments, &desired_release)?;

    // Open a remote handle per slot and run reconciliation / recovery.
    let members = config.target_slots(target_name)?;
    let mut remotes: HashMap<PlacementSlotId, Box<dyn Remote>> = HashMap::new();
    let mut helpers: HashMap<PlacementSlotId, RemoteHelper> = HashMap::new();
    let mut statuses: HashMap<PlacementSlotId, crate::remote::helper::RemoteStatus> =
        HashMap::new();
    for (slot, s) in &members {
        let slot_id = PlacementSlotId::new(slot.id.clone());
        let remote = factory(s, slot)?;
        remotes.insert(slot_id, remote);
    }
    for (slot, _s) in &members {
        let slot_id = PlacementSlotId::new(slot.id.clone());
        let r = remotes.get(&slot_id).unwrap();
        let helper = RemoteHelper::new(r.as_ref());
        // Prepare the host identity (verify/pin the host key) BEFORE any status
        // request: a fingerprint-only configuration cannot connect at all
        // without the pinned key, and a dry run still connects to inspect
        // status. Pinning writes only to a LOCAL cache, never the remote
        // layout, so the dry-run "mutates nothing remotely" guarantee holds.
        r.prepare_identity()?;
        let status = helper.status()?;
        if !opts.dry_run {
            // Production path: protocol handshake FIRST, then create the remote
            // layout, clear abandoned incoming, check lock, recover missing
            // local objects. The handshake records `control/protocol.json`
            // before any other remote layout mutation; a dry run never reaches
            // this, so an unprovisioned remote stays untouched.
            helper.handshake()?;
            remotes.get(&slot_id).unwrap().provision_layout()?;
            for pend in &status.pending_incoming {
                if pend != deployment_id.as_str() {
                    helper.remove_incoming(pend)?;
                }
            }
            if let Some(held) = &status.lock
                && held != op_id.as_str()
            {
                return Err(Error::preflight(format!(
                    "slot {slot_id} mutation lock held by '{held}'"
                )));
            }
            for a in &assignments {
                if a.placement_slot == slot_id {
                    recover_if_missing(helper.remote(), store, &a.artifact.tree)?;
                }
            }
        }
        helpers.insert(slot_id.clone(), helper);
        statuses.insert(slot_id.clone(), status);
    }

    // Build the per-slot plan with expected (pre-push) generation.
    let mut plan_servers: BTreeMap<PlacementSlotId, ServerPlan> = BTreeMap::new();
    let mut new_gen: HashMap<PlacementSlotId, GenerationId> = HashMap::new();
    let mut pre_push: BTreeMap<PlacementSlotId, Option<AttemptServer>> = BTreeMap::new();
    for a in &assignments {
        let slot_id = &a.placement_slot;
        let expected = statuses
            .get(slot_id)
            .and_then(|st| st.current_generation.clone())
            .map(GenerationId::new);
        let expected_tree = statuses
            .get(slot_id)
            .and_then(|st| st.current_tree.clone())
            .map(TreeDigest::new);
        let gid = GenerationId::generate();
        new_gen.insert(slot_id.clone(), gid.clone());
        plan_servers.insert(
            slot_id.clone(),
            ServerPlan {
                slot_id: slot_id.clone(),
                artifact: a.artifact.clone(),
                expected_generation: expected.clone(),
                expected_tree,
            },
        );
        pre_push.insert(
            slot_id.clone(),
            expected.as_ref().map(|g| {
                // Record the slot's *actual* current assignment (read from the
                // remote generation), not the desired one.
                helpers[slot_id]
                    .read_assignment(g.as_str())
                    .map(|asn| AttemptServer {
                        artifact: asn.artifact.clone(),
                        generation: Some(g.clone()),
                    })
                    .unwrap_or_else(|_| AttemptServer {
                        artifact: a.artifact.clone(),
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
        slot_ids: assignments
            .iter()
            .map(|a| a.placement_slot.clone())
            .collect(),
        slots: plan_servers.clone(),
        source,
        desired_release: desired_release.clone(),
    };

    // ---- Dry-run: read-only planning, no mutation of store/remote/locks -----
    if opts.dry_run {
        let mut msg = String::new();
        for a in &assignments {
            let st = statuses.get(&a.placement_slot).expect("status present");
            let cur = st.current_generation.clone();
            let want = new_gen[&a.placement_slot].as_str().to_string();
            let missing_locally = !store.object_exists(&a.artifact.tree);
            let note = match cur {
                Some(c) if c == want => format!(
                    "slot {}: already at desired generation ({})\n",
                    a.placement_slot, c
                ),
                Some(c) => format!(
                    "slot {}: current {} -> desired {} (tree {})\n",
                    a.placement_slot, c, want, a.artifact.tree
                ),
                None => format!(
                    "slot {}: first deployment (tree {})\n",
                    a.placement_slot, a.artifact.tree
                ),
            };
            msg.push_str(&note);
            if missing_locally {
                msg.push_str(&format!(
                    "  would recover tree {} from a retaining server\n",
                    a.artifact.tree
                ));
            }
        }
        // Explicit, FALLIBLE cleanup BEFORE returning: remove the disposable
        // staging tree, restoring owner-write permission on read-only entries
        // first so the removal can succeed (materialized trees can contain
        // read-only dirs/files, which make `remove_dir_all` fail with EACCES).
        // A cleanup failure returns an Err so a dry run fails visibly instead
        // of silently leaking `staging/dry-<id>` forever. Taking the path out
        // of the guard empties it, so its Drop becomes a no-op here (the guard
        // remains only as a fallback for panic/unwind paths).
        if let Some(root) = staging_guard.as_mut().and_then(|g| g.0.take()) {
            cleanup_dry_run_staging(&root)?;
        }
        return Ok(PushReport {
            status: None,
            attempt: None,
            message: format!("dry-run plan:\n{msg}"),
            dry_run: true,
        });
    }

    // Reconcile `PendingCommit` attempts left by earlier pushes BEFORE the
    // early no-op check: an up-to-date push must complete the missing
    // fleet-commit markers (and advance the snapshot log) rather than
    // returning "Everything up to date" with the metadata still absent. Runs
    // under the local target lock already held by this push; never reactivates
    // or restarts services (markers/transition/snapshot only).
    reconcile_pending_commits(store, config, target_name, op_id, &helpers)?;

    // Early "Everything up to date" check for HEAD pushes. Run BEFORE persisting
    // any plan/status record so an up-to-date no-op leaves no dangling
    // `in_progress` deployment behind.
    if matches!(pref, PushRef::Head) {
        let mut all_match = true;
        for a in &assignments {
            let st = statuses.get(&a.placement_slot).expect("status present");
            let matches = st
                .current_generation
                .as_ref()
                .map(|g| {
                    helpers[&a.placement_slot]
                        .read_assignment(g)
                        .map(|asn| {
                            asn.artifact.tree == a.artifact.tree
                                && asn.artifact.release == a.artifact.release
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
            // Verify the running services to confirm true up-to-date state.
            let mut verified = true;
            for a in &assignments {
                let remote = remotes[&a.placement_slot].as_ref();
                let Some(variant_behavior) = desired_behaviors.get(a.artifact.variant.as_str())
                else {
                    // Coverage was validated before any remote mutation; a miss
                    // means the up-to-date claim cannot be established. Fall
                    // through to a real push rather than panicking.
                    verified = false;
                    break;
                };
                let vars = slot_vars(
                    &members,
                    config,
                    target_name,
                    &a.placement_slot,
                    a.artifact.variant.as_str(),
                    Some(deployment_id),
                    Some(&new_gen[&a.placement_slot]),
                    Some(&a.artifact.tree),
                )?;
                if run_verification(remote, &variant_behavior.verification, &vars).is_err() {
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

    // Persist the plan before any server mutation (finding 6), then record the
    // INITIAL status transition: the attempt is `InProgress`. The per-deployment
    // transition stream is append-only; later transitions (the final status, or
    // reconciliation finalization) overlay it, and the LATEST transition is the
    // deployment's current status.
    store.write_plan(deployment_id.as_str(), &plan)?;
    store.append_transition(
        deployment_id.as_str(),
        &DeploymentStatus::InProgress,
        Some("attempt started"),
    )?;

    // PERSIST THE ATTEMPT INTENT BEFORE ANY REMOTE MUTATION. The attempt
    // record is the IMMUTABLE INTENT of the deployment: deployment_id, target,
    // membership, behavior digest, attempted_at, the planned (`desired`)
    // generations, and the observed pre-push state. It must be durable BEFORE
    // any server's `current`/generation changes, so a crash can never lose a
    // deployment whose servers already advanced: without the record the next
    // push would see every server at the desired generation and report
    // "Everything up to date" with no attempt/snapshot/ref ever recorded.
    // The record carries NO outcomes — the `slots` (actual) map is persisted
    // empty; the actual per-slot outcomes are recorded separately in
    // `deployments/<id>/results.json` after the mutation loop, and the status
    // lifecycle lives in the per-deployment transition stream.
    let slot_ids: Vec<PlacementSlotId> = assignments
        .iter()
        .map(|a| a.placement_slot.clone())
        .collect();
    let desired_map: BTreeMap<PlacementSlotId, GenerationRef> = assignments
        .iter()
        .map(|a| {
            (
                a.placement_slot.clone(),
                GenerationRef {
                    generation: new_gen[&a.placement_slot].clone(),
                    assignment: a.clone(),
                },
            )
        })
        .collect();
    let attempt_intent = DeploymentAttempt {
        deployment_schema_version: 2,
        deployment_id: deployment_id.clone(),
        target: TargetName::new(target_name.to_string()),
        slot_ids,
        behavior_sha256: desired_behavior_sha.clone(),
        attempted_at: crate::remote::helper::now_rfc3339(),
        desired: desired_map,
        pre_push,
        slots: BTreeMap::new(),
    };
    store.append_attempt(target_name, &attempt_intent)?;

    // 8 & 9. Capacity preflight and staging. Capacity is a per-server policy
    // read from the caller's CURRENT `deploy.toml` (`ServerDef.capacity`), not
    // from any release snapshot: servers have no per-release history, so a
    // historical or rollback push applies the server's current headroom
    // exactly as a HEAD push does. Only the variant behavior contract resolves
    // from the immutable snapshot (see `desired_behaviors` above).
    capacity_preflight(
        store,
        &assignments,
        &helpers,
        op_id,
        deployment_id,
        config,
        &target.rotation,
    )?;
    // Stage every needed tree into operation-unique incoming paths.
    for a in &assignments {
        let _remote = remotes[&a.placement_slot].as_ref();
        let helper = &helpers[&a.placement_slot];
        if !helper.tree_exists(a.artifact.tree.as_str()) {
            let host_obj = store.object_root(&a.artifact.tree);
            helper.stage_incoming(deployment_id.as_str(), a.artifact.tree.as_str(), &host_obj)?;
        }
    }

    // 10-13. Process slots in batches.
    let batch_size = target.rollout.batch_size.max(1) as usize;
    let failure_policy = target.rollout.failure_policy.clone();
    let stop_on_failure = target.rollout.stop_on_failure;

    let mut results: BTreeMap<PlacementSlotId, ServerResult> = BTreeMap::new();
    let mut advanced: Vec<PlacementSlotId> = Vec::new();
    let mut compensated: Vec<PlacementSlotId> = Vec::new();
    let mut had_failure = false;

    let servers_order: Vec<PlacementSlotId> = assignments
        .iter()
        .map(|a| a.placement_slot.clone())
        .collect();
    let mut idx = 0;
    'batches: while idx < servers_order.len() {
        let end = (idx + batch_size).min(servers_order.len());
        for sid in &servers_order[idx..end] {
            let a = assignments
                .iter()
                .find(|x| &x.placement_slot == sid)
                .unwrap();
            // Select the assigned variant's frozen behavior contract (never the
            // caller's current variant file) before activation/verification.
            // Coverage was validated before any remote mutation, so a miss here
            // is an internal invariant violation: record a per-slot failure
            // instead of panicking.
            let Some(variant_behavior) = desired_behaviors.get(a.artifact.variant.as_str()) else {
                had_failure = true;
                results.insert(
                    sid.clone(),
                    ServerResult {
                        slot_id: sid.clone(),
                        outcome: ServerOutcomeKind::Failed,
                        generation: Some(new_gen[sid].clone()),
                        compensated: false,
                        error: Some(format!(
                            "internal: no behavior contract for variant '{}' after coverage check",
                            a.artifact.variant
                        )),
                    },
                );
                if stop_on_failure {
                    break 'batches;
                }
                continue;
            };
            let variant_behavior_sha = crate::release::behavior_contract_digest(variant_behavior);
            let vars = slot_vars(
                &members,
                config,
                target_name,
                sid,
                a.artifact.variant.as_str(),
                Some(deployment_id),
                Some(&new_gen[sid]),
                Some(&a.artifact.tree),
            )?;
            let outcome = process_server(
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                &a.artifact,
                &new_gen[sid],
                plan_servers[sid].expected_generation.as_ref(),
                variant_behavior,
                &variant_behavior_sha,
                &vars,
                config,
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
                    slot_id: sid.clone(),
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

    // Any slot never started (e.g. skipped after an earlier failure under
    // stop_on_failure) still appears in the attempt, with its reconciled
    // current assignment rather than a generated desired generation.
    for a in &assignments {
        if !results.contains_key(&a.placement_slot) {
            let cur = statuses
                .get(&a.placement_slot)
                .and_then(|s| s.current_generation.clone())
                .map(GenerationId::new);
            results.insert(
                a.placement_slot.clone(),
                ServerResult {
                    slot_id: a.placement_slot.clone(),
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
            // slot stays advanced and the attempt is marked Degraded.
            let vars = slot_vars(
                &members,
                config,
                target_name,
                sid,
                plan_servers[sid].artifact.variant.as_str(),
                Some(deployment_id),
                Some(&new_gen[sid]),
                Some(&plan_servers[sid].artifact.tree),
            )?;
            let ok = compensate_server(
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                prior,
                &new_gen[sid],
                config,
                &vars,
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

    // 15. Fleet-commit markers (only for otherwise-successful attempts). The
    // demotion reason is recorded alongside the final transition so `deploy
    // log` can explain why an attempt ended up `PendingCommit` or `Degraded`
    // (e.g. "recoverable metadata failure", "marker integrity conflict").
    let mut commit_status = status.clone();
    let mut commit_reason: Option<&'static str> = None;
    if status == DeploymentStatus::Successful {
        // The full placement-slot set participating in this fleet commit.
        let slot_ids: Vec<String> = servers_order
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
                    commit_reason = Some("recoverable metadata failure");
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
                    // commit incomplete and keep going. A later push reconciles
                    // this `PendingCommit` attempt (see
                    // `reconcile_pending_commits`) before its own no-op check.
                    commit_status = DeploymentStatus::PendingCommit;
                    commit_reason = Some("recoverable metadata failure");
                    continue;
                }
            };
            if cur.as_deref() != Some(new_gen[sid].as_str()) {
                // The live generation no longer matches what we deployed: the
                // controller's view diverged, so this marker would be wrong.
                // Report Degraded rather than a falsely successful commit.
                commit_status = DeploymentStatus::Degraded;
                commit_reason = Some("fleet commit diverged");
                continue;
            }
            match helper.write_commit_marker(
                deployment_id.as_str(),
                new_gen[sid].as_str(),
                &slot_ids,
            ) {
                Err(Error::Integrity(_)) => {
                    // A conflicting marker already exists with different
                    // content: a concurrent controller recorded a different
                    // fact, or the remote state diverged/corrupted. This is a
                    // PERMANENT condition — retrying will never fix it, and
                    // leaving the attempt `PendingCommit` would strand it
                    // forever (every later push re-hits the same integrity
                    // error). Finalize as `Degraded` (no snapshot entry) rather
                    // than falsely reporting `Successful`.
                    commit_status = DeploymentStatus::Degraded;
                    commit_reason = Some("marker integrity conflict");
                    continue;
                }
                Err(_) => {
                    // Recoverable metadata failure writing the marker: the
                    // attempt is recorded `PendingCommit` and a later push's
                    // `reconcile_pending_commits` completes the marker set
                    // before its no-op check.
                    commit_status = DeploymentStatus::PendingCommit;
                    continue;
                }
                Ok(_) => {}
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
                commit_reason = Some("recoverable metadata failure");
                break;
            }
        }
    }

    // 16 & 17. Record attempt, history, rotation.
    //
    // `actual_servers` reflects each slot's *real* final state, read from the
    // remote generation it currently points at, rather than the desired plan
    // values. Failed/skipped/restored slots therefore report their actual
    // artifact instead of the desired one.
    let mut actual_servers: BTreeMap<PlacementSlotId, AttemptServer> = BTreeMap::new();
    for a in &assignments {
        let sid = &a.placement_slot;
        let helper = &helpers[sid];
        let final_gen = helper.status().ok().and_then(|s| s.current_generation);
        let actual = match final_gen {
            Some(g) => match helper.read_assignment(&g) {
                Ok(asn) => AttemptServer {
                    artifact: asn.artifact.clone(),
                    generation: Some(GenerationId::new(g)),
                },
                Err(_) => {
                    // The generation is observed (`g`), but its assignment could
                    // not be read. Never substitute the planned (desired)
                    // artifact for a failed observation: preserve the observed
                    // generation and mark the assignment unknown rather than
                    // fabricating desired state.
                    AttemptServer {
                        artifact: ArtifactRef::default(),
                        generation: Some(GenerationId::new(g)),
                    }
                }
            },
            None => AttemptServer {
                artifact: a.artifact.clone(),
                generation: None,
            },
        };
        actual_servers.insert(sid.clone(), actual);
    }
    // `desired` (each slot's minted generation for its planned artifact, as a
    // complete [`GenerationRef`]) was computed BEFORE the mutation loop and
    // persisted as part of the immutable intent (`attempt_intent`); it is not
    // recomputed here.

    // 16 & 17. Record outcomes, finalize, history, rotation. The append-only
    // attempts.jsonl record (persisted BEFORE the mutation loop) keeps only
    // the immutable intent; the ACTUAL per-slot outcomes are recorded
    // separately in `deployments/<id>/results.json` — the outcomes store the
    // snapshot and observed state are built from. The REPORT's attempt also
    // carries the actuals (for display / rollback); the persisted record does
    // not.
    let attempt = DeploymentAttempt {
        slots: actual_servers.clone(),
        ..attempt_intent.clone()
    };
    store.write_results(
        deployment_id.as_str(),
        &DeploymentResults {
            deployment_id: deployment_id.clone(),
            target: TargetName::new(target_name.to_string()),
            slots: results.clone(),
        },
    )?;

    // Finalize the attempt's terminal status REPLAY-SAFELY. A SUCCESSFUL
    // attempt goes through the SAME shared finalizer as recovery
    // ([`history::finalize_successful_attempt`]): first the
    // recoverable `PendingCommit` marker is persisted (so a crash
    // mid-finalization leaves the attempt re-eligible — its latest
    // transition is `PendingCommit`, never a prematurely-written
    // `Successful`), then the idempotent snapshot append and
    // `refs/last-successful`, and the terminal `Successful` transition is
    // written LAST. The snapshot is built from the actual per-slot OUTCOMES
    // (`actual_servers`), not from the intent record. A non-successful final
    // status (`Degraded` / `PendingCommit` demoted by the fleet-commit step)
    // is a plain transition append; it produces no snapshot entry.
    let mut message = format!("push status: {commit_status:?}");
    if commit_status == DeploymentStatus::Successful {
        // The snapshot records each slot's physical server binding so an exact
        // rollback can verify a slot still lives on the host it was deployed
        // onto (a rebound slot must refuse rather than deploy to the wrong
        // host). The binding comes from the CURRENT configuration: it is the
        // live placement this attempt actually used. The snapshot itself is
        // built from the actual per-slot OUTCOMES (`actual_servers`), never
        // from the intent record.
        let slot_servers = config.target_slot_servers(target_name)?;
        let idx = history::finalize_successful_attempt(
            store,
            &attempt_intent,
            &actual_servers,
            "push completed",
            &slot_servers,
        )?;
        message = format!("push successful; fleet ref {}@f{idx}", target_name);
    } else {
        store.append_transition(deployment_id.as_str(), &commit_status, commit_reason)?;
    }

    // Refresh observed state. Observed maps are keyed by placement slot (the
    // deployment-location identity); the per-server record (`servers/<id>.json`)
    // keeps the actual [`crate::model::ServerId`] for transport identity.
    let mut observed = ObservedTarget {
        target: TargetName::new(target_name.to_string()),
        slots: Default::default(),
    };
    for (slot, sdef) in &members {
        let slot_id = PlacementSlotId::new(slot.id.clone());
        let Some(asv) = actual_servers.get(&slot_id) else {
            continue;
        };
        let observed_server = ObservedServer {
            generation: asv.generation.clone(),
            artifact: Some(asv.artifact.clone()),
            last_deployment: Some(deployment_id.clone()),
        };
        observed
            .slots
            .insert(slot_id.clone(), observed_server.clone());
        store.write_server(&crate::records::ServerState {
            id: crate::model::ServerId::new(sdef.id.clone()),
            last_seen_target: Some(TargetName::new(target_name.to_string())),
            last_observed: Some(observed_server),
        })?;
    }
    store.write_observed(target_name, &observed)?;

    // 17. Per-slot rotation under each slot's mutation lock. Rotation uses
    // the slot's ACTUAL final assignment (read after any compensation), not
    // the desired plan: a compensated slot restored its prior variant. The
    // retention policy is the target's `rotation` configuration from
    // `deploy.toml`, so it applies uniformly regardless of which variant each
    // slot ended up running.
    for sid in &servers_order {
        let helper = &helpers[sid];
        if helper.acquire_lock(op_id.as_str(), false).is_ok() {
            let retained = compute_retained(helper, &config.pins, store, &target.rotation)?;
            let active_incoming = HashSet::from([deployment_id.as_str().to_string()]);
            helper.rotate(&retained, &active_incoming)?;
            helper.release_lock(op_id.as_str())?;
        }
        // Clean up this deployment's incoming directory. Best-effort by
        // design: the push already succeeded, so a leftover here cannot change
        // the reported outcome, and the next push's reconciliation removes
        // abandoned incoming dirs explicitly. Same for the (already released)
        // lock file: releasing the advisory lock again is a no-op, and a
        // stale lock file is re-acquired harmlessly next time.
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

/// Reconcile incomplete attempts recorded by earlier pushes (steps 15 of
/// `requirement.md`). An attempt is eligible when its fleet-commit markers
/// were not all durable and/or its finalization never completed — the latest
/// transition is `PendingCommit` (markers missing: the earlier push gave up
/// during the metadata phase) OR `InProgress` (the intent was persisted before
/// mutation but finalization never started/completed — e.g. a crash between
/// `append_attempt` and the finalize marker, or a faulted `write_results`);
/// the snapshot log never advanced, and a naive "Everything up to date" push
/// would otherwise skip the missing markers/finalization.
///
/// Eligibility is determined by the attempt's LATEST transition
/// (`deployments/<id>/transitions.jsonl`), not the append-only
/// `attempts.jsonl` record (which carries no status at all): an attempt is
/// reconciled only while its latest transition is `PendingCommit` or
/// `InProgress` (or no transition exists yet for a just-recorded attempt).
/// Once a push finalizes the attempt with a `Successful` or `Degraded`
/// transition, it is skipped on every later push — a finalized attempt is
/// never re-reconciled and never re-entered into the snapshot log.
///
/// For each eligible attempt, oldest first (attempts.jsonl order, so
/// snapshot indices stay monotonic):
/// 1. Membership: every participating server must still exist in the target.
/// 2. Generations: each participating server's CURRENT generation (fresh
///    `helper.status()`) must equal the generation the attempt recorded for it
///    (`desired[server].generation`, falling back to `servers[server].generation`).
/// 3. If everything matches, write the missing markers under each server's
///    mutation lock (idempotent: already-written markers are a byte-for-byte
///    no-op) using the attempt's ORIGINAL deployment ID, then finalize
///    REPLAY-SAFELY through the SAME shared finalizer as the main success
///    path ([`history::finalize_successful_attempt`]): the recoverable
///    `PendingCommit` marker step is a no-op here when the latest transition
///    is already `PendingCommit` (for an `InProgress` attempt it appends the
///    marker — the attempt becomes re-eligible), then the idempotent snapshot
///    entry + `refs/last-successful` repair ([`history::ensure_snapshot`]),
///    and the final `Successful` transition LAST. The snapshot is built from
///    the attempt's OUTCOMES — `deployments/<id>/results.json` when present,
///    else the verified desired state
///    ([`history::resolve_attempt_outcomes`]). The latest transition is the
///    eligibility gate for recovery: as long as it still says `PendingCommit`
///    (or `InProgress`), any crash or error mid-finalization leaves the attempt
///    eligible and the next push replays exactly the remaining steps; once it
///    says `Successful`, every earlier step is already durable, so nothing is
///    lost.
/// 4. A confirmed membership/generation mismatch finalizes the attempt as
///    `Degraded` (no snapshot entry). An existing marker whose content differs
///    from the deterministic payload is an integrity conflict — a concurrent
///    controller recorded a different fact or the remote state diverged — and
///    is NOT transient: the conflicting marker is left untouched and the
///    attempt is finalized `Degraded` (transition only, no snapshot entry)
///    instead of being stranded `PendingCommit` forever. Only transient remote
///    failures (lock held, status read error, transport-level marker write
///    error) leave the attempt `PendingCommit` for a later retry: it is never
///    falsely marked `Successful` (markers are missing) and never falsely
///    accused of divergence (fail-closed, not degrade, on errors we cannot
///    attribute to state change).
///
/// Recovery only touches markers, the transition stream, the snapshot log,
/// and `refs/last-successful`: no activation, no verification adapters, no
/// `current` changes, no restart of healthy services.
fn reconcile_pending_commits(
    store: &LocalStore,
    config: &Config,
    target_name: &str,
    op_id: &OperationId,
    helpers: &HashMap<PlacementSlotId, RemoteHelper>,
) -> Result<()> {
    // Eligible attempts: the attempts.jsonl record must exist AND the latest
    // transition must be `PendingCommit` or `InProgress` (or the transition
    // stream is momentarily absent for a just-recorded attempt). A finalized
    // attempt (latest transition `Successful` / `Degraded`, or any other
    // non-eligible status) is skipped — an already-reconciled attempt is
    // never re-reconciled on a later push. `InProgress` is eligible because
    // the intent is now persisted BEFORE any remote mutation: a crash after
    // the mutation phase but before finalization leaves the latest transition
    // `InProgress` with the servers already at the desired generations, and
    // skipping it would strand the deployment unrecoverable (the next push
    // would see everything up to date but never record a snapshot/ref).
    let mut pending: Vec<DeploymentAttempt> = Vec::new();
    for attempt in store.read_attempts(target_name)? {
        match store.latest_status(attempt.deployment_id.as_str())? {
            // No transition recorded yet: legitimately new pending attempt.
            None => pending.push(attempt),
            Some(DeploymentStatus::PendingCommit) => pending.push(attempt),
            // Intent persisted but finalization never completed: recover it
            // exactly like a pending attempt (the finalizer appends the
            // recoverable `PendingCommit` marker first, since the latest
            // transition is not yet `PendingCommit`).
            Some(DeploymentStatus::InProgress) => pending.push(attempt),
            // Finalized on an earlier push (Successful/Degraded): skip.
            Some(_) => {}
        }
    }
    if pending.is_empty() {
        return Ok(());
    }

    // Current target membership: a pending attempt whose participants were
    // removed from the target can no longer be completed as a fleet commit.
    let members: HashSet<String> = config
        .target_slots(target_name)?
        .iter()
        .map(|(slot, _)| slot.id.clone())
        .collect();
    // The slot→server binding map recorded into snapshots finalized by
    // recovery (identical to the map the original commit would have recorded).
    let slot_servers = config.target_slot_servers(target_name)?;

    'pending: for attempt in pending {
        // 1. Membership check.
        let membership_ok = attempt
            .slot_ids
            .iter()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            store.append_transition(
                attempt.deployment_id.as_str(),
                &DeploymentStatus::Degraded,
                Some("membership mismatch"),
            )?;
            continue;
        }

        // 2. Generation verification against fresh remote status reads.
        // `recorded` collects the generation the attempt minted for each
        // slot (the same value step 15 compared against when writing the
        // markers), so recovery writes markers identical to what the original
        // commit would have written.
        let mut recorded: BTreeMap<PlacementSlotId, GenerationId> = BTreeMap::new();
        let mut all_match = true;
        let mut unverifiable = false;
        for sid in &attempt.slot_ids {
            let Some(recorded_gen) = attempt
                .desired
                .get(sid)
                .map(|d| d.generation.clone())
                .or_else(|| attempt.slots.get(sid).and_then(|s| s.generation.clone()))
            else {
                // No recorded generation for a participant: the attempt is not
                // a coherent fleet commit; finalize as degraded.
                all_match = false;
                break;
            };
            let Some(helper) = helpers.get(sid) else {
                all_match = false;
                break;
            };
            match helper.status() {
                Ok(st) if st.current_generation.as_deref() == Some(recorded_gen.as_str()) => {
                    recorded.insert(sid.clone(), recorded_gen);
                }
                Ok(_) => {
                    // Confirmed divergence: the slot no longer points at the
                    // generation this attempt minted.
                    all_match = false;
                    break;
                }
                Err(_) => {
                    // Transient status read failure: cannot verify, so leave
                    // the attempt pending for a later retry (fail-closed).
                    unverifiable = true;
                    break;
                }
            }
        }
        if unverifiable {
            continue;
        }
        if !all_match {
            store.append_transition(
                attempt.deployment_id.as_str(),
                &DeploymentStatus::Degraded,
                Some("generation diverged"),
            )?;
            continue;
        }

        // 3. Write the missing markers under each slot's mutation lock
        // (mirroring step 15's lock discipline: the guard is held for the
        // whole write and released on drop). The marker payload carries the
        // full participating slot set; already-present markers are an
        // idempotent byte-for-byte no-op.
        let slot_ids: Vec<String> = attempt
            .slot_ids
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        let mut markers_written = true;
        for sid in &attempt.slot_ids {
            let helper = &helpers[sid];
            let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
                Ok(g) => g,
                Err(_) => {
                    // Lock transiently held elsewhere: keep the attempt pending
                    // so a later push retries rather than degrading a healthy
                    // attempt on a transient blip.
                    markers_written = false;
                    break;
                }
            };
            match helper.write_commit_marker(
                attempt.deployment_id.as_str(),
                recorded[sid].as_str(),
                &slot_ids,
            ) {
                Err(Error::Integrity(_)) => {
                    // Conflicting marker already exists with different
                    // content: a permanent condition, not a transient blip.
                    // Leave the conflicting marker untouched, finalize THIS
                    // attempt as `Degraded` (transition only, no snapshot
                    // entry) and move on to the next pending attempt — a later
                    // retry would only hit the same integrity error again.
                    store.append_transition(
                        attempt.deployment_id.as_str(),
                        &DeploymentStatus::Degraded,
                        Some("marker integrity conflict"),
                    )?;
                    continue 'pending;
                }
                Err(_) => {
                    // Marker not durable yet: leave the attempt pending.
                    markers_written = false;
                    break;
                }
                Ok(_) => {}
            }
            // `_guard` drops here, releasing the lock.
        }
        if !markers_written {
            continue;
        }

        // 4. Finalize REPLAY-SAFELY through the SAME shared finalizer as the
        //    main success path ([`history::finalize_successful_attempt`]):
        //    the recoverable `PendingCommit` marker step is a no-op here when
        //    the attempt's latest transition is already `PendingCommit` (for
        //    an `InProgress` attempt it appends the marker — the eligibility
        //    gate for recovery), then the idempotent snapshot
        //    insert + `refs/last-successful` repair
        //    ([`history::ensure_snapshot`] never appends a second entry for
        //    the same deployment), and the terminal `Successful` transition
        //    LAST. A crash or error at ANY of these steps leaves the attempt
        //    eligible (`PendingCommit` / `InProgress`) and the next push
        //    replays exactly the remaining steps; once the transition says
        //    `Successful`, every earlier step is already durable. The
        //    append-only attempts.jsonl record is untouched (still the
        //    original deployment ID, no status field, no outcomes). The
        //    snapshot is built from the attempt's OUTCOMES —
        //    `deployments/<id>/results.json` when present, else the verified
        //    desired state ([`history::resolve_attempt_outcomes`]) — and
        //    records each slot's physical server binding from the current
        //    config (`slot_servers`), so rollback can verify a slot still
        //    lives on the host it was deployed onto.
        let outcomes = history::resolve_attempt_outcomes(store, &attempt)?;
        history::finalize_successful_attempt(
            store,
            &attempt,
            &outcomes,
            "recovery finalized",
            &slot_servers,
        )?;
    }
    Ok(())
}

struct ServerProc {
    kind: ServerOutcomeKind,
    generation: GenerationId,
    did_compensate: bool,
    error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn process_server(
    store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    artifact: &ArtifactRef,
    new_gen: &GenerationId,
    expected_gen: Option<&GenerationId>,
    behavior: &BehaviorContract,
    behavior_sha256: &str,
    template_vars: &crate::template::TemplateVars,
    config: &Config,
) -> Result<ServerProc> {
    // Acquire the slot's mutation lock via an RAII guard so every return path
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
    if let Err(e) = helper.publish_from_incoming(deployment_id.as_str(), artifact.tree.as_str()) {
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
    let object_rel = layout::tree_root(artifact.tree.as_str());
    if let Err(e) = download_tree_to_host(remote, &object_rel, verify_tmp.path()) {
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
    if meta.tree_sha256 != artifact.tree.as_str() {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!(
                "integrity: remote tree digest {} does not match requested {}",
                meta.tree_sha256, artifact.tree
            )),
        });
    }

    // 3. Validate all declared artifact paths and types before changing current.
    if let Err(e) = validate_artifact_paths(remote, &object_rel, &behavior.activation) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("artifact validation: {e}")),
        });
    }

    // 4. Publish the release record (idempotent) and create the generation.
    if let Some((release_json, behavior_json)) =
        REMOTE_RELEASE_JSON.with(|c| c.borrow().get(&artifact.release).cloned())
        && let Err(e) =
            helper.publish_release(artifact.release.as_str(), &release_json, &behavior_json)
    {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_compensate: false,
            error: Some(format!("publish release failed: {e}")),
        });
    }
    let assignment = crate::remote::helper::GenerationAssignment {
        deployment_id: deployment_id.clone(),
        generation_id: new_gen.clone(),
        artifact: artifact.clone(),
        behavior_sha256: behavior_sha256.to_string(),
        prior_generation: expected_gen.cloned(),
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

    // Atomically move `current` (the per-slot commit point).
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
    // The generation's tree content root: `generations/<gen>/root` is a
    // symlink to `objects/sha256/<tree>/root`, the same directory `current`
    // points at (it is the tree content root, not a nested `root/root`).
    let generation_root = remote
        .root()
        .join(layout::generation(new_gen.as_str()))
        .join("root");

    // Activation adapter. On failure, compensate (current was advanced).
    if let Err(e) = run_activation(
        remote,
        &generation_root,
        &behavior.activation,
        template_vars,
    ) {
        let comp = compensate_server(
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            expected_gen,
            new_gen,
            config,
            template_vars,
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
    if let Err(e) = run_verification(remote, &behavior.verification, template_vars) {
        let comp = compensate_server(
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            expected_gen,
            new_gen,
            config,
            template_vars,
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
    // A later push's `reconcile_pending_commits` completes the marker set
    // without touching the healthy server when its generation still matches.
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
/// configuration. `advanced_gen` is the generation this slot was just advanced
/// to; it is used as the compare-and-swap precondition so a concurrent
/// controller cannot have its `current` clobbered. `template_vars` supplies the
/// slot context (deploy_dir, application, ...); the VARIANT is overridden with
/// the prior assignment's variant, because compensation re-runs the PRIOR
/// generation's contract. Returns true if compensation restored prior state.
#[allow(clippy::too_many_arguments)]
fn compensate_server(
    _store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    _deployment_id: &DeploymentId,
    prior_gen: Option<&GenerationId>,
    advanced_gen: &GenerationId,
    _config: &Config,
    template_vars: &crate::template::TemplateVars,
) -> Result<bool> {
    // Hold the slot's mutation lock for the duration of compensation. Re-acquiring
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
                    &prior_assignment.artifact.release,
                    prior_assignment.artifact.variant.as_str(),
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
                .join(layout::generation(prior.as_str()))
                .join("root");
            // Re-run prior activation contract + verification. A failure means the
            // service was not actually restored to prior behavior, so propagate
            // it as a compensation failure (the attempt is marked Degraded).
            // The prior contract is rendered with the PRIOR variant (a restored
            // slot may switch variants, and its unit content/argv must resolve
            // for the variant that is actually being restored).
            let prior_vars = template_vars.with_variant(prior_assignment.artifact.variant.as_str());
            run_activation(remote, &root, &prior_behavior.activation, &prior_vars)
                .map_err(|e| Error::remote(format!("compensation activation failed: {e}")))?;
            run_verification(remote, &prior_behavior.verification, &prior_vars)
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
    let root_rel = layout::tree_root(digest.as_str());
    if !remote.exists(&root_rel) {
        return Ok(());
    }
    let tmp = store
        .staging_dir()
        .join(format!("recover-{}", digest.as_str()));
    // A stale `recover-<digest>` dir can survive an interrupted earlier
    // recovery, and downloaded trees carry remote file modes (read-only
    // dirs/files), so removal can fail with EACCES. Removal is EXPLICIT and
    // FALLIBLE: restore owner-write inside the stale tree, then remove it. A
    // stale temp that cannot be removed aborts the recovery loudly instead of
    // letting `download_tree_to_host` write INTO the stale dir and
    // `store.store_object` persist a mixed (stale leftovers + fresh content)
    // tree under the digest. A missing temp is a no-op.
    if tmp.exists() {
        remove_tree_restoring_write(&tmp, "remove stale recovery temp")?;
    }
    download_tree_to_host(remote, &root_rel, &tmp)?;
    store.store_object(digest, &tmp)?;
    // Explicit FALLIBLE cleanup of the disposable download temp before
    // returning, so a successful recovery never leaves `recover-<digest>`
    // behind (a leftover that a later recovery would treat as stale and that
    // could accumulate read-only content). `store_object` copies, so the temp
    // is no longer needed; a cleanup failure surfaces as an error naming the
    // path, mirroring the dry-run staging cleanup.
    remove_tree_restoring_write(&tmp, "remove recovery temp")?;
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
            // Best-effort prep: in the only caller (`recover_if_missing`) the
            // destination tree is freshly downloaded, so `dest` does not exist
            // and remove_file returns NotFound. If a stale entry did linger, the
            // subsequent symlink fails loudly with EEXIST rather than silently
            // producing a wrong tree.
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
        if !behaviors.contains_key(a.artifact.variant.as_str()) {
            missing
                .entry(a.artifact.variant.as_str())
                .or_default()
                .push(a.placement_slot.as_str());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let detail = missing
        .iter()
        .map(|(variant, slots)| format!("variant '{variant}' (slots: {})", slots.join(", ")))
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
/// Capacity headroom is a per-server policy declared on the top-level
/// `[[servers]]` entry (`ServerDef.capacity`) and is ALWAYS resolved from the
/// caller's current `deploy.toml` — for HEAD pushes and historical/rollback
/// pushes alike. Servers have no per-release history, so capacity is never
/// part of the release snapshot: the release identity covers mappings,
/// behavior, and trees only. Rotation (used for the protected pre-rotation) is
/// target-level configuration from `deploy.toml`.
#[allow(clippy::too_many_arguments)]
fn capacity_preflight(
    store: &LocalStore,
    assignments: &[crate::push::plan::PlannedAssignment],
    helpers: &HashMap<PlacementSlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    config: &Config,
    rotation: &crate::config::RotationConfig,
) -> Result<()> {
    for a in assignments {
        // Resolve the server's CURRENT capacity policy for this assignment.
        // Capacity is a per-server policy resolved from the caller's current
        // config (never a release snapshot). The assignment names a placement
        // slot; the slot binds one server. A miss is an internal invariant
        // violation: the assignment was planned against this config.
        let slot = config
            .slot_defs()
            .into_iter()
            .find(|s| s.id.as_str() == a.placement_slot.as_str())
            .expect("assignment slot present in config");
        let server = config
            .servers
            .iter()
            .find(|s| s.id == slot.server)
            .expect("slot's server present in config");
        let capacity = &server.capacity;
        let reserve_bytes = capacity.reserve_bytes;
        let reserve_percent = capacity.reserve_percent as f64 / 100.0;
        let helper = helpers.get(&a.placement_slot).expect("helper present");
        if helper.tree_exists(a.artifact.tree.as_str()) {
            continue;
        }
        let need = tree_size_on_host(&store.object_root(&a.artifact.tree));
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
            // Run protected rotation using the target's rotation policy, then
            // recheck capacity directly rather than failing the restore.
            // Best-effort by design: rotation is only an optimization to free
            // capacity, and the hard capacity check below decides the outcome.
            // A rotation failure is not recoverable at this point (the push
            // would have to abort mid-preflight), and the recheck fails the
            // push loudly if space is genuinely short.
            if helper.acquire_lock(op_id.as_str(), false).is_ok() {
                let retained = compute_retained(helper, &config.pins, store, rotation)?;
                let active = HashSet::from([deployment_id.as_str().to_string()]);
                helper.rotate(&retained, &active).ok();
                helper.release_lock(op_id.as_str()).ok();
            }
            let avail2 = helper.remote().available_bytes().unwrap_or(0);
            if need + reserve > avail2 {
                return Err(Error::preflight(format!(
                    "insufficient capacity on slot {}: need {} + reserve {} > avail {}",
                    a.placement_slot, need, reserve, avail2
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

/// Restore owner-write permission (u+w, mode bit 0o200) on every directory and
/// file under `root` that lacks it, leaving all other mode bits untouched.
/// Materialized dry-run staging trees can contain read-only entries — artifact
/// source modes are preserved by [`crate::mapper::materialize_variant`] — and
/// POSIX `remove_dir_all` needs write permission on every directory it enters,
/// so a read-only subdirectory makes the whole removal fail with EACCES.
/// Symlinks are never followed or modified.
fn restore_owner_write_recursive(root: &Path) -> std::io::Result<()> {
    fn walk(dir: &Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                walk(&path)?;
            } else if ft.is_symlink() {
                continue;
            }
            let mode = entry.metadata()?.permissions().mode();
            if mode & 0o200 == 0 {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode | 0o200))?;
            }
        }
        Ok(())
    }
    walk(root)?;
    let mode = std::fs::metadata(root)?.permissions().mode();
    if mode & 0o200 == 0 {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(mode | 0o200))?;
    }
    Ok(())
}

/// Remove a directory tree, restoring owner-write permission on read-only
/// entries inside it first, then removing the whole tree. A missing tree is a
/// no-op. `remove_dir_all` needs write permission on every directory it enters
/// AND on the tree's parent; restoring u+w inside the tree fixes read-only
/// entries preserved from artifact source modes, but never the parent (that is
/// outside the tree's responsibility). Failures map to [`Error::transport`]
/// with `what` and the path in the message, so every caller (dry-run staging
/// cleanup, recovery temp removal) fails visibly instead of silently leaking
/// the tree.
fn remove_tree_restoring_write(root: &Path, what: &str) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    restore_owner_write_recursive(root)
        .map_err(|e| Error::transport(format!("{what} {}: {e}", root.display())))?;
    std::fs::remove_dir_all(root)
        .map_err(|e| Error::transport(format!("{what} {}: {e}", root.display())))?;
    Ok(())
}

/// Remove a dry-run's staging tree, propagating failures. Restores owner-write
/// permission on read-only entries inside the tree first (the tree cannot fix
/// permissions on its own parent), then removes the whole tree. A missing tree
/// is a no-op. Failures map to [`Error::transport`] with the path in the
/// message, so a dry run whose staging could not be cleaned fails visibly
/// instead of silently leaving `staging/dry-<id>` behind forever.
fn cleanup_dry_run_staging(root: &Path) -> Result<()> {
    remove_tree_restoring_write(root, "remove dry-run staging")
}

/// Removes the disposable dry-run staging tree on drop (error, panic, or
/// normal exit), so an interrupted dry run never leaves state behind. This is
/// only a FALLBACK: the normal dry-run path runs the explicit fallible
/// [`cleanup_dry_run_staging`] and empties the guard first, so cleanup failures
/// surface as a push error rather than being silently swallowed. The Drop
/// performs the same permission-restore + remove best-effort (still silent),
/// so even panic/unwind paths clean read-only trees when they can.
struct StagingCleanup(Option<std::path::PathBuf>);
impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = cleanup_dry_run_staging(&p);
        }
    }
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
        // Best-effort by design, like the other Drop fallbacks: this runs on
        // every return path (including panic/unwind), so a failure must not
        // surface, and a stale lock file is re-acquired harmlessly next time
        // (the flock itself is released by the kernel when the fd drops).
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
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const NONE_VARIANT: &str = r#"
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

    const NONE_TOML: &str = r#"
schema_version = 1
application = "eng"
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

    const SYSTEMD_VARIANT: &str = r#"
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
"#;

    const SYSTEMD_TOML: &str = r#"
schema_version = 1
application = "eng"
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
                &crate::template::TemplateVars::mapping(
                    &config.application,
                    config.release.as_str(),
                    "standard",
                ),
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
            // Slot context from the harness config (one slot p1 on server s1,
            // target t1, deploy_dir /srv/eng).
            let members = self.config.target_slots("t1").unwrap();
            let (slot, server) = members[0];
            let vars = crate::template::TemplateVars::slot(
                &slot.deploy_dir,
                "standard",
                &self.config.application,
                self.config.release.as_str(),
                "t1",
                &server.id,
            )
            .with_server(&server.user, &server.address, server.port)
            .with_slot_id(&slot.id)
            .with_deployment(Some(&deployment_id), Some(&new_gen), Some(&self.tree));
            process_server(
                &self.store,
                &self.remote,
                &helper,
                &op_id,
                &deployment_id,
                &ArtifactRef {
                    release: ReleaseId::new("r1".to_string()),
                    variant: VariantName::new("standard".to_string()),
                    tree: self.tree.clone(),
                },
                &new_gen,
                expected_gen.as_ref(),
                &behavior,
                &sha,
                &vars,
                &self.config,
            )
            .unwrap()
        }

        fn helper(&self) -> RemoteHelper<'_> {
            RemoteHelper::new(&self.remote)
        }
    }

    #[test]
    fn staging_cleanup_drop_removes_tree_take_prevents_removal() {
        let base = tempfile::tempdir().unwrap();

        // Drop removes the whole staging tree.
        let p = base.path().join("dry-a");
        std::fs::create_dir_all(p.join("nested")).unwrap();
        std::fs::write(p.join("nested/f"), b"x").unwrap();
        {
            let _g = StagingCleanup(Some(p.clone()));
            assert!(p.exists(), "tree survives while the guard is held");
        }
        assert!(!p.exists(), "drop must remove the staging tree");

        // Dropping a None guard is a no-op (non-dry-run path).
        drop(StagingCleanup(None));

        // take() hands ownership out: dropping the emptied guard keeps the
        // tree, dropping the taken value removes it.
        let q = base.path().join("dry-b");
        std::fs::create_dir_all(&q).unwrap();
        let mut g = StagingCleanup(Some(q.clone()));
        let taken = g.0.take();
        assert!(taken.is_some(), "take must yield the guarded path");
        drop(g);
        assert!(q.exists(), "emptied guard's drop must not remove anything");
        // Responsibility was handed out with take(): whoever re-wraps the path
        // into a guard gets cleanup on their own drop.
        drop(StagingCleanup(taken));
        assert!(!q.exists(), "the re-wrapped taken value cleans up on drop");
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
        assert!(h.remote.exists(layout::current()));
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
            .join(crate::layout::objects())
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
        assert!(!h.remote.exists(layout::current()));
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

    /// Regression: the engine must hand the activation adapter
    /// `<remote>/generations/<gid>/root` (the `root` symlink to the tree
    /// content root) as the generation root — never a nested `root/root`. A
    /// full push with the systemd adapter exercises the real path
    /// construction at both `run_activation` call sites; staging reads the
    /// unit from `generations/<gid>/root/<artifact>`, so a `root/root`
    /// double-join would ENOENT and the push would never reach Activated.
    /// Fake `systemctl` in PATH and a temp `XDG_CONFIG_HOME` keep the
    /// activation hermetic (same pattern as the adapter end-to-end test; the
    /// shared `ENV_LOCK` serializes env-mutating tests).
    #[test]
    fn systemd_push_activation_uses_generation_root_not_nested() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        // Fake systemctl (daemon-reload/enable/restart all succeed) and a temp
        // config home so the installed unit lands somewhere hermetic.
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        let old_path = std::env::var_os("PATH");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bindir.display(),
                    old_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
            );
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }

        let outcome = (|| {
            let h = Harness::new(
                SYSTEMD_TOML,
                SYSTEMD_VARIANT,
                &[
                    ("build/output/app/server", "v1"),
                    ("deployment/common/README", "common"),
                    (
                        "units/example.service",
                        "[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
                    ),
                ],
            );
            let proc = h.run(None);
            // The activation read the unit from `generations/<gid>/root`
            // (through the `root` symlink into the tree content root). A
            // `root/root` double-join would fail that read and never reach
            // Activated.
            assert_eq!(
                proc.kind,
                ServerOutcomeKind::Activated,
                "activation failed (root/root double-join?): {:?}",
                proc.error
            );
            assert!(!proc.did_compensate);
            let gen_root = h
                .remote
                .root()
                .join(crate::layout::generation(proc.generation.as_str()))
                .join("root");
            assert!(
                gen_root.ends_with(
                    Path::new("generations")
                        .join(proc.generation.as_str())
                        .join("root")
                ),
                "activation generation root must be <root>/generations/<gid>/root, got {}",
                gen_root.display()
            );
            assert!(
                !gen_root.to_string_lossy().contains("root/root"),
                "activation generation root must not be a nested root/root"
            );
            // The double-joined path resolves to nothing on the published
            // layout: the tree content root has no nested `root` directory.
            assert!(
                !h.remote
                    .root()
                    .join(crate::layout::generation(proc.generation.as_str()))
                    .join("root/root")
                    .exists(),
                "published tree must have no nested root dir (root/root double-join would ENOENT)"
            );
            // The installed unit's content proves staging read the artifact
            // through `generations/<gid>/root` and rendered it with the slot
            // context (deploy_dir /srv/eng from the variant).
            let installed = config_home.join("systemd/user/example.service");
            assert_eq!(
                std::fs::read_to_string(&installed).unwrap(),
                "[Service]\nExecStart=/srv/eng/current/app/server\n"
            );
            Ok::<(), String>(())
        })();
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        match old_xdg {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
        outcome.unwrap();
    }

    #[test]
    fn dry_run_removes_readonly_staging_tree() {
        // A dry-run staging tree containing read-only directories/files (modes
        // preserved from the artifact sources by materialize_variant) must be
        // fully removed before the push returns. Regression: the old Drop-only
        // cleanup swallowed remove_dir_all's EACCES and left `staging/dry-<id>`
        // (and every file inside it) behind forever.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), NONE_VARIANT).unwrap();
        std::fs::write(project.join("deploy.toml"), NONE_TOML).unwrap();
        let artifacts_dir = release_dir.join("artifacts");
        for (p, c) in [
            ("build/output/app/server", "v1"),
            ("deployment/common/README", "common"),
        ] {
            let fp = artifacts_dir.join(p);
            std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
            std::fs::write(&fp, c).unwrap();
        }
        // Make one artifact source directory AND one file read-only; their
        // modes are preserved into the staged tree, where they break
        // remove_dir_all unless the cleanup restores owner-write first.
        std::fs::set_permissions(
            artifacts_dir.join("deployment/common"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        std::fs::set_permissions(
            artifacts_dir.join("deployment/common/README"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();

        let config_path = project.join("deploy.toml");
        let config = Config::load(&config_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let factory = move |_s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(
                LocalTransport::new(remotes_base.join("s1")).unwrap(),
            ))
        };

        let r = push(
            &config_path,
            &store,
            &factory,
            "t1",
            &config,
            &PushOptions {
                dry_run: true,
                ref_token: None,
            },
        )
        .unwrap();
        assert!(r.dry_run);
        assert!(r.message.contains("dry-run plan"));

        // The read-only staged tree must actually be gone: no `dry-<id>` entry
        // (and no leftover files) may remain under the staging dir.
        let leftovers: Vec<String> = std::fs::read_dir(store.staging_dir())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("dry-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "read-only dry-run staging tree left behind: {leftovers:?}"
        );
        assert_eq!(
            std::fs::read_dir(store.staging_dir()).unwrap().count(),
            0,
            "no entries may remain under staging after a dry run"
        );
    }

    #[test]
    fn dry_run_cleanup_failure_is_reported() {
        // Injection: removing the staging root requires write permission on its
        // PARENT directory, and the cleanup only restores permissions INSIDE
        // its own tree (it must not touch anything outside). So a read-only
        // parent makes remove_dir_all fail with EACCES, and that failure must
        // surface as an Err — not a silent success that leaves the tree behind.
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("dry-x");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/f"), b"x").unwrap();
        // Parent becomes read-only AFTER the tree is built. This parent-side
        // injection is not reachable through a real materialize-then-push: a
        // push needs to CREATE the dry-<id> root inside staging, which requires
        // write on the parent at materialize time. So the failure injection is
        // unit-level, against the exact routine the dry-run branch calls;
        // the engine-level read-only-restore path is covered by
        // `dry_run_removes_readonly_staging_tree`.
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let err = cleanup_dry_run_staging(&root).unwrap_err();
        assert!(
            matches!(err, Error::Transport(_)),
            "cleanup failure must be a transport error, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("remove dry-run staging") && msg.contains("dry-x"),
            "error must name the staging root, got: {msg}"
        );
        // The tree was NOT silently swallowed: it is still present, and the
        // dry-run branch propagates this Err instead of returning Ok.
        assert!(
            root.exists(),
            "failed cleanup must not silently remove the tree"
        );

        // Restore the parent so the tempdir can clean up after the test.
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        // The fallback Drop still removes read-only trees best-effort when it
        // CAN (read-only entries INSIDE the tree): u+w is restored and the
        // whole tree is removed silently on drop.
        let p = base.path().join("dry-ro");
        std::fs::create_dir_all(p.join("sub")).unwrap();
        std::fs::write(p.join("sub/f"), b"y").unwrap();
        std::fs::set_permissions(p.join("sub"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(p.join("sub/f"), std::fs::Permissions::from_mode(0o444)).unwrap();
        {
            let _g = StagingCleanup(Some(p.clone()));
        }
        assert!(!p.exists(), "fallback Drop must clean a read-only tree");
    }

    #[test]
    fn recovery_removes_stale_readonly_temp_no_mixed_tree() {
        // A stale `recover-<digest>` temp (left by an interrupted earlier
        // recovery) with READ-ONLY content must be removed FALLIBLY during
        // recovery — restore owner-write, then remove_dir_all — so the
        // re-downloaded tree is never mixed with stale leftovers before being
        // stored under the digest. Regression: the old code swallowed
        // remove_dir_all's EACCES, downloaded INTO the stale dir, and
        // persisted a mixed tree (or failed verification).
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), NONE_VARIANT).unwrap();
        std::fs::write(project.join("deploy.toml"), NONE_TOML).unwrap();
        let artifacts_dir = release_dir.join("artifacts");
        for (p, c) in [
            ("build/output/app/server", "v1"),
            ("deployment/common/README", "common"),
        ] {
            let fp = artifacts_dir.join(p);
            std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
            std::fs::write(&fp, c).unwrap();
        }

        let config_path = project.join("deploy.toml");
        let config = Config::load(&config_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let remote_path = remotes_base.join("s1");
        let factory_path = remote_path.clone();
        let factory = move |_s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(factory_path.clone()).unwrap()))
        };

        // First push: deploys and publishes the tree into the remote object
        // store, which is what recovery later re-downloads from.
        let r0 = push(
            &config_path,
            &store,
            &factory,
            "t1",
            &config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .unwrap();
        assert_eq!(
            r0.status,
            Some(DeploymentStatus::Successful),
            "first push must deploy"
        );
        let tree = r0.attempt.expect("attempt recorded").slots[&PlacementSlotId::new("p1")]
            .artifact
            .tree
            .clone();

        // Drop the local object: recovery must re-fetch from the remote.
        std::fs::remove_dir_all(store.object_root(&tree)).unwrap();
        assert!(!store.object_exists(&tree), "local object removed");
        let remote_handle = LocalTransport::new(remote_path).unwrap();
        assert!(
            remote_handle.exists(&crate::layout::tree_root(tree.as_str())),
            "remote still retains the tree"
        );

        // Plant a stale recovery temp with READ-ONLY content, simulating a
        // crashed earlier recovery whose temp could not be removed.
        let tmp = store
            .staging_dir()
            .join(format!("recover-{}", tree.as_str()));
        std::fs::create_dir_all(tmp.join("stale-sub")).unwrap();
        std::fs::write(tmp.join("stale-sub/stale-file"), b"STALE").unwrap();
        std::fs::set_permissions(
            tmp.join("stale-sub"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        std::fs::set_permissions(
            tmp.join("stale-sub/stale-file"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();

        // Second push: a ROLLBACK to f0 cannot re-materialize the tree from
        // local artifacts (materialization only runs for HEAD pushes), so its
        // reconciliation must `recover_if_missing` the missing digest from the
        // remote. The stale read-only temp must be removed fallibly and must
        // NOT be mixed into the re-downloaded object.
        let r1 = push(
            &config_path,
            &store,
            &factory,
            "t1",
            &config,
            &PushOptions {
                dry_run: false,
                ref_token: Some("t1@f0".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            r1.status,
            Some(DeploymentStatus::Successful),
            "rollback push must deploy from the recovered object: {}",
            r1.message
        );

        // The stored object must contain ONLY the tree downloaded from the
        // remote: no stale leftovers mixed in.
        let obj = store.object_root(&tree);
        assert!(obj.exists(), "recovered object present");
        let meta = crate::tree::canonicalize_tree(&obj).unwrap();
        assert_eq!(
            meta.tree_sha256,
            tree.as_str(),
            "recovered object must be exactly the remote tree (no mixing)"
        );
        let stale: Vec<String> = std::fs::read_dir(&obj)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("stale"))
            .collect();
        assert!(
            stale.is_empty(),
            "stale temp content must not be mixed into the object: {stale:?}"
        );

        // The stale temp dir itself must be gone.
        assert!(!tmp.exists(), "stale recovery temp must be removed");
    }

    #[test]
    fn remove_tree_restoring_write_reports_removal_failure() {
        // Injection: removing the temp root requires write permission on its
        // PARENT directory, and the helper only restores permissions INSIDE
        // its own tree (it must not touch anything outside). So a read-only
        // parent makes remove_dir_all fail with EACCES even after the
        // owner-write restore, and that failure must surface as an Err naming
        // the path — never a silent swallow that lets a mixed tree be stored.
        // Mirrors `dry_run_cleanup_failure_is_reported`.
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("recover-x");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/f"), b"x").unwrap();
        // Read-only entries INSIDE the tree are fixed by the helper; only the
        // parent-side injection breaks removal.
        std::fs::set_permissions(root.join("nested"), std::fs::Permissions::from_mode(0o555))
            .unwrap();
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let err = remove_tree_restoring_write(&root, "remove stale recovery temp").unwrap_err();
        assert!(
            matches!(err, Error::Transport(_)),
            "removal failure must be a transport error, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("remove stale recovery temp") && msg.contains("recover-x"),
            "error must name the tree path, got: {msg}"
        );
        assert!(
            root.exists(),
            "failed removal must not silently remove the tree"
        );

        // Restore the parent so the tempdir can clean up after the test.
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
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
            &crate::template::TemplateVars::mapping(
                &config.application,
                config.release.as_str(),
                "standard",
            ),
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

    // ---- Replay-safe recovery finalization -------------------------------
    //
    // `reconcile_pending_commits` finalizes a recovered attempt with three
    // persistence steps, ordered ensure-snapshot (idempotent by deployment
    // ID) -> `refs/last-successful` (idempotent) -> final `Successful`
    // transition LAST. A crash at any step must leave the attempt
    // re-eligible, and a follow-up push must complete exactly the remaining
    // steps without duplicating the snapshot. These tests arm a one-shot
    // store fault keyed by the pending attempt's deployment ID (see
    // `src/store/local.rs::test_faults`) on each persistence step, run a push
    // that aborts mid-finalization, then run a clean push and assert
    // exactly-one semantics: one snapshot entry, `refs/last-successful`
    // pointing at the attempt, latest transition `Successful`, markers
    // present on the remotes.

    /// A remote that fails fleet-commit marker writes exactly once: the first
    /// write/create under `state/commits/` errors (leaving the marker absent),
    /// then the wrapper behaves normally. Lets a test record a `PendingCommit`
    /// attempt on the first push and observe the next push's reconciliation
    /// completing the markers with the ORIGINAL deployment ID. Mirror of the
    /// integration-test `FailOnceMarkerRemote`, kept in-crate because the
    /// store fault hooks are `#[cfg(test)]` crate-internal.
    struct FailOnceMarkerRemote {
        inner: LocalTransport,
        armed: Arc<AtomicBool>,
    }

    impl FailOnceMarkerRemote {
        fn build(base: PathBuf, armed: Arc<AtomicBool>) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FailOnceMarkerRemote {
                inner: LocalTransport::new(base)?,
                armed,
            }))
        }
        fn fail_marker(&self, rel: &std::path::Path) -> bool {
            self.armed.load(Ordering::SeqCst) && rel.to_string_lossy().starts_with("state/commits/")
        }
    }

    impl Remote for FailOnceMarkerRemote {
        fn root(&self) -> &std::path::Path {
            self.inner.root()
        }
        fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
            if self.fail_marker(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceMarkerRemote: commit marker write forced to fail (once)",
                ));
            }
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<bool> {
            if self.fail_marker(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceMarkerRemote: commit marker create forced to fail (once)",
                ));
            }
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &std::path::Path) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &std::path::Path) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &std::path::Path, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(
            &self,
            rel: &std::path::Path,
        ) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &std::path::Path, link: &std::path::Path) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &std::path::Path) -> Result<std::path::PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &std::path::Path) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &std::path::Path) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &std::path::Path) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &std::path::Path) -> Result<crate::remote::transport::RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(
            &self,
            argv: &[String],
            timeout: std::time::Duration,
        ) -> Result<crate::remote::transport::ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn available_bytes(&self) -> Result<u64> {
            self.inner.available_bytes()
        }
    }

    /// A single-server (`s1`/`t1`) project + store + remote base for the
    /// full-push recovery scenarios, mirroring the integration-test setup.
    struct RecoveryHarness {
        _dir: tempfile::TempDir,
        cfg_path: PathBuf,
        config: Config,
        store: LocalStore,
        remotes_base: PathBuf,
    }

    impl RecoveryHarness {
        fn new() -> RecoveryHarness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let release_dir = project.join("releases").join("v1");
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(release_dir.join("standard.toml"), NONE_VARIANT).unwrap();
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
            let config = Config::load(&cfg_path).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let remotes_base = dir.path().join("remotes");
            std::fs::create_dir_all(&remotes_base).unwrap();
            RecoveryHarness {
                _dir: dir,
                cfg_path,
                config,
                store,
                remotes_base,
            }
        }
    }

    /// Push 1 of the recovery scenarios: the fleet-commit marker write fails
    /// once, so the attempt is recorded `PendingCommit` (activation already
    /// happened; the latest transition says `PendingCommit`, no snapshot
    /// entry, no `refs/last-successful`).
    fn push_pending_attempt(h: &RecoveryHarness) -> DeploymentAttempt {
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            FailOnceMarkerRemote::build(rf.join(&s.id), armed_for_factory.clone())
        };
        let r1 = push(
            &h.cfg_path,
            &h.store,
            &fault_factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .unwrap();
        assert_eq!(
            r1.status,
            Some(DeploymentStatus::PendingCommit),
            "failed marker write must yield PendingCommit"
        );
        let attempt = r1.attempt.expect("attempt recorded");
        let marker = h
            .remotes_base
            .join("s1")
            .join(crate::layout::commit_marker(attempt.deployment_id.as_str()));
        assert!(
            !marker.exists(),
            "marker must be absent after the failed push"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "no snapshot for a pending attempt"
        );
        assert!(
            h.store.read_last_successful("t1").is_none(),
            "last-successful must not point at a pending attempt"
        );
        attempt
    }

    /// A push with a healthy `LocalTransport` remote.
    fn push_clean(h: &RecoveryHarness) -> Result<PushReport> {
        let rf = h.remotes_base.clone();
        let clean_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        push(
            &h.cfg_path,
            &h.store,
            &clean_factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
    }

    /// The latest recorded transition status for a deployment.
    fn latest_status(h: &RecoveryHarness, deployment_id: &str) -> DeploymentStatus {
        h.store
            .latest_status(deployment_id)
            .unwrap()
            .expect("a transition must be recorded")
    }

    /// Assert the exactly-one end state of a fully replayed recovery: exactly
    /// one snapshot entry at index 0 for the attempt, `refs/last-successful`
    /// pointing at it, latest transition `Successful`, and the fleet-commit
    /// marker present on the remote.
    fn assert_finalized(h: &RecoveryHarness, attempt: &DeploymentAttempt) {
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(
            snapshots.len(),
            1,
            "exactly one successful fleet snapshot, got {}",
            snapshots.len()
        );
        assert_eq!(snapshots[0].index, 0);
        assert_eq!(snapshots[0].deployment_id, attempt.deployment_id);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(attempt.deployment_id.as_str()),
            "refs/last-successful must point at the recovered attempt"
        );
        assert_eq!(
            latest_status(h, attempt.deployment_id.as_str()),
            DeploymentStatus::Successful,
            "latest transition must be finalized as Successful"
        );
        let marker = h
            .remotes_base
            .join("s1")
            .join(crate::layout::commit_marker(attempt.deployment_id.as_str()));
        assert!(
            marker.exists(),
            "commit marker must be present on the remote"
        );
    }

    #[test]
    fn recovery_replays_after_snapshot_append_failure() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: the snapshot append (first persistence step of finalization)
        // fails once -> the push aborts with Err and nothing is durable yet.
        crate::store::local::test_faults::arm_append_snapshot(attempt.deployment_id.as_str());
        let err = push_clean(&h)
            .err()
            .expect("push must abort when the snapshot append fails");
        assert!(
            err.to_string().contains("append_snapshot"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "no snapshot after the failed append"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, attempt.deployment_id.as_str()),
            DeploymentStatus::PendingCommit
        );

        // Push 3: a clean push replays and completes finalization exactly once.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &attempt);
    }

    #[test]
    fn recovery_replays_after_last_successful_failure() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: the snapshot append succeeds but `refs/last-successful` (the
        // second persistence step) fails once -> Err; the snapshot exists
        // but the ref is stale and the attempt stays `PendingCommit`.
        crate::store::local::test_faults::arm_write_last_successful(attempt.deployment_id.as_str());
        let err = push_clean(&h)
            .err()
            .expect("push must abort when the last-successful write fails");
        assert!(
            err.to_string().contains("write_last_successful"),
            "error must name the injected fault, got: {err}"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1, "snapshot was appended before the crash");
        assert_eq!(snapshots[0].deployment_id, attempt.deployment_id);
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, attempt.deployment_id.as_str()),
            DeploymentStatus::PendingCommit
        );

        // Push 3: the idempotent ensure must NOT append a second entry; it
        // repairs last-successful and finishes. Exactly one entry remains.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &attempt);
    }

    #[test]
    fn recovery_replays_after_transition_append_failure() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: the snapshot and last-successful are durable but the
        // final `Successful` transition append fails -> Err; the attempt
        // stays `PendingCommit`, so it is still eligible for the next push.
        crate::store::local::test_faults::arm_append_transition(attempt.deployment_id.as_str());
        let err = push_clean(&h)
            .err()
            .expect("push must abort when the final transition append fails");
        assert!(
            err.to_string().contains("append_transition"),
            "error must name the injected fault, got: {err}"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(attempt.deployment_id.as_str())
        );
        assert_eq!(
            latest_status(&h, attempt.deployment_id.as_str()),
            DeploymentStatus::PendingCommit
        );

        // Push 3: the replay completes the final transition append; the ensure
        // is a no-op and no duplicate entry is created.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &attempt);
    }

    #[test]
    fn recovery_plain_replay_is_idempotent() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: a clean push completes finalization fully (no faults).
        let r2 = push_clean(&h).unwrap();
        assert_eq!(
            r2.status, None,
            "the reconciling push is an up-to-date no-op"
        );
        assert_finalized(&h, &attempt);

        // Push 3: a further clean push re-runs reconciliation (the attempts
        // record is untouched and the transition already says `Successful`)
        // but every step is idempotent: no duplicate snapshot, no changed
        // refs, no new attempt.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None);
        assert_eq!(r3.message, "Everything up to date");
        assert_finalized(&h, &attempt);
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no new attempt may be recorded by the replays"
        );
    }

    // ---- Main-path replay-safe finalization ------------------------------
    //
    // The NORMAL success path finalizes through the SAME replay-safe
    // finalizer as recovery (`history::finalize_successful_attempt`):
    // recoverable `PendingCommit` marker -> idempotent snapshot +
    // `refs/last-successful` -> terminal `Successful` transition LAST. These
    // tests fault a normal push's finalization once at each persistence step
    // and prove the recoverable window (the attempt's latest transition is
    // `PendingCommit`, never a prematurely-written `Successful`) plus
    // exactly-once replay on a clean follow-up push.
    //
    // `push()` mints the deployment id internally, so the faulted push drives
    // `push_inner` DIRECTLY with a fixed id (the test module is inside
    // `engine.rs`, so it can): the one-shot `arm_*` faults stay keyed by
    // deployment id exactly like the recovery tests — deterministic under
    // parallel `cargo test`.

    /// A normal single-server push with a caller-supplied deployment id over
    /// healthy `LocalTransport` remotes (no injected remote faults). Drives
    /// the FULL normal success path (`push_inner`) so a test can arm store
    /// faults keyed by the fixed deployment id BEFORE the push runs.
    fn push_main_with_id(h: &RecoveryHarness, deployment_id: &DeploymentId) -> Result<PushReport> {
        let project_root = h.config.project_root(&h.cfg_path);
        let target = h
            .config
            .targets
            .get("t1")
            .expect("harness configures target t1");
        let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &PushRef::Head,
            deployment_id,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
    }

    /// The single attempt recorded for target `t1`.
    fn single_attempt(h: &RecoveryHarness) -> DeploymentAttempt {
        let mut attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "exactly one attempt recorded");
        attempts.remove(0)
    }

    #[test]
    fn main_path_replays_after_snapshot_append_failure() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-main-snapshot-fault".to_string());

        // Push 1: a NORMAL push whose finalization is faulted at its first
        // persistence step — the snapshot append fails once. The finalizer
        // already persisted the recoverable `PendingCommit` marker, so the
        // attempt is left in the crash window: latest transition
        // `PendingCommit` (never `Successful`), no snapshot entry, no
        // `refs/last-successful`.
        crate::store::local::test_faults::arm_append_snapshot(id.as_str());
        let err = push_main_with_id(&h, &id)
            .err()
            .expect("push must abort when the snapshot append fails");
        assert!(
            err.to_string().contains("append_snapshot"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "no snapshot after the failed snapshot append"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit,
            "crash window must leave the attempt PendingCommit, not Successful"
        );

        // Push 2: a clean push reconciles the pending attempt (servers are
        // already at the desired generation) and completes finalization
        // exactly once: one snapshot entry, `refs/last-successful` pointing
        // at it, latest transition `Successful`, marker present.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "the replay must not record a new attempt"
        );
        assert_finalized(&h, &single_attempt(&h));
    }

    #[test]
    fn main_path_replays_after_last_successful_failure() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-main-last-successful-fault".to_string());

        // First: the snapshot append succeeds but `refs/last-successful`
        // (the second persistence step) fails once -> Err; the snapshot
        // entry exists but the ref is stale and the attempt stays
        // `PendingCommit`.
        crate::store::local::test_faults::arm_write_last_successful(id.as_str());
        let err = push_main_with_id(&h, &id)
            .err()
            .expect("push must abort when the last-successful write fails");
        assert!(
            err.to_string().contains("write_last_successful"),
            "error must name the injected fault, got: {err}"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1, "snapshot was appended before the crash");
        assert_eq!(snapshots[0].deployment_id, id);
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit,
            "crash window must leave the attempt PendingCommit, not Successful"
        );

        // Push 2: the idempotent ensure must NOT append a second entry; it
        // repairs `refs/last-successful` and finishes. Exactly one entry
        // remains.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &single_attempt(&h));
    }

    #[test]
    fn main_path_replays_after_transition_append_failure() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::from("deploy-main-transition-fault".to_string());

        // First: the snapshot and `refs/last-successful` are durable but the
        // final `Successful` transition append fails -> Err. The fault is
        // armed for the TERMINAL transition only
        // (`arm_append_transition_successful`), so the recoverable
        // `PendingCommit` marker append passes through; the attempt stays
        // `PendingCommit` and remains eligible.
        crate::store::local::test_faults::arm_append_transition_successful(id.as_str());
        let err = push_main_with_id(&h, &id)
            .err()
            .expect("push must abort when the final transition append fails");
        assert!(
            err.to_string().contains("append_transition"),
            "error must name the injected fault, got: {err}"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit,
            "crash window must leave the attempt PendingCommit, not Successful"
        );

        // Push 2: the replay completes the final transition append; the
        // ensure is a no-op and no duplicate entry is created.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &single_attempt(&h));
    }

    #[test]
    fn main_path_finalize_is_replay_safe_and_idempotent() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::from("deploy-main-plain".to_string());

        // First: a normal push completes finalization fully (no faults):
        // the attempt is `Successful`, one snapshot entry, the ref set.
        let r1 = push_main_with_id(&h, &id).unwrap();
        assert_eq!(
            r1.status,
            Some(DeploymentStatus::Successful),
            "clean push must finalize Successful"
        );
        assert!(
            r1.message.contains("fleet ref t1@f0"),
            "message must carry the fleet ref, got: {}",
            r1.message
        );
        assert_finalized(&h, &single_attempt(&h));

        // Push 2: a further push sees everything up to date; reconciliation
        // skips the finalized attempt and no duplicate snapshot appears.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None);
        assert_eq!(r2.message, "Everything up to date");
        assert_finalized(&h, &single_attempt(&h));
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no new attempt may be recorded by the no-op push"
        );
    }

    // ---- Intent persisted BEFORE remote mutation; InProgress recovery -----
    //
    // The attempt INTENT is now persisted BEFORE any server mutation (a crash
    // after servers advanced can never lose the deployment: the intent is
    // already durable and the next push reconciles it), outcomes are recorded
    // separately in `deployments/<id>/results.json`, and recovery reconciles
    // attempts whose latest transition is `InProgress` (intent durable,
    // finalization never completed) through the SAME verification, marker, and
    // replay-safe finalizer path as `PendingCommit` attempts.
    //
    // Each of the one-shot store faults below is armed by EXACTLY ONE test: the
    // fault statics are process-global keyed by deployment id, so two tests
    // arming the same fault (with different ids) would clobber each other
    // under parallel `cargo test` execution.

    /// Faulting the intent persist (`append_attempt`) must abort the push
    /// BEFORE any remote mutation: no generation is created and `current` is
    /// never touched (the per-server mutation loop cannot start), and no
    /// attempt record leaks.
    #[test]
    fn intent_persist_fault_leaves_remote_untouched() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-intent-fault".to_string());
        crate::store::local::test_faults::arm_append_attempt(id.as_str());

        let err = push_main_with_id(&h, &id)
            .err()
            .expect("push must abort when the intent persist fails");
        assert!(
            err.to_string().contains("append_attempt"),
            "error must name the injected fault, got: {err}"
        );

        // Nothing recorded locally...
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            0,
            "no attempt record when the intent persist failed"
        );
        assert!(h.store.read_results(id.as_str()).is_err(), "no results");
        // ...and NOTHING on the remote mutated: no `current`, no generation.
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(
            !remote.exists(crate::layout::current()),
            "current must not exist before the intent is durable"
        );
        assert_eq!(
            remote.list(crate::layout::generations()).unwrap().len(),
            0,
            "no generation may be created before the intent is durable"
        );

        // A clean push with a fresh id proceeds normally: remote advances.
        let id2 = DeploymentId::new("deploy-intent-fault-clean".to_string());
        let r2 = push_main_with_id(&h, &id2).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Successful),
            "a clean follow-up push succeeds"
        );
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(remote.exists(crate::layout::current()), "remote advanced");
        assert_finalized(&h, &single_attempt(&h));
    }

    /// The inverse guarantee plus crash window (b): when the outcomes store
    /// (`write_results`) is faulted, push 1 fails with the servers ALREADY
    /// advanced but no results.json — yet the intent record exists (immutable
    /// intent, EMPTY `slots`, latest transition `InProgress`, never
    /// `Successful` anywhere). Push 2 reconciles the `InProgress` attempt and
    /// builds the snapshot from the verified desired state — exactly one
    /// snapshot, ref, marker, and terminal `Successful` transition.
    #[test]
    fn write_results_fault_leaves_intent_durable_and_recovers_from_verified_desired() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-inprogress-no-results".to_string());
        crate::store::local::test_faults::arm_write_results(id.as_str());

        let err = push_main_with_id(&h, &id)
            .err()
            .expect("push must abort when write_results fails");
        assert!(err.to_string().contains("write_results"));

        // The intent record is durable even though a later step failed; it
        // carries the planned (desired) and observed (pre_push) maps but NO
        // outcomes (empty `slots`), and the attempt never appears Successful
        // anywhere (no snapshot, no ref, latest transition `InProgress`).
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "intent must be recorded before mutation");
        let intent = &attempts[0];
        assert_eq!(intent.deployment_id, id);
        assert!(
            intent.slots.is_empty(),
            "persisted intent carries NO outcomes (they live in results.json)"
        );
        assert!(
            intent.desired.contains_key(&PlacementSlotId::new("p1"))
                && intent.pre_push.contains_key(&PlacementSlotId::new("p1")),
            "intent carries the planned (desired) and observed (pre_push) maps"
        );
        assert!(
            h.store.read_results(id.as_str()).is_err(),
            "no results.json"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::InProgress,
            "the crash window leaves the latest transition InProgress"
        );
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());
        // Servers DID advance (the mutation loop ran before write_results).
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(remote.exists(crate::layout::current()), "remote advanced");

        // Push 2: recovery verifies every slot is at the intent's desired
        // generation, then finalizes; the snapshot is built from the verified
        // desired state (results.json absent).
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        let intent = single_attempt(&h);
        assert_finalized(&h, &intent);
        let snap = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snap.len(), 1);
        let g = &snap[0].slots[&PlacementSlotId::new("p1")];
        let desired = &intent.desired[&PlacementSlotId::new("p1")];
        assert_eq!(
            g.generation.as_str(),
            desired.generation.as_str(),
            "snapshot generation comes from the verified desired state"
        );
        assert_eq!(g.assignment.artifact.tree, desired.assignment.artifact.tree);
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
    }

    /// Crash window (a)/(c): intent + outcomes durable, but the finalize
    /// marker — the recoverable `PendingCommit` transition, first step of the
    /// shared finalizer — is faulted by the status-qualified
    /// `arm_append_transition_pending` (the earlier `InProgress` transition
    /// passes through). The attempt's latest transition is `InProgress` —
    /// never `Successful` — and the NEXT push reconciles it to exactly-once
    /// success: one snapshot, `refs/last-successful`, the marker, and the
    /// terminal `Successful` transition.
    #[test]
    fn inprogress_crash_window_reconciles_to_exactly_once_success() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-inprogress-window".to_string());
        crate::store::local::test_faults::arm_append_transition_pending(id.as_str());

        // Push 1: mutation completes, outcomes are durable, but the first
        // PendingCommit append (the finalize marker) fails once -> Err.
        let err = push_main_with_id(&h, &id)
            .err()
            .expect("push must abort when the finalize marker append fails");
        assert!(
            err.to_string().contains("append_transition"),
            "error must name the injected fault, got: {err}"
        );
        let results = h.store.read_results(id.as_str()).unwrap();
        assert_eq!(
            results.slots[&PlacementSlotId::new("p1")].outcome,
            ServerOutcomeKind::Activated,
            "outcomes durable before the finalize marker"
        );
        assert_eq!(
            h.store.read_transitions(id.as_str()).unwrap().len(),
            1,
            "only the in_progress transition exists before finalization"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::InProgress,
            "crash window must leave the attempt InProgress, never Successful"
        );
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());

        // Push 2: a clean push reconciles the `InProgress` attempt (servers
        // are already at the desired generation) and completes finalization
        // exactly once; the finalizer's marker step now appends
        // `PendingCommit` and the terminal `Successful` transition is LAST.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_finalized(&h, &single_attempt(&h));
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "the replay must not record a new attempt"
        );
        assert_eq!(latest_status(&h, id.as_str()), DeploymentStatus::Successful);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
    }

    /// Crash window (d): an `InProgress` attempt whose generation NO LONGER
    /// matches (the remote advanced elsewhere) finalizes `Degraded` — no
    /// snapshot entry for it — and the up-to-date no-op still reports
    /// correctly. The `InProgress` attempt is crafted directly: its intent
    /// (desired generation) is a FRESH minted generation the remote never
    /// reached, while the remote already advanced to push 1's generation —
    /// the exact state a pre-mutation-persisted intent leaves behind after a
    /// crash plus a concurrent controller. Crafting the record (rather than
    /// arming a second fault) also keeps each one-shot fault armed by exactly
    /// one test.
    #[test]
    fn inprogress_attempt_diverged_generation_finalizes_degraded() {
        let h = RecoveryHarness::new();
        // Push 1: a real successful deployment advances the remote.
        let id_b = DeploymentId::new("deploy-diverged-baseline".to_string());
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(remote.exists(crate::layout::current()), "remote advanced");

        // Craft an InProgress intent (id A) whose desired generation the
        // remote never minted: intent durable, finalization never started,
        // and the remote's current points elsewhere.
        let target_a = GenerationId::generate();
        let id_a = DeploymentId::new("deploy-inprogress-diverged".to_string());
        let desired_ref = baseline.desired[&PlacementSlotId::new("p1")].clone();
        let intent = DeploymentAttempt {
            deployment_schema_version: 2,
            deployment_id: id_a.clone(),
            target: TargetName::new("t1".to_string()),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: baseline.behavior_sha256.clone(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            desired: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: target_a,
                    assignment: desired_ref.assignment,
                },
            )]),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        h.store.append_attempt("t1", &intent).unwrap();
        h.store
            .append_transition(
                id_a.as_str(),
                &DeploymentStatus::InProgress,
                Some("attempt started"),
            )
            .unwrap();
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            DeploymentStatus::InProgress
        );

        // Push 2: recovery verifies the InProgress attempt; the slot's current
        // generation no longer matches the intent's desired generation, so it
        // finalizes Degraded — no snapshot entry for it, no last-successful
        // change — and the up-to-date check (same artifact) reports a no-op.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            DeploymentStatus::Degraded,
            "the diverged attempt must finalize Degraded"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1, "only the baseline snapshot exists");
        assert_eq!(snapshots[0].deployment_id, id_b);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id_b.as_str()),
            "last-successful still points at the baseline deployment"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 2);
    }
}

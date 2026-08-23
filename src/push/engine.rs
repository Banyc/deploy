//! Push transaction engine.
//!
//! Implements the deployment transaction described in `requirement.md`:
//! validation, locking, materialization, release identity, reconciliation,
//! preflight capacity, staging, batched per-server publication with a
//! compare-and-swap precondition, atomic `current` swap, activation,
//! verification, compensation, fleet-commit markers, history, rollback, and
//! per-server rotation.

use crate::adapter::verify::run_verification;
use crate::config::{Config, Mapping, SlotDef};
use crate::error::{Error, Result};
use crate::history::{self, PushRef};
use crate::layout;
use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, GenerationRef, OperationId,
    PlacementSlotId, ReleaseId, TargetName, TreeDigest, VariantName,
};
use crate::push::capacity::capacity_preflight;
use crate::push::reconcile::reconcile_pending_commits;
use crate::push::server::{
    REMOTE_RELEASE_JSON, ServerProc, compensate_server, download_tree_to_host, process_server,
};
use crate::push::staging::{StagingCleanup, cleanup_dry_run_staging, remove_tree_restoring_write};
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

/// Build the template context for one placement slot from the ARTIFACT being
/// processed: `release`/`variant`/`tree` are the assigned artifact's own
/// immutable `ReleaseId`, `VariantName`, and `TreeDigest` — never the caller's
/// current release name — so a historical/rollback push renders the release id
/// it actually deploys, and a template never sees a torn (desired-variant,
/// current-release) combination. Compensation overrides the triple again with
/// the PRIOR artifact via [`crate::template::TemplateVars::with_artifact`].
///
/// `deployment_id`/`generation` are the per-deployment identity, available
/// only in the per-server activation/verification path; sites that do not know
/// them (e.g. the reconciliation loop) pass `None`, and a template referencing
/// such a variable there fails loudly.
fn slot_vars(
    members: &[(&crate::config::SlotDef, &crate::config::ServerDef)],
    config: &Config,
    target_name: &str,
    slot_id: &PlacementSlotId,
    artifact: &ArtifactRef,
    deployment_id: Option<&DeploymentId>,
    generation: Option<&GenerationId>,
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
        artifact.variant.as_str(),
        &config.application,
        artifact.release.as_str(),
        target_name,
        &server.id,
    )
    .with_server(&server.user, &server.address, server.port)
    .with_slot_id(&slot.id)
    .with_deployment(deployment_id, generation, Some(&artifact.tree)))
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

    // 4. Freeze per-variant mappings + behavior + slots and generate or reuse
    // the release record. The release identity covers the name-sorted mappings,
    // behavior contracts, and slot declarations of every declared variant plus
    // each variant's tree. Slots ARE part of the identity: they are declared
    // inside the variant files, so rebinding a slot to another server, moving
    // its `deploy_dir`, or retargeting it produces a new release. Capacity is
    // NOT part of the release: it is a per-server policy resolved from the
    // caller's current `deploy.toml` at preflight time (servers have no
    // per-release history), so a server-capacity change never produces a new
    // release. Rotation is fleet-wide configuration read from `deploy.toml` at
    // push time, so it is not snapshotted per variant either.
    let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    let mut variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::new();
    let mut variant_slots: BTreeMap<String, Vec<SlotDef>> = BTreeMap::new();
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
        variant_slots.insert(v.clone(), vcfg.slots.clone());
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
        let rec = crate::release::build_release(
            &mapping_sha,
            &behavior_sha,
            &bindings,
            &variant_slots,
            project_root,
        );
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
                // remote generation), not the desired one. When the live
                // generation's assignment cannot be read (a missing or corrupt
                // `assignment.json`), never substitute the planned (desired)
                // artifact: preserve the observed generation and mark the
                // assignment unknown — the same contract the post-push
                // `actual_servers` refresh uses (see below).
                helpers[slot_id]
                    .read_assignment(g.as_str())
                    .map(|asn| AttemptServer {
                        artifact: asn.artifact.clone(),
                        generation: Some(g.clone()),
                    })
                    .unwrap_or_else(|_| AttemptServer {
                        artifact: ArtifactRef::default(),
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
                    &a.artifact,
                    Some(deployment_id),
                    Some(&new_gen[&a.placement_slot]),
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
    //
    // A PREFLIGHT failure here happens AFTER the attempt intent and its
    // initial `InProgress` transition were persisted (requirement.md step 14
    // orders the intent before capacity, step 8). The attempt must therefore
    // end terminal `FailedPreflight` — "an attempt that fails before any
    // `current` change is `failed_preflight`" — never stranded `InProgress`
    // (which would be misreported later as a recoverable/pending attempt or
    // falsely degraded as "generation diverged" by a later reconcile).
    // Failures BEFORE the intent is persisted (plan resolution, historical
    // behavior snapshot, handshake) surface as the push error with no attempt
    // record at all.
    capacity_preflight(
        store,
        &assignments,
        &helpers,
        op_id,
        deployment_id,
        config,
        &target.rotation,
    )
    .map_err(|e| {
        if matches!(e, Error::Preflight(_)) {
            let _ = store.append_transition(
                deployment_id.as_str(),
                &DeploymentStatus::FailedPreflight,
                Some("preflight failed"),
            );
        }
        e
    })?;
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
                &a.artifact,
                Some(deployment_id),
                Some(&new_gen[sid]),
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
                did_advance,
                did_compensate,
                error,
            } = outcome;
            if kind == ServerOutcomeKind::Failed {
                had_failure = true;
            }
            if did_compensate {
                compensated.push(sid.clone());
            } else if did_advance {
                // Any slot this deployment advanced — Activated, or a
                // post-swap failure whose compensation failed — remains a
                // "still-advanced" server for the failure-policy pass and the
                // status decision. Pre-swap failures (never advanced) are NOT
                // included: for them `advanced.is_empty()` correctly yields
                // `FailedRolledBack` (nothing to roll back).
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
                &plan_servers[sid].artifact,
                Some(deployment_id),
                Some(&new_gen[sid]),
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
        // The snapshot records each slot's COMPLETE physical binding
        // (`{server, deploy_dir}`) so an exact rollback can verify a slot
        // still lives at the exact on-host location it was deployed onto (a
        // rebound slot OR a slot whose deploy_dir moved must refuse rather
        // than deploy to the wrong host/location). The binding comes from
        // the CURRENT configuration: it is the live placement this attempt
        // actually used. The snapshot itself is built from the actual
        // per-slot OUTCOMES (`actual_servers`), never from the intent
        // record.
        let slot_bindings = config.target_slot_bindings(target_name)?;
        let idx = history::finalize_successful_attempt(
            store,
            &attempt_intent,
            &actual_servers,
            "push completed",
            &slot_bindings,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::transport::LocalTransport;
    use std::os::unix::fs::PermissionsExt;
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
        crate::testutil::test_faults::arm_append_snapshot(attempt.deployment_id.as_str());
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
        crate::testutil::test_faults::arm_write_last_successful(attempt.deployment_id.as_str());
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
        crate::testutil::test_faults::arm_append_transition(attempt.deployment_id.as_str());
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
        crate::testutil::test_faults::arm_append_snapshot(id.as_str());
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
        crate::testutil::test_faults::arm_write_last_successful(id.as_str());
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
        crate::testutil::test_faults::arm_append_transition_successful(id.as_str());
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
        crate::testutil::test_faults::arm_append_attempt(id.as_str());

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
        crate::testutil::test_faults::arm_write_results(id.as_str());

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
        crate::testutil::test_faults::arm_append_transition_pending(id.as_str());

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

    // ---- Transition sequence, outcomes separation, no-op trace, mid-mutation
    // durability, and multi-attempt reconcile ordering -----------------------

    /// A remote that fails the FIRST generation-record write exactly once
    /// (`try_write_new` under `generations/`), then behaves normally. Fires
    /// inside `create_generation`, i.e. AFTER the intent is durable and BEFORE
    /// the server's `current` advances: the exact mid-mutation window.
    struct FailOnceGenerationRemote {
        inner: LocalTransport,
        armed: Arc<AtomicBool>,
    }

    impl FailOnceGenerationRemote {
        fn build(base: PathBuf, armed: Arc<AtomicBool>) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FailOnceGenerationRemote {
                inner: LocalTransport::new(base)?,
                armed,
            }))
        }
        fn fail_generation(&self, rel: &std::path::Path) -> bool {
            self.armed.load(Ordering::SeqCst)
                && rel.to_string_lossy().starts_with("generations/")
                && rel.to_string_lossy().ends_with("assignment.json")
        }
    }

    impl Remote for FailOnceGenerationRemote {
        fn root(&self) -> &std::path::Path {
            self.inner.root()
        }
        fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<bool> {
            if self.fail_generation(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceGenerationRemote: generation write forced to fail (once)",
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

    /// Recursively snapshot every file under `dir` as (relative path, bytes),
    /// sorted, for byte-for-byte store-comparison assertions.
    fn snapshot_files(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let rel = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                    out.push((rel, std::fs::read(&p).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    /// A clean successful push records the EXACT latest-status evolution
    /// `InProgress -> PendingCommit (finalize marker) -> Successful` (the
    /// recoverable window is `PendingCommit`), writes `results.json` after the
    /// mutation loop, and builds the snapshot from those OUTCOMES — the
    /// persisted intent record itself carries an empty `slots` map.
    #[test]
    fn clean_push_transition_sequence_and_outcomes() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-sequence".to_string());
        let r = push_main_with_id(&h, &id).unwrap();
        assert_eq!(r.status, Some(DeploymentStatus::Successful));

        let transitions = h.store.read_transitions(id.as_str()).unwrap();
        let statuses: Vec<DeploymentStatus> =
            transitions.iter().map(|t| t.status.clone()).collect();
        assert_eq!(
            statuses,
            vec![
                DeploymentStatus::InProgress,
                DeploymentStatus::PendingCommit,
                DeploymentStatus::Successful,
            ],
            "a successful push must evolve InProgress -> PendingCommit -> Successful"
        );
        // The finalize marker carries the recoverable-window reason.
        assert_eq!(
            transitions[1].reason.as_deref(),
            Some("finalization started")
        );

        // Outcomes separation: results.json exists with the per-slot outcome
        // and the persisted intent carries NO outcomes.
        let results = h.store.read_results(id.as_str()).unwrap();
        assert_eq!(
            results.slots[&PlacementSlotId::new("p1")].outcome,
            ServerOutcomeKind::Activated
        );
        let attempt = single_attempt(&h);
        assert!(
            attempt.slots.is_empty(),
            "the persisted intent record must carry no outcomes"
        );

        // The snapshot is built from the OUTCOMES: its per-slot generation
        // equals results.json's outcome generation, and its artifact equals the
        // report's actual (observed) assignment.
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        let snap = &snapshots[0];
        assert_eq!(
            snap.slots[&PlacementSlotId::new("p1")].generation,
            results.slots[&PlacementSlotId::new("p1")]
                .generation
                .clone()
                .unwrap()
        );
        let actual = &r.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")];
        assert_eq!(
            snap.slots[&PlacementSlotId::new("p1")].assignment.artifact,
            actual.artifact
        );
    }

    /// A remote failure MID-mutation (after the intent is durable, before the
    /// server's generation record — and therefore `current` — exists) leaves
    /// the intent record durable with an EMPTY outcomes map, records a failure
    /// outcome in results.json, and never advances the remote; a follow-up
    /// clean push recovers.
    #[test]
    fn mid_mutation_fault_leaves_intent_durable_without_advancing_remote() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-mid-mutation".to_string());
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            FailOnceGenerationRemote::build(rf.join(&s.id), armed_for_factory.clone())
        };
        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.targets.get("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let r = push_inner(
            &project_root,
            &h.store,
            &fault_factory,
            "t1",
            &PushRef::Head,
            &id,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .unwrap();
        assert!(
            r.status == Some(DeploymentStatus::FailedRolledBack)
                || r.status == Some(DeploymentStatus::Degraded),
            "mid-mutation failure must be reported as a failure, got {:?}",
            r.status
        );

        // The intent record is durable with EMPTY outcomes (results live in
        // results.json, which records the per-slot failure).
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "intent must be recorded before mutation");
        assert!(attempts[0].slots.is_empty(), "intent carries no outcomes");
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::FailedRolledBack
        );
        let results = h.store.read_results(id.as_str()).unwrap();
        assert_eq!(
            results.slots[&PlacementSlotId::new("p1")].outcome,
            ServerOutcomeKind::Failed
        );

        // The remote never advanced: no `current`, no durable generation
        // record (the mid-mutation fault fired before the assignment write, so
        // the generation dir may exist but is empty).
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(!remote.exists(crate::layout::current()), "no current");
        for e in remote.list(crate::layout::generations()).unwrap() {
            assert!(
                !remote.exists(
                    &crate::layout::generations()
                        .join(&e.name)
                        .join("assignment.json")
                ),
                "no generation record may be durable ({} was never written)",
                e.name
            );
        }

        // A follow-up clean push succeeds and advances the remote.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Successful),
            "the interrupted state must be recoverable: {}",
            r2.message
        );
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(remote.exists(crate::layout::current()), "remote advanced");
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 2);
    }

    /// Everything-up-to-date no-op: a second push with nothing changed records
    /// no new attempt, no new snapshot, no transition stream, and leaves the
    /// whole per-target store state byte-for-byte identical (attempts,
    /// transitions, observed, refs).
    #[test]
    fn no_op_push_leaves_store_untouched() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-noop-baseline".to_string());
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
        let observed = h.store.read_observed("t1").unwrap();
        assert_eq!(
            observed.slots[&PlacementSlotId::new("p1")].generation,
            r1.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")].generation
        );
    }

    /// A just-recorded attempt with NO transition stream at all (latest status
    /// `None`) is eligible for reconciliation: the next push finalizes it
    /// Successful with its own snapshot entry instead of skipping it.
    #[test]
    fn reconcile_attempt_without_transitions_is_eligible() {
        let h = RecoveryHarness::new();
        let id_b = DeploymentId::new("deploy-no-status-baseline".to_string());
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(remote.exists(crate::layout::current()), "remote advanced");

        // Craft an intent with NO transition appended: eligibility treats the
        // absent status file as eligible (a just-recorded attempt).
        let id_a = DeploymentId::new("deploy-no-status".to_string());
        let desired_ref = baseline.desired[&PlacementSlotId::new("p1")].clone();
        let intent = DeploymentAttempt {
            deployment_schema_version: 2,
            deployment_id: id_a.clone(),
            target: TargetName::new("t1".to_string()),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: baseline.behavior_sha256.clone(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            desired: BTreeMap::from([(PlacementSlotId::new("p1".to_string()), desired_ref)]),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        h.store.append_attempt("t1", &intent).unwrap();
        assert_eq!(
            h.store.latest_status(id_a.as_str()).unwrap(),
            None,
            "no transition stream for the crafted attempt"
        );

        // The next push reconciles the transition-less attempt (the remote is
        // already at its desired generation) and finalizes it Successful.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "reconciling push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            DeploymentStatus::Successful
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 2, "baseline + reconciled attempt");
        assert_eq!(snapshots[1].deployment_id, id_a);
        assert_eq!(snapshots[1].index, 1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id_a.as_str())
        );
        let marker = h
            .remotes_base
            .join("s1")
            .join(crate::layout::commit_marker(id_a.as_str()));
        assert!(marker.exists(), "marker written for the original id");
    }

    /// Multiple pending attempts are reconciled OLDEST FIRST (attempts.jsonl
    /// order) so snapshot/reflog indices stay monotonic: two crafted
    /// `InProgress` intents appended A-then-B finalize in that order with
    /// indices 1 and 2 after the baseline.
    #[test]
    fn reconcile_multiple_pending_oldest_first_with_monotonic_indices() {
        let h = RecoveryHarness::new();
        let id_b = DeploymentId::new("deploy-multi-baseline".to_string());
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let desired_ref = baseline.desired[&PlacementSlotId::new("p1")].clone();

        let mk = |id: &str| DeploymentAttempt {
            deployment_schema_version: 2,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new("t1".to_string()),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: baseline.behavior_sha256.clone(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            desired: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                desired_ref.clone(),
            )]),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        let a = mk("deploy-multi-a");
        let b = mk("deploy-multi-b");
        h.store.append_attempt("t1", &a).unwrap();
        h.store
            .append_transition(
                a.deployment_id.as_str(),
                &DeploymentStatus::InProgress,
                Some("attempt started"),
            )
            .unwrap();
        h.store.append_attempt("t1", &b).unwrap();
        h.store
            .append_transition(
                b.deployment_id.as_str(),
                &DeploymentStatus::InProgress,
                Some("attempt started"),
            )
            .unwrap();

        // One push reconciles BOTH, oldest first.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.message, "Everything up to date");
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[1].deployment_id, a.deployment_id);
        assert_eq!(snapshots[2].deployment_id, b.deployment_id);
        assert_eq!(snapshots[1].index, 1, "reflog indices stay monotonic");
        assert_eq!(snapshots[2].index, 2);
        assert_eq!(
            latest_status(&h, a.deployment_id.as_str()),
            DeploymentStatus::Successful
        );
        assert_eq!(
            latest_status(&h, b.deployment_id.as_str()),
            DeploymentStatus::Successful
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(b.deployment_id.as_str())
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 3);
        for id in [a.deployment_id.as_str(), b.deployment_id.as_str()] {
            let marker = h
                .remotes_base
                .join("s1")
                .join(crate::layout::commit_marker(id));
            assert!(marker.exists(), "marker present for {id}");
        }
    }

    /// Replay-safe retry chain: faulting the SAME finalize step on the main
    /// push AND on the first replay still converges on a later clean push with
    /// exactly one snapshot entry and one attempt record (idempotent retries).
    #[test]
    fn second_faulted_replay_still_converges_exactly_once() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-retry-chain".to_string());

        // Push 1: the terminal Successful transition fails once -> PendingCommit.
        crate::testutil::test_faults::arm_append_transition_successful(id.as_str());
        let err = push_main_with_id(&h, &id)
            .err()
            .expect("first faulted push must abort");
        assert!(err.to_string().contains("append_transition"));
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit
        );
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);

        // Push 2: the REPLAY faults the SAME step again -> still PendingCommit,
        // still exactly one snapshot (idempotent ensure, no duplicate).
        crate::testutil::test_faults::arm_append_transition_successful(id.as_str());
        let err2 = push_clean(&h)
            .err()
            .expect("second faulted replay must abort");
        assert!(err2.to_string().contains("append_transition"));
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit
        );
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "a second faulted replay must not duplicate the snapshot"
        );

        // Push 3: a clean replay converges to exactly-once success.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None);
        assert_eq!(r3.message, "Everything up to date");
        assert_finalized(&h, &single_attempt(&h));
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
    }

    // ---- Verification-failure rollback + observed refresh -----------------
    //
    // An attempt whose ACTIVATION succeeds but whose VERIFICATION fails must
    // compensate back to the PRIOR generation (restoring the prior behavior
    // contract), report `FailedRolledBack`, and refresh `observed.json` with
    // the ACTUAL restored state — the prior generation and artifact — never
    // the desired (failed) artifact. This is the dedicated verification-
    // failure variant the integration `end_to_end_push_rollback` does NOT
    // exercise (that test only pushes/rolls back successful states).

    #[test]
    fn verification_failure_compensates_prior_and_observed_reflects_actual() {
        let h = RecoveryHarness::new();
        let id1 = DeploymentId::new("deploy-verify-fail-baseline".to_string());
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior = r1.attempt.as_ref().expect("attempt recorded").slots
            [&PlacementSlotId::new("p1")]
            .clone();
        let prior_gen = prior.generation.clone().expect("prior generation");
        let prior_tree = prior.artifact.tree.clone();
        let prior_release = prior.artifact.release.clone();
        // Behavior digest A (verification argv "true") frozen into f0.
        let var_a = h.config.variant("standard").unwrap();
        let a_digest = crate::release::behavior_contract_digest(&crate::model::BehaviorContract {
            activation: var_a.activation.clone(),
            verification: var_a.verification.clone(),
        });

        // v2: verification argv flips to "false" AND the artifact content
        // changes, so the desired tree + release differ from the prior state
        // and the push is not an up-to-date no-op.
        let project_root = h.config.project_root(&h.cfg_path);
        let variant_path = project_root
            .join("releases")
            .join("v1")
            .join("standard.toml");
        let new_variant = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("argv = [\"true\"]", "argv = [\"false\"]");
        assert_ne!(new_variant, std::fs::read_to_string(&variant_path).unwrap());
        std::fs::write(&variant_path, new_variant).unwrap();
        std::fs::write(
            project_root
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server"),
            "v2\n",
        )
        .unwrap();
        let config2 = Config::load(&h.cfg_path).unwrap();
        let var_b = config2.variant("standard").unwrap();
        let b_digest = crate::release::behavior_contract_digest(&crate::model::BehaviorContract {
            activation: var_b.activation.clone(),
            verification: var_b.verification.clone(),
        });
        assert_ne!(a_digest, b_digest, "behaviors must differ");

        let id2 = DeploymentId::new("deploy-verify-fail".to_string());
        let target = config2.targets.get("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id2.as_str()));
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let r2 = push_inner(
            &config2.project_root(&h.cfg_path),
            &h.store,
            &factory,
            "t1",
            &PushRef::Head,
            &id2,
            &op_id,
            &config2,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::FailedRolledBack),
            "a verification failure after activation must roll the whole attempt back, got {:?}",
            r2.status
        );

        // The report's ACTUAL per-slot state reflects the restored PRIOR
        // generation and artifact, never the desired v2 tree.
        let actual =
            &r2.attempt.as_ref().expect("attempt recorded").slots[&PlacementSlotId::new("p1")];
        assert_eq!(actual.generation, Some(prior_gen.clone()));
        assert_eq!(
            actual.artifact.tree, prior_tree,
            "the actual artifact must be the restored prior tree, not the desired v2 tree"
        );

        // results.json records the compensation: the slot FAILED (verification)
        // and was compensated inside the per-server pipeline — outcome `Failed`
        // with `compensated: true`, at the PRIOR generation. (`Restored` is
        // reserved for Activated slots compensated by the failure-policy pass.)
        let results = h.store.read_results(id2.as_str()).unwrap();
        let res = &results.slots[&PlacementSlotId::new("p1")];
        assert_eq!(res.outcome, ServerOutcomeKind::Failed);
        assert!(res.compensated);
        assert_eq!(res.generation, Some(prior_gen.clone()));

        // The remote `current` points at the PRIOR generation, whose stored
        // assignment carries the PRIOR behavior digest (A), never B: the
        // prior behavior contract was restored, not the desired one.
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        let cur = status
            .current_generation
            .expect("compensation must restore current");
        assert_eq!(cur.as_str(), prior_gen.as_str());
        let assignment: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &crate::layout::generations()
                        .join(&cur)
                        .join("assignment.json"),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(assignment.behavior_sha256, a_digest);
        assert_ne!(
            assignment.behavior_sha256, b_digest,
            "the restored generation must carry the PRIOR behavior, not the desired one"
        );

        // OBSERVED REFRESH: observed.json carries the ACTUAL per-slot state —
        // the restored prior generation/artifact — and attributes the failed
        // attempt as the last deployment. It must NOT reflect the desired
        // (failed) v2 tree.
        let observed = h.store.read_observed("t1").unwrap();
        let os = &observed.slots[&PlacementSlotId::new("p1")];
        assert_eq!(os.generation, Some(prior_gen.clone()));
        let oa = os.artifact.as_ref().expect("observed artifact");
        assert_eq!(
            oa.tree, prior_tree,
            "observed tree must be the restored prior tree"
        );
        assert_eq!(oa.release, prior_release);
        let desired_tree = r2.attempt.as_ref().unwrap().desired[&PlacementSlotId::new("p1")]
            .assignment
            .artifact
            .tree
            .clone();
        assert_ne!(
            oa.tree, desired_tree,
            "observed must NOT reflect the desired (failed) v2 tree"
        );
        assert_eq!(os.last_deployment, Some(id2.clone()));
        // The per-server record mirrors the observed slot state.
        let server_state = h.store.read_server("s1").unwrap();
        assert_eq!(
            server_state
                .last_observed
                .as_ref()
                .and_then(|o| o.generation.clone()),
            Some(prior_gen.clone())
        );

        // The failed attempt is terminal FailedRolledBack, produced no
        // snapshot, and the f0 snapshot/ref are untouched.
        assert_eq!(
            latest_status(&h, id2.as_str()),
            DeploymentStatus::FailedRolledBack
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 2);
    }

    // ---- Batched stop_on_failure with batch_size > 1 ---------------------
    //
    // The integration `stop_on_failure_records_all_servers` test uses
    // batch_size = 1 and fails the FIRST server. Here the FIRST batch
    // advances successfully, a LATER batch fails, and stop_on_failure must
    // not start any subsequent batch — while the attempt still records EVERY
    // server (advanced, failed, and skipped alike).

    #[test]
    fn batched_stop_on_failure_stops_after_failing_batch() {
        const BATCHED_TOML: &str = r#"
schema_version = 1
application = "batched"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 2

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "c"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s4"
address = "d"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 2, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Variant `good` (sorts first, so its slots come first in the plan)
        // declares p1/p2 with PASSING verification; variant `z-failing`
        // declares p3/p4 with FAILING verification.
        let good = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/p2"

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
        let z_failing = r#"
[[slots]]
id = "p3"
server = "s3"
target = "t1"
deploy_dir = "/srv/p3"

[[slots]]
id = "p4"
server = "s4"
target = "t1"
deploy_dir = "/srv/p4"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("good.toml"), good).unwrap();
        std::fs::write(release_dir.join("z-failing.toml"), z_failing).unwrap();
        let artifacts = release_dir.join("artifacts");
        std::fs::create_dir_all(artifacts.join("build/output/app")).unwrap();
        std::fs::write(artifacts.join("build/output/app/server"), "v1\n").unwrap();

        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, BATCHED_TOML).unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = DeploymentId::new("deploy-batched-stop".to_string());
        let project_root = config.project_root(&cfg_path);
        let target = config.targets.get("t1").expect("target t1");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let r = push_inner(
            &project_root,
            &store,
            &factory,
            "t1",
            &PushRef::Head,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .unwrap();
        assert_eq!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack),
            "a failing later batch under stop_on_failure must roll the attempt back, got {:?}",
            r.status
        );

        // The attempt records ALL four servers (advanced, failed, skipped).
        let attempt = r.attempt.expect("attempt recorded on failure");
        assert_eq!(attempt.slot_ids.len(), 4);
        for sid in ["p1", "p2", "p3", "p4"] {
            assert!(
                attempt.slots.contains_key(&PlacementSlotId::new(sid)),
                "slot {sid} missing from attempt"
            );
        }
        let results = store.read_results(id.as_str()).unwrap();
        assert_eq!(results.slots.len(), 4);
        // The first batch advanced, then compensated back (no prior state ->
        // `current` removed): Restored.
        assert_eq!(
            results.slots[&PlacementSlotId::new("p1")].outcome,
            ServerOutcomeKind::Restored
        );
        assert_eq!(
            results.slots[&PlacementSlotId::new("p2")].outcome,
            ServerOutcomeKind::Restored
        );
        // The failing slot of the second batch.
        assert_eq!(
            results.slots[&PlacementSlotId::new("p3")].outcome,
            ServerOutcomeKind::Failed
        );
        // The slot after the failing one in the same/later batch was never
        // started.
        assert_eq!(
            results.slots[&PlacementSlotId::new("p4")].outcome,
            ServerOutcomeKind::Skipped
        );

        // The never-started server (p4) was left untouched: no `current`
        // pointer, no generation record.
        let remote4 = LocalTransport::new(remotes_base.join("s4")).unwrap();
        assert!(
            !remote4.exists(crate::layout::current()),
            "p4's server must never receive a current pointer"
        );
        assert_eq!(
            remote4.list(crate::layout::generations()).unwrap().len(),
            0,
            "p4's server must never receive a generation record"
        );
        // The failed slot's server was compensated back to no prior state.
        let remote3 = LocalTransport::new(remotes_base.join("s3")).unwrap();
        assert!(
            !remote3.exists(crate::layout::current()),
            "a compensated first-deploy slot has no current"
        );

        assert_eq!(store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(
            store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::FailedRolledBack)
        );

        // OBSERVED REFRESH FOR SKIPPED SLOTS: `observed.json` is refreshed
        // for EVERY member slot, including the never-started p4. The refresh
        // loop reads each slot's ACTUAL state from the remote `current` and
        // falls back to `{artifact: desired, generation: None}` when the
        // server has no live `current` — the contract for a Skipped slot (and
        // for a first-deploy slot compensated back to no prior state). The
        // observed entry must carry the DESIRED artifact (never a fabricated
        // generation, never a stale pre-push state).
        let observed = store.read_observed("t1").unwrap();
        assert_eq!(
            observed.slots.len(),
            4,
            "every member slot is refreshed in observed.json"
        );
        for sid in ["p1", "p2", "p3", "p4"] {
            let os = &observed.slots[&PlacementSlotId::new(sid)];
            assert_eq!(
                os.generation, None,
                "slot {sid} has no live generation after the failed push (Skipped or compensated first-deploy)"
            );
            let desired_art = &attempt.desired[&PlacementSlotId::new(sid)]
                .assignment
                .artifact;
            let oa = os.artifact.as_ref().expect("observed artifact present");
            assert_eq!(
                oa.tree, desired_art.tree,
                "slot {sid}'s observed artifact must be the DESIRED tree (no live generation to read)"
            );
            assert_eq!(oa.variant, desired_art.variant);
            assert_eq!(oa.release, desired_art.release);
            assert_eq!(os.last_deployment, Some(id.clone()));
        }

        assert!(
            store.read_snapshots("t1").unwrap().is_empty(),
            "a failed attempt must produce no snapshot"
        );
    }

    // ---- Fleet-ref membership-change refusal ------------------------------
    //
    // Exact fleet rollback requires the current target's placement-slot SET to
    // be identical to the snapshot's recorded set (in addition to each slot's
    // physical binding). When the variant file declares a DIFFERENT slot, the
    // refusal must fire in planning — before any remote connection or store
    // write — and leave every byte of store + remote state untouched.

    #[test]
    fn fleet_ref_membership_change_refuses_and_mutates_nothing() {
        let h = RecoveryHarness::new();
        let id1 = DeploymentId::new("deploy-membership-baseline".to_string());
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "f0 exists for the p1 membership"
        );

        // Change the target's placement-slot set: the variant file now
        // declares slot `p2` instead of `p1` (same server, same target). The
        // snapshot's recorded set ({p1}) then differs from the current
        // target's ({p2}) — membership CHANGED, unlike every other rollback
        // test which keeps the membership identical.
        let project_root = h.config.project_root(&h.cfg_path);
        let variant_path = project_root
            .join("releases")
            .join("v1")
            .join("standard.toml");
        let rebind_variant = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("id = \"p1\"", "id = \"p2\"");
        assert_ne!(
            rebind_variant,
            std::fs::read_to_string(&variant_path).unwrap(),
            "fixture must actually change the declared slot"
        );
        std::fs::write(&variant_path, rebind_variant).unwrap();
        let config2 = Config::load(&h.cfg_path).unwrap();
        let members2 = config2.target_slots("t1").unwrap();
        assert_eq!(members2.len(), 1);
        assert_eq!(members2[0].0.id, "p2", "current membership is now p2");

        // The exact fleet rollback must be refused with the membership error
        // and must not mutate ANY deployment state. The refusal fires in
        // `plan_assignments` (before the remote phase opens a connection);
        // `push()`'s advisory lock files are the only bytes created.
        let remotes_before = snapshot_files(&h.remotes_base);
        let observed_before = h.store.read_observed("t1").unwrap();
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let err = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &config2,
            &PushOptions {
                dry_run: false,
                ref_token: Some("t1@f0".to_string()),
            },
        )
        .err()
        .expect("membership change must refuse exact fleet rollback");
        assert!(
            err.to_string().contains("target membership changed"),
            "error must state the membership-change refusal, got: {err}"
        );
        assert!(
            err.to_string()
                .contains("identical stable placement-slot set"),
            "error must state the identical-slot-set requirement, got: {err}"
        );

        // Nothing mutated: no attempt, no snapshot, no observed change, and
        // the remote roots are byte-for-byte identical.
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        assert_eq!(h.store.read_observed("t1").unwrap(), observed_before);
        assert_eq!(
            remotes_before,
            snapshot_files(&h.remotes_base),
            "the refused rollback must not touch a single remote byte"
        );
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(
            remote.exists(crate::layout::current()),
            "the baseline f0 deployment on the remote is untouched"
        );
    }

    // ---- Historical dry runs (@fN and release/<id> refs) ------------------
    //
    // Every earlier dry-run test uses HEAD. A dry run against a HISTORICAL ref
    // must report exactly what a real push would do (the plan built from the
    // snapshot/release) while persisting NOTHING and touching no remote: no
    // attempt/transition/snapshot/store change, no generation/current change.

    #[test]
    fn historical_dry_run_fleet_ref_plans_without_mutating() {
        let h = RecoveryHarness::new();
        let id1 = DeploymentId::new("deploy-hist-dry-f0".to_string());
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let f0 = &r1.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")];
        let f0_tree = f0.artifact.tree.clone();
        let f0_gen = f0.generation.clone().expect("f0 generation");

        let store_before = snapshot_files(&h.store.base());
        let remotes_before = snapshot_files(&h.remotes_base);
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let r = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: true,
                ref_token: Some("t1@f0".to_string()),
            },
        )
        .unwrap();
        assert!(r.dry_run, "report flags the dry run");
        assert_eq!(r.status, None, "a dry run creates no attempt");
        assert!(r.attempt.is_none());
        assert!(
            r.message.contains("dry-run plan"),
            "reports a plan, got: {}",
            r.message
        );
        assert!(
            r.message.contains(f0_tree.as_str()),
            "the plan names the historical f0 tree, got: {}",
            r.message
        );

        // Persists NOTHING (byte-for-byte store) and touches no remote
        // (byte-for-byte remotes; the live `current` still names f0's
        // generation, no new generation was minted remotely).
        assert_eq!(
            store_before,
            snapshot_files(&h.store.base()),
            "a historical dry run must not write a single store byte"
        );
        assert_eq!(
            remotes_before,
            snapshot_files(&h.remotes_base),
            "a historical dry run must not touch a single remote byte"
        );
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        assert_eq!(
            status.current_generation.as_deref(),
            Some(f0_gen.as_str()),
            "the remote current still points at f0's generation"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
        assert_eq!(
            h.store.read_observed("t1").unwrap().slots[&PlacementSlotId::new("p1")].generation,
            Some(f0_gen),
            "observed state untouched by the dry run"
        );
    }

    #[test]
    fn historical_dry_run_release_ref_plans_without_mutating() {
        let h = RecoveryHarness::new();
        let id1 = DeploymentId::new("deploy-hist-dry-rel".to_string());
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let f0 = &r1.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")];
        let release = f0.artifact.release.clone();
        let tree = f0.artifact.tree.clone();

        let store_before = snapshot_files(&h.store.base());
        let remotes_before = snapshot_files(&h.remotes_base);
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let r = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: true,
                ref_token: Some(format!("release/{}", release.as_str())),
            },
        )
        .unwrap();
        assert!(r.dry_run);
        assert_eq!(r.status, None);
        assert!(r.attempt.is_none());
        assert!(
            r.message.contains("dry-run plan"),
            "reports a plan, got: {}",
            r.message
        );
        assert!(
            r.message.contains(tree.as_str()),
            "the plan names the release's tree, got: {}",
            r.message
        );
        assert_eq!(
            store_before,
            snapshot_files(&h.store.base()),
            "a historical release dry run must not write a single store byte"
        );
        assert_eq!(
            remotes_before,
            snapshot_files(&h.remotes_base),
            "a historical release dry run must not touch a single remote byte"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
    }

    // ---- Engine-level activation-failure compensation ---------------------
    //
    // The end-to-end rollback tests cover VERIFICATION failure; here the
    // systemd ACTIVATION fails mid-push (after `current` advanced) via a fake
    // `systemctl` shim that errors on `restart`. The attempt must compensate
    // back to the prior generation + prior behavior contract, end
    // `FailedRolledBack`, and refresh `observed.json` with the restored prior
    // state. The second test pins the compensation-FAILURE contract: the
    // attempt must be `Degraded` (requirement.md step 13: "If all compensation
    // succeeds, mark the attempt failed_rolled_back; otherwise mark it
    // degraded"), never a falsely clean `FailedRolledBack`.
    //
    // The fake systemctl is installed on PATH and `XDG_CONFIG_HOME` is pointed
    // at a hermetic temp dir (the unit gets installed there), under
    // `crate::testutil::ENV_LOCK` per the env-mutation invariant.

    const SYSD_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/sysd"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "systemd"
scope = "user"
units = [{ name = "svc.service", artifact_path = "app/svc.service", enable = true, restart = true }]

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// Restore the process env on drop, so a test that panics mid-way cannot
    /// leak a mutated PATH/XDG_CONFIG_HOME into a later test.
    struct EnvGuard {
        old_path: Option<std::ffi::OsString>,
        old_xdg: Option<std::ffi::OsString>,
        fail_marker: Option<std::ffi::OsString>,
        once: Option<std::ffi::OsString>,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.old_path {
                    Some(p) => std::env::set_var("PATH", p),
                    None => std::env::remove_var("PATH"),
                }
                match &self.old_xdg {
                    Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                    None => std::env::remove_var("XDG_CONFIG_HOME"),
                }
                match &self.fail_marker {
                    Some(v) => std::env::set_var("FAKE_SYSTEMCTL_FAIL", v),
                    None => std::env::remove_var("FAKE_SYSTEMCTL_FAIL"),
                }
                match &self.once {
                    Some(v) => std::env::set_var("FAKE_SYSTEMCTL_ONCE", v),
                    None => std::env::remove_var("FAKE_SYSTEMCTL_ONCE"),
                }
            }
        }
    }

    /// Install a fake `systemctl` shim on PATH and point `XDG_CONFIG_HOME` at
    /// a hermetic temp dir (the installed unit lands there). The shim fails
    /// `restart` (exit 1) while the marker file exists; with `once` it
    /// CONSUMES the marker on the first failure, so a later restart (e.g. the
    /// compensation's prior-activation restart) succeeds.
    fn install_fake_systemctl(
        base: &std::path::Path,
        marker: &std::path::Path,
        once: bool,
    ) -> EnvGuard {
        let bindir = base.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(
            &fake,
            "#!/bin/sh\nif [ \"$1\" = \"--user\" ]; then shift; fi\ncase \"$1\" in\nrestart)\n  if [ -n \"$FAKE_SYSTEMCTL_FAIL\" ] && [ -f \"$FAKE_SYSTEMCTL_FAIL\" ]; then\n    if [ \"$FAKE_SYSTEMCTL_ONCE\" = \"1\" ]; then rm -f \"$FAKE_SYSTEMCTL_FAIL\"; fi\n    echo \"fake systemctl: forced restart failure\" >&2\n    exit 1\n  fi\n  exit 0\n  ;;\n*)\n  exit 0\n  ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let old_path = std::env::var_os("PATH");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let old_fail = std::env::var_os("FAKE_SYSTEMCTL_FAIL");
        let old_once = std::env::var_os("FAKE_SYSTEMCTL_ONCE");
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
            std::env::set_var("XDG_CONFIG_HOME", base.join("xdg"));
            std::env::set_var("FAKE_SYSTEMCTL_FAIL", marker);
            std::env::set_var("FAKE_SYSTEMCTL_ONCE", if once { "1" } else { "0" });
        }
        EnvGuard {
            old_path,
            old_xdg,
            fail_marker: old_fail,
            once: old_once,
        }
    }

    /// A single-slot (`s1`/`t1`) project whose variant uses SYSTEMD
    /// activation with a `restart` unit, plus the artifact files.
    struct SysdHarness {
        _dir: tempfile::TempDir,
        cfg_path: PathBuf,
        config: Config,
        store: LocalStore,
        remotes_base: PathBuf,
    }

    impl SysdHarness {
        fn new() -> SysdHarness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let release_dir = project.join("releases").join("v1");
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(release_dir.join("standard.toml"), SYSD_VARIANT).unwrap();
            std::fs::write(project.join("deploy.toml"), NONE_TOML).unwrap();
            let artifacts = release_dir.join("artifacts");
            for (p, c) in [
                ("build/output/app/server", "v1\n"),
                (
                    "build/output/svc.service",
                    "[Unit]\nDescription=svc ({{ user }})\n\n[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
                ),
            ] {
                let fp = artifacts.join(p);
                std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
                std::fs::write(&fp, c).unwrap();
            }
            let cfg_path = project.join("deploy.toml");
            let config = Config::load(&cfg_path).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let remotes_base = dir.path().join("remotes");
            std::fs::create_dir_all(&remotes_base).unwrap();
            SysdHarness {
                _dir: dir,
                cfg_path,
                config,
                store,
                remotes_base,
            }
        }

        fn push_head(&self, deployment_id: &DeploymentId) -> Result<PushReport> {
            let project_root = self.config.project_root(&self.cfg_path);
            let target = self.config.targets.get("t1").expect("harness target");
            let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
            let rf = self.remotes_base.clone();
            let factory = move |s: &crate::config::ServerDef,
                                _slot: &crate::config::SlotDef|
                  -> Result<Box<dyn Remote>> {
                Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
            };
            push_inner(
                &project_root,
                &self.store,
                &factory,
                "t1",
                &PushRef::Head,
                deployment_id,
                &op_id,
                &self.config,
                target,
                &PushOptions {
                    dry_run: false,
                    ref_token: None,
                },
            )
        }
    }

    #[test]
    fn activation_failure_compensates_prior_and_observed_reflects_actual() {
        // The env-lock invariant: PATH/XDG_CONFIG_HOME/FAKE_SYSTEMCTL_* are
        // process-global, and the fake-ssh fingerprint suite mutates PATH too.
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let h = SysdHarness::new();
        let marker = h._dir.path().join("fail-restart");
        let _env = install_fake_systemctl(h._dir.path(), &marker, true);

        // Push 1: baseline. The fake systemctl succeeds (no marker), so
        // activation completes; f0 records the prior generation/artifact and
        // the remote publishes the prior behavior contract.
        let id1 = DeploymentId::new("deploy-act-fail-baseline".to_string());
        let r1 = h.push_head(&id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior = r1.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")].clone();
        let prior_gen = prior.generation.clone().expect("prior generation");
        let prior_tree = prior.artifact.tree.clone();
        let prior_release = prior.artifact.release.clone();
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let prior_assignment: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &crate::layout::generations()
                        .join(prior_gen.as_str())
                        .join("assignment.json"),
                )
                .unwrap(),
        )
        .unwrap();
        let prior_behavior_sha = prior_assignment.behavior_sha256.clone();

        // Push 2: the artifact content changes (so the push is not a no-op)
        // and the activation-failure marker is armed. The fake systemctl fails
        // the FIRST restart (the desired generation's activation) and consumes
        // the marker, so the compensation's prior-activation restart succeeds.
        let project_root = h.config.project_root(&h.cfg_path);
        std::fs::write(
            project_root
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server"),
            "v2\n",
        )
        .unwrap();
        std::fs::write(&marker, "fail").unwrap();
        let id2 = DeploymentId::new("deploy-act-fail".to_string());
        let r2 = h.push_head(&id2).unwrap();
        // Restore the environment and release the env lock BEFORE any
        // assertion: a failing assertion must never poison the shared
        // `ENV_LOCK` for the fingerprint/systemd env suites.
        drop(_env);
        drop(_lock);
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::FailedRolledBack),
            "an activation failure after the swap with successful compensation must end FailedRolledBack, got {:?}",
            r2.status
        );
        assert!(
            !marker.exists(),
            "the one-shot marker was consumed by the desired activation's failed restart"
        );

        // The report's ACTUAL per-slot state reflects the restored PRIOR
        // generation and artifact, never the desired v2 tree.
        let actual =
            &r2.attempt.as_ref().expect("attempt recorded").slots[&PlacementSlotId::new("p1")];
        assert_eq!(actual.generation, Some(prior_gen.clone()));
        assert_eq!(
            actual.artifact.tree, prior_tree,
            "the actual artifact must be the restored prior tree, not the desired v2 tree"
        );

        // results.json records the compensation: the slot FAILED (activation)
        // and was compensated inside the per-server pipeline at the PRIOR
        // generation.
        let results = h.store.read_results(id2.as_str()).unwrap();
        let res = &results.slots[&PlacementSlotId::new("p1")];
        assert_eq!(res.outcome, ServerOutcomeKind::Failed);
        assert!(res.compensated, "activation failure must be compensated");
        assert_eq!(res.generation, Some(prior_gen.clone()));

        // The remote `current` points at the PRIOR generation, whose stored
        // assignment carries the PRIOR behavior digest: the prior behavior
        // contract was restored, not the desired one.
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        let cur = status
            .current_generation
            .expect("compensation must restore current");
        assert_eq!(cur.as_str(), prior_gen.as_str());
        let assignment: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &crate::layout::generations()
                        .join(&cur)
                        .join("assignment.json"),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            assignment.behavior_sha256, prior_behavior_sha,
            "the restored generation must carry the PRIOR behavior contract"
        );

        // OBSERVED REFRESH: observed.json carries the ACTUAL per-slot state —
        // the restored prior generation/artifact — and attributes the failed
        // attempt as the last deployment. It must NOT reflect the desired
        // (failed) v2 tree.
        let observed = h.store.read_observed("t1").unwrap();
        let os = &observed.slots[&PlacementSlotId::new("p1")];
        assert_eq!(os.generation, Some(prior_gen.clone()));
        let oa = os.artifact.as_ref().expect("observed artifact");
        assert_eq!(
            oa.tree, prior_tree,
            "observed tree must be the restored prior tree"
        );
        assert_eq!(oa.release, prior_release);
        let desired_tree = r2.attempt.as_ref().unwrap().desired[&PlacementSlotId::new("p1")]
            .assignment
            .artifact
            .tree
            .clone();
        assert_ne!(
            oa.tree, desired_tree,
            "observed must NOT reflect the desired (failed) v2 tree"
        );
        assert_eq!(os.last_deployment, Some(id2.clone()));

        // The failed attempt is terminal FailedRolledBack, produced no
        // snapshot, and the f0 snapshot/ref are untouched.
        assert_eq!(
            h.store.latest_status(id2.as_str()).unwrap(),
            Some(DeploymentStatus::FailedRolledBack)
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
    }

    #[test]
    fn activation_failure_compensation_failure_is_degraded_not_rolled_back() {
        // Same scenario, but the marker is NEVER consumed (`once = false`):
        // the desired activation fails AND the compensation's prior-activation
        // restart fails too. requirement.md step 13 pins the contract: "If all
        // compensation succeeds, mark the attempt failed_rolled_back;
        // otherwise mark it degraded and retain the actual mixed per-server
        // state." A failed compensation must therefore end `Degraded`, never a
        // falsely clean `FailedRolledBack`.
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let h = SysdHarness::new();
        let marker = h._dir.path().join("fail-restart");
        let _env = install_fake_systemctl(h._dir.path(), &marker, false);

        let id1 = DeploymentId::new("deploy-act-compfail-baseline".to_string());
        let r1 = h.push_head(&id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior_gen = r1.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")]
            .generation
            .clone()
            .expect("prior generation");
        let prior_tree = r1.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")]
            .artifact
            .tree
            .clone();

        let project_root = h.config.project_root(&h.cfg_path);
        std::fs::write(
            project_root
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server"),
            "v2\n",
        )
        .unwrap();
        std::fs::write(&marker, "fail").unwrap();
        let id2 = DeploymentId::new("deploy-act-compfail".to_string());
        let r2 = h.push_head(&id2).unwrap();
        // Restore the environment and release the env lock BEFORE any
        // assertion: a failing assertion must never poison the shared
        // `ENV_LOCK` for the fingerprint/systemd env suites.
        drop(_env);
        drop(_lock);
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Degraded),
            "a failed compensation must end Degraded (docs: 'otherwise mark it degraded'), got {:?}",
            r2.status
        );
        assert!(
            marker.exists(),
            "the marker persists: every restart (desired AND compensation) failed"
        );

        // results.json records the failure WITHOUT compensation: the slot
        // stayed on the DESIRED generation (the compensation swap-back could
        // not re-activate the prior service).
        let results = h.store.read_results(id2.as_str()).unwrap();
        let res = &results.slots[&PlacementSlotId::new("p1")];
        assert_eq!(res.outcome, ServerOutcomeKind::Failed);
        assert!(
            !res.compensated,
            "the failed compensation must not be recorded as compensated"
        );

        // The attempt is terminal Degraded and produced no snapshot; f0 is
        // untouched.
        assert_eq!(
            h.store.latest_status(id2.as_str()).unwrap(),
            Some(DeploymentStatus::Degraded)
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1, "only the baseline snapshot exists");
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        // The mixed per-server state is retained, not hidden: the observed
        // refresh reads the ACTUAL `current`, which the compensation swap-back
        // moved to the prior generation even though the prior service could
        // not be re-activated.
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        assert_eq!(
            status.current_generation.as_deref(),
            Some(prior_gen.as_str()),
            "the compensation swap-back is visible on the remote current"
        );
        let observed = h.store.read_observed("t1").unwrap();
        let os = &observed.slots[&PlacementSlotId::new("p1")];
        assert_eq!(os.generation, Some(prior_gen.clone()));
        assert_eq!(
            os.artifact.as_ref().expect("observed artifact").tree,
            prior_tree
        );
    }

    // ---- First-deploy activation failure, preflight outcomes, observed
    // unknown-assignment fallback ------------------------------------------

    /// A transport wrapper that reports a FIXED number of available bytes,
    /// letting a test control the headroom the capacity preflight sees
    /// deterministically (mirrors `push::capacity::tests`).
    struct FakeCapacityRemote {
        inner: LocalTransport,
        avail: u64,
    }

    impl FakeCapacityRemote {
        fn build(base: PathBuf, avail: u64) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FakeCapacityRemote {
                inner: LocalTransport::new(base)?,
                avail,
            }))
        }
    }

    impl Remote for FakeCapacityRemote {
        fn root(&self) -> &std::path::Path {
            self.inner.root()
        }
        fn provision_layout(&self) -> Result<()> {
            self.inner.provision_layout()
        }
        fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<bool> {
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
            Ok(self.avail)
        }
    }

    /// FIRST-DEPLOY activation failure: there is no prior generation to
    /// restore, so compensation removes `current` — compare-and-swap style,
    /// only while it still points at the generation this attempt advanced
    /// (`remove_current_if`) — and the attempt is `FailedRolledBack`
    /// (requirement.md step 11: "On a first deployment with no prior
    /// generation, compensation removes `current` and reverses only adapter
    /// resources created by that attempt"; step 13: "If all compensation
    /// succeeds, mark the attempt `failed_rolled_back`"). The remote is left
    /// WITHOUT a stale `current` pointing at the dead generation.
    #[test]
    fn first_deploy_activation_failure_compensates_and_removes_current() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let h = SysdHarness::new();
        let marker = h._dir.path().join("fail-restart");
        // One-shot marker: the desired activation's restart fails and consumes
        // it; the (absent) prior activation contract has nothing to re-run.
        let _env = install_fake_systemctl(h._dir.path(), &marker, true);
        std::fs::write(&marker, "fail").unwrap();

        let id = DeploymentId::new("deploy-first-act-fail".to_string());
        let r = h.push_head(&id).unwrap();
        // Restore the environment and release the env lock BEFORE any
        // assertion: a failing assertion must never poison the shared
        // `ENV_LOCK` for the fingerprint/systemd env suites.
        drop(_env);
        drop(_lock);

        assert_eq!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack),
            "a compensated first-deploy activation failure must end FailedRolledBack, got {:?}",
            r.status
        );
        assert!(
            !marker.exists(),
            "the one-shot marker was consumed by the failed restart"
        );

        // The remote has NO stale `current`: the compare-and-swap removal
        // removed the link (it still pointed at the generation this attempt
        // advanced).
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(
            !remote.exists(crate::layout::current()),
            "first-deploy compensation must remove `current`"
        );
        let status = RemoteHelper::new(&remote).status().unwrap();
        assert!(
            status.current_generation.is_none(),
            "no current generation may remain after first-deploy compensation"
        );

        // results.json records the failure WITH compensation (the failure AND
        // the compensation result are both recorded, step 11) at the advanced
        // (then removed) generation.
        let results = h.store.read_results(id.as_str()).unwrap();
        let res = &results.slots[&PlacementSlotId::new("p1")];
        assert_eq!(res.outcome, ServerOutcomeKind::Failed);
        assert!(
            res.compensated,
            "first-deploy compensation must be recorded as compensated"
        );

        // The attempt is terminal FailedRolledBack and produced no snapshot /
        // no ref — a failed FIRST deployment has nothing to roll the ref back
        // from.
        assert_eq!(
            h.store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::FailedRolledBack)
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "a failed first deployment must produce no snapshot"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
    }

    /// A CAPACITY preflight failure (after the intent is durable, before any
    /// server mutation) must end the attempt `FailedPreflight` —
    /// requirement.md: "An attempt that fails before any `current` change is
    /// `failed_preflight`" — never a stranded `InProgress` that a later push
    /// would misreport as a recoverable attempt or falsely degrade. No
    /// generation, `current`, or object is created remotely; no snapshot or
    /// ref is produced.
    #[test]
    fn capacity_preflight_failure_records_failed_preflight_status() {
        let h = RecoveryHarness::new();
        let id = DeploymentId::new("deploy-capacity-preflight".to_string());
        // Deterministic capacity: the remote reports 100 bytes available and
        // the server policy reserves 1 MiB, so the first deployment cannot
        // fit its tree.
        let mut config = Config::load(&h.cfg_path).unwrap();
        config.servers[0].capacity = crate::config::CapacityConfig {
            reserve_bytes: 1024 * 1024,
            reserve_percent: 0,
        };
        let project_root = config.project_root(&h.cfg_path);
        let target = config.targets.get("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            FakeCapacityRemote::build(rf.join(&s.id), 100)
        };
        let err = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &PushRef::Head,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .err()
        .expect("capacity preflight must fail the push");
        assert!(
            err.to_string().contains("insufficient capacity"),
            "expected a capacity preflight error, got: {err}"
        );

        // The intent is durable and the attempt's LATEST status is the
        // terminal `FailedPreflight` — never stranded `InProgress`.
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(
            attempts.len(),
            1,
            "intent must be persisted before preflight"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::FailedPreflight,
            "a preflight failure after intent must end FailedPreflight"
        );
        let transitions = h.store.read_transitions(id.as_str()).unwrap();
        let statuses: Vec<DeploymentStatus> =
            transitions.iter().map(|t| t.status.clone()).collect();
        assert_eq!(
            statuses,
            vec![
                DeploymentStatus::InProgress,
                DeploymentStatus::FailedPreflight,
            ],
            "the attempt must evolve InProgress -> FailedPreflight"
        );

        // No reflog/snapshot, and NO remote deployment mutation: no `current`,
        // no generation record, no tree object.
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(!remote.exists(crate::layout::current()), "no current");
        assert!(
            remote
                .list(crate::layout::generations())
                .unwrap()
                .is_empty(),
            "no generation record may be durable"
        );
        assert!(
            remote.list(crate::layout::objects()).unwrap().is_empty(),
            "no tree object may be published"
        );
    }

    /// A HISTORICAL push whose release's behavior snapshot is missing (or
    /// corrupt) must fail in PREFLIGHT before any attempt, reflog, snapshot,
    /// or remote connection — never silently substitute the caller's current
    /// configuration (requirement.md: "a missing or corrupt historical
    /// behavior snapshot aborts the attempt during preflight").
    #[test]
    fn historical_release_missing_behavior_snapshot_fails_preflight_untouched() {
        let h = RecoveryHarness::new();
        // A release record whose behavior snapshot was never written:
        // `write_release` persists `release.json` only; the aux
        // `behavior.json` is absent.
        let release = crate::model::ReleaseId::new("rel-sha256-no-behavior".to_string());
        h.store
            .write_release(&crate::model::ReleaseRecord {
                release_schema_version: 1,
                release_id: release.as_str().to_string(),
                release_sha256: "rel-sha256-no-behavior".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                provenance: crate::model::Provenance {
                    git_revision: None,
                    mapping_sha256: "m".to_string(),
                    behavior_sha256: "b".to_string(),
                },
                variants: BTreeMap::from([("standard".to_string(), "tree-x".to_string())]),
                slots: BTreeMap::new(),
            })
            .unwrap();

        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.targets.get("t1").expect("harness target");
        let op_id = OperationId::new("op-historical-behavior".to_string());
        let id = DeploymentId::new("deploy-hist-behavior".to_string());
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let err = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &id,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .err()
        .expect("a release without its behavior snapshot must fail preflight");
        assert!(
            err.to_string().contains("historical behavior")
                && err.to_string().contains("unavailable"),
            "expected a historical-behavior preflight error, got: {err}"
        );

        // Nothing recorded and nothing touched: no attempt, no snapshot/ref,
        // and the remote directory was never even created (the failure fires
        // before any remote connection).
        assert!(h.store.read_attempts("t1").unwrap().is_empty());
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());
        assert!(
            !h.remotes_base.join("s1").exists(),
            "no remote layout may be created before the preflight failure"
        );

        // The same preflight refusal fires for a CORRUPT (unparseable)
        // behavior snapshot: write garbage over behavior.json.
        let behavior_path = h.store.release_dir(&release).join("behavior.json");
        std::fs::create_dir_all(behavior_path.parent().unwrap()).unwrap();
        std::fs::write(&behavior_path, b"{ not json !").unwrap();
        let op_id2 = OperationId::new("op-historical-behavior-2".to_string());
        let err2 = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &PushRef::Release {
                release: release.clone(),
                current_variant: false,
            },
            &id,
            &op_id2,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .err()
        .expect("a corrupt behavior snapshot must also fail preflight");
        assert!(
            err2.to_string().contains("historical behavior")
                && err2.to_string().contains("unavailable"),
            "expected a historical-behavior preflight error, got: {err2}"
        );
        assert!(h.store.read_attempts("t1").unwrap().is_empty());
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
    }

    /// OBSERVED-REFRESH UNKNOWN-ASSIGNMENT FALLBACK: when a live generation's
    /// `assignment.json` cannot be read (missing/corrupt), the refresh must
    /// preserve the OBSERVED generation and mark the assignment UNKNOWN
    /// (`ArtifactRef::default()`) — never substitute the desired/planned
    /// artifact. BOTH the pre-push intent (`pre_push`) and the post-push
    /// observed refresh use this contract; results.json records the slot's
    /// pre-swap failure, `current` stays on the observed (corrupt) generation,
    /// and no stale snapshot/ref is produced.
    #[test]
    fn observed_refresh_preserves_generation_with_unknown_assignment() {
        let h = RecoveryHarness::new();
        let id1 = DeploymentId::new("deploy-obs-fallback-baseline".to_string());
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let gen1 = r1.attempt.as_ref().expect("attempt").slots[&PlacementSlotId::new("p1")]
            .generation
            .clone()
            .expect("baseline generation");
        eprintln!("DEBUG gen1={gen1}");

        // Corrupt the live generation's assignment record on the remote.
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let asn_path = crate::layout::generations()
            .join(gen1.as_str())
            .join("assignment.json");
        remote.write(&asn_path, b"{ corrupt json !", 0o600).unwrap();
        assert!(
            RemoteHelper::new(&remote)
                .read_assignment(gen1.as_str())
                .is_err(),
            "the assignment must be unreadable after corruption"
        );

        // Push 2: the artifact content changes (not a no-op) and the
        // generation-record write for the NEW generation fails once
        // (pre-swap). `current` therefore stays at gen1 — whose assignment is
        // unreadable.
        std::fs::write(
            h.config
                .project_root(&h.cfg_path)
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server"),
            "v2\n",
        )
        .unwrap();
        let id2 = DeploymentId::new("deploy-obs-fallback".to_string());
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            FailOnceGenerationRemote::build(rf.join(&s.id), armed_for_factory.clone())
        };
        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.targets.get("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id2.as_str()));
        let r2 = push_inner(
            &project_root,
            &h.store,
            &fault_factory,
            "t1",
            &PushRef::Head,
            &id2,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::FailedRolledBack),
            "a pre-swap mid-mutation failure must be reported as a failure, got {:?}",
            r2.status
        );

        // The remote `current` still points at gen1 (never advanced, never
        // clobbered) — the observed generation we are about to record.
        let status = RemoteHelper::new(&remote).status().unwrap();
        assert_eq!(status.current_generation.as_deref(), Some(gen1.as_str()));

        // THE OBSERVED FALLBACK: observed.json preserves the observed
        // generation and marks the assignment UNKNOWN (the default artifact),
        // never the desired v2 artifact.
        let observed = h.store.read_observed("t1").unwrap();
        let os = &observed.slots[&PlacementSlotId::new("p1")];
        assert_eq!(
            os.generation,
            Some(gen1.clone()),
            "observed generation must be preserved"
        );
        let oa = os.artifact.as_ref().expect("observed artifact present");
        assert_eq!(
            oa,
            &ArtifactRef::default(),
            "an unreadable assignment must be marked unknown (default artifact), got: {oa:?}"
        );
        let desired_art = &r2.attempt.as_ref().expect("attempt").desired
            [&PlacementSlotId::new("p1")]
            .assignment
            .artifact;
        assert_ne!(
            oa.tree, desired_art.tree,
            "observed must NOT substitute the desired v2 artifact"
        );
        assert_eq!(os.last_deployment, Some(id2.clone()));

        // The PERSISTED INTENT's pre_push map uses the SAME contract:
        // generation preserved, assignment unknown.
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 2);
        let intent2 = &attempts[1];
        assert_eq!(intent2.deployment_id, id2);
        let pp = intent2.pre_push[&PlacementSlotId::new("p1")]
            .as_ref()
            .expect("pre_push present");
        assert_eq!(pp.generation, Some(gen1.clone()));
        assert_eq!(
            pp.artifact,
            ArtifactRef::default(),
            "pre_push must mark the unreadable assignment unknown, not fabricate the desired one"
        );

        // results.json records the pre-swap failure; the failed attempt
        // produced no snapshot/ref and the baseline ref is untouched.
        let results = h.store.read_results(id2.as_str()).unwrap();
        assert_eq!(
            results.slots[&PlacementSlotId::new("p1")].outcome,
            ServerOutcomeKind::Failed
        );
        assert_eq!(
            latest_status(&h, id2.as_str()),
            DeploymentStatus::FailedRolledBack
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
    }

    /// The `leave_changed` failure policy (requirement.md step 13: "An
    /// optional `leave_changed` policy may retain successful advances
    /// deliberately; any attempt with failures under that policy is
    /// `degraded`") must NOT compensate earlier successful batches: the
    /// advanced slots keep their `current`, the attempt ends `Degraded` (never
    /// a falsely clean `FailedRolledBack`), and the failing slot is still
    /// compensated IN-PROCESS (step 11, per-server) with its own `current`
    /// removed on first deploy.
    #[test]
    fn leave_changed_policy_retains_advances_and_reports_degraded() {
        const LEAVE_TOML: &str = r#"
schema_version = 1
application = "leave"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 2

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "c"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s4"
address = "d"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 2, stop_on_failure = true, failure_policy = "leave_changed" }
"#;
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Variant `good` (sorts first) declares p1/p2 with PASSING
        // verification; variant `z-failing` declares p3/p4 with FAILING
        // verification.
        let good = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/p2"

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
        let z_failing = r#"
[[slots]]
id = "p3"
server = "s3"
target = "t1"
deploy_dir = "/srv/p3"

[[slots]]
id = "p4"
server = "s4"
target = "t1"
deploy_dir = "/srv/p4"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("good.toml"), good).unwrap();
        std::fs::write(release_dir.join("z-failing.toml"), z_failing).unwrap();
        let artifacts = release_dir.join("artifacts");
        std::fs::create_dir_all(artifacts.join("build/output/app")).unwrap();
        std::fs::write(artifacts.join("build/output/app/server"), "v1\n").unwrap();

        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, LEAVE_TOML).unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = DeploymentId::new("deploy-leave-changed".to_string());
        let project_root = config.project_root(&cfg_path);
        let target = config.targets.get("t1").expect("target t1");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let r = push_inner(
            &project_root,
            &store,
            &factory,
            "t1",
            &PushRef::Head,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
        .unwrap();
        assert_eq!(
            r.status,
            Some(DeploymentStatus::Degraded),
            "under leave_changed a failing batch must end Degraded, got {:?}",
            r.status
        );

        // The earlier successful batch is retained deliberately: p1/p2 keep
        // their live `current` (no fleet compensation pass runs).
        for (sid, sname) in [("p1", "s1"), ("p2", "s2")] {
            let remote = LocalTransport::new(remotes_base.join(sname)).unwrap();
            assert!(
                remote.exists(crate::layout::current()),
                "slot {sid} must stay advanced under leave_changed"
            );
        }
        // The FAILING slot is still compensated in-process (step 11) and its
        // first-deploy `current` was removed; the never-started slot is
        // untouched.
        let remote3 = LocalTransport::new(remotes_base.join("s3")).unwrap();
        assert!(
            !remote3.exists(crate::layout::current()),
            "the failing slot's current is removed by in-process compensation"
        );
        let remote4 = LocalTransport::new(remotes_base.join("s4")).unwrap();
        assert!(
            !remote4.exists(crate::layout::current()),
            "the never-started slot has no current"
        );

        // Per-slot outcomes: advanced, failed(+compensated), skipped.
        let results = store.read_results(id.as_str()).unwrap();
        assert_eq!(
            results.slots[&PlacementSlotId::new("p1")].outcome,
            ServerOutcomeKind::Activated
        );
        assert_eq!(
            results.slots[&PlacementSlotId::new("p2")].outcome,
            ServerOutcomeKind::Activated
        );
        assert_eq!(
            results.slots[&PlacementSlotId::new("p3")].outcome,
            ServerOutcomeKind::Failed
        );
        assert!(
            results.slots[&PlacementSlotId::new("p3")].compensated,
            "the failing slot's in-process compensation is recorded"
        );
        assert_eq!(
            results.slots[&PlacementSlotId::new("p4")].outcome,
            ServerOutcomeKind::Skipped
        );

        // No snapshot/ref for a degraded attempt.
        assert!(
            store.read_snapshots("t1").unwrap().is_empty(),
            "a degraded attempt must produce no snapshot"
        );
        assert!(store.read_last_successful("t1").is_none());
        assert_eq!(
            store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::Degraded)
        );
    }

    /// The bare `@fN` ref form (no target prefix) is filled in by the engine
    /// from the push's own target argument (`history.rs`: "An empty target
    /// (e.g. ref token `@f0`) is filled in by the caller from the separate
    /// target argument"). A dry run against `@f0` must plan the SAME
    /// historical fleet snapshot as the explicit `t1@f0` form.
    #[test]
    fn bare_at_f_ref_fills_target_from_push_argument() {
        let h = RecoveryHarness::new();
        let id1 = DeploymentId::new("deploy-bare-atf".to_string());
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let f0_tree = r1.attempt.as_ref().unwrap().slots[&PlacementSlotId::new("p1")]
            .artifact
            .tree
            .clone();

        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotDef|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
        };
        let r = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: true,
                ref_token: Some("@f0".to_string()),
            },
        )
        .unwrap();
        assert!(r.dry_run, "the bare `@f0` dry run plans without mutating");
        assert!(
            r.message.contains(f0_tree.as_str()),
            "the bare `@f0` form must plan the same f0 snapshot as `t1@f0`, got: {}",
            r.message
        );
    }
}

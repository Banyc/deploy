//! The PRE-MUTATION phases of the push transaction: the numbered steps that
//! run BEFORE any server `current` changes (variant materialization + the
//! release identity, read-only remote construction + status, reconciliation,
//! ref resolution, the frozen behavior index, plan construction, the
//! partial-rollout + behavior-coverage guards, mutating remote prep, the
//! per-slot plan / pre-push observation tables, intent persistence, and the
//! capacity + staging preflight). [`run_preflight`] is the single
//! coordinator and returns the [`PreflightOutcome`] the mutation phases
//! consume; the direct-release membership gate and the advisory-lock
//! acquisition that [`crate::deploy::push::push`] performs before
//! [`crate::deploy::push::push_inner`] also live here.
//!
//! Nested by phase: [`gate`] (the direct-release membership gate), [`locks`]
//! (the advisory-lock acquisition), [`remotes`] (read-only remote
//! construction + status inspection), [`capacity`] (the capacity + staging
//! preflight), [`intent`] (intent persistence).

use crate::config::Mapping;
use crate::config::SlotConfig;
use crate::deploy::plan::PlannedAssignment;
use crate::deploy::push::PushContext;
use crate::deploy::rollout::REMOTE_RELEASE_JSON;
use crate::error::Error;
use crate::error::Result;
use crate::identity::BehaviorContract;
use crate::identity::GenerationId;
use crate::identity::ReleaseId;
use crate::identity::SlotId;
use crate::identity::TreeDigest;
use crate::identity::VariantName;
use crate::kernel::snapshot::PreviousGeneration;
use crate::ledger;
use crate::ledger::BehaviorIndex;
use crate::ledger::DeploymentPlan;
use crate::ledger::Observation;
use crate::ledger::ObservationError;
use crate::ledger::PushRef;
use crate::ledger::SlotPlan;
use crate::ledger::recovery::reconcile_pending_commits;
use crate::remote::canonical as tree;
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::Remote;
use crate::store::local::ledger::TargetLedgerTxn;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;

mod capacity;
mod gate;
mod intent;
mod locks;
mod remotes;

pub(crate) use capacity::*;
pub(crate) use gate::*;
pub(crate) use intent::*;
pub(crate) use locks::*;
pub(crate) use remotes::*;

// PRE-MUTATION phases of the push transaction (the numbered steps that run
// BEFORE any server `current` changes): variant materialization + the
// release identity (steps 3-4), the read-only remote construction + status,
// reconciliation, the ref-resolution ordering, the frozen behavior index,
// plan construction (steps 5 & 7), the partial-rollout + behavior-coverage
// guards, the mutating remote prep (phase B), the per-slot plan / pre-push
// observation tables, intent persistence, and the capacity + staging
// preflight (steps 8-9). [`run_preflight`] is the single coordinator for
// this block and returns the [`PreflightOutcome`] the mutation phases
// (execute, commit) consume; the
// direct-release membership gate and the advisory-lock acquisition that
// [`crate::deploy::push::push`] performs before
// [`crate::deploy::push::push_inner`] live here as
// [`gate_direct_release_membership`] and [`acquire_locks`]. A failure in
// any phase here ends the attempt `FailedPreflight` (no slot was touched) —
// the capacity/staging failure path is the caller's [`PreflightFailure`]
// contract.

/// A preflight failure tagged with the failing phase, so the terminal reason
/// is DERIVED from the error at the failure site — never a hand-maintained
/// string that a new failure source could leave naming the wrong phase.
pub(crate) struct PreflightFailure {
    /// The `FailedPreflight` terminal reason naming the failing phase.
    pub(crate) reason: &'static str,
    /// The ORIGINAL error, returned unchanged by the caller.
    pub(crate) source: Error,
}

/// Everything the pre-mutation phases produce for the mutation + commit
/// phases: the open per-slot remotes/helpers/statuses stay in the caller's
/// scope (the helpers borrow the remotes, so they cannot travel inside this
/// struct), while the planning outcome — the resolved ref, the frozen
/// behavior index, the planned assignments, the per-slot plan / pre-push
/// tables, and the persisted plan — travels in this struct.
pub(crate) struct PreflightOutcome {
    /// The RESOLVED push ref (post-reconciliation for a real push; the
    /// pre-resolved dry-run ref otherwise).
    pub pref: PushRef,
    /// The frozen per-release, per-variant behavior index this attempt is
    /// bound to (the digest the intent persists).
    pub behavior_index: BehaviorIndex,
    /// The planned per-slot assignments (exactly the SELECTED slots).
    pub assignments: Vec<PlannedAssignment>,
    /// The per-slot plan with the expected (pre-push) generation.
    pub plan_servers: BTreeMap<SlotId, SlotPlan>,
    /// The freshly minted desired generation per planned slot.
    pub new_gen: HashMap<SlotId, GenerationId>,
    /// The observed pre-push state per planned slot — the intent's OWN
    /// three-state observations ([`Observation<PreviousGeneration>`]), used
    /// DIRECTLY (no intermediate re-wrap).
    pub pre_push: BTreeMap<SlotId, Observation<PreviousGeneration>>,
    /// The plan persisted BEFORE any server mutation.
    pub plan: DeploymentPlan,
}

/// Run every pre-mutation phase from the remote-open point on (steps 3-9,
/// in the numbered order) and return the planning outcome. The per-slot
/// `remotes`/`helpers`/`statuses` were opened by [`open_remotes`] +
/// [`inspect_remotes`] and outlive this call (the helpers borrow the
/// remotes — see [`PreflightOutcome`]). `txn` is the push's target ledger
/// transaction (owned by the caller): `Some` for a real push (recovery
/// appends through it), `None` for a dry run (which touches nothing).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_preflight(
    ctx: &PushContext,
    txn: &mut Option<TargetLedgerTxn<'_>>,
    remotes: &HashMap<SlotId, Box<dyn Remote>>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    statuses: &HashMap<SlotId, crate::remote::helper::RemoteStatus>,
) -> Result<PreflightOutcome> {
    let project_root = ctx.project_root;
    let store = ctx.store;
    let target_name = ctx.target_name;
    let selection = ctx.selection;
    let ref_expr = ctx.ref_expr;
    let deployment_id = ctx.deployment_id;
    let op_id = ctx.op_id;
    let config = ctx.config;
    let opts = ctx.opts;
    // The PRE-RESOLVED ref: `Some` for a dry run (resolved by [`push`]
    // before any lock or remote factory invocation); `None` for a real push,
    // which resolves at the post-reconciliation resolution point below.
    let resolved = ctx.resolved.clone();
    // 3. Materialize every declared variant. Mappings resolve from the release
    //    directory (`<project>/releases/<release>/` — the structure is forced),
    //    not the project root, so an artifact `from` can never escape into the
    //    project's other files. Dry-run uses disposable staging and never writes
    //    to the object store.
    let release_root = project_root
        .join("releases")
        .join(config.release().as_str());
    let mut variant_trees: BTreeMap<String, TreeDigest> = BTreeMap::new();
    if ref_expr.is_head_push() {
        for v in config.variant_names() {
            let staging = if opts.dry_run {
                store
                    .staging_dir()
                    .join(format!("dry-{}", deployment_id.as_str()))
                    .join(&v)
            } else {
                store.staging_dir().join(&v)
            };
            crate::remote::canonical::materialize_variant(
                &release_root,
                &config.variant(&v)?.artifact.mappings,
                &crate::remote::canonical::TemplateVars::mapping(
                    config.application().as_str(),
                    config.release().as_str(),
                    &v,
                ),
                &staging,
            )?;
            let meta = tree::canonicalize_tree(&staging)?;
            if !opts.dry_run {
                store.store_object(
                    &TreeDigest::parse(&meta.tree_sha256)
                        .expect("canonicalized tree sha256 is a valid digest"),
                    &staging,
                )?;
            }
            variant_trees.insert(
                v,
                TreeDigest::parse(&meta.tree_sha256)
                    .expect("canonicalized tree sha256 is a valid digest"),
            );
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
    // release. Retention is target-wide configuration read from `deploy.toml` at
    // push time, so it is not snapshotted per variant either.
    let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    let mut variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::new();
    let mut variant_slots: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
    for v in config.variant_names() {
        let vcfg = config.variant(&v)?;
        variant_mappings.insert(v.clone(), vcfg.artifact.mappings.clone());
        variant_behaviors.insert(
            v.clone(),
            BehaviorContract::new(vcfg.activation.clone(), vcfg.verification.clone()),
        );
        variant_slots.insert(v.clone(), vcfg.slots.clone());
    }
    let mapping_sha = crate::verify::release::variant_mappings_digest(&variant_mappings);
    let behavior_sha = crate::verify::release::variant_behaviors_digest(&variant_behaviors);
    let behavior_json = serde_json::to_value(&variant_behaviors)?;
    let mapping_toml = toml::to_string_pretty(&variant_mappings)
        .map_err(|e| Error::store(format!("serialize mappings: {e}")))?;

    // The available SERVER SET of the graph being deployed: every release's
    // frozen slots must bind servers that exist in the caller's CURRENT
    // configuration (a slot binding an unknown server cannot be operated on).
    // This is the server context handed to the complete release validator.
    let server_ids: BTreeSet<String> = config
        .servers()
        .map(|s| s.id.as_str().to_string())
        .collect();

    // The helpers/statuses cover ALL of the target's member slots (a pending
    // attempt may involve any of them, and deferred-retention debt for any of
    // them is serviced from here); the SELECTED slots — the per-branch
    // resolution of the {target, group} selection — are the ones this push
    // plans, mutates, and refreshes, derived from the plan's assignments
    // below (after `plan_assignments` resolved the group's slot IDs inside
    // each reference branch: HEAD/deployment from the CURRENT topology,
    // `release:<id>` from the release's FROZEN topology rebound to the
    // current physical slots).
    let all_members = config.target_slots(target_name)?;

    // Reconcile `PendingCommit` attempts left by earlier pushes BEFORE the
    // ref is resolved and BEFORE the early no-op check: an up-to-date push
    // must complete the missing commit markers (and advance the snapshot log)
    // rather than returning "Everything up to date" with the metadata still
    // absent. Runs under the local target lock already held by this push;
    // never reactivates or restarts services (markers/transition/snapshot
    // only). A recovered attempt finalizes through the SHARED finalizer
    // (`ledger::finalize_successful_locked`), which APPENDS its snapshot
    // entry to the target's chain — the very append the relative refs below
    // must see. THE STRICT-LINEAR REFUSAL (spec item 6): when the recovery
    // step CANNOT finish the previous pending attempt (the shared finalizer
    // returned `Pending` — locks contended / live state not finalizable
    // right now — OR a degraded path's evidence-collection lock acquisition
    // failed: a truthful degraded terminal cannot be built without the
    // backend read), the attempt REMAINS pending and the push REFUSES — it
    // never plans a second intent on top while any previous intent lacks a
    // terminal (even for disjoint groups). Dry-run never reconciles (it
    // touches nothing).
    if !opts.dry_run {
        use crate::ledger::recovery::RecoveryOutcome;
        let txn = txn
            .as_mut()
            .expect("a real push holds the target ledger txn");
        if let Some(RecoveryOutcome::StillPending) =
            reconcile_pending_commits(txn, config, op_id, helpers)?
        {
            return Err(Error::conflict("a previous deployment is still pending"));
        }
    }

    // RESOLUTION POINT — a REAL push's parsed ref is resolved ONLY NOW:
    // AFTER reconciliation appended any recovered snapshot entries (a
    // relative ref must see the post-recovery chain: `@-` means one before
    // the latest INCLUDING this push's reconciled append, so `parent(@, d)`
    // selects post-reconciliation latest - d) and AFTER the locks were
    // acquired. A dry run arrives with `resolved = Some(...)` from [`push`]
    // (resolved pre-lock, pre-factory — a dry run never reconciles, so the
    // chain it resolved against is identical) and skips this store read;
    // only a real push reaches it. Parsing happened up front (store-free,
    // before serialization); every step from here down consumes the RESOLVED
    // form.
    let pref = match resolved {
        Some(pref) => pref,
        None => ledger::resolve_ref_expr(ref_expr, target_name, store)?,
    };

    // Historical and rollback pushes carry EACH referenced release's own
    // per-variant behavior contracts (the per-release, per-variant behavior
    // index); they never fall back to the caller's current config. A rollback
    // snapshot's slots can carry artifacts from DIFFERENT releases (partial
    // pushes over time), so the index spans every release the ref references
    // and each slot's behavior resolves from ITS OWN (release, variant)
    // binding — never a snapshot-wide single release.
    let (local_release_id, behavior_index): (ReleaseId, BehaviorIndex) = if matches!(
        &pref,
        PushRef::Head
    ) {
        let bindings: BTreeMap<VariantName, TreeDigest> = variant_trees
            .iter()
            .map(|(k, v)| {
                (
                    VariantName::parse(k).expect("variant name is a safe segment"),
                    v.clone(),
                )
            })
            .collect();
        let rec = crate::verify::release::build_release(
            &mapping_sha,
            &behavior_sha,
            &bindings,
            &variant_slots,
            project_root,
        );
        let rid = ReleaseId::parse(&rec.release_id)
            .expect("newly built release record carries a validated release id");
        // COMPLETE SEMANTIC VALIDATION of the freshly built record BEFORE it
        // is persisted or planned: the record + its behavior contracts must
        // form a consistent release graph (slot declarations complete and
        // parseable, unique slot ids, every binding's server known, complete
        // behavior coverage, digest-consistent record AND behavior graph).
        // An unsupported/unknown activation or verification adapter was
        // already refused when the contracts were parsed into the closed
        // enums above, so a silent no-op adapter can never reach a push.
        crate::verify::release::ValidatedRelease::try_new(
            rec.clone(),
            variant_behaviors.clone(),
            &server_ids,
        )
        .map_err(|e| Error::preflight(format!("release {rid} fails semantic validation: {e}")))?;
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
        (rid.clone(), BTreeMap::from([(rid, variant_behaviors)]))
    } else {
        // Historical ref: the referenced releases are DERIVED from the ref. A
        // rollback snapshot carries per-slot artifacts from DIFFERENT
        // releases, so the set comes from the slots' own bindings — there is
        // NO snapshot-wide single release.
        let releases: BTreeSet<ReleaseId> = match &pref {
            PushRef::Deployment {
                target: ft,
                deployment_id,
            } => ledger::resolve_deployment(store, ft, deployment_id)?.releases(),
            PushRef::Release { release, .. } => BTreeSet::from([release.clone()]),
            PushRef::Head => unreachable!(),
        };
        if releases.is_empty() {
            return Err(Error::preflight(
                "rollback snapshot carries no slots; cannot resolve behavior contracts (fail closed)",
            ));
        }
        // Restore the historical per-release, per-variant behavior contracts
        // from the release records, NOT the caller's current configuration.
        // If any referenced release's behavior is unavailable we fail closed
        // (preflight) rather than silently deploying the caller's current
        // configuration instead.
        let index = crate::deploy::plan::release_behavior_index(store, &releases).map_err(|e| {
            Error::preflight(format!(
                "historical behavior unavailable (immutable behavior required): {e}"
            ))
        })?;
        // COMPLETE SEMANTIC VALIDATION of EVERY referenced release BEFORE
        // anything is planned or published (dry-run too): each record + its
        // own per-variant behavior contracts must form a consistent release
        // graph (slot declarations complete and parseable, unique slot ids,
        // every frozen slot binding a known server, complete behavior
        // coverage with digest-consistent record AND behavior graph). An
        // unsupported activation/verification adapter in a frozen behavior
        // snapshot was already refused when the contracts were parsed into
        // the closed enums by [`LocalStore::read_release_behaviors`] — a
        // silent no-op adapter can never reach a historical push.
        for rid in &releases {
            let rec = store.read_release(rid).map_err(|e| {
                Error::preflight(format!("historical release {rid} not found: {e}"))
            })?;
            let behaviors = index.get(rid).cloned().ok_or_else(|| {
                Error::preflight(format!(
                    "historical release {rid} has no behavior contracts (fail closed)"
                ))
            })?;
            crate::verify::release::ValidatedRelease::try_new(rec, behaviors, &server_ids)
                .map_err(|e| {
                    Error::preflight(format!(
                        "historical release {rid} fails semantic validation: {e}"
                    ))
                })?;
        }
        if !opts.dry_run {
            // Publish EVERY referenced release's record + behavior snapshot:
            // each slot's server publishes ITS OWN slot's release, so a
            // multi-release rollback must carry every referenced release into
            // the publication cache — never only the first.
            for rid in &releases {
                let rec = store.read_release(rid).map_err(|e| {
                    Error::preflight(format!("historical release {rid} not found: {e}"))
                })?;
                let release_json = serde_json::to_string(&rec)
                    .map_err(|e| Error::store(format!("serialize release: {e}")))?;
                let behaviors_json = serde_json::to_string(&index[rid])
                    .map_err(|e| Error::store(format!("serialize behavior: {e}")))?;
                REMOTE_RELEASE_JSON.with(|c| {
                    c.borrow_mut()
                        .insert(rid.clone(), (release_json, behaviors_json))
                });
            }
        }
        (
            releases
                .first()
                .cloned()
                .expect("releases non-empty after empty check"),
            index,
        )
    };

    // The behavior digest this attempt is bound to is the canonical digest of
    // the frozen per-release, per-variant index; it is computed when the
    // intent is persisted ([`persist_intent`]) — historical and rollback
    // pushes use the historical releases' own contracts (the index above).

    // 5 & 7. Build the plan from the RESOLVED ref (post-reconciliation).
    // The plan covers exactly the SELECTED slots (the normalized selection).
    // THE SOURCE OWNS ITS REQUIRED PAYLOAD: the plan's origin
    // ([`crate::ledger::PlanOrigin`]) is the VERIFIED form — a DIRECT
    // release ref (a `release:<id>` push applies the release's frozen
    // topology onto the CURRENT physical slots) carries its
    // [`crate::ledger::VerifiedReleaseRebinding`] proof INSIDE the source;
    // HEAD and deployment refs carry none. The planner ALSO produces the
    // PROOF-BEARING resolution ([`crate::deploy::plan::ResolvedSelection`]:
    // target + declared temporal source + the non-empty resolved slot set),
    // which the engine consumes BY ACCESSOR below (`planned.resolved()`) —
    // never by construction.
    // (`desired_releases` is now DERIVED from the plan's authoritative per-slot
    // collection (`DeploymentPlan::releases`), never stored on the domain).
    let planned = crate::deploy::plan::plan_assignments(
        selection,
        &pref,
        &local_release_id,
        &variant_trees,
        store,
        config,
    )?;
    // The PROOF-BEARING resolution is consumed BY ACCESSOR (the planner is
    // the only constructor; the engine never builds one).
    let resolved_sel = planned.resolved().clone();
    let (assignments, origin) = (planned.assignments, planned.origin);
    // The plan's target is DERIVED from the proof-bearing resolution: the
    // resolved target IS the plan's target. The plan's ORIGIN is the
    // planner's VERIFIED [`crate::ledger::PlanOrigin`] (built from the
    // resolution's declared temporal source — the planner's proof is the
    // single authority for what this plan resolves against — and, for a
    // Release origin, the membership gate's verified rebinding proof).

    // THE SELECTED (slot, server) pairs this push plans, mutates, and
    // refreshes: derived from the plan's assignments — the per-branch
    // slot-ID resolution (`plan_assignments` resolved the group's slots
    // inside each reference branch: HEAD/deployment from the CURRENT
    // topology, a `release:<id>` from the RELEASE's FROZEN group topology,
    // rebound onto the current physical slots), so the remote phase,
    // verification, and refresh always operate on exactly the planned slots
    // — even when the release's frozen group partition differs from the
    // current one (the bug: the selection resolved the group from the
    // caller's current config alone, so a historical release's frozen group
    // selected the WRONG slots here).
    //
    // The plan's PROOF-BEARING resolution ([`crate::deploy::plan::ResolvedSelection`])
    // is consumed by accessor: the planner built it (target + declared
    // temporal source + the non-empty resolved slot set), the engine never
    // constructs one.
    let members: Vec<(&crate::config::SlotConfig, &crate::config::ServerDef)> = assignments
        .iter()
        .map(|a| {
            all_members
                .iter()
                .find(|(s, _)| s.id == a.placement_slot.as_str())
                .copied()
                .ok_or_else(|| {
                    Error::internal(format!(
                        "planned slot '{}' has no current physical declaration",
                        a.placement_slot
                    ))
                })
        })
        .collect::<Result<_>>()?;

    // PARTIAL-ROLLOUT GUARDS (before any remote mutation): a group push
    // derives its complete snapshot by overlaying the selected slots onto the
    // latest successful target snapshot, so the base must be able to carry
    // every unselected slot forward — on a target's first deployment the
    // group must cover every target slot, and after membership changes every
    // current unselected slot must have a prior assignment with a matching
    // physical binding. A full-target push (no group) is always allowed. The
    // selected set is the plan's per-branch resolution — consumed from the
    // planner's PROOF-BEARING [`crate::deploy::plan::ResolvedSelection`] by
    // accessor (`planned.resolved().slots()`), the exact non-empty slot set
    // the planner resolved against the reference's declared temporal source.
    let planned_slot_ids: Vec<SlotId> = resolved_sel.slots().iter().cloned().collect();
    crate::deploy::plan::validate_partial_rollout(selection, &planned_slot_ids, config, store)?;

    // Behavior coverage gate: EVERY planned assignment's (release, variant)
    // must have a frozen behavior contract BEFORE any remote state is touched
    // (handshake, incoming cleanup, staging, publication) — each slot's
    // behavior resolves from ITS OWN artifact binding, never a snapshot-wide
    // single release. A historical behavior snapshot can be incomplete (a
    // corrupted or truncated behavior.json parses fine but lacks a variant);
    // without this gate the missing entry would panic mid-rollout, after
    // remote trees had already been staged. Fail closed in preflight with
    // context instead.
    crate::deploy::plan::validate_behavior_coverage(&behavior_index, &assignments)?;

    // Mutating remote phase (phase B), only behind the non-dry-run gate:
    // protocol handshake FIRST, then create the remote layout, clear
    // abandoned incoming, check lock, recover missing local objects. The
    // handshake records `control/protocol.json` before any other remote
    // layout mutation; a dry run never reaches this, so an unprovisioned
    // remote stays untouched. Deliberately AFTER planning: a plan rejection
    // (ref failure, membership, behavior) fails before any remote byte is
    // written. The abandoned-incoming cleanup lives in
    // [`crate::deploy::plan::cleanup_abandoned_incoming`] (A7) and the
    // local-object recovery in
    // [`crate::store::objects::LocalStore::recover_if_missing`] (A3).
    if !opts.dry_run {
        for (slot, _s) in &members {
            let slot_id =
                SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

            let helper = &helpers[&slot_id];
            let status = &statuses[&slot_id];
            helper.handshake()?;
            remotes.get(&slot_id).unwrap().provision_layout()?;
            crate::deploy::plan::cleanup_abandoned_incoming(
                helper,
                &status.pending_incoming,
                deployment_id,
            )?;
            if let Some(held) = &status.lock
                && held != op_id.as_str()
            {
                return Err(Error::preflight(format!(
                    "slot {slot_id} mutation lock held by '{held}' — recover via `deploy unlock {target_name} {slot_id} --yes` after confirming the holder died"
                )));
            }
            for a in &assignments {
                if a.placement_slot == slot_id {
                    store.recover_if_missing(helper.remote(), &a.artifact.tree)?;
                }
            }
        }
    }

    // Build the per-slot plan with expected (pre-push) generation.
    let mut plan_servers: BTreeMap<SlotId, SlotPlan> = BTreeMap::new();
    let mut new_gen: HashMap<SlotId, GenerationId> = HashMap::new();
    let mut pre_push: BTreeMap<SlotId, Observation<PreviousGeneration>> = BTreeMap::new();
    for a in &assignments {
        let slot_id = &a.placement_slot;
        let expected = statuses
            .get(slot_id)
            .and_then(|st| st.current_generation().cloned());
        let gid = GenerationId::generate();
        new_gen.insert(slot_id.clone(), gid.clone());
        plan_servers.insert(
            slot_id.clone(),
            SlotPlan {
                slot_id: slot_id.clone(),
                artifact: a.artifact.clone(),
                expected_generation: expected.clone(),
            },
        );
        // Record the slot's *actual* current assignment (read from the
        // remote generation), not the desired one, DIRECTLY as the intent's
        // three-state pre-push observation ([`Observation<PreviousGeneration>`]):
        // `Known(PreviousGeneration { generation, artifact })` after a
        // successful assignment read, `Unknown(error)` when the read fails (a
        // DISTINCT value, never a valid-looking artifact — there is no
        // sentinel artifact), and `KnownAbsent` when the status read showed
        // no state (never deployed) — the same contract the post-push
        // `actual_servers` refresh uses (see below).
        pre_push.insert(
            slot_id.clone(),
            match expected {
                Some(g) => {
                    // The assignment read verifies the generation's OWNER
                    // MARKER against this application + slot (fail closed on
                    // a transplanted record).
                    let owner = crate::remote::helper::GenerationOwner::new(
                        config.application().clone(),
                        slot_id.clone(),
                    );
                    match helpers[slot_id].read_assignment(g.as_str(), &owner) {
                        Ok(asn) => Observation::Known(PreviousGeneration {
                            generation: g,
                            artifact: asn.artifact,
                        }),
                        Err(e) => Observation::Unknown(ObservationError {
                            message: format!("assignment read failed: {e}"),
                        }),
                    }
                }
                None => Observation::KnownAbsent,
            },
        );
    }

    // The plan's fields are private (invariant-bearing domain record): the
    // builder assembles it from already-validated parts — the per-slot plans
    // (validated SlotIds/artifacts), the behavior index, and the VERIFIED
    // origin ([`PlanOrigin`] — a Release origin carries its sealed rebinding
    // proof inside the source).
    let plan = DeploymentPlan::new(
        deployment_id.clone(),
        resolved_sel.target().clone(),
        behavior_index.clone(),
        plan_servers.clone(),
        origin,
    );

    Ok(PreflightOutcome {
        pref,
        behavior_index,
        assignments,
        plan_servers,
        new_gen,
        pre_push,
        plan,
    })
}

#[cfg(test)]
pub(crate) mod preflight_tests {
    //! PRE-MUTATION phase tests: the dry-run / materialization / staging /
    //! capacity / membership-gate / ref-resolution-ordering paths, driven
    //! end-to-end through [`push`] /
    //! [`push_inner`]. The shared harnesses live in
    //! [`crate::deploy::testsupport`].

    use crate::deploy::testsupport::*;
    use crate::error::Error;
    use crate::identity::{
        GenerationRef, test_deployment_id, test_generation_id, test_tree_digest,
    };
    use crate::ledger::PushRef;
    use crate::remote::canonical as tree;
    use crate::remote::helper::RemoteHelper;
    use crate::remote::transport::LocalTransport;
    use crate::testutil::test_remotes::{
        FailOnceMarkerRemote, FailOnceStagingRemote, recording_factory,
    };
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn dry_run_removes_readonly_staging_tree() {
        // A dry-run staging tree containing read-only directories/files (modes
        // preserved from the artifact sources by materialize_variant) must be
        // fully removed before the push returns. Regression: the old Drop-only
        // cleanup swallowed remove_dir_all's EACCES and left `staging/dry-<id>`
        // (and every file inside it) behind forever.
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
        let config = ProjectConfig::load(&config_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let factory = move |_s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(
                LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join("s1"))
                    .unwrap(),
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
                group: None,
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
        let config = ProjectConfig::load(&config_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let remote_path = remotes_base.join("s1");
        let factory_path = remote_path.clone();
        let factory = move |_s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(
                LocalTransport::new(&crate::testutil::fixture_env(), factory_path.clone()).unwrap(),
            ))
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
                group: None,
            },
        )
        .unwrap();
        assert_eq!(
            r0.status,
            Some(DeploymentStatus::Successful),
            "first push must deploy"
        );
        // The rollback ref for later: the FIRST push's deployment id
        // (rollback payloads are keyed by deployment id).
        let baseline_dep = r0
            .attempt
            .as_ref()
            .expect("first push records an attempt")
            .deployment_id
            .clone();
        let tree = known_artifact(&r0.attempt.expect("attempt recorded").slots[&SlotId::new("p1")])
            .tree
            .clone();

        // Drop the local object: recovery must re-fetch from the remote.
        std::fs::remove_dir_all(store.object_root(&tree)).unwrap();
        assert!(!store.object_exists(&tree), "local object removed");
        let remote_handle =
            LocalTransport::new(&crate::testutil::fixture_env(), remote_path).unwrap();
        assert!(
            remote_handle.exists(&crate::remote::layout::tree_root(tree.as_str())),
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

        // Second push: a ROLLBACK to s0 cannot re-materialize the tree from
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
                ref_token: Some(baseline_dep.as_str().to_string()),
                group: None,
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
        let meta = crate::remote::canonical::canonicalize_tree(&obj).unwrap();
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let release_root = config.release_root(&cfg_path);
        let vcfg = config.variant("standard").unwrap();
        let staging = store.staging_dir().join("standard");
        crate::remote::canonical::materialize_variant(
            &release_root,
            &vcfg.artifact.mappings,
            &crate::remote::canonical::TemplateVars::mapping(
                config.application().as_str(),
                config.release().as_str(),
                "standard",
            ),
            &staging,
        )
        .unwrap();
        let meta = tree::canonicalize_tree(&staging).unwrap();
        let tree = TreeDigest::new(meta.tree_sha256.clone());
        store.store_object(&tree, &staging).unwrap();

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
    // `src/store/local.rs`'s per-fixture fault registry) on each persistence
    // step, run a push
    // that aborts mid-finalization, then run a clean push and assert
    // exactly-one semantics: one snapshot entry, `refs/last-successful`
    // pointing at the attempt, latest transition `Successful`, markers
    // present on the remotes.

    #[test]
    fn intent_persist_fault_leaves_remote_untouched() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-intent-fault");
        let err = {
            h.store.fault_registry().arm_append_attempt(id.as_str());
            push_main_with_id(&h, &id).expect_err("push must abort when the intent persist fails")
        };
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
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            !remote.exists(crate::remote::layout::current()),
            "current must not exist before the intent is durable"
        );
        assert_eq!(
            remote
                .list(crate::remote::layout::generations())
                .unwrap()
                .len(),
            0,
            "no generation may be created before the intent is durable"
        );

        // A clean push with a fresh id proceeds normally: remote advances.
        let id2 = test_deployment_id("deploy-intent-fault-clean");
        let r2 = push_main_with_id(&h, &id2).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Successful),
            "a clean follow-up push succeeds"
        );
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            remote.exists(crate::remote::layout::current()),
            "remote advanced"
        );
        assert_finalized(&h, &single_attempt(&h));
    }

    #[test]
    fn snapshot_ref_membership_change_refuses_and_mutates_nothing() {
        let h = RecoveryHarness::new();
        let id1 = test_deployment_id("deploy-membership-baseline");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "s0 exists for the p1 membership"
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
        let config2 = ProjectConfig::load(&h.cfg_path).unwrap();
        let members2 = config2.target_slots("t1").unwrap();
        assert_eq!(members2.len(), 1);
        assert_eq!(members2[0].0.id, "p2", "current membership is now p2");

        // The exact rollback must be refused (fail closed) and must not
        // mutate ANY deployment state. The refusal now fires at the
        // READ-ONLY remote phase: the rebind (p1 -> p2 on the same physical
        // location) makes the remote's generations owner-mismatched, so the
        // first status verification refuses the transplanted state with an
        // integrity error — before any plan/attempt record, before the
        // membership gate in `plan_assignments` is even reached, and before
        // any remote byte changes. `push()`'s advisory lock files are the
        // only bytes created.
        let remotes_before = snapshot_files(&h.remotes_base);
        let observed_before = h.store.read_observed("t1", &h.config).unwrap();
        let rf = h.remotes_base.clone();
        let script = h.script.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let err = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &config2,
            &PushOptions {
                dry_run: false,
                ref_token: Some(
                    test_deployment_id("deploy-membership-baseline")
                        .as_str()
                        .to_string(),
                ),
                group: None,
            },
        )
        .expect_err("membership change must refuse exact rollback");
        // THE OWNER-MARKER REFUSAL (the review's fail-closed contract): the
        // rebind renames the slot p1 -> p2 on the SAME physical location, so
        // the remote's generations now carry an owner marker that does not
        // match the current slot identity — the first status verification
        // (a read, never a mutation) refuses the remote as transplanted
        // state, before any plan/attempt record and before any remote byte
        // changes. The membership-change gate in `plan_assignments` would
        // ALSO refuse (the snapshot's slot set differs from the current
        // one), but the owner-marker check fires first, at the read-only
        // remote phase.
        assert!(
            err.to_string().contains("owner marker mismatch"),
            "error must state the owner-marker refusal (fail closed), got: {err}"
        );
        assert!(
            err.to_string().contains("integrity") || err.to_string().contains("digest"),
            "error must be an integrity-class refusal, got: {err}"
        );

        // Nothing mutated: no attempt, no snapshot, no observed change, and
        // the remote roots are byte-for-byte identical.
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        assert_eq!(
            h.store.read_observed("t1", &h.config).unwrap(),
            observed_before
        );
        assert_eq!(
            remotes_before,
            snapshot_files(&h.remotes_base),
            "the refused rollback must not touch a single remote byte"
        );
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            remote.exists(crate::remote::layout::current()),
            "the baseline s0 deployment on the remote is untouched"
        );
    }

    // ---- Historical dry runs (snapshot refids and release refids) -----------
    //
    // Every earlier dry-run test uses HEAD. A dry run against a HISTORICAL ref
    // must report exactly what a real push would do (the plan built from the
    // snapshot/release) while persisting NOTHING and touching no remote: no
    // attempt/transition/snapshot/store change, no generation/current change.

    #[test]
    fn historical_dry_run_snapshot_ref_plans_without_mutating() {
        let h = RecoveryHarness::new();
        let id1 = test_deployment_id("deploy-hist-dry-s0");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let s0 = &r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")];
        let s0_tree = known_artifact(s0).tree.clone();
        let s0_gen = known_generation(s0).clone();

        let store_before = snapshot_files(h.store.base());
        let remotes_before = snapshot_files(&h.remotes_base);
        let rf = h.remotes_base.clone();
        let script = h.script.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let r = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: true,
                ref_token: Some(
                    test_deployment_id("deploy-hist-dry-s0")
                        .as_str()
                        .to_string(),
                ),
                group: None,
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
            r.message.contains(s0_tree.as_str()),
            "the plan names the historical s0 tree, got: {}",
            r.message
        );

        // Persists NOTHING (byte-for-byte store) and touches no remote
        // (byte-for-byte remotes; the live `current` still names s0's
        // generation, no new generation was minted remotely).
        assert_eq!(
            store_before,
            snapshot_files(h.store.base()),
            "a historical dry run must not write a single store byte"
        );
        assert_eq!(
            remotes_before,
            snapshot_files(&h.remotes_base),
            "a historical dry run must not touch a single remote byte"
        );
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        let status = RemoteHelper::new(&remote)
            .status(&crate::remote::helper::test_owner("eng", "p1"))
            .unwrap();
        assert_eq!(
            status.current_generation().map(|g| g.as_str()),
            Some(s0_gen.as_str()),
            "the remote current still points at s0's generation"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let crate::ledger::ObservedAssignment::Known { generation, .. } =
            &observed.slots[&SlotId::new("p1")].assignment
        else {
            panic!("observed p1 must be a successful read");
        };
        assert_eq!(
            Some(generation.clone()),
            Some(s0_gen),
            "observed state untouched by the dry run"
        );
    }

    #[test]
    fn historical_dry_run_release_ref_plans_without_mutating() {
        let h = RecoveryHarness::new();
        let id1 = test_deployment_id("deploy-hist-dry-rel");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let s0 = &r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")];
        let tree = known_artifact(s0).tree.clone();

        let store_before = snapshot_files(h.store.base());
        let remotes_before = snapshot_files(&h.remotes_base);
        let rf = h.remotes_base.clone();
        let script = h.script.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let r = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: true,
                ref_token: Some(id1.as_str().to_string()),
                group: None,
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
            snapshot_files(h.store.base()),
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
    // (env is passed as a snapshot; the parent env is never mutated).

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
        let id = test_deployment_id("deploy-capacity-preflight");
        // Deterministic capacity: the remote reports 100 bytes available and
        // the server policy reserves 1 MiB, so the first deployment cannot
        // fit its tree.
        let mut config = ProjectConfig::load(&h.cfg_path).unwrap();
        config = config
            .with_server_capacity(
                "s1",
                crate::config::CapacityConfig {
                    reserve_bytes: 1024 * 1024,
                    reserve_percent: crate::identity::CapacityPercent::new(0)
                        .expect("0 is in range"),
                },
            )
            .unwrap();
        let project_root = config.project_root(&h.cfg_path);
        let target = config.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FakeCapacityRemote::build(rf.join(s.id.as_str()), 100)
        };
        let err = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
            &mut Some(
                crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", "test").unwrap(),
            ),
        )
        .expect_err("capacity preflight must fail the push");
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
            Some(DeploymentStatus::FailedPreflight),
            "a preflight failure after intent must end FailedPreflight"
        );
        let transitions = h.store.read_transitions(id.as_str()).unwrap();
        let statuses: Vec<DeploymentStatus> = transitions.iter().map(|t| t.status()).collect();
        assert_eq!(
            statuses,
            vec![DeploymentStatus::FailedPreflight],
            "a preflight failure appends exactly ONE terminal event (FailedPreflight)"
        );

        // No op log/snapshot, and NO remote deployment mutation: no `current`,
        // no generation record, no tree object.
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            !remote.exists(crate::remote::layout::current()),
            "no current"
        );
        assert!(
            remote
                .list(crate::remote::layout::generations())
                .unwrap()
                .is_empty(),
            "no generation record may be durable"
        );
        assert!(
            remote
                .list(crate::remote::layout::objects())
                .unwrap()
                .is_empty(),
            "no tree object may be published"
        );
    }

    /// THE PREFLIGHT TERMINAL-APPEND FAILURE IS PROPAGATED (the review's
    /// P1 fix — the acceptance's "a swallowed preflight-append failure can
    /// no longer exist"): a capacity preflight fails, and the
    /// `FailedPreflight` terminal append is faulted
    /// ([`FaultKind::AppendTerminal`]). The push MUST report the append
    /// failure (the caller sees the persistence boundary failed — never the
    /// original capacity error as if the attempt had settled), the attempt
    /// stays intent-only (recoverable-pending), and NOTHING advanced on the
    /// remote, so a later clean push's recovery settles the attempt
    /// `FailedRolledBack` — the EXACT PRE-PUSH STATE settles rolled-back,
    /// never `Degraded` (the review's exact fix: recovery decides through
    /// the SAME [`crate::kernel::transition::decide_terminal`] path as
    /// normal execution).
    #[test]
    fn preflight_terminal_append_failure_is_propagated_and_recovery_rolls_back() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-preflight-append-fault");
        // Deterministic capacity failure (mirrors
        // [`capacity_preflight_failure_records_failed_preflight_status`]).
        let mut config = ProjectConfig::load(&h.cfg_path).unwrap();
        config = config
            .with_server_capacity(
                "s1",
                crate::config::CapacityConfig {
                    reserve_bytes: 1024 * 1024,
                    reserve_percent: crate::identity::CapacityPercent::new(0)
                        .expect("0 is in range"),
                },
            )
            .unwrap();
        let project_root = config.project_root(&h.cfg_path);
        let target = config.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        // The preflight terminal append fails once (one-shot, id-qualified).
        h.store.fault_registry().arm_append_terminal(id.as_str());
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FakeCapacityRemote::build(rf.join(s.id.as_str()), 100)
        };
        let txn =
            crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", op_id.as_str())
                .expect("a real push holds the target ledger txn");
        let err = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
            &mut Some(txn),
        )
        .expect_err("the preflight terminal-append failure must fail the push");
        assert!(
            err.to_string().contains("append_terminal"),
            "the append failure must be PROPAGATED — never swallowed in favor of the capacity error, got: {err}"
        );
        assert!(
            !err.to_string().contains("insufficient capacity"),
            "the append failure REPLACES the preflight error — the attempt never settled, got: {err}"
        );
        // The attempt stays intent-only (recoverable-pending): no terminal,
        // no snapshot, nothing advanced on the remote.
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "the intent is durable before the preflight terminal append"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            None,
            "the attempt stays intent-only (pending) when the FailedPreflight terminal append fails"
        );
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            !remote.exists(crate::remote::layout::current()),
            "nothing advanced on the remote — the preflight failed before any `current` change"
        );

        // A LATER CLEAN PUSH: recovery sees the intent-only attempt whose
        // live state is EXACTLY the original pre-push state (nothing
        // changed — the retry observes the pre-push state the review's
        // sequence described) and settles it `FailedRolledBack` — never
        // `Degraded` (a Degraded terminal with NO remaining change is
        // unrepresentable). The retry then proceeds with its OWN fresh
        // deployment (the original push never advanced anything), which
        // succeeds.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Successful),
            "the retry push proceeds with a fresh deployment after recovery settled the old attempt"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            Some(DeploymentStatus::FailedRolledBack),
            "the exact pre-push state settles FailedRolledBack — never Degraded (the review's fix)"
        );
        let transitions = h.store.read_transitions(id.as_str()).unwrap();
        let last = transitions.last().expect("transition stream non-empty");
        assert!(
            last.reason().is_some_and(|r| r.contains("state diverged")),
            "the recovery's refusal reason explains the disposition, got: {:?}",
            last.reason()
        );
    }

    /// A STAGING failure (after the intent is durable, before any `current`
    /// change) must end the attempt `FailedPreflight` — the same terminal
    /// status as a capacity failure — never a stranded `InProgress`.
    /// Regression: the staging loop used `?` directly, so ANY staging error
    /// (a remote write failure, a store fault, a transport error) propagated
    /// as the push error with the attempt's latest transition still
    /// `InProgress`; a later reconcile would then misreport it (generation
    /// never minted → falsely "degraded as diverged") instead of the
    /// documented "an attempt that fails before any `current` change is
    /// `failed_preflight`". The staging phase may have uploaded partial
    /// incoming content; that content is removed best-effort, and no
    /// generation/`current`/object is published.
    #[test]
    fn staging_failure_records_failed_preflight_status() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-staging-fail");
        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        // One-shot fault: the FIRST incoming file write of the staging upload
        // fails (after the incoming dir and its `app/` subdir were created),
        // so a real partial upload exists for the cleanup to remove.
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FailOnceStagingRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
        };
        let err = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
            &mut Some(
                crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", "test").unwrap(),
            ),
        )
        .expect_err("staging failure must fail the push");
        assert!(
            err.to_string()
                .contains("incoming staging write forced to fail"),
            "the ORIGINAL staging error must surface, got: {err}"
        );
        assert!(
            !armed.load(Ordering::SeqCst),
            "the one-shot staging fault must have fired"
        );

        // The intent is durable and the attempt's LATEST status is the
        // terminal `FailedPreflight` — never stranded `InProgress`.
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "intent must be persisted before staging");
        assert_eq!(
            latest_status(&h, id.as_str()),
            Some(DeploymentStatus::FailedPreflight),
            "a staging failure after intent must end FailedPreflight"
        );
        let transitions = h.store.read_transitions(id.as_str()).unwrap();
        let statuses: Vec<DeploymentStatus> = transitions.iter().map(|t| t.status()).collect();
        assert_eq!(
            statuses,
            vec![DeploymentStatus::FailedPreflight],
            "a preflight failure appends exactly ONE terminal event (FailedPreflight)"
        );

        // No op log/snapshot, and NO remote deployment mutation: no `current`,
        // no generation record, no published object.
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            !remote.exists(crate::remote::layout::current()),
            "no current"
        );
        assert!(
            remote
                .list(crate::remote::layout::generations())
                .unwrap()
                .is_empty(),
            "no generation record may be durable"
        );
        assert!(
            remote
                .list(crate::remote::layout::objects())
                .unwrap()
                .is_empty(),
            "no tree object may be published"
        );

        // The partially-created incoming directory was cleaned best-effort:
        // the fault fired on the first file write, AFTER the incoming dir and
        // its `app/` subdir were created, so a real partial upload existed and
        // must be gone.
        assert!(
            !remote.exists(&crate::remote::layout::incoming_dir(id.as_str())),
            "the partial incoming upload must be cleaned best-effort"
        );
    }

    /// A staging failure on a LATER assignment (the first assignment's tree
    /// staged fine) must still end the attempt `FailedPreflight`, and the
    /// best-effort incoming cleanup must remove the FIRST assignment's
    /// already-staged incoming directory too — a partial staging is
    /// never left behind for a later reconcile to trip over.
    #[test]
    fn staging_failure_on_later_assignment_cleans_earlier_incoming() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // One variant declaring p1 (s1) and p2 (s2); both servers are fresh,
        // so BOTH assignments need staging, in slot order p1 then p2.
        let two_slot_variant = r#"
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
        std::fs::write(release_dir.join("standard.toml"), two_slot_variant).unwrap();
        let artifacts_dir = release_dir.join("artifacts");
        for (p, c) in [
            ("build/output/app/server", "v1\n"),
            ("deployment/common/README", "common\n"),
        ] {
            let fp = artifacts_dir.join(p);
            std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
            std::fs::write(&fp, c).unwrap();
        }
        let two_slot_toml = r#"
schema_version = 2
application = "two-slot"
release = "v1"

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

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, two_slot_toml).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = test_deployment_id("deploy-staging-later");
        let project_root = config.project_root(&cfg_path);
        let target = config.target("t1").expect("target t1");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        // Arm the fault ONLY on s2 (the LATER assignment): s1's staging must
        // complete, then s2's first incoming write fails.
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            let arm = if s.id.as_str() == "s2" {
                armed_for_factory.clone()
            } else {
                Arc::new(AtomicBool::new(false))
            };
            FailOnceStagingRemote::build(rf.join(s.id.as_str()), arm)
        };
        let err = push_inner(
            &project_root,
            &store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
            &mut Some(
                crate::store::local::ledger::TargetLedgerTxn::open(&store, "t1", "test").unwrap(),
            ),
        )
        .expect_err("the later staging failure must fail the push");
        assert!(
            err.to_string()
                .contains("incoming staging write forced to fail"),
            "the ORIGINAL staging error must surface, got: {err}"
        );
        assert!(
            !armed.load(Ordering::SeqCst),
            "the one-shot staging fault on s2 must have fired"
        );

        // The attempt ends terminal FailedPreflight, never stranded
        // InProgress.
        assert_eq!(
            store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::FailedPreflight),
            "a later staging failure must end FailedPreflight"
        );
        let transitions = store.read_transitions(id.as_str()).unwrap();
        let statuses: Vec<DeploymentStatus> = transitions.iter().map(|t| t.status()).collect();
        assert_eq!(
            statuses,
            vec![DeploymentStatus::FailedPreflight],
            "a preflight failure appends exactly ONE terminal event (FailedPreflight)"
        );

        // The FIRST assignment's already-staged incoming dir was cleaned
        // best-effort, and the second's partial upload too; no `current`,
        // generation, or published object on either server.
        for sname in ["s1", "s2"] {
            let remote =
                LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join(sname))
                    .unwrap();
            assert!(
                !remote.exists(&crate::remote::layout::incoming_dir(id.as_str())),
                "slot {sname}'s incoming dir must be cleaned best-effort"
            );
            assert!(
                !remote.exists(crate::remote::layout::current()),
                "no current on {sname}"
            );
            assert!(
                remote
                    .list(crate::remote::layout::generations())
                    .unwrap()
                    .is_empty(),
                "no generation record on {sname}"
            );
            assert!(
                remote
                    .list(crate::remote::layout::objects())
                    .unwrap()
                    .is_empty(),
                "no published object on {sname}"
            );
        }
    }

    /// A HISTORICAL push whose release's behavior snapshot is missing (or
    /// corrupt) must fail in PREFLIGHT before any attempt record, snapshot
    /// append, op-log advance, or remote byte — never silently substitute the
    /// caller's current configuration (requirement.md: "a missing or corrupt
    /// historical behavior snapshot aborts the attempt during preflight").
    ///
    /// Resolution never produces a bare `PushRef::Release` (release refids
    /// resolve to the most recent snapshot referencing the release), so the
    /// release-identity path is driven through a REAL ref form: a snapshot
    /// ref (`s0`) whose snapshot's release lacks the behavior snapshot. The
    /// preflight fires in the release-identity block, before planning, so the
    /// fixture snapshot is the only snapshot the store ever holds.
    #[test]
    fn historical_release_missing_behavior_snapshot_fails_preflight_untouched() {
        let h = RecoveryHarness::new();
        // A release record whose behavior snapshot was never written:
        // `write_release` persists `release.json` only; the aux
        // `behavior.json` is absent. The record itself must be a
        // content-verifiable current-format record (its OWN slot snapshot,
        // identity recomputed from that content) or `write_release` refuses
        // it: an empty slot snapshot cannot be verified (fail closed).
        let mut rec = crate::identity::ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: crate::identity::Provenance {
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
            },
            variants: BTreeMap::from([("standard".to_string(), "tree-x".to_string())]),
            slots: BTreeMap::from([(
                "standard".to_string(),
                crate::identity::CanonicalSlots {
                    slots: vec![crate::identity::CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/eng".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    }],
                },
            )]),
        };
        let digest = crate::verify::release::recompute_release_digest(&rec)
            .expect("test release must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::identity::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        let release = crate::identity::ReleaseId::new(rec.release_id.clone());
        h.store.write_release(&rec).unwrap();
        // A snapshot at index 0 whose slots reference that release: the ref
        // resolves to it, and the release-identity step then demands the
        // release's behavior snapshot (which was never written).
        seed_snapshot(
            &h.store,
            "t1",
            "deploy-hist-behavior-fixture",
            "sha256-aa",
            BTreeMap::from([(
                SlotId::parse("p1").unwrap(),
                GenerationRef {
                    generation: test_generation_id("gen-hist"),
                    assignment: crate::identity::PlacementSlotAssignment {
                        placement_slot: SlotId::parse("p1").unwrap(),
                        artifact: ArtifactRef {
                            release: release.clone(),
                            variant: VariantName::parse("standard").unwrap(),
                            tree: test_tree_digest("tree-x"),
                        },
                    },
                },
            )]),
            // The binding key set must equal the slot key set EXACTLY (the
            // wire → domain conversion refuses a rollback whose bindings
            // omit a slotted generation); this fixture's point is the
            // MISSING BEHAVIOR SNAPSHOT, so the payload must be otherwise
            // valid for the ledger to load at all.
            BTreeMap::from([(
                SlotId::parse("p1").unwrap(),
                crate::ledger::PhysicalBinding::new(
                    crate::identity::ServerId::parse("s1").unwrap(),
                    "/srv/eng",
                )
                .expect("test binding is absolute and traversal-free"),
            )]),
        );

        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.target("t1").expect("harness target");
        let op_id = OperationId::new("op-historical-behavior".to_string());
        let id = test_deployment_id("deploy-hist-behavior");
        let rf = h.remotes_base.clone();
        let script = h.script.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let err = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
            &ledger::parse_ref_expr(test_deployment_id("deploy-hist-behavior-fixture").as_str())
                .unwrap(),
            None,
            &id,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
            &mut Some(
                crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", "test").unwrap(),
            ),
        )
        .expect_err("a release without its behavior snapshot must fail preflight");
        assert!(
            err.to_string().contains("historical behavior")
                && err.to_string().contains("unavailable"),
            "expected a historical-behavior preflight error, got: {err}"
        );

        // Nothing recorded and nothing touched: no NEW attempt, no NEW
        // snapshot, no `refs/last-successful`, and the remote directory was
        // never even created (the failure fires before the mutating remote
        // phase — the earlier status inspection writes no remote bytes).
        assert_eq!(
            h.store.read_ledger("t1").unwrap().len(),
            1,
            "only the fixture's seeded entry exists; the preflight failure appends nothing"
        );
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "the fixture snapshot is the only entry; the preflight failure must not append"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(test_deployment_id("deploy-hist-behavior-fixture").as_str()),
            "the derived last-successful still points at the fixture entry"
        );
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
            &crate::deploy::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
            &ledger::parse_ref_expr(test_deployment_id("deploy-hist-behavior-fixture").as_str())
                .unwrap(),
            None,
            &id,
            &op_id2,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
            &mut Some(
                crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", "test").unwrap(),
            ),
        )
        .expect_err("a corrupt behavior snapshot must also fail preflight");
        assert!(
            err2.to_string().contains("historical behavior")
                && err2.to_string().contains("unavailable"),
            "expected a historical-behavior preflight error, got: {err2}"
        );
        assert_eq!(
            h.store.read_ledger("t1").unwrap().len(),
            1,
            "only the fixture's seeded entry exists; the preflight failure appends nothing"
        );
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "the preflight failure must not append a snapshot"
        );
    }

    /// The bare deployment-id ref form (no `@` prefix) resolves against the
    /// push's
    /// OWN target argument — the target is passed once, never repeated in the
    /// reference. A dry run against `s0` must plan the same historical
    /// snapshot as the `parent(@, N)` equivalent.
    #[test]
    fn snapshot_ref_resolves_target_from_push_argument() {
        let h = RecoveryHarness::new();
        let id1 = test_deployment_id("deploy-bare-atf");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let s0_tree = known_artifact(&r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")])
            .tree
            .clone();

        let rf = h.remotes_base.clone();
        let script = h.script.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let r = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: true,
                ref_token: Some(id1.as_str().to_string()),
                group: None,
            },
        )
        .unwrap();
        assert!(
            r.dry_run,
            "the bare deployment-id dry run plans without mutating"
        );
        assert!(
            r.message.contains(s0_tree.as_str()),
            "the bare deployment-id form must plan that deployment's stored state for the push's              own target, got: {}",
            r.message
        );
    }

    // ---- Relative refs resolve AFTER reconciliation (property) ------------
    //
    // THE BUG THIS FIXES: the engine used to resolve the push ref — INCLUDING
    // the relative forms (`@`, `@-`, `parent(@, N)`) — into a concrete
    // deployment BEFORE it acquired locks and BEFORE
    // `reconcile_pending_commits` appended the recovered attempt's snapshot.
    // A relative ref computed against the PRE-reconciliation chain therefore
    // selected a stale deployment: `@-` should mean "one before the latest
    // INCLUDING this push's reconciled append", but early resolution gave
    // "one before the pre-recovery latest". The fix parses the token to a
    // store-free [`RefExpr`] FIRST and resolves it only after reconciliation
    // (see the resolution point in `push_inner`).
    //
    // THE PROPERTY: for an initial chain whose latest POSITION is `L`
    // (deployments 0..=L, i.e. L+1 successful deployments — the log order
    // IS the deployment history; positions are derived, never stored), a
    // pending-commit attempt whose reconciliation appends EXACTLY ONE
    // snapshot (a new deployment at position L+1) during the ref push, and
    // a relative ref with ancestor depth d (1..=L; `@-` for d=1,
    // `parent(@, d)` otherwise), the SELECTED deployment in the plan equals
    // POST-RECONCILIATION latest - depth = the deployment at position
    // (L + 1) - d. The pre-fix behavior selected position L - d (stale, off
    // by exactly the reconciled append) or failed outright on a chain too
    // short for the walk. Depth 0 is the `@` HEAD form — the current-files
    // push, chain-independent and covered by the pure-parse unit tests in
    // `history.rs` — so the ancestor range starts at 1.
    //
    // COST CONTROL: the initial chain is FIXTURED at the store level (a real
    // pending push writes the release + tree + remote state, then synthetic
    // snapshot entries 0..=L reference that release), and the ref push is
    // faulted at its FIRST transition — after `plan.json` is durable but
    // before staging/deployment — so the plan's resolved index is observable
    // without running the full mutation loop.

    // ---- dry-run ref resolution: invalid refs never touch a remote -------

    /// Control: a VALID ref (`@`) with the recording factory dry-runs
    /// successfully — dry runs still contact remotes to inspect status, so
    /// the zero-contact contract applies ONLY to the invalid-ref failure
    /// path — and the counters DO move, proving the recording seam would
    /// catch a regression that re-introduced remote contact before the ref
    /// check (a counter that cannot move would make the zero-invocation
    /// property below vacuous).
    #[test]
    fn dry_run_valid_ref_contacts_factory_and_plans() {
        let h = RecoveryHarness::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let factory = recording_factory(h.remotes_base.clone(), calls.clone());
        let r = push(
            &h.cfg_path,
            &h.store,
            &factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: true,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert!(r.dry_run);
        assert!(
            r.message.contains("dry-run plan"),
            "valid dry run must plan, got: {}",
            r.message
        );
        assert!(
            calls.load(Ordering::SeqCst) > 0,
            "a valid dry run contacts remotes for status; the recording factory must have counted \
              at least one invocation"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn direct_release_membership_drift_rejected_before_remote_factory(
            release_inc in prop::array::uniform3(prop::bool::ANY),
            current_inc in prop::array::uniform3(prop::bool::ANY),
            physical_drift in prop::bool::ANY,
        ) {
            let (_dir, cfg_path, config, store, release) =
                membership_drift_fixture(release_inc, current_inc, physical_drift);
            let remotes_base = _dir.path().join("remotes");
            let token = format!("release:{release}");
            // The membership on the destination `t1` reduces to exactly the
            // generated universe members plus the constant `phys` (iso is
            // t2-only), so the sets match iff the two generated arrays match
            // element-wise.
            let mismatch = release_inc != current_inc;

            if mismatch {
                // MISMATCH: rejected BEFORE any remote construction or method
                // call, in BOTH modes.
                for dry in [false, true] {
                    let calls = Arc::new(AtomicUsize::new(0));
                    let factory = recording_factory(remotes_base.clone(), calls.clone());
                    let err = push(
                        &cfg_path,
                        &store,
                        &factory,
                        "t1",
                        &config,
                        &PushOptions {
                            dry_run: dry,
                            ref_token: Some(token.clone()),
                        group: None},
                    )
                    .expect_err(&format!(
                        "a membership mismatch must reject the push (dry_run={dry})"
                    ));
                    let msg = err.to_string();
                    assert!(
                        msg.contains("release")
                            && msg.contains("drift")
                            && msg.contains("before remote access"),
                        "refusal must be the membership-drift error (dry_run={dry}), got: {msg}"
                    );
                    assert_eq!(
                        calls.load(Ordering::SeqCst),
                        0,
                        "a membership mismatch must fail BEFORE any remote construction or method \
                         call (dry_run={dry}): zero factory invocations, got {}",
                        calls.load(Ordering::SeqCst)
                    );
                }
            } else {
                // CONTROL — matching membership: both modes PLAN (dry run
                // returns a dry-run plan; the real push completes a full
                // deployment), and the recording factory IS invoked: a valid
                // push legitimately contacts remotes. The zero-contact
                // assertion applies ONLY to the mismatch path; the `calls > 0`
                // checks prove the recording seam counts real work.
                let calls = Arc::new(AtomicUsize::new(0));
                let factory = recording_factory(remotes_base.clone(), calls.clone());
                let r = push(
                    &cfg_path,
                    &store,
                    &factory,
                    "t1",
                    &config,
                    &PushOptions {
                        dry_run: true,
                        ref_token: Some(token.clone()),
                    group: None},
                )
                .unwrap_or_else(|e| panic!("a matching membership must dry-run-plan: {e}"));
                assert!(r.dry_run);
                assert!(
                    r.message.contains("dry-run plan"),
                    "control dry run must plan, got: {}",
                    r.message
                );
                assert!(
                    calls.load(Ordering::SeqCst) > 0,
                    "the control dry run contacts remotes for status; the recording factory must \
                     count it"
                );

                let calls = Arc::new(AtomicUsize::new(0));
                let factory = recording_factory(remotes_base.clone(), calls.clone());
                let r = push(
                    &cfg_path,
                    &store,
                    &factory,
                    "t1",
                    &config,
                    &PushOptions {
                        dry_run: false,
                        ref_token: Some(token.clone()),
                    group: None},
                )
                .unwrap_or_else(|e| panic!("a matching membership must deploy for real: {e}"));
                assert_eq!(
                    r.status,
                    Some(DeploymentStatus::Successful),
                    "control real push must complete a full deployment"
                );
                assert!(
                    calls.load(Ordering::SeqCst) > 0,
                    "the control real push contacts remotes; the recording factory must count it"
                );
            }
        }
    }

    // THE USER'S DIRECT-RELEASE GROUP PROPERTY: for generated MATCHING
    // frozen/current memberships (the release freezes exactly the target's
    // current membership, by construction) plus an ARBITRARY NONEMPTY group
    // subset of the target's slots, a direct `release:<id> --group <g>` push
    // (the COMPLETE push path, dry-run mode) RESOLVES AND PLANS — the
    // membership gate now validates the release's FULL frozen set against the
    // target's COMPLETE current set (never the group-filtered selection), so
    // EVERY proper subset plans, and the dry-run plan covers EXACTLY the
    // group's slots. MUTATING the COMPLETE membership (add/remove/rename of a
    // full-target slot) ALWAYS fails BEFORE REMOTE ACCESS: the drift gate
    // fires on the FULL set in BOTH real and dry-run modes with the recording
    // factory reporting ZERO invocations.
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x0EA5_0E11_0BEA),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn relative_ref_resolves_post_reconciliation_latest_minus_depth(
            (latest, depth) in (0u64..=4).prop_flat_map(|latest| {
                (Just(latest), 1u64..=latest.max(1))
            }),
        ) {
            let h = RecoveryHarness::new();
            let slot = SlotId::parse("p1").unwrap();

            // (c) A concurrent/reconciled append: the chain is seeded FIRST
            // (the strictly-linear model — a pending attempt can only ever be
            // the NEWEST entry, so the synthetic chain descends from the
            // store's OWN head, never from the pending attempt). Entry 0 is a
            // REAL push (it persists the release record + behavior snapshot +
            // tree the synthetic entries below reuse), and entries 1..=latest
            // are synthetic snapshots chaining onto the current head with the
            // SAME durable artifact.
            let r0 = push_main_with_id(
                &h,
                &test_deployment_id(&format!("deploy-relative-chain-{latest}-0")),
            )
            .unwrap();
            assert_eq!(r0.status, Some(DeploymentStatus::Successful));
            let chain_artifact = known_artifact(&r0.attempt.as_ref().expect("attempt").slots[&slot])
                .clone();
            let bindings = crate::ledger::PhysicalBinding::new(
                    crate::identity::ServerId::parse("s1").unwrap(),
                    "/srv/eng",
                )
                .expect("test binding is absolute and traversal-free");
            for i in 1..=latest {
                crate::deploy::testsupport::seed_snapshot(
                    &h.store,
                    "t1",
                    &format!("deploy-relative-chain-{latest}-{i}"),
                    "b",
                    BTreeMap::from([(
                        slot.clone(),
                        GenerationRef {
                            generation: test_generation_id(&format!("gen-relative-{latest}-{i}")),
                            assignment: crate::identity::PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: chain_artifact.clone(),
                            },
                        },
                    )]),
                    BTreeMap::from([(slot.clone(), bindings.clone())]),
                );
            }
            assert_eq!(
                h.store.read_snapshots("t1").unwrap().len() as u64,
                latest + 1,
                "the seeded chain holds latest + 1 snapshots"
            );

            // The PENDING attempt: the target gets NEW content first (a
            // distinct release R2), then a real HEAD push OVER the chain head
            // (`chain-latest`) records it — its commit marker write fails
            // once, so the intent is durable and no snapshot/terminal was
            // appended yet.
            let project_root = h.config.project_root(&h.cfg_path);
            let variant_path = project_root
                .join("releases")
                .join("v1")
                .join("standard.toml");
            let v2 = std::fs::read_to_string(&variant_path)
                .unwrap()
                .replace("argv = [\"true\"]", "argv = [\"true\", \"b\"]");
            assert_ne!(
                v2,
                std::fs::read_to_string(&variant_path).unwrap(),
                "the fixture must actually change the verification argv"
            );
            std::fs::write(&variant_path, v2).unwrap();
            std::fs::write(
                project_root
                    .join("releases")
                    .join("v1")
                    .join("artifacts")
                    .join("build/output/app/server"),
                "v2\n",
            )
            .unwrap();
            let config2 = ProjectConfig::load(&h.cfg_path).unwrap();
            let armed = Arc::new(AtomicBool::new(true));
            let armed_for_factory = armed.clone();
            let rf = h.remotes_base.clone();
            let fault_factory = move |s: &crate::config::ServerDef,
                                      _slot: &crate::config::SlotConfig|
                     -> Result<Box<dyn Remote>> {
                FailOnceMarkerRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
            };
            let rp = push(
                &h.cfg_path,
                &h.store,
                &fault_factory,
                "t1",
                &config2,
                &PushOptions {
                    dry_run: false,
                    ref_token: None,
                    group: None,
                },
            )
            .unwrap();
            assert_eq!(
                rp.status, None,
                "the failed-marker push leaves the attempt pending (intent-only)"
            );
            let pending = rp.attempt.as_ref().expect("the pending push records an attempt");
            let pending_id = pending.deployment_id.clone();
            assert_eq!(
                h.store.read_snapshots("t1").unwrap().len() as u64,
                latest + 1,
                "the pending attempt appends no snapshot yet"
            );

            // The ref is RELATIVE: `@-` for depth 1, `parent(@, d)` else.
            let token = if depth == 1 {
                "@-".to_string()
            } else {
                format!("parent(@, {depth})")
            };
            // The PRE-FIX behavior resolved BEFORE reconciliation: against the
            // seeded chain (latest + 1 successful entries) `parent(@, depth)`
            // selects position latest - depth (stale), or fails outright when
            // the chain is too short (latest == 0). The pending attempt is
            // NOT yet a successful entry, so it cannot be selected.
            let pre_reconcile = ledger::resolve_ref_expr(
                &ledger::parse_ref_expr(&token).unwrap(),
                "t1",
                &h.store,
            );
            // THE POST-RECONCILIATION chain: the pending attempt is the
            // NEWEST entry (the strictly-linear model — it was appended LAST,
            // at chain position latest + 1), and the ref push's reconcile
            // appends its Successful terminal, so the successful chain becomes
            // chain-0..chain-latest, pending (latest + 2 entries). The ref
            // `parent(@, depth)` selects successful position (latest + 1) -
            // depth from the newest: depth 1 -> chain-latest, depth latest ->
            // chain-1 (never the pending itself for depth >= 1).
            let selected = (latest + 1) - depth;
            let selected_deployment: String =
                test_deployment_id(&format!("deploy-relative-chain-{latest}-{selected}"))
                    .as_str()
                    .to_string();
            // The PRE-reconcile resolution (against the seeded chain only):
            // `parent(@, depth)` walks to position (latest - depth) — the
            // stale selection — or fails outright when the chain is too short
            // (latest == 0 with depth 1 underflows).
            match pre_reconcile {
                Ok(PushRef::Deployment { deployment_id, .. }) => {
                    assert!(latest > 0, "a non-empty chain must resolve pre-reconcile");
                    assert_eq!(
                        deployment_id.as_str(),
                        test_deployment_id(&format!(
                            "deploy-relative-chain-{latest}-{}",
                            latest - depth
                        ))
                        .as_str(),
                        "the stale pre-fix selection"
                    );
                }
                Ok(_) => {
                    panic!(
                        "a relative deployment ref must not resolve to a non-deployment pre-reconcile"
                    )
                }
                Err(_) => {
                    assert_eq!(
                        latest, 0,
                        "pre-fix on a non-empty chain must resolve (stale), not fail"
                    );
                }
            }
            // The fixed flow: the engine reconciles FIRST (appending the
            // pending attempt's TERMINAL EVENT — it becomes the successful
            // entry at position latest + 1), THEN resolves the ref against
            // the post-reconciliation chain, then plans. The push is faulted
            // at its FIRST store write after `plan.json` — the INTENT append
            // — so the plan's resolved source is observable without the
            // (slow) mutation loop.
            let rf2 = h.remotes_base.clone();
            let script = h.script.clone();
            let clean_factory = move |s: &crate::config::ServerDef,
                                      _slot: &crate::config::SlotConfig|
                     -> Result<Box<dyn Remote>> {
                Ok(Box::new(LocalTransport::with_exec(
                    &crate::testutil::fixture_env(),
                    rf2.join(s.id.as_str()),
                    script.clone(),
                )?))
            };
            let ref_id = test_deployment_id(&format!("deploy-relative-ref-{latest}-{depth}"));
            h.store
                .fault_registry()
                .arm_append_attempt(ref_id.as_str());
            let err = push_ref_with_id(
                &h.cfg_path,
                &h.store,
                &clean_factory,
                "t1",
                &h.config,
                &PushOptions {
                    dry_run: false,
                    ref_token: Some(token.clone()),
                    group: None,
                },
                &ref_id,
            )
            .expect_err(
                "the plan is durable before the first intent write, so the faulted push must Err",
            );
            assert!(
                err.to_string().contains("append_attempt"),
                "the injected intent fault must be the failure, got: {err}"
            );

            // (c) The reconciled append happened: the pending attempt's entry
            // (the NEWEST — its intent line was appended LAST) now carries
            // its Successful terminal — the successful chain is
            // chain-0..chain-latest, pending (latest + 2 entries).
            let snapshots = h.store.read_snapshots("t1").unwrap();
            assert_eq!(
                snapshots.len() as u64,
                latest + 2,
                "seeded (latest+1) + reconciled (1); the faulted ref push appends nothing"
            );
            let reconciled = snapshots.last().expect("the reconciled entry must exist");
            assert_eq!(
                reconciled.deployment_id.as_str(),
                pending_id.as_str(),
                "the reconciled entry is the pending attempt (its intent line was newest)"
            );
            assert_eq!(
                ledger::successful_index(
                    &h.store,
                    "t1",
                    &DeploymentId::parse(pending_id.as_str()).expect("canonical pending id"),
                )
                .unwrap()
                .unwrap(),
                latest + 1,
                "the pending attempt's successful position is s{latest_plus_one}",
                latest_plus_one = latest + 1,
            );

            // THE ASSERTION: the SELECTED deployment recorded in the plan
            // equals post-reconciliation position (latest + 1) - depth from
            // the newest — the deployment id at that chain position.
            let plan: DeploymentPlan = serde_json::from_str(
                &std::fs::read_to_string(h.store.deployment_dir(ref_id.as_str()).join("plan.json"))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                plan.source(),
                &crate::ledger::PlanOrigin::Deployment(
                    DeploymentId::parse(&selected_deployment).expect("canonical selected id")
                ),
                "'{token}' must select the entry at successful-chain position {selected} = s{}(latest + 1) - {depth} — the POST-reconciliation selection (the pending reconciled at the top), not the pre-reconcile s{}(latest) - {depth}",
                latest + 1,
                latest
            );
        }
    }

    // THE property: a dry run with a NONEXISTENT ref returns a REF error
    // and never contacts a remote — the recording factory reports ZERO
    // invocations (and zero remote method calls) for every generated
    // invalid ref. Tokens are shape-valid (they parse) but semantically
    // unresolvable against the small fixture chain: snapshot indices beyond
    // the chain (`s{latest+k}`), ancestor walks past the start
    // (`parent(@, N)`), and deployment refids absent from the chain
    // (`deploy-absent-...`). The early resolution lives in [`push`] (before
    // any lock or factory invocation) precisely so this holds.

    // THE USER'S DIRECT-RELEASE GROUP PROPERTY: for generated MATCHING
    // frozen/current memberships (the release freezes exactly the target's
    // current membership, by construction) plus an ARBITRARY NONEMPTY group
    // subset of the target's slots, a direct `release:<id> --group <g>` push
    // (the COMPLETE push path, dry-run mode) RESOLVES AND PLANS — the
    // membership gate now validates the release's FULL frozen set against the
    // target's COMPLETE current set (never the group-filtered selection), so
    // EVERY proper subset plans, and the dry-run plan covers EXACTLY the
    // group's slots. MUTATING the COMPLETE membership (add/remove/rename of a
    // full-target slot) ALWAYS fails BEFORE REMOTE ACCESS: the drift gate
    // fires on the FULL set in BOTH real and dry-run modes with the recording
    // factory reporting ZERO invocations.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn dry_run_invalid_ref_never_contacts_remotes(
            kind in 0u32..3,
            offset in 1u64..=4,
        ) {
            // Fixture: target 't1' with a three-entry deployment history
            // (deploy-fixture-0..=2, latest = 2). Only the chain's SHAPE
            // matters (the log order + deployment ids): the generated refs
            // fail in resolution, before any planning reads the snapshots'
            // artifacts.
            let h = RecoveryHarness::new();
            let slot = SlotId::parse("p1").unwrap();
            let artifact = ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-1111"),
                variant: VariantName::parse("p1").unwrap(),
                tree: test_tree_digest("aa")};
            let bindings = crate::ledger::PhysicalBinding::new(
                crate::identity::ServerId::parse("s1").unwrap(),
                "/srv/eng",
            )
            .expect("test binding is absolute and traversal-free");
            for i in 0..=2u64 {
                seed_snapshot(
                    &h.store,
                    "t1",
                    &format!("deploy-fixture-{i}"),
                    "bb",
                    BTreeMap::from([(
                        slot.clone(),
                        GenerationRef {
                            generation: test_generation_id(&format!("gen-fixture-{i}")),
                            assignment: crate::identity::PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: artifact.clone()}},
                    )]),
                    BTreeMap::from([(slot.clone(), bindings.clone())]),
                );
            }

            // Shape-valid but semantically unresolvable: derive the token
            // from the fixture's shape (latest = 2, three successful
            // deployments deploy-fixture-0..=2).
            let token = match kind {
                // A deployment id absent from the chain.
                0 => test_deployment_id(&format!("deploy-absent-{offset}"))
                    .as_str()
                    .to_string(),
                // An ancestor walk past the start of the 3-deployment chain.
                1 => format!("parent(@, {})", 2 + offset),
                // A deployment-id ancestor stepping past the FIRST deployment.
                _ => format!("{}-", test_deployment_id("deploy-fixture-0"))};
            // Self-check: the token parses and genuinely fails to resolve.
            let expr = ledger::parse_ref_expr(&token).unwrap();
            assert!(
                ledger::resolve_ref_expr(&expr, "t1", &h.store).is_err(),
                "generated token must be semantically unresolvable: {token}"
            );

            // The recording factory: any remote contact (construction or
            // method call) increments `calls`.
            let calls = Arc::new(AtomicUsize::new(0));
            let factory = recording_factory(h.remotes_base.clone(), calls.clone());

            let err = push(
                &h.cfg_path,
                &h.store,
                &factory,
                "t1",
                &h.config,
                &PushOptions {
                    dry_run: true,
                    ref_token: Some(token.clone()),
                group: None},
            )
            .expect_err("a dry run with an invalid ref must fail with a ref error");
            assert!(
                matches!(err, Error::Ref(_)),
                "expected a REF error for '{token}', got: {err}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "dry-run '{token}' must fail BEFORE any remote construction or method call \
                 (zero factory invocations), got {}",
                calls.load(Ordering::SeqCst)
            );
        }
    }

    // THE USER'S DIRECT-RELEASE GROUP PROPERTY: for generated MATCHING
    // frozen/current memberships (the release freezes exactly the target's
    // current membership, by construction) plus an ARBITRARY NONEMPTY group
    // subset of the target's slots, a direct `release:<id> --group <g>` push
    // (the COMPLETE push path, dry-run mode) RESOLVES AND PLANS — the
    // membership gate now validates the release's FULL frozen set against the
    // target's COMPLETE current set (never the group-filtered selection), so
    // EVERY proper subset plans, and the dry-run plan covers EXACTLY the
    // group's slots. MUTATING the COMPLETE membership (add/remove/rename of a
    // full-target slot) ALWAYS fails BEFORE REMOTE ACCESS: the drift gate
    // fires on the FULL set in BOTH real and dry-run modes with the recording
    // factory reporting ZERO invocations.
    // THE USER'S DIRECT-RELEASE GROUP PROPERTY: for generated MATCHING
    // frozen/current memberships (the release freezes exactly the target's
    // current membership, by construction) plus an ARBITRARY NONEMPTY group
    // subset of the target's slots, a direct `release:<id> --group <g>` push
    // (the COMPLETE push path, dry-run mode) RESOLVES AND PLANS — the
    // membership gate now validates the release's FULL frozen set against the
    // target's COMPLETE current set (never the group-filtered selection), so
    // EVERY proper subset plans, and the dry-run plan covers EXACTLY the
    // group's slots. MUTATING the COMPLETE membership (add/remove/rename of a
    // full-target slot) ALWAYS fails BEFORE REMOTE ACCESS: the drift gate
    // fires on the FULL set in BOTH real and dry-run modes with the recording
    // factory reporting ZERO invocations.
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn direct_release_group_every_subset_plans_membership_mutation_fails_pre_remote(
            group_inc in prop::array::uniform3(prop::bool::ANY)
                .prop_filter("the group subset must be non-empty", |a| a.iter().any(|b| *b)),
            extra_inc in prop::array::uniform3(prop::bool::ANY),
            mutation in prop_oneof![
                Just(MembershipMutation::Add),
                Just(MembershipMutation::Remove),
                Just(MembershipMutation::Rename),
            ],
        ) {
            let (_dir, cfg_path, config, store, release, group) =
                group_membership_fixture(group_inc, extra_inc);
            let remotes_base = _dir.path().join("remotes");
            let token = format!("release:{release}");

            // EVERY non-empty group subset plans: the membership matches (the
            // release froze exactly the target's current slots), the early
            // gate passes, and the dry run plans EXACTLY the group's slots —
            // never the ungrouped members, never phys.
            let group_slots: Vec<&str> = MEMBERSHIP_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| group_inc[*i])
                .map(|(_, id)| *id)
                .collect();
            assert!(
                !group_slots.is_empty(),
                "the generated group subset must be non-empty"
            );
            let ungrouped: Vec<&str> = MEMBERSHIP_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| !group_inc[*i] && extra_inc[*i])
                .map(|(_, id)| *id)
                .collect();
            let calls = Arc::new(AtomicUsize::new(0));
            let factory = recording_factory(remotes_base.clone(), calls.clone());
            let r = push(
                &cfg_path,
                &store,
                &factory,
                "t1",
                &config,
                &PushOptions {
                    dry_run: true,
                    ref_token: Some(token.clone()),
                    group: Some(group.clone())},
            )
            .unwrap_or_else(|e| {
                panic!("a matching membership with group {group} must dry-run-plan: {e}")
            });
            assert!(r.dry_run);
            assert!(r.message.contains("dry-run plan"), "got: {}", r.message);
            for id in &group_slots {
                assert!(
                    r.message.contains(&format!("slot {id}:")),
                    "the plan must cover the group slot {id}, got:\n{}",
                    r.message
                );
            }
            for id in &ungrouped {
                assert!(
                    !r.message.contains(&format!("slot {id}:")),
                    "the plan must not cover the unselected member {id}, got:\n{}",
                    r.message
                );
            }
            assert!(
                !r.message.contains("slot phys:"),
                "phys is in no group; the plan must not cover it, got:\n{}",
                r.message
            );
            assert!(
                calls.load(Ordering::SeqCst) > 0,
                "a valid dry run contacts remotes; the recording factory must count it"
            );

            // MUTATING the COMPLETE membership always fails BEFORE any remote
            // access, in BOTH modes: the gate validates the FULL current set,
            // so a slot added, `phys` removed, or `phys` renamed refuses with
            // the drift error and ZERO factory invocations.
            let mut_config =
                apply_group_membership_mutation(&_dir, &cfg_path, group_inc, extra_inc, mutation);
            for dry in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let factory = recording_factory(remotes_base.clone(), calls.clone());
                let err = push(
                    &cfg_path,
                    &store,
                    &factory,
                    "t1",
                    &mut_config,
                    &PushOptions {
                        dry_run: dry,
                        ref_token: Some(token.clone()),
                        group: Some(group.clone())},
                )
                .expect_err(&format!(
                    "a full-target membership mutation must refuse the group push (dry_run={dry})"
                ));
                let msg = err.to_string();
                assert!(
                    msg.contains("release")
                        && msg.contains("drift")
                        && msg.contains("before remote access"),
                    "refusal must be the membership-drift error (dry_run={dry}), got: {msg}"
                );
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    0,
                    "a membership mutation must fail BEFORE any remote construction or method \
                     call (dry_run={dry}): zero factory invocations, got {}",
                    calls.load(Ordering::SeqCst)
                );
            }
        }
    }
}

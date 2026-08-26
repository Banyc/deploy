//! Push transaction engine.
//!
//! Implements the deployment transaction described in `requirement.md`:
//! validation, locking, materialization, release identity, reconciliation,
//! preflight capacity, staging, batched per-server publication with a
//! compare-and-swap precondition, atomic `current` swap, activation,
//! verification, compensation, commit markers, history, rollback, and
//! per-server retention.

use crate::adapter::verify::run_verification;
use crate::config::{FailurePolicy, Mapping, ProjectConfig, RetentionConfig, SlotConfig};
use crate::error::{Error, Result};
use crate::history::{self, PushRef, RefExpr};
use crate::layout;
use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, OperationId, ReleaseId, SlotId,
    TargetName, TreeDigest, VariantName, unknown_artifact,
};
use crate::push::capacity::capacity_preflight;
use crate::push::lock::FileLock;
use crate::push::reconcile::reconcile_pending_commits;
use crate::push::server::{
    REMOTE_RELEASE_JSON, ServerProc, compensate_server, download_tree_to_host, process_server,
};
use crate::push::staging::{StagingCleanup, cleanup_dry_run_staging, remove_tree_restoring_write};
use crate::records::{
    BehaviorIndex, DeploymentIntent, DeploymentPlan, DeploymentStatus, DesiredGeneration,
    IntentSlot, LedgerIntentReport, LedgerTerminal, NonEmptySlotTable, ObservedSlot,
    PreviousGeneration, SlotAttemptState, SlotOutcome, SlotOutcomeKind, SlotPlan, SlotResult,
    SlotTable, TerminalDisposition,
};
use crate::remote::helper::{GenerationAssignment, RemoteHelper};
use crate::remote::transport::Remote;
use crate::retention::compute_retained;
use crate::store::local::LocalStore;
#[cfg(test)]
use crate::testutil::step17_hook::HookPhase;
use crate::tree;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

pub struct PushOptions {
    pub dry_run: bool,
    pub ref_token: Option<String>,
    /// The optional rollout group (`deploy push <target> --group <name>`):
    /// selects a subset of the target's slots. `None` selects every slot
    /// owned by the target.
    pub group: Option<String>,
}

#[derive(Debug)]
pub struct PushReport {
    /// `None` means no attempt was created (dry-run or already up to date).
    pub status: Option<DeploymentStatus>,
    /// The in-memory REPORT form of the attempt: the verified intent fields
    /// PLUS the observed per-slot actuals (`slots`). Never persisted — the
    /// ledger's intent line keeps the `slots` map empty (outcomes live in the
    /// terminal event's `outcomes` map).
    pub attempt: Option<LedgerIntentReport>,
    pub message: String,
    /// Warning about post-commit maintenance deferred on this push (e.g. a
    /// per-slot retention that failed after the deployment already committed).
    /// The push itself is unaffected — its status/attempt are the real
    /// outcome — and the deferred work is retried on later pushes, including
    /// no-ops. `None` when no maintenance is outstanding.
    pub warning: Option<String>,
    pub dry_run: bool,
}

type RemoteFactory =
    dyn Fn(&crate::config::ServerDef, &crate::config::SlotConfig) -> Result<Box<dyn Remote>>;

/// Build the template context for one placement slot from the ARTIFACT being
/// processed: `release`/`variant`/`tree` are the assigned artifact's own
/// immutable `ReleaseId`, `VariantName`, and `TreeDigest` — never the caller's
/// current release name — so a historical/rollback push renders the release id
/// it actually deploys, and a template never sees a torn (desired-variant,
/// current-release) combination. Compensation overrides the five
/// deployment-scoped values again with the PRIOR assignment via
/// [`crate::template::TemplateVars::with_assignment`]: the prior artifact's
/// release/variant/tree AND the prior deployment identity
/// (`deployment_id`/`generation`) move together.
///
/// `deployment_id`/`generation` are the per-deployment identity, available
/// only in the per-server activation/verification path; sites that do not know
/// them (e.g. the reconciliation loop) pass `None`, and a template referencing
/// such a variable there fails loudly.
fn slot_vars(
    members: &[(&crate::config::SlotConfig, &crate::config::ServerDef)],
    config: &ProjectConfig,
    target_name: &str,
    slot_id: &SlotId,
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
        slot.deploy_dir(),
        artifact.variant.as_str(),
        config.application().as_str(),
        artifact.release.as_str(),
        target_name,
        server.id.as_str(),
    )
    .with_server(server.user(), server.address(), server.port())
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
    config: &ProjectConfig,
    opts: &PushOptions,
) -> Result<PushReport> {
    let deployment_id = DeploymentId::generate();
    let op_id = OperationId::generate();
    let target = config
        .target(target_name)
        .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
    let project_root = config.project_root(config_path);

    // 0. NORMALIZE THE SELECTION once near command entry: the owning target
    // and the requested rollout group only — a branch-agnostic {target,
    // group} pair, WITHOUT resolving slot IDs from the caller's current
    // configuration. Each reference branch resolves the selected slot IDs
    // against its own declared temporal source at plan time (HEAD and
    // deployment refs: the current group declarations; `release:<id>`: the
    // release's FROZEN per-slot groups, rebound onto the current physical
    // slots), so a historical release's frozen group partition governs its
    // push even when it differs from the current one. An unknown/empty group
    // is a configuration error for the branch's own era (the current config
    // for HEAD/deployment refs, the release's frozen topology for release
    // refs) and surfaces before any remote mutation. Planning, execution,
    // reporting, and persistence consume this selection plus the per-branch
    // resolution instead of independently filtering slots.
    let selection =
        crate::push::plan::SlotSelection::normalize(config, target_name, opts.group.as_deref())?;

    // 1. Validate configuration (already validated at load) and PARSE the
    // push ref — syntax only, NO store access. The relative forms (`@-`,
    // `parent(@, N)`, `<refid>--`, ...) are held as a structured [`RefExpr`]
    // and resolved LATER, inside `push_inner`, AFTER reconciliation has
    // appended any recovered snapshots: a relative ref must be computed
    // against the POST-reconciliation chain (see the resolution point in
    // `push_inner`), so the target's snapshot chain is read at resolution
    // time — post-lock, post-reconcile — never here, before the push even
    // holds the target lock.
    let ref_expr = match &opts.ref_token {
        Some(t) => history::parse_ref_expr(t)?,
        None => RefExpr::Head,
    };

    // 1b. DRY-RUN ONLY: resolve the parsed ref against the target's chain
    // NOW — before any lock, before the remote factory is ever touched. The
    // dry-run contract is "touches nothing — no locks, no writes, no remote";
    // with the resolution living inside `push_inner` (after the read-only
    // remote status and reconciliation), a dry run carrying an INVALID ref
    // would contact every remote and only then fail with the ref error.
    // Resolving here makes an invalid ref fail before ANY factory
    // invocation. The chain read is the PRE-reconcile chain — but a dry run
    // never reconciles (it touches nothing), so this is exactly the chain
    // the dry run would plan against. Real pushes keep `resolved = None` and
    // resolve inside `push_inner` after reconciliation appended any
    // recovered snapshots: relative refs must see the reconciled append.
    let resolved = if opts.dry_run {
        Some(history::resolve_ref_expr(&ref_expr, target_name, store)?)
    } else {
        None
    };

    // 1c. DIRECT-RELEASE MEMBERSHIP GATE — BOTH modes, immediately after the
    // ref is parsed/resolved and BEFORE any lock, any factory invocation: a
    // `release:<id>` push deploys onto the CURRENT target's slots, so the
    // release's OWN frozen slot set must EXACTLY equal the target's current
    // membership. The check reads only the release record (immutable store
    // data) and the config — no lock, no remote — so a drifting membership
    // refuses HERE, before the remote factory inside `push_inner` is ever
    // touched (previously the check ran at PLAN time inside `push_inner`,
    // AFTER the read-only remote status and reconciliation, so a mismatched
    // push contacted every remote first). For a dry run the ref is already
    // resolved above; for a real push the direct form's resolution
    // (`RefExpr::Release` -> `PushRef::Release`) is store-free and never
    // touches the snapshot chain (see `resolve_ref_expr`), so gating on the
    // parsed form is exactly equivalent to gating on the resolved ref — no
    // post-reconcile resolution is needed for the direct form.
    // The gate compares the FULL membership — `config.target_slots`, EVERY
    // slot whose owning target equals the target — never the group-filtered
    // selection: a `release:<id> --group <g>` push validates the complete
    // set here and then plans only the selected slots downstream.
    if let RefExpr::Release(release) = &ref_expr {
        let rec = store
            .read_release(release)
            .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
        let current_slot_ids: Vec<SlotId> = config
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, _)| {
                SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
            })
            .collect();
        crate::push::plan::validate_direct_release_membership(
            target_name,
            release,
            &rec,
            &current_slot_ids,
        )?;
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
        // DURABLE pre-creation of the target directory BEFORE the target
        // lock is acquired. The lock file lives INSIDE the target dir, so
        // the lock path used to create `targets/<target>/` with a plain
        // (UNSYNCED) mkdir that ran BEFORE the durable first-append helper
        // — the append's "newly created" detection then no-oped and a
        // reported-successful first push could recover with the target
        // directory missing after power loss. Pre-creating durably here
        // (every new directory entry fsynced, see
        // [`crate::store::atomic::ensure_private_dir_durable`]) means the
        // lock's own parent creation finds the directory existing and
        // never touches the fs.
        store.ensure_target_dir_durable(target_name)?;
        Some(FileLock::acquire(
            &store.target_dir(target_name).join("operation.lock"),
            op_id.as_str(),
        )?)
    };

    let result = push_inner(
        &project_root,
        store,
        factory,
        target_name,
        &selection,
        &ref_expr,
        resolved,
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

/// Test-only entry point: drive [`push_inner`] for a HEAD push with a
/// caller-supplied deployment id, so the state-machine / fault-matrix tests
/// can arm the one-shot store faults (keyed by deployment id) BEFORE the push
/// runs. Mirrors the recovery tests' `push_main_with_id`; exposed crate-wide
/// for the [`crate::semantic_invariants`] fixture. Same as [`push`] minus the
/// advisory-lock acquisition (irrelevant to the fault matrix).
#[cfg(test)]
pub(crate) fn push_with_id(
    config_path: &Path,
    store: &LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    config: &ProjectConfig,
    opts: &PushOptions,
    deployment_id: &DeploymentId,
) -> Result<PushReport> {
    let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
    let target = config
        .target(target_name)
        .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
    let project_root = config.project_root(config_path);
    let selection =
        crate::push::plan::SlotSelection::normalize(config, target_name, opts.group.as_deref())?;
    push_inner(
        &project_root,
        store,
        factory,
        target_name,
        &selection,
        &RefExpr::Head,
        // Real push (the fault-matrix entry points always push for real):
        // resolution stays inside `push_inner`, post-reconciliation.
        None,
        deployment_id,
        &op_id,
        config,
        target,
        opts,
    )
}

/// Test-only entry point: drive [`push_inner`] for a caller-supplied ref
/// (a deployment-keyed rollback etc.) with a caller-supplied deployment id,
/// mirroring [`push_with_id`] for the ref-token path. Lets the state-machine fixture
/// arm the one-shot store faults (keyed by deployment id) BEFORE a rollback
/// push runs, so rollback steps can carry the same per-step failure classes
/// as HEAD pushes.
#[cfg(test)]
pub(crate) fn push_ref_with_id(
    config_path: &Path,
    store: &LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    config: &ProjectConfig,
    opts: &PushOptions,
    deployment_id: &DeploymentId,
) -> Result<PushReport> {
    let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
    let target = config
        .target(target_name)
        .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
    let project_root = config.project_root(config_path);
    // Parse the ref token EARLY (syntax only, store-free — mirroring
    // [`push`]); `push_inner` resolves it after reconciliation.
    let ref_expr = match &opts.ref_token {
        Some(t) => history::parse_ref_expr(t)?,
        None => RefExpr::Head,
    };
    let selection =
        crate::push::plan::SlotSelection::normalize(config, target_name, opts.group.as_deref())?;
    push_inner(
        &project_root,
        store,
        factory,
        target_name,
        &selection,
        &ref_expr,
        // Real push (the state-machine fixture never dry-runs): resolution
        // stays inside `push_inner` after reconciliation.
        None,
        deployment_id,
        &op_id,
        config,
        target,
        opts,
    )
}

// The 10 parameters are the full push operation (data: project_root, store,
// factory, target_name, ref_expr, deployment_id, op_id; policy: config,
// target, opts). The `config` + `opts` pair is already the settings half,
// and `target`/`project_root` are derived views of it. Bundling all three
// policy args into one settings struct is a dedicated refactor (deferred: it
// would touch every internal `config`/`target`/`opts` reference in this
// ~1200-line body with no behavioral gain), so the allow documents the
// deliberate choice rather than a band-aid.
#[allow(clippy::too_many_arguments)]
fn push_inner(
    project_root: &Path,
    store: &LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    selection: &crate::push::plan::SlotSelection,
    ref_expr: &RefExpr,
    // The PRE-RESOLVED ref: `Some` for a dry run (resolved by [`push`]
    // BEFORE any lock or remote factory invocation, against the pre-reconcile
    // chain — the only chain a dry run ever sees); `None` for a real push,
    // which resolves at the post-reconciliation resolution point below (the
    // relative refs must see the reconciled append).
    resolved: Option<PushRef>,
    deployment_id: &DeploymentId,
    op_id: &OperationId,
    config: &ProjectConfig,
    target: &crate::config::TargetConfig,
    opts: &PushOptions,
) -> Result<PushReport> {
    // 3. Materialize every declared variant. Mappings resolve from the release
    //    directory (`<project>/releases/<release>/` — the structure is forced),
    //    not the project root, so an artifact `from` can never escape into the
    //    project's other files. Dry-run uses disposable staging and never writes
    //    to the object store.
    let release_root = project_root
        .join("releases")
        .join(config.release().as_str());
    let mut variant_trees: BTreeMap<String, TreeDigest> = BTreeMap::new();
    // Dry-run staging is disposable. The guard's Drop removes the whole
    // `dry-<deployment>` tree (on error, `?`, or unwind); the guard must
    // outlive the Head-materialization block because the dry-run branch below
    // performs an explicit FALLIBLE cleanup (reporting errors instead of
    // silently swallowing them) and empties the guard first, keeping the Drop
    // as a fallback only. A non-dry-run push stages into the persistent
    // per-variant staging dirs and stores objects, so no guard.
    let mut staging_guard = if opts.dry_run && ref_expr.is_head_push() {
        Some(StagingCleanup(Some(
            store
                .staging_dir()
                .join(format!("dry-{}", deployment_id.as_str())),
        )))
    } else {
        None
    };
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
            crate::mapper::materialize_variant(
                &release_root,
                &config.variant(&v)?.artifact.mappings,
                &crate::template::TemplateVars::mapping(
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
            BehaviorContract {
                activation: crate::config::ActivationConfig::from(vcfg.activation.clone()),
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

    // Open a remote handle per slot: the READ-ONLY half of the remote phase
    // (construct + host-identity prep + a status inspection). No remote bytes
    // are written here — `prepare_identity` pins only a LOCAL cache and
    // `status` is a read — so a later plan rejection (ref failure,
    // membership, behavior) still fails before any remote mutation. It must
    // run BEFORE reconciliation (which needs live helpers to verify
    // generations and write markers) and before resolution (which must see
    // the post-reconciliation chain).
    //
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
    let mut remotes: HashMap<SlotId, Box<dyn Remote>> = HashMap::new();
    let mut helpers: HashMap<SlotId, RemoteHelper> = HashMap::new();
    let mut statuses: HashMap<SlotId, crate::remote::helper::RemoteStatus> = HashMap::new();
    for (slot, s) in &all_members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let remote = factory(s, slot)?;
        remotes.insert(slot_id, remote);
    }
    for (slot, _s) in &all_members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let r = remotes.get(&slot_id).unwrap();
        let helper = RemoteHelper::new(r.as_ref());
        // Prepare the host identity (verify/pin the host key) BEFORE any status
        // request: a fingerprint-only configuration cannot connect at all
        // without the pinned key, and a dry run still connects to inspect
        // status. Pinning writes only to a LOCAL cache, never the remote
        // layout, so the dry-run "mutates nothing remotely" guarantee holds.
        r.prepare_identity()?;
        let status = helper.status()?;
        helpers.insert(slot_id.clone(), helper);
        statuses.insert(slot_id.clone(), status);
    }

    // Reconcile `PendingCommit` attempts left by earlier pushes BEFORE the
    // ref is resolved and BEFORE the early no-op check: an up-to-date push
    // must complete the missing commit markers (and advance the snapshot log)
    // rather than returning "Everything up to date" with the metadata still
    // absent. Runs under the local target lock already held by this push;
    // never reactivates or restarts services (markers/transition/snapshot
    // only). A recovered attempt finalizes through the SHARED finalizer
    // (`history::finalize_successful_attempt`), which APPENDS its snapshot
    // entry to the target's chain — the very append the relative refs below
    // must see. Dry-run never reconciles (it touches nothing).
    if !opts.dry_run {
        reconcile_pending_commits(store, config, target_name, op_id, &helpers)?;
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
        None => history::resolve_ref_expr(ref_expr, target_name, store)?,
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
            } => history::resolve_deployment(store, ft, deployment_id)?
                .slots
                .values()
                .map(|g| g.assignment.artifact.release.clone())
                .collect(),
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
        let index = crate::push::plan::release_behavior_index(store, &releases).map_err(|e| {
            Error::preflight(format!(
                "historical behavior unavailable (immutable behavior required): {e}"
            ))
        })?;
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
        (releases.first().cloned().unwrap_or_default(), index)
    };

    // The behavior digest this attempt is bound to: the canonical digest of
    // the frozen per-release, per-variant index (every referenced release's
    // every declared variant's activation + verification contract).
    // Historical and rollback pushes use the historical releases' own
    // contracts.
    let desired_behavior_sha = crate::release::behavior_index_digest(&behavior_index);

    // 5 & 7. Build the plan from the RESOLVED ref (post-reconciliation).
    // The plan covers exactly the SELECTED slots (the normalized selection).
    // THE SOURCE OWNS ITS REQUIRED PAYLOAD: the plan's origin
    // ([`crate::records::PlanOrigin`]) is the VERIFIED form — a DIRECT
    // release ref (a `release:<id>` push applies the release's frozen
    // topology onto the CURRENT physical slots) carries its
    // [`crate::records::VerifiedReleaseRebinding`] proof INSIDE the source;
    // HEAD and deployment refs carry none. The planner ALSO produces the
    // PROOF-BEARING resolution ([`crate::push::plan::ResolvedSelection`]:
    // target + declared temporal source + the non-empty resolved slot set),
    // which the engine consumes BY ACCESSOR below (`planned.resolved()`) —
    // never by construction.
    // (`desired_releases` is now DERIVED from the plan's authoritative per-slot
    // collection (`DeploymentPlan::releases`), never stored on the domain).
    let planned = crate::push::plan::plan_assignments(
        selection,
        &pref,
        &local_release_id,
        &variant_trees,
        store,
        config,
    )?;
    // The PROOF-BEARING resolution is consumed BY ACCESSOR (the planner is
    // the only constructor; the engine never builds one).
    let resolved = planned.resolved().clone();
    let (assignments, origin) = (planned.assignments, planned.origin);
    // The plan's target is DERIVED from the proof-bearing resolution: the
    // resolved target IS the plan's target. The plan's ORIGIN is the
    // planner's VERIFIED [`crate::records::PlanOrigin`] (built from the
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
    // The plan's PROOF-BEARING resolution ([`crate::push::plan::ResolvedSelection`])
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
    // planner's PROOF-BEARING [`crate::push::plan::ResolvedSelection`] by
    // accessor (`planned.resolved().slots()`), the exact non-empty slot set
    // the planner resolved against the reference's declared temporal source.
    let planned_slot_ids: Vec<SlotId> = resolved.slots().iter().cloned().collect();
    crate::push::plan::validate_partial_rollout(selection, &planned_slot_ids, config, store)?;

    // Behavior coverage gate: EVERY planned assignment's (release, variant)
    // must have a frozen behavior contract BEFORE any remote state is touched
    // (handshake, incoming cleanup, staging, publication) — each slot's
    // behavior resolves from ITS OWN artifact binding, never a snapshot-wide
    // single release. A historical behavior snapshot can be incomplete (a
    // corrupted or truncated behavior.json parses fine but lacks a variant);
    // without this gate the missing entry would panic mid-rollout, after
    // remote trees had already been staged. Fail closed in preflight with
    // context instead.
    validate_behavior_coverage(&behavior_index, &assignments)?;

    // Mutating remote phase (phase B), only behind the non-dry-run gate:
    // protocol handshake FIRST, then create the remote layout, clear
    // abandoned incoming, check lock, recover missing local objects. The
    // handshake records `control/protocol.json` before any other remote
    // layout mutation; a dry run never reaches this, so an unprovisioned
    // remote stays untouched. Deliberately AFTER planning: a plan rejection
    // (ref failure, membership, behavior) fails before any remote byte is
    // written.
    if !opts.dry_run {
        for (slot, _s) in &members {
            let slot_id =
                SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

            let helper = &helpers[&slot_id];
            let status = &statuses[&slot_id];
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
    }

    // Build the per-slot plan with expected (pre-push) generation.
    let mut plan_servers: BTreeMap<SlotId, SlotPlan> = BTreeMap::new();
    let mut new_gen: HashMap<SlotId, GenerationId> = HashMap::new();
    let mut pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> = BTreeMap::new();
    for a in &assignments {
        let slot_id = &a.placement_slot;
        let expected = statuses
            .get(slot_id)
            .and_then(|st| st.current_generation.clone());
        let expected_tree = statuses
            .get(slot_id)
            .and_then(|st| st.current_tree.clone())
            .map(|t| TreeDigest::parse(&t).expect("observed tree is a valid digest"));
        let gid = GenerationId::generate();
        new_gen.insert(slot_id.clone(), gid.clone());
        plan_servers.insert(
            slot_id.clone(),
            SlotPlan {
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
                    .map(|asn| SlotAttemptState {
                        artifact: asn.artifact.clone(),
                        generation: Some(g.clone()),
                    })
                    .unwrap_or_else(|_| SlotAttemptState {
                        artifact: unknown_artifact(),
                        generation: Some(g.clone()),
                    })
            }),
        );
    }

    let plan = DeploymentPlan {
        deployment_id: deployment_id.clone(),
        target: resolved.target().clone(),
        behaviors: behavior_index.clone(),
        slots: plan_servers.clone(),
        source: origin,
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
                Some(c) if c.as_str() == want => format!(
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
            warning: None,
            dry_run: true,
        });
    }

    // Early "Everything up to date" check for HEAD pushes. Run BEFORE persisting
    // any plan/status record so an up-to-date no-op leaves no dangling
    // `in_progress` deployment behind.
    if matches!(&pref, PushRef::Head) {
        // Retain the CURRENT generation assignment for every matching slot: the
        // no-op verification below renders the EXISTING generation's identities
        // (deployment_id/generation_id/artifact) — the running service was
        // deployed with those, and the no-op creates no records, so the NEW
        // deployment/generation ids would be fabricated.
        let mut existing: BTreeMap<SlotId, GenerationAssignment> = BTreeMap::new();
        let mut all_match = true;
        for a in &assignments {
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
            for a in &assignments {
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
                    &members,
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
                    &helpers,
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
                            generation: Some(asn.generation_id.clone()),
                            artifact: Some(asn.artifact.clone()),
                            last_deployment: Some(asn.deployment_id.clone()),
                        },
                    );
                }
                let mut observed_warnings: Vec<String> = Vec::new();
                refresh_observed(
                    store,
                    target_name,
                    &members,
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
                return Ok(PushReport {
                    status: None,
                    attempt: None,
                    message: "Everything up to date".to_string(),
                    warning,
                    dry_run: false,
                });
            }
        }
    }

    // Persist the plan before any server mutation (finding 6), then persist
    // the attempt INTENT: the ledger's `{"kind":"intent"}` line. The intent
    // is the deployment's durable key — it is appended BEFORE any server
    // mutation, and its TERMINAL EVENT (appended after the mutation loop)
    // carries the status, outcomes, and rollback state. There is no separate
    // `InProgress` transition: an intent-only ledger entry IS the
    // in-progress/pending state.
    store.write_plan(deployment_id.as_str(), &plan)?;

    // PERSIST THE ATTEMPT INTENT BEFORE ANY REMOTE MUTATION. The intent
    // record is the IMMUTABLE INTENT of the deployment: deployment_id, target,
    // membership, behavior digest, attempted_at, the planned (`desired`)
    // generations, and the observed pre-push state. It must be durable BEFORE
    // any server's `current`/generation changes, so a crash can never lose a
    // deployment whose servers already advanced: without the record the next
    // push would see every server at the desired generation and report
    // "Everything up to date" with no attempt/rollback ever recorded.
    // The record carries NO outcomes — the `slots` (actual) map is persisted
    // empty; the actual per-slot outcomes and the status live in the
    // deployment's TERMINAL EVENT (appended after the mutation loop).
    // The DOMAIN intent stores ONE slot table (the membership + the
    // desired/pre-push entries are the same table — the exact-key-set
    // invariant is structural); the wire re-expands it on serialization.
    let intent_slots: Vec<(SlotId, IntentSlot)> = assignments
        .iter()
        .map(|a| {
            (
                a.placement_slot.clone(),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: new_gen[&a.placement_slot].clone(),
                        artifact: a.artifact.clone(),
                    },
                    pre_push: pre_push
                        .get(&a.placement_slot)
                        .and_then(|p| p.clone())
                        .map(|p| PreviousGeneration {
                            artifact: p.artifact,
                            generation: p.generation,
                        }),
                },
            )
        })
        .collect();
    let attempt_intent = DeploymentIntent {
        deployment_id: deployment_id.clone(),
        target: TargetName::parse(target_name).expect("target name is a safe segment"),
        group: selection.group.clone(),
        behavior_sha256: desired_behavior_sha.clone(),
        attempted_at: crate::remote::helper::now_rfc3339(),
        slots: NonEmptySlotTable::build(intent_slots)?,
    };
    store.append_intent(target_name, &attempt_intent)?;

    // 8 & 9. Capacity preflight and staging. Capacity is a per-server policy
    // read from the caller's CURRENT `deploy.toml` (`ServerDef.capacity`), not
    // from any release snapshot: servers have no per-release history, so a
    // historical or rollback push applies the server's current headroom
    // exactly as a HEAD push does. Only the per-slot variant behavior
    // contracts resolve from the immutable snapshots (see `behavior_index`
    // above).
    //
    // Capacity AND staging form ONE pre-mutation result block: a failure in
    // EITHER phase happens AFTER the attempt intent and its initial
    // `InProgress` transition were persisted (requirement.md step 14 orders
    // the intent before capacity, step 8) and BEFORE any `current` change, so
    // the attempt must end terminal `FailedPreflight` — "an attempt that
    // fails before any `current` change is `failed_preflight`" — never
    // stranded `InProgress` (which would be misreported later as a
    // recoverable/pending attempt or falsely degraded as "generation
    // diverged" by a later reconcile). On EVERY error in the block the
    // terminal `FailedPreflight` transition is appended (the reason names the
    // failing phase), any incoming directories the staging phase may have
    // created on the remotes are removed best-effort (mirroring the
    // post-push cleanup below), and the ORIGINAL error is returned unchanged.
    // Failures BEFORE the intent is persisted (plan resolution, historical
    // behavior snapshot, handshake) surface as the push error with no attempt
    // record at all.
    let mut preflight_reason = "preflight failed";
    let preflight = (|| -> Result<()> {
        capacity_preflight(store, &assignments, &helpers, op_id, deployment_id, config)?;
        // Stage every needed tree into operation-unique incoming paths.
        preflight_reason = "staging failed";
        for a in &assignments {
            let _remote = remotes[&a.placement_slot].as_ref();
            let helper = &helpers[&a.placement_slot];
            if !helper.tree_exists(a.artifact.tree.as_str()) {
                let host_obj = store.object_root(&a.artifact.tree);
                helper.stage_incoming(
                    deployment_id.as_str(),
                    a.artifact.tree.as_str(),
                    &host_obj,
                )?;
            }
        }
        Ok(())
    })();
    if let Err(e) = preflight {
        // The preflight failure is the attempt's TERMINAL EVENT (status
        // `FailedPreflight`, empty outcomes — no slot was touched): appended to
        // the ledger like every other terminal. Incoming staging dirs created
        // by the failed phase are removed best-effort.
        let _ = store.append_terminal(
            target_name,
            deployment_id,
            &LedgerTerminal {
                recorded_at: crate::remote::helper::now_rfc3339(),
                // FailedPreflight carries no payload: no rollback and no
                // outcomes (a pre-mutation failure touched no slot).
                disposition: TerminalDisposition::FailedPreflight,
                reason: Some(preflight_reason.to_string()),
            },
        );
        for a in &assignments {
            helpers[&a.placement_slot]
                .remove_incoming(deployment_id.as_str())
                .ok();
        }
        return Err(e);
    }

    // 10-13. Process slots in batches. The batch size is a validated NONZERO
    // [`BatchSize`] (the raw -> domain conversion rejects zero), so the
    // `max(1)` guard is an invariant-preserving no-op kept for the batch loop.
    let batch_size = target.rollout.batch_size.get().max(1) as usize;
    // The TYPED batch-failure policy: never a loose string. It is matched
    // EXHAUSTIVELY below (step 13 compensation and step 14 status) — an
    // unsupported spelling cannot exist (the strict parse rejected it at
    // config load), so there is no implicit fallback to "leave changed".
    let failure_policy = target.rollout.failure_policy;
    let stop_on_failure = target.rollout.stop_on_failure;

    let mut results: BTreeMap<SlotId, SlotResult> = BTreeMap::new();
    let mut advanced: Vec<SlotId> = Vec::new();
    let mut compensated: Vec<SlotId> = Vec::new();
    // Pre-swap failures (never advanced): the slot's outcome records the
    // ACTUAL observed generation (the post-mutation status read below),
    // never the desired one — the outcome's generation field is the observed
    // post-state the remaining-changes derivation compares against pre_push.
    let mut never_advanced: Vec<SlotId> = Vec::new();
    let mut had_failure = false;

    let servers_order: Vec<SlotId> = assignments
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
            // Select the assigned slot's OWN (release, variant) frozen
            // behavior contract (never the caller's current variant file, and
            // never another release's contract) before
            // activation/verification. Coverage was validated before any
            // remote mutation, so a miss here is an internal invariant
            // violation: record a per-slot failure instead of panicking.
            let Some(variant_behavior) = behavior_index
                .get(&a.artifact.release)
                .and_then(|m| m.get(a.artifact.variant.as_str()))
            else {
                had_failure = true;
                results.insert(
                    sid.clone(),
                    SlotResult {
                        slot_id: sid.clone(),
                        outcome: SlotOutcomeKind::Failed,
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
                target_name,
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
            if kind == SlotOutcomeKind::Failed {
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
            } else {
                // A pre-swap failure (never advanced) or a compare-and-swap
                // skip: the slot's outcome records the ACTUAL observed
                // generation (the post-mutation status read below), never the
                // desired one.
                never_advanced.push(sid.clone());
            }
            results.insert(
                sid.clone(),
                SlotResult {
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
                .and_then(|s| s.current_generation.clone());
            results.insert(
                a.placement_slot.clone(),
                SlotResult {
                    slot_id: a.placement_slot.clone(),
                    outcome: SlotOutcomeKind::Skipped,
                    generation: cur,
                    compensated: false,
                    error: None,
                },
            );
        }
    }

    // 13. Failure policy compensation of still-advanced servers. The policy
    // is matched EXHAUSTIVELY (no `_ =>` fallback, no string compare):
    //
    // * [`FailurePolicy::RollbackChanged`] (the default) — postcondition:
    //   every server whose batch already advanced when a later batch failed
    //   is COMPENSATED back to its pre-push generation. A compensation
    //   failure (e.g. prior behavior unavailable, or activation/verification
    //   failed during rollback) is reported as a failed compensation rather
    //   than aborting the whole push; the slot stays advanced and the
    //   attempt is marked Degraded.
    // * [`FailurePolicy::LeaveChanged`] — postcondition: the earlier
    //   successfully-mutated batches are RETAINED deliberately; no
    //   compensation pass runs and the attempt ends Degraded with the mixed
    //   per-server state.
    if had_failure {
        match failure_policy {
            FailurePolicy::RollbackChanged => {
                for sid in &advanced {
                    let prior = plan_servers[sid].expected_generation.as_ref();
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
                            r.outcome = SlotOutcomeKind::Restored;
                        }
                    }
                }
                advanced.retain(|s| !compensated.contains(s));
            }
            FailurePolicy::LeaveChanged => {
                // Deliberate retention: earlier batches keep their new
                // state, so no compensation pass runs at all.
            }
        }
    }

    // 14. Determine attempt status — again an EXHAUSTIVE match on the typed
    // policy (no string compare, no fallback): a failed push is
    // `FailedRolledBack` under `RollbackChanged` when every advanced server
    // was compensated (or nothing had advanced), `Degraded` when any
    // compensation failed; under `LeaveChanged` a failed push is always
    // `Degraded` (the advances are retained deliberately).
    let status = if !had_failure {
        DeploymentStatus::Successful
    } else {
        match failure_policy {
            FailurePolicy::RollbackChanged => {
                if compensated.len() == assignments.len() || advanced.is_empty() {
                    DeploymentStatus::FailedRolledBack
                } else {
                    DeploymentStatus::Degraded
                }
            }
            FailurePolicy::LeaveChanged => DeploymentStatus::Degraded,
        }
    };

    // 15. Commit markers (only for otherwise-successful attempts). The
    // demotion reason is recorded alongside the final transition so `deploy
    // log` can explain why an attempt ended up `PendingCommit` or `Degraded`
    // (e.g. "recoverable metadata failure", "marker integrity conflict").
    let mut commit_status = status.clone();
    let mut commit_reason: Option<&'static str> = None;
    if status == DeploymentStatus::Successful {
        // The full placement-slot set participating in this commit.
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
                    // (which would leave the attempt unrecorded); mark the
                    // commit incomplete and keep going. A later push reconciles
                    // this `PendingCommit` attempt (see
                    // `reconcile_pending_commits`) before its own no-op check.
                    commit_status = DeploymentStatus::PendingCommit;
                    commit_reason = Some("recoverable metadata failure");
                    continue;
                }
            };
            if cur.as_ref().map(|g| g.as_str()) != Some(new_gen[sid].as_str()) {
                // The live generation no longer matches what we deployed: the
                // controller's view diverged, so this marker would be wrong.
                // Report Degraded rather than a falsely successful commit.
                commit_status = DeploymentStatus::Degraded;
                commit_reason = Some("commit diverged");
                continue;
            }
            match helper.write_commit_marker(
                deployment_id.as_str(),
                new_gen[sid].as_str(),
                &slot_ids,
                Some(target_name),
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
                && r.outcome == SlotOutcomeKind::Activated
                && r.error.is_some()
            {
                commit_status = DeploymentStatus::PendingCommit;
                commit_reason = Some("recoverable metadata failure");
                break;
            }
        }
    }

    // 16 & 17. Record attempt, history, retention.
    //
    // `actual_servers` reflects each slot's *real* final state, read from the
    // remote generation it currently points at, rather than the desired plan
    // values. Failed/skipped/restored slots therefore report their actual
    // artifact instead of the desired one.
    let mut actual_servers: BTreeMap<SlotId, SlotAttemptState> = BTreeMap::new();
    for a in &assignments {
        let sid = &a.placement_slot;
        let helper = &helpers[sid];
        let final_gen = helper.status().ok().and_then(|s| s.current_generation);
        let actual = match final_gen {
            Some(g) => match helper.read_assignment(g.as_str()) {
                Ok(asn) => SlotAttemptState {
                    artifact: asn.artifact.clone(),
                    generation: Some(g),
                },
                Err(_) => {
                    // The generation is observed (`g`), but its assignment could
                    // not be read. Never substitute the planned (desired)
                    // artifact for a failed observation: preserve the observed
                    // generation and mark the assignment unknown rather than
                    // fabricating desired state.
                    SlotAttemptState {
                        artifact: unknown_artifact(),
                        generation: Some(g),
                    }
                }
            },
            None => SlotAttemptState {
                artifact: a.artifact.clone(),
                generation: None,
            },
        };
        actual_servers.insert(sid.clone(), actual);
    }
    // A pre-swap failure (never advanced) records the ACTUAL observed
    // generation — the outcome's generation field is the observed post-state
    // the remaining-changes derivation compares against pre_push, never the
    // desired generation. The post-mutation status read above reflects the
    // true state: the slot never advanced, so it is still on its pre-push
    // generation (or `None` when the read fails — the state is unknown, and
    // an unknown state is not evidence of a change). Skipped outcomes
    // already record the reconciled current assignment.
    for sid in &never_advanced {
        if let Some(r) = results.get_mut(sid)
            && r.outcome == SlotOutcomeKind::Failed
        {
            r.generation = actual_servers.get(sid).and_then(|a| a.generation.clone());
        }
    }
    // `desired` (each slot's minted generation for its planned artifact, as a
    // complete [`GenerationRef`]) was computed BEFORE the mutation loop and
    // persisted as part of the immutable intent (`attempt_intent`); it is not
    // recomputed here.

    // 16 & 17. Record outcomes, finalize, history, retention. The ledger's
    // intent line (persisted BEFORE the mutation loop) keeps only the
    // immutable intent; the ACTUAL per-slot outcomes and the terminal status
    // are appended as the deployment's TERMINAL EVENT (the ledger's
    // `{"kind":"terminal"}` line) — the outcomes store the rollback state is
    // built from. The REPORT's attempt ([`LedgerIntentReport`]) also carries
    // the actuals (for display); the persisted intent does not — outcomes are
    // never part of the verified intent object.
    let mut attempt = LedgerIntentReport::from_intent(&attempt_intent)?;
    attempt.slots = actual_servers.clone();
    let outcomes_map: BTreeMap<SlotId, SlotResult> = results.clone();

    // Finalize the attempt's terminal event. A SUCCESSFUL attempt goes
    // through the SAME shared finalizer as recovery
    // ([`history::finalize_successful_attempt`]): ONE atomic terminal append
    // carrying the `Successful` status, the per-slot outcomes, and the
    // ROLLBACK STATE (built from the actual per-slot OUTCOMES
    // (`actual_servers`), never from the intent record). A non-successful
    // final status (`Degraded` / `FailedRolledBack`) is a plain terminal
    // append carrying the status and outcomes, no rollback. A demoted
    // `PendingCommit` status (the commit markers are not all durable) is NOT
    // terminal at all: the entry stays intent-only — the recoverable pending
    // state a later push reconciles before its own no-op check.
    let mut message = format!("push status: {commit_status:?}");
    if commit_status == DeploymentStatus::Successful {
        // The rollback state records each slot's COMPLETE physical binding
        // (`{server, deploy_dir}`) so an exact rollback can verify a slot
        // still lives at the exact on-host location it was deployed onto (a
        // rebound slot OR a slot whose deploy_dir moved must refuse rather
        // than deploy to the wrong host/location). The binding comes from
        // the CURRENT configuration: it is the live placement this attempt
        // actually used.
        let slot_bindings = config.target_slot_bindings(target_name)?;
        // The CURRENT target slot set: the complete snapshot omits slots
        // removed from the current configuration and carries every current
        // unselected slot forward from the base.
        // The rollback must key EXACTLY the deployment's membership (the
        // four-set equality: outcomes == rollback slots == rollback bindings
        // == intent membership, enforced by the conversion). The membership
        // is the SELECTED slots (`assignments` — the full target for a full
        // push, the group for a group push), so the rollback records exactly
        // what the deployment touched: slots removed from the current
        // configuration are omitted (they are not selected), and the
        // partial-rollout overlay (carrying unselected base slots forward)
        // is gone — a successful terminal's rollback must equal its
        // outcomes.
        let current_slot_ids: Vec<SlotId> = assignments
            .iter()
            .map(|a| a.placement_slot.clone())
            .collect();
        history::finalize_successful_attempt(
            store,
            &attempt_intent,
            &outcomes_map,
            &actual_servers,
            "push completed",
            &slot_bindings,
            &current_slot_ids,
        )?;
        // The new successful deployment is keyed by its deployment id (the
        // public grammar is deployment-keyed — successful positions are
        // derived internally, never exposed as sN).
        message = format!(
            "push successful; rollback payload keyed by deployment {deployment_id} of target {target_name}"
        );
    } else if commit_status != DeploymentStatus::PendingCommit {
        // A demoted `PendingCommit` status is NOT terminal: the entry stays
        // intent-only (the recoverable pending state a later push reconciles
        // before its own no-op check) — appending a PendingCommit terminal
        // would strand the attempt forever (reconciliation only picks up
        // entries WITHOUT a terminal).
        // The wire outcomes are converted to the DOMAIN outcomes, deriving
        // each slot's TRANSITION STATE from the wire's status/outcome fields
        // and DROPPING the wire outcome's redundant `slot_id` into the key
        // (the domain value carries no slot — the table key owns identity).
        let outcomes: SlotTable<SlotOutcome> = SlotTable::from_map(outcomes_map);
        // MAP the final status to its DISPOSITION (the domain truth table is
        // structural): FailedPreflight carries nothing (no slot touched),
        // FailedRolledBack owns the outcome table as its compensation
        // report, Degraded owns the outcome table its remaining changes are
        // derived from (the slots whose FINAL OBSERVED STATE differs from
        // their pre_push state) — the same derivation the read path applies,
        // so the domain and the wire conversion stay in sync.
        let disposition = match &commit_status {
            DeploymentStatus::FailedPreflight => TerminalDisposition::FailedPreflight,
            DeploymentStatus::FailedRolledBack => {
                TerminalDisposition::FailedRolledBack { outcomes }
            }
            DeploymentStatus::Degraded => {
                // The Degraded disposition's remaining changes are DERIVED
                // from the outcomes (the slots whose final observed state
                // differs from their pre_push state) — never stored. The
                // conversion refuses a Degraded wire whose outcomes are ALL
                // restored (a fully-compensated attempt must be
                // `FailedRolledBack`, never `Degraded`); a Degraded terminal
                // whose outcomes are all never-advanced (e.g. a
                // `leave_changed` failure that advanced nothing) is
                // legitimate — the policy marks the attempt Degraded even
                // though no slot changed.
                if outcomes
                    .values()
                    .all(|r| r.outcome == SlotOutcomeKind::Restored)
                {
                    return Err(Error::store(
                        "a Degraded terminal requires at least one non-restored outcome — none recorded"
                            .to_string(),
                    ));
                }
                TerminalDisposition::Degraded { outcomes }
            }
            other => {
                return Err(Error::store(format!(
                    "internal: cannot append a terminal for status {other:?} — only FailedPreflight / FailedRolledBack / Degraded reach the terminal append"
                )));
            }
        };
        store.append_terminal(
            target_name,
            deployment_id,
            &LedgerTerminal {
                recorded_at: crate::remote::helper::now_rfc3339(),
                disposition,
                reason: commit_reason.map(str::to_string),
            },
        )?;
    }

    // Refresh observed state — the shared [`refresh_observed`] helper, also
    // used by the no-op path so the projection is IDENTICAL whichever path
    // last touched a slot. Observed state is stored ONCE PER PLACEMENT SLOT
    // (`slots/<slot-id>/observed.json`), never per target: targets are
    // SELECTION VIEWS over the global slot map, so `deploy status <other>`
    // and every consumer of a target's observed view see the CURRENT
    // assignment (generation, artifact, last deployment) through the slot's
    // single physical record — a shared slot is written ONCE regardless of
    // how many targets it is a member of. The per-server record
    // (`servers/<id>.json`) keeps the actual [`crate::model::ServerId`] for
    // transport identity.
    //
    // POST-COMMIT MAINTENANCE: this refresh runs AFTER the terminal transition
    // was written — for a Successful attempt the shared finalizer already
    // appended the snapshot, `refs/last-successful`, and the terminal
    // `Successful` transition — so the deployment is DURABLY committed here.
    // A local store fault in this block (a `write_server`, `read_slot_observed`,
    // or `write_slot_observed` failure) must therefore NEVER turn the push into
    // an `Err`: it is recorded as a warning on the report (merged into the same
    // `maintenance` channel as retention) and the push still returns `Ok` with
    // the committed status.
    //
    // Unlike retention there is deliberately NO persistent debt marker. The
    // observed records are exactly that — PROJECTIONS of already-durable
    // facts (generations, artifacts, deployments), none of which depend on
    // this refresh — so a failure is only a projection lag. Convergence needs
    // no marker to retry: the next real push re-projects from current state,
    // and the refresh is not incremental — it rewrites each advanced slot's
    // physical record from the LIVE per-slot assignments. Retries therefore
    // converge without duplicate history: the projection refresh never
    // re-records an attempt, snapshot, or transition.
    //
    // THE PROJECTION MUST EQUAL THE LIVE REMOTE ASSIGNMENT — never the
    // desired plan and never this deployment's id for a slot it did not
    // touch. `actual_servers` substitutes the DESIRED artifact when the
    // post-mutation status read fails (a pre-swap-unreachable slot), and the
    // old refresh stamped THIS deployment's id on every member slot
    // regardless of whether the deployment advanced it — a slot that was
    // SKIPPED (stop_on_failure) or UNREACHABLE pre-swap (its `process_server`
    // aborted `Ok(Failed)` before the swap) kept its prior live generation
    // yet had its truthful observed record overwritten with a fabricated
    // `{generation: None, artifact: desired}` and a false `last_deployment`.
    // The projection is therefore rebuilt from each slot's LIVE generation
    // assignment (read directly, not from `actual_servers`): a slot this
    // deployment advanced IS the live assignment this deployment created
    // (same generation, artifact, and deployment id as before — behavior
    // preserved), while a skipped/unreachable/unadvanced slot keeps the
    // assignment's OWN deployment id — the deployment that actually created
    // the live generation — and, when the live assignment cannot be read,
    // carries its PRIOR physical observed record over verbatim (never
    // fabricated, never re-stamped).
    let mut observed_warnings: Vec<String> = Vec::new();
    let mut observed_servers: BTreeMap<SlotId, ObservedSlot> = BTreeMap::new();
    for (slot, _sdef) in &members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        // The slot's LIVE remote assignment. `status` is a read; under the
        // one-shot pre-swap arm it has already fired and been consumed inside
        // `process_server`, so this read reflects the true post-mutation
        // state: the new generation for an advanced slot, the PRIOR
        // generation for a skipped/unreachable one.
        let live = helpers[&slot_id]
            .status()
            .ok()
            .and_then(|s| s.current_generation)
            .and_then(|g| helpers[&slot_id].read_assignment(g.as_str()).ok());
        match live {
            Some(asn) => {
                observed_servers.insert(
                    slot_id.clone(),
                    ObservedSlot {
                        generation: Some(asn.generation_id.clone()),
                        artifact: Some(asn.artifact.clone()),
                        last_deployment: Some(asn.deployment_id.clone()),
                    },
                );
            }
            None => {
                // No readable live assignment (the server was never deployed,
                // or its status/assignment read failed — the
                // pre-swap-unreachable slot): carry the slot's PRIOR PHYSICAL
                // observed record over VERBATIM, so the projection never
                // fabricates state this push did not establish and never
                // re-stamps a deployment that did not touch the slot. A slot
                // with no prior record and no live assignment stays absent.
                if let Ok(Some(prior_server)) = store.read_slot_observed(&slot_id) {
                    observed_servers.insert(slot_id.clone(), prior_server);
                }
            }
        }
    }
    refresh_observed(
        store,
        target_name,
        &members,
        &observed_servers,
        &mut observed_warnings,
    );

    // 17. Per-slot retention under each slot's mutation lock. Retention uses
    // the slot's ACTUAL final assignment (read after any compensation), not
    // the desired plan: a compensated slot restored its prior variant.
    //
    // RETENTION IS SLOT-OWNED: each slot has ONE policy — the policy of its
    // OWNING VARIANT (the variant file whose `[[slots]]` entry declares the
    // slot), resolved from the caller's current `deploy.toml` via
    // `ProjectConfig::slot_retention` (retention is never part of a release
    // snapshot). There is NO per-target policy and NO union across the
    // slot's member targets: a slot shared across targets rotates under its
    // single owning-variant policy, so which target triggered this push (or
    // which targets the slot is a member of) never changes what is retained.
    //
    // POST-COMMIT MAINTENANCE: by this point the deployment has ALREADY
    // committed (servers advanced, snapshot recorded, attempt recorded), so a
    // retention failure must NOT change the reported outcome — the push still
    // returns `Ok` with the real `commit_status`. A failure is instead
    // recorded as a PERSISTENT debt marker (per target+slot, under the local
    // store) and surfaced as a warning on the report; later pushes —
    // including no-ops — retry the maintenance and clear the marker once the
    // retention succeeds. The capacity-path preflight retention in
    // `capacity.rs` is already best-effort with `.ok()`; this step-17 path is
    // what used to propagate retention errors as push failures.
    //
    // The mutation lock is held via an RAII guard for the whole retention
    // block, so an error from `compute_retained` or `rotate` releases the
    // lock on drop instead of leaking it (a manual acquire/release pair would
    // strand every later operation on this slot with "mutation lock held by
    // ..."). A lock acquisition conflict (held by another operation) NEVER
    // skips silently: it defers the maintenance the same way a retention
    // failure does — a best-effort debt marker plus an explicit warning
    // naming the slot — so after a successful push every slot is either
    // ROTATED or carries debt + a warning, and a later push (including a
    // no-op) services the marker once the lock is free.
    //
    let mut maintenance: Vec<String> = Vec::new();
    // Observed-refresh deferrals (post-commit projection lag) ride the same
    // warning channel as retention; unlike retention there is no debt marker to
    // retry — the next real push re-projects from durable facts.
    maintenance.extend(observed_warnings);
    // Retry any debt left by earlier pushes FIRST (before this push's own
    // retention), so a marker that succeeds here is cleared without re-rotating
    // the same slot immediately after a fresh step-17 failure. The retry is
    // NON-FALLIBLE (post-commit maintenance): every debt read/write failure is
    // a warning entry in the returned vec, never an `Err` — a debt-file fault
    // must not change the outcome of a deployment that already committed.
    maintenance.extend(retry_deferred_retentions(
        store,
        config,
        target_name,
        &helpers,
        op_id,
        deployment_id,
    ));
    // The store-global PENDING SWEEP (deferred by an earlier checkpoint
    // whose sweep did not complete) is likewise POST-COMMIT MAINTENANCE:
    // retry it on this push — recomputing reachability fresh, no persisted
    // worklist — and clear the marker once it completes. NON-FALLIBLE: every
    // debt read/write failure is a warning entry in the returned vec, never
    // an `Err` — a debt-file fault must not change the outcome of a
    // deployment that already committed.
    maintenance.extend(retry_pending_sweep(store, config, deployment_id.as_str()));
    for sid in &servers_order {
        let helper = &helpers[sid];
        // The slot's ONE retention policy, from its OWNING VARIANT (the
        // variant that declares the slot) — never a member-target union.
        let slot_retention = config
            .slot_retention(sid.as_str())
            .expect("every planned slot is declared by some variant");
        // TEST-ONLY step-17 phase hook: when a test armed the barrier for
        // THIS deployment id, signal "at step-17 lock acquisition" (with the
        // FRESH-STEP-17 phase — this push's own per-slot retention, whose
        // contended else-branch defers the maintenance as a debt marker) and
        // park until the test releases the engine (the fixture holds the
        // competing guard meanwhile) — per-slot lock contention becomes
        // DETERMINISTIC, with no thread racing the lock file. A no-op in
        // production builds (both this call and the store method are
        // `#[cfg(test)]`) and in unarmed tests.
        #[cfg(test)]
        store.step17_hook_barrier(deployment_id, HookPhase::FreshStep17);
        if let Ok(_guard) = helper.acquire_lock_guard(op_id.as_str()) {
            match rotate_slot_locked(helper, store, config, slot_retention, deployment_id) {
                Ok(()) => {
                    // Maintenance done for this slot: clear any marker left by
                    // an earlier push whose retention failed after commit. The
                    // clear is NON-FALLIBLE post-commit maintenance: a debt
                    // read/write failure becomes a warning, never an `Err`.
                    maintenance.extend(clear_retention_deferred(store, target_name, sid));
                }
                Err(e) => {
                    // The deployment already committed; defer the maintenance
                    // (marker + warning) instead of failing the push. The
                    // deferral is NON-FALLIBLE: a debt read/write failure here
                    // (e.g. the marker cannot be persisted) is a warning, never
                    // an `Err` — the committed outcome is unchanged.
                    maintenance.extend(set_retention_deferred(
                        store,
                        target_name,
                        sid,
                        &e.to_string(),
                    ));
                    maintenance.push(format!(
                        "retention deferred for slot '{}': {e}",
                        sid.as_str()
                    ));
                }
            }
        } else {
            // The slot's mutation lock is CONTENDED (held by another
            // operation), so the retention cannot run now. The deployment has
            // already committed, so this must NEVER fail the push: record the
            // deferral as best-effort debt (persistence faults are
            // warning-only per the post-commit lifecycle) and surface an
            // explicit warning naming the slot. The marker makes the
            // deferral retryable — a later push (including an up-to-date
            // no-op) services the maintenance once the lock is free and
            // clears the marker.
            maintenance.push(format!(
                "retention deferred for slot '{}': slot lock held by another operation",
                sid.as_str()
            ));
            // Best-effort debt record; NEVER propagates an error out of
            // post-commit maintenance: every debt read/write failure becomes
            // a warning in the returned vec (merged into the report's
            // `maintenance` channel), never an `Err` — the committed outcome
            // is unchanged. On persistence failure there is no marker, but
            // the explicit "retention debt maintenance deferred" warning
            // names the slot, so the report distinguishes a retryable
            // deferral (marker persisted) from one that must be re-deferred
            // by a later push.
            maintenance.extend(set_retention_deferred(
                store,
                target_name,
                sid,
                "slot lock held by another operation",
            ));
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
        warning: maintenance_warning(&maintenance),
        dry_run: false,
    })
}

/// Run one slot's retention — retained-set computation plus mark-and-sweep —
/// for a caller already holding the slot's mutation lock (RAII guard). The
/// single retention block shared by step 17 and by deferred-maintenance
/// retries, so both paths apply the same retention semantics and the same
/// lock discipline. `deployment_id` marks this operation's incoming
/// directory as active so retention never sweeps a deployment currently being
/// published. `retention` is the slot's ONE policy, already resolved from its
/// OWNING VARIANT by the caller (`ProjectConfig::slot_retention`) — retention is
/// slot-owned, never a per-target surface. Pins are the config's own pins
/// (policy lives in the caller-supplied `config` settings object, never a
/// separate argument).
fn rotate_slot_locked(
    helper: &RemoteHelper,
    store: &LocalStore,
    config: &ProjectConfig,
    retention: &RetentionConfig,
    deployment_id: &DeploymentId,
) -> Result<()> {
    let retained = compute_retained(helper, config.pins(), store, retention)?;
    let active_incoming = HashSet::from([deployment_id.as_str().to_string()]);
    helper.rotate(&retained, &active_incoming)?;
    Ok(())
}

/// Record a deferred-retention debt marker for one slot (keyed by
/// target+slot). Called only when the retention failed after the deployment
/// already committed — POST-COMMIT MAINTENANCE, so this function is
/// NON-FALLIBLE: every debt I/O failure (a read or write of the marker file)
/// becomes a WARNING returned here (merged into the report's `maintenance`
/// channel by the caller), never an `Err`. On a read failure the write is
/// skipped entirely — writing a map built from scratch would silently drop
/// the OTHER slots' existing markers — and the returned warning names the
/// deferral, so the maintenance is explicitly warned even though this slot's
/// marker was not persisted.
pub(crate) fn set_retention_deferred(
    store: &LocalStore,
    target: &str,
    slot: &SlotId,
    reason: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut debt = match store.read_retention_debt(target) {
        Ok(debt) => debt,
        Err(e) => {
            warnings.push(format!(
                "retention debt maintenance deferred: failed to read retention debt for \
                 '{target}': {e}"
            ));
            return warnings;
        }
    };
    debt.insert(slot.as_str().to_string(), reason.to_string());
    if let Err(e) = store.write_retention_debt(target, &debt) {
        warnings.push(format!(
            "retention debt maintenance deferred: failed to write retention debt for \
             '{target}': {e}"
        ));
    }
    warnings
}

/// Clear a slot's deferred-retention debt marker once the retention succeeded.
/// POST-COMMIT MAINTENANCE, so this is NON-FALLIBLE: a debt read failure
/// leaves the marker in place (a later push retries it) and a write/remove
/// failure keeps the stale marker — both become WARNING entries returned to
/// the caller (merged into the report's `maintenance` channel), never an
/// `Err`.
fn clear_retention_deferred(store: &LocalStore, target: &str, slot: &SlotId) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut debt = match store.read_retention_debt(target) {
        Ok(debt) => debt,
        Err(e) => {
            warnings.push(format!(
                "retention debt maintenance deferred: failed to read retention debt for \
                 '{target}': {e}"
            ));
            return warnings;
        }
    };
    if debt.remove(slot.as_str()).is_some()
        && let Err(e) = store.write_retention_debt(target, &debt)
    {
        warnings.push(format!(
            "retention debt maintenance deferred: failed to clear retention debt for \
             '{target}': {e}"
        ));
    }
    warnings
}

/// Refresh `observed.json` for `target_name` from a caller-supplied per-slot
/// observed projection, and propagate every shared slot's entry to EACH of its
/// member targets. Every store fault in this block is WARNING-ONLY: the
/// refresh runs after the deployment durably committed, so a fault must never
/// change the push's reported outcome. The warnings are pushed into
/// `observed_warnings` (merged into the report's `maintenance` warning
/// channel); this function NEVER returns `Err`.
///
/// The single source of truth for the observed refresh: the REAL-push path
/// (which feeds it the actual post-mutation state) and the NO-OP path (which
/// feeds it the EXISTING generation's assignment, since an up-to-date push
/// creates no records) both run this exact block, so a shared slot's
/// projection in every member target is refreshed identically by whichever
/// Refresh the PHYSICAL observed state for `target_name`'s member slots: each
/// advanced slot's ONE record is written EXACTLY ONCE (`slots/<slot-id>/observed.json`),
/// never once per member target — targets are selection views over the global
/// slot map, so a shared slot's single physical record serves every member
/// target's `read_observed` view. Every store fault in this block is
/// WARNING-ONLY: the refresh runs after the deployment durably committed, so a
/// fault must never change the push's reported outcome. The warnings are
/// pushed into `observed_warnings` (merged into the report's `maintenance`
/// warning channel); this function NEVER returns `Err`.
///
/// The single source of truth for the observed refresh: the REAL-push path
/// (which feeds it the actual post-mutation state) and the NO-OP path (which
/// feeds it the EXISTING generation's assignment, since an up-to-date push
/// creates no records) both run this exact block, so a shared slot's
/// physical record is refreshed identically by whichever path last touched
/// it. Observed maps are keyed by placement slot (the deployment-location
/// identity); the per-server record (`servers/<id>.json`) keeps the actual
/// [`crate::model::ServerId`] for transport identity. A member slot with no
/// entry in `observed_servers` is skipped (slots the caller's push did not
/// plan keep their prior physical record untouched).
fn refresh_observed(
    store: &LocalStore,
    target_name: &str,
    members: &[(&crate::config::SlotConfig, &crate::config::ServerDef)],
    observed_servers: &BTreeMap<SlotId, ObservedSlot>,
    observed_warnings: &mut Vec<String>,
) {
    for (slot, sdef) in members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let Some(observed_server) = observed_servers.get(&slot_id) else {
            continue;
        };
        if let Err(e) = store.write_server(&crate::records::ServerState {
            id: crate::model::ServerId::parse(sdef.id.as_str())
                .expect("validated server id is a safe segment"),
            last_seen_target: Some(
                TargetName::parse(target_name).expect("target name is a safe segment"),
            ),
            last_observed: Some(observed_server.clone()),
        }) {
            // The durable facts are recorded; only the per-server projection
            // is stale. Warn and continue — a later push's refresh rewrites it.
            observed_warnings.push(format!(
                "observed refresh deferred for server '{}': {e}",
                sdef.id.as_str()
            ));
        }
        // ONE physical write per slot — the slot's own observed record. A
        // shared slot is written ONCE regardless of how many targets it is a
        // member of: every member target's view (a filter over the global
        // slot map) sees the same physical record, so no per-target
        // propagation is needed (or possible) anymore.
        if let Err(e) = store.write_slot_observed(&slot_id, observed_server) {
            // A fault leaves only THIS slot's physical record stale — every
            // member target's view of it lags together. The next real push
            // re-projects from durable facts, so convergence needs no marker.
            observed_warnings.push(format!(
                "observed refresh deferred for slot '{}': {e}",
                slot_id.as_str()
            ));
        }
    }
}

/// Retry deferred post-commit retention maintenance for `target_name`: every slot
/// carrying a debt marker gets its retention re-attempted under the slot's
/// mutation lock (the same RAII-guarded block as step 17). Success clears the
/// marker; failure keeps it and refreshes its reason. Runs on later pushes —
/// before step 17 on the normal path and at the no-op return — because
/// retention is maintenance that must never change a deployment's reported
/// outcome. NON-FALLIBLE by contract: this function never returns `Err` — a
/// debt I/O failure (a read treated as empty debt, or a write/remove of the
/// marker) becomes a WARNING entry in the returned vec, so a debt-file fault
/// can never turn a push (real or no-op) into an error after the deployment
/// durably committed. Returns the slots still deferred, for the push report's
/// warning.
pub(crate) fn retry_deferred_retentions(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    helpers: &HashMap<SlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
) -> Vec<String> {
    // A debt READ failure is treated as empty debt: nothing can be serviced
    // this push, and the marker file (if any) is left untouched for a later
    // push to retry — the warning keeps the deferral explicit.
    let mut debt = match store.read_retention_debt(target_name) {
        Ok(debt) => debt,
        Err(e) => {
            return vec![format!(
                "retention debt maintenance deferred: failed to read retention debt for \
                 '{target_name}': {e}"
            )];
        }
    };
    if debt.is_empty() {
        return Vec::new();
    }
    let mut still_deferred: Vec<String> = Vec::new();
    let mut serviced: Vec<String> = Vec::new();
    for slot_str in debt.keys().cloned().collect::<Vec<_>>() {
        let sid = SlotId::parse(&slot_str).expect("rotation debt slot id is a safe segment");

        let Some(helper) = helpers.get(&sid) else {
            // The slot is no longer a member of this target, so its retention
            // cannot be serviced from here; keep the marker and say so.
            still_deferred.push(format!(
                "retention still deferred for slot '{slot_str}' (no longer a member of target \
                 '{target_name}')"
            ));
            continue;
        };
        // TEST-ONLY phase hook: the deferred-maintenance retry shares the
        // same RAII-guarded retention block as step 17, so it signals + parks
        // at the SAME barrier, tagged with the DEFERRED-RETRY phase (it runs
        // BEFORE the fresh step-17 retention and reads the debt FIRST — a test
        // that arms the debt fault only at the fresh step-17 phase therefore
        // does NOT arm it here). A test that armed the step-17 hook for this
        // deployment id gets deterministic contention at the retry too (the
        // no-op path reaches a step-17-equivalent lock acquisition only
        // here). A no-op in production builds and unarmed tests.
        #[cfg(test)]
        store.step17_hook_barrier(deployment_id, HookPhase::DeferredRetry);
        if let Ok(_guard) = helper.acquire_lock_guard(op_id.as_str()) {
            // The slot's ONE retention policy, from its OWNING VARIANT
            // (resolved from the current config — retention is never a
            // member-target union).
            let slot_retention = match config.slot_retention(slot_str.as_str()) {
                Ok(retention) => retention,
                Err(e) => {
                    // The slot is no longer declared by any variant: its
                    // retention cannot be serviced from here; keep the marker
                    // and say so.
                    still_deferred.push(format!(
                        "retention still deferred for slot '{slot_str}': {e}"
                    ));
                    continue;
                }
            };
            match rotate_slot_locked(helper, store, config, slot_retention, deployment_id) {
                Ok(()) => serviced.push(slot_str.clone()),
                Err(e) => {
                    // Keep the marker with the fresh reason.
                    debt.insert(slot_str.clone(), e.to_string());
                    still_deferred.push(format!(
                        "retention still deferred for slot '{slot_str}': {e}"
                    ));
                }
            }
        } else {
            still_deferred.push(format!(
                "retention still deferred for slot '{slot_str}': slot lock held by another \
                 operation"
            ));
        }
    }
    for s in &serviced {
        debt.remove(s);
    }
    // A debt WRITE/REMOVE failure (the marker could not be persisted or
    // removed) is post-commit maintenance: warn and leave the marker file as
    // it is — the retention itself succeeded, but a later push retries and
    // converges. Never an `Err`.
    if let Err(e) = store.write_retention_debt(target_name, &debt) {
        still_deferred.push(format!(
            "retention debt maintenance deferred: failed to write retention debt for \
             '{target_name}': {e}"
        ));
    }
    still_deferred
}

/// Retry the store-global PENDING SWEEP (the checkpoint's best-effort global
/// sweep, deferred as durable sweep debt — `<base>/sweep-debt.json`). Runs on
/// later pushes — real and no-op — because the sweep is POST-COMMIT
/// MAINTENANCE that must never change a deployment's reported outcome: a
/// sweep that has not run (or failed) is retried here, recomputing
/// reachability FRESH (no persisted deletion worklist), and the marker is
/// cleared once the sweep completes. NON-FALLIBLE by contract: this function
/// never returns `Err` — a debt read/write failure (a read treated as no
/// debt, or a write/remove of the marker) becomes a WARNING entry in the
/// returned vec, so a debt-file fault can never turn a push (real or no-op)
/// into an error after the deployment durably committed. Returns the
/// pending-sweep warnings for the push report's maintenance channel.
pub(crate) fn retry_pending_sweep(
    store: &LocalStore,
    config: &ProjectConfig,
    anchor: &str,
) -> Vec<String> {
    // A debt READ failure is treated as no debt: nothing can be serviced
    // this push, and the marker file (if any) is left untouched for a later
    // push to retry — the warning keeps the deferral explicit.
    let pending = match store.read_sweep_debt() {
        Ok(p) => p,
        Err(e) => {
            return vec![format!(
                "sweep debt maintenance deferred: failed to read sweep debt: {e}"
            )];
        }
    };
    let Some(reason) = pending else {
        return Vec::new();
    };
    // The push-side sweep retry recomputes reachability from the CURRENT
    // ledgers — NO checkpoint ledger override: the override is the
    // checkpoint's retained-suffix hypothetical and exists only while a
    // checkpoint sweep runs (see `crate::push::checkpoint`).
    match store.run_sweep(config, anchor, None) {
        Ok((_, true)) => {
            // The sweep completed: clear the marker. A write/remove failure
            // is post-commit maintenance: warn and leave the marker as it
            // is — a later push retries and converges. Never an `Err`.
            if let Err(e) = store.write_sweep_debt(None) {
                return vec![format!(
                    "sweep debt maintenance deferred: failed to clear sweep debt: {e}"
                )];
            }
            Vec::new()
        }
        Ok((_, false)) => {
            // Still incomplete: keep the marker with the fresh reason.
            if let Err(e) = store.write_sweep_debt(Some(
                "sweep still incomplete on retry; a later push retries it",
            )) {
                return vec![format!(
                    "sweep debt maintenance deferred: failed to write sweep debt: {e}"
                )];
            }
            vec![format!(
                "sweep still deferred: the global sweep did not complete ({reason}); a later push retries it"
            )]
        }
        Err(e) => {
            // The sweep failed: keep the marker with the fresh reason.
            if let Err(e2) = store.write_sweep_debt(Some(&e.to_string())) {
                return vec![format!(
                    "sweep debt maintenance deferred: failed to write sweep debt: {e2}"
                )];
            }
            vec![format!("sweep still deferred: {e}")]
        }
    }
}

/// Build the report's `warning` from deferred-maintenance entries: `None`
/// when nothing is outstanding, otherwise one message describing the deferred
/// work.
fn maintenance_warning(deferred: &[String]) -> Option<String> {
    if deferred.is_empty() {
        None
    } else {
        Some(format!(
            "post-commit maintenance deferred: {}",
            deferred.join("; ")
        ))
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

/// Fail closed in preflight if any planned assignment's (release, variant)
/// lacks a frozen behavior contract. EACH SLOT's behavior resolves from ITS
/// OWN artifact binding (`slot.assignment.artifact = {release, variant,
/// tree}`) — the per-release, per-variant index — never a snapshot-wide
/// single release. Historical behavior snapshots can be incomplete (a
/// corrupted or truncated `behavior.json` parses successfully but covers only
/// some variants); reaching rollout with a missing entry previously panicked
/// after trees were already staged onto servers. This gate runs before any
/// remote mutation and names the missing (release, variant) pairs and the
/// affected servers.
fn validate_behavior_coverage(
    index: &BehaviorIndex,
    assignments: &[crate::push::plan::PlannedAssignment],
) -> Result<()> {
    let mut missing: BTreeMap<(ReleaseId, String), Vec<&str>> = BTreeMap::new();
    for a in assignments {
        let covered = index
            .get(&a.artifact.release)
            .is_some_and(|m| m.contains_key(a.artifact.variant.as_str()));
        if !covered {
            missing
                .entry((
                    a.artifact.release.clone(),
                    a.artifact.variant.as_str().to_string(),
                ))
                .or_default()
                .push(a.placement_slot.as_str());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let detail = missing
        .iter()
        .map(|((release, variant), slots)| {
            format!(
                "release {release} variant '{variant}' (slots: {})",
                slots.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(Error::preflight(format!(
        "behavior snapshot incomplete: missing {detail}; \
         refusing to start before any remote state is changed"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CanonicalSlot, CanonicalSlots, GenerationRef, Provenance, RELEASE_RECORD_SCHEMA_VERSION,
        ReleaseRecord, test_deployment_id, test_generation_id, test_tree_digest,
    };
    use crate::records::LedgerEntry;
    use crate::remote::transport::{FsBytes, LocalTransport};
    use crate::testutil::test_remotes::{
        FailOnceGenerationRemote, FailOnceMarkerRemote, FailOnceStagingRemote, recording_factory,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
to = "app-common/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
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

    const NONE_TOML: &str = r#"
schema_version = 2
application = "eng"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    /// The two-group variant for the multi-release harness: `p1` in
    /// `group-a` (server `s1`), `p2` in `group-b` (server `s2`), verification
    /// argv carrying the contract tag `a` (so contract B, produced by the
    /// test's variant edit, digests DIFFERENTLY from contract A while both
    /// pass `true`).
    const TWO_SLOT_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = ["group-a"]
deploy_dir = "/srv/eng-a"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
groups = ["group-b"]
deploy_dir = "/srv/eng-b"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true", "a"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// The two-server config backing [`TWO_SLOT_VARIANT`] (one server per
    /// group slot, so each slot's remote is its own host).
    const TWO_SERVER_TOML: &str = r#"
schema_version = 2
application = "eng"
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

    /// A two-group harness (slots `p1`/`p2` on their own servers, groups
    /// `group-a`/`group-b`) so a test can build a REAL multi-release partial
    /// snapshot: a full push establishes both slots under release R1, a
    /// group-b push advances only `p2` to release R2, and the overlay
    /// snapshot carries BOTH releases.
    struct TwoSlotHarness {
        _dir: tempfile::TempDir,
        cfg_path: PathBuf,
        config: ProjectConfig,
        store: LocalStore,
        remotes_base: PathBuf,
    }

    impl TwoSlotHarness {
        fn new() -> TwoSlotHarness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let release_dir = project.join("releases").join("v1");
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(release_dir.join("standard.toml"), TWO_SLOT_VARIANT).unwrap();
            std::fs::write(project.join("deploy.toml"), TWO_SERVER_TOML).unwrap();
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
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let remotes_base = dir.path().join("remotes");
            std::fs::create_dir_all(&remotes_base).unwrap();
            TwoSlotHarness {
                _dir: dir,
                cfg_path,
                config,
                store,
                remotes_base,
            }
        }
    }

    /// One push against the two-slot harness with an explicit config, ref
    /// expression, and rollout group.
    fn two_slot_push(
        h: &TwoSlotHarness,
        config: &ProjectConfig,
        ref_expr: &RefExpr,
        group: Option<&str>,
        deployment_id: &DeploymentId,
    ) -> Result<PushReport> {
        let project_root = config.project_root(&h.cfg_path);
        let target = config.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
        };
        push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(config, "t1", group).unwrap(),
            ref_expr,
            None,
            deployment_id,
            &op_id,
            config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: group.map(str::to_string),
            },
        )
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
        let config = ProjectConfig::load(&config_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let factory = move |_s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
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
        let config = ProjectConfig::load(&config_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let remote_path = remotes_base.join("s1");
        let factory_path = remote_path.clone();
        let factory = move |_s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
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
        let tree = r0.attempt.expect("attempt recorded").slots[&SlotId::new("p1")]
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
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let release_root = config.release_root(&cfg_path);
        let vcfg = config.variant("standard").unwrap();
        let staging = store.staging_dir().join("standard");
        crate::mapper::materialize_variant(
            &release_root,
            &vcfg.artifact.mappings,
            &crate::template::TemplateVars::mapping(
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

    /// A single-server (`s1`/`t1`) project + store + remote base for the
    /// full-push recovery scenarios, mirroring the integration-test setup.
    struct RecoveryHarness {
        _dir: tempfile::TempDir,
        cfg_path: PathBuf,
        config: ProjectConfig,
        store: LocalStore,
        remotes_base: PathBuf,
    }

    impl RecoveryHarness {
        fn new() -> RecoveryHarness {
            RecoveryHarness::with_variant(NONE_VARIANT)
        }

        /// A harness whose variant file carries the given TOML (so a test can
        /// install a verification argv that renders template variables).
        fn with_variant(variant_toml: &str) -> RecoveryHarness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let release_dir = project.join("releases").join("v1");
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
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

    /// Push 1 of the recovery scenarios: the commit marker write fails
    /// once, so the attempt is recorded `PendingCommit` (activation already
    /// happened; the latest transition says `PendingCommit`, no snapshot
    /// entry, no `refs/last-successful`).
    /// Seed the target's ledger with ONE successful deployment carrying the
    /// given rollback payload (intent + `Successful` terminal). The entry's
    /// position in the successful chain is its `sN` — there are no explicit
    /// snapshot indices in the ledger.
    fn seed_snapshot(
        store: &LocalStore,
        target: &str,
        deployment_id: &str,
        behavior_sha256: &str,
        slots: BTreeMap<SlotId, GenerationRef>,
        bindings: BTreeMap<SlotId, crate::records::PhysicalBinding>,
    ) {
        // ONE slot table: the membership + the desired entries.
        let slot_table: BTreeMap<SlotId, IntentSlot> = slots
            .iter()
            .map(|(k, g)| {
                (
                    k.clone(),
                    IntentSlot {
                        desired: DesiredGeneration {
                            generation: g.generation.clone(),
                            artifact: g.assignment.artifact.clone(),
                        },
                        pre_push: None,
                    },
                )
            })
            .collect();
        store
            .append_intent(
                target,
                &DeploymentIntent {
                    deployment_id: test_deployment_id(deployment_id),
                    target: TargetName::new(target.to_string()),
                    group: None,
                    behavior_sha256: behavior_sha256.to_string(),
                    attempted_at: "2026-01-01T00:00:00Z".to_string(),
                    slots: NonEmptySlotTable::build(slot_table)
                        .expect("a seeded snapshot always has at least one slot"),
                },
            )
            .unwrap();
        store
            .append_terminal(
                target,
                &test_deployment_id(deployment_id),
                &LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    // The EXACT-EQUAL shape: the outcomes keys equal the
                    // rollback's slots keys (and bindings keys) — the
                    // four-set equality (outcomes == rollback slots ==
                    // rollback bindings == intent membership) is enforced
                    // by the conversion, so a seeded Successful terminal
                    // must carry one Activated outcome per slotted
                    // generation.
                    disposition: TerminalDisposition::Successful {
                        rollback: crate::records::LedgerRollback {
                            slots: slots.clone(),
                            bindings,
                        },
                        outcomes: SlotTable::from_map(
                            slots
                                .iter()
                                .map(|(k, g)| {
                                    (
                                        k.clone(),
                                        SlotResult {
                                            slot_id: k.clone(),
                                            outcome: SlotOutcomeKind::Activated,
                                            generation: Some(g.generation.clone()),
                                            compensated: false,
                                            error: None,
                                        },
                                    )
                                })
                                .collect(),
                        ),
                    },
                    reason: None,
                },
            )
            .unwrap();
    }

    fn push_pending_attempt(h: &RecoveryHarness) -> LedgerIntentReport {
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FailOnceMarkerRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
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
                group: None,
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

    /// A remote that records every `exec` argv it is handed (delegating all
    /// other operations to the wrapped `LocalTransport`), so a test can assert
    /// the RENDERED verification command vector without spawning a process.
    struct RecordingRemote {
        inner: LocalTransport,
        executed: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl RecordingRemote {
        fn new(base: PathBuf, executed: Arc<Mutex<Vec<Vec<String>>>>) -> Result<Self> {
            Ok(RecordingRemote {
                inner: LocalTransport::new(base)?,
                executed,
            })
        }
    }

    impl Remote for RecordingRemote {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn read(&self, rel: &Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<bool> {
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &Path, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &Path) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &Path) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &Path) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &Path) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &Path) -> Result<crate::remote::transport::RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(
            &self,
            argv: &[String],
            timeout: std::time::Duration,
        ) -> Result<crate::remote::transport::ExecOutcome> {
            self.executed.lock().unwrap().push(argv.to_vec());
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<FsBytes> {
            self.inner.filesystem_bytes()
        }
    }

    /// A push with a healthy `LocalTransport` remote.
    fn push_clean(h: &RecoveryHarness) -> Result<PushReport> {
        let rf = h.remotes_base.clone();
        let clean_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
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
                group: None,
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
    /// pointing at it, latest transition `Successful`, and the commit
    /// marker present on the remote.
    fn assert_finalized(h: &RecoveryHarness, attempt: &LedgerIntentReport) {
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(
            snapshots.len(),
            1,
            "exactly one successful snapshot, got {}",
            snapshots.len()
        );
        assert_eq!(
            snapshots[0].deployment_id, attempt.deployment_id,
            "exactly one successful entry, and it is the recovered attempt"
        );
        assert_eq!(
            history::successful_index(&h.store, "t1", &attempt.deployment_id)
                .unwrap()
                .unwrap(),
            0,
            "the recovered attempt is the successful chain position s0"
        );
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

    /// Build and persist a valid release record protecting the given variant
    /// trees (the pin-only trees of the engine-level pin-abort test).
    fn engine_pin_release(store: &LocalStore, pin_trees: &[&str]) -> ReleaseRecord {
        let variants: BTreeMap<VariantName, TreeDigest> = pin_trees
            .iter()
            .enumerate()
            .map(|(i, t)| {
                (
                    VariantName::new(format!("v{i}")),
                    TreeDigest::new(t.to_string()),
                )
            })
            .collect();
        let rec = crate::release::build_release(
            "mapping-sha",
            "behavior-sha",
            &variants,
            &BTreeMap::from([(
                "standard".to_string(),
                vec![SlotConfig::new(
                    "p1".to_string(),
                    "s1".to_string(),
                    PathBuf::from("/srv/pin"),
                    "t1".to_string(),
                    Vec::new(),
                )],
            )]),
            std::path::Path::new("."),
        );
        store.write_release(&rec).unwrap();
        rec
    }

    /// ENGINE-LEVEL wiring for the fail-closed pin abort: a post-commit
    /// step-17 retention whose pinned release record is unreadable must abort
    /// before ANY deletion, and the retention caller must convert the abort
    /// into the retention-debt machinery — the push still reports SUCCESS with
    /// a deferred-maintenance warning and a durable debt marker (never a hard
    /// push failure), and the NEXT push's maintenance retry services the
    /// marker once the record is repaired, deleting EXACTLY the genuinely
    /// unretained trees: the pin-only trees survive and the true garbage is
    /// removed. (All three corruption classes — missing / malformed /
    /// unverifiable — produce the SAME integrity abort and are each covered
    /// deterministically in the retention unit tests plus the 16-case
    /// property; this engine test proves the debt/warning/retry wiring with
    /// the missing-record class.)
    #[test]
    fn pin_abort_defers_retention_and_retry_after_repair_deletes_exactly() {
        let mut h = RecoveryHarness::new();

        // Push 1 (no pins yet): the first deployment establishes the
        // receiver — generation, current, tree.
        let r1 = push_clean(&h).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));

        // The pinned release protects two pin-only trees (referenced ONLY by
        // the pin — outside every count/age window), and a garbage object is
        // referenced by nothing.
        let rec = engine_pin_release(&h.store, &["tree-pin-a", "tree-pin-b"]);
        h.config = h
            .config
            .with_pin(crate::config::Pin {
                release: rec.release_id.clone(),
                reason: "known-good".into(),
            })
            .unwrap();
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let helper = RemoteHelper::new(&remote);
        for t in ["tree-pin-a", "tree-pin-b", "tree-garbage"] {
            helper
                .remote()
                .create_dir_all(&layout::tree_root(t))
                .unwrap();
        }

        // MISSING pinned release record: the pin names nothing on disk.
        let path = h
            .store
            .release_dir(&ReleaseId::new(rec.release_id.clone()))
            .join("release.json");
        std::fs::remove_file(&path).unwrap();

        // Push 2 (a REAL push — changed artifact content promotes a new
        // generation, so step-17 retention runs): the pin abort must NOT fail
        // the push. It is converted into retention debt + a warning, and
        // NOTHING is deleted.
        let artifacts = h
            .cfg_path
            .parent()
            .unwrap()
            .join("releases")
            .join("v1")
            .join("artifacts");
        std::fs::write(
            artifacts
                .join("build")
                .join("output")
                .join("app")
                .join("server"),
            "v2\n",
        )
        .unwrap();
        let r2 = push_clean(&h).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Successful),
            "the pin abort must never hard-fail the push (post-commit maintenance)"
        );
        let warning = r2
            .warning
            .as_ref()
            .expect("the push must warn about the deferred retention");
        assert!(
            warning.contains("retention deferred"),
            "the warning describes the deferred retention, got: {warning}"
        );
        let debt = h.store.read_retention_debt("t1").unwrap();
        let reason = debt
            .get("p1")
            .expect("a durable debt marker for slot p1 must be recorded");
        assert!(
            reason.contains("pin names release"),
            "the debt marker records the un-honorable pin, got: {reason}"
        );

        // ZERO DELETIONS: every pre-existing object survives push 2 (the
        // only inventory delta is the push's own new tree object).
        let inventory_after = helper.status().unwrap().inventory;
        for t in ["tree-pin-a", "tree-pin-b", "tree-garbage"] {
            assert!(
                inventory_after.contains(&t.to_string()),
                "tree {t} must survive the failed retention"
            );
        }

        // Repair the pinned release's record.
        let dir = h.store.release_dir(&ReleaseId::new(rec.release_id.clone()));
        std::fs::remove_dir_all(&dir).unwrap();
        h.store.write_release(&rec).unwrap();

        // Push 3 (up-to-date no-op): the deferred-maintenance retry
        // services the marker — the retention now succeeds, deleting
        // EXACTLY the genuinely unretained trees — and clears the marker.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.message, "Everything up to date");
        assert!(
            r3.warning.is_none(),
            "the retried retention succeeded: no warning remains, got {:?}",
            r3.warning
        );
        assert!(
            h.store.read_retention_debt("t1").unwrap().is_empty(),
            "the debt marker is cleared once the retry succeeds"
        );
        let inventory = helper.status().unwrap().inventory;
        for t in ["tree-pin-a", "tree-pin-b"] {
            assert!(
                inventory.contains(&t.to_string()),
                "pin-only tree {t} survives the retry"
            );
        }
        assert!(
            !inventory.contains(&"tree-garbage".to_string()),
            "the true garbage is removed by the retry"
        );
        let cur = helper
            .status()
            .unwrap()
            .current_generation
            .expect("a current generation exists");
        let live = helper
            .read_assignment(cur.as_str())
            .unwrap()
            .artifact
            .tree
            .as_str()
            .to_string();
        assert!(
            inventory.contains(&live),
            "the live tree {live} survives the retry"
        );
    }

    /// The TERMINAL EVENT append (the deployment's ONE atomic finalize write)
    /// fails once on the replaying push: `Err`, no rollback state exists
    /// (the entry stays intent-only = recoverable-pending), and the next
    /// clean push replays and completes finalization exactly once. There is
    /// no separate snapshot/last-successful/transition sequence anymore —
    /// the terminal carries status + outcomes + rollback in one write.
    #[test]
    fn recovery_replays_after_terminal_append_failure() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: the terminal append fails once -> the push aborts with Err
        // and nothing is durable yet (no rollback state).
        let err = {
            h.store
                .fault_registry()
                .arm_append_terminal(attempt.deployment_id.as_str());
            push_clean(&h).expect_err("push must abort when the terminal append fails")
        };
        assert!(
            err.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "no rollback state after the failed append"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, attempt.deployment_id.as_str()),
            DeploymentStatus::PendingCommit,
            "the intent-only entry stays recoverable-pending"
        );

        // Push 3: a clean push replays and completes finalization exactly once.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &attempt);
    }

    /// The SAME atomic terminal append, faulted on the MAIN path (the push
    /// itself): `Err`, the entry stays intent-only (recoverable-pending), and
    /// the next push reconciles it to exactly-once success.
    #[test]
    fn main_path_replays_after_terminal_append_failure() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-main-terminal-fault");

        let err = {
            h.store.fault_registry().arm_append_terminal(id.as_str());
            push_main_with_id(&h, &id).expect_err("push must abort when the terminal append fails")
        };
        assert!(
            err.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "no rollback state after the failed append"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit,
            "crash window must leave the attempt PendingCommit, not Successful"
        );

        // Push 2: a clean push reconciles the pending attempt (servers are
        // already at the desired generation) and completes finalization
        // exactly once.
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

    /// A SECOND faulted replay still converges exactly once: the terminal
    /// append is faulted on two consecutive pushes, and the THIRD push
    /// finalizes the attempt exactly once.
    #[test]
    fn second_faulted_replay_still_converges_exactly_once() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: terminal append faulted -> Err.
        let r2 = {
            h.store
                .fault_registry()
                .arm_append_terminal(attempt.deployment_id.as_str());
            push_clean(&h).expect_err("push 2 must abort when the terminal append fails")
        };
        assert!(
            r2.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {r2}"
        );

        // Push 3: terminal append faulted again -> Err; the entry is still
        // intent-only (no rollback state, nothing duplicated).
        let r3 = {
            h.store
                .fault_registry()
                .arm_append_terminal(attempt.deployment_id.as_str());
            push_clean(&h).expect_err("push 3 must abort when the terminal append fails again")
        };
        assert!(
            r3.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {r3}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "a second faulted replay must still leave no rollback state"
        );

        // Push 4: clean -> finalizes exactly once.
        let r4 = push_clean(&h).unwrap();
        assert_eq!(r4.status, None, "the replaying push is an up-to-date no-op");
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
    // parallel `cargo test`, because each harness arms ITS OWN store's
    // per-fixture fault registry (no process-global slots, no lock).

    /// A normal single-server push with a caller-supplied deployment id over
    /// healthy `LocalTransport` remotes (no injected remote faults). Drives
    /// the FULL normal success path (`push_inner`) so a test can arm store
    /// faults keyed by the fixed deployment id BEFORE the push runs.
    fn push_main_with_id(h: &RecoveryHarness, deployment_id: &DeploymentId) -> Result<PushReport> {
        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.target("t1").expect("harness configures target t1");
        let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
        };
        push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            deployment_id,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
    }

    /// The single attempt recorded for target `t1`, in REPORT form (the
    /// in-memory view of the persisted intent; the report's `slots` map is
    /// empty because the persisted intent carries no outcomes).
    fn single_attempt(h: &RecoveryHarness) -> LedgerIntentReport {
        let mut attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "exactly one attempt recorded");
        LedgerIntentReport::from_intent(&attempts.remove(0).intent).expect("verified intent parses")
    }

    /// The rollback payload of a successful ledger entry (the test view of
    /// the `DeploymentSnapshot` fields: `slots`, `bindings`).
    fn rollback_of(entry: &LedgerEntry) -> &crate::records::LedgerRollback {
        match &entry
            .terminal
            .as_ref()
            .expect("the entry has a terminal")
            .disposition
        {
            TerminalDisposition::Successful { rollback, .. } => rollback,
            _ => panic!("a successful snapshot entry carries a rollback state"),
        }
    }

    #[test]
    fn main_path_finalize_is_replay_safe_and_idempotent() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-main-plain");

        // First: a normal push completes finalization fully (no faults):
        // the attempt is `Successful`, one snapshot entry, the ref set.
        let r1 = push_main_with_id(&h, &id).unwrap();
        assert_eq!(
            r1.status,
            Some(DeploymentStatus::Successful),
            "clean push must finalize Successful"
        );
        assert!(
            r1.message.contains(&format!(
                "rollback payload keyed by deployment {id} of target t1"
            )),
            "message must carry the deployment-keyed rollback payload, got: {}",
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

    /// The marker-integrity-conflict recovery contract (requirement.md step
    /// 15): a `PendingCommit` attempt whose marker ALREADY exists with
    /// DIFFERENT content — a concurrent controller recorded a different fact,
    /// or the remote state diverged — must finalize `Degraded` with reason
    /// "marker integrity conflict", never `Successful`. The conflicting
    /// marker must be left byte-for-byte untouched (a retry would only hit the
    /// same permanent condition, so the attempt must not strand `PendingCommit`
    /// forever either), and no snapshot entry may appear for the attempt.
    #[test]
    fn conflicting_commit_marker_finalizes_degraded_and_never_successful() {
        let h = RecoveryHarness::new();
        // Baseline: a clean successful push (dep1) owns s0.
        let id1 = test_deployment_id("deploy-conflict-baseline");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));

        // Push 2 must MUTATE (otherwise it is an up-to-date no-op and the
        // marker fault never fires): change the artifact content first. The
        // commit marker write fails once -> PendingCommit; the marker is
        // absent, no snapshot exists, and the SERVERS already advanced to the
        // attempt's generation.
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
        // Faulted push (inline, since `push_pending_attempt` asserts an empty
        // snapshot log, which a baseline push precludes): the commit-marker
        // write fails once -> PendingCommit; the marker is absent, no NEW
        // snapshot exists, and the servers already advanced to the attempt's
        // generation.
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FailOnceMarkerRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
        };
        let r2 = push(
            &h.cfg_path,
            &h.store,
            &fault_factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(r2.status, Some(DeploymentStatus::PendingCommit));
        let attempt = r2.attempt.expect("attempt recorded");
        let dep2 = attempt.deployment_id.clone();
        let gen_v2 = attempt.desired[&SlotId::new("p1")].generation.clone();
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "the PendingCommit push adds no snapshot entry"
        );
        let marker_path = h
            .remotes_base
            .join("s1")
            .join(crate::layout::commit_marker(dep2.as_str()));
        assert!(
            !marker_path.exists(),
            "marker absent after the faulted push"
        );

        // A concurrent controller (or divergent remote state) planted a marker
        // for dep2 with DIFFERENT content: a different generation.
        let conflicting = serde_json::json!({
            "deployment_id": dep2.as_str(),
            "committed": true,
            "generation": "gen-from-another-controller",
            "slots": ["p1"],
        });
        let conflicting_bytes = serde_json::to_vec_pretty(&conflicting).unwrap();
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        std::fs::write(&marker_path, &conflicting_bytes).unwrap();

        // Push 3: recovery sees the conflicting marker, finalizes dep2 as
        // Degraded (transition only, no snapshot entry), leaves the marker
        // untouched, and then proceeds with the HEAD push (a no-op here).
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None, "the main HEAD push is an up-to-date no-op");
        assert_eq!(r3.message, "Everything up to date");
        assert_eq!(
            latest_status(&h, dep2.as_str()),
            DeploymentStatus::Degraded,
            "a conflicting marker must NEVER finalize the attempt Successful"
        );
        let transitions = h.store.read_transitions(dep2.as_str()).unwrap();
        let last = transitions.last().expect("transition stream non-empty");
        assert_eq!(
            last.reason.as_deref(),
            Some("marker integrity conflict"),
            "the degradation must be explained"
        );
        assert_eq!(
            std::fs::read(&marker_path).unwrap(),
            conflicting_bytes,
            "the conflicting marker must be left byte-for-byte untouched"
        );
        // No snapshot entry for dep2; the ref still points at the baseline.
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        // The live deployment is undisturbed: the servers stay at the gen the
        // PendingCommit attempt actually advanced them to.
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert_eq!(
            RemoteHelper::new(&remote)
                .status()
                .unwrap()
                .current_generation
                .as_ref()
                .map(|g| g.as_str()),
            Some(gen_v2.as_str()),
            "the conflict must not disturb the live deployment"
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
        let id2 = test_deployment_id("deploy-intent-fault-clean");
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
        let id = test_deployment_id("deploy-inprogress-no-results");
        let err = {
            h.store.fault_registry().arm_append_terminal(id.as_str());
            push_main_with_id(&h, &id).expect_err("push must abort when write_results fails")
        };
        assert!(err.to_string().contains("append_terminal"));

        // The intent record is durable even though a later step failed; it
        // carries the planned (desired) and observed (pre_push) maps but NO
        // outcomes (empty `slots`), and the attempt never appears Successful
        // anywhere (no snapshot, no ref, latest transition `InProgress`).
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "intent must be recorded before mutation");
        let intent = &attempts[0];
        assert_eq!(intent.deployment_id, id);
        // The verified domain intent carries NO outcomes map at all (the
        // type split: outcomes live in the terminal event and the in-memory
        // report, never in the persisted intent). The ONE slot table carries
        // the planned (desired) + observed (pre_push) entries per member.
        assert!(
            intent.intent.slots.contains_key(&SlotId::new("p1")),
            "the intent's one slot table carries the planned (desired) + observed (pre_push) entries"
        );
        assert!(
            h.store.read_results(id.as_str()).is_err(),
            "no results.json"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit,
            "the crash window leaves the entry intent-only (recoverable-pending)"
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
        let g = &rollback_of(&snap[0]).slots[&SlotId::new("p1")];
        let desired = &intent.desired[&SlotId::new("p1")];
        assert_eq!(
            g.generation.as_str(),
            desired.generation.as_str(),
            "snapshot generation comes from the verified desired state"
        );
        assert_eq!(g.assignment.artifact.tree, desired.assignment.artifact.tree);
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
    }

    /// Crash window: the intent is durable (outcomes live in the ONE
    /// terminal event, which was NOT appended — the faulted write), so the
    /// attempt is intent-only = the recoverable `PendingCommit` state —
    /// never `Successful` — and the NEXT push reconciles it to exactly-once
    /// success: one rollback state, derived last-successful, the marker, and
    /// the terminal `Successful` event.
    #[test]
    fn inprogress_crash_window_reconciles_to_exactly_once_success() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-inprogress-window");
        let err = {
            h.store.fault_registry().arm_append_terminal(id.as_str());
            push_main_with_id(&h, &id).expect_err("push must abort when the terminal append fails")
        };
        assert!(
            err.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_results(id.as_str()).is_err(),
            "no outcomes store exists until the terminal event lands"
        );
        assert_eq!(
            h.store.read_transitions(id.as_str()).unwrap().len(),
            0,
            "no terminal event exists before finalization"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit,
            "crash window must leave the attempt PendingCommit (intent-only), never Successful"
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
        let id_b = test_deployment_id("deploy-diverged-baseline");
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(remote.exists(crate::layout::current()), "remote advanced");

        // Craft an InProgress intent (id A) whose desired generation the
        // remote never minted: intent durable, finalization never started,
        // and the remote's current points elsewhere.
        let target_a = GenerationId::generate();
        let id_a = test_deployment_id("deploy-inprogress-diverged");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();

        let intent = DeploymentIntent {
            deployment_id: id_a.clone(),
            target: TargetName::new("t1".to_string()),
            group: None,
            behavior_sha256: baseline.behavior_sha256.as_str().to_string(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            slots: NonEmptySlotTable::build(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: target_a,
                        artifact: desired_ref.assignment.artifact.clone(),
                    },
                    pre_push: None,
                },
            )]))
            .expect("one member slot"),
        };
        h.store.append_attempt("t1", &intent).unwrap();
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            DeploymentStatus::PendingCommit,
            "the intent-only entry is the recoverable pending state"
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

    /// A clean successful push records ONE TERMINAL EVENT (the ledger's
    /// atomic finalize append) carrying the `Successful` status, the per-slot
    /// outcomes, and the rollback state. The persisted intent record itself
    /// carries an empty `slots` map (the outcomes live in the terminal).
    #[test]
    fn clean_push_transition_sequence_and_outcomes() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-sequence");
        let r = push_main_with_id(&h, &id).unwrap();
        assert_eq!(r.status, Some(DeploymentStatus::Successful));

        let transitions = h.store.read_transitions(id.as_str()).unwrap();
        let statuses: Vec<DeploymentStatus> = transitions.iter().map(|t| t.status()).collect();
        assert_eq!(
            statuses,
            vec![DeploymentStatus::Successful],
            "a successful push appends exactly ONE terminal event (Successful)"
        );
        assert_eq!(transitions[0].reason.as_deref(), Some("push completed"));

        // Outcomes separation: the terminal event carries the per-slot
        // outcome and the persisted intent carries NO outcomes.
        let results = h.store.read_results(id.as_str()).unwrap();
        assert_eq!(
            results[&SlotId::new("p1")].outcome,
            SlotOutcomeKind::Activated
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
            rollback_of(snap).slots[&SlotId::new("p1")].generation,
            results[&SlotId::new("p1")].generation.clone().unwrap()
        );
        let actual = &r.attempt.as_ref().unwrap().slots[&SlotId::new("p1")];
        assert_eq!(
            rollback_of(snap).slots[&SlotId::new("p1")]
                .assignment
                .artifact,
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
        let id = test_deployment_id("deploy-mid-mutation");
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FailOnceGenerationRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
        };
        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let r = push_inner(
            &project_root,
            &h.store,
            &fault_factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
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
        )
        .unwrap();
        assert!(
            r.status == Some(DeploymentStatus::FailedRolledBack)
                || r.status == Some(DeploymentStatus::Degraded),
            "mid-mutation failure must be reported as a failure, got {:?}",
            r.status
        );

        // The intent record is durable with NO outcomes member (outcomes live
        // in the terminal event and the report, never in the persisted intent
        // — the domain type carries no `slots` map).
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "intent must be recorded before mutation");
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::FailedRolledBack
        );
        let results = h.store.read_results(id.as_str()).unwrap();
        assert_eq!(results[&SlotId::new("p1")].outcome, SlotOutcomeKind::Failed);

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
        assert_eq!(
            observed.slots[&SlotId::new("p1")].generation,
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
        let assignment: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &crate::layout::generations()
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
        assert_eq!(
            observed.slots[&SlotId::new("p1")].generation.as_ref(),
            Some(&assignment.generation_id),
            "observed.json must be unchanged"
        );
    }

    /// A just-recorded attempt with NO transition stream at all (latest status
    /// `None`) is eligible for reconciliation: the next push finalizes it
    /// Successful with its own snapshot entry instead of skipping it.
    #[test]
    fn reconcile_attempt_without_transitions_is_eligible() {
        let h = RecoveryHarness::new();
        let id_b = test_deployment_id("deploy-no-status-baseline");
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(remote.exists(crate::layout::current()), "remote advanced");

        // Craft an intent with NO transition appended: eligibility treats the
        // absent status file as eligible (a just-recorded attempt).
        let id_a = test_deployment_id("deploy-no-status");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();

        let intent = DeploymentIntent {
            slots: NonEmptySlotTable::build(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: desired_ref.generation.clone(),
                        artifact: desired_ref.assignment.artifact.clone(),
                    },
                    pre_push: None,
                },
            )]))
            .expect("one member slot"),
            deployment_id: id_a.clone(),
            target: TargetName::new("t1".to_string()),
            group: None,
            behavior_sha256: baseline.behavior_sha256.as_str().to_string(),
            attempted_at: crate::remote::helper::now_rfc3339(),
        };
        h.store.append_attempt("t1", &intent).unwrap();
        assert_eq!(
            h.store.latest_status(id_a.as_str()).unwrap(),
            Some(DeploymentStatus::PendingCommit),
            "an intent-only entry is the recoverable pending state"
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
        assert_eq!(
            history::successful_index(&h.store, "t1", &id_a)
                .unwrap()
                .unwrap(),
            1,
            "the reconciled attempt is successful-chain position s1"
        );
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
    /// order) so snapshot/op-log indices stay monotonic: two crafted
    /// `InProgress` intents appended A-then-B finalize in that order with
    /// indices 1 and 2 after the baseline.
    #[test]
    fn reconcile_multiple_pending_oldest_first_with_monotonic_indices() {
        let h = RecoveryHarness::new();
        let id_b = test_deployment_id("deploy-multi-baseline");
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();

        let mk = |id: &str| DeploymentIntent {
            deployment_id: test_deployment_id(id),
            target: TargetName::new("t1".to_string()),
            group: None,
            behavior_sha256: baseline.behavior_sha256.as_str().to_string(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            slots: NonEmptySlotTable::build(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: desired_ref.generation.clone(),
                        artifact: desired_ref.assignment.artifact.clone(),
                    },
                    pre_push: None,
                },
            )]))
            .expect("one member slot"),
        };
        let a = mk("deploy-multi-a");
        let b = mk("deploy-multi-b");
        // Two intent-only entries: eligible for reconciliation, oldest first.
        h.store.append_attempt("t1", &a).unwrap();
        h.store.append_attempt("t1", &b).unwrap();

        // One push reconciles BOTH, oldest first.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.message, "Everything up to date");
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[1].deployment_id, a.deployment_id);
        assert_eq!(snapshots[2].deployment_id, b.deployment_id);
        assert_eq!(
            history::successful_index(&h.store, "t1", &a.deployment_id)
                .unwrap()
                .unwrap(),
            1,
            "successful-chain positions stay monotonic"
        );
        assert_eq!(
            history::successful_index(&h.store, "t1", &b.deployment_id)
                .unwrap()
                .unwrap(),
            2
        );
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
        let id1 = test_deployment_id("deploy-verify-fail-baseline");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior =
            r1.attempt.as_ref().expect("attempt recorded").slots[&SlotId::new("p1")].clone();
        let prior_gen = prior.generation.clone().expect("prior generation");
        let prior_tree = prior.artifact.tree.clone();
        let prior_release = prior.artifact.release.clone();
        // Behavior digest A (verification argv "true") frozen into s0.
        let var_a = h.config.variant("standard").unwrap();
        let a_digest = crate::release::behavior_contract_digest(&crate::model::BehaviorContract {
            activation: crate::config::ActivationConfig::from(var_a.activation.clone()),
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
        let config2 = ProjectConfig::load(&h.cfg_path).unwrap();
        let var_b = config2.variant("standard").unwrap();
        let b_digest = crate::release::behavior_contract_digest(&crate::model::BehaviorContract {
            activation: crate::config::ActivationConfig::from(var_b.activation.clone()),
            verification: var_b.verification.clone(),
        });
        assert_ne!(a_digest, b_digest, "behaviors must differ");

        let id2 = test_deployment_id("deploy-verify-fail");
        let target = config2.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id2.as_str()));
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
        };
        let r2 = push_inner(
            &config2.project_root(&h.cfg_path),
            &h.store,
            &factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(&config2, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id2,
            &op_id,
            &config2,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
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
        let actual = &r2.attempt.as_ref().expect("attempt recorded").slots[&SlotId::new("p1")];
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
        let res = &results[&SlotId::new("p1")];
        assert_eq!(res.outcome, SlotOutcomeKind::Failed);
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
                        .join(cur.as_str())
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
        // the restored prior generation/artifact — with the LIVE assignment's
        // OWN minting deployment (id1 created the restored generation; the
        // failed id2 did not), never the desired (failed) v2 tree and never
        // the failed deployment re-stamped onto a generation it did not
        // create.
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let os = &observed.slots[&SlotId::new("p1")];
        assert_eq!(os.generation, Some(prior_gen.clone()));
        let oa = os.artifact.as_ref().expect("observed artifact");
        assert_eq!(
            oa.tree, prior_tree,
            "observed tree must be the restored prior tree"
        );
        assert_eq!(oa.release, prior_release);
        let desired_tree = r2.attempt.as_ref().unwrap().desired[&SlotId::new("p1")]
            .assignment
            .artifact
            .tree
            .clone();
        assert_ne!(
            oa.tree, desired_tree,
            "observed must NOT reflect the desired (failed) v2 tree"
        );
        assert_eq!(
            os.last_deployment,
            Some(id1.clone()),
            "observed last_deployment must be the LIVE assignment's OWN minting deployment \
             (id1), not the failed attempt id2"
        );
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
        // snapshot, and the s0 snapshot/ref are untouched.
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
schema_version = 2
application = "batched"
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
        // declares p3/p4 with FAILING verification. BOTH own the retention
        // policy of the slots they declare (retention lives in the slot's
        // owning variant file).
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

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

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

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

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
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = test_deployment_id("deploy-batched-stop");
        let project_root = config.project_root(&cfg_path);
        let target = config.target("t1").expect("target t1");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
        };
        let r = push_inner(
            &project_root,
            &store,
            &factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
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
                attempt.slots.contains_key(&SlotId::new(sid)),
                "slot {sid} missing from attempt"
            );
        }
        let results = store.read_results(id.as_str()).unwrap();
        assert_eq!(results.len(), 4);
        // The first batch advanced, then compensated back (no prior state ->
        // `current` removed): Restored.
        assert_eq!(
            results[&SlotId::new("p1")].outcome,
            SlotOutcomeKind::Restored
        );
        assert_eq!(
            results[&SlotId::new("p2")].outcome,
            SlotOutcomeKind::Restored
        );
        // The failing slot of the second batch.
        assert_eq!(results[&SlotId::new("p3")].outcome, SlotOutcomeKind::Failed);
        // The slot after the failing one in the same/later batch was never
        // started.
        assert_eq!(
            results[&SlotId::new("p4")].outcome,
            SlotOutcomeKind::Skipped
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

        // OBSERVED REFRESH FOR SKIPPED/COMPENSATED SLOTS: `observed.json` is
        // refreshed for every member slot with a READABLE LIVE remote
        // assignment (or a prior observed record carried over verbatim).
        // NONE of the four slots has a live generation after the failed push
        // (the first-deploy batch was compensated back to no prior state, p3
        // failed, p4 was never started) and none has a prior record — so the
        // observed map must NOT fabricate entries: no `{generation: None,
        // artifact: desired}` lie for a slot nothing deployed to, no
        // re-stamped `last_deployment`.
        let observed = store.read_observed("t1", &config).unwrap();
        assert!(
            observed.slots.is_empty(),
            "slots without a live assignment (and without a prior record) must stay absent — \
             never fabricated with the desired artifact: {:?}",
            observed.slots.keys().collect::<Vec<_>>()
        );

        assert!(
            store.read_snapshots("t1").unwrap().is_empty(),
            "a failed attempt must produce no snapshot"
        );
    }

    // ---- Deployment order: the batching follows the plan's order ---------
    //
    // The wire's `slot_ids` is documented as "in deployment order (the same
    // set the commit marker `slots` payload records)". The plan's assignment
    // order — which drives the ROLLOUT BATCHING — is the config's
    // deterministic order (variants in name order, then each variant's slots
    // in FILE order), NOT sorted by slot id. The intent's slot table must
    // preserve that order, so the recorded `slot_ids` matches the batching
    // order exactly. Here the slots are declared in the deliberately
    // NON-sorted plan order [p3, p1, p2] and p1's verification FAILS: with
    // batch_size = 1 + stop_on_failure the batching processes p3 first
    // (advances), then p1 (fails) and stops — p2 is never started. If the
    // batching (or the recorded slot_ids) were sorted by id, p1 would fail
    // FIRST and p3 would never advance.

    #[test]
    fn batching_follows_the_deployment_order_not_sorted_slot_ids() {
        const ORDERED_TOML: &str = r#"
schema_version = 2
application = "ordered"
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

[[servers]]
id = "s3"
address = "c"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Variant `a` (sorts first) declares p3 with PASSING verification;
        // variant `b` declares p1 (FAILING verification) then p2 (passing,
        // never reached). The plan order is [p3, p1, p2] — the deployment
        // order — never the sorted [p1, p2, p3].
        let a = r#"
[[slots]]
id = "p3"
server = "s3"
target = "t1"
deploy_dir = "/srv/p3"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        let b = r#"
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

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("a.toml"), a).unwrap();
        std::fs::write(release_dir.join("b.toml"), b).unwrap();
        let artifacts = release_dir.join("artifacts");
        std::fs::create_dir_all(artifacts.join("build/output/app")).unwrap();
        std::fs::write(artifacts.join("build/output/app/server"), "v1\n").unwrap();

        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, ORDERED_TOML).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = test_deployment_id("deploy-ordered");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
        };
        let r = push_inner(
            &config.project_root(&cfg_path),
            &store,
            &factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &config,
            config.target("t1").expect("target t1"),
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack),
            "the failing p1 under stop_on_failure must roll the attempt back, got {:?}",
            r.status
        );

        // The recorded intent's slot_ids are the DEPLOYMENT order (the
        // batching order), never the sorted-by-id order.
        let attempt = r.attempt.expect("attempt recorded on failure");
        assert_eq!(
            attempt.slot_ids,
            vec![
                SlotId::new("p3".to_string()),
                SlotId::new("p1".to_string()),
                SlotId::new("p2".to_string()),
            ],
            "the wire's slot_ids must record the deployment order (the batching order), never sorted by id"
        );

        // The BATCHING order: p3 (the FIRST planned slot) advanced before
        // p1 failed; p2 (after the failing slot) was never started. Under a
        // sorted-by-id order p1 would have failed FIRST and p3 would never
        // have advanced.
        let results = store.read_results(id.as_str()).unwrap();
        assert_eq!(
            results[&SlotId::new("p3")].outcome,
            SlotOutcomeKind::Restored,
            "p3 (first in the deployment order) advanced before the failure and was compensated back"
        );
        assert_eq!(
            results[&SlotId::new("p1")].outcome,
            SlotOutcomeKind::Failed,
            "p1 (second in the deployment order) is the failing slot"
        );
        assert_eq!(
            results[&SlotId::new("p2")].outcome,
            SlotOutcomeKind::Skipped,
            "p2 (after the failing slot) was never started"
        );
    }

    // ---- Snapshot-ref membership-change refusal ------------------------------
    //
    // Exact snapshot rollback requires the current target's placement-slot SET to
    // be identical to the snapshot's recorded set (in addition to each slot's
    // physical binding). When the variant file declares a DIFFERENT slot, the
    // refusal must fire in planning — before any remote connection or store
    // write — and leave every byte of store + remote state untouched.

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

        // The exact rollback must be refused with the membership error
        // and must not mutate ANY deployment state. The refusal fires in
        // `plan_assignments` (before the remote phase opens a connection);
        // `push()`'s advisory lock files are the only bytes created.
        let remotes_before = snapshot_files(&h.remotes_base);
        let observed_before = h.store.read_observed("t1", &h.config).unwrap();
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
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
        assert_eq!(
            h.store.read_observed("t1", &h.config).unwrap(),
            observed_before
        );
        assert_eq!(
            remotes_before,
            snapshot_files(&h.remotes_base),
            "the refused rollback must not touch a single remote byte"
        );
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        assert!(
            remote.exists(crate::layout::current()),
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
        let s0_tree = s0.artifact.tree.clone();
        let s0_gen = s0.generation.clone().expect("s0 generation");

        let store_before = snapshot_files(h.store.base());
        let remotes_before = snapshot_files(&h.remotes_base);
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
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
        let remote = LocalTransport::new(h.remotes_base.join("s1")).unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        assert_eq!(
            status.current_generation.as_ref().map(|g| g.as_str()),
            Some(s0_gen.as_str()),
            "the remote current still points at s0's generation"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
        assert_eq!(
            h.store.read_observed("t1", &h.config).unwrap().slots[&SlotId::new("p1")].generation,
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
        let tree = s0.artifact.tree.clone();

        let store_before = snapshot_files(h.store.base());
        let remotes_before = snapshot_files(&h.remotes_base);
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
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
        config: ProjectConfig,
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
            let config = ProjectConfig::load(&cfg_path).unwrap();
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
            let target = self.config.target("t1").expect("harness target");
            let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
            let rf = self.remotes_base.clone();
            let factory = move |s: &crate::config::ServerDef,
                                _slot: &crate::config::SlotConfig|
                  -> Result<Box<dyn Remote>> {
                Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
            };
            push_inner(
                &project_root,
                &self.store,
                &factory,
                "t1",
                &crate::push::plan::SlotSelection::normalize(&self.config, "t1", None).unwrap(),
                &RefExpr::Head,
                None,
                deployment_id,
                &op_id,
                &self.config,
                target,
                &PushOptions {
                    dry_run: false,
                    ref_token: None,
                    group: None,
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
        // activation completes; s0 records the prior generation/artifact and
        // the remote publishes the prior behavior contract.
        let id1 = test_deployment_id("deploy-act-fail-baseline");
        let r1 = h.push_head(&id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior = r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")].clone();
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
        let id2 = test_deployment_id("deploy-act-fail");
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
        let actual = &r2.attempt.as_ref().expect("attempt recorded").slots[&SlotId::new("p1")];
        assert_eq!(actual.generation, Some(prior_gen.clone()));
        assert_eq!(
            actual.artifact.tree, prior_tree,
            "the actual artifact must be the restored prior tree, not the desired v2 tree"
        );

        // results.json records the compensation: the slot FAILED (activation)
        // and was compensated inside the per-server pipeline at the PRIOR
        // generation.
        let results = h.store.read_results(id2.as_str()).unwrap();
        let res = &results[&SlotId::new("p1")];
        assert_eq!(res.outcome, SlotOutcomeKind::Failed);
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
                        .join(cur.as_str())
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
        // the restored prior generation/artifact — with the LIVE assignment's
        // OWN minting deployment (id1 created the prior generation; the
        // failed id2 did not). It must NOT reflect the desired (failed) v2
        // tree, and the failed attempt must not be re-stamped onto a slot it
        // did not leave live.
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let os = &observed.slots[&SlotId::new("p1")];
        assert_eq!(os.generation, Some(prior_gen.clone()));
        let oa = os.artifact.as_ref().expect("observed artifact");
        assert_eq!(
            oa.tree, prior_tree,
            "observed tree must be the restored prior tree"
        );
        assert_eq!(oa.release, prior_release);
        let desired_tree = r2.attempt.as_ref().unwrap().desired[&SlotId::new("p1")]
            .assignment
            .artifact
            .tree
            .clone();
        assert_ne!(
            oa.tree, desired_tree,
            "observed must NOT reflect the desired (failed) v2 tree"
        );
        assert_eq!(
            os.last_deployment,
            Some(id1.clone()),
            "observed last_deployment must be the LIVE assignment's OWN minting deployment \
             (id1), not the failed attempt id2"
        );

        // The failed attempt is terminal FailedRolledBack, produced no
        // snapshot, and the s0 snapshot/ref are untouched.
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

        let id1 = test_deployment_id("deploy-act-compfail-baseline");
        let r1 = h.push_head(&id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior_gen = r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")]
            .generation
            .clone()
            .expect("prior generation");
        let prior_tree = r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")]
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
        let id2 = test_deployment_id("deploy-act-compfail");
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
        let res = &results[&SlotId::new("p1")];
        assert_eq!(res.outcome, SlotOutcomeKind::Failed);
        assert!(
            !res.compensated,
            "the failed compensation must not be recorded as compensated"
        );

        // The attempt is terminal Degraded and produced no snapshot; s0 is
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
            status.current_generation.as_ref().map(|g| g.as_str()),
            Some(prior_gen.as_str()),
            "the compensation swap-back is visible on the remote current"
        );
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let os = &observed.slots[&SlotId::new("p1")];
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
        fn filesystem_bytes(&self) -> Result<crate::remote::transport::FsBytes> {
            Ok(crate::remote::transport::FsBytes {
                total: self.avail,
                available: self.avail,
            })
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

        let id = test_deployment_id("deploy-first-act-fail");
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
        let res = &results[&SlotId::new("p1")];
        assert_eq!(res.outcome, SlotOutcomeKind::Failed);
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
                    reserve_percent: crate::scalar::CapacityPercent::new(0).expect("0 is in range"),
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
            &crate::push::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
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
            DeploymentStatus::FailedPreflight,
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
            &crate::push::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
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
            DeploymentStatus::FailedPreflight,
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

        // The partially-created incoming directory was cleaned best-effort:
        // the fault fired on the first file write, AFTER the incoming dir and
        // its `app/` subdir were created, so a real partial upload existed and
        // must be gone.
        assert!(
            !remote.exists(&crate::layout::incoming_dir(id.as_str())),
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
        let dir = tempfile::tempdir().unwrap();
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
            &crate::push::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
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
            let remote = LocalTransport::new(remotes_base.join(sname)).unwrap();
            assert!(
                !remote.exists(&crate::layout::incoming_dir(id.as_str())),
                "slot {sname}'s incoming dir must be cleaned best-effort"
            );
            assert!(
                !remote.exists(crate::layout::current()),
                "no current on {sname}"
            );
            assert!(
                remote
                    .list(crate::layout::generations())
                    .unwrap()
                    .is_empty(),
                "no generation record on {sname}"
            );
            assert!(
                remote.list(crate::layout::objects()).unwrap().is_empty(),
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
        let mut rec = crate::model::ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: crate::model::Provenance {
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
            },
            variants: BTreeMap::from([("standard".to_string(), "tree-x".to_string())]),
            slots: BTreeMap::from([(
                "standard".to_string(),
                crate::model::CanonicalSlots {
                    slots: vec![crate::model::CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/eng".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    }],
                },
            )]),
        };
        let digest = crate::release::recompute_release_digest(&rec)
            .expect("test release must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::model::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        let release = crate::model::ReleaseId::new(rec.release_id.clone());
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
                SlotId::new("p1".to_string()),
                GenerationRef {
                    generation: test_generation_id("gen-hist"),
                    assignment: crate::model::PlacementSlotAssignment {
                        placement_slot: SlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: release.clone(),
                            variant: VariantName::new("standard".to_string()),
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
                SlotId::new("p1".to_string()),
                crate::records::PhysicalBinding {
                    server: crate::model::ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/eng".to_string(),
                },
            )]),
        );

        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.target("t1").expect("harness target");
        let op_id = OperationId::new("op-historical-behavior".to_string());
        let id = test_deployment_id("deploy-hist-behavior");
        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
        };
        let err = push_inner(
            &project_root,
            &h.store,
            &factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
            &history::parse_ref_expr(test_deployment_id("deploy-hist-behavior-fixture").as_str())
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
            &crate::push::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
            &history::parse_ref_expr(test_deployment_id("deploy-hist-behavior-fixture").as_str())
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

    /// GROUP-PUSH ROLLBACK COVERS EXACTLY THE GROUP (the four-set equality,
    /// end to end): a successful terminal's outcomes keys, rollback slots
    /// keys, rollback bindings keys, and the intent's membership are EXACTLY
    /// EQUAL — so a group push's rollback records EXACTLY its selected
    /// slots (never the unselected base slots carried forward), and a
    /// rollback of that deployment restores EXACTLY the group, resolving
    /// EACH slot's behavior from ITS OWN (release, variant) binding — never
    /// a snapshot-wide single release.
    ///
    /// Drives the REAL push path on a two-group harness: a full push
    /// establishes both slots under contract A (release R1), a group-b push
    /// advances only `p2` to contract B (release R2) and records a rollback
    /// covering EXACTLY `p2` (the four-set equality — the unselected `p1`
    /// is NOT carried into the rollback). A rollback of that deployment
    /// restores `p2` to R2's variant behavior digest while `p1` stays on
    /// R1's (each slot's OWN release — under the old snapshot-wide behavior
    /// `p2` would receive R1's digest), and the referenced release's record
    /// is published on its server's remote.
    #[test]
    fn group_push_rollback_covers_exactly_the_group_and_publishes_per_slot_behavior() {
        let h = TwoSlotHarness::new();
        let slot_a = SlotId::new("p1".to_string());
        let slot_b = SlotId::new("p2".to_string());

        // Push 1: FULL Head push under contract A (argv ["true", "a"]) —
        // release R1 for BOTH slots; snapshot S0: p1=R1, p2=R1.
        let id1 = test_deployment_id("deploy-mr-baseline");
        let r1 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let var_a = h.config.variant("standard").unwrap();
        let digest_a = crate::release::behavior_contract_digest(&BehaviorContract {
            activation: crate::config::ActivationConfig::from(var_a.activation.clone()),
            verification: var_a.verification.clone(),
        });
        let attempt1 = r1.attempt.as_ref().expect("attempt recorded");
        let r1_release = attempt1.desired[&slot_a]
            .assignment
            .artifact
            .release
            .clone();
        assert_eq!(
            attempt1.desired[&slot_b].assignment.artifact.release, r1_release,
            "the full push deploys one release across both slots"
        );

        // Edit the variant to contract B (argv ["true", "b"]) AND a
        // DIFFERENT artifact payload, then reload: a group-b Head push now
        // builds a DISTINCT release R2.
        let project_root = h.config.project_root(&h.cfg_path);
        let variant_path = project_root
            .join("releases")
            .join("v1")
            .join("standard.toml");
        let v2 = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("argv = [\"true\", \"a\"]", "argv = [\"true\", \"b\"]");
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
        let var_b = config2.variant("standard").unwrap();
        let digest_b = crate::release::behavior_contract_digest(&BehaviorContract {
            activation: crate::config::ActivationConfig::from(var_b.activation.clone()),
            verification: var_b.verification.clone(),
        });
        assert_ne!(
            digest_a, digest_b,
            "the two contracts must be DISTINGUISHABLE"
        );

        // Push 2: PARTIAL group-b push under contract B — p2 advances to R2,
        // p1 stays R1. The rollback covers EXACTLY the group (the four-set
        // equality: outcomes == rollback slots == rollback bindings == the
        // intent's membership — the selected slots only).
        let id2 = test_deployment_id("deploy-mr-group-b");

        let r2 = two_slot_push(&h, &config2, &RefExpr::Head, Some("group-b"), &id2).unwrap();
        assert_eq!(r2.status, Some(DeploymentStatus::Successful));
        let attempt2 = r2.attempt.as_ref().expect("attempt recorded");
        let r2_release = attempt2.desired[&slot_b]
            .assignment
            .artifact
            .release
            .clone();
        assert_ne!(
            r1_release, r2_release,
            "the group push must produce a DISTINCT release"
        );
        assert_eq!(
            attempt2.desired.len(),
            1,
            "a group push plans only its selected slots"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 2, "baseline + the group-b snapshot");
        let s1 = rollback_of(&snapshots[1]);
        assert_eq!(
            s1.slots.len(),
            1,
            "the group push's rollback covers EXACTLY its membership (the four-set equality) — the unselected slot is NOT carried forward"
        );
        assert_eq!(
            s1.slots[&slot_b].assignment.artifact.release, r2_release,
            "the group push's rollback records its selected slot's own release (R2)"
        );

        // A FULL rollback to the group-b deployment is REFUSED: the
        // rollback must key EXACTLY the deployment's membership (the
        // four-set equality), so a full rollback of a group-only snapshot
        // cannot cover the unselected slot — exact rollback requires an
        // identical stable placement-slot set.
        let id3 = test_deployment_id("deploy-mr-rollback");
        let err = two_slot_push(
            &h,
            &config2,
            &history::parse_ref_expr(id2.as_str()).unwrap(),
            None,
            &id3,
        )
        .expect_err(
            "a FULL rollback of a group-only snapshot must be refused (the rollback keys exactly the deployment's membership)",
        );
        assert!(
            err.to_string()
                .contains("identical stable placement-slot set"),
            "expected the exact-rollback membership error, got: {err}"
        );

        // Push 3: FULL rollback of the BASELINE deployment (id1 — a full
        // push whose rollback covers both slots) restores BOTH slots to
        // their recorded state (R1, contract A).

        let r3 = two_slot_push(
            &h,
            &config2,
            &history::parse_ref_expr(id1.as_str()).unwrap(),
            None,
            &id3,
        )
        .unwrap();
        assert_eq!(r3.status, Some(DeploymentStatus::Successful));

        // The persisted plan carries the frozen PER-RELEASE behavior index
        // for the rollback's referenced release (R1 — the baseline's own
        // release) and the referenced-release set derived from the
        // snapshot's slots.
        let plan: DeploymentPlan = serde_json::from_str(
            &std::fs::read_to_string(h.store.deployment_dir(id3.as_str()).join("plan.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            plan.releases(),
            BTreeSet::from([r1_release.clone()]),
            "the rollback plan references the baseline's own release (R1)"
        );
        assert_eq!(
            plan.behaviors.len(),
            1,
            "one frozen behavior block per referenced release"
        );
        assert_eq!(
            crate::release::behavior_contract_digest(&plan.behaviors[&r1_release]["standard"]),
            digest_a
        );

        // EVERY SELECTED SLOT receives EXACTLY its own release's variant
        // behavior: the live generation assignment published on p1's and p2's
        // servers carries digest A (R1) — the baseline's own release — never
        // a snapshot-wide single release's contract.
        for (server, slot, want_digest, want_release) in [
            ("s1", &slot_a, &digest_a, &r1_release),
            ("s2", &slot_b, &digest_a, &r1_release),
        ] {
            let remote = LocalTransport::new(h.remotes_base.join(server)).unwrap();
            let helper = RemoteHelper::new(&remote);
            let status = helper.status().unwrap();
            let cur = status
                .current_generation
                .expect("the rollback must advance the slot");
            let assignment: GenerationAssignment = serde_json::from_slice(
                &remote
                    .read(
                        &crate::layout::generations()
                            .join(cur.as_str())
                            .join("assignment.json"),
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                assignment.behavior_sha256.as_str(),
                want_digest.as_str(),
                "slot {slot} must publish ITS OWN release's variant behavior digest"
            );
            assert_eq!(assignment.artifact.release.as_str(), want_release.as_str());
            assert!(
                remote.exists(
                    &crate::layout::remote_release(want_release.as_str()).join("release.json")
                ),
                "slot {slot}'s release record must be published on its server's remote"
            );
            assert!(
                remote.exists(
                    &crate::layout::remote_release(want_release.as_str()).join("behavior.json")
                ),
                "slot {slot}'s release behavior.json must be published on its server's remote"
            );
        }
        // And the two contracts are DISTINGUISHABLE — the assertion above is
        // not vacuous: the group push's release R2 really differs from the
        // baseline's R1 (a single contract would have made the group push a
        // no-op).
        assert_ne!(digest_a, digest_b);
    }

    /// A corrupt CURRENT generation assignment is detected by `status()`
    /// itself — the complete symlink layout is validated (`current` ->
    /// generation dir -> `assignment.json` -> generation id) — so a push
    /// against a remote whose live assignment is corrupt FAILS CLOSED with an
    /// integrity error BEFORE any mutation or intent persistence: never a
    /// panic, never a fabricated observation, never a silent proceed on an
    /// unverifiable current.
    #[test]
    fn corrupt_current_assignment_fails_status_and_push_closed() {
        let h = RecoveryHarness::new();
        let id1 = test_deployment_id("deploy-obs-fallback-baseline");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let gen1 = r1.attempt.as_ref().expect("attempt").slots[&SlotId::new("p1")]
            .generation
            .clone()
            .expect("baseline generation");

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

        // `status()` validates the complete symlink layout: a corrupt
        // assignment under the current generation is a MALFORMED remote state
        // and fails closed with an integrity error — never a panic, never a
        // `None` that would let a caller proceed on an unverifiable current.
        let err = RemoteHelper::new(&remote)
            .status()
            .expect_err("a corrupt current assignment must fail status closed");
        assert!(
            err.to_string().contains("integrity"),
            "the status failure must be an integrity error, got: {err}"
        );

        // A push against the corrupt remote fails closed at the status read,
        // BEFORE any mutation or intent persistence: no new generation, no
        // attempt, no snapshot, and the baseline ref is untouched.
        let id2 = test_deployment_id("deploy-obs-fallback");
        let err = push_main_with_id(&h, &id2)
            .expect_err("a push against a corrupt current assignment must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "the push failure must be an integrity error, got: {err}"
        );
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no attempt may be recorded for the failed push"
        );
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "no snapshot may be recorded for the failed push"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str()),
            "the baseline ref must be untouched"
        );
        // The remote `current` still points at gen1 — the failed push never
        // mutated the remote.
        assert_eq!(
            remote.read_link(crate::layout::current()).unwrap(),
            crate::layout::generation(gen1.as_str()).join("root"),
            "current must still point at the baseline generation"
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
schema_version = 2
application = "leave"
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
        // verification. BOTH variants own the retention policy of the slots
        // they declare (retention lives in the slot's owning variant file).
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

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

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

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

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
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = test_deployment_id("deploy-leave-changed");
        let project_root = config.project_root(&cfg_path);
        let target = config.target("t1").expect("target t1");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
        };
        let r = push_inner(
            &project_root,
            &store,
            &factory,
            "t1",
            &crate::push::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
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
        )
        .unwrap();
        assert_eq!(
            r.status,
            Some(DeploymentStatus::Degraded),
            "under leave_changed a failing batch must end Degraded, got {:?}",
            r.status
        );

        // The earlier successful batch is retained deliberately: p1/p2 keep
        // their live `current` (no compensation pass runs).
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
            results[&SlotId::new("p1")].outcome,
            SlotOutcomeKind::Activated
        );
        assert_eq!(
            results[&SlotId::new("p2")].outcome,
            SlotOutcomeKind::Activated
        );
        assert_eq!(results[&SlotId::new("p3")].outcome, SlotOutcomeKind::Failed);
        assert!(
            results[&SlotId::new("p3")].compensated,
            "the failing slot's in-process compensation is recorded"
        );
        assert_eq!(
            results[&SlotId::new("p4")].outcome,
            SlotOutcomeKind::Skipped
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
        let s0_tree = r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")]
            .artifact
            .tree
            .clone();

        let rf = h.remotes_base.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(rf.join(s.id.as_str()))?))
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

    /// Regression: the early "Everything up to date" comparison must compare
    /// the COMPLETE `ArtifactRef` (release + variant + tree), never just
    /// tree+release. Two variants can materialize the SAME tree bytes
    /// (identical artifact mappings and identical artifact source content ->
    /// same tree digest) while carrying DIFFERENT behavior contracts.
    /// Switching the slot's variant binding from `standard` to `other` (with
    /// the same tree) must be a REAL push (new generation, new attempt,
    /// verification under `other`'s contract) — a tree+release comparison
    /// would falsely report "Everything up to date", leaving the service
    /// claimed verified under the new contract without ever running it.
    #[test]
    fn variant_switch_same_tree_no_op_comparison() {
        // Two variants with IDENTICAL artifact mappings (and identical source
        // content) -> the SAME tree digest, but DIFFERENT verification
        // contracts: `standard` runs `["true"]`, `other` runs
        // `["true", "{{ variant }}"]` so the recording remote proves WHICH
        // contract actually ran.
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
        assert_eq!(first_slot.artifact.variant.as_str(), "standard");
        let first_tree = first_slot.artifact.tree.clone();
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
        assert_eq!(second_slot.artifact.variant.as_str(), "other");
        assert_eq!(
            second_slot.artifact.tree, first_tree,
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
                    &crate::layout::generations()
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
            cases: 4,
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
            let slot = SlotId::new("p1".to_string());

            // (c) A concurrent/reconciled append: a pending-commit attempt
            // whose reconciliation will append EXACTLY ONE snapshot during
            // the ref push. The push itself is real (it deploys to the remote
            // and records the attempt) but the commit marker write fails
            // once, so no snapshot is appended yet. It also persists the
            // release record + behavior snapshot + tree the synthetic chain
            // below reuses.
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
                &h.config,
                &PushOptions {
                    dry_run: false,
                    ref_token: None,
                group: None,
                },
            )
            .unwrap();
            assert_eq!(rp.status, Some(DeploymentStatus::PendingCommit));
            let pending = rp.attempt.as_ref().expect("the pending push records an attempt");
            let pending_id = pending.deployment_id.clone();
            let pending_artifact = pending.slots[&slot].artifact.clone();
            assert!(
                h.store.read_snapshots("t1").unwrap().is_empty(),
                "the pending attempt appends no snapshot yet"
            );

            // (a) Initial chain: synthetic snapshots 0..=latest (length L+1),
            // all referencing the pending push's REAL release + tree (which
            // are durable in the store), each with the harness's exact
            // physical binding so `plan_assignments` accepts the rollback.
            let bindings = crate::records::PhysicalBinding {
                server: crate::model::ServerId::new("s1".to_string()),
                deploy_dir: "/srv/eng".to_string(),
            };
            for i in 0..=latest {
               seed_snapshot(
                   &h.store,
                   "t1",
                   &format!("deploy-relative-chain-{latest}-{i}"),
                   pending.behavior_sha256.as_str(),
                   BTreeMap::from([(
                       slot.clone(),
                       GenerationRef {
                           generation: test_generation_id(&format!("gen-relative-{latest}-{i}")),
                           assignment: crate::model::PlacementSlotAssignment {
                               placement_slot: slot.clone(),
                               artifact: pending_artifact.clone(),
                           },
                        },
                   )]),
                   BTreeMap::from([(slot.clone(), bindings.clone())]),
               );
            }
            assert_eq!(
                h.store.read_snapshots("t1").unwrap().len() as u64,
                latest + 1,
                "the initial chain holds latest + 1 snapshots"
            );

            // The ref is RELATIVE: `@-` for depth 1, `parent(@, d)` else.
            let token = if depth == 1 {
                "@-".to_string()
            } else {
                format!("parent(@, {depth})")
            };
            // The PRE-FIX behavior resolved BEFORE reconciliation: against the
           // pre-append chain it selected position latest - depth (stale) or
           // failed outright when the chain was too short for the walk.
            let pre_reconcile = history::resolve_ref_expr(
                &history::parse_ref_expr(&token).unwrap(),
                "t1",
                &h.store,
            );
           // The POST-reconciliation chain: the pending attempt's ENTRY sits
           // at position 0 (its intent line was appended BEFORE the seeded
           // chain — the ledger's append order IS the history order), and
           // the seeded chain fills positions 1..=latest+1. The ref
           // `parent(@, depth)` selects chain position (latest + 1) - depth:
           // 0 -> the pending attempt, p>0 -> the chain entry at p - 1.
            let selected = (latest + 1) - depth;
           let selected_deployment: String = if selected == 0 {
               pending_id.as_str().to_string()
           } else {
               test_deployment_id(&format!("deploy-relative-chain-{latest}-{}", selected - 1))
                   .as_str()
                   .to_string()
           };
           // The PRE-reconcile resolution (against the seeded chain only):
           // `parent(@, depth)` walks to position (latest - depth) — the
           // stale selection — or fails outright when the chain is too short
           // (latest == 0 with depth 1 underflows). The pending attempt is
           // NOT yet a successful entry, so it cannot be selected.
            match pre_reconcile {
               Ok(PushRef::Deployment { deployment_id, .. }) => {
                   assert!(
                       latest > 0,
                       "a non-empty chain must resolve pre-reconcile"
                   );
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
                    panic!("a relative deployment ref must not resolve to a non-deployment pre-reconcile")
                }
                Err(_) => {
                    assert_eq!(
                        latest, 0,
                        "pre-fix on a non-empty chain must resolve (stale), not fail"
                    );
                }
            }
           // The POST-reconcile chain keeps the pending entry at its INTENT
           // position 0 (the ledger's append order is the history order), so
           // for latest >= 1 the relative walk from `@` lands on the SAME
           // chain entry pre- and post-reconcile; only the latest==0 case
           // (depth 1 == latest + 1) selects the reconciled pending itself.
           // The essential claim is unchanged: the ref is resolved against
           // the POST-reconciliation chain, which INCLUDES the pending.

            // The fixed flow: the engine reconciles FIRST (appending the
           // pending attempt's TERMINAL EVENT — it becomes the successful
           // entry at position latest + 1), THEN resolves the ref against the
           // post-reconciliation chain, then plans. The push is faulted at
           // its FIRST store write after `plan.json` — the INTENT append —
           // so the plan's resolved source is observable without the (slow)
           // mutation loop.
            let rf2 = h.remotes_base.clone();
            let clean_factory = move |s: &crate::config::ServerDef,
                                      _slot: &crate::config::SlotConfig|
                     -> Result<Box<dyn Remote>> {
                Ok(Box::new(LocalTransport::new(rf2.join(s.id.as_str()))?))
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
           .expect_err("the plan is durable before the first intent write, so the faulted push must Err");
            assert!(
               err.to_string().contains("append_attempt"),
               "the injected intent fault must be the failure, got: {err}"
            );

           // (c) The reconciled append happened: the pending attempt's entry
           // (intent line at position 0) now carries its Successful terminal
           // — it is the successful-chain entry at position 0, and the
           // seeded chain fills positions 1..=latest+1.
            let snapshots = h.store.read_snapshots("t1").unwrap();
            assert_eq!(
                snapshots.len() as u64,
                latest + 2,
               "seeded (latest+1) + reconciled (1); the faulted ref push appends nothing"
            );
           let reconciled = snapshots.first().expect("the reconciled entry must exist");
            assert_eq!(
                reconciled.deployment_id.as_str(),
                pending_id.as_str(),
               "the reconciled entry is the pending attempt (its intent line was first)"
           );
           assert_eq!(
               history::successful_index(
                   &h.store,
                   "t1",
                   &DeploymentId::parse(pending_id.as_str()).expect("canonical pending id"),
               )
               .unwrap()
               .unwrap(),
               0,
               "the pending attempt's successful position is s0"
            );

           // THE ASSERTION: the SELECTED deployment recorded in the plan
           // equals post-reconciliation position (latest + 1) - depth — the
           // deployment id at that chain position.
            let plan: DeploymentPlan = serde_json::from_str(
                &std::fs::read_to_string(h.store.deployment_dir(ref_id.as_str()).join("plan.json"))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                plan.source,
                crate::records::PlanOrigin::Deployment(
                    DeploymentId::parse(&selected_deployment).expect("canonical selected id")
                ),

               "'{token}' must select the entry at successful-chain position {selected} =                  s{}(latest + 1) - {depth} — the POST-reconciliation selection, not the                  pre-reconcile s{}(latest) - {depth}",
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
            let slot = SlotId::new("p1".to_string());
            let artifact = ArtifactRef {
                release: ReleaseId::new("rel-sha256-1111".to_string()),
                variant: VariantName::new("p1".to_string()),
                tree: test_tree_digest("aa"),
            };
            let bindings = crate::records::PhysicalBinding {
                server: crate::model::ServerId::new("s1".to_string()),
                deploy_dir: "/srv/eng".to_string(),
            };
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
                            assignment: crate::model::PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: artifact.clone(),
                            },
                        },
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
                _ => format!("{}-", test_deployment_id("deploy-fixture-0")),
            };
            // Self-check: the token parses and genuinely fails to resolve.
            let expr = history::parse_ref_expr(&token).unwrap();
            assert!(
                history::resolve_ref_expr(&expr, "t1", &h.store).is_err(),
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
                group: None,
                },
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

    // ---------------------------------------------------------------------
    // DIRECT-RELEASE MEMBERSHIP DRIFT: `release:<id>` must be rejected BEFORE
    // the remote factory is invoked (zero remote contact) in BOTH real and
    // dry-run modes, and must plan when the membership matches (control).
    // ---------------------------------------------------------------------

    /// The slot universe + fixed members the generated memberships draw from,
    /// mirroring the plan.rs property: `p1`/`p2`/`p3` are the generated
    /// COMMON members (declared for BOTH targets), `iso` is a `t2`-ONLY
    /// member, and `phys` is a constant member whose PHYSICAL binding
    /// (server) the fixture may drift while its id stays (logical-only
    /// comparison). Each slot owns a distinct server so the per-target
    /// server-uniqueness validation passes for every generated membership.
    const MEMBERSHIP_UNIVERSE: [&str; 3] = ["p1", "p2", "p3"];

    /// Build the membership-drift fixture: a project with targets `t1`/`t2`
    /// whose CURRENT variant declares the generated membership (plus the
    /// constants `phys`, `iso`), and a release record whose OWN frozen
    /// canonical slot snapshot declares the RELEASE-VERSIONED membership
    /// (plus the same constants). The variant is MATERIALIZED and the real
    /// tree object stored, and the release record carries a REAL behavior
    /// snapshot (verified against the record's provenance digest), so a
    /// MATCHING-membership real push can complete the whole deployment (the
    /// property's control branch). `physical_drift` rebinds `phys` to a
    /// different server in the config only (its id stays — the membership
    /// comparison is logical only). Returns the fixture's tempdir, config
    /// path, config, store, and the written release id.
    fn membership_drift_fixture(
        release_inc: [bool; 3],
        current_inc: [bool; 3],
        physical_drift: bool,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        ProjectConfig,
        LocalStore,
        ReleaseId,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();

        // Current variant file: one slot entry per generated current member,
        // plus the constant `iso` (t2-only) and `phys` (rebound when
        // `physical_drift`). The mappings + activation/verification mirror the
        // harness `NONE_VARIANT` so a real push completes.
        let mut variant = String::new();
        let add_slot = |variant: &mut String, id: &str, server: &str, target: &str, dir: &str| {
            variant.push_str(&format!(
                "[[slots]]\nid = \"{id}\"\nserver = \"{server}\"\ntarget = \"{target}\"\ndeploy_dir = \"{dir}\"\n\n"
            ));
        };
        for (i, inc) in current_inc.iter().enumerate() {
            if *inc {
                let id = MEMBERSHIP_UNIVERSE[i];
                add_slot(
                    &mut variant,
                    id,
                    &format!("s{}", i + 1),
                    "t1",
                    &format!("/srv/{id}"),
                );
            }
        }
        add_slot(&mut variant, "iso", "s4", "t2", "/srv/iso");
        add_slot(
            &mut variant,
            "phys",
            if physical_drift { "s6" } else { "s5" },
            "t1",
            "/srv/phys",
        );
        variant.push_str(
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n\
             [[artifact.mappings]]\nfrom = \"artifacts/deployment/common/\"\nto = \"app-common/\"\nrecursive = true\n\n\
             [retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n\
             [retention.deployment]\nprotect_deployments = 1\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
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
                "schema_version = 2\napplication = \"eng\"\nrelease = \"v1\"\n\n\
                 {servers}\
                 [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n\n\
                 [targets.t2]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        // The artifact files the mappings reference (and the real tree
        // materialized from them).
        let artifacts_dir = release_dir.join("artifacts");
        for (p, c) in [
            ("build/output/app/server", "v1\n"),
            ("deployment/common/README", "common\n"),
        ] {
            let fp = artifacts_dir.join(p);
            std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
            std::fs::write(&fp, c).unwrap();
        }
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        // Materialize the variant and store the REAL tree object, exactly as a
        // HEAD push would, so the matching-membership control can run a FULL
        // real push (staging reads the local object).
        let staging = store.staging_dir().join("membership-fixture");
        crate::mapper::materialize_variant(
            &release_dir,
            &config.variant("standard").unwrap().artifact.mappings,
            &crate::template::TemplateVars::mapping(
                config.application().as_str(),
                config.release().as_str(),
                "standard",
            ),
            &staging,
        )
        .unwrap();
        let meta = crate::tree::canonicalize_tree(&staging).unwrap();
        let tree = meta.tree_sha256;
        store
            .store_object(&TreeDigest::new(tree.clone()), &staging)
            .unwrap();

        // The release's OWN frozen canonical snapshot: the generated
        // membership (targets t1+t2) plus the constant phys (t1+t2, at its
        // ORIGINAL server s5) and iso (t2-only), exactly mirroring the
        // current config's targets lists.
        let mut canonical: Vec<CanonicalSlot> = Vec::new();
        for (i, id) in MEMBERSHIP_UNIVERSE.iter().enumerate() {
            if release_inc[i] {
                canonical.push(CanonicalSlot {
                    id: id.to_string(),
                    server: format!("s{}", i + 1),
                    deploy_dir: format!("/srv/{id}"),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                });
            }
        }
        canonical.push(CanonicalSlot {
            id: "phys".to_string(),
            server: "s5".to_string(),
            deploy_dir: "/srv/phys".to_string(),
            target: "t1".to_string(),
            groups: Vec::new(),
        });
        canonical.push(CanonicalSlot {
            id: "iso".to_string(),
            server: "s4".to_string(),
            deploy_dir: "/srv/iso".to_string(),
            target: "t2".to_string(),
            groups: Vec::new(),
        });
        canonical.sort_by(|a, b| a.id.cmp(&b.id));

        // The behavior snapshot the real push's `read_release_behaviors`
        // verifies against the record's provenance digest, plus the mapping
        // aux file — mirroring what a HEAD push's `write_release_aux` stores.
        let vcfg = config.variant("standard").unwrap();
        let variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::from([(
            "standard".to_string(),
            BehaviorContract {
                activation: crate::config::ActivationConfig::from(vcfg.activation.clone()),
                verification: vcfg.verification.clone(),
            },
        )]);
        let behavior_sha = crate::release::variant_behaviors_digest(&variant_behaviors);
        let behavior_json = serde_json::to_value(&variant_behaviors).unwrap();
        let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
        variant_mappings.insert("standard".to_string(), vcfg.artifact.mappings.clone());
        let mapping_sha = crate::release::variant_mappings_digest(&variant_mappings);

        // Assemble the record with the REAL provenance digests, then recompute
        // its identity from its own content (the digest folds the slot
        // snapshot, variant bindings, and provenance in), so `write_release`'s
        // recompute-and-verify passes.
        let mut rec = ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: "unused".to_string(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                mapping_sha256: mapping_sha,
                behavior_sha256: behavior_sha,
            },
            variants: BTreeMap::from([("standard".to_string(), tree.clone())]),
            slots: BTreeMap::from([("standard".to_string(), CanonicalSlots { slots: canonical })]),
        };
        let release = crate::release::recompute_release_digest(&rec)
            .expect("the fixture record carries its slot snapshot");
        rec.release_sha256 = release.as_str().to_string();
        rec.release_id = crate::model::ReleaseId::from_digest(&release)
            .as_str()
            .to_string();
        let rid = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        let mapping_toml = toml::to_string_pretty(&variant_mappings).unwrap();
        store
            .write_release_aux(&rid, &mapping_toml, &behavior_json)
            .unwrap();

        (dir, cfg_path, config, store, rid)
    }

    // THE REQUIRED DIRECT-RELEASE MEMBERSHIP PROPERTY: for generated
    // RELEASE-VERSIONED vs CURRENT membership sets, a direct `release:<id>`
    // push invokes the COMPLETE push path (`push(...)`) in BOTH modes — real
    // (`dry_run: false`) and dry-run (`dry_run: true`) — with a RECORDING
    // factory (construction AND every remote method call tick a shared
    // counter). Every MISMATCHED membership is rejected with the
    // membership-drift error BEFORE the remote factory is invoked: ZERO
    // factory invocations and ZERO remote calls, in both modes — the drift
    // gate lives in `push()` right after the ref is parsed/resolved, ahead of
    // any lock and any factory contact (previously the check ran at plan time
    // inside `push_inner`, after the read-only remote status had already
    // contacted every remote).
    //
    // CONTROL (matching membership): both modes PLAN — the dry run returns a
    // dry-run plan and the real push completes a FULL deployment — and the
    // recording factory IS invoked (a valid push legitimately contacts
    // remotes to inspect status / to deploy): the property's zero-contact
    // assertion applies ONLY to the mismatch path, and the control's
    // `calls > 0` checks prove the recording seam would catch a regression
    // that re-introduced remote contact before the membership gate (a
    // counter that could never move would make the zero-invocation assertion
    // vacuous).
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: 4,
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
                        group: None,
                        },
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
                    group: None,
                    },
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
                    group: None,
                    },
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

    // ---------------------------------------------------------------------
    // DIRECT-RELEASE GROUP PROPERTY: `release:<id> --group <g>` validates the
    // release against the target's COMPLETE membership — every generated
    // proper group subset plans — and a mutated COMPLETE membership
    // (add/remove/rename of a full-target slot) always fails before any
    // remote access (zero recording-factory invocations, both modes).
    // ---------------------------------------------------------------------

    /// A mutation of the CURRENT config only — the release record stays
    /// frozen to the ORIGINAL membership, so every mutation is a
    /// COMPLETE-membership drift. The mutated slot is a CONSTANT member
    /// (never a group slot), so the group selection stays valid and the
    /// refusal is always the membership-drift error, never a
    /// group-selects-nothing config error.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum MembershipMutation {
        /// A fresh slot (`p99` on server `s7`) joins the target's current
        /// membership — the release froze a target without it.
        Add,
        /// The constant member `phys` is dropped from the target's current
        /// membership — the release froze it as a member.
        Remove,
        /// The constant member `phys` is renamed `physX` — the release froze
        /// the old id.
        Rename,
    }

    /// Render the variant file for a t1 membership: the generated universe
    /// slots (`group_inc` in the group `group-a`, `extra_inc` outside any
    /// group), the constant `phys` (id `phys_id` — `None` drops it, the
    /// Remove mutation), and an optional extra slot (the Add mutation's
    /// `p99`). Every slot owns a distinct server so the per-target
    /// server-uniqueness validation passes for every rendered membership.
    fn group_variant_string(
        group_inc: [bool; 3],
        extra_inc: [bool; 3],
        phys_id: Option<&str>,
        add_slot: Option<(&str, &str, &str)>,
    ) -> String {
        let mut variant = String::new();
        let push_slot = |variant: &mut String,
                         id: &str,
                         server: &str,
                         groups: &[&str],
                         dir: &str| {
            let groups_line = if groups.is_empty() {
                String::new()
            } else {
                format!("groups = [\"{}\"]\n", groups.join("\", \""))
            };
            variant.push_str(&format!(
                    "[[slots]]\nid = \"{id}\"\nserver = \"{server}\"\ntarget = \"t1\"\n{groups_line}deploy_dir = \"{dir}\"\n\n"
                ));
        };
        let group = "group-a";
        for (i, inc) in group_inc.iter().enumerate() {
            if *inc {
                let id = MEMBERSHIP_UNIVERSE[i];
                push_slot(
                    &mut variant,
                    id,
                    &format!("s{}", i + 1),
                    &[group],
                    &format!("/srv/{id}"),
                );
            }
        }
        for (i, inc) in extra_inc.iter().enumerate() {
            if *inc && !group_inc[i] {
                let id = MEMBERSHIP_UNIVERSE[i];
                push_slot(
                    &mut variant,
                    id,
                    &format!("s{}", i + 1),
                    &[],
                    &format!("/srv/{id}"),
                );
            }
        }
        if let Some(pid) = phys_id {
            push_slot(&mut variant, pid, "s5", &[], "/srv/phys");
        }
        if let Some((id, server, dir)) = add_slot {
            push_slot(&mut variant, id, server, &[], dir);
        }
        variant.push_str(
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n\
             [[artifact.mappings]]\nfrom = \"artifacts/deployment/common/\"\nto = \"app-common/\"\nrecursive = true\n\n\
             [retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n\
             [retention.deployment]\nprotect_deployments = 1\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
        variant
    }

    /// The group fixture's config: servers `s1..=s7` (s7 backs the Add
    /// mutation's `p99`; unused servers are harmless) and the single target
    /// `t1`.
    fn group_config_string() -> String {
        let mut servers = String::new();
        for i in 1..=7 {
            servers.push_str(&format!(
                "[[servers]]\nid = \"s{i}\"\naddress = \"a{i}\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n"
            ));
        }
        format!(
            "schema_version = 2\napplication = \"eng\"\nrelease = \"v1\"\n\n\
             {servers}\
             [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
        )
    }

    /// Build the direct-release GROUP fixture: target `t1`'s CURRENT config
    /// declares the generated membership (the group `group-a` on exactly the
    /// `group_inc` subset of the universe, the `extra_inc` slots outside any
    /// group) plus the constant `phys`; the release record's OWN frozen
    /// canonical snapshot declares the SAME membership (matching by
    /// construction); and a SUCCESSFUL ledger entry carries every current t1
    /// member with its current physical binding — the base a proper-subset
    /// group push's partial-rollout guard needs to carry the unselected slots
    /// forward. The behavior + mapping aux snapshots are stored so the
    /// release path's `read_release_behaviors` verifies. Returns the
    /// fixture's tempdir, config path, config, store, release id, and group
    /// name.
    fn group_membership_fixture(
        group_inc: [bool; 3],
        extra_inc: [bool; 3],
    ) -> (
        tempfile::TempDir,
        PathBuf,
        ProjectConfig,
        LocalStore,
        ReleaseId,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(
            release_dir.join("standard.toml"),
            group_variant_string(group_inc, extra_inc, Some("phys"), None),
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, group_config_string()).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        // The behavior snapshot + mapping aux the release path verifies
        // against the record's provenance digests (mirroring a HEAD push's
        // `write_release_aux`).
        let vcfg = config.variant("standard").unwrap();
        let variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::from([(
            "standard".to_string(),
            BehaviorContract {
                activation: crate::config::ActivationConfig::from(vcfg.activation.clone()),
                verification: vcfg.verification.clone(),
            },
        )]);
        let behavior_sha = crate::release::variant_behaviors_digest(&variant_behaviors);
        let behavior_json = serde_json::to_value(&variant_behaviors).unwrap();
        let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
        variant_mappings.insert("standard".to_string(), vcfg.artifact.mappings.clone());
        let mapping_sha = crate::release::variant_mappings_digest(&variant_mappings);

        // The release's OWN frozen canonical snapshot: the generated
        // membership (group declarations mirroring the config) plus the
        // constant `phys`.
        let group = "group-a".to_string();
        let mut canonical: Vec<CanonicalSlot> = Vec::new();
        for (i, id) in MEMBERSHIP_UNIVERSE.iter().enumerate() {
            if group_inc[i] || extra_inc[i] {
                canonical.push(CanonicalSlot {
                    id: id.to_string(),
                    server: format!("s{}", i + 1),
                    deploy_dir: format!("/srv/{id}"),
                    target: "t1".to_string(),
                    groups: if group_inc[i] {
                        vec![group.clone()]
                    } else {
                        Vec::new()
                    },
                });
            }
        }
        canonical.push(CanonicalSlot {
            id: "phys".to_string(),
            server: "s5".to_string(),
            deploy_dir: "/srv/phys".to_string(),
            target: "t1".to_string(),
            groups: Vec::new(),
        });
        canonical.sort_by(|a, b| a.id.cmp(&b.id));
        let mut rec = ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: "unused".to_string(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                mapping_sha256: mapping_sha,
                behavior_sha256: behavior_sha,
            },
            variants: BTreeMap::from([(
                "standard".to_string(),
                test_tree_digest("tree-group").as_str().to_string(),
            )]),
            slots: BTreeMap::from([("standard".to_string(), CanonicalSlots { slots: canonical })]),
        };
        let release = crate::release::recompute_release_digest(&rec)
            .expect("the fixture record carries its slot snapshot");
        rec.release_sha256 = release.as_str().to_string();
        rec.release_id = crate::model::ReleaseId::from_digest(&release)
            .as_str()
            .to_string();
        let rid = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        let mapping_toml = toml::to_string_pretty(&variant_mappings).unwrap();
        store
            .write_release_aux(&rid, &mapping_toml, &behavior_json)
            .unwrap();

        // The SUCCESSFUL ledger entry whose rollback payload carries every
        // current t1 member and its current binding — the base a
        // proper-subset group push's partial-rollout guard needs to carry the
        // unselected slots forward.
        let artifact = ArtifactRef {
            release: rid.clone(),
            variant: VariantName::new("standard".to_string()),
            tree: test_tree_digest("tree-group"),
        };
        let slots: BTreeMap<SlotId, GenerationRef> = config
            .target_slots("t1")
            .unwrap()
            .into_iter()
            .map(|(slot, _)| {
                let slot_id =
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

                (
                    slot_id.clone(),
                    GenerationRef {
                        generation: test_generation_id(slot.id.as_str()),
                        assignment: crate::model::PlacementSlotAssignment {
                            placement_slot: slot_id.clone(),
                            artifact: artifact.clone(),
                        },
                    },
                )
            })
            .collect();
        let bindings = config.target_slot_bindings("t1").unwrap();
        seed_snapshot(
            &store,
            "t1",
            "deploy-group-base",
            "sha256-base",
            slots,
            bindings,
        );

        (dir, cfg_path, config, store, rid, group)
    }

    /// Rewrite the fixture's CURRENT config with a COMPLETE-membership
    /// mutation on target `t1` (the release record and ledger stay frozen to
    /// the original membership), and return the reloaded config.
    fn apply_group_membership_mutation(
        dir: &tempfile::TempDir,
        cfg_path: &Path,
        group_inc: [bool; 3],
        extra_inc: [bool; 3],
        mutation: MembershipMutation,
    ) -> ProjectConfig {
        let variant_path = dir
            .path()
            .join("proj")
            .join("releases")
            .join("v1")
            .join("standard.toml");
        let (phys_id, add_slot) = match mutation {
            MembershipMutation::Add => (Some("phys"), Some(("p99", "s7", "/srv/p99"))),
            MembershipMutation::Remove => (None, None),
            MembershipMutation::Rename => (Some("physX"), None),
        };
        std::fs::write(
            &variant_path,
            group_variant_string(group_inc, extra_inc, phys_id, add_slot),
        )
        .unwrap();
        ProjectConfig::load(cfg_path).unwrap()
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
            cases: 16,
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
                    group: Some(group.clone()),
                },
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
                        group: Some(group.clone()),
                    },
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

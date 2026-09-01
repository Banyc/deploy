//! THE PUSH OPERATION: the full `deploy push` transaction.
//!
//! Nested along the push phases: this module holds the push spine
//! (`push` / `push_inner` and the numbered steps), the `PushContext`
//! and the report assembly; each phase group lives in its own submodule:
//!
//! * `preflight` — the PRE-mutation phases (read-only remotes, intent
//!   persistence, capacity + staging), itself nested by phase.
//! * `execute` — the MUTATION phases (batch loop, failure policy, status
//!   decision, actual observation).
//! * `commit` — the POST-mutation phases (terminal finalization, step-17
//!   maintenance wiring, report assembly).
//! * `noop` — the "Everything up to date" no-op path.
//! * `dryrun` — the dry-run plan rendering.

use crate::config::ProjectConfig;
use crate::config::ServerDef;
use crate::deploy::plan::StagingCleanup;
use crate::deploy::plan::cleanup_dry_run_staging;
use crate::deploy::project::ValidatedProject;
use crate::error::Error;
use crate::error::Result;
use crate::identity::ArtifactRef;
use crate::identity::DeploymentId;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::identity::ReceiverUuid;
use crate::identity::SlotId;
use crate::identity::TargetName;
use crate::kernel::terminal::NonSuccessfulDisposition;
use crate::ledger;
use crate::ledger::DeploymentStatus;
use crate::ledger::LedgerIntentReport;
use crate::ledger::LedgerTerminal;
use crate::ledger::PushRef;
use crate::ledger::RefExpr;
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use crate::store::local::ledger::TargetLedgerTxn;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;

mod commit;
mod dryrun;
mod execute;
mod noop;
mod preflight;
mod prepared;

pub(crate) use commit::*;
pub(crate) use dryrun::*;
pub(crate) use execute::*;
pub(crate) use noop::*;
pub(crate) use preflight::*;
pub(crate) use prepared::*;

// ---- push spine: orchestration and numbered steps ----
// Push transaction ORCHESTRATION (A1 deployment semantics): the spine of
// the old `push::engine`. [`push`] → [`push_inner`] run the numbered
// deployment pipeline as a THIN COORDINATOR over the phases: selection
// normalization + ref parsing + locking, materialization / release identity /
// planning / capacity + staging ([`run_preflight`], [`persist_intent`]), the
// batched per-server publication + failure-policy compensation (with the
// batch loop and status derivation in [`crate::deploy::rollout`]), the
// commit markers / status decision, and the terminal finalization +
// observed-refresh + step-17 maintenance ([`crate::deploy::maintenance`]).
// The dry-run branch renders its plan via [`render_dry_run_plan`]; the
// behavior-coverage gate lives in [`crate::deploy::plan`].
//
// This section keeps only the genuinely-orchestration pieces: [`push`], the
// test-only entry points ([`push_with_id`], [`push_ref_with_id`]), the
// [`slot_vars`] template helper (consumed by [`crate::deploy::rollout`]), the
// shared [`PushContext`] the phase functions take, and the ordering test
// (`clean_push_transition_sequence_and_outcomes`). The pre-mutation phases
// (preflight), the mutation phases (execute) and the post-mutation phases
// (commit) follow in their own sections below; the shared test fixtures live
// in [`crate::deploy::testsupport`].

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

pub(crate) type RemoteFactory =
    dyn Fn(&crate::config::ServerDef, &crate::config::SlotConfig) -> Result<Box<dyn Remote>>;

/// The full push operation as a shared context: every input the phase modules
/// ([`crate::deploy::push`], [`crate::deploy::push`],
/// [`crate::deploy::push`]) consume, bundled so the phase functions have
/// clean signatures. [`push_inner`] constructs it from its own parameters
/// and hands it down.
pub(crate) struct PushContext<'a> {
    pub(crate) project_root: &'a Path,
    pub(crate) store: &'a LocalStore,
    pub(crate) factory: &'a RemoteFactory,
    pub(crate) target_name: &'a str,
    pub(crate) selection: &'a crate::deploy::plan::SlotSelection,
    pub(crate) ref_expr: &'a RefExpr,
    /// The PRE-RESOLVED ref: `Some` for a dry run (resolved by [`push`]
    /// before any lock or remote factory invocation); `None` for a real push,
    /// which resolves at the post-reconciliation resolution point inside
    /// [`run_preflight`].
    pub(crate) resolved: Option<PushRef>,
    pub(crate) deployment_id: &'a DeploymentId,
    pub(crate) op_id: &'a OperationId,
    pub(crate) config: &'a ProjectConfig,
    pub(crate) target: &'a crate::config::TargetConfig,
    pub(crate) opts: &'a PushOptions,
}

/// Build the template context for one placement slot from the ARTIFACT being
/// processed: `release`/`variant`/`tree` are the assigned artifact's own
/// immutable `ReleaseId`, `VariantName`, and `TreeDigest` — never the caller's
/// current release name — so a historical/rollback push renders the release id
/// it actually deploys, and a template never sees a torn (desired-variant,
/// current-release) combination. Compensation overrides the five
/// deployment-scoped values again with the PRIOR assignment via
/// [`crate::remote::canonical::TemplateVars::with_assignment`]: the prior artifact's
/// release/variant/tree AND the prior deployment identity
/// (`deployment_id`/`generation`) move together.
///
/// `deployment_id`/`generation` are the per-deployment identity, available
/// only in the per-server activation/verification path; sites that do not know
/// them (e.g. the reconciliation loop) pass `None`, and a template referencing
/// such a variable there fails loudly.
/// The slot's template variables — DERIVED from the VALIDATED PROJECT's
/// typed topology (the slot's owner target — never a re-parsed target
/// string), the slot's declared transport server (config connection
/// metadata, never topology), and the OPEN REMOTE's root (the deploy_dir
/// the remote was opened against — no raw path is re-parsed from a config
/// slot view). `slot_vars` consumes the executed slot by id from the ONE
/// topology map; a slot missing from it is an internal error.
//
// 8 parameters: the full per-slot template context (topology: project,
// slot_id; transport: servers, remote_root; identity: config, artifact;
// deployment: deployment_id, generation); bundling them would hide the
// derivation contract this signature enforces, so the allow documents the
// deliberate choice (mirrors `process_server` / `check_up_to_date`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn slot_vars(
    project: &ValidatedProject,
    servers: &BTreeMap<SlotId, &ServerDef>,
    remote_root: &Path,
    config: &ProjectConfig,
    slot_id: &SlotId,
    artifact: &ArtifactRef,
    deployment_id: Option<&DeploymentId>,
    generation: Option<&GenerationId>,
) -> Result<crate::remote::canonical::TemplateVars> {
    let slot = project.slot(slot_id).ok_or_else(|| {
        Error::internal(format!(
            "slot '{}' is not part of the validated project topology",
            slot_id.as_str()
        ))
    })?;
    let server = servers.get(slot_id).ok_or_else(|| {
        Error::internal(format!(
            "slot '{}' has no declared server in the config",
            slot_id.as_str()
        ))
    })?;
    Ok(crate::remote::canonical::TemplateVars::slot(
        remote_root,
        artifact.variant.as_str(),
        config.application().as_str(),
        artifact.release.as_str(),
        slot.owner().as_str(),
        server.id.as_str(),
    )
    .with_server(server.user(), server.address(), server.port())
    .with_slot_id(slot_id.as_str())
    .with_deployment(deployment_id, generation, Some(&artifact.tree)))
}

/// Run a push against `target_name`.
///
/// Dry-run gating: `opts.dry_run` short-circuits every mutating stage of
/// `push_inner` — no local or remote locks, no handshake or recovery, no
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
        crate::deploy::plan::SlotSelection::normalize(config, target_name, opts.group.as_deref())?;

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
        Some(t) => ledger::parse_ref_expr(t)?,
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
        Some(ledger::resolve_ref_expr(&ref_expr, target_name, store)?)
    } else {
        None
    };

    // 1c. DIRECT-RELEASE MEMBERSHIP GATE — BOTH modes, immediately after the
    // ref is parsed/resolved and BEFORE any lock, any factory invocation
    // (the gate lives in [`gate_direct_release_membership`],
    // which compares the release's frozen slot set against the target's
    // COMPLETE current membership — never the group-filtered selection).
    gate_direct_release_membership(store, config, target_name, &ref_expr)?;

    // 2. Acquire local application-store lock then the TARGET LEDGER
    //    TRANSACTION (in that order — the txn's `open` acquires the target
    //    `operation.lock` AND folds the ledger state; see
    //    [`acquire_locks`] for the durable target-directory pre-creation
    //    and the dry-run no-lock rule). The txn is the ONLY ledger write
    //    surface for the whole push: every intent/terminal write happens
    //    through it under the target lock. The guards drop here (releasing
    //    the advisory lock and the txn's target lock) regardless of how
    //    `push_inner` resolves.
    let (local_guard, mut txn) = acquire_locks(store, target_name, &op_id, opts.dry_run)?;

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
        &mut txn,
    );

    drop(txn);
    drop(local_guard);
    result
}

/// Test-only entry point: drive [`push_inner`] for a HEAD push with a
/// caller-supplied deployment id, so the state-machine / fault-matrix tests
/// can arm the one-shot store faults (keyed by deployment id) BEFORE the push
/// runs. Mirrors the recovery tests' `push_main_with_id`; exposed crate-wide
/// for the [`crate::semantic_invariants`] fixture. Same as [`push`] minus the
/// LOCAL application-store lock acquisition (irrelevant to the fault
/// matrix); the TARGET ledger transaction is still opened (every write goes
/// through the locked txn).
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
        crate::deploy::plan::SlotSelection::normalize(config, target_name, opts.group.as_deref())?;
    let txn = TargetLedgerTxn::open(store, target_name, op_id.as_str())?;
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
        &mut Some(txn),
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
        Some(t) => ledger::parse_ref_expr(t)?,
        None => RefExpr::Head,
    };
    let selection =
        crate::deploy::plan::SlotSelection::normalize(config, target_name, opts.group.as_deref())?;
    let txn = TargetLedgerTxn::open(store, target_name, op_id.as_str())?;
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
        &mut Some(txn),
    )
}

// The 12 parameters are the full push operation (data: project_root, store,
// factory, target_name, ref_expr, deployment_id, op_id; policy: config,
// target, opts). The `config` + `opts` pair is already the settings half,
// and `target`/`project_root` are derived views of it. Bundling all three
// policy args into one settings struct is a dedicated refactor (deferred: it
// would touch every internal `config`/`target`/`opts` reference in the
// body with no behavioral gain), so the allow documents the deliberate
// choice rather than a band-aid. [`PushContext`] is the shared bundle the
// PHASE modules receive; this signature stays put so the test entry points
// drive the spine unchanged.
#[allow(clippy::too_many_arguments)]
pub(crate) fn push_inner<'a>(
    project_root: &Path,
    store: &'a LocalStore,
    factory: &RemoteFactory,
    target_name: &str,
    selection: &crate::deploy::plan::SlotSelection,
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
    // THE TARGET LEDGER TRANSACTION — the push's ONLY ledger write surface
    // (owns the target `operation.lock` + the folded state): `Some` for a
    // real push (opened by [`push`] / the test entry points), `None` for a
    // dry run (which touches nothing and opens no txn).
    txn: &mut Option<TargetLedgerTxn<'a>>,
) -> Result<PushReport> {
    // The shared context the phase modules consume (see [`PushContext`]).
    let ctx = PushContext {
        project_root,
        store,
        factory,
        target_name,
        selection,
        ref_expr,
        resolved,
        deployment_id,
        op_id,
        config,
        target,
        opts,
    };
    // Dry-run staging is disposable. The guard's Drop removes the whole
    // `dry-<deployment>` tree (on error, `?`, or unwind); the guard must
    // outlive the pre-mutation phases because the dry-run branch below
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
    // The open per-slot remotes/helpers/statuses are filled by the preflight
    // phases and outlive them (the helpers borrow the remotes, so they stay
    // in this scope rather than travelling inside
    // [`PreflightOutcome`]).
    let mut remotes: HashMap<SlotId, Box<dyn Remote>> = HashMap::new();
    let mut helpers: HashMap<SlotId, RemoteHelper> = HashMap::new();
    let mut statuses: HashMap<SlotId, crate::remote::helper::RemoteStatus> = HashMap::new();

    // PRE-MUTATION PHASES (steps 3-9, before any `current` change) live in
    // [`crate::deploy::push`]: the read-only remote construction +
    // status ([`open_remotes`](open_remotes) /
    // [`inspect_remotes`](inspect_remotes)),
    // materialization + release identity, reconciliation + ref resolution,
    // the behavior index, plan construction, the partial-rollout + coverage
    // guards, the mutating remote prep (phase B), and the per-slot plan /
    // pre-push observation tables.
    open_remotes(&ctx, &mut remotes)?;
    inspect_remotes(&ctx, &remotes, &mut helpers, &mut statuses)?;
    let preflight = run_preflight(&ctx, txn, &remotes, &helpers, &statuses)?;

    // ---- Dry-run: read-only planning, no mutation of store/remote/locks -----
    if opts.dry_run {
        // The dry-run PLAN RENDERING is a PROJECTION of the prepared
        // deployment: the intent is built (read-only — nothing is
        // persisted) and the per-slot current -> desired lines, the
        // would-recover notes, and the first-deployment line are rendered
        // from the intent's assignments + generations projections. A dry
        // run must never contact a remote, acquire a lock, or persist
        // anything — the render is pure plan data.
        let prepared = PreparedDeployment::new(
            build_intent(&ctx, &preflight, None)?,
            preflight.behavior_index.clone(),
        )?;
        let msg = prepared.plan_rendering(store, &statuses);
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

    // THE VALIDATED PROJECT — the ONE authoritative, typed, canonical,
    // DISJOINT provisioned topology of the EXECUTED members (the structural
    // verdict's point 1): constructed from the config's slot declarations,
    // the MANDATORY provisioned receivers (read from the provisioned
    // remotes after phase B), and the store's SEALED [`OwnedRoot`]. A
    // selected slot whose deploy_dir carries no receiver UUID is REFUSED
    // here (fail closed — the old silent bare-binding fallback in the
    // intent is gone: an intent can never be persisted with an unknown
    // physical identity). The mutation + commit phases consume ONLY this
    // topology — never a re-parse of the config's slot views.
    let target_typed = TargetName::parse(target_name).expect("target name is a safe segment");
    let selected_ids: Vec<SlotId> = preflight
        .assignments
        .iter()
        .map(|a| a.placement_slot.clone())
        .collect();
    let provisioned_receivers: BTreeMap<SlotId, ReceiverUuid> = preflight
        .receiver_uuids
        .iter()
        .map(|(sid, r)| {
            let r = r.as_ref().ok_or_else(|| {
                Error::preflight(format!(
                    "slot '{sid}' has no provisioned receiver UUID — the deploy_dir was never provisioned (or was provisioned before the receiver-UUID feature); refusing to build the provisioned topology"
                ))
            })?;
            Ok((sid.clone(), r.clone()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let project = ValidatedProject::for_selected(
        ctx.config,
        &target_typed,
        &selected_ids,
        &provisioned_receivers,
        ctx.store.owned_root_for_project()?,
    )?;
    // The TRANSPORT declarations of the executed slots: the config-driven
    // slot → server connection metadata (id/user/address/port) the template
    // variables and the observed records resolve — connection config, never
    // topology (the topology itself is the validated project above).
    let servers: BTreeMap<SlotId, &ServerDef> = config
        .target_slots(target_name)?
        .into_iter()
        .map(|(slot, server)| {
            (
                SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment"),
                server,
            )
        })
        .collect();

    // Early "Everything up to date" check for HEAD pushes, run BEFORE
    // persisting any plan/status record so an up-to-date no-op leaves no
    // dangling `in_progress` deployment behind. The detection (complete
    // ArtifactRef equality + per-slot verification rendering the EXISTING
    // generation's identities) and the no-op path's hidden maintenance
    // wiring (A7) live in [`crate::deploy::push`].
    if let Some(report) = check_up_to_date(
        &preflight.pref,
        store,
        config,
        target_name,
        &project,
        &servers,
        &preflight.assignments,
        &statuses,
        &helpers,
        &remotes,
        &preflight.behavior_index,
        op_id,
        deployment_id,
    )? {
        return Ok(report);
    }

    // PERSIST THE ATTEMPT INTENT BEFORE ANY REMOTE MUTATION: the intent
    // record is the IMMUTABLE INTENT of the deployment (deployment_id,
    // target, membership, behavior digest, attempted_at, the planned
    // (`desired`) generations, and the observed pre-push state). It must be
    // durable BEFORE any server's `current`/generation changes, so a crash
    // can never lose a deployment whose servers already advanced. The
    // record carries NO outcomes — the actual per-slot outcomes and the
    // status live in the deployment's TERMINAL EVENT. See
    // [`persist_intent`].
    let txn = txn
        .as_mut()
        .expect("a real push opens the target ledger txn");
    // PERSIST THE ATTEMPT INTENT BEFORE ANY REMOTE MUTATION and RETAIN the
    // SEALED PREPARED DEPLOYMENT: the intent record is the IMMUTABLE INTENT
    // of the deployment (deployment_id, target, membership, behavior
    // digest, attempted_at, the planned (`desired`) generations, and the
    // observed pre-push state). It must be durable BEFORE any server's
    // `current`/generation changes, so a crash can never lose a deployment
    // whose servers already advanced. The record carries NO outcomes — the
    // actual per-slot outcomes and the status live in the deployment's
    // TERMINAL EVENT. The mutation + commit phases consume ONLY the
    // prepared deployment's PROJECTIONS (never the preflight outcome). See
    // [`persist_intent`].
    let prepared = persist_intent(&ctx, txn, &preflight, &project)?;

    // 8 & 9. Capacity + staging preflight — capacity is the caller's CURRENT
    // per-server policy; every failure ends the attempt `FailedPreflight`
    // (see [`run_capacity_and_staging`]).
    if let Err(failure) = run_capacity_and_staging(
        store,
        &preflight.assignments,
        &helpers,
        op_id,
        deployment_id,
        config,
    ) {
        // FailedPreflight terminal (empty outcomes — no slot was touched) +
        // best-effort incoming cleanup, then the ORIGINAL error. The engine
        // NEVER constructs terminal variants itself — [`decide_terminal`]
        // owns the truth table, so the preflight-failure path routes through
        // it with the intent, exactly like every other disposition.
        let disposition = crate::kernel::transition::decide_terminal(
            prepared.intent(),
            crate::kernel::transition::ExecutionReport::PreflightFailed,
        )
        .map_err(|e| {
            Error::integrity(format!(
                "push {deployment_id}: the kernel refused the preflight-failure disposition: {e}"
            ))
        })?;
        // Best-effort incoming cleanup runs FIRST (the partial staging upload
        // is disposable — the review keeps it best-effort), then THE
        // TERMINAL-APPEND FAILURE IS PROPAGATED (the review's P1 fix — a
        // swallowed preflight-append failure can no longer exist): when the
        // FailedPreflight terminal append fails, the attempt stays
        // intent-only (recoverable-pending — a later push's recovery settles
        // it through [`crate::ledger::recovery`]) and THIS push surfaces the
        // append failure instead of silently continuing and returning the
        // original preflight error as if the attempt had settled. The caller
        // must see the persistence boundary failed.
        for a in &preflight.assignments {
            helpers[&a.placement_slot]
                .remove_incoming(deployment_id)
                .ok();
        }
        txn.append_terminal(
            deployment_id,
            &LedgerTerminal::new(
                crate::remote::helper::now_rfc3339_ts(),
                crate::kernel::terminal::intent_digest(prepared.intent()),
                NonSuccessfulDisposition::from_decision(disposition),
                Some(failure.reason.to_string()),
            ),
        )?;
        return Err(failure.source);
    }

    // MUTATION PHASES (steps 10-15) in [`crate::deploy::push`]: the
    // deployment-order batch loop, the failure-policy compensation + status
    // derivation, the commit-marker / status decision, and the post-mutation
    // ACTUAL observation. The execution consumes ONLY the prepared
    // deployment's PROJECTIONS — the intent is the single source of truth;
    // nothing is re-derived from the preflight outcome.
    let execution = run_execution(
        &ctx,
        &prepared,
        &project,
        &servers,
        &remotes,
        &helpers,
        &preflight.bundles,
    )?;

    // POST-MUTATION PHASES (steps 16-17) in [`crate::deploy::push`]: the
    // terminal event finalization (successful finalizer / plain terminal
    // append), the observed refresh + step-17 maintenance, and the report
    // assembly.
    run_commit(
        &ctx, txn, &prepared, &execution, &project, &servers, &helpers,
    )
}

#[cfg(test)]
pub(crate) mod push_tests {
    use crate::deploy::testsupport::*;
    use crate::identity::test_deployment_id;

    /// The ORDERING test: a clean successful push appends exactly ONE
    /// terminal event (`Successful`) in the deployment order, with the
    /// outcomes separation under the new model — the persisted intent line
    /// carries NO outcomes AND the Successful terminal is PAYLOAD-FREE (the
    /// resulting snapshot resolves from the intent's own slot table, never
    /// from a duplicated outcome payload).
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
        assert_eq!(transitions[0].reason(), Some("push completed"));

        // Outcomes separation: the Successful terminal carries NO per-slot
        // outcome rows (payload-free — the disposition only says the
        // planned result was achieved), and the persisted intent line also
        // keeps none (the report's `slots` actuals stay empty).
        let results = h.store.read_results(id.as_str()).unwrap();
        assert!(
            results.is_empty(),
            "a Successful terminal is payload-free — no per-slot outcome row"
        );
        let attempt = single_attempt(&h);
        assert!(
            attempt.slots.is_empty(),
            "the recovered report carries no outcomes (the ledger intent line keeps them empty)"
        );

        // The snapshot IS the intent's planned result (derived on demand,
        // never stored in any terminal payload): its per-slot generation
        // equals the report's observed actual generation, and its artifact
        // equals the observed assignment.
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        let snap = &snapshots[0];
        let actual = &r.attempt.as_ref().unwrap().slots[&SlotId::new("p1")];
        let rollback = rollback_of(snap);
        let snap_p1 = rollback.get(&SlotId::new("p1")).unwrap();
        assert_eq!(
            snap_p1.generation().clone(),
            known_generation(actual).clone(),
            "the snapshot's generation equals the observed actual generation"
        );
        assert_eq!(
            snap_p1.artifact().clone(),
            known_artifact(actual).clone(),
            "the snapshot's artifact equals the observed assignment"
        );
    }
}

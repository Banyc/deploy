//! Checkpoint: retain one target's history suffix and sweep the unreachable
//! rest.
//!
//! Moved from `crate::push::checkpoint` during the encapsulation restructure;
//! the ledger / history-floor primitives live in
//! [`super::reachability::history_floor`] and the sweep-debt orchestration in
//! `debt`.
//!
//! `deploy checkpoint <target> <deployment-id>` compacts the target's ONE
//! deployment LEDGER (`targets/<target>/ledger.jsonl`) to the retained
//! suffix at/after the checkpoint deployment — the floor is IMPLICIT: the
//! ledger's first entry is the oldest retained rollback state, there is NO
//! separate floor marker — and then best-effort sweeps the globally
//! unreachable deployment directories, release records, and tree objects.
//! The checkpoint deployment must be a SUCCESSFUL deployment of the target
//! (its ledger entry carries a `Successful` terminal event with a rollback
//! state); its entry becomes the ledger's first (oldest) entry. Everything
//! strictly before it — older entries, failed attempts included, and their
//! `deployments/<id>/` directories — is discarded. The operation is
//! IRREVERSIBLE: the CLI requires `--yes` (or `--dry-run` to preview the
//! exact discard list) and an explicit deployment id.
//!
//! # The three steps (the only commit is the atomic replacement)
//!
//! 1. CALCULATE THE RETAINED SUFFIX (`LocalStore::ledger_suffix`): every
//!    physical ledger line from the checkpoint entry's intent line onward.
//! 2. ATOMICALLY REPLACE the ledger with that suffix
//!    (`LocalStore::write_ledger_suffix`: temp + fsync + chmod-private +
//!    rename + parent-dir fsync). The replace reports its TWO COMMIT
//!    POINTS explicitly ([`crate::store::atomic::ReplaceOutcome`]): the
//!    RENAME (the truncated ledger becomes VISIBLE) and the
//!    PARENT-DIRECTORY FSYNC (it becomes DURABLE across power loss). THIS is
//!    the checkpoint's ONLY logical commit: a reader never observes a torn
//!    ledger (wholly old or wholly new). A FAILURE BEFORE THE RENAME (temp
//!    write/sync/rename) means NO DELETION HAPPENS — the checkpoint is a
//!    plain `Err` and the full history stands untouched. A FAILURE OF THE
//!    PARENT-DIRECTORY FSYNC AFTER THE RENAME is NOT a checkpoint `Err`: the
//!    truncated ledger IS visibly committed, so the checkpoint returns a
//!    STRUCTURED report (`established: true`) carrying a DURABILITY WARNING
//!    and DEFERRING the sweep — no deletion is ever attempted against a
//!    floor whose durability is unconfirmed, and the owed sweep is recorded
//!    as the TYPED [`crate::store::local::debt::SweepDebt::AwaitingCheckpointDurability`]
//!    marker (see
//!    step 3) so the push-side sweep runner REFUSES to sweep until the
//!    ledger is durably rewritten. ONCE THE REPLACE IS DURABLE
//!    (or the unknown-durability report is made), the checkpoint cannot
//!    return `Err` for any post-commit maintenance failure (scan,
//!    enumeration, deletion, or the debt-marker write): each is converted
//!    into a report with `established: true`, `sweep_completed: false`, and
//!    a warning (see step 3).
//! 3. BEST-EFFORT GLOBAL SWEEP (`LocalStore::run_sweep`) of unreachable
//!    deployment directories (`deployments/<id>/`), release records
//!    (`releases/<release-id>/`), and tree objects
//!    (`objects/sha256/<digest>/`). The sweep builds ONE locked
//!    reachability snapshot (`LocalStore::reachability_snapshot`) — every
//!    root source read ONCE and frozen — and every deletion stage consumes
//!    ONLY that snapshot's retained sets: no stage re-reads a source that
//!    could drift. The scan
//!    is recomputed FRESH on every retry and keeps everything reachable
//!    from ANOTHER target's ledger, the current/incomplete state (observed
//!    artifacts, pending intent-only entries, in-flight deployment dirs),
//!    or a PIN. A failed sweep is retried by RECOMPUTING reachability — no
//!    persisted deletion worklist, no backup — and an incomplete sweep
//!    records a DURABLE, TYPED SWEEP-DEBT marker ("<base>/sweep-debt.json"):
//!    [`crate::store::local::debt::SweepDebt::Ready`] when
//!    the ledger commit was durable (the sweep may run on a later push),
//!    [`crate::store::local::debt::SweepDebt::AwaitingCheckpointDurability`] when the commit's
//!    durability is unconfirmed (the sweep is gated until the
//!    durability-confirming rewrite). The marker is TRIAGE-ONLY — it decides
//!    HOW the next push's reconciliation proceeds, never WHETHER it runs:
//!    every push (real and no-op) reconciles regardless of any marker, so a
//!    missing or failed marker write can never skip the owed maintenance
//!    forever. Sweeps are best-effort and NOT secure erasure.
//!
//! # Preview == execution (the ledger override)
//!
//! The sweep's reachability is computed against the checkpointed target's
//! ledger AS-IF the suffix replacement ALREADY happened (`LedgerOverride`):
//! the pre-checkpoint history's releases, trees, and deployment dirs are
//! unreachable the MOMENT the ledger is shortened. The flow computes the
//! retained suffix ONCE and feeds the parsed suffix as the override to BOTH
//! the dry-run preview and the real execution — the preview (touch nothing)
//! and the real command (atomic replacement + sweep) share the SAME
//! reachability calculation, so the previewed deletion sets EXACTLY match
//! what the real command deletes. (Without the override the preview would
//! scan the CURRENT ledger, where the pre-checkpoint entries are still
//! present, and under-report the artifacts that only become garbage after
//! the replacement.)
//!
//! The old multi-file checkpoint machinery — the `history-floor.json` marker,
//! the transactional floor ADVANCE with its tagged `.prev.<tag>` backups,
//! restore/recovery of torn advances, the tri-state marker discovery, and
//! the `cleanup-pending.json` debt flag with its three report flags — is
//! GONE: the atomic ledger replacement is the only logical commit, and the
//! report carries at most the commit status + durability (confirmed or
//! unconfirmed) + sweep completed / retry-required (plus the sweep-debt
//! warning when the marker could not be persisted).
//!
//! # Concurrency
//!
//! The real operation runs under the SAME lock discipline as pushes
//! (`crate::deploy::lock::FileLock`): the application-store lock then the
//! target lock, both advisory (flock) and released on drop. The checkpoint
//! itself NEVER opens a remote: it is local-only by construction. A
//! `--dry-run` preview takes NO locks, writes NOTHING, and enumerates
//! exactly what the replacement + sweep would discard.

use crate::config::ProjectConfig;

// The sweep-debt orchestration for the checkpoint's post-commit sweep
// (retry-required marker / clear on completion).
pub(crate) mod debt;

use crate::deploy::lock::FileLock;
use crate::error::Result;
use crate::identity::{DeploymentId, OperationId, TargetName};
use crate::retention::reachability::history_floor::{LedgerDiscards, LedgerOverride};
use crate::store::atomic::ReplaceOutcome;
use crate::store::local::LocalStore;
use crate::store::local::ledger::TargetLedgerTxn;

/// The outcome of one checkpoint invocation (preview or real).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointReport {
    pub target: String,
    /// THE KEY: the checkpoint deployment. Its POSITION in the ledger
    /// (derived, never stored) is the retained suffix's start — the floor is
    /// implicit: everything strictly before it is discarded.
    pub deployment_id: DeploymentId,
    /// Exactly what was / would be discarded: the entries dropped from the
    /// ledger by the suffix replacement plus the sweep's PLANNED candidate
    /// sets and the counts ACTUALLY unlinked (see [`LedgerDiscards`] — the
    /// preview reports the planned sets; the execution reports removed +
    /// pending).
    pub discards: LedgerDiscards,
    /// True when this call performed the LOGICAL COMMIT (the atomic ledger
    /// replacement); false for dry-run previews.
    pub established: bool,
    /// True when the best-effort sweep ran all three stages clean; false
    /// means the sweep is RETRY-REQUIRED — a durable sweep-debt marker was
    /// recorded and the next push (or a re-run of the same checkpoint)
    /// recomputes reachability fresh and finishes it.
    pub sweep_completed: bool,
    /// THE EXPLICIT POST-COMMIT BOUNDARY WARNING: a sweep READ/DELETION
    /// failure that surfaced AFTER the irreversible ledger replacement
    /// committed (the reachable-set scan, the directory enumeration, or a
    /// deletion stage) is converted into this warning — `established` stays
    /// `true`, `sweep_completed` is `false`, and the sweep is retry-required
    /// (the durable sweep-debt marker records it; the next push — or a
    /// re-run — recomputes reachability fresh). The checkpoint NEVER returns
    /// `Err` for a post-commit sweep failure; this field carries the reason.
    /// `None` when the sweep ran without a post-commit error (a
    /// merely-incomplete sweep is reported via `sweep_completed` + the
    /// renderer's retry line, not here).
    pub sweep_warning: Option<String>,
    /// THE DURABILITY WARNING (the second commit boundary): the ledger
    /// replacement's RENAME happened — the shortened suffix IS visibly the
    /// ledger, `established` is `true` — but the PARENT-DIRECTORY FSYNC
    /// failed (commit point 2), so the commit's DURABILITY IS UNCONFIRMED.
    /// The checkpoint NEVER deletes against an unconfirmed floor: no
    /// reachability scan and no sweep ran, the owed sweep is recorded as
    /// durable sweep-debt (deferred until a repeated checkpoint
    /// re-establishes durability or the next push), and this field carries
    /// the reason. DISTINCT from `sweep_warning` — which describes a
    /// failure AFTER a durable commit — this describes a commit whose
    /// rename stands but whose durability was never confirmed; the CLI
    /// surfaces it so an operator knows the ledger IS short while its
    /// durability is outstanding. `None` when durability was confirmed.
    pub durability_warning: Option<String>,
    /// Warning about the sweep-debt marker I/O when the sweep did not
    /// complete (the marker could not be persisted). Post-commit
    /// maintenance: a debt write failure is a warning, never an `Err` — the
    /// checkpoint's logical commit stands either way. `None` when the sweep
    /// completed or the marker was recorded cleanly.
    pub sweep_debt_warning: Option<String>,
    /// True when the operation ran read-only (`--dry-run`): no locks, no
    /// writes, no replacement, no sweep.
    pub dry_run: bool,
}

/// Establish (or preview) a checkpoint on `target` at `deployment_id`: the
/// ledger is atomically replaced with the retained suffix (the only logical
/// commit), then the global unreachable-content sweep runs best-effort.
pub fn run_checkpoint(
    store: &LocalStore,
    config: &ProjectConfig,
    target: &str,
    deployment_id: &DeploymentId,
    dry_run: bool,
) -> Result<CheckpointReport> {
    if dry_run {
        return preview_checkpoint(store, config, target, deployment_id);
    }
    let op_id = OperationId::generate();
    let local_guard = FileLock::acquire(&store.base().join("operation.lock"), op_id.as_str())?;
    // THE TARGET LEDGER TRANSACTION: the txn acquires the target
    // `operation.lock` (durably pre-creating the target directory BEFORE
    // the lock — the reported bug's durable first-append machinery — and
    // folding the ledger state) and is the ONLY ledger write surface: the
    // checkpoint's atomic suffix replacement runs THROUGH it (see
    // [`TargetLedgerTxn::write_suffix`]).
    let mut txn = TargetLedgerTxn::open(store, target, op_id.as_str())?;
    let result = checkpoint_inner(store, config, target, deployment_id, &mut txn);
    // The guards drop here, releasing both advisory locks regardless of how
    // `checkpoint_inner` resolves.
    drop(txn);
    drop(local_guard);
    result
}

/// Test-only entry point: drive [`checkpoint_inner`] for a REAL checkpoint
/// through a fresh [`TargetLedgerTxn`] (the txn's target `operation.lock`
/// acquisition is the ONLY lock this entry takes — mirroring the fixture's
/// push entry points ([`crate::deploy::push_with_id`], which skip the LOCAL
/// application-store lock the same way). The state-machine fixture is
/// single-threaded, so the flock adds only I/O; the validation, the atomic
/// ledger replacement (the logical commit), and the full sweep path run
/// UNMODIFIED.
#[cfg(test)]
pub(crate) fn run_checkpoint_unlocked(
    store: &LocalStore,
    config: &ProjectConfig,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    let mut txn = TargetLedgerTxn::open(store, target, "test-checkpoint")?;
    checkpoint_inner(store, config, target, deployment_id, &mut txn)
}

/// Build the checkpoint's NEW ledger payload: the checkpoint EVENT line
/// (the record of the discarded prefix) followed by the retained suffix
/// lines. Shared by the checkpoint and the durability-confirming retry —
/// the retry recomputes the retained suffix deterministically, so the
/// rewritten ledger's retained content is identical to the visible ledger's
/// whenever the ledger is still the trigger-time one (and the CURRENT
/// suffix when another push appended).
fn checkpoint_ledger_payload(
    deployment_id: &DeploymentId,
    discarded: usize,
    suffix: &[String],
) -> Result<Vec<String>> {
    let checkpoint_line = serde_json::to_string(&crate::ledger::LedgerEventWire::Checkpoint(
        crate::ledger::CheckpointWire::new(
            deployment_id,
            discarded as u64,
            &crate::remote::helper::now_rfc3339(),
        ),
    ))
    .map_err(|e| crate::error::Error::store(format!("serialize ledger checkpoint: {e}")))?;
    let mut new_ledger = vec![checkpoint_line];
    new_ledger.extend(suffix.iter().cloned());
    Ok(new_ledger)
}

/// The real (locked) checkpoint: compute the retained suffix, ATOMICALLY
/// replace the ledger with it (the ONLY logical commit — a pre-rename
/// failure is a plain `Err`, nothing was deleted, the full history stands;
/// a post-rename parent-dir-fsync failure is a STRUCTURED report with the
/// commit established and durability unconfirmed), then run the best-effort
/// global sweep. A repeated checkpoint of the same deployment recomputes
/// the SAME suffix (the ledger already IS it — the replacement is an
/// identical rewrite) and re-runs the sweep to convergence.
///
/// # The TWO COMMIT POINTS — the EXPLICIT COMMIT BOUNDARY
///
/// The ledger replace has TWO commit points and the checkpoint reports them
/// explicitly ([`crate::store::atomic::ReplaceOutcome`]):
///
/// * `Err` — the RENAME never happened (a pre-rename failure): nothing is
///   committed, the full history stands, no deletion.
/// * [`crate::store::atomic::ReplaceOutcome::ReplacedDurable`] — the rename
///   happened AND the parent-directory fsync succeeded: the truncated
///   ledger is visible and durable, and the checkpoint is IRREVERSIBLY
///   committed. From this point on it CANNOT return `Err`: the sweep (the
///   reachable-set scan, the directory enumeration, the three deletion
///   stages) and the sweep-debt marker are POST-COMMIT MAINTENANCE, and
///   every failure of theirs is converted into a report with
///   `established: true`, `sweep_completed: false`, and a warning (see
///   [`CheckpointReport::sweep_warning`]).
/// * [`crate::store::atomic::ReplaceOutcome::ReplacedDurabilityUnknown`] —
///   the rename happened (the truncated ledger IS visibly committed:
///   `established: true`) but durability is UNCONFIRMED. The checkpoint
///   NEVER deletes against it (no reachability scan, no sweep — a sweep
///   against a floor whose durability is unconfirmed could let an
///   interrupted retry expose history below the floor): it records the owed
///   sweep as durable sweep-debt and returns a structured report with a
///   DURABILITY WARNING and `sweep_completed: false`. A repeated checkpoint
///   of the same deployment rewrites the SAME suffix — on retry it obtains
///   [`crate::store::atomic::ReplaceOutcome::ReplacedDurable`] and the
///   sweep runs to convergence.
///
/// Only the suffix computation and a PRE-RENAME replacement failure return
/// `Err` (nothing was committed).
fn checkpoint_inner(
    store: &LocalStore,
    config: &ProjectConfig,
    target: &str,
    deployment_id: &DeploymentId,
    txn: &mut TargetLedgerTxn<'_>,
) -> Result<CheckpointReport> {
    // The TYPED sweep-debt marker carries the checkpoint's validated target
    // identity; parse it UP FRONT (pre-commit — an invalid target name fails
    // the checkpoint before any state change, exactly as a missing ledger
    // would).
    let target_name = TargetName::parse(target)?;
    // 1. Calculate the retained suffix (the physical LINES for the atomic
    //    replacement + the SAME suffix parsed as entries) and the entries it
    //    discards.
    let (suffix, suffix_entries, discarded_entries) = store.ledger_suffix(target, deployment_id)?;
    // THE SHARED LEDGER OVERRIDE: the checkpointed target's ledger as-if the
    // suffix replacement already happened. Computed ONCE here and fed to the
    // sweep in BOTH paths — the dry-run preview and this real execution use
    // the SAME reachability, so the previewed deletion sets are exactly the
    // real ones (the artifacts that become garbage only when the ledger is
    // shortened are enumerated by the preview too).
    let ledger_override = LedgerOverride {
        target: target.to_string(),
        entries: suffix_entries,
    };
    // 2. THE LOGICAL COMMIT: atomically replace the ledger with the
    //    CHECKPOINT EVENT + the retained suffix — the checkpointed ledger's
    //    FIRST line is the checkpoint event (the record of the discarded
    //    prefix), then the retained suffix lines. THE REPLACEMENT RUNS
    //    THROUGH THE TXN ([`TargetLedgerTxn::write_suffix`] — the ONLY way
    //    a checkpoint event enters a ledger; there is no general
    //    `append_checkpoint`). If the replacement fails, NO DELETION
    //    HAPPENS — the previous ledger stands. `?` is correct here: a
    //    failed replacement is a PRE-COMMIT failure and the checkpoint
    //    returns a plain `Err`.
    let new_ledger = checkpoint_ledger_payload(deployment_id, discarded_entries.len(), &suffix)?;
    // 2. THE LOGICAL COMMIT — the replace reports its TWO COMMIT POINTS
    //    (the rename → the truncated ledger becomes VISIBLE; the
    //    parent-directory fsync → it becomes DURABLE) explicitly, so the
    //    checkpoint can distinguish "the rename never happened" (a plain
    //    `Err` from [`TargetLedgerTxn::write_suffix`] — nothing
    //    committed, the full history stands) from "the rename happened but
    //    durability is unconfirmed" (the shortened ledger IS visible, so
    //    the checkpoint reports the commit as ESTABLISHED with a durability
    //    warning and DEFERS the sweep — never delete anything against a
    //    floor whose durability is unconfirmed).
    match txn.write_suffix(&new_ledger)? {
        // BOTH commit points confirmed: the new ledger is visible AND
        // durable — run the best-effort post-commit sweep as today.
        ReplaceOutcome::ReplacedDurable => {
            // 3. POST-COMMIT MAINTENANCE: the ledger commit is
            //    irreversible, so the sweep + debt marker run in the
            //    non-fallible [`run_post_commit_sweep`] — never an `Err`
            //    from this point on. The marker reconcile writes
            //    [`SweepDebt::Ready`] when the sweep stays outstanding
            //    (the floor IS durable) or clears it on completion.
            let post = run_post_commit_sweep(
                store,
                config,
                deployment_id.as_str(),
                &ledger_override,
                &target_name,
                deployment_id,
            );
            Ok(CheckpointReport {
                target: target.to_string(),
                deployment_id: deployment_id.clone(),
                discards: LedgerDiscards {
                    discarded_entries,
                    ..post.discards
                },
                established: true,
                sweep_completed: post.completed,
                sweep_warning: post.warning,
                durability_warning: None,
                sweep_debt_warning: post.debt_warning,
                dry_run: false,
            })
        }
        // COMMIT POINT 1 ONLY: the truncated ledger IS visible under its
        // final name but durability is UNCONFIRMED — NEVER attempt artifact
        // deletion (no reachability scan, no sweep, no `run_post_commit_sweep`:
        // a sweep against a floor whose durability is unconfirmed could let
        // an interrupted retry expose history below the floor). Record the
        // owed sweep as the TYPED [`SweepDebt::AwaitingCheckpointDurability`]
        // marker (best-effort — a marker write failure becomes a warning,
        // never an `Err`) so the push-side sweep runner REFUSES the sweep
        // until the durability-confirming rewrite transitions the marker to
        // `Ready` — and report the commit as ESTABLISHED with the durability
        // warning. A repeated checkpoint recomputes the SAME suffix (an
        // identical rewrite), obtains `ReplacedDurable`, and runs the sweep
        // to convergence.
        ReplaceOutcome::ReplacedDurabilityUnknown { error } => {
            let warning = format!(
                "ledger replaced for target '{target}' but its durability is unconfirmed \
                 (the parent-directory fsync failed: {error}); NO sweep ran — the sweep is \
                 deferred until a repeated checkpoint re-establishes durability or the next push"
            );
            let debt_warning = debt::record_awaiting_durability(store, &target_name, deployment_id);
            Ok(CheckpointReport {
                target: target.to_string(),
                deployment_id: deployment_id.clone(),
                discards: LedgerDiscards {
                    discarded_entries,
                    ..LedgerDiscards::default()
                },
                established: true,
                sweep_completed: false,
                sweep_warning: None,
                durability_warning: Some(warning),
                sweep_debt_warning: debt_warning,
                dry_run: false,
            })
        }
    }
}

/// The durability-confirming retry (the P1 gate): the push-side sweep
/// runner ([`crate::deploy::maintenance::retry_pending_sweep`]) calls this
/// when the sweep-debt marker is
/// [`crate::store::local::debt::SweepDebt::AwaitingCheckpointDurability`] — the sweep MUST NOT run
/// until the triggering checkpoint's ledger replace is durable, because a
/// crash could restore an OLDER, longer ledger that still references
/// below-floor history already deleted by the sweep. It recomputes the
/// CURRENT retained suffix (deterministic from the current ledger: identical
/// to the trigger-time suffix while the ledger is unchanged; the CURRENT
/// suffix if another push landed) and rewrites the ledger — the identical
/// rewrite that obtains [`ReplaceOutcome::ReplacedDurable`] (the rename AND
/// the parent-directory fsync confirmed) — then transitions the marker to
/// [`crate::store::local::debt::SweepDebt::Ready`]. It NEVER runs the sweep: the sweep executes only
/// once the marker reads `Ready` (a later maintenance pass, or a user
/// re-run). The caller (a push / no-op push) already holds the advisory
/// locks, so none are taken here — and the transition to `Ready` requires
/// EXACTLY the durable rewrite (same suffix bytes + parent-dir fsync
/// confirmed), never a bare "fsync the current bytes" shortcut that could
/// confirm the WRONG ledger state.
pub(crate) fn confirm_checkpoint_durability(
    store: &LocalStore,
    target: &TargetName,
    retained_from: &DeploymentId,
) -> Result<CheckpointDurabilityOutcome> {
    // 1. Recompute the retained suffix from the CURRENT ledger and the
    //    exact ledger payload the checkpoint would build (see
    //    [`checkpoint_ledger_payload`]).
    let (suffix, _suffix_entries, discarded_entries) =
        store.ledger_suffix(target.as_str(), retained_from)?;
    let new_ledger = checkpoint_ledger_payload(retained_from, discarded_entries.len(), &suffix)?;
    // 2. THE DURABLE REWRITE — the ONLY acceptable transition: an EXACT
    //    ledger rewrite whose rename + parent-directory fsync are BOTH
    //    confirmed (`ReplacedDurable`) is what may move the marker to
    //    `Ready`; a pre-rename failure is a plain `Err` (nothing changed,
    //    the marker stays as it is); a post-rename fsync failure keeps the
    //    floor unconfirmed and the marker `AwaitingCheckpointDurability`.
    match store.write_ledger_suffix(target.as_str(), &new_ledger)? {
        ReplaceOutcome::ReplacedDurable => {
            // 3. Transition the marker: the durable rewrite means the sweep
            //    may run — record `SweepDebt::Ready` (a marker-write failure
            //    is a warning, never an `Err`). NO sweep here.
            let debt_warning = debt::reconcile_sweep_debt(store, false, target, retained_from);
            Ok(CheckpointDurabilityOutcome::Durable { debt_warning })
        }
        ReplaceOutcome::ReplacedDurabilityUnknown { error } => {
            // The rewrite's rename stands but the fsync failed AGAIN: the
            // floor is STILL not durable — re-record the
            // `AwaitingCheckpointDurability` marker; the sweep stays refused.
            let warning = format!(
                "ledger replace for target '{target}' STILL has unconfirmed durability \
                 (the parent-directory fsync failed: {error}); the sweep stays deferred until a \
                 durability-confirming rewrite succeeds"
            );
            let debt_warning = debt::record_awaiting_durability(store, target, retained_from);
            Ok(CheckpointDurabilityOutcome::StillUnconfirmed {
                warning,
                debt_warning,
            })
        }
    }
}

/// The outcome of a durability-confirming retry
/// ([`confirm_checkpoint_durability`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointDurabilityOutcome {
    /// The rewrite confirmed BOTH commit points ([`ReplaceOutcome::ReplacedDurable`]):
    /// the ledger is DURABLE and the marker was transitioned to
    /// [`crate::store::local::debt::SweepDebt::Ready`] — the sweep may run. `debt_warning` is the
    /// marker-write warning when the transition could not be persisted.
    Durable { debt_warning: Option<String> },
    /// The rewrite's rename stands but the fsync failed again: durability is
    /// STILL unconfirmed — the marker stays
    /// [`crate::store::local::debt::SweepDebt::AwaitingCheckpointDurability`] and NO sweep may run.
    StillUnconfirmed {
        warning: String,
        debt_warning: Option<String>,
    },
}

/// Post-commit maintenance after the irreversible ledger commit: the
/// best-effort global sweep (with the SAME override the preview used) and
/// the durable sweep-debt marker. NON-FALLIBLE BY CONSTRUCTION — returns a
/// plain [`PostCommitSweep`], never `Result`; every failure surfaces as a
/// warning (or `completed: false` from `run_sweep` itself), so the caller's
/// report carries `established: true` regardless.
struct PostCommitSweep {
    discards: LedgerDiscards,
    completed: bool,
    /// A sweep failure (its READ stages) — the retry-required warning.
    warning: Option<String>,
    /// A sweep-debt marker write/clear failure.
    debt_warning: Option<String>,
}

fn run_post_commit_sweep(
    store: &LocalStore,
    config: &ProjectConfig,
    deployment_id: &str,
    ledger_override: &LedgerOverride,
    target: &TargetName,
    checkpoint_deployment: &DeploymentId,
) -> PostCommitSweep {
    // The sweep's DELETION stages are absorbed into `completed = false` by
    // `run_sweep` itself (stage faults and deletion errors); its READ stages
    // escape as `Err` and are converted here into the retry-required warning.
    let (discards, completed, warning) =
        match store.run_sweep(config, deployment_id, Some(ledger_override)) {
            Ok((sweep, complete)) => (sweep, complete, None),
            Err(e) => (
                LedgerDiscards::default(),
                false,
                Some(format!(
                    "checkpoint sweep failed after the ledger commit ({e}); the sweep is \
                 retry-required — the next push recomputes reachability fresh and finishes it"
                )),
            ),
        };
    // The DURABLE sweep-debt marker: an incomplete OR failed sweep records
    // retry-required so the NEXT PUSH recomputes reachability FRESH (no
    // persisted deletion worklist) and finishes it; a COMPLETED sweep clears
    // any stale marker. The write/clear is itself non-fallible maintenance:
    // a failure is a warning on the report, never an `Err` — the
    // orchestration lives in [`debt`]. The ledger commit is DURABLE here
    // (both commit points confirmed), so the recorded marker is the sweepable
    // [`SweepDebt::Ready`] state, never an awaiting-durability gate.
    let debt_warning = debt::reconcile_sweep_debt(store, completed, target, checkpoint_deployment);
    PostCommitSweep {
        discards,
        completed,
        warning,
        debt_warning,
    }
}

/// The read-only preview (`--dry-run`): the same validation (successful
/// deployment in the ledger) plus the exact replacement + sweep enumeration —
/// and nothing else. No locks, no replacement, no sweep, no remote.
///
/// THE PARITY FIX: the preview computes the deletion sets with the SAME
/// [`LedgerOverride`] the real execution uses — the checkpointed target's
/// ledger as-if the suffix replacement already happened — so the preview
/// enumerates EXACTLY what the real command deletes (including the
/// artifacts that become unreachable only when the ledger is shortened).
fn preview_checkpoint(
    store: &LocalStore,
    config: &ProjectConfig,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    let (suffix, suffix_entries, discarded_entries) = store.ledger_suffix(target, deployment_id)?;
    // The shared override (see [`checkpoint_inner`]): the preview scans the
    // checkpointed target's ledger as-if the atomic replacement already
    // happened, so the pre-checkpoint history's releases/trees/deployment
    // dirs — garbage the moment the ledger is shortened — are enumerated
    // here, exactly as the real sweep deletes them. `suffix` (the raw lines)
    // is unused in the preview: it is the replacement payload only.
    let _ = suffix;
    let ledger_override = LedgerOverride {
        target: target.to_string(),
        entries: suffix_entries,
    };
    let sweep = store.sweep_discards(config, Some(&ledger_override))?;
    Ok(CheckpointReport {
        target: target.to_string(),
        deployment_id: deployment_id.clone(),
        discards: LedgerDiscards {
            discarded_entries,
            ..sweep
        },
        established: false,
        sweep_completed: false,
        sweep_warning: None,
        durability_warning: None,
        sweep_debt_warning: None,
        dry_run: true,
    })
}

/// Render a checkpoint report for the CLI: a dry-run preview reports the
/// PLANNED deletion sets ("would remove N" — nothing was touched); a real
/// checkpoint reports what WAS ACTUALLY unlinked ("removed N; P pending" —
/// a candidate is counted as removed only after a successful unlink, and
/// the candidates the sweep identified but did not remove — an aborted
/// stage, or a stage that never ran — stay pending, never claimed as
/// removed). The CLI prints exactly these lines; the unit tests assert on
/// them directly.
pub fn render_checkpoint_report(report: &CheckpointReport) -> Vec<String> {
    let mut lines = Vec::new();
    let head = if report.dry_run {
        format!(
            "dry-run: checkpoint at deployment {} of target {}",
            report.deployment_id, report.target
        )
    } else {
        format!(
            "checkpoint established: retained history starts at deployment {} of target {}",
            report.deployment_id, report.target
        )
    };
    lines.push(head);
    lines.push(format!(
        "{} {} ledger entr{} below the checkpoint",
        if report.dry_run {
            "would discard"
        } else {
            "discarded"
        },
        report.discards.discarded_entries.len(),
        plural(report.discards.discarded_entries.len())
    ));
    lines.push(sweep_line(
        "deployment director",
        report.dry_run,
        report.discards.sweep_deployments.len(),
        report.discards.removed_deployments,
    ));
    lines.push(sweep_line(
        "release record",
        report.dry_run,
        report.discards.sweep_releases.len(),
        report.discards.removed_releases,
    ));
    lines.push(sweep_line(
        "tree object",
        report.dry_run,
        report.discards.sweep_objects.len(),
        report.discards.removed_objects,
    ));
    if !report.dry_run && !report.sweep_completed {
        lines.push(format!(
            "warning: sweep did not complete — the next push retries it; re-run `deploy checkpoint {} {}` to finish it now",
            report.target, report.deployment_id
        ));
    }
    if let Some(w) = &report.sweep_warning {
        lines.push(format!("warning: {w}"));
    }
    if let Some(w) = &report.durability_warning {
        lines.push(format!("warning: {w}"));
    }
    if let Some(w) = &report.sweep_debt_warning {
        lines.push(format!("warning: {w}"));
    }
    lines
}

/// ONE sweep category's report line. A DRY-RUN reports the PLANNED set
/// ("would remove N") — the preview enumerates the candidates and touches
/// nothing. An EXECUTION reports the count ACTUALLY unlinked plus the
/// PENDING remainder ("removed R; P pending"): `removed` is only ever
/// incremented after a successful filesystem unlink, so the line never
/// claims a candidate was deleted when the deletion failed — the pending
/// candidates (an aborted stage, or a stage that never ran) stay visible
/// as `pending`.
fn sweep_line(category: &str, dry_run: bool, planned: usize, removed: usize) -> String {
    if dry_run {
        format!(
            "would remove {planned} {category}{} (unreachable)",
            plural(planned)
        )
    } else {
        let pending = planned - removed;
        match pending {
            0 => format!(
                "removed {removed} {category}{} (unreachable)",
                plural(removed)
            ),
            _ => format!(
                "removed {removed} {category}{} (unreachable); {pending} pending",
                plural(removed)
            ),
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::deploy::maintenance::retry_pending_sweep;
    use crate::identity::{
        ArtifactRef, DeploymentId, ReleaseId, ServerId, SlotId, TargetName, TreeDigest,
        VariantName, test_deployment_id, test_generation_id, test_tree_digest,
    };
    use crate::ledger::{DeploymentIntent, LedgerTerminal, ObservedAssignment, ObservedSlot, Pins};
    use crate::store::local::debt::SweepDebt;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;

    const TARGET: &str = "t1";

    /// A single-slot (`p1`) VALID intent over the given release/tree, whose
    /// frozen snapshot entry (generation gen-1, artifact, binding s1
    /// /srv/deploy/p1) MATCHES the rollback `terminal_for` builds (the new
    /// shared validator requires the match, and the old fixtures were wrong
    /// under the new contract).
    fn intent_for_over(
        id: &str,
        target: &str,
        release: &str,
        tree: &str,
        head: Option<&DeploymentIntent>,
    ) -> DeploymentIntent {
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::kernel::snapshot::SnapshotSlot;
        use crate::ledger::Observation;
        let p1 = SlotId::parse("p1").unwrap();
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(id),
            target: TargetName::new(target.to_string()),
            parent: head.map(|h| h.deployment_id().clone()),
            parent_snapshot: head.map(|h| h.resulting_snapshot()),
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1.clone(),
                result: SnapshotSlot::new(
                    test_generation_id("gen-1"),
                    ArtifactRef {
                        release: crate::identity::test_release_id(release),
                        variant: VariantName::parse("standard").unwrap(),
                        tree: test_tree_digest(tree),
                    },
                    crate::ledger::PhysicalBinding::new(
                        ServerId::parse("s1").unwrap(),
                        "/srv/deploy/p1",
                    )
                    .expect("test binding is absolute and traversal-free"),
                ),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: crate::identity::BehaviorDigest::parse(
                crate::identity::DIGEST_TEST_HEX_1,
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("the checkpoint-test intent plans")
    }

    /// A Successful terminal BOUND to the given intent (payload-free; the
    /// snapshot resolves from the intent's slot table).
    fn terminal_for(intent: &DeploymentIntent) -> LedgerTerminal {
        crate::testutil::fixtures::successful_terminal(intent)
    }

    fn seed_history(
        store: &LocalStore,
        target: &str,
        prefix: &str,
        history: &[bool],
    ) -> Vec<String> {
        let mut successful = Vec::new();
        for (i, ok) in history.iter().enumerate() {
            let id = format!("{prefix}-{i}");
            // The successful chain must be parented (the lineage invariant —
            // at most one `Successful` per parent): each seed plans against
            // the CURRENT successful head.
            let head = store
                .read_ledger(target)
                .unwrap()
                .into_iter()
                .rev()
                .find(|e| {
                    e.terminal.as_ref().is_some_and(|t| {
                        t.status() == crate::ledger::records::DeploymentStatus::Successful
                    })
                })
                .map(|e| e.intent);
            if *ok {
                // Successful: intent's desired must MATCH the rollback (generation, artifact, binding)
                let rel = id.clone();
                let matching_intent = intent_for_over(&id, target, &rel, "tree-1", head.as_ref());
                store.test_append_intent(target, &matching_intent).unwrap();
                store
                    .test_append_terminal(
                        target,
                        matching_intent.deployment_id(),
                        &terminal_for(&matching_intent),
                    )
                    .unwrap();
                successful.push(test_deployment_id(&id).as_str().to_string());
            } else {
                // A FAILED (settled) entry is also STRICTLY LINEAR: it
                // descends from the CURRENT successful head (the same
                // parenting as a success), so it appends after the previous
                // entry's terminal and never introduces a second pending
                // attempt.
                let it = intent_for_over(&id, target, "rel-1", "tree-1", head.as_ref());
                store.test_append_intent(target, &it).unwrap();
                store
                    .test_append_terminal(
                        target,
                        it.deployment_id(),
                        &crate::testutil::fixtures::rolled_back_terminal(
                            &it,
                            &it.full_membership().into_iter().collect::<Vec<_>>(),
                        ),
                    )
                    .unwrap();
            }
        }
        successful
    }

    /// A minimal but VALID variant file (the config loader requires a real
    /// variant: mappings, activation, verification).
    const VARIANT_TOML: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

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

    fn config_for(dir: &tempfile::TempDir) -> ProjectConfig {
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            VARIANT_TOML,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            format!(
                "schema_version = 2\napplication = \"cp\"\nrelease = \"v1\"\n\n\
                 [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
                 [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        ProjectConfig::load(&project.join("deploy.toml")).unwrap()
    }

    /// Seed an UNREACHABLE deployment dir + release record + object dir (not
    /// referenced by any ledger, observed state, or pin): the sweep must
    /// delete it.
    fn seed_unreachable(store: &LocalStore, deployment: &str, release: &str, tree: &str) {
        // The deployment dir is keyed by the CANONICAL id (the ledger
        // references the validated form).
        let dir = store.deployment_dir(&test_deployment_id(deployment));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plan.json"), "{}").unwrap();
        let rel_dir = store.release_dir(&crate::identity::test_release_id(release));
        std::fs::create_dir_all(&rel_dir).unwrap();
        std::fs::write(rel_dir.join("release.json"), "{}").unwrap();
        let obj_dir = store.object_root(&test_tree_digest(tree));
        std::fs::create_dir_all(&obj_dir).unwrap();
        std::fs::write(obj_dir.join("file"), "x").unwrap();
    }

    /// Write a REAL release record for the pin tests and return its
    /// content-derived id (release ids are derived from content, so the pin
    /// must reference the id the record actually got).
    fn seed_real_release(store: &LocalStore) -> ReleaseId {
        let rec = crate::verify::release::build_release(
            "cp",
            "sha256-aa",
            &BTreeMap::from([(
                VariantName::parse("standard").unwrap(),
                test_tree_digest("tree-pinned"),
            )]),
            &BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotConfig::new(
                    "p1".to_string(),
                    "s1".to_string(),
                    std::path::PathBuf::from("/srv/deploy/p1"),
                    TARGET.to_string(),
                    Vec::new(),
                )],
            )]),
            std::path::Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        id
    }

    /// Build a REAL release record and return its content-DERIVED id (release
    /// ids are derived from content, so a pin must reference the id the
    /// record actually got — `store.write_release` binds the record to its
    /// derived read path, and the pin expansion's `record.release_id == read
    /// path` check then holds; a record at a differently-named dir would be
    /// refused). `tag` differentiates the record's variant tree so distinct
    /// seeds produce distinct ids.
    fn seed_named_release(store: &LocalStore, tag: &str) -> ReleaseId {
        let rec = crate::verify::release::build_release(
            "sw",
            "sha256-aa",
            &std::collections::BTreeMap::from([(
                crate::identity::VariantName::parse("standard").unwrap(),
                crate::identity::test_tree_digest(&format!("tree-pinned-{tag}")),
            )]),
            &std::collections::BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotConfig::new(
                    "p1".to_string(),
                    "s1".to_string(),
                    std::path::PathBuf::from("/srv/deploy/p1"),
                    TARGET.to_string(),
                    Vec::new(),
                )],
            )]),
            std::path::Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        id
    }

    /// Create a release directory under the given NAME with junk content —
    /// the sweep keeps or sweeps it by NAME (the reachability set carries the
    /// names the ledgers/observations reference; only PINNED releases are
    /// read, and they need a real record seeded via [`seed_named_release`]).
    fn seed_named_release_dir(store: &LocalStore, name: &str) {
        let dir = store.release_dir(&crate::identity::test_release_id(name));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("release.json"), "{}").unwrap();
    }

    /// Create a deployment directory under the given id (junk content) — the
    /// sweep enumerates `deployments/` and sweeps the unreachable dirs. The
    /// dir is keyed by the CANONICAL id (the ledger references the validated
    /// form).
    fn seed_deployment_dir(store: &LocalStore, id: &str) {
        let dir = store.deployment_dir(&test_deployment_id(id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plan.json"), "{}").unwrap();
    }

    /// Create a tree object directory under the given digest name (junk
    /// content) — the sweep enumerates `objects/sha256/` and sweeps the
    /// unreachable digests.
    fn seed_tree_dir(store: &LocalStore, tree: &str) {
        let dir = store.object_root(&test_tree_digest(tree));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file"), "x").unwrap();
    }

    /// Seed ONE successful deployment whose rollback references the caller's
    /// EXACT release + tree (the shared `seed_history` helper always rolls
    /// back to the same tree digest, so the pre-suffix-unique-artifact cases
    /// need a custom entry).
    fn seed_success(store: &LocalStore, target: &str, id: &str, release: &str, tree: &str) {
        // THE COMPLETE RESULT IS STORED ONCE: the intent's slot table bakes
        // the caller's release + tree; the successful terminal is
        // payload-free and bound by the canonical digest. The seed chains
        // onto the CURRENT successful head (the lineage invariant — at most
        // one `Successful` per parent).
        let head = store
            .read_ledger(target)
            .unwrap()
            .into_iter()
            .rev()
            .find(|e| {
                e.terminal.as_ref().is_some_and(|t| {
                    t.status() == crate::ledger::records::DeploymentStatus::Successful
                })
            })
            .map(|e| e.intent);
        let matching_intent = intent_for_over(id, target, release, tree, head.as_ref());
        store.test_append_intent(target, &matching_intent).unwrap();
        store
            .test_append_terminal(
                target,
                matching_intent.deployment_id(),
                &crate::testutil::fixtures::successful_terminal(&matching_intent),
            )
            .unwrap();
    }

    /// THE PARITY FIX (deterministic regression): a checkpoint whose
    /// PRE-SUFFIX history references artifacts UNIQUE to it — the dry-run
    /// preview MUST enumerate them. With the ledger override the
    /// pre-checkpoint releases / trees / deployment dirs are unreachable the
    /// moment the suffix replacement happens, so the preview lists them;
    /// WITHOUT the override the preview scans the CURRENT ledger (where the
    /// pre-checkpoint entries are still present) and misses them — the
    /// under-report this fix removes.
    #[test]
    fn preview_lists_artifacts_that_become_unreachable_only_after_the_suffix_replacement() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        // Three successful deployments, each with a UNIQUE release + tree
        // (rel-sha256-old/tree-old, rel-sha256-mid/tree-mid,
        // rel-sha256-new/tree-new).
        seed_success(&store, TARGET, "deploy-0", "rel-sha256-old", "tree-old");
        seed_success(&store, TARGET, "deploy-1", "rel-sha256-mid", "tree-mid");
        seed_success(&store, TARGET, "deploy-2", "rel-sha256-new", "tree-new");
        // Materialize the deployment dirs / release dirs / object dirs for
        // all three entries (the sweep only enumerates what exists).
        for id in ["deploy-0", "deploy-1", "deploy-2"] {
            seed_deployment_dir(&store, id);
        }
        for rel in ["rel-sha256-old", "rel-sha256-mid", "rel-sha256-new"] {
            seed_named_release_dir(&store, rel);
        }
        for tree in ["tree-old", "tree-mid", "tree-new"] {
            seed_tree_dir(&store, tree);
        }
        // Checkpoint at deploy-1: deploy-0 is strictly BEFORE it — its
        // release, tree, and deployment dir are reachable only from the
        // pre-suffix ledger that the replacement discards.
        let preview = run_checkpoint(&store, &cfg, TARGET, &test_deployment_id("deploy-1"), true)
            .expect("the dry-run preview succeeds");
        assert!(preview.dry_run);
        assert!(!preview.established);
        assert_eq!(
            preview.discards.discarded_entries,
            vec![test_deployment_id("deploy-0").as_str().to_string()],
            "exactly the entries strictly before the checkpoint are discarded"
        );
        // THE FIX: the preview lists the pre-suffix-only content (reachable
        // only from the discarded history).
        assert!(
            preview
                .discards
                .sweep_deployments
                .contains(&test_deployment_id("deploy-0").as_str().to_string()),
            "the pre-suffix deployment dir must be previewed for deletion"
        );
        assert!(
            preview.discards.sweep_releases.contains(
                &crate::identity::test_release_id("rel-sha256-old")
                    .as_str()
                    .to_string()
            ),
            "the pre-suffix release must be previewed for deletion"
        );
        assert!(
            preview
                .discards
                .sweep_objects
                .contains(&test_tree_digest("tree-old").as_str().to_string()),
            "the pre-suffix tree must be previewed for deletion"
        );
        // The retained suffix's own content is NOT previewed for deletion.
        assert!(
            !preview
                .discards
                .sweep_deployments
                .contains(&test_deployment_id("deploy-1").as_str().to_string())
        );
        assert!(
            !preview.discards.sweep_releases.contains(
                &crate::identity::test_release_id("rel-sha256-mid")
                    .as_str()
                    .to_string()
            )
        );
        assert!(
            !preview
                .discards
                .sweep_objects
                .contains(&test_tree_digest("tree-mid").as_str().to_string())
        );
        // COUNTERFACTUAL: WITHOUT the ledger override the preview scans the
        // CURRENT ledger — deploy-0's entry is still present, so its unique
        // content is NOT listed (and nothing else is unreachable either).
        // This is the under-report the bug describes.
        let no_override = store.sweep_discards(&cfg, None).unwrap();
        assert!(no_override.sweep_deployments.is_empty());
        assert!(no_override.sweep_releases.is_empty());
        assert!(no_override.sweep_objects.is_empty());
    }

    /// The checkpoint compacts the ledger to the suffix at the checkpoint
    /// deployment and sweeps the unreachable content.
    #[test]
    fn checkpoint_compacts_ledger_to_the_suffix_and_sweeps() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        // History: deploy-0 (successful, rel-a/tree-a), deploy-1 (FAILED),
        // deploy-2 (successful). Plus UNREACHABLE ghost content.
        let ids = seed_history(&store, TARGET, "deploy", &[true, false, true]);
        seed_unreachable(&store, "ghost-deploy", "rel-sha256-ghost", "tree-ghost");
        let checkpoint = &ids[1]; // the second successful = deploy-2
        let rep = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(checkpoint).expect("canonical checkpoint id"),
        )
        .expect("checkpoint succeeds");
        assert!(rep.established);
        assert!(rep.sweep_completed);
        // The ledger now holds exactly the checkpoint entry onward
        // (deploy-0 and deploy-1 — before deploy-2 — are gone).
        let entries = store.read_ledger(TARGET).unwrap();
        assert_eq!(entries.len(), 1, "only the checkpoint entry is retained");
        assert_eq!(
            entries[0].deployment_id.as_str(),
            DeploymentId::parse(checkpoint)
                .expect("canonical checkpoint id")
                .as_str()
        );
        // The unreachable ghost content was swept.
        assert!(
            !store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists()
        );
        assert!(
            !store
                .release_dir(&crate::identity::test_release_id("rel-sha256-ghost"))
                .exists()
        );
        assert!(!store.object_root(&test_tree_digest("tree-ghost")).exists());
    }

    /// A failed ledger replacement deletes NOTHING: the checkpoint fails
    /// cleanly with the full history intact (the fault is injected at the
    /// replacement's TEMP-WRITE stage — a PRE-RENAME failure, so the visible
    /// ledger is wholly OLD).
    #[test]
    fn checkpoint_fails_cleanly_when_replacement_faults() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        let ids = seed_history(&store, TARGET, "deploy", &[true, true, true]);
        let before = store.read_ledger(TARGET).unwrap();
        store.fault_registry().arm_ledger_replace_write(TARGET);
        let err = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(&ids[1]).expect("canonical checkpoint id"),
        )
        .expect_err("the pre-rename fault fails the checkpoint");
        assert!(err.to_string().contains("ledger"));
        assert_eq!(
            store.read_ledger(TARGET).unwrap(),
            before,
            "the visible ledger is wholly OLD after a failed replacement"
        );
    }

    /// A checkpoint on ONE target compacts ONLY that target's OWN ledger:
    /// `checkpoint(t).affected_history == history_of(t)` — the per-target
    /// ledger of every OTHER target is byte-for-byte untouched.
    #[test]
    fn checkpoint_affects_only_the_targets_own_ledger() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        // Two targets, each with its OWN per-target history (t1: deploy-0..2,
        // t2: dep2-0..2).
        let t1_ids = seed_history(&store, TARGET, "deploy", &[true, true, true]);
        seed_history(&store, "t2", "dep2", &[true, true, true]);
        let t2_before = store.read_ledger("t2").unwrap();

        // Checkpoint t1 at its MIDDLE successful deployment (deploy-1): only
        // t1's history is compacted to the suffix at/after that floor.
        let checkpoint = &t1_ids[1];
        let rep = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(checkpoint).expect("canonical checkpoint id"),
        )
        .expect("checkpoint succeeds");
        assert!(rep.established);
        let t1_after = store.read_ledger(TARGET).unwrap();
        assert_eq!(
            t1_after.len(),
            2,
            "t1's ledger is compacted to the retained suffix"
        );
        assert_eq!(
            t1_after[0].deployment_id.as_str(),
            DeploymentId::parse(checkpoint)
                .expect("canonical checkpoint id")
                .as_str(),
            "the retained suffix begins at the checkpoint deployment"
        );
        // t2's ledger is EXACTLY as before: a checkpoint on t1 never touches
        // another target's history (affected history == the target's own).
        assert_eq!(
            store.read_ledger("t2").unwrap(),
            t2_before,
            "a checkpoint on t1 must leave t2's ledger untouched"
        );
    }

    /// The sweep keeps everything reachable from another target or a pin:
    /// only the unreachable content is swept.
    #[test]
    fn checkpoint_keeps_other_target_and_pinned_content() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // A pin keeps a release that is NOT in any ledger (retained by the
        // PIN only). The release id is content-derived, so the pin must
        // reference the id the real record got.
        let pinned = seed_real_release(&store);
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            VARIANT_TOML,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            format!(
                "schema_version = 2\napplication = \"cp\"\nrelease = \"v1\"\n\n\
                 [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
                 [[pins]]\nrelease = \"{pinned}\"\nreason = \"keep\"\n\n\
                 [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let cfg = ProjectConfig::load(&project.join("deploy.toml")).unwrap();

        // t1's ledger references rel-sha256-a; t2's ledger references
        // rel-sha256-other (reachable from ANOTHER target's ledger).
        seed_history(&store, TARGET, "deploy", &[true]);
        seed_history(&store, "t2", "dep2", &[true]);
        // The referenced release dirs (kept by NAME: the ledgers reference
        // them — seeded under the same canonical tags the ledgers use).
        seed_named_release_dir(&store, "deploy-0");
        seed_named_release_dir(&store, "dep2-0");
        // Unreachable ghost release.
        seed_named_release_dir(&store, "rel-sha256-ghost");

        let id0 = store.read_ledger(TARGET).unwrap()[0].deployment_id.clone();
        let rep = run_checkpoint_unlocked(&store, &cfg, TARGET, &id0)
            .expect("checkpoint at the first entry succeeds");
        assert!(rep.established);
        assert!(rep.sweep_completed);
        // Reachable content survives: the t1 retained release, the t2
        // ledger's release, and the pinned release.
        assert!(
            store
                .release_dir(&crate::identity::test_release_id("deploy-0"))
                .exists()
        );
        assert!(
            store
                .release_dir(&crate::identity::test_release_id("dep2-0"))
                .exists()
        );
        assert!(store.release_dir(&pinned).exists());
        // The ghost release was swept.
        assert!(
            !store
                .release_dir(&crate::identity::test_release_id("rel-sha256-ghost"))
                .exists()
        );
    }

    // ---------------------------------------------------------------------
    // THE PROPERTY: inject a failure at EVERY atomic-replacement stage (the
    // pre-rename temp write/sync/rename, the post-rename parent-dir sync)
    // and at every sweep stage; the visible ledger is always WHOLY OLD or
    // WHOLY NEW (the atomic replace), retained and pinned content survives
    // every failure, and retries converge (repeating the checkpoint
    // recomputes reachability fresh and finishes the sweep).
    // ---------------------------------------------------------------------

    /// The fault slots of the property: the four atomic-replacement stages
    /// (the PRE-RENAME temp write/sync/rename — plain `Err`, ledger wholly
    /// OLD — and the POST-RENAME parent-dir sync — a STRUCTURED report with
    /// the commit established and durability unconfirmed, ledger wholly NEW,
    /// NO deletion, sweep deferred), and EVERY POST-COMMIT sweep stage: the
    /// reachability read/scan ([`FaultKind::SweepScan`]), the directory
    /// enumeration ([`FaultKind::SweepEnumerate`]), the three deletion
    /// stages (deployment dirs / release records / tree objects), and the
    /// sweep-debt marker write. Once the ledger replacement has committed
    /// (durability confirmed), a fault at ANY of these stages must be
    /// CONVERTED into an established report (never `Err`) — the explicit
    /// commit boundary.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CheckpointFault {
        LedgerReplaceWrite,
        LedgerReplaceSync,
        LedgerReplaceRename,
        LedgerReplaceDirSync,
        SweepScan,
        SweepEnumerate,
        SweepDeployments,
        SweepReleases,
        SweepObjects,
        SweepDebtWrite,
    }

    fn arm_fault(store: &LocalStore, fault: CheckpointFault) {
        let reg = store.fault_registry();
        match fault {
            CheckpointFault::LedgerReplaceWrite => reg.arm_ledger_replace_write(TARGET),
            CheckpointFault::LedgerReplaceSync => reg.arm_ledger_replace_sync(TARGET),
            CheckpointFault::LedgerReplaceRename => reg.arm_ledger_replace_rename(TARGET),
            CheckpointFault::LedgerReplaceDirSync => reg.arm_ledger_replace_dir_sync(TARGET),
            CheckpointFault::SweepScan => reg.arm_sweep_scan(),
            CheckpointFault::SweepEnumerate => reg.arm_sweep_enumerate(),
            CheckpointFault::SweepDeployments => reg.arm_sweep_deployments(),
            CheckpointFault::SweepReleases => reg.arm_sweep_releases(),
            CheckpointFault::SweepObjects => reg.arm_sweep_objects(),
            // The debt-write fault fires only when the sweep is INCOMPLETE
            // (the marker write is reached): arm a sweep-stage fault too, so
            // the debt write is actually attempted.
            CheckpointFault::SweepDebtWrite => {
                reg.arm_sweep_deployments();
                reg.arm_write_sweep_debt();
            }
        }
    }

    /// Run ONE property case: seed a history (a successful checkpoint
    /// deployment at `checkpoint_at`, later successes after it), seed
    /// unreachable + pinned content, inject `fault` at the checkpoint, then
    /// RETRY the checkpoint (no fault) until it converges. Asserts:
    ///
    /// * the ATOMIC-REPLACEMENT stage→outcome mapping: a PRE-RENAME fault
    ///   (temp write/sync/rename) is a plain `Err` with the ledger wholly
    ///   OLD and nothing deleted; the POST-RENAME parent-dir-sync fault is
    ///   a STRUCTURED report (established, durability warning,
    ///   `sweep_completed: false`) with the wholly-NEW suffix visible and
    ///   ZERO artifacts deleted (no sweep ran) — never an `Err`;
    /// * THE EXPLICIT COMMIT BOUNDARY: a POST-commit fault (EVERY sweep
    ///   stage — the reachability scan, the enumeration, the three deletion
    ///   stages, the debt-marker write) is CONVERTED into an established
    ///   report with `sweep_completed: false` and a warning — NEVER an
    ///   `Err`;
    /// * the visible ledger is always WHOLY OLD or WHOLY NEW — never torn
    ///   (the atomic replace): wholly OLD only for the pre-rename faults
    ///   (nothing committed); wholly NEW — EXACTLY the retained suffix — for
    ///   the post-rename durability fault and every post-commit fault (the
    ///   commit stands);
    /// * retained and pinned content survives every failure;
    /// * the retry converges: `sweep_completed: true`, the ledger matches
    ///   the retained suffix, the unreachable content is gone, the sweep
    ///   debt is cleared.
    fn run_fault_case(at: usize, fault: CheckpointFault) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        config_for(&dir);
        // A pin keeps a release that is NOT in any ledger (retained by the
        // PIN only). The release id is content-derived, so the pin references
        // the id the real record got.
        let pinned = seed_real_release(&store);
        let pinned_rel = pinned.as_str().to_string();
        // Rebuild the config WITH the pin (the property asserts pinned
        // content survives every failure).
        let project = dir.path().join("proj");
        std::fs::write(
            project.join("deploy.toml"),
            format!(
                "schema_version = 2\napplication = \"cp\"\nrelease = \"v1\"\n\n\
                 [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
                 [[pins]]\nrelease = \"{pinned}\"\nreason = \"keep\"\n\n\
                 [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let cfg = ProjectConfig::load(&project.join("deploy.toml")).unwrap();
        // History: successful deployments deploy-0..deploy-5; checkpoint at
        // index `at`. Unreachable ghost content to sweep.
        let ids = seed_history(&store, TARGET, "deploy", &[true; 6]);
        seed_unreachable(&store, "ghost-deploy", "rel-sha256-ghost", "tree-ghost");
        let checkpoint_id = &ids[at];

        let expected_suffix = {
            let entries = store.read_ledger(TARGET).unwrap();
            entries[at..]
                .iter()
                .map(|e| e.deployment_id.as_str().to_string())
                .collect::<Vec<_>>()
        };

        // THE FAULTED CHECKPOINT + THE EXPLICIT COMMIT BOUNDARY. The ledger
        // is always WHOLY OLD or WHOLY NEW (the atomic replace, never torn),
        // and the fault's CLASS decides which:
        arm_fault(&store, fault);
        let faulted = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(checkpoint_id).expect("canonical checkpoint id"),
        );
        let visible: Vec<String> = store
            .read_ledger(TARGET)
            .unwrap()
            .iter()
            .map(|e| e.deployment_id.as_str().to_string())
            .collect();
        match fault {
            // ---- the PRE-RENAME replacement stages: a failed replacement
            // is a plain `Err` (the rename never happened — nothing was
            // committed), never a report, and the visible ledger is wholly
            // OLD ----
            CheckpointFault::LedgerReplaceWrite
            | CheckpointFault::LedgerReplaceSync
            | CheckpointFault::LedgerReplaceRename => {
                assert!(
                    faulted.is_err(),
                    "fault {fault:?}: a pre-rename replacement fault must fail the checkpoint with Err"
                );
                assert_eq!(
                    visible, ids,
                    "fault {fault:?}: a pre-rename fault leaves the ledger wholly OLD"
                );
                assert!(
                    store
                        .deployment_dir(&test_deployment_id("ghost-deploy"))
                        .exists(),
                    "fault {fault:?}: a pre-rename fault must delete nothing"
                );
            }
            // ---- the POST-RENAME durability stage: the rename happened —
            // the wholly-NEW suffix IS visible under its final name — but
            // durability is unconfirmed, so the checkpoint returns a
            // STRUCTURED report (established, durability warning, sweep
            // deferred) — NEVER an `Err` — and deletes NOTHING (a sweep
            // against a floor whose durability is unconfirmed could let an
            // interrupted retry expose history below the floor) ----
            CheckpointFault::LedgerReplaceDirSync => {
                let rep = faulted.unwrap_or_else(|e| {
                    panic!(
                        "fault {fault:?}: a post-rename durability failure must be a structured \
                         report, never an Err, got {e}"
                    )
                });
                assert!(
                    rep.established,
                    "fault {fault:?}: the rename committed the ledger — established"
                );
                assert!(
                    !rep.sweep_completed,
                    "fault {fault:?}: the sweep is deferred (sweep_completed false)"
                );
                assert!(
                    rep.sweep_warning.is_none(),
                    "fault {fault:?}: no post-commit sweep ran, so no sweep warning"
                );
                assert!(
                    rep.durability_warning
                        .as_ref()
                        .is_some_and(|w| w.contains("durability is unconfirmed")),
                    "fault {fault:?}: the durability warning must be carried"
                );
                assert!(
                    rep.sweep_debt_warning.is_none(),
                    "fault {fault:?}: the owed sweep recorded as durable debt cleanly"
                );
                assert_eq!(
                    visible, expected_suffix,
                    "fault {fault:?}: the committed ledger is EXACTLY the retained suffix, wholly new"
                );
                // ZERO ARTIFACTS DELETED: no reachability scan, no sweep ran.
                assert!(
                    store
                        .deployment_dir(&test_deployment_id("ghost-deploy"))
                        .exists(),
                    "fault {fault:?}: no sweep may run against an unconfirmed floor"
                );
                assert!(
                    store
                        .release_dir(&crate::identity::test_release_id("rel-sha256-ghost"))
                        .exists(),
                    "fault {fault:?}: no sweep may run against an unconfirmed floor"
                );
                assert!(
                    store.object_root(&test_tree_digest("tree-ghost")).exists(),
                    "fault {fault:?}: no sweep may run against an unconfirmed floor"
                );
                // The owed sweep is recorded as the TYPED durability-gated
                // marker: AwaitingCheckpointDurability (the floor is NOT
                // durable — no sweep may run until a durability-confirming
                // rewrite transitions it).
                assert!(
                    matches!(
                        store.read_sweep_debt().unwrap(),
                        Some(SweepDebt::AwaitingCheckpointDurability { .. })
                    ),
                    "fault {fault:?}: the deferred sweep is recorded as the typed awaiting-durability marker"
                );
                // The report's discards carry step 1's suffix computation
                // (the entries strictly before the checkpoint); the sweep
                // candidate/removed sets stay EMPTY since no sweep ran.
                assert_eq!(
                    rep.discards.discarded_entries,
                    ids[..at].to_vec(),
                    "fault {fault:?}: the report carries the discarded ledger entries"
                );
                assert!(
                    rep.discards.sweep_deployments.is_empty()
                        && rep.discards.sweep_releases.is_empty()
                        && rep.discards.sweep_objects.is_empty(),
                    "fault {fault:?}: no sweep ran, so no sweep candidates"
                );
                assert_eq!(
                    (
                        rep.discards.removed_deployments,
                        rep.discards.removed_releases,
                        rep.discards.removed_objects,
                    ),
                    (0, 0, 0),
                    "fault {fault:?}: zero artifacts removed (no sweep ran)"
                );
            }
            // ---- THE POST-COMMIT BOUNDARY: the replacement succeeded AND
            // durability was confirmed, so EVERY sweep-stage fault is
            // CONVERTED into an established report (never Err); the
            // retained suffix is preserved (the ledger = the suffix, wholly
            // new) ----
            _ => {
                let rep = faulted.unwrap_or_else(|e| {
                    panic!(
                        "fault {fault:?}: a post-commit sweep failure must NEVER be an Err, got {e}"
                    )
                });
                assert!(
                    rep.established,
                    "fault {fault:?}: the ledger commit stands (established)"
                );
                assert!(
                    !rep.sweep_completed,
                    "fault {fault:?}: the sweep is reported retry-required"
                );
                assert_eq!(
                    visible, expected_suffix,
                    "fault {fault:?}: the committed ledger is EXACTLY the retained suffix, wholly new"
                );
                match fault {
                    // The sweep READ/scan + enumeration failures: the reason
                    // surfaces as the report's sweep warning; the durable
                    // debt marker records the pending sweep.
                    CheckpointFault::SweepScan | CheckpointFault::SweepEnumerate => {
                        assert!(
                            rep.sweep_warning.is_some(),
                            "fault {fault:?}: a sweep read failure must surface a warning on the report"
                        );
                        assert!(
                            rep.sweep_debt_warning.is_none(),
                            "fault {fault:?}: the debt marker itself wrote cleanly"
                        );
                        assert!(
                            matches!(
                                store.read_sweep_debt().unwrap(),
                                Some(SweepDebt::Ready { .. })
                            ),
                            "fault {fault:?}: the pending sweep is recorded as the typed Ready marker (the ledger commit IS durable)"
                        );
                    }
                    // The debt-marker WRITE failure: the report carries the
                    // debt warning and no marker is left on disk.
                    CheckpointFault::SweepDebtWrite => {
                        assert!(
                            rep.sweep_warning.is_none(),
                            "fault {fault:?}: the sweep itself did not error"
                        );
                        assert!(
                            rep.sweep_debt_warning.is_some(),
                            "fault {fault:?}: the failed debt write is a warning, never an Err"
                        );
                        assert!(
                            store.read_sweep_debt().unwrap().is_none(),
                            "fault {fault:?}: the failed marker write leaves no marker on disk"
                        );
                    }
                    // The deletion stages: internally absorbed by `run_sweep`
                    // into `sweep_completed: false` + a cleanly-recorded
                    // debt marker.
                    _ => {
                        assert!(
                            rep.sweep_warning.is_none(),
                            "fault {fault:?}: a deletion-stage fault is absorbed, not an error"
                        );
                        assert!(
                            rep.sweep_debt_warning.is_none(),
                            "fault {fault:?}: the debt marker recorded cleanly"
                        );
                        assert!(
                            matches!(
                                store.read_sweep_debt().unwrap(),
                                Some(SweepDebt::Ready { .. })
                            ),
                            "fault {fault:?}: a pending sweep records the typed Ready marker (the ledger commit IS durable)"
                        );
                    }
                }
            }
        }
        // INVARIANT: retained and pinned content survives every failure.
        assert!(
            store.release_dir(&ReleaseId::new(&pinned_rel)).exists(),
            "fault {fault:?}: the pinned release must survive"
        );

        // RETRY CONVERGES: repeat the checkpoint without a fault — the
        // suffix is recomputed (identical) and the sweep finishes (the debt
        // marker is cleared).
        let retry = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(checkpoint_id).expect("canonical checkpoint id"),
        )
        .expect("the retry checkpoint succeeds");
        assert!(
            retry.sweep_completed,
            "fault {fault:?}: the retry must finish the sweep (converged)"
        );
        assert!(
            retry.sweep_warning.is_none() && retry.sweep_debt_warning.is_none(),
            "fault {fault:?}: the converged retry has no warnings"
        );
        assert!(
            store.read_sweep_debt().unwrap().is_none(),
            "fault {fault:?}: the converged sweep cleared the debt"
        );
        assert_eq!(
            store
                .read_ledger(TARGET)
                .unwrap()
                .iter()
                .map(|e| e.deployment_id.as_str().to_string())
                .collect::<Vec<_>>(),
            expected_suffix,
            "fault {fault:?}: the converged ledger is the retained suffix"
        );
        assert!(
            !store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists(),
            "fault {fault:?}: the converged sweep deleted the unreachable deployment dir"
        );
        assert!(
            store.release_dir(&ReleaseId::new(&pinned_rel)).exists(),
            "fault {fault:?}: the pinned release survives the converged sweep"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded `proptest_cases(4)` (full 4 with `DEPLOY_FULL_TESTS=1`,
            // fast default), fixed seed per house style.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE ATOMIC-REPLACEMENT STAGE→OUTCOME + EXPLICIT COMMIT BOUNDARY
        /// PROPERTY: a fault at EVERY atomic-replacement stage maps to its
        /// contract — a PRE-RENAME fault (temp write/sync/rename) is a plain
        /// `Err` (ledger wholly OLD, nothing deleted); the POST-RENAME
        /// parent-dir-sync fault is a STRUCTURED report (established,
        /// durability warning, sweep deferred — zero deletions, debt
        /// recorded); a fault at EVERY POST-COMMIT sweep stage — the
        /// reachability scan, the directory enumeration, the three deletion
        /// stages (deployment dirs / release records / tree objects), and
        /// the sweep-debt write — is CONVERTED into an established report
        /// (never `Err`), the retained suffix is preserved (the ledger = the
        /// suffix, wholly new), and a repeat of the same checkpoint
        /// converges (`sweep_completed`, debt cleared).
        #[test]
        fn checkpoint_faults_never_torn_and_retries_converge(
            at in 0usize..=5,
            fault in prop_oneof![
                Just(CheckpointFault::LedgerReplaceWrite),
                Just(CheckpointFault::LedgerReplaceSync),
                Just(CheckpointFault::LedgerReplaceRename),
                Just(CheckpointFault::LedgerReplaceDirSync),
                Just(CheckpointFault::SweepScan),
                Just(CheckpointFault::SweepEnumerate),
                Just(CheckpointFault::SweepDeployments),
                Just(CheckpointFault::SweepReleases),
                Just(CheckpointFault::SweepObjects),
                Just(CheckpointFault::SweepDebtWrite),
            ],
        ) {
            run_fault_case(at, fault);
        }
    }

    // ---- the deterministic unit tests, one per sweep stage ----------------
    // Each pins ONE stage's conversion at the explicit commit boundary: the
    // faulted checkpoint returns an ESTABLISHED report (never `Err`), the
    // retained suffix is preserved (the ledger = the suffix, wholly new),
    // and the re-run of the same checkpoint converges (`sweep_completed`,
    // debt cleared).
    #[test]
    fn sweep_scan_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepScan);
    }

    #[test]
    fn sweep_enumeration_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepEnumerate);
    }

    #[test]
    fn sweep_deployment_deletion_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepDeployments);
    }

    #[test]
    fn sweep_release_deletion_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepReleases);
    }

    #[test]
    fn sweep_object_deletion_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepObjects);
    }

    #[test]
    fn sweep_debt_write_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepDebtWrite);
    }

    // ---- the deterministic ATOMIC-REPLACEMENT stage unit tests -----------
    // One per replacement stage: a PRE-RENAME fault (temp write/sync/rename)
    // is a plain `Err` with the ledger wholly OLD; the POST-RENAME
    // parent-dir-sync fault is a STRUCTURED report (established, durability
    // warning, sweep deferred, no deletion) that converges on the re-run.
    #[test]
    fn replacement_write_fault_fails_cleanly_with_the_old_ledger_visible() {
        run_fault_case(2, CheckpointFault::LedgerReplaceWrite);
    }

    #[test]
    fn replacement_sync_fault_fails_cleanly_with_the_old_ledger_visible() {
        run_fault_case(2, CheckpointFault::LedgerReplaceSync);
    }

    #[test]
    fn replacement_rename_fault_fails_cleanly_with_the_old_ledger_visible() {
        run_fault_case(2, CheckpointFault::LedgerReplaceRename);
    }

    /// The post-rename parent-dir-sync fault: the checkpoint returns a
    /// STRUCTURED report (established, durability warning, `sweep_completed:
    /// false`), the wholly-NEW suffix is visible, zero artifacts are deleted,
    /// the owed sweep is recorded as durable debt, and the CLI renderer
    /// surfaces the durability warning DISTINCTLY (a `warning:` line whose
    /// text names the unconfirmed durability, separate from any sweep
    /// warning).
    #[test]
    fn replacement_dir_sync_fault_reports_established_with_durability_warning() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // Three successful deployments, checkpoint at deploy-1.
        let ids = seed_history(&store, TARGET, "deploy", &[true, true, true]);
        seed_unreachable(&store, "ghost-deploy", "rel-sha256-ghost", "tree-ghost");
        let cfg = config_for(&dir);
        store.fault_registry().arm_ledger_replace_dir_sync(TARGET);
        let rep = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(&ids[1]).expect("canonical checkpoint id"),
        )
        .expect("the durability-unconfirmed checkpoint is a structured report, never Err");
        assert!(rep.established);
        assert!(!rep.sweep_completed);
        assert!(rep.sweep_warning.is_none());
        let dur = rep
            .durability_warning
            .as_ref()
            .expect("the durability warning is set");
        assert!(
            dur.contains("durability is unconfirmed") && dur.contains("fsync"),
            "the warning names the unconfirmed durability and its fsync failure: {dur}"
        );
        assert!(rep.sweep_debt_warning.is_none());
        // The truncation stands (deploy-0 discarded) and no sweep ran.
        assert_eq!(rep.discards.discarded_entries, vec![ids[0].clone()]);
        // The owed sweep is recorded as the TYPED AwaitingCheckpointDurability
        // marker (the floor is NOT durable — the sweep is gated).
        assert!(
            matches!(
                store.read_sweep_debt().unwrap(),
                Some(SweepDebt::AwaitingCheckpointDurability { .. })
            ),
            "the deferred sweep is recorded as the typed awaiting-durability marker"
        );
        assert!(
            store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists(),
            "no sweep ran against the unconfirmed floor"
        );
        // THE RENDERER: the durability warning surfaces distinctly.
        let rendered = render_checkpoint_report(&rep);
        assert!(
            rendered
                .iter()
                .any(|l| { l.starts_with("warning:") && l.contains("durability is unconfirmed") }),
            "the CLI surfaces the durability warning: {rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|l| l.contains("sweep did not complete")),
            "the deferred sweep is reported retry-required: {rendered:?}"
        );
        // The retry converges: durable suffix + completed sweep, debt cleared.
        let retry = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(&ids[1]).expect("canonical checkpoint id"),
        )
        .expect("the retry checkpoint succeeds");
        assert!(retry.sweep_completed && retry.durability_warning.is_none());
        assert!(store.read_sweep_debt().unwrap().is_none());
        assert!(
            !store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists(),
            "the converged retry sweep deleted the unreachable content"
        );
    }

    /// The durability-unconfirmed report plus a sweep-debt WRITE failure:
    /// the debt record could not be persisted, so the report carries the
    /// debt warning (never an `Err`) while the durability warning still
    /// stands and nothing was deleted.
    #[test]
    fn replacement_dir_sync_fault_with_debt_write_failure_reports_both_warnings() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        // THREE successful deployments, checkpoint at deploy-1.
        let ids = seed_history(&store, TARGET, "deploy", &[true, true, true]);
        seed_unreachable(&store, "ghost-deploy", "rel-sha256-ghost", "tree-ghost");
        store.fault_registry().arm_ledger_replace_dir_sync(TARGET);
        store.fault_registry().arm_write_sweep_debt();
        let rep = run_checkpoint_unlocked(
            &store,
            &cfg,
            TARGET,
            &DeploymentId::parse(&ids[1]).expect("canonical checkpoint id"),
        )
        .expect("the structured report is never an Err");
        assert!(rep.established && !rep.sweep_completed);
        assert!(rep.durability_warning.is_some());
        assert!(
            rep.sweep_debt_warning.is_some(),
            "the failed debt record is a warning, never an Err"
        );
        assert!(
            store.read_sweep_debt().unwrap().is_none(),
            "the failed debt write leaves no marker on disk"
        );
        assert!(
            store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists(),
            "no sweep ran against the unconfirmed floor"
        );
    }

    // ---------------------------------------------------------------------
    // THE DURABILITY GATE PROPERTY (P1 review fix): a checkpoint whose
    // ledger replace is VISIBLE but whose durability is UNCONFIRMED records
    // the TYPED [`SweepDebt::AwaitingCheckpointDurability`] marker, and NO
    // maintenance path (a no-op push, a cross-target push) may sweep until a
    // durability-confirming retry durably rewrites the SAME ledger and
    // transitions the marker to [`SweepDebt::Ready`]. The sweep runs ONLY
    // against a `Ready` marker — below-floor objects are never deleted
    // before the durable transition (the monotone invariant: the `Awaiting`
    // state is never skipped).
    // ---------------------------------------------------------------------

    /// Run ONE durability-gate case: seed t1 history (every entry carries a
    /// UNIQUE release+tree pair, so the artifacts strictly BEFORE the
    /// checkpoint are below-floor content referenced only by the discarded
    /// prefix), a second target's ledger, and ghost garbage; fault the t1
    /// checkpoint's parent-dir fsync so it lands `ReplacedDurabilityUnknown`
    /// and the typed `AwaitingCheckpointDurability` marker; then drive the
    /// maintenance paths:
    ///
    /// * CRASH RECOVERY — a fresh store over the same base re-reads the same
    ///   shortened (visible) ledger and the same typed marker (the
    ///   durable-restore possibility);
    /// * THE NO-OP PUSH PATH — with the marker `Awaiting`, the maintenance
    ///   runner REFUSES the sweep: it runs ONLY the durability-confirming
    ///   rewrite (same-suffix durable replace → `ReplacedDurable`) and
    ///   transitions the marker to `Ready` — NOTHING is deleted;
    /// * THE CROSS-TARGET CHECKPOINT + PUSH PATH — a second checkpoint on t2
    ///   faults the same stage (a fresh `Awaiting{t2}` marker overwrites the
    ///   store-global slot), and the cross-target push's maintenance REFUSES
    ///   again (confirmation only, marker → `Ready{t2}`, still NOTHING
    ///   deleted — t1's below-floor content survives the cross-target push);
    /// * THE READY SWEEP — the next maintenance pass reads `Ready` and ONLY
    ///   THEN the sweep deletes the below-floor objects and clears the
    ///   marker.
    ///
    /// The invariant is asserted at every step: no below-floor object is
    /// ever deleted while the marker is `Awaiting` (the typed transition is
    /// monotone — `Awaiting` is never skipped).
    fn run_durability_gate_case(t1_len: usize, at: usize) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // t1's history: every entry carries a UNIQUE release+tree pair, so
        // the artifacts strictly before the checkpoint are below-floor
        // content referenced only by the discarded prefix.
        for i in 0..t1_len {
            let id = format!("dep-t1-{i}");
            let rel = format!("rel-{i}");
            let tree = format!("tree-{i}");
            seed_success(&store, TARGET, &id, &rel, &tree);
            seed_unreachable(&store, &id, &rel, &tree);
        }
        // A second target's ledger: a push to t2 runs the SAME store-global
        // maintenance; its content is reachable and must survive.
        seed_success(&store, "t2", "dep-t2-0", "rel-t2-0", "tree-t2-0");
        seed_unreachable(&store, "dep-t2-0", "rel-t2-0", "tree-t2-0");
        // Ghost garbage unreachable from any ledger.
        seed_unreachable(&store, "ghost-deploy", "rel-sha256-ghost", "tree-ghost");

        // The assert helper: every below-floor artifact (the discarded
        // entries' deployment dirs, release records, and trees) exists.
        let below_floor_exists = |s: &LocalStore| -> bool {
            (0..at).all(|i| {
                s.deployment_dir(&test_deployment_id(&format!("dep-t1-{i}")))
                    .exists()
                    && s.release_dir(&crate::identity::test_release_id(&format!("rel-{i}")))
                        .exists()
                    && s.object_root(&test_tree_digest(&format!("tree-{i}")))
                        .exists()
            })
        };

        let checkpoint_id = test_deployment_id(&format!("dep-t1-{at}"));
        let cfg = config_for(&dir);

        // 1. THE FAULTED CHECKPOINT: the parent-dir fsync of the ledger
        //    replace fails — the truncation IS visible (established) but its
        //    durability is UNCONFIRMED: NO sweep ran, the marker is the
        //    TYPED AwaitingCheckpointDurability, below-floor content intact.
        store.fault_registry().arm_ledger_replace_dir_sync(TARGET);
        let rep = run_checkpoint_unlocked(&store, &cfg, TARGET, &checkpoint_id)
            .expect("the durability-unconfirmed checkpoint is a structured report, never Err");
        assert!(rep.established && !rep.sweep_completed);
        assert!(
            rep.durability_warning
                .as_ref()
                .is_some_and(|w| w.contains("durability is unconfirmed")),
            "the report carries the durability warning"
        );
        assert!(
            matches!(
                store.read_sweep_debt().unwrap(),
                Some(SweepDebt::AwaitingCheckpointDurability { target, retained_from })
                    if target.as_str() == TARGET && retained_from == checkpoint_id
            ),
            "the owed sweep is the typed AwaitingCheckpointDurability marker for the faulted checkpoint"
        );
        assert!(
            below_floor_exists(&store),
            "no sweep ran against the unconfirmed floor"
        );
        assert!(
            store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists()
        );

        // 2. CRASH-RECOVERY RE-READ: a FRESH store over the same base reads
        //    the same shortened (visible) ledger and the same typed marker —
        //    the durable-restore possibility under test: even while the
        //    marker is Awaiting, the maintenance gate holds.
        let fresh = LocalStore::with_base(store.base().to_path_buf()).unwrap();
        assert!(
            matches!(
                fresh.read_sweep_debt().unwrap(),
                Some(SweepDebt::AwaitingCheckpointDurability { .. })
            ),
            "a fresh store re-reads the typed awaiting marker"
        );
        assert_eq!(
            fresh.read_ledger(TARGET).unwrap().len(),
            t1_len - at,
            "the shortened ledger is visible to the fresh store"
        );
        assert!(
            below_floor_exists(&fresh),
            "crash recovery: nothing was deleted"
        );

        // 3. THE NO-OP PUSH PATH with the marker Awaiting: the maintenance
        //    runner REFUSES the sweep — it runs ONLY the durability-
        //    confirming rewrite (the same-suffix durable replace →
        //    `ReplacedDurable`) and transitions the marker to `Ready`; the
        //    below-floor content is NOT deleted (the sweep never runs while
        //    the marker is Awaiting).
        let w = retry_pending_sweep(&store, &cfg, "noop-push");
        assert!(
            w.iter().all(|s| s.contains("sweep still deferred")),
            "the no-op push defers the sweep: {w:?}"
        );
        assert!(
            matches!(
                store.read_sweep_debt().unwrap(),
                Some(SweepDebt::Ready { target, retained_from })
                    if target.as_str() == TARGET && retained_from == checkpoint_id
            ),
            "the durability-confirming retry transitions the marker to Ready"
        );
        assert!(
            below_floor_exists(&store),
            "the no-op push must NOT delete below-floor content while the marker was Awaiting"
        );
        assert!(
            store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists()
        );

        // 4. THE CROSS-TARGET PATH: a second checkpoint on t2 faults the
        //    same stage — its OWN visible-but-unconfirmed ledger replace
        //    records a FRESH AwaitingCheckpointDurability marker (the
        //    store-global slot now names t2's floor); the cross-target
        //    push's maintenance then REFUSES the sweep again (confirmation
        //    only, marker → Ready{t2}), and t1's below-floor content stays
        //    intact while the marker is Awaiting.
        store.fault_registry().arm_ledger_replace_dir_sync("t2");
        let rep2 = run_checkpoint_unlocked(&store, &cfg, "t2", &test_deployment_id("dep-t2-0"))
            .expect("the t2 durability-unconfirmed checkpoint is a structured report, never Err");
        assert!(rep2.established && rep2.durability_warning.is_some());
        assert!(
            matches!(
                store.read_sweep_debt().unwrap(),
                Some(SweepDebt::AwaitingCheckpointDurability { target, retained_from })
                    if target.as_str() == "t2" && retained_from == test_deployment_id("dep-t2-0")
            ),
            "the t2 faulted checkpoint records a fresh Awaiting marker"
        );
        assert!(
            below_floor_exists(&store),
            "no sweep ran against t2's unconfirmed floor either"
        );
        let w2 = retry_pending_sweep(&store, &cfg, "cross-target-push");
        assert!(
            w2.iter().all(|s| s.contains("sweep still deferred")),
            "the cross-target push defers the sweep: {w2:?}"
        );
        assert!(
            matches!(
                store.read_sweep_debt().unwrap(),
                Some(SweepDebt::Ready { target, retained_from })
                    if target.as_str() == "t2" && retained_from == test_deployment_id("dep-t2-0")
            ),
            "the cross-target push's confirmation transitions t2's marker to Ready"
        );
        assert!(
            below_floor_exists(&store),
            "the CROSS-TARGET push must NOT delete below-floor content while the marker was Awaiting"
        );
        assert!(
            store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists()
        );

        // 5. THE READY SWEEP: the marker is now `Ready` (the floor is
        //    durable) — ONLY NOW may the sweep delete: the next maintenance
        //    pass runs the global sweep, which removes the unreachable
        //    below-floor content (t1's discarded entries' artifacts + the
        //    ghost) and clears the marker.
        let w3 = retry_pending_sweep(&store, &cfg, "final-pass");
        assert!(w3.is_empty(), "the Ready sweep converges cleanly: {w3:?}");
        assert_eq!(
            store.read_sweep_debt().unwrap(),
            None,
            "the completed sweep clears the marker"
        );
        for i in 0..at {
            assert!(
                !store
                    .deployment_dir(&test_deployment_id(&format!("dep-t1-{i}")))
                    .exists(),
                "below-floor deployment {i} deleted only after the durable transition"
            );
            assert!(
                !store
                    .release_dir(&crate::identity::test_release_id(&format!("rel-{i}")))
                    .exists(),
                "below-floor release {i} deleted only after the durable transition"
            );
            assert!(
                !store
                    .object_root(&test_tree_digest(&format!("tree-{i}")))
                    .exists(),
                "below-floor tree {i} deleted only after the durable transition"
            );
        }
        assert!(
            !store
                .deployment_dir(&test_deployment_id("ghost-deploy"))
                .exists(),
            "the ghost deployment is swept"
        );
        // Retained content survives: the t1 checkpoint entry + later
        // entries' artifacts, and t2's sole entry.
        for i in at..t1_len {
            assert!(
                store
                    .deployment_dir(&test_deployment_id(&format!("dep-t1-{i}")))
                    .exists()
                    && store
                        .release_dir(&crate::identity::test_release_id(&format!("rel-{i}")))
                        .exists()
                    && store
                        .object_root(&test_tree_digest(&format!("tree-{i}")))
                        .exists(),
                "retained entry {i} survives the sweep"
            );
        }
        assert!(
            store
                .deployment_dir(&test_deployment_id("dep-t2-0"))
                .exists()
        );
        assert!(
            store
                .release_dir(&crate::identity::test_release_id("rel-t2-0"))
                .exists()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded `proptest_cases(4)` (full 4 with `DEPLOY_FULL_TESTS=1`,
            // fast default), fixed seed per house style.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE DURABILITY GATE PROPERTY: for every generated checkpoint
        /// position, a dir-sync-faulted checkpoint lands
        /// `ReplacedDurabilityUnknown` + the typed
        /// [`SweepDebt::AwaitingCheckpointDurability`] marker; the NO-OP
        /// PUSH path and the CROSS-TARGET PUSH path both refuse the sweep
        /// while the marker is `Awaiting` (confirmation-only: the
        /// same-suffix durable rewrite transitions the marker to `Ready`,
        /// and below-floor objects are NOT deleted); the sweep runs only for
        /// a `Ready` marker and deletes the below-floor objects then. No
        /// below-floor object is ever deleted before the durable transition
        /// (the `Awaiting` state is never skipped).
        #[test]
        fn sweep_never_runs_before_checkpoint_durability(
            (t1_len, at) in (3usize..=5).prop_flat_map(|n| (Just(n), 1usize..n)),
        ) {
            run_durability_gate_case(t1_len, at);
        }
    }

    // ---------------------------------------------------------------------
    // THE PREVIEW == EXECUTION PARITY PROPERTY: multi-target stores with a
    // shared release/tree pool, observed state, and pins — the dry-run
    // preview of a checkpoint on ONE target must enumerate EXACTLY the
    // deletion sets the same checkpoint performs on a CLONED store (the
    // previewed inventory == the real deletions), including the artifacts
    // that become unreachable only AFTER the suffix replacement.
    // ---------------------------------------------------------------------

    /// The artifact pools of the parity property. Index 3 is RESERVED for
    /// t1's entry-0 (the pre-suffix-only pair every case discards at the
    /// checkpoint); indices 0..=2 are the pool the ledger entries draw from.
    /// The observed state and the pins reference their OWN content-derived
    /// release ids (see [`seed_named_release`]) — a pin must name the id the
    /// record actually got.
    const PROPERTY_RELEASES: [&str; 4] = [
        "rel-sha256-p0",
        "rel-sha256-p1",
        "rel-sha256-p2",
        "rel-sha256-p3",
    ];
    const PROPERTY_TREES: [&str; 4] = ["tree-p0", "tree-p1", "tree-p2", "tree-p3"];

    /// ProjectConfig for the parity property: TWO targets (t1 + t2), each with its
    /// own slot (the loader requires every declared target to have at least
    /// one member slot). No config `[[pins]]` — the property pins via the
    /// store-level `pins.json` surface instead.
    fn config_for_property(dir: &tempfile::TempDir) -> ProjectConfig {
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[slots]]
id = "p2"
server = "s1"
target = "t2"
deploy_dir = "/srv/eng2"

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
        std::fs::write(
            project.join("deploy.toml"),
            r#"schema_version = 2
application = "cp"
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
"#,
        )
        .unwrap();
        ProjectConfig::load(&project.join("deploy.toml")).unwrap()
    }

    /// Run ONE parity case: seed two targets' histories (t1's entry 0 always
    /// carries the UNIQUE pre-suffix-only pair (p3, p3); every other entry
    /// draws from the pool shared with the observed state and the pins),
    /// add observed state + pins + ghost content, PREVIEW the checkpoint on
    /// the original store (touches nothing), CLONE the base and EXECUTE the
    /// same checkpoint on the clone, and assert the previewed deletion
    /// inventory EXACTLY equals the real one — and that the real sweep
    /// actually removed what it reported.
    fn run_preview_parity_case(
        t1_len: usize,
        t2_len: usize,
        at: usize,
        t1_rest: &[(usize, usize)],
        t2_hist: &[(usize, usize)],
    ) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for_property(&dir);

        // t1's full history: entry 0 carries the UNIQUE pre-suffix-only
        // artifact (p3) — the checkpoint at `at >= 1` discards it, so every
        // case exercises the parity fix (content unreachable only after the
        // suffix replacement). The rest of t1 (and all of t2) draw from the
        // pool shared with the observed state and the pins (p0..p2).
        let mut t1_specs: Vec<(usize, usize)> = vec![(3, 3)];
        t1_specs.extend_from_slice(t1_rest);
        for (i, &(r, t)) in t1_specs.iter().enumerate() {
            let id = format!("dep-t1-{i}");
            seed_success(&store, "t1", &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
            seed_unreachable(&store, &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
        }
        for (i, &(r, t)) in t2_hist.iter().enumerate() {
            let id = format!("dep-t2-{i}");
            seed_success(&store, "t2", &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
            seed_unreachable(&store, &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
        }
        // Ghost content unreachable from ANY ledger, observation, or pin.
        seed_unreachable(&store, "dep-ghost", "rel-sha256-ghost", "tree-ghost");
        // OBSERVED state: the slot observed the (obs_rel) artifact, with its
        // last deployment the CHECKPOINTED deployment (dep-t1-{at}) — the
        // observed release + tree and that deployment dir are retained. The
        // observed release is a content-derived id seeded as a REAL record
        // (the sweep keeps the observed release by the id the record got).
        let obs_rel = seed_named_release(&store, "obs");
        store
            .write_slot_observed(
                &SlotId::parse("s-obs").unwrap(),
                &ObservedSlot {
                    slot: SlotId::parse("s-obs").unwrap(),
                    assignment: ObservedAssignment::Known {
                        generation: test_generation_id("gen-obs"),
                        artifact: ArtifactRef {
                            release: obs_rel.clone(),
                            variant: VariantName::parse("standard").unwrap(),
                            tree: test_tree_digest(PROPERTY_TREES[0]),
                        },
                        last_deployment: test_deployment_id(&format!("dep-t1-{at}")),
                        owner: Some(crate::remote::helper::test_owner("test-app", "s-obs")),
                        version: Some("2026-01-01T00:00:00Z".to_string()),
                    },
                },
            )
            .unwrap();
        seed_tree_dir(&store, PROPERTY_TREES[0]);
        // PINS — REAL, verifiable records. KEEP-BOTH with the gc side's
        // fail-closed pin handling (a pinned release's record is read +
        // identity-verified, so a junk-named dir can never be a pin target):
        // the property pins a genuine content-derived record instead — a
        // WHOLE-RELEASE pin (keeps the record + its variant trees) AND an
        // EXACT-BINDING pin on the SAME record ((release, tree) kept). The
        // pin-retained content is asserted below via the record's real id.
        let pinned = seed_real_release(&store);
        let pinned_tree = "tree-pinned".to_string();
        seed_tree_dir(&store, &pinned_tree);

        store
            .write_pins(&Pins {
                schema_version: crate::ledger::PINS_SCHEMA_VERSION,
                releases: vec![pinned.clone()],
                bindings: vec![ArtifactRef {
                    release: pinned.clone(),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest(&pinned_tree),
                }],
            })
            .unwrap();

        let checkpoint_id = test_deployment_id(&format!("dep-t1-{at}"));
        // PREVIEW on the ORIGINAL store (read-only: no locks, no writes).
        let preview = run_checkpoint(&store, &cfg, "t1", &checkpoint_id, true)
            .expect("the dry-run preview succeeds");
        assert!(preview.dry_run);
        assert!(!preview.established);

        // CLONE the base (the preview touched nothing) and EXECUTE the same
        // checkpoint on the clone.
        let clone_base = dir.path().join("clone");
        crate::store::atomic::copy_dir_recursive(store.base(), &clone_base)
            .expect("the store base clones");
        let clone = LocalStore::with_base(clone_base).unwrap();
        let executed = run_checkpoint_unlocked(&clone, &cfg, "t1", &checkpoint_id)
            .expect("the real checkpoint on the cloned store succeeds");
        assert!(executed.established);
        assert!(executed.sweep_completed);

        // THE PARITY (PLANNED == REMOVED + PENDING): the preview reports
        // the PLANNED deletion sets ("would remove N" — the candidates); the
        // execution reports REMOVED + PENDING. The two must reconcile: the
        // previewed candidate sets (the `sweep_*` lists and the ledger
        // entries) are IDENTICAL between the preview and the execution, and
        // the executed sweep — which completed clean — removed EXACTLY the
        // previewed candidates (removed == planned, nothing left pending).
        assert_eq!(
            preview.discards.discarded_entries, executed.discards.discarded_entries,
            "the previewed and executed ledger discard sets must match (t1_len={t1_len}, t2_len={t2_len}, at={at})"
        );
        assert_eq!(
            preview.discards.sweep_deployments, executed.discards.sweep_deployments,
            "the previewed PLANNED deployment dirs must equal the executed candidate sets (t1_len={t1_len}, t2_len={t2_len}, at={at})"
        );
        assert_eq!(
            preview.discards.sweep_releases, executed.discards.sweep_releases,
            "the previewed PLANNED release records must equal the executed candidate sets (t1_len={t1_len}, t2_len={t2_len}, at={at})"
        );
        assert_eq!(
            preview.discards.sweep_objects, executed.discards.sweep_objects,
            "the previewed PLANNED tree objects must equal the executed candidate sets (t1_len={t1_len}, t2_len={t2_len}, at={at})"
        );
        assert_eq!(
            executed.discards.removed_deployments,
            preview.discards.sweep_deployments.len(),
            "the executed sweep removed EXACTLY the previewed deployment candidates (nothing pending)"
        );
        assert_eq!(
            executed.discards.removed_releases,
            preview.discards.sweep_releases.len(),
            "the executed sweep removed EXACTLY the previewed release candidates (nothing pending)"
        );
        assert_eq!(
            executed.discards.removed_objects,
            preview.discards.sweep_objects.len(),
            "the executed sweep removed EXACTLY the previewed tree candidates (nothing pending)"
        );
        // The pre-suffix-only artifact MUST be in both (the fix).
        assert!(
            executed.discards.sweep_releases.contains(
                &crate::identity::test_release_id(PROPERTY_RELEASES[3])
                    .as_str()
                    .to_string()
            ),
            "the pre-suffix-only release must be deleted (t1_len={t1_len}, at={at})"
        );
        assert!(
            executed
                .discards
                .sweep_objects
                .contains(&test_tree_digest(PROPERTY_TREES[3]).as_str().to_string()),
            "the pre-suffix-only tree must be deleted (t1_len={t1_len}, at={at})"
        );

        // The real store removed exactly what it reported.
        for d in &executed.discards.sweep_deployments {
            assert!(
                !clone.deployment_dir_named(d).exists(),
                "deployment dir {d} must be deleted"
            );
        }
        for r in &executed.discards.sweep_releases {
            assert!(
                !clone.release_dir(&ReleaseId::new(r.clone())).exists(),
                "release dir {r} must be deleted"
            );
        }
        for t in &executed.discards.sweep_objects {
            assert!(
                !clone.object_root(&TreeDigest::new(t.clone())).exists(),
                "tree object {t} must be deleted"
            );
        }
        // Retained content survives: the observed REAL record (obs_rel, per
        // the master's observed seeding) + its observed tree, the pinned
        // REAL record + its tree, and every t2 ledger entry's content. (The
        // pool names p0..p2 survive only when a retained ledger or the
        // observed state references them — an unreferenced pool dir is
        // correctly swept; only the pin-/observed-retained records are
        // asserted unconditionally.)
        assert!(
            clone.release_dir(&obs_rel).exists(),
            "the observed release record survives"
        );
        assert!(
            clone.release_dir(&pinned).exists(),
            "the pinned release record survives"
        );
        assert!(
            clone
                .object_root(&test_tree_digest(PROPERTY_TREES[0]))
                .exists()
        );
        assert!(
            clone.object_root(&test_tree_digest(&pinned_tree)).exists(),
            "the pinned record's variant tree survives"
        );
        assert!(
            clone
                .deployment_dir(&test_deployment_id(&format!("dep-t1-{at}")))
                .exists()
        );
        for (i, &(r, t)) in t2_hist.iter().enumerate() {
            assert!(
                clone
                    .deployment_dir(&test_deployment_id(&format!("dep-t2-{i}")))
                    .exists()
            );
            assert!(
                clone
                    .release_dir(&crate::identity::test_release_id(PROPERTY_RELEASES[r]))
                    .exists()
            );
            assert!(
                clone
                    .object_root(&test_tree_digest(PROPERTY_TREES[t]))
                    .exists()
            );
        }
    }

    /// One parity case's generated shape: t1_len, t2_len, the checkpoint
    /// index into t1's history, and the per-entry artifact pool indices
    /// (release, tree) for t1's entries 1.. and for all of t2's entries
    /// (t1's entry 0 is the reserved pre-suffix-only pair, not generated).
    type ParityCase = (
        usize,
        usize,
        usize,
        Vec<(usize, usize)>,
        Vec<(usize, usize)>,
    );

    /// The parity case generator: t1_len >= 2, the checkpoint index `at` in
    /// 1..t1_len (the checkpoint always has pre-suffix content), t2_len >= 1,
    /// and the entry artifact refs (pool indices 0..3) for t1's entries
    /// 1.. and all of t2's entries (t1's entry 0 is the reserved (3, 3)
    /// pre-suffix-only pair).
    fn parity_case_strategy() -> impl Strategy<Value = ParityCase> {
        (2usize..=4usize)
            .prop_flat_map(|t1_len| (Just(t1_len), 1usize..t1_len, 1usize..=3usize))
            .prop_flat_map(|(t1_len, at, t2_len)| {
                (
                    Just(t1_len),
                    Just(at),
                    Just(t2_len),
                    proptest::collection::vec((0usize..3usize, 0usize..3usize), t1_len - 1),
                    proptest::collection::vec((0usize..3usize, 0usize..3usize), t2_len),
                )
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded `proptest_cases(4)` (full 4 with `DEPLOY_FULL_TESTS=1`,
            // fast default), fixed seed per house style.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// MULTI-TARGET PREVIEW == EXECUTION PARITY: for every generated
        /// two-target store (shared release/tree pool, observed state, pins,
        /// ghost content), the dry-run preview of a checkpoint on t1 must
        /// enumerate EXACTLY the deletion sets the same checkpoint performs
        /// on a cloned store.
        #[test]
        fn checkpoint_preview_deletions_exactly_match_execution(
            (t1_len, at, t2_len, t1_rest, t2_hist) in parity_case_strategy(),
        ) {
            run_preview_parity_case(t1_len, t2_len, at, &t1_rest, &t2_hist);
        }
    }
}

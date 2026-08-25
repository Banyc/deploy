//! Deployment history, rollback snapshots, and rollback reference handling.
//!
//! Only fully successful deployments produce a snapshot
//! (`refs/snapshots.jsonl`), and the SNAPSHOT LOG IS THE DEPLOYMENT HISTORY:
//! each successful deployment IS a rollback payload KEYED BY ITS DEPLOYMENT
//! ID (`deploy push <target> <deployment-id>` restores exactly that
//! deployment's stored state). Failed and degraded attempts remain visible
//! through `deploy log` and `attempts.jsonl` but are NOT valid rollback
//! sources — a failed deployment id never resolves. The separate snapshot
//! index (`sN`) has been REMOVED from the public surface: any internal
//! position the floor/compaction needs is DERIVED from the LOG ORDER (the
//! log is appended in deployment order), never stored as a public index.
//!
//! # History floor
//!
//! A checkpoint (`deploy checkpoint <target> <deployment-id>`) establishes a
//! monotonic history floor for the target, KEYED BY DEPLOYMENT ID: every
//! read here resolves against the FLOORED chain — [`LocalStore::read_snapshots`]
//! exposes only the suffix beginning at the checkpoint deployment's position
//! in the log, so the checkpoint deployment itself stays resolvable while
//! `@-` / `parent(...)` stepping below it (and any deployment id below it)
//! fails closed with a "history floor" ref error. Appends after a checkpoint
//! simply append (the log is deployment-keyed, so a new deployment id always
//! mints a new line — compaction can never reuse an identity).
//!
//! # Reference syntax (jj-style)
//!
//! The reference LANGUAGE is encapsulated in [`crate::revset`]: a pure,
//! store-free grammar whose [`crate::revset::parse_ref_expr`] returns only
//! the AST ([`RefExpr`] and friends, re-exported below) — no store access,
//! no resolution. This module keeps only the store-dependent RESOLUTION that
//! FOLLOWS the AST. Resolution is a TWO-PHASE process:
//!
//! * [`parse_ref_expr`] (in [`crate::revset`]) turns the token into a
//!   structured [`RefExpr`] with NO store access — pure syntax. The engine
//!   parses the token BEFORE it acquires locks or persists anything, so a
//!   malformed token fails before any side effect and the deployment id/plan
//!   are never serialized against a half-parsed reference.
//! * [`resolve_ref_expr`] turns the parsed expression into a concrete
//!   [`PushRef`] against the target's deployment history in the store. The
//!   engine calls it AFTER reconciliation
//!   ([`crate::push::reconcile::reconcile_pending_commits`]) has appended any
//!   recovered snapshots, so a relative ref is computed against the
//!   POST-reconciliation chain: `@-` means one before the latest INCLUDING
//!   this push's reconciled append, never a stale pre-recovery snapshot.
//!
//! The accepted forms — `` (empty)/`HEAD`/`@`, `@-`, `@--`, `parent(@, N)`,
//! the bare `<deployment-id>` (EXACT rollback to that deployment's stored
//! state), `<deployment-id>-`, `<deployment-id>--`,
//! `parent(<deployment-id>, N)`, and `release:<id>` (the DIRECT release
//! form) — and the legacy/removed forms they reject (the `sN` snapshot-index
//! forms, the `fN` prefix, the release-refid ancestor forms, and the legacy
//! combined forms) are documented in [`crate::revset`], which owns the
//! grammar. The push reference is jj-style: the TARGET IS NEVER REPEATED in
//! the reference, and the `@`-relative forms resolve against the
//! separately-given target argument. A deployment id resolves to EXACTLY
//! that deployment's stored state, and the ancestor steps walk the
//! DEPLOYMENT HISTORY from a base POSITION (the log order — positions are
//! DERIVED, never stored); stepping past the start of the chain, an
//! unresolvable deployment id, or an empty chain fail closed with a ref
//! error — never underflow, never guess.

use crate::error::{Error, Result};
use crate::model::{
    DeploymentId, GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, TargetName,
};
use crate::records::{
    AttemptServer, DeploymentAttempt, DeploymentSnapshot, DeploymentStatus, PhysicalBinding,
};
use crate::store::local::LocalStore;
use std::collections::BTreeMap;

/// The reference LANGUAGE (types + parser) is re-exported here from
/// [`crate::revset`], which owns the grammar; this module keeps only the
/// store-dependent RESOLUTION ([`resolve_ref_expr`]) that FOLLOWS the AST.
/// The re-export keeps the existing `history::parse_ref_expr` /
/// `history::RefExpr` call sites (push engine, plan, checkpoint) resolving
/// unchanged.
pub(crate) use crate::revset::{RefExpr, RelBase, parse_ref_expr};

/// A concrete push source reference (store + target already resolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRef {
    /// Materialize the currently mapped local files; assign configured variants.
    Head,
    /// Restore the stored state of a historical successful deployment, KEYED
    /// BY ITS DEPLOYMENT ID (`deploy push <target> <deployment-id>`, and the
    /// `@` / `parent(...)` walk of the deployment history).
    Deployment {
        target: TargetName,
        deployment_id: DeploymentId,
    },
    /// Assign each current server its configured variant from a named release
    /// (plans only when the target's CURRENT slot-id membership exactly
    /// matches the slot set the release record froze for it; physical
    /// bindings are not compared).
    Release { release: ReleaseId },
}

/// Resolve a parsed [`RefExpr`] to a concrete [`PushRef`] against the
/// separately-given `target` and the target's deployment history in `store`.
///
/// Store-DEPENDENT (unlike [`parse_ref_expr`]): reads the target's snapshot
/// log (the DEPLOYMENT HISTORY — each successful deployment is a rollback
/// payload keyed by its deployment id), so the caller must invoke it AFTER
/// reconciliation has appended any recovered snapshots — the engine parses
/// the token up front but resolves only once the chain is stable, so relative
/// refs see the reconciled append. The target is passed ONCE (the push
/// argument); the relative forms never repeat it. Failures are ref errors: an
/// empty chain, an unresolvable deployment id, and walking past the start of
/// the chain all fail closed rather than guessing.
pub(crate) fn resolve_ref_expr(
    expr: &RefExpr,
    target: &str,
    store: &LocalStore,
) -> Result<PushRef> {
    match expr {
        // `@` / `HEAD` / the default push: the current local files.
        RefExpr::Head => Ok(PushRef::Head),
        // The DIRECT release form: `release:<id>` maps straight to a
        // `PushRef::Release` — no deployment-history stepping, no target
        // history required (cross-target capable by design; the release's own
        // stored slot snapshot and the CURRENT target's slots are what the
        // plan resolves against — the release-versioned vs current membership
        // equality check runs at plan time, before any remote access).
        RefExpr::Release(release) => Ok(PushRef::Release {
            release: release.clone(),
        }),
        RefExpr::Relative(rel) => {
            // `parent(@, 0)` is the same as `@` itself: the current state.
            if rel.base == RelBase::At && rel.steps == 0 {
                return Ok(PushRef::Head);
            }
            // The deployment history IS the snapshot log, ordered by appends
            // (deployment order). POSITIONS are derived from that order —
            // there is no stored index — so the chain is a contiguous
            // position space and any position < len is a member.
            let entries = store.read_snapshots(target)?;
            let base_pos = resolve_base_pos(&rel.base, target, &entries, expr, store)?;
            let base_id = match &rel.base {
                RelBase::At => entries[base_pos].deployment_id.as_str(),
                RelBase::Refid(dep) => dep.as_str(),
            };
            let pos = base_pos.checked_sub(rel.steps as usize).ok_or_else(|| {
                Error::r#ref(format!(
                    "'{expr}' walks {} step(s) back from deployment '{base_id}' on target \
                    '{target}', before the start of the deployment history",
                    rel.steps
                ))
            })?;
            // The history floor gates resolution: the chain the read exposed is
            // already the suffix beginning at the checkpoint deployment
            // (read_snapshots filters by the durable marker), so a
            // below-floor position is structurally unreachable here — but the
            // explicit check documents the guarantee and guards any future
            // caller that resolves against a raw chain.
            if let Some(floor) = store.read_history_floor(target)?
                && let Some(fpos) = entries
                    .iter()
                    .position(|e| e.deployment_id == floor.deployment_id)
                && pos < fpos
            {
                return Err(Error::r#ref(format!(
                    "cannot roll back below the deployment floor (checkpoint {}) on target \
                    '{target}': history before the checkpoint has been discarded",
                    floor.deployment_id
                )));
            }
            Ok(PushRef::Deployment {
                target: TargetName::new(target.to_string()),
                deployment_id: entries[pos].deployment_id.clone(),
            })
        }
    }
}

/// Resolve a relative reference's base to a POSITION in the floored
/// deployment chain (the snapshot log in deployment order). `expr` renders
/// the reference for error messages (the parsed form has no raw token
/// anymore). The chain is the FLOORED read (the suffix beginning at the
/// checkpoint deployment), so a deployment id below the floor is absent;
/// when the target has a history floor, the absence is reported as a
/// below-floor refusal naming the checkpoint rather than a plain "no
/// deployment" error.
fn resolve_base_pos(
    base: &RelBase,
    target: &str,
    entries: &[DeploymentSnapshot],
    expr: &RefExpr,
    store: &LocalStore,
) -> Result<usize> {
    match base {
        RelBase::At => entries.len().checked_sub(1).ok_or_else(|| {
            Error::r#ref(format!(
                "no successful deployments for target '{target}'; cannot resolve '{expr}'"
            ))
        }),
        RelBase::Refid(dep) => match entries.iter().position(|e| e.deployment_id == *dep) {
            Some(pos) => Ok(pos),
            None => {
                // The history-floor hint: a deployment absent from the
                // FLOORED chain with a floor established sits strictly
                // before the checkpoint — either it is still in the RAW log
                // (an interrupted compaction) or the checkpoint's physical
                // compaction already discarded it. Both are "cannot roll
                // back below the history floor" — report the floor naming
                // it rather than a generic "no deployment" error (an id
                // that never existed stays a plain error).
                if let Some(floor) = store.read_history_floor(target)? {
                    let below_raw = store
                        .read_snapshots_raw(target)?
                        .iter()
                        .any(|e| e.deployment_id == *dep);
                    return Err(Error::r#ref(format!(
                        "cannot roll back below the history floor (checkpoint {}) on target \
                        '{target}': history before the checkpoint has been discarded{}",
                        floor.deployment_id,
                        if below_raw {
                            format!(" (deployment '{dep}' sits below it)")
                        } else {
                            format!(" (deployment '{dep}' was discarded with it)")
                        }
                    )));
                }
                Err(Error::r#ref(format!(
                    "no successful deployment '{dep}' on target '{target}'"
                )))
            }
        },
    }
}

/// Human-readable display name for a successful deployment's rollback
/// payload, e.g. `deployment deploy-abc of target production`.
pub fn ref_name(target: &TargetName, deployment_id: &DeploymentId) -> String {
    format!(
        "deployment {} of target {}",
        deployment_id.as_str(),
        target.as_str()
    )
}

/// Ensure the snapshot log contains exactly one successful snapshot for the
/// attempt's deployment ID, and that `refs/last-successful` points at it.
/// Returns the snapshot's deployment id (THE KEY — the log is deployment-
/// keyed; positions are derived from the log order, never stored).
///
/// This is the single idempotent insert used by BOTH the main success path
/// and recovery finalization, and it is replay-safe:
///
/// * If a snapshot with `deployment_id == attempt.deployment_id` already
///   exists (a previous finalization crashed after appending the snapshot but
///   before finishing), no second snapshot is appended: the existing
///   snapshot's key is returned. The log never contains two snapshots for
///   the same deployment ID.
/// * `refs/last-successful` is (re)written to the attempt's deployment ID in
///   both cases — idempotent, the same value on every replay — which also
///   repairs the stale ref left by a crash between the snapshot append and
///   the ref update.
///
/// The snapshot is built from the attempt's OUTCOMES (`outcomes`: the
/// per-slot actual state the engine observed — results.json on the main path,
/// or the verified desired state during recovery), NOT from the attempt
/// record itself: the persisted attempt is the immutable intent and its
/// `slots` map is empty.
///
/// # GC integration note (in-flight feature)
///
/// The snapshot payload (`slots`, `behavior_sha256`, `bindings`, and the
/// release its generations came from) is the INTERNAL rollback payload and is
/// kept INTACT here — keyed by deployment id. The GC retained-set rule
/// ("every snapshot at or above every floor") keys off the same deployment
/// identity: a retained set is every snapshot at or after the floor
/// deployment's POSITION in the log (derived, never stored). Any GC work
/// lands at that integration point; this function only guarantees the payload
/// survives, keyed by its deployment id.
pub fn ensure_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<DeploymentId> {
    let target = target.as_str();
    // RAW (floor-unfiltered) snapshot log: the key space is the deployment id
    // space. A checkpoint compacts the log to a suffix (the below-floor
    // deployments are discarded); a NEW deployment id always appends a NEW
    // line — compaction can never reuse an identity.
    let entries = store.read_snapshots_raw(target)?;
    if let Some(existing) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
    {
        store.write_last_successful(target, attempt.deployment_id.as_str())?;
        return Ok(existing.deployment_id.clone());
    }
    let entry = build_snapshot(attempt, outcomes, bindings);
    store.append_snapshot(target, &entry)?;
    store.write_last_successful(target, attempt.deployment_id.as_str())?;
    Ok(attempt.deployment_id.clone())
}

/// Append a successful snapshot to the snapshot log and return its
/// deployment id (the key).
///
/// Idempotent by deployment ID: delegates to
/// [`ensure_snapshot`], so re-running finalization for the same
/// attempt never duplicates the snapshot and always repairs
/// `refs/last-successful`. Kept as the historical name; the main success
/// path now finalizes through the shared
/// [`finalize_successful_attempt`], which calls this. The snapshot is built
/// from the attempt's OUTCOMES map, not the attempt record (see
/// [`ensure_snapshot`]).
pub fn append_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<DeploymentId> {
    ensure_snapshot(store, target, attempt, outcomes, bindings)
}

/// Finalize a successful deployment attempt replay-safely: the single shared
/// terminal path used by BOTH the normal push success path and recovery
/// ([`crate::push::reconcile::reconcile_pending_commits`]).
///
/// The snapshot is built from the attempt's OUTCOMES (`outcomes`: per-slot
/// actual state observed by the engine — live actuals on the main path,
/// results.json or the verified desired state during recovery), never from
/// the attempt record itself (the persisted attempt is the immutable intent;
/// its `slots` map is empty).
///
/// Persistence order:
/// 1. RECOVERABLE MARKER: ensure the attempt's LATEST transition is
///    `PendingCommit`, appending a `PendingCommit` transition (reason
///    "finalization started") only when the latest is not already
///    `PendingCommit`. The latest transition is recovery's eligibility
///    gate, so a crash at any later point leaves the attempt re-eligible and
///    the next push replays exactly the remaining steps. On the main path the
///    attempt's latest is `InProgress` here (this appends `PendingCommit`);
///    in recovery it is already `PendingCommit` (a no-op).
/// 2. SNAPSHOT + REF: [`ensure_snapshot`] — idempotent by deployment ID (a
///    replay never appends a second entry) and (re)writes
///    `refs/last-successful`, repairing a stale ref left by a crash between
///    the snapshot append and the ref update.
/// 3. STATUS LAST: append the terminal `Successful` transition with `reason`
///    only after every durable step, so the attempt is never recorded
///    `Successful` while its snapshot is missing.
///
/// Replay idempotency: step 1 is skipped when the latest transition is
/// already `PendingCommit`; step 2 is a no-op (or ref repair) when the
/// snapshot entry already exists; step 3 appends exactly once — a crash
/// before it leaves the attempt eligible, and a crash after it means every
/// earlier step is already durable (and the eligibility gate skips the
/// attempt forever once the latest transition says `Successful`).
///
/// Returns the attempt's snapshot deployment id (the rollback key).
pub fn finalize_successful_attempt(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    reason: &str,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<DeploymentId> {
    let id = attempt.deployment_id.as_str();
    // Already fully finalized (the eligibility gate normally prevents this):
    // every earlier step is durable by construction; only repair a stale
    // `refs/last-successful` and stop without appending anything.
    if store.latest_status(id)? == Some(DeploymentStatus::Successful) {
        return ensure_snapshot(store, &attempt.target, attempt, outcomes, bindings);
    }
    // 1. Recoverable marker: the attempt must be re-eligible if we crash
    //    before the snapshot lands.
    if store.latest_status(id)? != Some(DeploymentStatus::PendingCommit) {
        store.append_transition(
            id,
            &DeploymentStatus::PendingCommit,
            Some("finalization started"),
        )?;
    }
    // 2. Snapshot entry + `refs/last-successful` (idempotent).
    let dep = ensure_snapshot(store, &attempt.target, attempt, outcomes, bindings)?;
    // 3. Terminal status LAST.
    store.append_transition(id, &DeploymentStatus::Successful, Some(reason))?;
    Ok(dep)
}

/// Resolve the per-slot outcomes used to build a successful snapshot
/// when the engine no longer has the live outcomes at hand (recovery): the
/// persisted results (`deployments/<id>/results.json`) when present — a
/// crash after the mutation loop but before/within finalization — otherwise
/// the attempt's verified desired state (a crash before outcomes were
/// persisted, e.g. a faulted `write_results`).
///
/// The per-slot ARTIFACT always resolves from the attempt's desired
/// assignment: results.json records outcomes (generation, status) but not
/// artifacts, and recovery already verified each slot's current generation
/// equals the desired generation. Slots without a recorded generation are
/// not part of a coherent successful snapshot and are dropped by
/// [`build_snapshot`].
pub fn resolve_attempt_outcomes(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
) -> Result<BTreeMap<PlacementSlotId, AttemptServer>> {
    // `read_results` fails when `results.json` is absent (crash before the
    // outcomes were persisted); treat that as "verified desired state only".
    let results = store.read_results(attempt.deployment_id.as_str()).ok();
    let mut outcomes = BTreeMap::new();
    for sid in &attempt.slot_ids {
        let Some(desired) = attempt.desired.get(sid) else {
            continue;
        };
        let generation = results
            .as_ref()
            .and_then(|r| r.slots.get(sid).and_then(|sr| sr.generation.clone()))
            .or_else(|| Some(desired.generation.clone()));
        outcomes.insert(
            sid.clone(),
            AttemptServer {
                artifact: desired.assignment.artifact.clone(),
                generation,
            },
        );
    }
    Ok(outcomes)
}

/// Build a snapshot entry from the attempt's OUTCOMES (per-slot actual
/// state), not from the attempt record: the persisted attempt is the
/// immutable intent (its `slots` map is empty), so the snapshot must be
/// built from the outcomes the engine observed — live per-slot actuals on
/// the main path, or results.json / the verified desired state during
/// recovery ([`resolve_attempt_outcomes`]). A successful snapshot
/// carries one complete [`GenerationRef`] per slot; slots without a
/// recorded generation are not part of a coherent successful snapshot and
/// are dropped.
///
/// The snapshot is KEYED BY THE ATTEMPT'S DEPLOYMENT ID (the old numeric
/// `index`/`sN` identity is gone — the log is deployment-keyed and ordered
/// by appends; positions are derived, never stored).
///
/// `bindings` records the COMPLETE physical binding (`{server, deploy_dir}`)
/// each slot had when the deployment ran (the engine passes the target's
/// current slot→binding map from `deploy.toml`). It is stored as a separate
/// map so the `slots` map and its [`GenerationRef`]s stay intact; a legacy
/// entry with no bindings map deserializes to an empty one (unverifiable,
/// so rollback refuses rather than guessing the host/location).
pub fn build_snapshot(
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> DeploymentSnapshot {
    DeploymentSnapshot {
        deployment_id: attempt.deployment_id.clone(),
        target: attempt.target.clone(),
        behavior_sha256: attempt.behavior_sha256.clone(),
        slots: outcomes
            .iter()
            .filter_map(|(slot, s)| {
                s.generation.clone().map(|generation| {
                    (
                        slot.clone(),
                        GenerationRef {
                            generation,
                            assignment: PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: s.artifact.clone(),
                            },
                        },
                    )
                })
            })
            .collect(),
        bindings: bindings.clone(),
    }
}

/// Resolve a deployment id to its stored rollback payload (the snapshot the
/// deployment produced). The id must be a SUCCESSFUL deployment of the
/// target (it must own a snapshot in the floored log); failed and degraded
/// attempts never resolve.
pub fn resolve_deployment(
    store: &LocalStore,
    target: &TargetName,
    deployment_id: &DeploymentId,
) -> Result<DeploymentSnapshot> {
    let target = target.as_str();
    let entries = store.read_snapshots(target)?;
    entries
        .into_iter()
        .find(|e| e.deployment_id == *deployment_id)
        .ok_or_else(|| {
            Error::r#ref(format!(
                "no successful deployment '{deployment_id}' for target '{target}'"
            ))
        })
}

/// Reconstruct the set of successful deployments for a target from the
/// snapshot log (used to rebuild history from servers when the local ref is
/// stale). The log order IS the deployment order.
pub fn successful_snapshots(
    store: &LocalStore,
    target: &TargetName,
) -> Result<Vec<DeploymentSnapshot>> {
    store.read_snapshots(target.as_str())
}

/// Collect the distinct placement slot IDs referenced across a set of attempts.
pub fn attempt_slot_ids(attempt: &DeploymentAttempt) -> Vec<PlacementSlotId> {
    attempt.slot_ids.clone()
}

/// Build a map of rollback display names (`deployment <deployment-id> of
/// target <target>`) -> snapshot.
pub fn deployment_index(
    store: &LocalStore,
    target: &TargetName,
) -> Result<BTreeMap<String, DeploymentSnapshot>> {
    let mut out = BTreeMap::new();
    for e in store.read_snapshots(target.as_str())? {
        out.insert(ref_name(target, &e.deployment_id), e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactRef, DeploymentId, GenerationId, PlacementSlotId, ReleaseId, SCHEMA_VERSION,
        ServerId, TreeDigest, VariantName,
    };
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};
    use std::collections::BTreeMap;

    use crate::records::HistoryFloor;

    // The reference-language test helpers (grammar generators, the
    // canonical fold, and the panic-free parse runner) live with the
    // parser in [`crate::revset::tests`]; the resolve leg imports them so
    // the parse/resolve contract stays pinned in ONE place.
    use crate::revset::tests::{fold, parse_no_panic, ref_token_strategy};

    /// A `deploy-<id>` deployment-id refid parses to a deployment base.
    /// deploy-a..deploy-f (every deployment SUCCESSFUL, so every one is a
    /// rollback payload; the deploy-c and deploy-d snapshots BOTH carry
    /// release rel-sha256-cccc — irrelevant now that release refids are
    /// removed, but kept to pin the payload contents).
    fn chain() -> (tempfile::TempDir, LocalStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for (n, (dep, rel)) in [
            ("deploy-a", "aaaa"),
            ("deploy-b", "bbbb"),
            ("deploy-c", "cccc"),
            ("deploy-d", "cccc"),
            ("deploy-e", "eeee"),
            ("deploy-f", "ffff"),
        ]
        .iter()
        .enumerate()
        {
            store
                .append_snapshot("production", &snapshot_entry(dep, rel))
                .unwrap();
            let _ = n;
        }
        (tmp, store)
    }

    fn snapshot_entry(deployment: &str, release: &str) -> DeploymentSnapshot {
        DeploymentSnapshot {
            deployment_id: DeploymentId::new(deployment.to_string()),
            target: TargetName::new("production".to_string()),
            behavior_sha256: "sha256-aa".to_string(),
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new(format!("gen-{deployment}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new(format!("rel-sha256-{release}")),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new(format!("tree-{deployment}")),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new("server-01".to_string()),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            )]),
        }
    }

    fn dep_ref(target: &TargetName, deployment_id: &str) -> PushRef {
        PushRef::Deployment {
            target: target.clone(),
            deployment_id: DeploymentId::new(deployment_id.to_string()),
        }
    }

    /// Parse-then-resolve a token against the store, mirroring the engine's
    /// two-phase flow (parse first, resolve later).
    fn resolve(token: &str, store: &LocalStore) -> Result<PushRef> {
        resolve_ref_expr(&parse_ref_expr(token)?, "production", store)
    }

    /// `@` / `HEAD` / `` / `parent(@, 0)` resolve to the default HEAD push.
    #[test]
    fn resolve_ref_head_forms() {
        let (_tmp, store) = chain();
        for token in ["", "HEAD", "@", "parent(@, 0)"] {
            assert_eq!(
                resolve(token, &store).unwrap(),
                PushRef::Head,
                "{token:?} must resolve to Head"
            );
        }
    }

    /// The documented `parent(@, 0) ≡ @` fold holds even on an EMPTY store:
    /// `resolve_ref_expr` short-circuits `Relative { base: At, steps: 0 }`
    /// to `PushRef::Head` BEFORE the chain read — no store access — so the
    /// empty chain never rejects it. This pins the fold that the
    /// ref-grammar resolve property's oracle mirrors, and contrasts it with
    /// a genuinely store-dependent relative (`@-`), which still fails
    /// closed on the empty store.
    #[test]
    fn resolve_parent_at_0_fold_on_empty_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for token in ["@", "parent(@, 0)"] {
            assert_eq!(
                resolve(token, &store).unwrap(),
                PushRef::Head,
                "{token:?} must fold to Head without touching the empty store"
            );
        }
        assert!(
            matches!(resolve("@-", &store), Err(Error::Ref(_))),
            "a store-dependent relative must still fail closed on an empty store"
        );
    }

    /// The ancestor steps on the deploy-a..deploy-f chain (latest =
    /// deploy-f): `@-` = deploy-e, `@--` = deploy-d, `parent(@, 3)` =
    /// deploy-c, `deploy-f--` = deploy-d, `parent(deploy-f, 2)` = deploy-d,
    /// `deploy-b-` = deploy-a, and the bare `deploy-b` / `parent(deploy-b, 0)`
    /// forms name deploy-b itself.
    #[test]
    fn resolve_ref_ancestor_steps() {
        let (_tmp, store) = chain();
        let target = TargetName::new("production".to_string());
        for (token, want) in [
            ("@-", "deploy-e"),
            ("@--", "deploy-d"),
            ("parent(@, 3)", "deploy-c"),
            ("parent(@, 2)", "deploy-d"),
            ("deploy-c--", "deploy-a"),
            ("parent(deploy-f, 2)", "deploy-d"),
            ("deploy-b-", "deploy-a"),
            ("deploy-b", "deploy-b"),
            ("parent(deploy-b, 0)", "deploy-b"),
            ("parent(deploy-c, 1)", "deploy-b"),
        ] {
            assert_eq!(
                resolve(token, &store).unwrap(),
                dep_ref(&target, want),
                "{token} must resolve to deployment {want}"
            );
        }
    }

    /// A deployment refid resolves to the snapshot that deployed it (its
    /// own stored state — exact rollback); the ancestor steps walk the
    /// deployment history back from there.
    #[test]
    fn resolve_ref_deployment_refids() {
        let (_tmp, store) = chain();
        let target = TargetName::new("production".to_string());
        assert_eq!(
            resolve("deploy-b", &store).unwrap(),
            dep_ref(&target, "deploy-b")
        );
        assert_eq!(
            resolve("deploy-b-", &store).unwrap(),
            dep_ref(&target, "deploy-a")
        );
        assert_eq!(
            resolve("parent(deploy-c, 0)", &store).unwrap(),
            dep_ref(&target, "deploy-c")
        );
        assert_eq!(
            resolve("parent(deploy-f, 4)", &store).unwrap(),
            dep_ref(&target, "deploy-b")
        );
        // The bare deployment id resolves to EXACTLY that deployment's stored
        // payload (the snapshot keyed by the id), never "the most recent
        // snapshot" of anything.
        let entry = resolve_deployment(&store, &target, &DeploymentId::new("deploy-c")).unwrap();
        assert_eq!(entry.deployment_id.as_str(), "deploy-c");
        assert_eq!(
            entry.slots[&PlacementSlotId::new("p1")].generation.as_str(),
            "gen-deploy-c"
        );
    }

    /// `release:<id>` resolves DIRECTLY to a `PushRef::Release` — with NO
    /// store lookup and NO target history: the direct form never steps the
    /// deployment history, so a cross-target / fresh-target direct
    /// deployment is expressible even when the destination has zero
    /// snapshots. This is the grammar's escape hatch for
    /// direct/cross-target release deployment (UNCHANGED).
    #[test]
    fn resolve_ref_direct_release_form_ignores_chain_and_store() {
        let (_tmp, store) = chain();
        assert_eq!(
            resolve_ref_expr(
                &parse_ref_expr("release:rel-sha256-cccc").expect("token must parse"),
                "production",
                &store
            )
            .unwrap(),
            PushRef::Release {
                release: ReleaseId::new("rel-sha256-cccc".to_string())
            }
        );
        assert_eq!(
            resolve_ref_expr(
                &parse_ref_expr("release:cccc").expect("token must parse"),
                "production",
                &store
            )
            .unwrap(),
            PushRef::Release {
                release: ReleaseId::new("rel-sha256-cccc".to_string())
            }
        );
        // A release that is not referenced by any snapshot — and a target
        // with an EMPTY chain — resolve the same way: resolution never reads
        // the store.
        let tmp = tempfile::tempdir().unwrap();
        let empty = LocalStore::with_base(tmp.path().join("store")).unwrap();
        assert_eq!(
            resolve_ref_expr(
                &parse_ref_expr("release:rel-sha256-zzzz").expect("must parse"),
                "brand-new-target",
                &empty
            )
            .unwrap(),
            PushRef::Release {
                release: ReleaseId::new("rel-sha256-zzzz".to_string())
            }
        );
    }

    /// Out-of-range and unresolvable references fail closed with a ref
    /// error: stepping before the chain start, a missing deployment id, and
    /// an EMPTY chain. Never underflow, never guess.
    #[test]
    fn resolve_ref_failures_fail_closed() {
        let (_tmp, store) = chain();
        for token in [
            "parent(@, 6)", // len 6, so 6 steps back underflows
            "deploy-a-",    // deploy-a is the first deployment
            "deploy-a--",
            "parent(deploy-b, 2)",
            "parent(deploy-a, 1)",
            "deploy-missing",
            "deploy-missing-",
            "parent(deploy-missing, 1)",
        ] {
            let err = resolve(token, &store).expect_err(&format!("{token} must fail closed"));
            assert!(
                err.to_string().contains("reference") || err.to_string().contains("step(s) back"),
                "{token} error must be a ref error, got: {err}"
            );
        }

        // An EMPTY target chain: `@` is still fine (HEAD), every relative
        // form fails.
        let tmp = tempfile::tempdir().unwrap();
        let empty = LocalStore::with_base(tmp.path().join("store")).unwrap();
        assert_eq!(resolve("@", &empty).unwrap(), PushRef::Head);
        for token in ["@-", "parent(@, 2)", "deploy-x", "deploy-x-"] {
            resolve(token, &empty).expect_err(&format!("{token} on an empty chain must fail"));
        }
    }

    #[test]
    fn ref_name_deployment() {
        assert_eq!(
            ref_name(
                &TargetName::new("production".to_string()),
                &DeploymentId::new("deploy-abc")
            ),
            "deployment deploy-abc of target production"
        );
    }

    #[test]
    fn append_snapshot_is_idempotent_by_deployment_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::new("production".to_string());
        let bindings: BTreeMap<PlacementSlotId, PhysicalBinding> = BTreeMap::from([(
            PlacementSlotId::new("p1"),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);
        let attempt = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-idempotent".to_string()),
            target: target.clone(),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // First call appends the snapshot and advances the ref. The snapshot
        // is built from the attempt's OUTCOMES map (the attempt record
        // itself carries only intent; its `slots` map is empty), and records
        // the slot→{server, deploy_dir} binding from `bindings`.
        let first = append_snapshot(&store, &target, &attempt, &attempt.slots, &bindings).unwrap();
        assert_eq!(first, attempt.deployment_id);
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, attempt.deployment_id);
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );

        // Second call with the same deployment ID is a no-op: same key, no
        // duplicate entry, and `refs/last-successful` is untouched.
        let second = append_snapshot(&store, &target, &attempt, &attempt.slots, &bindings).unwrap();
        assert_eq!(second, first, "repeated append must return the same key");
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1, "no duplicate snapshot entry");
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );
    }

    #[test]
    fn build_snapshot_records_each_slots_physical_binding() {
        let slot = PlacementSlotId::new("p1".to_string());
        let attempt = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-binding-map".to_string()),
            target: TargetName::new("production".to_string()),
            slot_ids: vec![slot.clone()],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::from([(
                slot.clone(),
                crate::records::AttemptServer {
                    artifact: ArtifactRef::default(),
                    generation: Some(GenerationId::new("gen-x".to_string())),
                },
            )]),
        };
        let bindings: BTreeMap<PlacementSlotId, PhysicalBinding> = BTreeMap::from([(
            slot.clone(),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);

        let snapshot = build_snapshot(&attempt, &attempt.slots, &bindings);
        assert_eq!(
            snapshot.bindings.get(&slot),
            Some(&PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            }),
            "the snapshot must record the slot's complete physical binding (server AND deploy_dir)"
        );
        assert_eq!(snapshot.slots.len(), 1, "generation refs preserved intact");
        assert_eq!(snapshot.bindings.len(), 1);
    }

    /// A legacy pre-feature snapshot line (no `bindings` key — either the
    /// oldest pre-binding shape or the intermediate shape that only recorded
    /// a `servers` map) must still deserialize; its `bindings` map defaults
    /// to empty, which rollback treats as unverifiable rather than guessing
    /// the host/location. The removed `index` key is an unknown field now and
    /// is IGNORED — legacy `sN`-era logs stay readable (the payload is what
    /// matters; the deployment id is the key).
    #[test]
    fn legacy_snapshot_without_bindings_deserializes_with_empty_map() {
        // Oldest shape: no binding recorded at all (and the removed `index`
        // key — ignored by the deployment-keyed record).
        let bare = r#"{"index":0,"deployment_id":"deploy-old","target":"production","behavior_sha256":"sha256-aa","slots":{}}"#;
        let snapshot: DeploymentSnapshot = serde_json::from_str(bare).unwrap();
        assert!(
            snapshot.bindings.is_empty(),
            "legacy line without bindings yields an empty map"
        );

        // Intermediate server-only shape: the `servers` key is an unknown
        // field now (the physical binding is richer than a bare ServerId),
        // so it is ignored and `bindings` still defaults to empty →
        // fail-closed refusal.
        let with_servers = r#"{"index":1,"deployment_id":"deploy_servers","target":"production","behavior_sha256":"sha256-aa","slots":{},"servers":{"p1":"server-01"}}"#;
        let snapshot: DeploymentSnapshot = serde_json::from_str(with_servers).unwrap();
        assert!(
            snapshot.bindings.is_empty(),
            "old `servers`-keyed line yields an empty bindings map"
        );
    }

    /// A deployment-history shape: 0..=8 (deployment_id, successful?) pairs
    /// (a FAILED deployment never gets a snapshot — the two-class history the
    /// user's property needs). Deployment ids are DETERMINISTIC PER POSITION
    /// (`deploy-{n:04}`), so each id is unique across the history and a
    /// FAILED id can never double as a SUCCESSFUL one (which would make
    /// "failed ids never resolve" vacuous). Plus an optional durable floor
    /// at a SUCCESSFUL deployment (never None on an empty chain or when the
    /// generated slot overruns the successes).
    fn chain_strategy() -> impl Strategy<Value = (Vec<(String, bool)>, Option<String>)> {
        (
            prop::collection::vec(any::<bool>(), 0..=8),
            prop::option::weighted(0.6, 0usize..8),
        )
            .prop_map(|(flags, floor_slot)| {
                let history: Vec<(String, bool)> = flags
                    .into_iter()
                    .enumerate()
                    .map(|(n, ok)| (format!("deploy-{n:04}"), ok))
                    .collect();
                let ok_ids: Vec<String> = history
                    .iter()
                    .filter(|(_, ok)| *ok)
                    .map(|(id, _)| id.clone())
                    .collect();
                let floor = floor_slot.and_then(|i| ok_ids.get(i).cloned());
                (history, floor)
            })
    }

    /// A minimal attempt record for the target, enough to bind a seeded
    /// history floor (the floor's own deployment must exist in the target's
    /// attempts log).
    fn attempt_entry(dep: &str) -> DeploymentAttempt {
        DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(dep.to_string()),
            target: TargetName::new("production".to_string()),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    /// THE USER'S PROPERTY, per resolve-leg case: seed a REAL store with a
    /// deployment history (successful + FAILED attempts interleaved — a
    /// failed attempt records an attempt + a `deployments/<id>/` dir but NO
    /// snapshot), optionally checkpoint it at a successful deployment, then
    /// assert that EVERY successful deployment id resolves to EXACTLY its
    /// stored state, every FAILED id never resolves (ref error), and the
    /// floored chain is exactly the suffix beginning at the checkpoint.
    fn assert_deployment_id_resolution(store: &LocalStore, history: &[(String, bool)]) {
        let target = TargetName::new("production".to_string());
        let stored: BTreeMap<String, DeploymentSnapshot> = store
            .read_snapshots("production")
            .unwrap()
            .into_iter()
            .map(|e| (e.deployment_id.as_str().to_string(), e))
            .collect();
        for (id, ok) in history {
            let expr = parse_ref_expr(id).expect("a seeded deployment id parses");
            match resolve_ref_expr(&expr, "production", store) {
                Ok(PushRef::Deployment {
                    deployment_id,
                    target: t,
                }) => {
                    assert!(
                        *ok,
                        "a FAILED deployment id ('{id}') must never resolve — got a deployment ref"
                    );
                    assert_eq!(t.as_str(), "production");
                    assert_eq!(deployment_id.as_str(), *id);
                    // EXACTLY its stored state: the resolved payload equals
                    // the recorded snapshot (slots, behavior, bindings, and
                    // the release the generations came from), keyed by id.
                    let resolved = resolve_deployment(store, &target, &deployment_id).unwrap();
                    assert_eq!(
                        &resolved,
                        stored.get(id).expect("the stored snapshot"),
                        "deployment '{id}' must resolve to EXACTLY its stored payload"
                    );
                }
                Ok(PushRef::Head | PushRef::Release { .. }) => {
                    panic!("deployment id '{id}' must not resolve to a non-deployment ref")
                }
                Err(Error::Ref(_)) => {
                    // FAILED ids never resolve; a SUCCESSFUL id resolves only
                    // when at/above the floor (a below-floor id fails closed
                    // with the floor refusal — asserted by the floor checks).
                }
                Err(e) => panic!("unexpected error class for '{id}': {e}"),
            }
        }
    }

    /// One resolve-leg case: seed a REAL store with a deployment history
    /// (successful + failed attempts), optionally floor it at a successful
    /// deployment, parse a generated token, and resolve it via the engine's
    /// two-phase flow. Asserts: no panic anywhere; every parse AND resolve
    /// failure is a ref error; a rejected shape never resolves; a resolved
    /// deployment is an actual member of the FLOORED chain at/after the
    /// floor; the deployment-id resolution property (successful ids resolve
    /// to exactly their stored state, failed ids never resolve) holds;
    /// `@` / `release:<id>` never touch the chain (they resolve even on an
    /// EMPTY store, while every relative form on an empty store fails closed
    /// — except `parent(@, 0)`, which the oracle folds to `Head` FIRST so it
    /// mirrors the engine's documented `Relative{At,0} ≡ Head` reduction).
    fn ref_grammar_resolve_case(
        history: Vec<(String, bool)>,
        floor: Option<String>,
        token: String,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for (id, ok) in &history {
            store
                .append_attempt("production", &attempt_entry(id))
                .unwrap();
            std::fs::create_dir_all(store.deployment_dir(id)).unwrap();
            if *ok {
                // Each successful deployment is a rollback payload keyed by
                // its id, with a deterministic payload derived from the id
                // (so "exactly its stored state" is a meaningful equality).
                let release = id.replace("deploy-", "rel-sha256-");
                store
                    .append_snapshot("production", &snapshot_entry(id, &release))
                    .unwrap();
            }
        }
        if let Some(fid) = &floor {
            store
                .write_history_floor(
                    "production",
                    &HistoryFloor {
                        schema_version: SCHEMA_VERSION,
                        target: TargetName::new("production".to_string()),
                        deployment_id: DeploymentId::new(fid.clone()),
                        established_at: "2026-01-01T00:00:00Z".to_string(),
                    },
                )
                .unwrap();
        }

        // THE USER'S PROPERTY (per case): successful ids resolve to exactly
        // their stored state, failed ids never resolve, and the floored chain
        // is exactly the suffix beginning at the floor deployment.
        assert_deployment_id_resolution(&store, &history);

        // Two-phase engine flow: parse first — a parse failure is a ref
        // error and the expression NEVER reaches resolution (a rejected
        // shape never resolves).
        let expr = match parse_no_panic(&token) {
            // Apply the engine's canonical fold to the parsed expression
            // BEFORE resolution, so the oracle and the engine agree on the
            // same reduced form: `parent(@, 0)` becomes `Head` (the engine
            // short-circuits `Relative{At,0}` to `PushRef::Head` before any
            // store read), and every other expression passes through
            // unchanged (the fold is a no-op for them).
            Ok(expr) => fold(expr),
            Err(err) => {
                assert!(
                    matches!(err, Error::Ref(_)),
                    "parse failure for {token:?} must be a ref error, got: {err}"
                );
                return;
            }
        };

        let result = std::panic::catch_unwind(|| resolve_ref_expr(&expr, "production", &store))
            .expect("resolve_ref_expr must never panic");

        // Fail-closed: every resolve failure is a ref error (the seeded
        // store is healthy, so only the ref contract can reject).
        if let Err(err) = &result {
            assert!(
                matches!(err, Error::Ref(_)),
                "resolve failure for {token:?} must be a ref error, got: {err}"
            );
        }

        // On an EMPTY store, `@`/HEAD/`release:<id>` still resolve — no
        // chain touch — while every relative form fails closed. `expr` was
        // already folded above, so the `parent(@, 0)` case is judged by the
        // Head arm (exactly what the engine does before its store read).
        if history.iter().all(|(_, ok)| !*ok) {
            match &expr {
                RefExpr::Head | RefExpr::Release(_) => assert!(
                    matches!(result, Ok(PushRef::Head | PushRef::Release { .. })),
                    "{token:?} on an empty store must resolve without touching the chain, got: {result:?}"
                ),
                RefExpr::Relative(_) => assert!(
                    matches!(result, Err(Error::Ref(_))),
                    "{token:?} on an empty store must fail closed with a ref error, got: {result:?}"
                ),
            }
        }

        // RESOLVE MEMBERSHIP: a resolved deployment is an actual member of
        // the floored read chain, at/after the floor.
        match result {
            Ok(PushRef::Deployment {
                target,
                deployment_id,
            }) => {
                assert_eq!(
                    target.as_str(),
                    "production",
                    "{token:?} must resolve against the passed target"
                );
                let floored = store.read_snapshots("production").unwrap();
                assert!(
                    floored.iter().any(|e| e.deployment_id == deployment_id),
                    "{token:?} resolved to deployment '{deployment_id}', which is not an actual \
                     member of the floored chain {floored:?}"
                );
                if let Some(fid) = &floor {
                    let fpos = floored
                        .iter()
                        .position(|e| e.deployment_id.as_str() == *fid)
                        .expect("the floor deployment is in the floored chain");
                    let pos = floored
                        .iter()
                        .position(|e| e.deployment_id == deployment_id)
                        .unwrap();
                    assert!(
                        pos >= fpos,
                        "{token:?} resolved below the deployment floor {fid}: {deployment_id}"
                    );
                }
            }
            Ok(PushRef::Head | PushRef::Release { .. }) => {}
            Err(_) => {}
        }
    }

    proptest! {
        // The RESOLVE leg — against a REAL seeded store per case (a
        // successful + failed deployment history plus an optional durable
        // floor at a successful deployment): the user's deployment-id
        // resolution property, resolve membership, and totality. Randomized
        // seeds + failure persistence, bounded at 96 cases (each case builds
        // a small tempdir store, so the bound keeps the suite fast).
        #![proptest_config(ProptestConfig {
            cases: 96,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ref_grammar_resolve_contract(
            (history, floor) in chain_strategy(),
            token in ref_token_strategy(),
        ) {
            ref_grammar_resolve_case(history, floor, token);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION for the resolve leg: the user's property
        // (every successful deployment id resolves to exactly its stored
        // state; failed ids never resolve) under the pinned 0x5EED_5EED
        // seed — the identical vectors on every invocation.
        #![proptest_config(ProptestConfig {
            cases: 96,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ref_grammar_resolve_contract_fixed_seed(
            (history, floor) in chain_strategy(),
            token in ref_token_strategy(),
        ) {
            ref_grammar_resolve_case(history, floor, token);
        }
    }
}

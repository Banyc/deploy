//! Deployment snapshot history, rollback snapshots, and rollback reference
//! handling.
//!
//! Only fully successful deployments produce a snapshot
//! (`refs/snapshots.jsonl`), exposed as the indices `s0`, `s1`, and so on
//! (`ref_name` renders them `snapshot s0 of target production` for display). Failed and degraded
//! attempts remain visible through `deploy log` and `attempts.jsonl` but are
//! not valid rollback sources.
//!
//! # History floor
//!
//! A checkpoint (`deploy checkpoint <target> <deployment-id>`) establishes a
//! monotonic history floor for the target: every read here resolves against
//! the FLOORED chain — [`LocalStore::read_snapshots`] exposes only the suffix
//! at/after the checkpoint's snapshot index, so the checkpoint snapshot
//! itself stays resolvable while `sN` / `parent(...)` / `@-` stepping below
//! it fails closed with a "history floor" ref error. Appends after a
//! checkpoint mint the next unique index from the RAW physical log
//! ([`ensure_snapshot`]), so compaction can never reuse an index.
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
//!   [`PushRef`] against the target's snapshot chain in the store. The engine
//!   calls it AFTER reconciliation
//!   ([`crate::push::reconcile::reconcile_pending_commits`]) has appended any
//!   recovered snapshots, so a relative ref is computed against the
//!   POST-reconciliation chain: `@-` means one before the latest INCLUDING
//!   this push's reconciled append, never a stale pre-recovery snapshot.
//!
//! The accepted forms — `` (empty)/`HEAD`/`@`, `@-`, `@--`, `parent(@, N)`,
//! `release:<id>`, `<refid>-`, `<refid>--`, `parent(<refid>, N)`, and the
//! bare refid itself (`s3`, `deploy-...`, `rel-sha256-...`/hex digest) —
//! and the legacy forms they reject are documented in [`crate::revset`].
//! The push reference is jj-style: the TARGET IS NEVER REPEATED in the
//! reference, and the `@`-relative forms resolve against the separately-given
//! target argument. A deployment/release refid resolves to the MOST RECENT
//! snapshot that deployed that deployment / references that release, and the
//! ancestor steps walk `s(index - N)`; stepping past the start of the chain,
//! an unresolvable refid, or an empty chain fail closed with a ref error —
//! never underflow, never guess.

use crate::error::{Error, Result};
use crate::model::{
    GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, TargetName,
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
pub(crate) use crate::revset::{RefExpr, RefId, RelBase, parse_ref_expr};

/// A concrete push source reference (store + target already resolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRef {
    /// Materialize the currently mapped local files; assign configured variants.
    Head,
    /// Restore a historical successful snapshot by index.
    Snapshot { target: TargetName, index: u64 },
    /// Assign each current server its configured variant from a named release
    /// (plans only when the target's CURRENT slot-id membership exactly
    /// matches the slot set the release record froze for it; physical
    /// bindings are not compared).
    Release { release: ReleaseId },
}

/// Resolve a parsed [`RefExpr`] to a concrete [`PushRef`] against the
/// separately-given `target` and the target's snapshot chain in `store`.
///
/// Store-DEPENDENT (unlike [`parse_ref_expr`]): reads the target's snapshot
/// chain, so the caller must invoke it AFTER reconciliation has appended any
/// recovered snapshots — the engine parses the token up front but resolves
/// only once the chain is stable, so relative refs see the reconciled append.
/// The target is passed ONCE (the push argument); the relative forms never
/// repeat it. Failures are ref errors: an empty chain, an unresolvable
/// refid, and walking past the start of the chain all fail closed rather
/// than guessing.
pub(crate) fn resolve_ref_expr(
    expr: &RefExpr,
    target: &str,
    store: &LocalStore,
) -> Result<PushRef> {
    match expr {
        // `@` / `HEAD` / the default push: the current local files.
        RefExpr::Head => Ok(PushRef::Head),
        // The DIRECT release form: `release:<id>` maps straight to a
        // `PushRef::Release` — no snapshot-chain stepping, no target history
        // required (cross-target capable by design; the release's own stored
        // slot snapshot and the CURRENT target's slots are what the plan
        // resolves against — the release-versioned vs current membership
        // equality check runs at plan time, before any remote access).
        RefExpr::Release(release) => Ok(PushRef::Release {
            release: release.clone(),
        }),
        RefExpr::Relative(rel) => {
            // `parent(@, 0)` is the same as `@` itself: the current state.
            if rel.base == RelBase::At && rel.steps == 0 {
                return Ok(PushRef::Head);
            }
            let entries = store.read_snapshots(target)?;
            let base_index = resolve_base_index(&rel.base, target, &entries, expr, store)?;
            let index = base_index.checked_sub(rel.steps).ok_or_else(|| {
                Error::r#ref(format!(
                    "'{expr}' walks {} step(s) back from snapshot s{base_index} on target '{target}', \
                    before the start of the snapshot chain",
                    rel.steps
                ))
            })?;
            // The history floor gates resolution: the chain the read exposed is
            // already the suffix at/after the floor (read_snapshots filters by
            // the durable marker), so a below-floor index is structurally
            // unreachable here — but the explicit check documents the guarantee
            // and guards any future caller that resolves against a raw chain.
            if let Some(floor) = store.read_history_floor(target)?
                && index < floor.snapshot_index
            {
                return Err(Error::r#ref(format!(
                    "cannot roll back below the history floor (checkpoint {} at s{}) on target '{target}': \
                    history before the checkpoint has been discarded",
                    floor.deployment_id, floor.snapshot_index
                )));
            }
            // The STEPPED index must be an actual member of the floored
            // read chain. [`resolve_base_index`] verifies only the BASE's
            // membership; on a GAPPED chain (e.g. [s3, s5] after checkpoint
            // compaction) an ancestor index can land in the hole — here
            // `@-` would step s5 → s4, an index no snapshot carries. Such a
            // dangling index must fail CLOSED here with a ref error naming
            // the index, never flow on to the rollback plan (which would
            // later fail with a misleading `resolve_snapshot` error).
            // Contiguous chains (prefix compaction + max+1 appends) are
            // unaffected: the floor check above already bounds the walk and
            // every index in [floor, max] is present, so this check is a
            // no-op for them.
            if !entries.iter().any(|e| e.index == index) {
                return Err(Error::r#ref(format!(
                    "'{expr}' walks {} step(s) back from snapshot s{base_index} on target '{target}' to s{index}, \
                    which is not present in the floored snapshot chain (the chain has a gap)",
                    rel.steps
                )));
            }
            Ok(PushRef::Snapshot {
                target: TargetName::new(target.to_string()),
                index,
            })
        }
    }
}

/// Resolve a relative reference's base to a snapshot index in the chain.
/// `expr` renders the reference for error messages (the parsed form has no
/// raw token anymore). The chain is the FLOORED read (the suffix at/after
/// the target's checkpoint), so a refid below the floor is absent; when the
/// target has a history floor, the absence is reported as a below-floor
/// refusal naming the checkpoint rather than a plain "no snapshot" error.
fn resolve_base_index(
    base: &RelBase,
    target: &str,
    entries: &[DeploymentSnapshot],
    expr: &RefExpr,
    store: &LocalStore,
) -> Result<u64> {
    // The history floor, when set: below-floor refids fail with a floor
    // error instead of a generic "no snapshot" error.
    let floor = store.read_history_floor(target)?;
    let below_floor = |k: u64| -> bool { floor.as_ref().is_some_and(|f| k < f.snapshot_index) };
    let latest = entries.iter().map(|e| e.index).max();
    match base {
        RelBase::At => latest.ok_or_else(|| {
            Error::r#ref(format!(
                "no successful snapshots for target '{target}'; cannot resolve '{expr}'"
            ))
        }),
        RelBase::Refid(RefId::SnapshotIndex(k)) => {
            if entries.iter().any(|e| e.index == *k) {
                Ok(*k)
            } else if below_floor(*k) {
                let f = floor.expect("below_floor implies a floor");
                Err(Error::r#ref(format!(
                    "no snapshot s{k} for target '{target}': cannot roll back below the history floor \
                    (checkpoint {} at s{}) — history before the checkpoint has been discarded",
                    f.deployment_id, f.snapshot_index
                )))
            } else {
                Err(Error::r#ref(format!(
                    "no snapshot s{k} for target '{target}'"
                )))
            }
        }
        RelBase::Refid(RefId::Deployment(id)) => entries
            .iter()
            .filter(|e| e.deployment_id.as_str() == id)
            .map(|e| e.index)
            .max()
            .ok_or_else(|| {
                Error::r#ref(format!(
                    "no successful snapshot for deployment '{id}' on target '{target}'",
                ))
            }),
        RelBase::Refid(RefId::Release(rid)) => {
            let want = ReleaseId::parse(rid);
            entries
                .iter()
                .filter(|e| snapshot_release(e) == want)
                .map(|e| e.index)
                .max()
                .ok_or_else(|| {
                    Error::r#ref(format!(
                        "no successful snapshot references release '{rid}' on target '{target}'",
                    ))
                })
        }
    }
}

/// The release a snapshot's generations came from (a coherent snapshot
/// carries one release across its slots).
fn snapshot_release(e: &DeploymentSnapshot) -> ReleaseId {
    e.slots
        .values()
        .next()
        .map(|g| g.assignment.artifact.release.clone())
        .unwrap_or_default()
}

/// Human-readable display name for a snapshot index, e.g.
/// `snapshot s1 of target production`.
pub fn ref_name(target: &TargetName, index: u64) -> String {
    format!("snapshot s{index} of target {}", target.as_str())
}

/// Ensure the snapshot log contains exactly one successful snapshot for
/// the attempt's deployment ID, and that `refs/last-successful` points at it.
/// Returns the snapshot's index.
///
/// This is the single idempotent insert used by BOTH the main success path
/// and recovery finalization, and it is replay-safe:
///
/// * If a snapshot with `deployment_id == attempt.deployment_id` already
///   exists (a previous finalization crashed after appending the snapshot but
///   before finishing), no second snapshot is appended: the existing
///   snapshot's index is returned. The log never contains two snapshots for
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
pub fn ensure_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<u64> {
    let target = target.as_str();
    // RAW (floor-unfiltered) snapshot log: index allocation must see every
    // physically recorded snapshot so a compaction can never reuse an index.
    // The floor only bounds what readers see; the index space is monotonic
    // over the full physical log.
    let entries = store.read_snapshots_raw(target)?;
    if let Some(existing) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
    {
        store.write_last_successful(target, attempt.deployment_id.as_str())?;
        return Ok(existing.index);
    }
    // NEXT INDEX = max existing index + 1 (never `entries.len()`: a compacted
    // chain like [s2, s3] has len 2 but the next unique index is 4, so len
    // would mint a reused index 2). Appending after a checkpoint therefore
    // always produces a unique, increasing index.
    let next = entries.iter().map(|e| e.index).max().map_or(0, |m| m + 1);
    let entry = build_snapshot(next, attempt, outcomes, bindings);
    store.append_snapshot(target, &entry)?;
    store.write_last_successful(target, attempt.deployment_id.as_str())?;
    Ok(next)
}

/// Append a successful snapshot to the snapshot log and return its
/// index.
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
) -> Result<u64> {
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
/// Returns the attempt's snapshot index.
pub fn finalize_successful_attempt(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    reason: &str,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<u64> {
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
    let idx = ensure_snapshot(store, &attempt.target, attempt, outcomes, bindings)?;
    // 3. Terminal status LAST.
    store.append_transition(id, &DeploymentStatus::Successful, Some(reason))?;
    Ok(idx)
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
/// `bindings` records the COMPLETE physical binding (`{server, deploy_dir}`)
/// each slot had when the deployment ran (the engine passes the target's
/// current slot→binding map from `deploy.toml`). It is stored as a separate
/// map so the `slots` map and its [`GenerationRef`]s stay intact; a legacy
/// entry with no bindings map deserializes to an empty one (unverifiable,
/// so rollback refuses rather than guessing the host/location).
pub fn build_snapshot(
    index: u64,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> DeploymentSnapshot {
    DeploymentSnapshot {
        index,
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

/// Resolve a snapshot index to its entry.
pub fn resolve_snapshot(
    store: &LocalStore,
    target: &TargetName,
    index: u64,
) -> Result<DeploymentSnapshot> {
    let target = target.as_str();
    let entries = store.read_snapshots(target)?;
    entries
        .into_iter()
        .find(|e| e.index == index)
        .ok_or_else(|| Error::r#ref(format!("no snapshot s{index} for target '{target}'")))
}

/// Reconstruct the set of successful deployments for a target from the
/// snapshot log (used to rebuild history from servers when the local ref is
/// stale).
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

/// Build a map of snapshot display names (`snapshot sN of target <target>`)
/// -> snapshot.
pub fn snapshot_index(
    store: &LocalStore,
    target: &TargetName,
) -> Result<BTreeMap<String, DeploymentSnapshot>> {
    let mut out = BTreeMap::new();
    for e in store.read_snapshots(target.as_str())? {
        out.insert(ref_name(target, e.index), e);
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

    /// Build a store whose target `production` has the chain s0..s5
    /// (deployments deploy-a..deploy-f; the s2 and s3 snapshots BOTH carry
    /// release rel-sha256-cccc, so the "most recent" release resolution is
    /// exercised).
    fn chain() -> (tempfile::TempDir, LocalStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for (i, (dep, rel)) in [
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
                .append_snapshot("production", &snapshot_entry(i as u64, dep, rel))
                .unwrap();
        }
        (tmp, store)
    }

    fn snapshot_entry(index: u64, deployment: &str, release: &str) -> DeploymentSnapshot {
        DeploymentSnapshot {
            index,
            deployment_id: DeploymentId::new(deployment.to_string()),
            target: TargetName::new("production".to_string()),
            behavior_sha256: "sha256-aa".to_string(),
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new(format!("gen-{index}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new(format!("rel-sha256-{release}")),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new(format!("tree-{index}")),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::new(),
        }
    }

    fn snap(target: &TargetName, index: u64) -> PushRef {
        PushRef::Snapshot {
            target: target.clone(),
            index,
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

    /// The ancestor steps on the s0..s5 chain (latest = s5): `@-` = s4,
    /// `@--` = s3, `parent(@, 3)` = s2, `s3--` = s1, `parent(s5, 2)` = s3,
    /// `s1-` = s0, and the bare `s1` / `parent(s1, 0)` forms name s1 itself.
    #[test]
    fn resolve_ref_ancestor_steps() {
        let (_tmp, store) = chain();
        let target = TargetName::new("production".to_string());
        for (token, want) in [
            ("@-", 4u64),
            ("@--", 3),
            ("parent(@, 3)", 2),
            ("parent(@, 2)", 3),
            ("s3--", 1),
            ("parent(s5, 2)", 3),
            ("s1-", 0),
            ("s1", 1),
            ("parent(s1, 0)", 1),
            ("parent(s2, 1)", 1),
        ] {
            assert_eq!(
                resolve(token, &store).unwrap(),
                snap(&target, want),
                "{token} must resolve to index {want}"
            );
        }
    }

    /// A deployment refid resolves to the snapshot that deployed it (most
    /// recent); a release refid to the most recent snapshot referencing the
    /// release — then the ancestor steps walk from there.
    #[test]
    fn resolve_ref_deployment_and_release_refids() {
        let (_tmp, store) = chain();
        let target = TargetName::new("production".to_string());
        // deploy-b deployed s1.
        assert_eq!(resolve("deploy-b-", &store).unwrap(), snap(&target, 0));
        assert_eq!(
            resolve("parent(deploy-b, 1)", &store).unwrap(),
            snap(&target, 0)
        );
        assert_eq!(
            resolve("parent(deploy-c, 0)", &store).unwrap(),
            snap(&target, 2)
        );
        // rel-sha256-cccc is referenced by BOTH s2 and s3; the most recent
        // (s3) wins, then the ancestor steps apply.
        assert_eq!(
            resolve("parent(rel-sha256-cccc, 0)", &store).unwrap(),
            snap(&target, 3)
        );
        assert_eq!(
            resolve("rel-sha256-cccc-", &store).unwrap(),
            snap(&target, 2)
        );
        assert_eq!(
            resolve("parent(rel-sha256-cccc, 2)", &store).unwrap(),
            snap(&target, 1)
        );
        // Abbreviated digest form resolves the same release.
        assert_eq!(
            resolve("parent(cccc, 0)", &store).unwrap(),
            snap(&target, 3)
        );
    }

    /// `release:<id>` resolves DIRECTLY to a `PushRef::Release` — with NO
    /// store lookup and NO target snapshot history: the bare release id never
    /// steps the deployment-snapshot chain, so a cross-target / fresh-target
    /// direct deployment is expressible even when the destination has zero
    /// snapshots. This is the grammar's escape hatch for
    /// direct/cross-target release deployment.
    #[test]
    fn resolve_ref_direct_release_form_ignores_chain_and_store() {
        let (_tmp, store) = chain();
        // Even though `rel-sha256-cccc` IS referenced by snapshots in this
        // chain, `release:` yields the bare release ref, not a snapshot.
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
        // A release that is NOT referenced by any snapshot — and a target
        // with an EMPTY chain — resolve the same way: resolution never reads
        // the store.
        let tmp = tempfile::tempdir().unwrap();
        let empty = LocalStore::with_base(tmp.path().join("store")).unwrap();
        assert_eq!(
            resolve_ref_expr(
                &parse_ref_expr("release:rel-sha256-zzzz").expect("token must parse"),
                "brand-new-target",
                &empty
            )
            .unwrap(),
            PushRef::Release {
                release: ReleaseId::new("rel-sha256-zzzz".to_string())
            }
        );
        // The refid form on the same empty chain still fails closed (it
        // needs a snapshot that references the release).
        resolve_ref_expr(
            &parse_ref_expr("parent(rel-sha256-zzzz, 0)").expect("token must parse"),
            "brand-new-target",
            &empty,
        )
        .expect_err("the refid form needs snapshot ancestry and must fail on an empty chain");
    }

    /// Out-of-range and unresolvable references fail closed with a ref
    /// error: stepping before the chain start, a missing snapshot index, an
    /// unknown deployment/release, and an EMPTY chain. Never underflow,
    /// never guess.
    #[test]
    fn resolve_ref_failures_fail_closed() {
        let (_tmp, store) = chain();
        for token in [
            "parent(@, 6)", // s5 - 6 underflows
            "s0-",
            "s0--",
            "parent(s1, 2)",
            "s9",
            "parent(s9, 0)",
            "deploy-missing-",
            "parent(deploy-missing, 1)",
            "parent(rel-sha256-zzzz, 0)",
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
        for token in ["@-", "parent(@, 2)", "s0", "deploy-x-"] {
            resolve(token, &empty).expect_err(&format!("{token} on an empty chain must fail"));
        }
    }

    #[test]
    fn ref_name_index() {
        assert_eq!(
            ref_name(&TargetName::new("production".to_string()), 3),
            "snapshot s3 of target production"
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
        assert_eq!(first, 0);
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, attempt.deployment_id);
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );

        // Second call with the same deployment ID is a no-op: same index, no
        // duplicate entry, and `refs/last-successful` is untouched.
        let second = append_snapshot(&store, &target, &attempt, &attempt.slots, &bindings).unwrap();
        assert_eq!(second, first, "repeated append must return the same index");
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

        let snapshot = build_snapshot(3, &attempt, &attempt.slots, &bindings);
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
    /// the host/location.
    #[test]
    fn legacy_snapshot_without_bindings_deserializes_with_empty_map() {
        // Oldest shape: no binding recorded at all.
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
        let with_servers = r#"{"index":1,"deployment_id":"deploy-old-servers","target":"production","behavior_sha256":"sha256-aa","slots":{},"servers":{"p1":"server-01"}}"#;
        let snapshot: DeploymentSnapshot = serde_json::from_str(with_servers).unwrap();
        assert!(
            snapshot.bindings.is_empty(),
            "old `servers`-keyed line yields an empty bindings map"
        );
    }

    /// A gapped snapshot-chain shape: 0..=8 indices, a sorted sample of
    /// 0..12 (GAPS DELIBERATE — chains are seeded with caller-chosen
    /// indices, exactly as checkpoint compaction rewrites the log), plus an
    /// optional durable floor at a MEMBER index ≤ max (None on an empty
    /// chain or when the generated slot overruns it).
    fn chain_strategy() -> impl Strategy<Value = (Vec<u64>, Option<u64>)> {
        (
            prop::collection::vec(0u64..12, 0..=8),
            prop::option::weighted(0.6, 0usize..9),
        )
            .prop_map(|(mut idx, floor_slot)| {
                idx.sort_unstable();
                idx.dedup();
                let floor = floor_slot.and_then(|i| idx.get(i).copied());
                (idx, floor)
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

    /// One resolve-leg case: seed a REAL store with a (possibly gapped,
    /// possibly floored) chain, parse a generated token, and resolve it via
    /// the engine's two-phase flow `resolve_ref_expr(&parse_ref_expr(t)?, ...)`.
    /// Asserts: no panic anywhere; every parse AND resolve failure is a ref
    /// error; a rejected shape never resolves; a resolved snapshot index is
    /// an actual member of the FLOORED chain at/after the floor; `@` /
    /// `release:<id>` never touch the chain (they resolve even on an EMPTY
    /// store, while every relative form on an empty store fails closed —
    /// except `parent(@, 0)`, which the oracle folds to `Head` FIRST so it
    /// mirrors the engine's documented `Relative{At,0} ≡ Head` reduction).
    fn ref_grammar_resolve_case(chain_idx: Vec<u64>, floor: Option<u64>, token: String) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for &i in &chain_idx {
            let dep = format!("deploy-seed-{i}");
            store
                .append_snapshot(
                    "production",
                    &snapshot_entry(i, &dep, &format!("{i:02x}{i:02x}")),
                )
                .unwrap();
        }
        if let Some(fi) = floor {
            let dep = format!("deploy-seed-{fi}");
            store
                .append_attempt("production", &attempt_entry(&dep))
                .unwrap();
            store
                .write_history_floor(
                    "production",
                    &HistoryFloor {
                        schema_version: SCHEMA_VERSION,
                        target: TargetName::new("production".to_string()),
                        deployment_id: DeploymentId::new(dep.clone()),
                        snapshot_index: fi,
                        established_at: "2026-01-01T00:00:00Z".to_string(),
                    },
                )
                .unwrap();
        }

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
        if chain_idx.is_empty() {
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

        // RESOLVE MEMBERSHIP: a resolved snapshot index is an actual member
        // of the floored read chain, at/after the floor.
        match result {
            Ok(PushRef::Snapshot { target, index }) => {
                assert_eq!(
                    target.as_str(),
                    "production",
                    "{token:?} must resolve against the passed target"
                );
                let floored = store.read_snapshots("production").unwrap();
                assert!(
                    floored.iter().any(|e| e.index == index),
                    "{token:?} resolved to s{index}, which is not an actual member of the \
                     floored chain {floored:?}"
                );
                if let Some(fi) = floor {
                    assert!(
                        index >= fi,
                        "{token:?} resolved below the history floor s{fi}: s{index}"
                    );
                }
            }
            Ok(PushRef::Head | PushRef::Release { .. }) => {}
            Err(_) => {}
        }
    }

    proptest! {
        // The RESOLVE leg — against a REAL seeded store per case (a gapped
        // chain with caller-chosen indices plus an optional durable floor at
        // a member index): resolve membership and totality. Randomized seeds
        // + failure persistence, bounded at 96 cases (each case builds a
        // small tempdir store, so the bound keeps the suite fast).
        #![proptest_config(ProptestConfig {
            cases: 96,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ref_grammar_resolve_contract(
            (chain_idx, floor) in chain_strategy(),
            token in ref_token_strategy(),
        ) {
            ref_grammar_resolve_case(chain_idx, floor, token);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION for the resolve leg.
        #![proptest_config(ProptestConfig {
            cases: 96,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ref_grammar_resolve_contract_fixed_seed(
            (chain_idx, floor) in chain_strategy(),
            token in ref_token_strategy(),
        ) {
            ref_grammar_resolve_case(chain_idx, floor, token);
        }
    }
}

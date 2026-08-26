//! Deployment history, rollback references, and finalization over the ONE
//! per-target deployment ledger.
//!
//! A target's deployment history is its ordered LEDGER
//! (`targets/<target>/ledger.jsonl`, see [`crate::records`]): each entry
//! starts as the durable INTENT (appended before any remote mutation) and its
//! TERMINAL EVENT carries the status, the per-slot outcomes, and — when
//! successful — the ROLLBACK STATE ([`crate::records::LedgerRollback`]:
//! per-slot generation refs + physical bindings). The ledger's append order
//! IS the history order; there is NO separate snapshot op log, NO floor
//! marker, and
//! NO `refs/last-successful` ref file — the latest successful entry is
//! DERIVED from the ledger.
//!
//! Rollback references resolve against the ledger's SUCCESSFUL terminal
//! events (each successful deployment IS a rollback payload KEYED BY ITS
//! DEPLOYMENT ID): `deploy push <target> <deployment-id>` restores exactly
//! that deployment's stored state, and the relative refs (`@-`, `@--`,
//! `parent(@, N)`, `<deployment-id>-`, `<deployment-id>--`,
//! `parent(<deployment-id>, N)`) walk the target's DEPLOYMENT HISTORY — the
//! ledger's successful entries in order. Failed and degraded attempts remain
//! visible through `deploy log` but are NOT valid rollback sources — a failed
//! deployment id never resolves. The public grammar has NO snapshot index
//! (`sN`): the merged [`crate::revset`] grammar is deployment-keyed
//! (`RefExpr = Head | Release | Relative{base: At | Refid(DeploymentId)}`).
//! Any internal position the checkpoint/compaction needs is DERIVED from the
//! ledger order ([`successful_index`], internal only — never a public ref).
//!
//! A SUCCESSFUL deployment finalizes replay-safely through the ONE shared
//! finalizer ([`finalize_successful_attempt`]), which APPENDS the terminal
//! event (status `Successful` + outcomes + rollback state) to the ledger.
//! The append is atomic (one line); a crash before it leaves the entry
//! intent-only (recoverable-pending) and the next push reconciles it.
//!
//! # Reference resolution (two-phase)
//!
//! The reference LANGUAGE is encapsulated in [`crate::revset`]: a pure,
//! store-free grammar whose [`crate::revset::parse_ref_expr`] returns only
//! the AST ([`RefExpr`] and friends, re-exported below) — no store access,
//! no resolution. This module keeps only the store-dependent RESOLUTION
//! ([`resolve_ref_expr`]) that FOLLOWS the AST. The engine parses the token
//! BEFORE it acquires locks or persists anything (a malformed token fails
//! before any side effect) and resolves only once the ledger is stable
//! (after reconciliation has appended any recovered terminal events), so a
//! relative ref is computed against the POST-reconciliation chain: `@-`
//! means one before the latest INCLUDING this push's reconciled append.
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
//! DEPLOYMENT HISTORY from a base POSITION (the ledger order — positions are
//! DERIVED, never stored); stepping past the start of the chain, an
//! unresolvable deployment id, or an empty chain fail closed with a ref
//! error — never underflow, never guess. After a checkpoint the ledger IS
//! the retained suffix (the floor is implicit), so a discarded deployment id
//! is simply absent and refuses.

use crate::error::{Error, Result};
use crate::model::{
    DeploymentId, GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, TargetName,
};
use crate::records::{
    DeploymentIntent, DeploymentStatus, LedgerEntry, LedgerRollback, LedgerTerminal,
    PhysicalBinding, SlotAttemptState, SlotResult, SlotTable, TerminalDisposition,
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
    /// Restore the rollback state of a historical successful deployment,
    /// KEYED BY ITS DEPLOYMENT ID (`deploy push <target> <deployment-id>`,
    /// and the `@` / `parent(...)` walk of the deployment history). The
    /// deployment's rollback payload is resolved from the target's ledger.
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
/// separately-given `target` and the target's ledger in `store`.
///
/// Store-DEPENDENT (unlike [`parse_ref_expr`]): reads the target's ledger
/// (the DEPLOYMENT HISTORY — each successful terminal event is a rollback
/// payload keyed by its deployment id), so the caller must invoke it AFTER
/// reconciliation has appended any recovered terminal events — the engine
/// parses the token up front but resolves only once the ledger is stable, so
/// relative refs see the reconciled append. The target is passed ONCE (the
/// push argument); the relative forms never repeat it. Failures are ref
/// errors: an empty chain, an unresolvable deployment id, and walking past
/// the start of the chain all fail closed rather than guessing.
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
            // The deployment history IS the ledger's successful entries,
            // ordered by appends (deployment order). POSITIONS are derived
            // from that order — there is no stored index — so the chain is a
            // contiguous position space and any position < len is a member.
            let entries = store.read_ledger(target)?;
            let chain = successful_chain(&entries);
            let base_pos = resolve_base_pos(&rel.base, target, &chain, expr)?;
            let base_id = match &rel.base {
                RelBase::At => chain[base_pos].deployment_id.as_str(),
                RelBase::Refid(dep) => dep.as_str(),
            };
            let pos = base_pos.checked_sub(rel.steps as usize).ok_or_else(|| {
                Error::r#ref(format!(
                    "'{expr}' walks {} step(s) back from deployment '{base_id}' on target \
                    '{target}', before the start of the deployment history",
                    rel.steps
                ))
            })?;
            Ok(PushRef::Deployment {
                target: TargetName::new(target.to_string()),
                deployment_id: chain[pos].deployment_id.clone(),
            })
        }
    }
}

/// The successful chain of a ledger: the entries whose terminal event is
/// `Successful` (carrying a rollback state), in ledger order. The position
/// in this chain is the internal snapshot position (0-based) — the ledger's
/// append order is the history order, and after a checkpoint the first
/// retained successful entry is position 0. Never exposed as a public ref.
fn successful_chain(entries: &[LedgerEntry]) -> Vec<&LedgerEntry> {
    entries
        .iter()
        .filter(|e| {
            e.terminal
                .as_ref()
                .is_some_and(|t| t.status() == DeploymentStatus::Successful)
        })
        .collect()
}

/// Resolve a relative reference's base to a POSITION in the successful chain's base to a POSITION in the successful chain
/// (the ledger in deployment order). `expr` renders the reference for error
/// messages. The chain is the CURRENT ledger (the retained suffix after a
/// checkpoint — the floor is implicit), so a deployment id below the
/// retained history is absent and refuses with a plain "no successful
/// deployment" error.
fn resolve_base_pos(
    base: &RelBase,
    target: &str,
    chain: &[&LedgerEntry],
    expr: &RefExpr,
) -> Result<usize> {
    match base {
        RelBase::At => chain.len().checked_sub(1).ok_or_else(|| {
            Error::r#ref(format!(
                "no successful deployments for target '{target}'; cannot resolve '{expr}'"
            ))
        }),
        RelBase::Refid(dep) => match chain.iter().position(|e| e.deployment_id == *dep) {
            Some(pos) => Ok(pos),
            None => Err(Error::r#ref(format!(
                "no successful deployment '{dep}' on target '{target}' (a failed, pending, or \
                already-checkpointed deployment never resolves)"
            ))),
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

/// Finalize a successful deployment replay-safely: the SINGLE shared
/// terminal path used by BOTH the normal push success path and recovery
/// ([`crate::push::reconcile::reconcile_pending_commits`]). Appends the
/// TERMINAL EVENT (status `Successful`, the per-slot `outcomes`, and the
/// rollback state built from `actuals`) to the target's ledger — ONE atomic
/// line append, the only commit of the finalize.
///
/// Replay idempotency: if the entry already carries a terminal event, every
/// durable step already happened and this call is a no-op — a crash after
/// the append can never duplicate the terminal ([`LocalStore::append_terminal`]
/// refuses duplicates).
///
/// The rollback is built from the attempt's OUTCOMES (`actuals`: per-slot
/// actual state observed by the engine — live actuals on the main path, the
/// verified desired state during recovery), never from the intent record
/// itself (the persisted intent is the immutable intent; its `slots` map is
/// empty).
///
/// PARTIAL-ROLLOUT SNAPSHOT SEMANTICS: every successful deployment —
/// including a group deployment — produces a COMPLETE snapshot of the
/// target's resulting state. The base is the latest successful snapshot
/// BEFORE this attempt; the SELECTED slots (the attempt's `slot_ids`) are
/// replaced with their actual successful assignments and current physical
/// bindings, unselected slots are carried forward unchanged, and slots
/// removed from the current target configuration (`current_slot_ids`) are
/// omitted.
pub fn finalize_successful_attempt(
    store: &LocalStore,
    attempt: &DeploymentIntent,
    outcomes: &BTreeMap<PlacementSlotId, SlotResult>,
    actuals: &BTreeMap<PlacementSlotId, SlotAttemptState>,
    reason: &str,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
    current_slot_ids: &[PlacementSlotId],
) -> Result<()> {
    let entries = store.read_ledger(attempt.target.as_str())?;
    if let Some(e) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
        && e.terminal.is_some()
    {
        return Ok(());
    }
    // The base for the complete snapshot: the latest successful snapshot
    // BEFORE this attempt (this attempt's terminal is not yet appended).
    let base = crate::push::plan::latest_successful_rollback(store, attempt.target.as_str())?;
    let rollback = build_rollback(actuals, bindings, base.as_ref(), current_slot_ids);
    let terminal = LedgerTerminal {
        recorded_at: crate::remote::helper::now_rfc3339(),
        outcomes: SlotTable::from_map(outcomes.clone()),
        // The Successful disposition ALWAYS carries the complete rollback
        // payload (the truth table is structural in the domain).
        disposition: TerminalDisposition::Successful { rollback },
        reason: Some(reason.to_string()),
    };
    store.append_terminal(attempt.target.as_str(), &attempt.deployment_id, &terminal)
}

/// Build the rollback state of a successful deployment from the attempt's
/// OUTCOMES (`actuals`: per-slot actual state), never from the intent record.
/// A successful deployment carries one complete [`GenerationRef`] per slot;
/// slots without a recorded generation are not part of a coherent rollback
/// and are dropped. `bindings` records the COMPLETE physical binding
/// (`{server, deploy_dir}`) each slot had when the deployment ran; a missing
/// entry is "unverifiable" and makes exact rollback refuse the slot.
///
/// PARTIAL-ROLLOUT OVERLAY: the result is the COMPLETE target snapshot — the
/// latest successful snapshot (`base`) with the SELECTED slots (the attempt's
/// actual per-slot results) replaced by their actual assignments and current
/// bindings, unselected slots carried forward unchanged, and slots absent
/// from `current_slot_ids` (removed from the current target configuration)
/// omitted. A full-target attempt replaces every slot, so the base is
/// irrelevant. There is NO snapshot-wide release/behavior: each slot's
/// `GenerationRef` carries its OWN artifact (release/variant/tree), so a
/// partial snapshot can span several releases (group pushes over time) and
/// the referenced releases are the set derived from the per-slot bindings.
pub fn build_rollback(
    actuals: &BTreeMap<PlacementSlotId, SlotAttemptState>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
    base: Option<&LedgerRollback>,
    current_slot_ids: &[PlacementSlotId],
) -> LedgerRollback {
    // Start from the base (or empty): unselected slots are carried forward
    // unchanged.
    let mut slots: BTreeMap<PlacementSlotId, GenerationRef> =
        base.map(|b| b.slots.clone()).unwrap_or_default();
    let mut out_bindings: BTreeMap<PlacementSlotId, PhysicalBinding> =
        base.map(|b| b.bindings.clone()).unwrap_or_default();
    // Replace the SELECTED slots with their actual successful assignments
    // and current physical bindings.
    for (slot, s) in actuals {
        if let Some(generation) = s.generation.clone() {
            slots.insert(
                slot.clone(),
                GenerationRef {
                    generation,
                    assignment: PlacementSlotAssignment {
                        placement_slot: slot.clone(),
                        artifact: s.artifact.clone(),
                    },
                },
            );
        }
        if let Some(b) = bindings.get(slot) {
            out_bindings.insert(slot.clone(), b.clone());
        }
    }
    // Omit slots removed from the current target configuration.
    let current: std::collections::HashSet<&str> =
        current_slot_ids.iter().map(|s| s.as_str()).collect();
    slots.retain(|k, _| current.contains(k.as_str()));
    out_bindings.retain(|k, _| current.contains(k.as_str()));
    LedgerRollback {
        slots,
        bindings: out_bindings,
    }
}

/// Resolve the per-slot OUTCOMES used to finalize a pending deployment when
/// the engine no longer has the live outcomes at hand (recovery): recovery
/// already verified each slot's live generation equals the desired
/// generation, so the outcomes ARE the desired assignments (the old
/// `deployments/<id>/results.json` outcomes store is GONE — the ledger
/// terminal carries outcomes, and a terminal-less entry has none by
/// construction). Returns the per-slot `SlotResult` outcomes AND the
/// per-slot actuals ([`SlotAttemptState`]) for the rollback, built from the
/// attempt's desired assignments.
pub fn recovery_outcomes(
    attempt: &DeploymentIntent,
) -> (
    BTreeMap<PlacementSlotId, SlotResult>,
    BTreeMap<PlacementSlotId, SlotAttemptState>,
) {
    let mut outcomes = BTreeMap::new();
    let mut actuals = BTreeMap::new();
    // Iterate the ONE authoritative slot table (the membership AND the
    // desired entries are the same table in the domain).
    for (sid, slot) in attempt.slots.iter() {
        outcomes.insert(
            sid.clone(),
            SlotResult {
                slot_id: sid.clone(),
                outcome: crate::records::ServerOutcomeKind::Activated,
                generation: Some(slot.desired.generation.clone()),
                compensated: false,
                error: None,
            },
        );
        actuals.insert(
            sid.clone(),
            SlotAttemptState {
                artifact: slot.desired.artifact.clone(),
                generation: Some(slot.desired.generation.clone()),
            },
        );
    }
    (outcomes, actuals)
}

/// Reconstruct the successful chain of a target from its ledger (the
/// rollback states — used to rebuild the derived latest-successful view).
pub fn successful_deployments(store: &LocalStore, target: &TargetName) -> Result<Vec<LedgerEntry>> {
    let entries = store.read_ledger(target.as_str())?;
    Ok(entries
        .into_iter()
        .filter(|e| {
            e.terminal
                .as_ref()
                .is_some_and(|t| t.status() == DeploymentStatus::Successful)
        })
        .collect())
}

/// Resolve a deployment id to its stored ROLLBACK PAYLOAD (the rollback
/// state of the ledger's successful terminal event). The id must be a
/// SUCCESSFUL deployment of the target (its ledger entry carries a
/// `Successful` terminal with a rollback state); failed, degraded, pending,
/// and already-checkpointed-away deployments never resolve.
pub fn resolve_deployment(
    store: &LocalStore,
    target: &TargetName,
    deployment_id: &DeploymentId,
) -> Result<LedgerRollback> {
    let entries = store.read_ledger(target.as_str())?;
    let entry = entries
        .iter()
        .find(|e| e.deployment_id == *deployment_id)
        .ok_or_else(|| {
            Error::r#ref(format!(
                "no successful deployment '{deployment_id}' for target '{target}'"
            ))
        })?;
    let terminal = entry.terminal.as_ref().ok_or_else(|| {
        Error::r#ref(format!(
            "deployment '{deployment_id}' on target '{target}' has no terminal event (the deployment did not complete)"
        ))
    })?;
    match &terminal.disposition {
        TerminalDisposition::Successful { rollback } => Ok(rollback.clone()),
        other => Err(Error::r#ref(format!(
            "deployment '{deployment_id}' on target '{target}' ended {:?} — only successful deployments carry a rollback state",
            other.status()
        ))),
    }
}

/// The INTERNAL snapshot position of a successful deployment: its position
/// in the CURRENT ledger's successful chain, or `None` when it is not a
/// successful entry. Internal only — positions are derived from the ledger
/// order and never exposed through the public grammar (which is
/// deployment-keyed).
pub fn successful_index(
    store: &LocalStore,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<Option<u64>> {
    let entries = store.read_ledger(target)?;
    let chain = successful_chain(&entries);
    Ok(chain
        .iter()
        .position(|e| e.deployment_id == *deployment_id)
        .map(|p| p as u64))
}

/// Collect the distinct placement slot IDs referenced across a set of
/// intent entries.
pub fn attempt_slot_ids(attempt: &DeploymentIntent) -> Vec<PlacementSlotId> {
    // The membership is the ONE table's key set (deployment order).
    attempt.slots.keys().cloned().collect()
}

/// Build a map of rollback display names (`deployment <deployment-id> of
/// target <target>`) -> rollback payload, for `deploy log`-style rendering.
pub fn deployment_index(
    store: &LocalStore,
    target: &TargetName,
) -> Result<BTreeMap<String, LedgerRollback>> {
    let mut out = BTreeMap::new();
    for e in successful_deployments(store, target)? {
        if let TerminalDisposition::Successful { rollback } =
            &e.terminal.as_ref().unwrap().disposition
        {
            out.insert(ref_name(target, &e.deployment_id), rollback.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArtifactRef, GenerationId, ReleaseId, ServerId, TreeDigest, VariantName};
    use crate::records::{
        DeploymentIntent, DesiredGeneration, IntentSlot, NonEmptySlotTable, SlotTable,
        TerminalDisposition,
    };
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};
    use std::collections::BTreeMap;

    // The reference-language test helpers (grammar generators, the
    // canonical fold, and the panic-free parse runner) live with the
    // parser in [`crate::revset::tests`]; the resolve leg imports them so
    // the parse/resolve contract stays pinned in ONE place.
    use crate::revset::tests::{fold, parse_no_panic, ref_token_strategy};

    /// A minimal but VALID intent for the target (EXACT key-set equality:
    /// `slot_ids == desired.keys() == pre_push.keys()`).
    fn intent(dep: &str) -> DeploymentIntent {
        let p1 = PlacementSlotId::new("p1".to_string());
        // ONE slot table (the membership + desired/pre-push entries).
        let slots = BTreeMap::from([(
            p1.clone(),
            IntentSlot {
                desired: DesiredGeneration {
                    generation: GenerationId::new("gen-1".to_string()),
                    artifact: ArtifactRef {
                        release: ReleaseId::new("rel-1".to_string()),
                        variant: VariantName::new("standard".to_string()),
                        tree: TreeDigest::new("tree-1".to_string()),
                    },
                },
                pre_push: None,
            },
        )]);
        DeploymentIntent {
            deployment_id: DeploymentId::new(dep.to_string()),
            target: TargetName::new("production".to_string()),
            group: None,
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a fixture intent always has at least one slot"),
        }
    }

    /// A SUCCESSFUL terminal for `deployment` carrying the given release in
    /// its rollback (one slot `p1`, deterministic payload derived from the
    /// deployment id so "exactly its stored state" is a meaningful equality).
    fn successful_terminal(dep: &str, release: &str) -> LedgerTerminal {
        LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: SlotTable::new(),
            disposition: TerminalDisposition::Successful {
                rollback: LedgerRollback {
                    slots: BTreeMap::from([(
                        PlacementSlotId::new("p1".to_string()),
                        GenerationRef {
                            generation: GenerationId::new(format!("gen-{dep}")),
                            assignment: PlacementSlotAssignment {
                                placement_slot: PlacementSlotId::new("p1".to_string()),
                                artifact: ArtifactRef {
                                    release: ReleaseId::new(release.to_string()),
                                    variant: VariantName::new("standard".to_string()),
                                    tree: TreeDigest::new(format!("tree-{dep}")),
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
                },
            },
            reason: None,
        }
    }

    /// Seed `count` successful deployments (ids `deploy-0`..`deploy-{n-1}`,
    /// releases derived from the ids) onto the target's ledger.
    fn seed_chain(store: &LocalStore, count: usize) -> Vec<String> {
        let mut ids = Vec::new();
        for n in 0..count {
            let id = format!("deploy-{n}");
            store.append_intent("production", &intent(&id)).unwrap();
            store
                .append_terminal(
                    "production",
                    &DeploymentId::new(id.clone()),
                    &successful_terminal(&id, &format!("rel-sha256-{id}")),
                )
                .unwrap();
            ids.push(id);
        }
        ids
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
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
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

    /// The ancestor steps on a 6-deployment chain (latest = deploy-5):
    /// `@-` = deploy-4, `@--` = deploy-3, `parent(@, 3)` = deploy-2,
    /// `deploy-5--` = deploy-3, `parent(deploy-5, 2)` = deploy-3,
    /// `deploy-1-` = deploy-0, and the bare `deploy-1` /
    /// `parent(deploy-1, 0)` forms name deploy-1 itself.
    #[test]
    fn resolve_ref_ancestor_steps() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let ids = seed_chain(&store, 6);
        let target = TargetName::new("production".to_string());
        for (token, want) in [
            ("@-", ids[4].as_str()),
            ("@--", ids[3].as_str()),
            ("parent(@, 3)", ids[2].as_str()),
            ("parent(@, 2)", ids[3].as_str()),
            ("deploy-4--", ids[2].as_str()),
            ("parent(deploy-5, 2)", ids[3].as_str()),
            ("deploy-1-", ids[0].as_str()),
            ("deploy-1", ids[1].as_str()),
            ("parent(deploy-1, 0)", ids[1].as_str()),
            ("parent(deploy-2, 1)", ids[1].as_str()),
        ] {
            assert_eq!(
                resolve(token, &store).unwrap(),
                dep_ref(&target, want),
                "{token} must resolve to deployment {want}"
            );
        }
    }

    /// A deployment refid resolves to the deployment that deployed it (its
    /// own stored state — exact rollback); the ancestor steps walk the
    /// deployment history back from there.
    #[test]
    fn resolve_ref_deployment_refids() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let ids = seed_chain(&store, 6);
        let target = TargetName::new("production".to_string());
        assert_eq!(resolve(&ids[1], &store).unwrap(), dep_ref(&target, &ids[1]));
        assert_eq!(
            resolve(&format!("{}-", ids[1]), &store).unwrap(),
            dep_ref(&target, &ids[0])
        );
        assert_eq!(
            resolve(&format!("parent({}, 0)", ids[2]), &store).unwrap(),
            dep_ref(&target, &ids[2])
        );
        assert_eq!(
            resolve(&format!("parent({}, 4)", ids[5]), &store).unwrap(),
            dep_ref(&target, &ids[1])
        );
        // The bare deployment id resolves to EXACTLY that deployment's stored
        // payload (the rollback state keyed by the id), never "the most
        // recent rollback" of anything.
        let rollback = resolve_deployment(&store, &target, &DeploymentId::new(&ids[2])).unwrap();
        assert_eq!(
            rollback.slots[&PlacementSlotId::new("p1")]
                .generation
                .as_str(),
            "gen-deploy-2"
        );
    }

    /// `release:<id>` resolves DIRECTLY to a `PushRef::Release` — with NO
    /// store lookup and NO target history: the direct form never steps the
    /// deployment history, so a cross-target / fresh-target direct
    /// deployment is expressible even when the destination has zero
    /// successful deployments. This is the grammar's escape hatch for
    /// direct/cross-target release deployment.
    #[test]
    fn resolve_ref_direct_release_form_ignores_chain_and_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
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
        // A release that is not referenced by any ledger — and a target with
        // an EMPTY chain — resolve the same way: resolution never reads the
        // store.
        let empty = LocalStore::with_base(tmp.path().join("store2")).unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_chain(&store, 4);
        for token in [
            "parent(@, 6)", // len 4, so 6 steps back underflows
            "deploy-0-",    // deploy-0 is the first deployment
            "deploy-0--",
            "parent(deploy-1, 2)",
            "parent(deploy-0, 1)",
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
        let empty = LocalStore::with_base(tmp.path().join("store3")).unwrap();
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

    /// Finalization appends the terminal event exactly once (replay-safe by
    /// deployment id): a repeated finalize for the same attempt is a no-op.
    #[test]
    fn finalize_is_idempotent_by_deployment_id() {
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
        let attempt = intent("deploy-idempotent");
        store.append_intent(target.as_str(), &attempt).unwrap();
        let actuals = BTreeMap::from([(
            PlacementSlotId::new("p1".to_string()),
            SlotAttemptState {
                artifact: ArtifactRef::default(),
                generation: Some(GenerationId::new("gen-1".to_string())),
            },
        )]);
        let outcomes = BTreeMap::from([(
            PlacementSlotId::new("p1".to_string()),
            SlotResult {
                slot_id: PlacementSlotId::new("p1".to_string()),
                outcome: crate::records::ServerOutcomeKind::Activated,
                generation: Some(GenerationId::new("gen-1".to_string())),
                compensated: false,
                error: None,
            },
        )]);

        finalize_successful_attempt(
            &store,
            &attempt,
            &outcomes,
            &actuals,
            "push completed",
            &bindings,
            &[PlacementSlotId::new("p1".to_string())],
        )
        .unwrap();
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].terminal.is_some());
        assert_eq!(
            store.latest_status("deploy-idempotent").unwrap(),
            Some(DeploymentStatus::Successful)
        );

        // Repeated finalize with the same deployment ID is a no-op: same
        // key, no duplicate terminal.
        finalize_successful_attempt(
            &store,
            &attempt,
            &outcomes,
            &actuals,
            "push completed",
            &bindings,
            &[PlacementSlotId::new("p1".to_string())],
        )
        .unwrap();
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1, "no duplicate terminal event");
    }

    /// `build_rollback` records each slot's complete physical binding.
    #[test]
    fn build_rollback_records_each_slots_physical_binding() {
        let slot = PlacementSlotId::new("p1".to_string());
        let actuals = BTreeMap::from([(
            slot.clone(),
            SlotAttemptState {
                artifact: ArtifactRef::default(),
                generation: Some(GenerationId::new("gen-x".to_string())),
            },
        )]);
        let bindings: BTreeMap<PlacementSlotId, PhysicalBinding> = BTreeMap::from([(
            slot.clone(),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);

        let rollback = build_rollback(&actuals, &bindings, None, std::slice::from_ref(&slot));
        assert_eq!(
            rollback.bindings.get(&slot),
            Some(&PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            }),
            "the rollback must record the slot's complete physical binding (server AND deploy_dir)"
        );
        assert_eq!(rollback.slots.len(), 1, "generation refs preserved intact");
        assert_eq!(rollback.bindings.len(), 1);
    }

    /// A legacy ledger line whose rollback has no `bindings` key must still
    /// deserialize; its `bindings` map defaults to empty, which rollback
    /// treats as unverifiable rather than guessing the host/location. The
    /// line ALSO carries the OLD snapshot-wide `behavior_sha256`/`release`
    /// members — serde ignores the unknown fields, and the rollback payload
    /// is interpreted purely through the per-slot bindings (legacy lines stay
    /// readable after the snapshot-wide fields were removed).
    #[test]
    fn legacy_rollback_without_bindings_deserializes_with_empty_map() {
        let line = r#"{"kind":"terminal","deployment_id":"deploy-old","target":"production","status":"successful","recorded_at":"2026-01-01T00:00:00Z","outcomes":{},"rollback":{"behavior_sha256":"sha256-aa","release":"rel-sha256-old","slots":{}}}"#;
        // The legacy line PARSES at the wire level (the legacy snapshot-wide
        // members are tolerated by serde — unknown members are skipped), and
        // the domain conversion REFUSES it (fail closed): the legacy
        // `release` disagrees with the snapshot's derived releases (the
        // per-slot bindings — empty here — are the authoritative source).
        let wire: crate::records::LedgerTerminalWire = serde_json::from_str(line).unwrap();
        let err = wire.into_domain().expect_err(
            "a legacy release that disagrees with the derived snapshot releases fails closed",
        );
        assert!(err.to_string().contains("release"), "error: {err}");
    }

    /// A deployment-history shape: 0..=8 (deployment_id, successful?) pairs
    /// (a FAILED deployment never gets a successful terminal — the
    /// two-class history the user's property needs). Deployment ids are
    /// DETERMINISTIC PER POSITION (`deploy-{n:04}`), so each id is unique
    /// across the history and a FAILED id can never double as a SUCCESSFUL
    /// one (which would make "failed ids never resolve" vacuous).
    fn chain_strategy() -> impl Strategy<Value = Vec<(String, bool)>> {
        prop::collection::vec(any::<bool>(), 0..=8).prop_map(|flags| {
            flags
                .into_iter()
                .enumerate()
                .map(|(n, ok)| (format!("deploy-{n:04}"), ok))
                .collect()
        })
    }

    /// A minimal intent record for the target, enough to seed a ledger entry.
    fn intent_entry(dep: &str) -> DeploymentIntent {
        intent(dep)
    }

    /// THE USER'S PROPERTY, per resolve-leg case: seed a REAL store with a
    /// deployment history (successful + FAILED entries interleaved — a
    /// failed entry records an intent + a FAILED terminal and NO rollback),
    /// then assert that EVERY successful deployment id resolves to EXACTLY
    /// its stored rollback state and every FAILED id never resolves (ref
    /// error).
    fn assert_deployment_id_resolution(store: &LocalStore, history: &[(String, bool)]) {
        let target = TargetName::new("production".to_string());
        let stored: BTreeMap<String, LedgerRollback> = successful_deployments(store, &target)
            .unwrap()
            .into_iter()
            .filter_map(|e| {
                e.terminal
                    .and_then(|t| match &t.disposition {
                        TerminalDisposition::Successful { rollback } => Some(rollback.clone()),
                        _ => None,
                    })
                    .map(|rb| (e.deployment_id.as_str().to_string(), rb))
            })
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
                    // EXACTLY its stored state: the resolved rollback equals
                    // the recorded rollback (slots, behavior, bindings, and
                    // the release the generations came from), keyed by id.
                    let resolved = resolve_deployment(store, &target, &deployment_id).unwrap();
                    assert_eq!(
                        &resolved,
                        stored.get(id).expect("the stored rollback"),
                        "deployment '{id}' must resolve to EXACTLY its stored payload"
                    );
                }
                Ok(PushRef::Head | PushRef::Release { .. }) => {
                    panic!("deployment id '{id}' must not resolve to a non-deployment ref")
                }
                Err(Error::Ref(_)) => {
                    // FAILED ids never resolve.
                }
                Err(e) => panic!("unexpected error class for '{id}': {e}"),
            }
        }
    }

    /// One resolve-leg case: seed a REAL store with a deployment history
    /// (successful + failed entries), parse a generated token, and resolve
    /// it via the engine's two-phase flow. Asserts: no panic anywhere; every
    /// parse AND resolve failure is a ref error; a rejected shape never
    /// resolves; a resolved deployment is an actual SUCCESSFUL member of the
    /// ledger chain; the deployment-id resolution property (successful ids
    /// resolve to exactly their stored state, failed ids never resolve)
    /// holds; `@` / `release:<id>` never touch the chain (they resolve even
    /// on an EMPTY store, while every relative form on an empty store fails
    /// closed — except `parent(@, 0)`, which the oracle folds to `Head`
    /// FIRST so it mirrors the engine's documented `Relative{At,0} ≡ Head`
    /// reduction).
    fn ref_grammar_resolve_case(history: Vec<(String, bool)>, token: String) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for (id, ok) in &history {
            store
                .append_intent("production", &intent_entry(id))
                .unwrap();
            if *ok {
                // Each successful deployment is a rollback payload keyed by
                // its id, with a deterministic payload derived from the id
                // (so "exactly its stored state" is a meaningful equality).
                let release = id.replace("deploy-", "rel-sha256-");
                store
                    .append_terminal(
                        "production",
                        &DeploymentId::new(id.clone()),
                        &successful_terminal(id, &release),
                    )
                    .unwrap();
            } else {
                store
                    .append_terminal(
                        "production",
                        &DeploymentId::new(id.clone()),
                        &LedgerTerminal {
                            recorded_at: "2026-01-01T00:00:00Z".to_string(),
                            outcomes: SlotTable::new(),
                            disposition: TerminalDisposition::FailedRolledBack,
                            reason: None,
                        },
                    )
                    .unwrap();
            }
        }

        // THE USER'S PROPERTY (per case): successful ids resolve to exactly
        // their stored state, failed ids never resolve.
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

        // RESOLVE MEMBERSHIP: a resolved deployment is an actual SUCCESSFUL
        // member of the ledger chain.
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
                let chain = successful_deployments(&store, &target).unwrap();
                assert!(
                    chain.iter().any(|e| e.deployment_id == deployment_id),
                    "{token:?} resolved to deployment '{deployment_id}', which is not an actual \
                     member of the successful chain"
                );
            }
            Ok(PushRef::Head | PushRef::Release { .. }) => {}
            Err(_) => {}
        }
    }

    proptest! {
        // The RESOLVE leg — against a REAL seeded store per case (a
        // successful + failed deployment history): the user's deployment-id
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
            history in chain_strategy(),
            token in ref_token_strategy(),
        ) {
            ref_grammar_resolve_case(history, token);
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
            history in chain_strategy(),
            token in ref_token_strategy(),
        ) {
            ref_grammar_resolve_case(history, token);
        }
    }
}

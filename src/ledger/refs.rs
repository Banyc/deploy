//! Reference RESOLUTION against the deployment ledger (feature area A2:
//! Ledger semantics — the reference grammar itself lives in
//! [`crate::deploy::refs`], owned by another pass).
//!
//! The reference LANGUAGE is encapsulated in [`crate::deploy::refs`]: a pure,
//! store-free grammar whose `crate::deploy::refs::parse_ref_expr` returns only
//! the AST (`RefExpr` and friends, re-exported below) — no store access,
//! no resolution. This module keeps only the store-dependent RESOLUTION
//! (`resolve_ref_expr`) that FOLLOWS the AST against the target's LEDGER:
//! the ledger's SUCCESSFUL terminal events in append order ARE the
//! deployment history (each successful deployment IS a rollback payload
//! KEYED BY ITS DEPLOYMENT ID), so `deploy push <target> <deployment-id>`
//! restores exactly that deployment's stored state and the relative refs
//! (`@-`, `@--`, `parent(@, N)`, `<deployment-id>-`, ...) walk the ledger's
//! successful chain. Failed/degraded/pending/checkpointed-away ids never
//! resolve (fail closed — never underflow, never guess). Positions are
//! DERIVED from the ledger order ([`successful_index`], internal only —
//! never a public ref).
//!
//! The engine parses the token BEFORE it acquires locks or persists anything
//! (a malformed token fails before any side effect) and resolves only once
//! the ledger is stable (after reconciliation has appended any recovered
//! terminal events), so a relative ref is computed against the
//! POST-reconciliation chain: `@-` means one before the latest INCLUDING
//! this push's reconciled append.
//!
use crate::error::{Error, Result};
use crate::identity::{DeploymentId, ReleaseId, SlotId, TargetName};
use crate::ledger::finalize::LedgerEntry;
use crate::ledger::records::DeploymentIntent;
use crate::ledger::records::{DeploymentStatus, TargetSnapshot};
use crate::store::local::LocalStore;
use std::collections::BTreeMap;

/// The reference LANGUAGE (types + parser) is re-exported here from
/// [`crate::deploy::refs`], which owns the grammar; this module keeps only the
/// store-dependent RESOLUTION ([`resolve_ref_expr`]) that FOLLOWS the AST.
/// The re-export keeps the grammar reachable at [`crate::ledger`] for the
/// in-crate consumers (push engine, plan, checkpoint) that call it through
/// the ledger path.
pub(crate) use crate::deploy::refs::{RefExpr, RelBase, parse_ref_expr};

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
                target: TargetName::parse(target).expect("ledger target is a safe segment"),
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

/// Resolve a deployment id to its stored snapshot (the resulting state of
/// the ledger's successful terminal event). The id must be a SUCCESSFUL
/// deployment of the target; failed, degraded, pending, and
/// already-checkpointed-away deployments never resolve. The snapshot is
/// RESOLVED from the successful entry's intent
/// ([`crate::kernel::snapshot::resolve_snapshot`]) — never stored in the
/// terminal payload.
pub fn resolve_deployment(
    store: &LocalStore,
    target: &TargetName,
    deployment_id: &DeploymentId,
) -> Result<TargetSnapshot> {
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
    if terminal.disposition().is_successful() {
        Ok(crate::kernel::snapshot::resolve_snapshot(entry)?)
    } else {
        Err(Error::r#ref(format!(
            "deployment '{deployment_id}' on target '{target}' ended {:?} — only successful deployments carry a snapshot",
            terminal.status()
        )))
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
pub fn attempt_slot_ids(attempt: &DeploymentIntent) -> Vec<SlotId> {
    // The SELECTED membership is the intent's Deploy slots (deployment
    // order).
    attempt.selected().map(|(k, _)| k).collect()
}

/// Build a map of rollback display names (`deployment <deployment-id> of
/// target <target>`) -> snapshot payload, for `deploy log`-style rendering.
/// Each snapshot is RESOLVED from the successful entry's intent.
pub fn deployment_index(
    store: &LocalStore,
    target: &TargetName,
) -> Result<BTreeMap<String, TargetSnapshot>> {
    let mut out = BTreeMap::new();
    for e in successful_deployments(store, target)? {
        out.insert(
            ref_name(target, &e.deployment_id),
            crate::kernel::snapshot::resolve_snapshot(&e)?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, DeploymentId, ServerId, SlotId, VariantName, test_deployment_id,
        test_generation_id, test_tree_digest,
    };
    use crate::ledger::records::LedgerTerminal;
    use crate::ledger::records::PhysicalBinding;
    use crate::ledger::records::{DeploymentIntent, TargetSnapshot};
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::{FileFailurePersistence, RngSeed};
    use std::collections::BTreeMap;

    // The reference-language test helpers (grammar generators, the
    // canonical fold, and the panic-free parse runner) live with the
    // parser in [`crate::deploy::refs::tests`]; the resolve leg imports them so
    // the parse/resolve contract stays pinned in ONE place.
    use crate::deploy::refs::tests::{fold, parse_no_panic, ref_token_strategy};

    /// A minimal but VALID FULL-push intent for the target: one slot `p1`
    /// with per-deployment generation/artifact/binding values DERIVED from
    /// the deployment id (so "exactly its stored state" is a meaningful
    /// equality), built through the kernel's validated constructor.
    fn intent(dep: &str) -> DeploymentIntent {
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::kernel::snapshot::SnapshotSlot;
        use crate::ledger::Observation;
        let p1 = SlotId::parse("p1").unwrap();
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(dep),
            target: TargetName::parse("production").unwrap(),
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1.clone(),
                result: SnapshotSlot::new(
                    test_generation_id(&format!("gen-{dep}")),
                    ArtifactRef {
                        release: crate::identity::test_release_id(dep),
                        variant: VariantName::parse("standard").unwrap(),
                        tree: test_tree_digest(&format!("tree-{dep}")),
                    },
                    PhysicalBinding {
                        server: ServerId::parse("server-01").unwrap(),
                        deploy_dir: "/srv/deploy/p1".to_string(),
                    },
                ),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: crate::identity::BehaviorDigest::parse(
                crate::identity::DIGEST_TEST_HEX_1,
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("the refs-test intent plans")
    }

    /// A SUCCESSFUL terminal BOUND to [`intent`] — the terminal is
    /// PAYLOAD-FREE; the snapshot resolves from the intent's slot table (the
    /// `release` argument is retained for call-site compatibility).
    fn successful_terminal(dep: &str, _release: &str) -> LedgerTerminal {
        crate::testutil::fixtures::successful_terminal(&intent(dep))
    }

    /// Seed `count` successful deployments (ids `deploy-0`..`deploy-{n-1}`,
    /// releases derived from the ids) onto the target's ledger.
    fn seed_chain(store: &LocalStore, count: usize) -> Vec<String> {
        let mut ids = Vec::new();
        for n in 0..count {
            let id = format!("deploy-{n}");
            let canonical = test_deployment_id(&id);
            store.append_intent("production", &intent(&id)).unwrap();
            store
                .append_terminal(
                    "production",
                    &canonical,
                    &successful_terminal(&id, crate::identity::test_release_id(&id).as_str()),
                )
                .unwrap();
            ids.push(canonical.as_str().to_string());
        }
        ids
    }

    fn dep_ref(target: &TargetName, deployment_id: &str) -> PushRef {
        PushRef::Deployment {
            target: target.clone(),
            deployment_id: DeploymentId::parse(deployment_id).expect("canonical id"),
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
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let ids = seed_chain(&store, 6);
        let target = TargetName::parse("production").unwrap();
        for (token, want) in [
            ("@-".to_string(), ids[4].as_str()),
            ("@--".to_string(), ids[3].as_str()),
            ("parent(@, 3)".to_string(), ids[2].as_str()),
            ("parent(@, 2)".to_string(), ids[3].as_str()),
            (format!("{}--", ids[4]), ids[2].as_str()),
            (format!("parent({}, 2)", ids[5]), ids[3].as_str()),
            (format!("{}-", ids[1]), ids[0].as_str()),
            (ids[1].clone(), ids[1].as_str()),
            (format!("parent({}, 0)", ids[1]), ids[1].as_str()),
            (format!("parent({}, 1)", ids[2]), ids[1].as_str()),
        ] {
            assert_eq!(
                resolve(&token, &store).unwrap(),
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
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let ids = seed_chain(&store, 6);
        let target = TargetName::parse("production").unwrap();
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
        let rollback =
            resolve_deployment(&store, &target, &DeploymentId::parse(&ids[2]).unwrap()).unwrap();
        assert_eq!(
            rollback
                .get(&SlotId::new("p1"))
                .unwrap()
                .generation()
                .as_str(),
            test_generation_id("gen-deploy-2").as_str()
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
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        // The canonical full form AND the bare 64-hex digest (converted by
        // the CLI parser BEFORE the strict domain parse) both resolve to the
        // same canonical release.
        let rid = crate::identity::test_release_id("rel-sha256-cccc");
        let bare = rid.digest();
        assert_eq!(
            resolve_ref_expr(
                &parse_ref_expr(&format!("release:{rid}")).expect("token must parse"),
                "production",
                &store
            )
            .unwrap(),
            PushRef::Release {
                release: rid.clone()
            }
        );
        assert_eq!(
            resolve_ref_expr(
                &parse_ref_expr(&format!("release:{bare}")).expect("token must parse"),
                "production",
                &store
            )
            .unwrap(),
            PushRef::Release {
                release: rid.clone()
            }
        );
        // A release that is not referenced by any ledger — and a target with
        // an EMPTY chain — resolve the same way: resolution never reads the
        // store.
        let empty = LocalStore::with_base(tmp.path().join("store2")).unwrap();
        let rid2 = crate::identity::test_release_id("rel-sha256-zzzz");
        assert_eq!(
            resolve_ref_expr(
                &parse_ref_expr(&format!("release:{rid2}")).expect("must parse"),
                "brand-new-target",
                &empty
            )
            .unwrap(),
            PushRef::Release { release: rid2 }
        );
    }

    /// Out-of-range and unresolvable references fail closed with a ref
    /// error: stepping before the chain start, a missing deployment id, and
    /// an EMPTY chain. Never underflow, never guess.
    #[test]
    fn resolve_ref_failures_fail_closed() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_chain(&store, 4);
        let c0 = test_deployment_id("deploy-0");
        let c1 = test_deployment_id("deploy-1");
        for token in [
            "parent(@, 6)".to_string(), // len 4, so 6 steps back underflows
            format!("{c0}-"),           // deploy-0 is the first deployment
            format!("{c0}--"),
            format!("parent({c1}, 2)"),
            format!("parent({c0}, 1)"),
            "deploy-missing".to_string(),
            "deploy-missing-".to_string(),
            "parent(deploy-missing, 1)".to_string(),
        ] {
            let err = resolve(&token, &store).expect_err(&format!("{token} must fail closed"));
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
                &TargetName::parse("production").unwrap(),
                &test_deployment_id("deploy-abc")
            ),
            format!(
                "deployment {} of target production",
                test_deployment_id("deploy-abc")
            )
        );
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
                .map(|(n, ok)| {
                    (
                        test_deployment_id(&format!("deploy-{n:04}"))
                            .as_str()
                            .to_string(),
                        ok,
                    )
                })
                .collect()
        })
    }

    /// A minimal intent record for the target, enough to seed a ledger entry.
    /// `dep` is a CANONICAL deployment id (the ledger is keyed by the
    /// validated form).
    fn intent_entry(dep: &str) -> DeploymentIntent {
        // Rebuild the one-slot intent with a CANONICAL deployment id (the
        // ledger is keyed by the validated form).
        let p1 = SlotId::parse("p1").unwrap();
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::kernel::snapshot::SnapshotSlot;
        use crate::ledger::Observation;
        crate::kernel::intent::plan(PlanInput {
            deployment_id: DeploymentId::parse(dep).expect("canonical seeded id"),
            target: TargetName::parse("production").unwrap(),
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1.clone(),
                result: SnapshotSlot::new(
                    test_generation_id(&format!("gen-{dep}")),
                    ArtifactRef {
                        release: crate::identity::test_release_id(dep),
                        variant: VariantName::parse("standard").unwrap(),
                        tree: test_tree_digest(&format!("tree-{dep}")),
                    },
                    PhysicalBinding {
                        server: ServerId::parse("server-01").unwrap(),
                        deploy_dir: "/srv/deploy/p1".to_string(),
                    },
                ),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: crate::identity::BehaviorDigest::parse(
                crate::identity::DIGEST_TEST_HEX_1,
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("the refs-test entry intent plans")
    }

    /// THE USER'S PROPERTY, per resolve-leg case: seed a REAL store with a
    /// deployment history (successful + FAILED entries interleaved — a
    /// failed entry records an intent + a FAILED terminal and NO rollback),
    /// then assert that EVERY successful deployment id resolves to EXACTLY
    /// its stored rollback state and every FAILED id never resolves (ref
    /// error).
    fn assert_deployment_id_resolution(store: &LocalStore, history: &[(String, bool)]) {
        let target = TargetName::parse("production").unwrap();
        let stored: BTreeMap<String, TargetSnapshot> = successful_deployments(store, &target)
            .unwrap()
            .into_iter()
            .filter(|e| {
                e.terminal
                    .as_ref()
                    .is_some_and(|t| t.disposition().is_successful())
            })
            .map(|e| {
                let rb = crate::kernel::snapshot::resolve_snapshot(&e)
                    .expect("a successful entry resolves its snapshot");
                (e.deployment_id.as_str().to_string(), rb)
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
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for (id, ok) in &history {
            store
                .append_intent("production", &intent_entry(id))
                .unwrap();
            if *ok {
                // Each successful deployment is a rollback payload keyed by
                // its id, with a deterministic payload derived from the id
                // (so "exactly its stored state" is a meaningful equality).
                // The terminal binds the EXACT appended intent (its digest
                // is validated by the reader/append — a re-derived intent
                // would carry a different canonical digest).
                let it = intent_entry(id);
                store
                    .append_terminal(
                        "production",
                        it.deployment_id(),
                        &crate::testutil::fixtures::successful_terminal(&it),
                    )
                    .unwrap();
            } else {
                let it = intent_entry(id);
                store
                    .append_terminal(
                        "production",
                        it.deployment_id(),
                        &crate::testutil::fixtures::rolled_back_terminal(
                            &it,
                            &it.full_membership().into_iter().collect::<Vec<_>>(),
                        ),
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
        // seeds + failure persistence, bounded at `proptest_cases(96)` (full
        // 96 with `DEPLOY_FULL_TESTS=1`, fast default; each case builds
        // a small tempdir store, so the bound keeps the suite fast).
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(96),
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
            cases: crate::testutil::proptest_cases(96),
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

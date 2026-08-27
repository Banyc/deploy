//! The MERGED deployment entry (feature area A2: Ledger semantics) — the
//! intent + optional terminal merge type the ledger's append/read path
//! carries.
//!
//! The two physical line kinds ([`crate::ledger::finalize::LedgerLine`] —
//! the WIRE enum the append-only JSONL stream carries) live in
//! [`crate::ledger::finalize`]; the merged ENTRY is this module's
//! [`LedgerEntry`]: the durable INTENT plus the optional TERMINAL EVENT
//! (absent while the deployment is in flight or recoverable-pending), with
//! the entry owning the deployment identity (the terminal carries none).
//! [`crate::store::local::LocalStore::read_ledger`] parses the wire lines,
//! runs the VERIFYING CONVERSION (refusing disagreeing records — an
//! entry's terminal must key the same deployment id, name the same target,
//! and cover exactly the intent's membership), and merges the validated
//! domain records into [`LedgerEntry`]s keyed by deployment id.

use crate::identity::{DeploymentId, TargetName};

use super::super::{DeploymentIntent, LedgerTerminal};
/// A merged deployment entry of the target's ledger: the durable INTENT plus
/// the optional TERMINAL EVENT (absent while the deployment is in flight or
/// recoverable-pending). The append order is the history order; `seq` is the
/// position of the intent line in the ledger. Only VALIDATED domain records
/// ([`DeploymentIntent`], [`LedgerTerminal`]) live here — never raw wire shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub intent: DeploymentIntent,
    pub terminal: Option<LedgerTerminal>,
    /// The position of this entry's intent line in the ledger (0-based
    /// append order — the entry's history position).
    pub seq: u64,
}

#[cfg(test)]
mod tests_entry {
    use super::*;
    // The ledger's two line kinds live in [`crate::ledger::finalize`]; the
    // wire shapes + their conversions live with the records.
    use crate::error::{Error, Result};
    use crate::identity::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, ServerId, SlotId, TargetName,
        VariantName, test_deployment_id, test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::ledger::finalize::LedgerLine;
    use crate::ledger::records::SlotOutcomeKind;
    use crate::ledger::records::{DeploymentIntent, LedgerIntentWire};
    use crate::ledger::records::{
        DeploymentStatus, LedgerRollbackWire, PhysicalBinding, SlotAttemptState, SlotResult,
    };
    use crate::ledger::records::{LedgerTerminal, LedgerTerminalWire, TerminalDisposition};
    use crate::store::local::LocalStore;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::{BTreeMap, BTreeSet};

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    fn slot_strategy() -> impl Strategy<Value = SlotId> {
        (0u32..6).prop_map(slot)
    }

    fn binding(sid: &SlotId) -> PhysicalBinding {
        PhysicalBinding {
            server: ServerId::new("s1".to_string()),
            deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
        }
    }

    /// A generation ref whose assignment names its own key (the agreeing
    /// form); the artifact's release is derived from the slot id.
    fn gen_ref_for(key: &SlotId) -> GenerationRef {
        GenerationRef {
            generation: test_generation_id(key.as_str()),
            assignment: PlacementSlotAssignment {
                placement_slot: key.clone(),
                artifact: ArtifactRef {
                    release: test_release_id(key.as_str()),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest(key.as_str()),
                },
            },
        }
    }
    fn agreeing_intent(keys: &[SlotId]) -> LedgerIntentWire {
        agreeing_intent_with_group(keys, None)
    }

    /// [`agreeing_intent`] with an explicit GROUP MODE: `Some(g)` selects a
    /// group push (the intent's `slot_ids` are the group's slots), `None` a
    /// full push (the intent's `slot_ids` are every target slot).
    fn agreeing_intent_with_group(keys: &[SlotId], group: Option<&str>) -> LedgerIntentWire {
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: test_deployment_id("deploy-w"),
            target: TargetName::new("t1".to_string()),
            group: group.map(str::to_string),
            slot_ids: keys.to_vec(),
            behavior_sha256: "sha256-w".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    fn outcome_for(key: &SlotId, kind: SlotOutcomeKind) -> SlotResult {
        let compensated = matches!(&kind, SlotOutcomeKind::Restored);
        SlotResult {
            slot_id: key.clone(),
            outcome: kind,
            generation: Some(test_generation_id(key.as_str())),
            compensated,
            error: None,
            observation_error: None,
        }
    }

    /// A terminal wire AGREEING with its intent (identity + outcome-key
    /// membership + status→disposition payload). `status_idx` selects the
    /// status: 0 Successful (complete rollback over the membership), 1
    /// FailedPreflight (no outcomes, no rollback), 2 FailedRolledBack
    /// (outcomes = the compensation report), 3 Degraded (non-restored
    /// outcomes over the membership → non-empty remaining changes). The
    /// Successful shape carries the EXACT-EQUAL memberships (selected ==
    /// full == the membership — the full-push proven shape; the mode is the
    fn agreeing_terminal(keys: &[SlotId], status_idx: u32) -> LedgerTerminalWire {
        let deployment_id = test_deployment_id("deploy-w");
        let target = TargetName::new("t1".to_string());
        match status_idx {
            // Successful: EVERY member slot recorded Activated, the
            // COMPLETE rollback payload covers the same membership with
            // exact bindings, and BOTH memberships equal that membership
            // (the proven exact-equal shape).
            0 => LedgerTerminalWire {
                deployment_id: deployment_id.clone(),
                target: target.clone(),
                status: DeploymentStatus::Successful,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Activated)))
                    .collect(),
                rollback: Some(LedgerRollbackWire {
                    slots: keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect(),
                    bindings: keys.iter().map(|k| (k.clone(), binding(k))).collect(),
                    behavior_sha256: None,
                    release: None,
                }),
                selected_membership: keys.to_vec(),
                full_membership: keys.to_vec(),
                reason: Some("push completed".to_string()),
            },
            // FailedPreflight: pre-mutation — NO outcomes, NO rollback, NO
            // memberships (only a Successful terminal proves them).
            1 => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::FailedPreflight,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: BTreeMap::new(),
                rollback: None,
                selected_membership: vec![],
                full_membership: vec![],
                reason: Some("preflight failed".to_string()),
            },
            // FailedRolledBack: the outcome table IS the compensation
            // report.
            2 => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::FailedRolledBack,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Restored)))
                    .collect(),
                rollback: None,
                selected_membership: vec![],
                full_membership: vec![],
                reason: Some("rolled back".to_string()),
            },
            // Degraded: every member's outcome is a REMAINING change — an
            // UNCOMPENSATED `Failed` (a pre-swap failure / failed
            // compensation: the advance outcome is unknown, and the
            // outcome's observed generation differs from the intent's
            // `pre_push` (None — a first deployment), so the derived
            // remaining-changes set is non-empty).
            _ => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::Degraded,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Failed)))
                    .collect(),
                rollback: None,
                selected_membership: vec![],
                full_membership: vec![],
                reason: Some("degraded".to_string()),
            },
        }
    }

    /// A valid (intent + terminal) WIRE PAIR strategy: non-empty membership
    /// K, exact key-set equality in the intent, and a terminal AGREEING with
    /// the intent's identity and membership.
    fn agreeing_pair() -> impl Strategy<Value = (LedgerIntentWire, LedgerTerminalWire)> {
        (prop::collection::btree_set(slot_strategy(), 1..4), 0u32..4).prop_map(
            |(keys, status_idx)| {
                let keys: Vec<SlotId> = keys.into_iter().collect();
                (
                    agreeing_intent(keys.as_slice()),
                    agreeing_terminal(keys.as_slice(), status_idx),
                )
            },
        )
    }

    // ---- THE VERIFYING PAIR CONVERSION + the read_ledger consumer ---------

    /// Run the full verifying conversion of an intent + terminal pair — the
    /// SAME checks `read_ledger` runs when it merges a terminal into its
    /// entry (the entry owns identity: the terminal's id is the entry key,
    /// its target must equal the entry's, every outcome key must be a
    /// member of the intent's membership, and the outcome key set must
    /// agree with the membership BY STATUS: Successful → the FULL-push
    /// equality leg only (the terminal's own memberships satisfy the
    /// terminal-local equations; the read requires selected == full when
    /// the intent has no group), FailedPreflight → empty, every other
    /// state → EXACT coverage) — returning the validated domain pair.
    fn pair_to_domain(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
    ) -> Result<(DeploymentIntent, LedgerTerminal)> {
        let intent = pair.0.clone().into_domain()?;
        if pair.1.deployment_id != intent.deployment_id {
            return Err(Error::integrity(format!(
                "terminal {}: deployment_id disagrees with its entry (the intent's)",
                pair.1.deployment_id
            )));
        }
        if pair.1.target != intent.target {
            return Err(Error::integrity(format!(
                "terminal {}: target '{}' disagrees with its entry (the intent's target '{}')",
                pair.1.deployment_id, pair.1.target, intent.target
            )));
        }
        for key in pair.1.outcomes.keys() {
            if !intent.slots.contains_key(key) {
                return Err(Error::integrity(format!(
                    "terminal {}: outcome for slot '{key}' is outside the intent's membership",
                    pair.1.deployment_id
                )));
            }
        }
        let terminal = pair.1.clone().into_domain()?;
        // STATUS-SPECIFIC OUTCOME AGREEMENT (the membership leg — the same
        // rules `read_ledger` enforces when it merges the terminal into its
        // entry). The terminal carries its OWN proven memberships (the
        // conversion enforced outcomes == selected, rollback == full,
        // selected ⊆ full — the record is self-proving), so the only
        // Successful leg is the FULL-push equality: a FULL push (no group)
        // selects every target slot, so selected == full; a GROUP push
        // allows a proper subset (the ⊆ is already enforced by the
        // conversion). The intent's `slot_ids` is NOT compared to either
        // membership (it is the historical selected set written before the
        // push; the terminal's memberships are proven at terminal time).
        let outcome_keys: BTreeSet<&SlotId> = terminal.outcomes().keys().collect();
        let membership: BTreeSet<&SlotId> = intent.slots.keys().collect();
        match terminal.status() {
            DeploymentStatus::Successful => {
                if intent.group.is_none() {
                    let (selected, full) = match &terminal.disposition {
                        TerminalDisposition::Successful {
                            selected_membership,
                            full_membership,
                            ..
                        } => (selected_membership, full_membership),
                        _ => {
                            unreachable!("a Successful terminal carries its rollback + memberships")
                        }
                    };
                    if selected != full {
                        return Err(Error::integrity(format!(
                            "terminal {}: Successful records selected membership {selected:?} and full membership {full:?} — a FULL push (no group) selects every target slot, so its selected membership must EXACTLY equal its full membership",
                            pair.1.deployment_id
                        )));
                    }
                }
            }
            DeploymentStatus::FailedPreflight => {
                if !outcome_keys.is_empty() {
                    return Err(Error::integrity(format!(
                        "terminal {}: FailedPreflight must carry NO outcomes (a pre-mutation failure touched no slot)",
                        pair.1.deployment_id
                    )));
                }
            }
            _ => {
                if outcome_keys != membership {
                    return Err(Error::integrity(format!(
                        "terminal {}: outcomes {outcome_keys:?} must EXACTLY cover the intent's membership {membership:?} — no missing, no extra",
                        pair.1.deployment_id
                    )));
                }
            }
        }
        Ok((intent, terminal))
    }

    /// Write the pair as a two-line ledger and read it back through the REAL
    /// consumer path (`read_ledger` — the FIRST consumer; rollback resolve
    /// and GC reachability consume its output, so failing here means failing
    /// BEFORE every consumer).
    fn write_pair_ledger(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
    ) -> Result<Vec<LedgerEntry>> {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(pair.0.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(pair.1.clone())).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        store.read_ledger("t1")
    }

    /// Inspect the DOMAIN shapes produced from a VALID pair: the intent's
    /// ONE table (non-empty, unique keys, every member carries its desired +
    /// pre_push), and the terminal's disposition — each disposition OWNS its
    /// outcomes table (the accessor returns the disposition's OWN table; a
    fn assert_domain_shape(
        intent: &DeploymentIntent,
        terminal: &LedgerTerminal,
        keys: &[SlotId],
        status_idx: u32,
    ) {
        assert!(!intent.slots.is_empty(), "the membership is non-empty");
        assert_eq!(
            intent.slots.len(),
            keys.len(),
            "the table's key count equals the membership count (no duplicates, no missing)"
        );
        assert_eq!(
            intent.membership(),
            keys.to_vec(),
            "the membership is exactly the wire's slot_ids (deployment order)"
        );
        for key in keys {
            let entry = &intent.slots[key];
            assert!(
                entry
                    .desired
                    .artifact
                    .release
                    .as_str()
                    .starts_with("rel-sha256-"),
                "each member carries its desired assignment"
            );
            // The pre_push ENTRY is structural: every member slot has an
            // IntentSlot (with `pre_push: Option<PreviousGeneration>`,
            // `None` for a first deployment) — there is no member without
            // its per-slot data.
        }
        match (&terminal.disposition, status_idx) {
            (
                TerminalDisposition::Successful {
                    rollback, outcomes, ..
                },
                0,
            ) => {
                assert_eq!(
                    rollback.slots.len(),
                    keys.len(),
                    "the complete rollback covers every member slot"
                );
                assert_eq!(
                    rollback.bindings.len(),
                    keys.len(),
                    "every slotted generation carries its physical binding"
                );
                // The Successful disposition OWNS its outcome table: the
                // accessor returns the disposition's OWN table, and every
                // outcome is Activated (the conversion's agreement).
                assert_eq!(
                    terminal.outcomes(),
                    outcomes,
                    "the accessor reads the disposition's OWN table"
                );
                assert_eq!(
                    outcomes.len(),
                    keys.len(),
                    "the Successful disposition owns one outcome per member"
                );
                assert!(
                    outcomes
                        .values()
                        .all(|o| o.outcome == SlotOutcomeKind::Activated),
                    "a Successful disposition's outcomes are all Activated"
                );
                // THE PERSISTED MEMBERSHIPS: the domain exposes both, equal
                // to the membership (the exact-equal proven shape) — the
                // record PROVES selected == full == the outcome/rollback key
                // set.
                assert_eq!(
                    terminal.selected_membership(),
                    Some(&BTreeSet::from_iter(keys.iter().cloned())),
                    "the Successful disposition exposes its selected membership (== the outcomes' keys)"
                );
                assert_eq!(
                    terminal.full_membership(),
                    Some(&BTreeSet::from_iter(keys.iter().cloned())),
                    "the Successful disposition exposes its full membership (== the rollback's slots)"
                );
            }
            (TerminalDisposition::FailedPreflight, 1) => {
                assert!(
                    terminal.outcomes().is_empty(),
                    "preflight touched no slot (the disposition carries no outcomes)"
                );
            }
            (TerminalDisposition::FailedRolledBack { .. }, 2) => {
                let compensation = terminal.compensation().expect(
                    "a FailedRolledBack terminal's compensation report IS its own outcomes table",
                );
                assert_eq!(
                    compensation.len(),
                    keys.len(),
                    "the compensation report covers every compensated slot"
                );
                assert!(
                    compensation
                        .iter()
                        .all(|(_, r)| r.outcome == SlotOutcomeKind::Restored),
                    "the compensation records the restored slots"
                );
            }
            (TerminalDisposition::Degraded { .. }, 3) => {
                let remaining_changes = terminal
                    .remaining_changes(intent)
                    .expect("a Degraded terminal derives its remaining changes from the outcomes");
                assert!(
                    !remaining_changes.is_empty(),
                    "degraded keeps non-empty remaining changes"
                );
                assert_eq!(
                    remaining_changes.len(),
                    keys.len(),
                    "every non-restored slot is a remaining change"
                );
                // The Degraded disposition OWNS its outcome table: the
                // accessor returns the disposition's OWN table (the
                // remaining changes derive from it).
                let TerminalDisposition::Degraded { outcomes } = &terminal.disposition else {
                    unreachable!("matched above");
                };
                assert_eq!(
                    terminal.outcomes(),
                    outcomes,
                    "the accessor reads the disposition's OWN table"
                );
            }
            (d, s) => panic!("disposition {d:?} does not match the wire status index {s}"),
        }
    }

    // ---- the mutations: ONE field at a time --------------------------------

    /// A single-field terminal tamper (the property applies ONE per case).
    type TerminalMutation = fn(&mut LedgerTerminalWire);
    fn tamper_status(t: &mut LedgerTerminalWire) {
        t.status = match &t.status {
            DeploymentStatus::Successful => DeploymentStatus::FailedPreflight,
            DeploymentStatus::FailedPreflight => DeploymentStatus::Successful,
            DeploymentStatus::FailedRolledBack => DeploymentStatus::Successful,
            DeploymentStatus::Degraded => DeploymentStatus::FailedPreflight,
            other => other.clone(),
        };
    }
    fn rollback_added_to_failed(t: &mut LedgerTerminalWire) {
        if t.status != DeploymentStatus::Successful {
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        } else {
            t.rollback = None;
        }
    }
    fn rollback_extra_binding(t: &mut LedgerTerminalWire) {
        if let Some(rb) = t.rollback.as_mut() {
            rb.bindings.insert(slot(9), binding(&slot(9)));
        } else {
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        }
    }
    fn outcome_slot_mismatch(t: &mut LedgerTerminalWire) {
        if let Some((_, r)) = t.outcomes.iter_mut().next() {
            // An outcome value naming a DIFFERENT placement than its key.
            r.slot_id = slot(9);
        } else {
            // No outcomes (FailedPreflight): add one whose value names a
            // different placement than its key.
            t.outcomes
                .insert(slot(0), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        }
    }
    fn outcome_outside_membership(t: &mut LedgerTerminalWire) {
        t.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
    }
    fn outcome_status_vs_disposition(t: &mut LedgerTerminalWire) {
        match &t.status {
            DeploymentStatus::Degraded => {
                // The Degraded disposition implies non-restored remaining
                // changes; an all-restored outcome table is a disagreement.
                for r in t.outcomes.values_mut() {
                    r.outcome = SlotOutcomeKind::Restored;
                }
            }
            DeploymentStatus::FailedPreflight => {
                // A pre-mutation failure touched no slot; any outcome is a
                // disagreement.
                t.outcomes
                    .insert(slot(0), outcome_for(&slot(0), SlotOutcomeKind::Activated));
            }
            DeploymentStatus::Successful => {
                // The Successful disposition implies every slot activated; a
                // failed outcome is a disagreement.
                if let Some(r) = t.outcomes.values_mut().next() {
                    r.outcome = SlotOutcomeKind::Failed;
                }
            }
            DeploymentStatus::FailedRolledBack => {
                // The compensation report IS the outcome table — no per-slot
                // status can disagree with it; the disagreement is a
                // rollback payload on a failed status.
                t.rollback = Some(LedgerRollbackWire {
                    slots: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                    behavior_sha256: None,
                    release: None,
                });
            }
            other => panic!("unexpected wire status {other:?}"),
        }
    }
    fn outcome_key_vs_rollback_slots(t: &mut LedgerTerminalWire) {
        if t.status == DeploymentStatus::Successful {
            // The Successful rollback is the authoritative rollback fact; an
            // outcome key the rollback no longer covers is a disagreement.
            let Some(rb) = t.rollback.as_mut() else {
                return;
            };
            let Some(key) = rb.slots.keys().next().cloned() else {
                return;
            };
            rb.slots.remove(&key);
            rb.bindings.remove(&key);
        } else {
            // Only Successful may carry a rollback; a failed status with one
            // is a disagreement.
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        }
    }
    fn reason_mutated(t: &mut LedgerTerminalWire) {
        // The reason is a free-form human NOTE, not a fact: it never
        // participates in invariants, so mutating it is NOT a disagreement.
        t.reason = Some("tampered note".to_string());
    }
    fn target_mismatch(t: &mut LedgerTerminalWire) {
        t.target = TargetName::new("other-target".to_string());
    }
    fn deployment_id_mismatch(t: &mut LedgerTerminalWire) {
        t.deployment_id = test_deployment_id("deploy-other");
    }

    proptest! {
        // PROPERTY (the directive's point 4): generate VALID wire pairs
        // (intent + terminal), then mutate ONE duplicated fact at a time —
        // the status→disposition mapping, the rollback payload, an outcome
        // slot, an outcome's status vs the disposition's implied state, an
        // outcome key vs the rollback's slots, the target identity — and
        // assert EVERY disagreement fails the verifying conversion BEFORE
        // any consumer (the REAL read_ledger consumer path), while the
        // VALID pair converts to a DOMAIN whose SHAPE has no
        // duplicates/missing keys (asserted by inspection of the
        // NonEmptySlotTable / outcomes / disposition) and whose DERIVED
        // methods (`remaining_changes`, `compensation`) agree with the
        // outcomes by construction. The REASON is a free-form human note,
        // NOT a fact: mutating it never creates a disagreement — the
        // conversion succeeds and carries the note through unchanged.
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
        // persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wire_pair_mutations_fail_before_any_consumer_and_valid_pairs_shape(
            (intent, terminal) in agreeing_pair()
        ) {
            let keys: Vec<SlotId> = intent.slot_ids.clone();
            let status_idx = match terminal.status {
                DeploymentStatus::Successful => 0,
                DeploymentStatus::FailedPreflight => 1,
                DeploymentStatus::FailedRolledBack => 2,
                DeploymentStatus::Degraded => 3,
                other => panic!("unexpected wire status {other:?}"),
            };
            let (d_intent, d_terminal) = pair_to_domain(&(intent.clone(), terminal.clone()))
                .expect("the agreeing pair converts");
            assert_domain_shape(&d_intent, &d_terminal, &keys, status_idx);
            let entries = write_pair_ledger(&(intent.clone(), terminal.clone()))
                .expect("the agreeing pair reads through the real ledger");
            assert_eq!(entries.len(), 1, "one merged entry");
            assert_domain_shape(
                &entries[0].intent,
                entries[0].terminal.as_ref().unwrap(),
                &keys,
                status_idx,
            );

            let mutations: [(&str, TerminalMutation); 9] = [
                ("status→disposition mismatch", tamper_status),
                ("rollback payload mismatch (missing on Successful / added to a failed status)", rollback_added_to_failed),
                ("rollback binding without a generation", rollback_extra_binding),
                ("outcome value naming a different slot", outcome_slot_mismatch),
                ("outcome key outside the membership", outcome_outside_membership),
                ("outcome status vs the disposition's implied state", outcome_status_vs_disposition),
                ("outcome key vs the rollback's slots", outcome_key_vs_rollback_slots),
                ("terminal target disagrees with the entry", target_mismatch),
                ("terminal deployment id keys no intent line", deployment_id_mismatch),
            ];
            for (name, mutate) in mutations {
                let mut bad = (intent.clone(), terminal.clone());
                mutate(&mut bad.1);
                let err = pair_to_domain(&bad);
                assert!(
                    err.is_err(),
                    "{name} must fail the conversion BEFORE any consumer"
                );
                let ledger_err = write_pair_ledger(&bad);
                assert!(
                    ledger_err.is_err(),
                    "{name} must fail read_ledger (the first consumer)"
                );
            }

            // The REASON is a free-form human note, NOT a fact: mutating it
            // never creates a disagreement — the conversion succeeds and
            // carries the note through unchanged (it never participates in
            // invariants).
            let mut noted = (intent, terminal);
            reason_mutated(&mut noted.1);
            let (_, d_terminal) =
                pair_to_domain(&noted).expect("a mutated reason is not a disagreement");
            assert_eq!(
                d_terminal.reason.as_deref(),
                Some("tampered note"),
                "the note is carried through unchanged"
            );
        }
    }

    // ---- THE MEMBERSHIP-EQUATIONS PROPERTY (Successful) --------------------

    /// One key-set operation applied to ONE of the four INDEPENDENT SETS
    /// (outcomes, selected_membership, full_membership, rollback slots).
    /// The ops are chosen INDEPENDENTLY per set; the application is
    /// deterministic given the op (delete the first key / add the first
    /// absent slot / replace the first key with a different absent slot), so
    /// the property's "acceptance iff the membership equations hold" verdict
    /// is exact.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KeyOp {
        Unchanged,
        Delete,
        Add,
        Replace,
    }
    fn key_op() -> impl Strategy<Value = KeyOp> {
        prop_oneof![
            Just(KeyOp::Unchanged),
            Just(KeyOp::Delete),
            Just(KeyOp::Add),
            Just(KeyOp::Replace),
        ]
    }

    /// Apply one key op to a slot set (deterministic: delete the first
    /// key, add the first slot absent from the set, replace the first key
    /// with the first absent slot).
    fn apply_key_op(set: &BTreeSet<SlotId>, op: KeyOp) -> BTreeSet<SlotId> {
        let mut out = set.clone();
        match op {
            KeyOp::Unchanged => {}
            KeyOp::Delete => {
                if let Some(k) = out.iter().next().cloned() {
                    out.remove(&k);
                }
            }
            KeyOp::Add => {
                for i in 0..6u32 {
                    let k = slot(i);
                    if !out.contains(&k) {
                        out.insert(k);
                        break;
                    }
                }
            }
            KeyOp::Replace => {
                if let Some(k) = out.iter().next().cloned() {
                    out.remove(&k);
                    for i in 0..6u32 {
                        let nk = slot(i);
                        if !out.contains(&nk) && nk != k {
                            out.insert(nk);
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    /// Rebuild the intent wire with a NEW membership, keeping the intent's
    /// internal agreement (slot_ids == desired == pre_push, each assignment
    /// names its own key, the wire actuals map empty).
    fn intent_with_membership(
        intent: &LedgerIntentWire,
        membership: &BTreeSet<SlotId>,
    ) -> LedgerIntentWire {
        let keys: Vec<SlotId> = membership.iter().cloned().collect();
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: intent.deployment_schema_version,
            deployment_id: intent.deployment_id.clone(),
            target: intent.target.clone(),
            group: intent.group.clone(),
            slot_ids: keys.clone(),
            behavior_sha256: intent.behavior_sha256.clone(),
            attempted_at: intent.attempted_at.clone(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    /// Apply the four INDEPENDENT key ops to a valid Successful pair and
    /// return the tampered pair: (1) the outcomes keys, (2) the
    /// selected_membership, (3) the full_membership, (4) the rollback's
    /// slots keys — with the rollback's BINDINGS COUPLED to its slots
    /// (slots == bindings is the separate structural rollback invariant,
    /// NOT one of the four independent sets — the user's requirement
    /// couples them here). The intent is REBUILT over the UNION of the four
    /// resulting sets (so the intent never adds a verdict of its own: every
    /// outcome key is an intent member by construction, and the read's
    /// Successful leg compares only the terminal's OWN memberships) with the
    /// given MODE applied to its `group` (`Some("g1")` = group push,
    /// `None` = full push).
    fn apply_four_set_tamper(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
        ops: [KeyOp; 4],
        group: bool,
    ) -> (LedgerIntentWire, LedgerTerminalWire) {
        let (intent, terminal) = pair;
        let mut terminal = terminal.clone();
        // (1) outcomes keys.
        let outcome_keys: BTreeSet<SlotId> = terminal.outcomes.keys().cloned().collect();
        let new_outcomes = apply_key_op(&outcome_keys, ops[0]);
        terminal.outcomes = new_outcomes
            .iter()
            .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Activated)))
            .collect();
        // (2) selected_membership, (3) full_membership.
        let selected: BTreeSet<SlotId> = terminal.selected_membership.iter().cloned().collect();
        terminal.selected_membership = apply_key_op(&selected, ops[1]).into_iter().collect();
        let full: BTreeSet<SlotId> = terminal.full_membership.iter().cloned().collect();
        terminal.full_membership = apply_key_op(&full, ops[2]).into_iter().collect();
        // (4) rollback slots keys (bindings coupled to the slots).
        let rb = terminal
            .rollback
            .as_mut()
            .expect("a Successful terminal carries its rollback");
        let slot_keys: BTreeSet<SlotId> = rb.slots.keys().cloned().collect();
        let new_slots = apply_key_op(&slot_keys, ops[3]);
        rb.slots = new_slots
            .iter()
            .map(|k| (k.clone(), gen_ref_for(k)))
            .collect();
        rb.bindings = new_slots.iter().map(|k| (k.clone(), binding(k))).collect();
        // The intent: rebuilt over the UNION of the four resulting sets so it
        // never adds a verdict (every outcome key is an intent member), with
        // the mode applied to its `group`.
        let union: BTreeSet<SlotId> = terminal
            .outcomes
            .keys()
            .cloned()
            .chain(terminal.selected_membership.iter().cloned())
            .chain(terminal.full_membership.iter().cloned())
            .chain(rb.slots.keys().cloned())
            .collect();
        let mut intent = intent_with_membership(intent, &union);
        intent.group = if group { Some("g1".to_string()) } else { None };
        (intent, terminal)
    }

    /// Evaluate THE MEMBERSHIP EQUATIONS for a written pair (the four sets +
    /// the mode) — the acceptance criterion the properties assert
    /// `read_ledger` is EXACTLY EQUIVALENT to:
    ///
    /// * outcomes == selected_membership
    /// * rollback slots == full_membership (bindings == slots by
    ///   construction — the coupled structural invariant)
    /// * selected_membership ⊆ full_membership
    /// * (FULL mode) selected_membership == full_membership — in GROUP mode
    ///   a proper-subset selected is allowed
    ///
    /// plus the Successful NON-EMPTINESS (a successful deployment records
    /// non-empty outcomes and both memberships non-empty).
    fn membership_equations_hold(pair: &(LedgerIntentWire, LedgerTerminalWire)) -> bool {
        let terminal = &pair.1;
        let outcomes: BTreeSet<SlotId> = terminal.outcomes.keys().cloned().collect();
        let selected: BTreeSet<SlotId> = terminal.selected_membership.iter().cloned().collect();
        let full: BTreeSet<SlotId> = terminal.full_membership.iter().cloned().collect();
        let rollback_slots: BTreeSet<SlotId> = terminal
            .rollback
            .as_ref()
            .map(|rb| rb.slots.keys().cloned().collect())
            .unwrap_or_default();
        let full_mode = pair.0.group.is_none();
        outcomes == selected
            && rollback_slots == full
            && selected.is_subset(&full)
            && (!full_mode || selected == full)
            && !outcomes.is_empty()
            && !selected.is_empty()
            && !full.is_empty()
            && !rollback_slots.is_empty()
    }

    /// The GROUP/FULL MODE of a Successful pair, generated per house style.
    fn membership_mode() -> impl Strategy<Value = bool> {
        prop_oneof![Just(true), Just(false)]
    }

    proptest! {
        // PROPERTY 1 (the user's requirement — the acceptance equivalence):
        // generate the FOUR INDEPENDENT SETS — (1) the outcome keys, (2)
        // the selected_membership, (3) the full_membership, (4) the
        // rollback's slot keys (bindings generated EQUAL to the slots — the
        // separate structural rollback invariant, kept coupled here) — by
        // INDEPENDENTLY DELETE / ADD / REPLACE ops from a valid base pair,
        // plus a group/full MODE. READING (the real `read_ledger` of the
        // written pair — the durable write → re-read path) SUCCEEDS IFF
        // THE MEMBERSHIP EQUATIONS HOLD FOR THAT MODE: outcomes ==
        // selected_membership, rollback slots == full_membership, selected
        // ⊆ full, and (full mode) selected == full — with a group mode a
        // proper-subset selected is allowed — plus the Successful
        // non-emptiness. The intent is rebuilt over the union of the four
        // sets so it never adds a verdict of its own; the mode is applied to
        // the intent's `group`. Bounded 16 cases, fixed seed 0x5EED_5EED
        // per house style, no persistence.
        //
        // PROPERTY 2 (the user's requirement — single-set mutation
        // rejection): start from a VALID pair (all equations hold), apply a
        // tamper to EXACTLY ONE of the four sets (add/remove/change a key)
        // while leaving the other three AND the mode fixed, and assert
        // read_ledger REJECTS — every single-set mutation breaks at least
        // one equation (mutating the outcomes or the selected membership
        // alone breaks outcomes == selected; mutating the full membership or
        // the rollback slots alone breaks rollback == full). The rejection
        // is asserted through the REAL ledger file (write → re-read — the
        // crash-recovery read path), so a tampered record is refused even
        // after a durable write.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn successful_membership_equations_are_necessary_and_sufficient(
            (intent, terminal) in agreeing_pair().prop_filter(
                "the property needs a Successful pair",
                |(_, t)| t.status == DeploymentStatus::Successful,
            ),
            ops in prop::array::uniform4(key_op()),
            group in membership_mode(),
        ) {
            let (t_intent, t_terminal) = apply_four_set_tamper(&(intent, terminal), ops, group);
            let pair = (t_intent, t_terminal);
            let expect_ok = membership_equations_hold(&pair);
            let read = write_pair_ledger(&pair);
            assert_eq!(
                read.is_ok(),
                expect_ok,
                "read_ledger must succeed iff the membership equations hold for the mode (outcomes {:?}, selected {:?}, full {:?}, rollback slots {:?}, full mode: {}); read: {:?}",
                pair.1.outcomes.keys().collect::<BTreeSet<_>>(),
                pair.1.selected_membership,
                pair.1.full_membership,
                pair.1.rollback.as_ref().map(|rb| rb.slots.keys().collect::<BTreeSet<_>>()),
                pair.0.group.is_none(),
                read
            );
        }

        #[test]
        fn mutating_any_single_membership_set_causes_rejection(
            (intent, terminal) in agreeing_pair().prop_filter(
                "the property needs a Successful pair",
                |(_, t)| t.status == DeploymentStatus::Successful,
            ),
            set_idx in 0u32..4,
            op in key_op().prop_filter("the tamper must change the set", |op| {
                *op != KeyOp::Unchanged
            }),
            group in membership_mode(),
        ) {
            let mut ops = [KeyOp::Unchanged; 4];
            ops[set_idx as usize] = op;
            let (t_intent, t_terminal) = apply_four_set_tamper(&(intent, terminal), ops, group);
            let pair = (t_intent, t_terminal);
            // A VALID base pair satisfies every equation, so tampering EXACTLY
            // ONE of the four sets must break at least one equation — and the
            // read (the durable write → re-read crash-recovery path) must
            // reject.
            assert!(
                !membership_equations_hold(&pair),
                "mutating exactly one set must break an equation (set {set_idx}, op {op:?})"
            );
            assert!(
                write_pair_ledger(&pair).is_err(),
                "mutating exactly one of the four sets (set {set_idx}, op {op:?}) must be rejected by read_ledger — the durable write → re-read is the crash-recovery read"
            );
        }
    }

    #[test]
    fn successful_membership_equations_suffice_when_a_tamper_keeps_them_satisfied() {
        let keys = vec![slot(1), slot(2)];
        let intent = agreeing_intent(&keys);
        let terminal = agreeing_terminal(&keys, 0);
        // The untampered pair reads.
        write_pair_ledger(&(intent.clone(), terminal.clone()))
            .expect("the exact-equal Successful pair reads");
        // FULL mode: add the SAME key (slot-9) to ALL FOUR sets — the
        // equations stay satisfied (outcomes == selected == full ==
        // rollback slots), so the read still succeeds.
        let mut intent = intent;
        intent.slot_ids.push(slot(9));
        intent.desired.insert(slot(9), gen_ref_for(&slot(9)));
        intent.pre_push.insert(slot(9), None);
        let mut terminal = terminal;
        terminal
            .outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        terminal.selected_membership.push(slot(9));
        terminal.full_membership.push(slot(9));
        let rb = terminal.rollback.as_mut().unwrap();
        rb.slots.insert(slot(9), gen_ref_for(&slot(9)));
        rb.bindings.insert(slot(9), binding(&slot(9)));
        let entries = write_pair_ledger(&(intent, terminal)).expect(
            "adding the same key to all four sets keeps the equations satisfied — the read succeeds",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].intent.slots.len(),
            3,
            "the intent's membership grew with the added key"
        );

        // GROUP mode: a proper-subset selected (selected = {slot-1} ⊊ full =
        // {slot-1, slot-2}) is LEGAL and reads.
        let selected = vec![slot(1)];
        let full = vec![slot(1), slot(2)];
        let mut terminal = agreeing_terminal(&full, 0);
        terminal.outcomes =
            BTreeMap::from([(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated))]);
        terminal.selected_membership = selected.clone();
        let intent = agreeing_intent_with_group(&selected, Some("g1"));
        write_pair_ledger(&(intent.clone(), terminal.clone()))
            .expect("the group-proper-subset pair reads");
        // GROW THE FULL SIDE ONLY (full + rollback): selected ⊊ full stays —
        // the read succeeds.
        let mut terminal2 = terminal.clone();
        terminal2.full_membership.push(slot(3));
        let rb = terminal2.rollback.as_mut().unwrap();
        rb.slots.insert(slot(3), gen_ref_for(&slot(3)));
        rb.bindings.insert(slot(3), binding(&slot(3)));
        write_pair_ledger(&(intent.clone(), terminal2))
            .expect("growing only the full membership keeps selected ⊆ full — the read succeeds");
        // GROW THE SELECTED SIDE ONLY, WITHIN the full membership
        // (selected + outcomes grow to equal full): selected ⊆ full stays —
        // the read succeeds. The intent (whose slot_ids ARE the selected
        // set for a group push) grows with the selection.
        let mut terminal3 = terminal;
        terminal3.selected_membership.push(slot(2));
        terminal3
            .outcomes
            .insert(slot(2), outcome_for(&slot(2), SlotOutcomeKind::Activated));
        let intent3 = agreeing_intent_with_group(&[slot(1), slot(2)], Some("g1"));
        write_pair_ledger(&(intent3, terminal3)).expect(
            "growing the selected membership (and its outcomes) within the full membership keeps selected ⊆ full — the read succeeds",
        );
    }

    /// Write the pair as a two-line ledger AND a `deploy.toml` whose target
    /// `t1` owns exactly the given SIMULATED current configuration slots,
    /// then read the ledger back through the REAL consumer path. The
    /// membership equations NEVER consult this configuration — the helper
    /// exists to demonstrate (in
    /// [`acceptance_is_pure_function_of_persisted_sets_and_mode_ignores_config`])
    /// that acceptance is a PURE function of the persisted sets + mode:
    /// re-reading the SAME pair under a DIFFERENT simulated config
    /// membership yields the SAME verdict.
    fn write_pair_ledger_under_config(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
        simulated_slots: &[SlotId],
    ) -> Result<Vec<LedgerEntry>> {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // A real, LOADABLE project config whose target `t1` owns exactly
        // `simulated_slots` (one server, one release). `read_ledger` never
        // touches it — the config exists only to make the simulation
        // concrete: a hypothetical config-reading consumer would see THIS
        // current membership.
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        let mut release = String::from("[artifact]\nmappings = []\n\n");
        for s in simulated_slots {
            release.push_str(&format!(
                "[[slots]]\nid = \"{}\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = []\ndeploy_dir = \"/srv\"\n\n",
                s.as_str()
            ));
        }
        release.push_str(
            "[retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n[retention.deployment]\nprotect_deployments = 1\n\n[activation]\nadapter = \"none\"\n\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            release,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            "schema_version = 2\napplication = \"records-tests\"\nrelease = \"v1\"\n\n\
             [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
             [targets.t1]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n",
        )
        .unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(pair.0.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(pair.1.clone())).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        store.read_ledger("t1")
    }

    /// CONFIGURATION MEMBERSHIP INDEPENDENCE (the user's requirement):
    /// acceptance of a Successful pair is a PURE function of the persisted
    /// sets + mode — the read path ([`LocalStore::read_ledger`]) NEVER
    /// consults the live configuration for the membership equations. The
    /// SAME written pair is read back while simulating DIFFERENT current
    /// configuration memberships (a target config whose slots differ from
    /// the pair's persisted sets), and the verdict is unchanged: a valid
    /// pair stays accepted, a tampered pair stays rejected.
    #[test]
    fn acceptance_is_pure_function_of_persisted_sets_and_mode_ignores_config() {
        // A valid GROUP-mode pair: selected = {slot-1} ⊊ full = {slot-1,
        // slot-2} — the group-proper-subset shape a group push legitimately
        // records (outcomes == selected, rollback == full, selected ⊆ full).
        let selected = vec![slot(1)];
        let full = vec![slot(1), slot(2)];
        let mut terminal = agreeing_terminal(&full, 0);
        terminal.outcomes =
            BTreeMap::from([(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated))]);
        terminal.selected_membership = selected.clone();
        let intent = agreeing_intent_with_group(&selected, Some("g1"));
        let pair = (intent, terminal);
        assert!(membership_equations_hold(&pair), "the group pair is valid");
        // Accepted under a config whose membership equals the FULL set …
        write_pair_ledger_under_config(&pair, &full)
            .expect("the valid pair reads under a config matching the full membership");
        // … and accepted under a config whose membership is a DIFFERENT set
        // (a simulated membership change): the verdict is unchanged.
        write_pair_ledger_under_config(&pair, &[slot(9)])
            .expect("the valid pair's acceptance is a PURE function of the persisted sets + mode — a different current configuration membership does not change it");

        // A tampered variant: add a key to the SELECTED set only — outcomes
        // == selected breaks. Rejected under BOTH simulated configs.
        let mut bad = pair.clone();
        bad.1.selected_membership.push(slot(3));
        assert!(
            !membership_equations_hold(&bad),
            "the single-set mutation breaks the equations"
        );
        write_pair_ledger_under_config(&bad, &full).expect_err(
            "the tampered pair must stay rejected under a config matching the full membership",
        );
        write_pair_ledger_under_config(&bad, &[slot(9)]).expect_err(
            "the tampered pair must stay rejected under a DIFFERENT current configuration membership",
        );

        // A valid FULL-mode pair (selected == full) and its tamper: same
        // independence.
        let keys = vec![slot(1), slot(2)];
        let pair = (agreeing_intent(&keys), agreeing_terminal(&keys, 0));
        assert!(membership_equations_hold(&pair), "the full pair is valid");
        write_pair_ledger_under_config(&pair, &keys)
            .expect("the valid full pair reads under a config matching its membership");
        write_pair_ledger_under_config(&pair, &[slot(5)]).expect(
            "the valid full pair's acceptance is a PURE function of the persisted sets + mode — a different current configuration membership does not change it",
        );
        let mut bad = pair.clone();
        bad.1.full_membership.push(slot(3));
        bad.1
            .rollback
            .as_mut()
            .unwrap()
            .slots
            .insert(slot(3), gen_ref_for(&slot(3)));
        bad.1
            .rollback
            .as_mut()
            .unwrap()
            .bindings
            .insert(slot(3), binding(&slot(3)));
        assert!(
            !membership_equations_hold(&bad),
            "the full-side mutation breaks the equations"
        );
        write_pair_ledger_under_config(&bad, &keys)
            .expect_err("the tampered full pair must stay rejected");
        write_pair_ledger_under_config(&bad, &[slot(5)]).expect_err(
            "the tampered full pair must stay rejected under a DIFFERENT current configuration membership",
        );
    }

    /// THE ENTRY OWNS IDENTITY: the domain terminal carries no
    /// deployment_id/target; the reader verifies the wire terminal's
    /// identity against its ENTRY (the intent's) and the outcome keys
    /// against the membership — a mismatch is refused before any consumer.
    #[test]
    fn entry_owns_identity_and_refuses_cross_record_disagreements() {
        let keys = vec![slot(1), slot(2)];
        let intent = agreeing_intent(&keys);
        // A terminal claiming a DIFFERENT target than its entry.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.target = TargetName::new("other".to_string());
        let err = pair_to_domain(&(intent.clone(), terminal))
            .expect_err("a target disagreement is refused");
        assert!(err.to_string().contains("target"), "err: {err}");
        // A terminal claiming a deployment id with no intent line.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.deployment_id = test_deployment_id("deploy-ghost");
        assert!(pair_to_domain(&(intent.clone(), terminal)).is_err());
        // An outcome key outside the intent's membership.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal
            .outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        assert!(pair_to_domain(&(intent.clone(), terminal)).is_err());
        // An outcome value naming a different slot than its key.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.outcomes.get_mut(&slot(1)).unwrap().slot_id = slot(2);
        assert!(pair_to_domain(&(intent, terminal)).is_err());
    }
}

//! The per-slot OUTCOME records of the deployment ledger (feature areas A1
//! "outcome dispositions" / "per-slot outcome kinds" / "degraded
//! semantics"): the per-slot outcome kinds ([`SlotOutcomeKind`]) and the
//! domain outcome ([`SlotOutcome`]) with its [`SlotTransition`] state, the
//! WIRE outcome row ([`SlotResult`] — the raw serde form the ledger's
//! JSONL carries, owned HERE next to its domain sibling), the wire → domain
//! derivations ([`SlotOutcome::from_wire`], [`SlotResult::from_outcome`]),
//! the [`CompensationReport`] alias, and the
//! [`LedgerTerminal::remaining_changes`],
//! [`LedgerTerminal::compensation`]).

use crate::identity::{GenerationId, SlotId};
use crate::ledger::intent::DeploymentIntent;
use crate::ledger::observation::{Observation, ObservationError, ObservedGeneration};
use crate::ledger::tables::SlotTable;
use crate::ledger::terminal::{LedgerTerminal, TerminalDisposition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotOutcomeKind {
    Activated,
    Failed,
    /// Reserved: never emitted today. In-process compensation (a post-swap
    /// activation/verification failure restored by the per-server pipeline,
    /// step 11) is recorded as [`SlotOutcomeKind::Failed`] with
    /// `SlotResult.compensated = true` — "record both the failure and the
    /// compensation result" — and failure-policy compensation (step 13)
    /// upgrades the slot to [`SlotOutcomeKind::Restored`].
    Compensated,
    Skipped,
    Restored,
}

/// The per-slot TRANSITION STATE of one slot during a deployment attempt —
/// the per-slot fact the terminal's outcomes carry (the DOMAIN form; the
/// WIRE keeps the current on-disk shape and the wire → domain conversion
/// derives the transition from the wire's status/outcome fields). The
/// remaining-changes derivation is based on THIS state, never on the
/// outcome's generation field alone: a slot that was never advanced (or
/// whose advance outcome is unknown) records a generation that is not
/// evidence of a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotTransition {
    /// The slot was NEVER mutated: skipped (stop_on_failure) or a
    /// pre-mutation failure. Its final observed state equals its pre_push
    /// state, so it is never a remaining change.
    NeverAdvanced,
    /// The slot successfully advanced to the new state: its outcome's
    /// generation is the generation it is on (a remaining change whenever
    /// the new state differs from pre_push).
    Advanced,
    /// The slot advanced then was compensated back to its pre_push state
    /// (never a remaining change).
    Restored,
    /// The advance outcome is UNKNOWN: a pre-swap failure — the slot may or
    /// may not have changed. The outcome's generation is the OBSERVED
    /// post-state (the engine records the actual generation, never the
    /// desired one); the slot is a remaining change iff that observed state
    /// differs from pre_push.
    AdvanceUnknown,
}

/// The WIRE outcome of one slot during a deployment's mutation loop — the
/// RAW serde form the ledger's JSONL carries, with the REDUNDANT `slot_id`
/// next to its map key (the wire keeps the on-disk shape; the wire → domain
/// conversion verifies the outcome names its own key and then DROPS the
/// slot into the key — the domain value [`SlotOutcome`] carries no slot).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotResult {
    pub slot_id: SlotId,
    pub outcome: SlotOutcomeKind,
    /// The generation this slot advanced to, or `None` if it never started.
    pub generation: Option<GenerationId>,
    pub compensated: bool,
    /// The pure OPERATION error (e.g. a swap failure) — the slot's own
    /// failure, INDEPENDENT of the post-mutation observation. NEVER
    /// rewritten by the post-observation pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The preserved error of a FAILED post-mutation OBSERVATION, or `None`
    /// when the observation succeeded (a recorded generation) or showed no
    /// state (`KnownAbsent`). Independent of `error`: an operation failure
    /// and a failed observation are TWO facts and both survive the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_error: Option<String>,
}

/// The per-slot OUTCOME of one slot during a deployment's mutation loop —
/// the DOMAIN value of the wire's [`SlotResult`] with the REDUNDANT
/// `slot_id` DROPPED: the enclosing [`SlotTable`] key owns the slot
/// identity, so the value stores each fact exactly once (the wire keeps the
/// on-disk shape — the wire outcome carries the slot; the wire → domain
/// conversion verifies the outcome names its own key and then drops it into
/// the key). The value ALSO carries the per-slot TRANSITION STATE
/// ([`SlotTransition`]) the remaining-changes derivation is based on (the
/// wire keeps the current on-disk shape; the wire → domain conversion
/// derives the transition from the wire's status/outcome fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotOutcome {
    pub outcome: SlotOutcomeKind,
    /// The THREE-STATE OBSERVATION of the slot's post-mutation state — the
    /// observed generation the remaining-changes derivation compares against
    /// pre_push. `Unknown(error)` when the post-mutation status read failed
    /// (the slot may or may not have changed — never classified as
    /// unchanged); `KnownAbsent` when the read succeeded showing no state
    /// (never deployed).
    pub observation: Observation<ObservedGeneration>,
    pub compensated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The per-slot transition state (see [`SlotTransition`]).
    pub transition: SlotTransition,
}

impl SlotOutcome {
    /// Derive the per-slot TRANSITION STATE from the wire's status/outcome
    /// fields (the wire keeps the current on-disk shape; the transition is
    /// the per-slot fact the domain outcomes carry). `Restored` and a
    /// compensated `Failed` are a compensation that restored the slot;
    /// `Skipped` never advanced; `Activated` advanced; an UNCOMPENSATED
    /// `Failed` is a pre-swap failure OR a post-swap failure whose
    /// compensation failed — the wire cannot distinguish them, so the
    /// advance outcome is UNKNOWN (the slot may or may not have changed;
    /// the remaining-changes derivation compares the outcome's OBSERVED
    /// generation against pre_push).
    pub fn from_wire(r: SlotResult) -> SlotOutcome {
        let transition = match r.outcome {
            SlotOutcomeKind::Restored => SlotTransition::Restored,
            SlotOutcomeKind::Skipped => SlotTransition::NeverAdvanced,
            SlotOutcomeKind::Activated => SlotTransition::Advanced,
            SlotOutcomeKind::Failed => {
                if r.compensated {
                    SlotTransition::Restored
                } else {
                    SlotTransition::AdvanceUnknown
                }
            }
            // Reserved: never emitted today. The in-process compensation
            // marker (a post-swap failure restored by the per-server
            // pipeline) is recorded as `Failed` with `compensated = true`;
            // a `Compensated` outcome would be a restored slot.
            SlotOutcomeKind::Compensated => SlotTransition::Restored,
        };
        // The THREE-STATE OBSERVATION is derived from the wire's fields: a
        // recorded generation is a successful read (`Known`); a `None`
        // generation with a preserved OBSERVATION error is a FAILED
        // observation (`Unknown` — the wire's `observation_error` field
        // carries the observation error INDEPENDENTLY of the operation
        // error, so the uncertainty survives the wire round trip); a `None`
        // generation with no observation error is a slot with no observed
        // state (`KnownAbsent`). `error` is the pure OPERATION error — it
        // NEVER participates in the observation.
        let observation = match r.generation {
            Some(g) => Observation::Known(ObservedGeneration { generation: g }),
            None => match r.observation_error.as_deref() {
                Some(e) => Observation::Unknown(ObservationError {
                    message: e.to_string(),
                }),
                None => Observation::KnownAbsent,
            },
        };
        SlotOutcome {
            outcome: r.outcome,
            observation,
            compensated: r.compensated,
            error: r.error,
            transition,
        }
    }
}

impl From<SlotResult> for SlotOutcome {
    /// Drop the wire outcome's redundant `slot_id` (the table key owns the
    /// slot identity — the wire → domain conversion verifies the outcome
    /// named its own key before dropping it) and derive the per-slot
    /// TRANSITION STATE from the wire's status/outcome fields.
    fn from(r: SlotResult) -> SlotOutcome {
        SlotOutcome::from_wire(r)
    }
}

impl SlotResult {
    /// Re-attach the table key as the wire outcome's `slot_id` (the wire
    /// keeps the on-disk shape; the domain value carries no slot) and encode
    /// the domain's TWO INDEPENDENT error facts back into the wire's fields:
    /// `error` carries the pure OPERATION error (always, regardless of the
    /// observation — the two facts never share a slot); the THREE-STATE
    /// OBSERVATION is encoded in the wire's `generation` + `observation_error`
    /// fields — the `Known` half is the recorded generation, the `Unknown`
    /// half is its OWN preserved error in `observation_error` (a `None`
    /// generation with an observation error reads back as `Unknown` — the
    /// uncertainty survives the round trip), and a `KnownAbsent` observation
    /// carries no observation error (a `None` generation with an observation
    /// error would read back as `Unknown`, not `KnownAbsent`). Every
    /// (operation_error, observation) combination round-trips EXACTLY.
    pub fn from_outcome(key: &SlotId, o: &SlotOutcome) -> Self {
        SlotResult {
            slot_id: key.clone(),
            outcome: o.outcome.clone(),
            generation: match &o.observation {
                Observation::Known(og) => Some(og.generation.clone()),
                Observation::KnownAbsent | Observation::Unknown(_) => None,
            },
            compensated: o.compensated,
            error: o.error.clone(),
            observation_error: match &o.observation {
                Observation::Unknown(e) => Some(e.message.clone()),
                Observation::Known(_) | Observation::KnownAbsent => None,
            },
        }
    }
}

/// The COMPENSATION REPORT of a [`TerminalDisposition::FailedRolledBack`]
/// terminal — the disposition's OWN per-slot outcomes table under the
/// disposition's name: each slot's result during the failed-then-rolled-back
/// attempt (which slots were compensated back and which compensation
/// failed). The report IS the disposition's outcomes table
/// ([`LedgerTerminal::compensation`]) — never a stored duplicate that could
/// disagree with the outcomes.
pub type CompensationReport = SlotTable<SlotOutcome>;

impl LedgerTerminal {
    /// The REMAINING CHANGES of a [`TerminalDisposition::Degraded`] terminal
    /// — DERIVED from the disposition's OWN per-slot outcomes (the slots
    /// whose FINAL OBSERVED STATE differs from their pre_push state, each
    /// mapped to its THREE-STATE OBSERVATION), never stored. `None` for any
    /// non-Degraded disposition. For a Degraded terminal the set may be
    /// EMPTY (a `leave_changed` failure that advanced nothing — e.g. a
    /// pre-swap failure with every slot skipped — is Degraded with no
    /// remaining change); the conversion refuses only a Degraded wire whose
    /// outcomes are ALL restored (a fully-compensated attempt must be
    /// `FailedRolledBack`, never Degraded).
    ///
    /// THE DERIVATION IS THE TRANSITION STATE, NOT THE OUTCOME'S GENERATION
    /// FIELD: each slot's [`SlotTransition`] classifies it — a
    /// `NeverAdvanced` slot (skipped) and a `Restored` slot (compensated
    /// back) are back at their pre_push state (never remaining changes); an
    /// `Advanced` slot is at the desired state (always a remaining change);
    /// an `AdvanceUnknown` slot (a pre-swap failure — the advance outcome is
    /// unknown) is a remaining change iff its OBSERVED state (the outcome's
    /// observation, which the engine records as the actual post-state, never
    /// the desired one) differs from pre_push. The intent's `pre_push` per
    /// slot is the comparison baseline.
    ///
    /// THE THREE-STATE OBSERVATION IS THE COMPARISON, NEVER A `None`
    /// COLLAPSED INTO "UNCHANGED": an `Unknown` observation (the post-mutation
    /// status read failed) is UNCERTAIN — the slot may or may not have
    /// changed — so it is NEVER classified as unchanged: it IS a remaining
    /// change, mapped to its `Unknown(error)` observation. A `KnownAbsent`
    /// observation (the read succeeded showing no state) is a remaining
    /// change only when the slot HAD a pre_push generation that is now gone.
    pub fn remaining_changes(
        &self,
        intent: &DeploymentIntent,
    ) -> Option<SlotTable<Observation<ObservedGeneration>>> {
        if !matches!(self.disposition, TerminalDisposition::Degraded { .. }) {
            return None;
        }
        let remaining: BTreeMap<SlotId, Observation<ObservedGeneration>> = self
            .outcomes()
            .iter()
            .filter(|(sid, r)| match r.transition {
                SlotTransition::NeverAdvanced | SlotTransition::Restored => false,
                SlotTransition::Advanced => true,
                SlotTransition::AdvanceUnknown => {
                    // The advance outcome is unknown (a pre-swap failure):
                    // the slot is a remaining change iff its OBSERVED state
                    // differs from pre_push. An `Unknown` observation (the
                    // post-mutation status read failed) is NOT evidence of
                    // no change — the slot may have changed; it is UNCERTAIN
                    // and therefore a remaining change.
                    let pre = intent
                        .slots
                        .get(sid)
                        .and_then(|s| s.pre_push.as_ref())
                        .and_then(|p| p.generation.clone());
                    match &r.observation {
                        Observation::Known(og) => {
                            let obs = og.generation.clone();
                            match (Some(obs), pre) {
                                (Some(obs), Some(pre_gen)) => obs != pre_gen,
                                (Some(_), None) => true,
                                _ => false,
                            }
                        }
                        // The read succeeded showing no state: a change only
                        // when the slot HAD a pre_push generation that is now
                        // gone.
                        Observation::KnownAbsent => pre.is_some(),
                        // The read FAILED: uncertain — never unchanged.
                        Observation::Unknown(_) => true,
                    }
                }
            })
            .map(|(k, r)| (k.clone(), r.observation.clone()))
            .collect();
        Some(SlotTable::from_map(remaining))
    }

    /// The COMPENSATION REPORT of a [`TerminalDisposition::FailedRolledBack`]
    /// terminal — the disposition's OWN per-slot outcomes table itself (the
    /// record of what the compensation pass did to each slot: which slots
    /// were restored and which compensation failed), never a stored
    /// duplicate. `None` for any other disposition.
    pub fn compensation(&self) -> Option<&CompensationReport> {
        if matches!(
            self.disposition,
            TerminalDisposition::FailedRolledBack { .. }
        ) {
            Some(self.outcomes())
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{GenerationId, SlotId, test_generation_id};
    use crate::ledger::observation::{ObservationError, ObservedGeneration};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    // =====================================================================

    /// An arbitrary OPERATION error (the slot's pure failure — the wire's
    /// `error` field): any failure reason, or none.
    fn arbitrary_operation_error() -> impl Strategy<Value = Option<String>> {
        prop::option::of(prop::sample::select(vec![
            "swap failed: boom".to_string(),
            "verification failed".to_string(),
            "internal: no behavior contract for variant 'x'".to_string(),
        ]))
    }

    /// An arbitrary THREE-STATE OBSERVATION: `Known` with an arbitrary
    /// VALID generation id, `KnownAbsent`, or `Unknown` with an arbitrary
    /// preserved message (the wire's `observation_error` field) — generated
    /// INDEPENDENTLY of the operation error.
    fn arbitrary_observation() -> impl Strategy<Value = Observation<ObservedGeneration>> {
        prop_oneof![
            (0u32..6).prop_map(|i| Observation::Known(ObservedGeneration {
                generation: test_generation_id(&format!("obs-{i}")),
            })),
            Just(Observation::KnownAbsent),
            prop::sample::select(vec![
                "status read failed: boom".to_string(),
                "assignment read failed: boom".to_string(),
            ])
            .prop_map(|e| Observation::Unknown(ObservationError { message: e })),
        ]
    }

    /// MIRROR of the engine's post-observation pass (`src/push/engine.rs`'s
    /// `never_advanced` loop): apply a generated post-mutation observation
    /// to a wire [`SlotResult`], mutating ONLY the observation fields
    /// (`generation` / `observation_error`) — the operation error (`error`)
    /// is NEVER touched. The engine loop is not cleanly reachable from a
    /// records-level unit test, so this helper mirrors its fixed logic.
    fn apply_post_observation(r: &mut SlotResult, observation: &Observation<ObservedGeneration>) {
        match observation {
            Observation::Known(og) => r.generation = Some(og.generation.clone()),
            Observation::Unknown(e) => {
                r.generation = None;
                r.observation_error = Some(e.message.clone());
            }
            Observation::KnownAbsent => {
                r.generation = None;
                r.observation_error = None;
            }
        }
    }

    /// (a) An outcome carrying BOTH an operation error AND an `Unknown`
    /// observation round-trips preserving both — the two facts are
    /// INDEPENDENT on the wire (the old single-error wire could not carry a
    /// distinct operation error alongside a failed observation).
    #[test]
    fn operation_error_and_unknown_observation_round_trip_preserves_both() {
        let outcome = SlotOutcome {
            outcome: SlotOutcomeKind::Failed,
            observation: Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            transition: SlotTransition::AdvanceUnknown,
        };
        let wire = SlotResult::from_outcome(&slot(1), &outcome);
        assert_eq!(wire.generation, None);
        assert_eq!(
            wire.error,
            Some("swap failed: boom".to_string()),
            "the operation error is written to the wire's error field"
        );
        assert_eq!(
            wire.observation_error,
            Some("status read failed: boom".to_string()),
            "the observation error is written to the wire's observation_error field"
        );
        // A full serde_json round trip of the wire keeps both fields.
        let json = serde_json::to_string(&wire).unwrap();
        let wire_json: SlotResult = serde_json::from_str(&json).unwrap();
        assert_eq!(wire_json.error, Some("swap failed: boom".to_string()));
        assert_eq!(
            wire_json.observation_error,
            Some("status read failed: boom".to_string())
        );
        let back = SlotOutcome::from_wire(wire);
        assert_eq!(
            back.error,
            Some("swap failed: boom".to_string()),
            "the operation error survives the wire untouched"
        );
        assert_eq!(
            back.observation,
            Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
            "the Unknown observation survives the wire untouched"
        );
    }

    /// (b) The engine's post-observation semantics preserve the operation
    /// error: a `KnownAbsent` observation must NOT wipe it and an `Unknown`
    /// observation must NOT overwrite it (the old loop did both).
    #[test]
    fn post_observation_preserves_the_operation_error() {
        // A pre-swap FAILED outcome ALREADY carries its operation error; the
        // post-observation pass mutates only the observation fields.
        let mut known_absent = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            generation: Some(GenerationId::new("desired-1".to_string())),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            observation_error: None,
        };
        apply_post_observation(&mut known_absent, &Observation::KnownAbsent);
        assert_eq!(
            known_absent.error,
            Some("swap failed: boom".to_string()),
            "KnownAbsent must NOT wipe the operation error"
        );
        assert_eq!(
            known_absent.generation, None,
            "KnownAbsent clears the generation"
        );
        assert_eq!(known_absent.observation_error, None);

        let mut unknown = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            generation: Some(GenerationId::new("desired-1".to_string())),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            observation_error: None,
        };
        apply_post_observation(
            &mut unknown,
            &Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
        );
        assert_eq!(
            unknown.error,
            Some("swap failed: boom".to_string()),
            "Unknown must NOT overwrite the operation error"
        );
        assert_eq!(unknown.generation, None);
        assert_eq!(
            unknown.observation_error,
            Some("status read failed: boom".to_string()),
            "the observation error lands in observation_error, never in error"
        );

        let mut known = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            generation: Some(GenerationId::new("desired-1".to_string())),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            observation_error: None,
        };
        apply_post_observation(
            &mut known,
            &Observation::Known(ObservedGeneration {
                generation: GenerationId::new("observed-1".to_string()),
            }),
        );
        assert_eq!(
            known.error,
            Some("swap failed: boom".to_string()),
            "Known must not touch the operation error"
        );
        assert_eq!(
            known.generation,
            Some(GenerationId::new("observed-1".to_string()))
        );
        assert_eq!(known.observation_error, None);
    }

    proptest! {
        // THE USER'S PROPERTY: the operation error and the post-mutation
        // observation are TWO INDEPENDENT facts. (1) Every (operation_error,
        // observation) pair round-trips domain → wire → domain EXACTLY,
        // including a full serde_json round trip of the wire. (2) Failure
        // injection (the engine's post-observation pass, mirrored by
        // [`apply_post_observation`]) never rewrites the operation error and
        // reflects the observation in the observation fields. The cross
        // product covers the directions where the OLD code was wrong: an
        // `Unknown` observation + a distinct operation error both survive,
        // and a `KnownAbsent` observation + an operation error survives.
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
        // persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn outcome_wire_round_trip_preserves_operation_error_and_observation_independently(
            operation_error in arbitrary_operation_error(),
            observation in arbitrary_observation(),
        ) {
            // A domain outcome carrying EXACTLY the two generated facts.
            let outcome = SlotOutcome {
                outcome: SlotOutcomeKind::Failed,
                observation: observation.clone(),
                compensated: false,
                error: operation_error.clone(),
                transition: SlotTransition::AdvanceUnknown,
            };
            // Domain → wire: each fact lands in its OWN wire field.
            let wire = SlotResult::from_outcome(&slot(0), &outcome);
            assert_eq!(
                wire.error,
                operation_error,
                "the operation error is written to the wire's error field"
            );
            // Wire → domain: both facts survive INDEPENDENTLY.
            let back = SlotOutcome::from_wire(wire.clone());
            assert_eq!(
                back.error,
                operation_error.clone(),
                "the operation error survives the wire untouched"
            );
            assert_eq!(
                back.observation,
                observation,
                "the observation survives the wire untouched"
            );
            // A full serde_json round trip of the wire preserves both fields.
            let json = serde_json::to_string(&wire).unwrap();
            let wire2: SlotResult = serde_json::from_str(&json).unwrap();
            assert_eq!(wire2.error, operation_error.clone());
            assert_eq!(wire2.observation_error, wire.observation_error);
            let back2 = SlotOutcome::from_wire(wire2);
            assert_eq!(back2.error, operation_error);
            assert_eq!(back2.observation, observation);
        }

        #[test]
        fn post_observation_preserves_both_facts(
            operation_error in arbitrary_operation_error(),
            observation in arbitrary_observation(),
        ) {
            // A pre-swap FAILED wire outcome ALREADY carries the original
            // operation error (e.g. "swap failed: ..."); its desired
            // generation is about to be replaced by the observed post-state.
            let mut wire = SlotResult {
                slot_id: slot(0),
                outcome: SlotOutcomeKind::Failed,
                generation: Some(GenerationId::new("desired-0".to_string())),
                compensated: false,
                error: operation_error.clone(),
                observation_error: None,
            };
            // Failure injection: the engine's post-observation pass.
            apply_post_observation(&mut wire, &observation);
            // The operation error is NEVER rewritten by the observation.
            assert_eq!(
                wire.error,
                operation_error.clone(),
                "the operation error must never be rewritten by the post-mutation observation"
            );
            // The observation facts reflect the observation.
            match &observation {
                Observation::Known(og) => {
                    assert_eq!(wire.generation, Some(og.generation.clone()));
                    assert_eq!(wire.observation_error, None);
                }
                Observation::KnownAbsent => {
                    assert_eq!(wire.generation, None);
                    assert_eq!(wire.observation_error, None);
                }
                Observation::Unknown(e) => {
                    assert_eq!(wire.generation, None);
                    assert_eq!(
                        wire.observation_error,
                        Some(e.message.clone()),
                        "the observation error lands in observation_error, never in error"
                    );
                }
            }
            // The injected wire still converts back to the SAME two facts.
            let back = SlotOutcome::from_wire(wire);
            assert_eq!(
                back.error,
                operation_error,
                "the operation error survives the injection untouched"
            );
            assert_eq!(
                back.observation,
                observation,
                "the observation survives the injection untouched"
            );
        }
    }
}

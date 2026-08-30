//! The per-slot OUTCOME records of the deployment ledger (feature areas A1
//! "outcome dispositions" / "per-slot outcome kinds" / "degraded
//! semantics"): the STRUCTURAL domain outcome ([`SlotOutcome`] — one
//! variant per execution state, with the post-mutation OBSERVATION as the
//! per-slot EVIDENCE the terminal decision needs), the STRUCTURAL WIRE
//! outcome row ([`SlotResult`] — the raw serde form the ledger's JSONL
//! carries, owned HERE next to its domain sibling), the wire → domain
//! BIJECTION ([`SlotOutcome::from_wire`],
//! [`SlotOutcomeRowWire::from_outcome`]), the [`CompensationReport`] alias,
//! and the [`LedgerTerminal::remaining_changes`],
//! [`LedgerTerminal::compensation`] derivations implemented on the terminal
//! here, next to the outcomes they derive from.
//!
//! # The ONE execution-state taxonomy (schema v11)
//!
//! Every per-slot classification in the codebase is ONE of exactly six
//! mutually exclusive execution states ([`SlotOutcome`], and the engine's
//! mirror [`crate::deploy::rollout::SlotExecution`]): a slot advanced
//! ([`Activated`](SlotOutcome::Activated) — the outcome of a successful
//! swap + activation + verification), was compensated back to its pre-push
//! state ([`Restored`](SlotOutcome::Restored)), was never started
//! ([`Skipped`](SlotOutcome::Skipped)), failed BEFORE the swap
//! ([`FailedBeforeAdvance`](SlotOutcome::FailedBeforeAdvance)), failed
//! AFTER the swap without a successful compensation
//! ([`FailedAfterAdvance`](SlotOutcome::FailedAfterAdvance) — the slot is
//! still on the generation the attempt advanced it to), or failed with an
//! outcome the backend cannot confirm
//! ([`Indeterminate`](SlotOutcome::Indeterminate)). Compensation is a
//! TRANSITION between states (a failed-advance slot the failure-policy pass
//! restores becomes `Restored`), NEVER a boolean next to a separate outcome
//! kind — the old wire could represent `Activated + compensated` and
//! silently discard an irrelevant `error` field (the persisted form was not
//! bijective); the v11 wire's body variants carry EXACTLY their own fields,
//! so those contradictory combinations are UNREPRESENTABLE (deserialization
//! rejects them).
//!
//! # The post-mutation OBSERVATION is the decision's evidence
//!
//! Every variant carries the slot's post-mutation OBSERVATION
//! ([`Observation<ObservedGeneration>`] — `Known` / `KnownAbsent` /
//! `Unknown(error)`) — the observed post-state the semantic kernel's ONE
//! slot classifier ([`crate::kernel::terminal::classify_slot_delta`])
//! compares against the intent's pre-push and DESIRED generations. The
//! `error` field of the three failed variants is the pure OPERATION error
//! (e.g. a swap failure), INDEPENDENT of the observation (an operation
//! failure and a failed observation are two facts, and both survive the
//! wire); the non-failed variants carry no error.

use crate::error::Result;
use crate::identity::SlotId;
use serde::{Deserialize, Serialize};

use super::super::SlotTable;
use super::super::observation::{
    Observation, ObservationWire, ObservedGeneration, ObservedGenerationWire,
};

/// The WIRE outcome body of one slot during a deployment's mutation loop —
/// the RAW serde form the ledger's JSONL carries: the STRUCTURAL execution
/// state, EXACTLY ONE variant per outcome class, tagged by `state` with
/// each variant carrying EXACTLY its own fields (`deny_unknown_fields` — a
/// member that is not one of the variant's OWN fields is refused at
/// deserialization). The OLD flat shape (`outcome` + `compensated` +
/// `error` as three independent members) is GONE: the wire can no longer
/// represent `Activated` + `compensated` (there is no `compensated` —
/// compensation is a STATE: `Restored`), no `error` on a non-failed state,
/// and no half-known state. The two failure facts — the slot's own
/// operation error (`error`) and the post-mutation observation's failed
/// read (`observation`'s `Unknown` half) — are INDEPENDENT and both
/// survive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SlotOutcomeBodyWire {
    /// The slot advanced to the new generation (swap + activation +
    /// verification succeeded): the observation is the recorded post-state
    /// (the deployment's own generation, at batch time).
    Activated {
        observation: ObservationWire<ObservedGenerationWire>,
    },
    /// The slot advanced then was compensated back to its pre-push state
    /// (by the per-server pipeline or the failure-policy pass): the
    /// observation is the generation restored to.
    Restored {
        observation: ObservationWire<ObservedGenerationWire>,
    },
    /// The slot was never mutated (skipped under `stop_on_failure`, or a
    /// compare-and-swap precondition skip): the observation is the slot's
    /// live post-state (never the desired generation).
    Skipped {
        observation: ObservationWire<ObservedGenerationWire>,
    },
    /// The slot failed BEFORE the swap (a pre-mutation failure — the
    /// attempt never advanced it): the observation is the ACTUAL observed
    /// post-state (the never-advanced observation rule — the outcome never
    /// records the desired generation; a failed read is `Unknown`, never
    /// read as "unchanged").
    FailedBeforeAdvance {
        observation: ObservationWire<ObservedGenerationWire>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// The slot advanced (its `current` moved to the attempt's generation)
    /// and was NOT compensated back: the slot is STILL ON the advanced
    /// generation (a remaining change — the failure-policy pass may yet
    /// flip it to `Restored`, or keep it here under `leave_changed`).
    /// The observation is the generation the attempt advanced it to — the
    /// evidence a later rollback/remaining-change decision compares against
    /// pre_push, never re-observed from a partially-restored backend.
    FailedAfterAdvance {
        observation: ObservationWire<ObservedGenerationWire>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// The slot's post-swap outcome is UNKNOWN — the backend cannot confirm
    /// whether the attempt's mutation stuck: always a remaining change (an
    /// unknown state is never evidence of "unchanged").
    Indeterminate {
        observation: ObservationWire<ObservedGenerationWire>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

/// The WIRE outcome of one slot during a deployment's mutation loop — the
/// RAW serde form the ledger's JSONL carries: the slot ROW OWNS ITS SLOT ID
/// (the row lives in the terminal's `outcomes` ARRAY — there is no object
/// key for the identity to disagree with) and its STRUCTURAL execution
/// state ([`SlotOutcomeBodyWire`] — the state tag owns the classification,
/// `deny_unknown_fields` refuses any member that is not the variant's own
/// field). The post-mutation OBSERVATION rides inside the body variant in
/// its STRICT adjacently-tagged wire form
/// ([`ObservationWire<ObservedGenerationWire>`], `deny_unknown_fields`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotOutcomeRowWire {
    pub slot_id: SlotId,
    pub result: SlotOutcomeBodyWire,
}

/// The PRE-ROW-ARRAY name of the wire outcome row — kept as a re-export
/// type alias so the in-memory engine result maps (the display/execution
/// result maps keyed by slot in `deploy/rollout` / `deploy/push/execute` /
/// the retention history floor) keep compiling: they share the wire's
/// shape but are NOT wire rows; the JSONL wire row is [`SlotOutcomeRowWire`].
pub type SlotResult = SlotOutcomeRowWire;

/// The per-slot OUTCOME of one slot during a deployment's mutation loop —
/// the STRUCTURAL DOMAIN value of the wire's [`SlotOutcomeRowWire`] with
/// the REDUNDANT `slot_id` DROPPED: the enclosing [`SlotTable`] key owns
/// the slot identity, so the value stores each fact exactly once. The
/// classification is the VARIANT ITSELF — one variant per execution state —
/// so a nonsense combination (a compensated `Activated`, an `error` on a
/// restored slot) is UNREPRESENTABLE instead of being accepted as
/// independent fields. The wire keeps the v11 on-disk shape (the wire
/// outcome carries the slot + the structural body); the wire → domain
/// conversion ([`SlotOutcome::from_wire`]) is the BIJECTION from the wire's
/// body variant to the SAME domain variant. The domain carries NO serde
/// (strict wire types only deserialize; the ledger's JSONL carries
/// [`SlotOutcomeRowWire`] and the `ObservationWire` forms). Every terminal
/// decision — rolled-back vs degraded, and the remaining-changes set —
/// classifies each slot by this outcome's OBSERVATION against the intent's
/// pre-push and DESIRED generations ([`crate::kernel::terminal::classify_slot_delta`]);
/// the old independently-stored transition state (a second authority that
/// could disagree with the outcome) is DELETED — the classification is
/// derived, never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotOutcome {
    /// The slot advanced to the new generation (the swap + activation +
    /// verification succeeded): the recorded observation is the deployment's
    /// own generation — always a remaining change (the classifier sees the
    /// observed state == the desired generation).
    Activated {
        observation: Observation<ObservedGeneration>,
    },
    /// The slot advanced then was compensated back to its pre-push state
    /// (by the per-server pipeline or the failure-policy pass): never a
    /// remaining change (the observed state == pre_push).
    Restored {
        observation: Observation<ObservedGeneration>,
    },
    /// The slot was never mutated (skipped under `stop_on_failure`, or a
    /// compare-and-swap precondition skip): never a remaining change when
    /// it is still at its pre-push state.
    Skipped {
        observation: Observation<ObservedGeneration>,
    },
    /// The slot failed BEFORE the swap (a pre-mutation failure — the
    /// attempt never advanced it): the observation is the ACTUAL observed
    /// post-state (never the desired generation), so an uncompensated
    /// pre-swap failure at its pre-push state is not a remaining change.
    FailedBeforeAdvance {
        observation: Observation<ObservedGeneration>,
        error: Option<String>,
    },
    /// The slot failed AFTER the swap WITHOUT a successful compensation —
    /// its `current` was advanced and not restored: the slot is STILL ON
    /// the advanced (desired) generation, ALWAYS a remaining change (the
    /// classifier sees the observed state == the desired generation — the
    /// review's P1 case: an uncompensated post-advance failure is NEVER
    /// classified rolled-back).
    FailedAfterAdvance {
        observation: Observation<ObservedGeneration>,
        error: Option<String>,
    },
    /// The slot's post-swap outcome is UNKNOWN — the backend cannot confirm
    /// whether the mutation stuck: ALWAYS a remaining change (an unknown
    /// state is never evidence of "unchanged").
    Indeterminate {
        observation: Observation<ObservedGeneration>,
        error: Option<String>,
    },
}

impl SlotOutcome {
    /// WIRE → DOMAIN (the boundary's fail-closed conversion): map the
    /// wire's structural body variant to the SAME domain variant
    /// (variant-preserving — each body variant maps to exactly its domain
    /// sibling; the strict wire observation converts to the permissive
    /// domain observation). The conversion is a BIJECTION: the domain and
    /// the wire share the variant set, so the evidence fields
    /// (observation + error) round-trip EXACTLY — nothing is ever silently
    /// dropped (the old flat wire accepted `Activated + compensated=true`
    /// and discarded the irrelevant field).
    pub fn from_wire(r: SlotOutcomeRowWire) -> Result<SlotOutcome> {
        let observation: Observation<ObservedGeneration> =
            r.result.observation().clone().try_into()?;
        Ok(match r.result {
            SlotOutcomeBodyWire::Activated { .. } => SlotOutcome::Activated { observation },
            SlotOutcomeBodyWire::Restored { .. } => SlotOutcome::Restored { observation },
            SlotOutcomeBodyWire::Skipped { .. } => SlotOutcome::Skipped { observation },
            SlotOutcomeBodyWire::FailedBeforeAdvance { error, .. } => {
                SlotOutcome::FailedBeforeAdvance { observation, error }
            }
            SlotOutcomeBodyWire::FailedAfterAdvance { error, .. } => {
                SlotOutcome::FailedAfterAdvance { observation, error }
            }
            SlotOutcomeBodyWire::Indeterminate { error, .. } => {
                SlotOutcome::Indeterminate { observation, error }
            }
        })
    }

    /// The outcome's three-state post-mutation OBSERVATION (the observed
    /// post-state every terminal decision compares against pre_push) —
    /// shared by every variant: the per-slot EVIDENCE, never duplicated.
    pub fn observation(&self) -> &Observation<ObservedGeneration> {
        match self {
            Self::Activated { observation }
            | Self::Restored { observation }
            | Self::Skipped { observation }
            | Self::FailedBeforeAdvance { observation, .. }
            | Self::FailedAfterAdvance { observation, .. }
            | Self::Indeterminate { observation, .. } => observation,
        }
    }

    /// The FAILED-variant operation error (the slot's own failure — `None`
    /// on the advanced/restored/skipped states, which carry no error).
    pub fn error(&self) -> Option<&str> {
        match self {
            Self::FailedBeforeAdvance { error, .. }
            | Self::FailedAfterAdvance { error, .. }
            | Self::Indeterminate { error, .. } => error.as_deref(),
            _ => None,
        }
    }
}

impl SlotOutcomeBodyWire {
    /// The body variant's post-mutation observation (the raw wire form —
    /// the shared evidence field of EVERY variant).
    pub fn observation(&self) -> &ObservationWire<ObservedGenerationWire> {
        match self {
            Self::Activated { observation }
            | Self::Restored { observation }
            | Self::Skipped { observation }
            | Self::FailedBeforeAdvance { observation, .. }
            | Self::FailedAfterAdvance { observation, .. }
            | Self::Indeterminate { observation, .. } => observation,
        }
    }
}

impl SlotOutcomeRowWire {
    /// Re-attach the table key as the wire outcome's `slot_id` (the wire
    /// keeps the on-disk shape; the domain value carries no slot) and encode
    /// the structural variant back into the wire's body ([`SlotOutcomeBodyWire`]).
    /// The observation is encoded as its EXACT strict wire form
    /// ([`ObservationWire<ObservedGenerationWire>`]) — the `Known` half is
    /// the recorded generation, the `Unknown` half is its OWN preserved
    /// error, and a `KnownAbsent` observation carries no value fields. The
    /// conversion is a BIJECTION: every domain variant maps to EXACTLY one
    /// wire body shape, and [`SlotOutcome::from_wire`] reads that shape back
    /// to the SAME variant with the SAME evidence.
    pub fn from_outcome(key: &SlotId, o: &SlotOutcome) -> Self {
        let result = match o {
            SlotOutcome::Activated { observation } => SlotOutcomeBodyWire::Activated {
                observation: ObservationWire::from(observation),
            },
            SlotOutcome::Restored { observation } => SlotOutcomeBodyWire::Restored {
                observation: ObservationWire::from(observation),
            },
            SlotOutcome::Skipped { observation } => SlotOutcomeBodyWire::Skipped {
                observation: ObservationWire::from(observation),
            },
            SlotOutcome::FailedBeforeAdvance { observation, error } => {
                SlotOutcomeBodyWire::FailedBeforeAdvance {
                    observation: ObservationWire::from(observation),
                    error: error.clone(),
                }
            }
            SlotOutcome::FailedAfterAdvance { observation, error } => {
                SlotOutcomeBodyWire::FailedAfterAdvance {
                    observation: ObservationWire::from(observation),
                    error: error.clone(),
                }
            }
            SlotOutcome::Indeterminate { observation, error } => {
                SlotOutcomeBodyWire::Indeterminate {
                    observation: ObservationWire::from(observation),
                    error: error.clone(),
                }
            }
        };
        SlotResult {
            slot_id: key.clone(),
            result,
        }
    }
}

/// The COMPENSATION REPORT of a [`crate::ledger::TerminalDisposition::FailedRolledBack`]
/// terminal — the disposition's OWN per-slot outcomes table under the
/// disposition's name: each slot's result during the failed-then-rolled-back
/// attempt (which slots were compensated back and which compensation
/// failed). The report IS the disposition's outcomes table
/// ([`crate::ledger::LedgerTerminal::compensation`]) — never a stored duplicate that could
/// disagree with the outcomes.
pub type CompensationReport = SlotTable<SlotOutcome>;

#[cfg(test)]
mod tests_outcomes {
    use super::*;
    use crate::identity::{GenerationId, SlotId, test_generation_id};
    use crate::ledger::records::{ObservationError, ObservedGeneration};
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    /// An arbitrary OPERATION error (the slot's pure failure — the failed
    /// variants' `error` field): any failure reason, or none.
    fn arbitrary_operation_error() -> impl Strategy<Value = Option<String>> {
        prop::option::of(prop::sample::select(vec![
            "swap failed: boom".to_string(),
            "verification failed".to_string(),
            "internal: no behavior contract for variant 'x'".to_string(),
        ]))
    }

    /// An arbitrary THREE-STATE OBSERVATION: `Known` with an arbitrary
    /// VALID generation id, `KnownAbsent`, or `Unknown` with an arbitrary
    /// preserved message — generated INDEPENDENTLY of the operation error.
    fn arbitrary_observation() -> impl Strategy<Value = Observation<ObservedGeneration>> {
        prop_oneof![
            (0u32..6).prop_map(|i| Observation::Known(ObservedGeneration {
                generation: test_generation_id(&format!("obs-{i}"))
            })),
            Just(Observation::KnownAbsent),
            prop::sample::select(vec![
                "status read failed: boom".to_string(),
                "assignment read failed: boom".to_string(),
            ])
            .prop_map(|e| Observation::Unknown(ObservationError { message: e })),
        ]
    }

    /// EVERY constructible wire outcome body: each of the SIX execution
    /// states, with every three-state observation and with/without an
    /// operation error.
    fn arbitrary_wire_outcome() -> impl Strategy<Value = SlotResult> {
        (
            arbitrary_observation(),
            arbitrary_operation_error(),
            0u32..6,
        )
            .prop_map(|(observation, error, idx)| {
                let observation = ObservationWire::from(&observation);
                let result = match idx {
                    0 => SlotOutcomeBodyWire::Activated { observation },
                    1 => SlotOutcomeBodyWire::Restored { observation },
                    2 => SlotOutcomeBodyWire::Skipped { observation },
                    3 => SlotOutcomeBodyWire::FailedBeforeAdvance { observation, error },
                    4 => SlotOutcomeBodyWire::FailedAfterAdvance { observation, error },
                    _ => SlotOutcomeBodyWire::Indeterminate { observation, error },
                };
                SlotResult {
                    slot_id: slot(0),
                    result,
                }
            })
    }

    /// (a) An outcome carrying BOTH an operation error AND an `Unknown`
    /// observation round-trips preserving both — the two facts are
    /// INDEPENDENT on the wire.
    #[test]
    fn operation_error_and_unknown_observation_round_trip_preserves_both() {
        let outcome = SlotOutcome::FailedBeforeAdvance {
            observation: Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
            error: Some("swap failed: boom".to_string()),
        };
        let wire = SlotResult::from_outcome(&slot(1), &outcome);
        assert_eq!(
            wire.result.observation(),
            &ObservationWire::Unknown(ObservationError {
                message: "status read failed: boom".to_string()
            }),
            "the Unknown observation is written to the wire body's observation"
        );
        assert_eq!(
            wire.result,
            SlotOutcomeBodyWire::FailedBeforeAdvance {
                observation: ObservationWire::Unknown(ObservationError {
                    message: "status read failed: boom".to_string()
                }),
                error: Some("swap failed: boom".to_string()),
            },
            "the body is the EXACT structural variant with its own fields"
        );
        // A full serde_json round trip of the wire keeps both facts.
        let json = serde_json::to_string(&wire).unwrap();
        let wire_json: SlotResult = serde_json::from_str(&json).unwrap();
        assert_eq!(wire_json, wire);
        let back = SlotOutcome::from_wire(wire).unwrap();
        assert_eq!(
            back.error(),
            Some("swap failed: boom"),
            "the operation error survives the wire untouched"
        );
        assert_eq!(
            back.observation(),
            &Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string()
            }),
            "the Unknown observation survives the wire untouched"
        );
    }

    /// (b) The engine's post-observation semantics preserve the operation
    /// error: a `KnownAbsent` observation must NOT wipe it and an `Unknown`
    /// observation must NOT overwrite it.
    #[test]
    fn post_observation_preserves_the_operation_error() {
        // A pre-swap FAILED outcome ALREADY carries its operation error; the
        // post-observation pass mutates only the observation.
        let mut known_absent = SlotResult {
            slot_id: slot(1),
            result: SlotOutcomeBodyWire::FailedBeforeAdvance {
                observation: ObservationWire::Known(ObservedGenerationWire {
                    generation: GenerationId::new("desired-1".to_string()),
                }),
                error: Some("swap failed: boom".to_string()),
            },
        };
        apply_post_observation(&mut known_absent, &Observation::KnownAbsent);
        assert_eq!(
            known_absent.result.observation(),
            &ObservationWire::KnownAbsent,
            "KnownAbsent is a unit on the wire"
        );
        assert_eq!(
            known_absent.result,
            SlotOutcomeBodyWire::FailedBeforeAdvance {
                observation: ObservationWire::KnownAbsent,
                error: Some("swap failed: boom".to_string()),
            },
            "KnownAbsent must NOT wipe the operation error"
        );

        let mut unknown = SlotResult {
            slot_id: slot(1),
            result: SlotOutcomeBodyWire::FailedBeforeAdvance {
                observation: ObservationWire::Known(ObservedGenerationWire {
                    generation: GenerationId::new("desired-1".to_string()),
                }),
                error: Some("swap failed: boom".to_string()),
            },
        };
        apply_post_observation(
            &mut unknown,
            &Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
        );
        assert_eq!(
            unknown.result,
            SlotOutcomeBodyWire::FailedBeforeAdvance {
                observation: ObservationWire::Unknown(ObservationError {
                    message: "status read failed: boom".to_string()
                }),
                error: Some("swap failed: boom".to_string()),
            },
            "Unknown must NOT overwrite the operation error"
        );

        let mut known = SlotResult {
            slot_id: slot(1),
            result: SlotOutcomeBodyWire::FailedBeforeAdvance {
                observation: ObservationWire::Known(ObservedGenerationWire {
                    generation: GenerationId::new("desired-1".to_string()),
                }),
                error: Some("swap failed: boom".to_string()),
            },
        };
        apply_post_observation(
            &mut known,
            &Observation::Known(ObservedGeneration {
                generation: GenerationId::new("observed-1".to_string()),
            }),
        );
        assert_eq!(
            known.result,
            SlotOutcomeBodyWire::FailedBeforeAdvance {
                observation: ObservationWire::Known(ObservedGenerationWire {
                    generation: GenerationId::new("observed-1".to_string())
                }),
                error: Some("swap failed: boom".to_string()),
            },
            "Known must not touch the operation error"
        );
    }

    /// (b2) THE STRUCTURAL VARIANT ROUND TRIP: every domain variant encodes
    /// to EXACTLY its own wire body variant and reads back to the SAME
    /// variant — the six-state taxonomy is bijective (the old flat wire's
    /// `Activated + compensated` and similar contradictions are
    /// UNREPRESENTABLE).
    #[test]
    fn structural_variants_round_trip_exactly() {
        let cases: Vec<SlotOutcome> = vec![
            SlotOutcome::Activated {
                observation: Observation::KnownAbsent,
            },
            SlotOutcome::Restored {
                observation: Observation::KnownAbsent,
            },
            SlotOutcome::Skipped {
                observation: Observation::KnownAbsent,
            },
            SlotOutcome::FailedBeforeAdvance {
                observation: Observation::KnownAbsent,
                error: Some("pre-swap boom".to_string()),
            },
            SlotOutcome::FailedAfterAdvance {
                observation: Observation::KnownAbsent,
                error: Some("post-swap boom".to_string()),
            },
            SlotOutcome::Indeterminate {
                observation: Observation::KnownAbsent,
                error: Some("unknown boom".to_string()),
            },
        ];
        for outcome in &cases {
            // Variant-preserving wire round trip: from_outcome → from_wire
            // reproduces the EXACT domain variant.
            let wire = SlotResult::from_outcome(&slot(0), outcome);
            let back = SlotOutcome::from_wire(wire.clone()).unwrap();
            assert_eq!(
                &back, outcome,
                "the wire round trip must preserve the EXACT variant: {outcome:?}"
            );
            // A full serde_json round trip preserves the wire row exactly.
            let json = serde_json::to_string(&wire).unwrap();
            let wire2: SlotResult = serde_json::from_str(&json).unwrap();
            assert_eq!(wire2, wire);
            // The encoded wire is canonical for the variant.
            assert_eq!(back.error(), outcome.error());
        }
    }

    /// (c) THE STRUCTURAL-WIRE REJECTIONS (the review's P2 acceptance): the
    /// OLD contradictory flat combos are UNREPRESENTABLE — a `compensated`
    /// member, an `error` on a non-failed variant, and an unknown member at
    /// EVERY nesting level are REFUSED by deserialization.
    #[test]
    fn contradictory_flat_combinations_are_unrepresentable() {
        // The OLD wire document (v10): an Activated outcome with
        // compensated = true and an error — the review's canonical
        // contradiction. The v11 structural wire rejects it.
        let json = serde_json::json!({
            "slot_id": slot(0),
            "outcome": "activated",
            "observation": {"state": "known", "value": {"generation": "g-1"}},
            "compensated": true,
            "error": "boom"
        });
        let err = serde_json::from_str::<SlotOutcomeRowWire>(&json.to_string()).unwrap_err();
        assert!(err.is_data(), "the old flat shape must be refused");

        // A non-failed variant smuggling an `error` member is refused.
        let json = serde_json::json!({
            "slot_id": slot(0),
            "result": {
                "state": "activated",
                "observation": {"state": "known", "value": {"generation": "g-1"}},
                "error": "boom"
            }
        });
        let err = serde_json::from_str::<SlotOutcomeRowWire>(&json.to_string()).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "an error on a non-failed variant must be refused, got: {err}"
        );

        // An unknown member at EVERY nesting level is refused: the row, the
        // body, the observation, and the generation payload.
        let mut row = serde_json::json!({
            "slot_id": slot(0),
            "result": {
                "state": "restored",
                "observation": {"state": "known", "value": {"generation": "g-1"}}
            },
            "extra_row": 1
        });
        for level in ["row", "body", "observation", "generation payload"] {
            // Inject the stray member at THIS nesting level (the doc borrow
            // is scoped so the row can be serialized after it drops).
            {
                let doc: &mut serde_json::Value = match level {
                    "row" => &mut row,
                    "body" => &mut row["result"],
                    "observation" => &mut row["result"]["observation"],
                    _ => &mut row["result"]["observation"]["value"],
                };
                if let Some(m) = doc.as_object_mut() {
                    m.insert("extra".to_string(), serde_json::json!(1));
                }
            }
            assert!(
                serde_json::from_str::<SlotOutcomeRowWire>(&serde_json::to_string(&row).unwrap())
                    .is_err(),
                "an unknown member at the {level} level must be refused"
            );
            {
                let doc: &mut serde_json::Value = match level {
                    "row" => &mut row,
                    "body" => &mut row["result"],
                    "observation" => &mut row["result"]["observation"],
                    _ => &mut row["result"]["observation"]["value"],
                };
                if let Some(m) = doc.as_object_mut() {
                    m.remove("extra");
                }
            }
        }
    }

    /// MIRROR of the engine's post-observation pass: apply a generated
    /// post-mutation observation to a wire [`SlotResult`], mutating ONLY the
    /// observation — the operation error (`error`) is NEVER touched.
    fn apply_post_observation(r: &mut SlotResult, observation: &Observation<ObservedGeneration>) {
        let obs = ObservationWire::from(observation);
        match &mut r.result {
            SlotOutcomeBodyWire::Activated { observation }
            | SlotOutcomeBodyWire::Restored { observation }
            | SlotOutcomeBodyWire::Skipped { observation }
            | SlotOutcomeBodyWire::FailedBeforeAdvance { observation, .. }
            | SlotOutcomeBodyWire::FailedAfterAdvance { observation, .. }
            | SlotOutcomeBodyWire::Indeterminate { observation, .. } => {
                *observation = obs;
            }
        }
    }

    proptest! {
        // THE USER'S PROPERTY: the operation error and the post-mutation
        // observation are TWO INDEPENDENT facts. Every (operation_error,
        // observation) pair round-trips domain → wire → domain EXACTLY on a
        // failed variant, including a full serde_json round trip of the
        // wire. Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
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
            // A domain FAILED-BEFORE-ADVANCE outcome carrying EXACTLY the
            // two generated facts.
            let outcome = SlotOutcome::FailedBeforeAdvance {
                observation: observation.clone(),
                error: operation_error.clone(),
            };
            // Domain → wire: each fact lands in its OWN wire slot.
            let wire = SlotResult::from_outcome(&slot(0), &outcome);
            assert_eq!(
                wire.result.observation(),
                &ObservationWire::from(&observation),
                "the observation is written to the body's observation field"
            );
            assert_eq!(
                wire.result,
                SlotOutcomeBodyWire::FailedBeforeAdvance {
                    observation: ObservationWire::from(&observation),
                    error: operation_error.clone(),
                }
            );
            // Wire → domain: both facts survive INDEPENDENTLY.
            let back = SlotOutcome::from_wire(wire.clone()).unwrap();
            assert_eq!(
                back.error(),
                operation_error.as_deref(),
                "the operation error survives the wire untouched"
            );
            assert_eq!(
                back.observation(),
                &observation,
                "the observation survives the wire untouched"
            );
            // A full serde_json round trip of the wire preserves both facts.
            let json = serde_json::to_string(&wire).unwrap();
            let wire2: SlotResult = serde_json::from_str(&json).unwrap();
            assert_eq!(wire2, wire);
            let back2 = SlotOutcome::from_wire(wire2).unwrap();
            assert_eq!(back2.error(), operation_error.as_deref());
            assert_eq!(back2.observation(), &observation);
        }

        #[test]
        fn post_observation_preserves_both_facts(
            operation_error in arbitrary_operation_error(),
            observation in arbitrary_observation(),
        ) {
            // A pre-swap FAILED wire outcome ALREADY carries the original
            // operation error; its desired observation is about to be
            // replaced by the observed post-state.
            let mut wire = SlotResult {
                slot_id: slot(0),
                result: SlotOutcomeBodyWire::FailedBeforeAdvance {
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: GenerationId::new("desired-0".to_string())}),
                    error: operation_error.clone()},
            };
            // Failure injection: the engine's post-observation pass.
            apply_post_observation(&mut wire, &observation);
            // The operation error is NEVER rewritten by the observation.
            assert_eq!(
                wire.result.observation(),
                &ObservationWire::from(&observation),
                "the wire observation must reflect the generated observation"
            );
            assert_eq!(
                wire.result,
                SlotOutcomeBodyWire::FailedBeforeAdvance {
                    observation: ObservationWire::from(&observation),
                    error: operation_error.clone(),
                },
                "the operation error must never be rewritten by the post-mutation observation"
            );
            // The injected wire still converts back to the SAME two facts.
            let back = SlotOutcome::from_wire(wire).unwrap();
            assert_eq!(
                back.error(),
                operation_error.as_deref(),
                "the operation error survives the injection untouched"
            );
            assert_eq!(
                back.observation(),
                &observation,
                "the observation survives the injection untouched"
            );
        }

        // THE FULL-VARIANT ROUND-TRIP PROPERTY: generate EVERY wire outcome
        // body variant — each of the six execution states, every
        // observation, with/without an operation error — and assert the full
        // round trip `wire → from_wire → from_outcome → from_wire` preserves
        // the EXACT semantic variant and its evidence (the domain value is a
        // FIXED POINT of the conversion).
        #[test]
        fn every_wire_outcome_variant_round_trips_to_the_same_domain_value(
            wire in arbitrary_wire_outcome(),
        ) {
            let domain = SlotOutcome::from_wire(wire.clone()).unwrap();
            let re_encoded = SlotResult::from_outcome(&wire.slot_id, &domain);
            let domain2 = SlotOutcome::from_wire(re_encoded).unwrap();
            assert_eq!(
                domain, domain2,
                "wire → from_wire → from_outcome → from_wire must preserve the EXACT semantic variant"
            );
            assert_eq!(
                domain.error(),
                domain2.error(),
                "the operation error must survive the round trip"
            );
            assert_eq!(
                domain.observation(),
                domain2.observation(),
                "the observation must survive the round trip"
            );
        }
    }
}

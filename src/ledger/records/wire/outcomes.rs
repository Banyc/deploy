//! The per-slot OUTCOME records of the deployment ledger (feature areas A1
//! "outcome dispositions" / "per-slot outcome kinds" / "degraded
//! semantics"): the per-slot outcome kinds ([`SlotOutcomeKind`]) and the
//! STRUCTURAL domain outcome ([`SlotOutcome`] — one variant per
//! classification, with the per-slot TRANSITION STATE ([`SlotTransition`])
//! DERIVED from the variant, never stored), the WIRE outcome row
//! ([`SlotResult`] — the raw serde form the ledger's JSONL carries, owned
//! HERE next to its domain sibling), the wire → domain BIJECTION
//! ([`SlotOutcome::from_wire`], [`SlotOutcomeRowWire::from_outcome`]), the
//! [`CompensationReport`] alias, and the
//! [`LedgerTerminal::remaining_changes`],
//! [`LedgerTerminal::compensation`]) — the derivations implemented on the
//! terminal here, next to the outcomes they derive from.

use crate::error::Result;
use crate::identity::SlotId;
use serde::{Deserialize, Serialize};

use super::super::SlotTable;
use super::super::observation::{
    Observation, ObservationWire, ObservedGeneration, ObservedGenerationWire,
};
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
/// the per-slot CLASSIFICATION the terminal's outcomes derive. Since the
/// structural outcome reshape, the transition is a DERIVED view of the
/// outcome variant ([`SlotOutcome::transition`]) — NEVER stored as an
/// independent field that could disagree with the outcome (the old
/// `SlotOutcome { outcome, compensated, transition }` stored the SAME fact
/// twice). The remaining-changes derivation is based on this state, never
/// on the outcome's generation field alone: a slot that was never advanced
/// (or whose advance outcome is unknown) records a generation that is not
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
/// RAW serde form the ledger's JSONL carries: the slot ROW OWNS ITS SLOT ID
/// (the row lives in the terminal's `outcomes` ARRAY — there is no object
/// key for the identity to disagree with). The post-mutation OBSERVATION
/// rides in its STRICT adjacently-tagged wire form
/// ([`ObservationWire<ObservedGenerationWire>`], `deny_unknown_fields`)
/// — the raw document rejects any field beyond the declared ones and any
/// observation shape that is not EXACTLY one variant (a mixed
/// generation-plus-error document can never deserialize into a half-known
/// state).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotOutcomeRowWire {
    pub slot_id: SlotId,
    pub outcome: SlotOutcomeKind,
    /// The THREE-STATE OBSERVATION of the slot's post-mutation state, in
    /// its STRICT WIRE form: `Known` (a successful read recording the
    /// observed generation), `KnownAbsent` (a successful read showing no
    /// state — never deployed), or `Unknown(error)` (a FAILED post-mutation
    /// OBSERVATION — the preserved error, INDEPENDENT of the operation
    /// `error`: an operation failure and a failed observation are TWO facts
    /// and both survive the wire).
    pub observation: ObservationWire<ObservedGenerationWire>,
    pub compensated: bool,
    /// The pure OPERATION error (e.g. a swap failure) — the slot's own
    /// failure, INDEPENDENT of the post-mutation observation. NEVER
    /// rewritten by the post-observation pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The PRE-ROW-ARRAY name of the wire outcome row — kept as a re-export
/// type alias so the in-memory engine result maps (the display/execution
/// result maps keyed by slot in `deploy/rollout` / `deploy/push/execute` /
/// the retention history floor) keep compiling: they share the wire's
/// shape but are NOT wire rows; the JSONL wire row is [`SlotOutcomeRowWire`].
pub type SlotResult = SlotOutcomeRowWire;

/// The per-slot OUTCOME of one slot during a deployment's mutation loop —
/// the STRUCTURAL DOMAIN value of the wire's [`SlotOutcomeRowWire`] with the
/// REDUNDANT `slot_id` DROPPED: the enclosing [`SlotTable`] key owns the
/// slot identity, so the value stores each fact exactly once. The
/// classification is the VARIANT ITSELF — one variant per outcome class —
/// so a nonsense combination (a compensated `Activated`, a restored
/// `Skipped`) is UNREPRESENTABLE instead of being accepted as three
/// independent fields. The wire keeps the current on-disk shape (the wire
/// outcome carries the slot + the raw kind/compensated/error fields); the
/// wire → domain conversion ([`SlotOutcome::from_wire`]) maps the wire's
/// (kind, compensated, observation, error) to the ONE variant the wire
/// describes, and [`SlotOutcomeRowWire::from_outcome`] encodes the variant back to
/// its CANONICAL wire shape — the conversion is a BIJECTION (variant-
/// preserving: both `Failed { compensated: true }` and `Compensated`
/// derive `Restored`, but they are DISTINCT variants that round-trip to
/// their exact wire shapes). The per-slot TRANSITION STATE
/// ([`SlotTransition`]) — the fact the remaining-changes derivation is
/// based on — is DERIVED from the variant ([`SlotOutcome::transition`]),
/// never stored. The domain carries NO serde (strict wire types only
/// deserialize; the ledger's JSONL carries [`SlotOutcomeRowWire`] and the
/// `ObservationWire` forms).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotOutcome {
    /// The slot advanced to the new state (the swap + activation +
    /// verification succeeded): always a remaining change when the new
    /// state differs from pre_push.
    Activated {
        observation: Observation<ObservedGeneration>,
    },
    /// The slot advanced then was compensated back to its pre_push state
    /// (by the per-server pipeline or the failure-policy pass): never a
    /// remaining change.
    Restored {
        observation: Observation<ObservedGeneration>,
    },
    /// The slot was never mutated (skipped under `stop_on_failure`, or a
    /// compare-and-swap precondition skip): never a remaining change.
    Skipped {
        observation: Observation<ObservedGeneration>,
    },
    /// The slot FAILED. `compensated: true` records a successful in-process
    /// compensation (the failure AND the compensation result are both
    /// recorded); `error` is the pure OPERATION error (e.g. a swap
    /// failure), INDEPENDENT of the observation. An UNCOMPENSATED failure
    /// is a pre-swap failure OR a post-swap failure whose compensation
    /// failed — the wire cannot distinguish them, so the advance outcome is
    /// UNKNOWN (the slot may or may not have changed; the remaining-changes
    /// derivation compares the outcome's OBSERVED generation against
    /// pre_push).
    Failed {
        observation: Observation<ObservedGeneration>,
        compensated: bool,
        error: Option<String>,
    },
    /// Reserved by the wire (never emitted today). A restored slot, like a
    /// compensated `Failed` — distinct from it on the wire.
    Compensated {
        observation: Observation<ObservedGeneration>,
    },
}

impl SlotOutcome {
    /// WIRE → DOMAIN (the boundary's fail-closed conversion): map the
    /// wire's (kind, compensated, observation, error) to the ONE structural
    /// variant the wire describes. Each kind maps to exactly one variant —
    /// `Activated` → [`SlotOutcome::Activated`], `Restored` →
    /// [`SlotOutcome::Restored`], `Skipped` → [`SlotOutcome::Skipped`],
    /// `Failed` (with BOTH `compensated` values) → [`SlotOutcome::Failed`],
    /// the reserved `Compensated` → [`SlotOutcome::Compensated`] — so the
    /// variant and the wire's classification can never disagree (the old
    /// domain stored the kind + a separately-written `transition` that a
    /// caller could contradict). The strict adjacently-tagged wire
    /// observation converts to the permissive domain observation; a wire
    /// value that is not representable is refused here (never read as a
    /// half-known state). `error` is the pure OPERATION error — it NEVER
    /// participates in the observation.
    pub fn from_wire(r: SlotOutcomeRowWire) -> Result<SlotOutcome> {
        let observation: Observation<ObservedGeneration> = r.observation.try_into()?;
        Ok(match r.outcome {
            SlotOutcomeKind::Activated => SlotOutcome::Activated { observation },
            SlotOutcomeKind::Restored => SlotOutcome::Restored { observation },
            SlotOutcomeKind::Skipped => SlotOutcome::Skipped { observation },
            SlotOutcomeKind::Failed => SlotOutcome::Failed {
                observation,
                compensated: r.compensated,
                error: r.error,
            },
            // Reserved: never emitted today. The in-process compensation
            // marker (a post-swap failure restored by the per-server
            // pipeline) is recorded as `Failed` with `compensated = true`;
            // a `Compensated` outcome would be a restored slot.
            SlotOutcomeKind::Compensated => SlotOutcome::Compensated { observation },
        })
    }

    /// The per-slot TRANSITION STATE, DERIVED from the variant (never
    /// stored — the variant IS the fact). `Restored` and a compensated
    /// `Failed` are a compensation that restored the slot; `Skipped` never
    /// advanced; `Activated` advanced; an UNCOMPENSATED `Failed` is a
    /// pre-swap failure OR a post-swap failure whose compensation failed —
    /// the wire cannot distinguish them, so the advance outcome is UNKNOWN
    /// (the slot may or may not have changed; the remaining-changes
    /// derivation compares the outcome's OBSERVED generation against
    /// pre_push).
    pub fn transition(&self) -> SlotTransition {
        match self {
            Self::Activated { .. } => SlotTransition::Advanced,
            Self::Restored { .. } | Self::Compensated { .. } => SlotTransition::Restored,
            Self::Skipped { .. } => SlotTransition::NeverAdvanced,
            Self::Failed {
                compensated: true, ..
            } => SlotTransition::Restored,
            Self::Failed {
                compensated: false, ..
            } => SlotTransition::AdvanceUnknown,
        }
    }

    /// The outcome's three-state post-mutation OBSERVATION (the observed
    /// generation the remaining-changes derivation compares against
    /// pre_push) — shared by every variant.
    pub fn observation(&self) -> &Observation<ObservedGeneration> {
        match self {
            Self::Activated { observation }
            | Self::Restored { observation }
            | Self::Skipped { observation }
            | Self::Failed { observation, .. }
            | Self::Compensated { observation } => observation,
        }
    }
}

impl SlotOutcomeRowWire {
    /// Re-attach the table key as the wire outcome's `slot_id` (the wire
    /// keeps the on-disk shape; the domain value carries no slot) and encode
    /// the structural variant back into the wire's CANONICAL shape: the
    /// variant's OWN kind + `compensated` value (only `Failed` carries
    /// `compensated`/`error` — the other variants encode their canonical
    /// `compensated: false, error: None` shape; the reserved `Compensated`
    /// encodes its own kind). The DOMAIN's TWO INDEPENDENT error facts map
    /// back into the wire's shape:
    /// `error` carries the pure OPERATION error (always, regardless of the
    /// observation — the two facts never share a slot); the THREE-STATE
    /// OBSERVATION is encoded as its EXACT strict wire form
    /// ([`ObservationWire<ObservedGenerationWire>`]) — the `Known` half is
    /// the recorded generation, the `Unknown` half is its OWN preserved
    /// error, and a `KnownAbsent` observation carries no value fields. The
    /// conversion is a BIJECTION: every domain variant maps to EXACTLY one
    /// wire shape, and [`SlotOutcome::from_wire`] reads that shape back to
    /// the SAME variant.
    pub fn from_outcome(key: &SlotId, o: &SlotOutcome) -> Self {
        let (outcome, compensated, error) = match o {
            SlotOutcome::Activated { .. } => (SlotOutcomeKind::Activated, false, None),
            SlotOutcome::Restored { .. } => (SlotOutcomeKind::Restored, false, None),
            SlotOutcome::Skipped { .. } => (SlotOutcomeKind::Skipped, false, None),
            SlotOutcome::Failed {
                compensated, error, ..
            } => (SlotOutcomeKind::Failed, *compensated, error.clone()),
            SlotOutcome::Compensated { .. } => (SlotOutcomeKind::Compensated, false, None),
        };
        SlotResult {
            slot_id: key.clone(),
            outcome,
            observation: ObservationWire::from(o.observation()),
            compensated,
            error,
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

    /// EVERY constructible wire outcome: each [`SlotOutcomeKind`] (incl. the
    /// reserved `Compensated`), BOTH `compensated` values on `Failed` (the
    /// other kinds carry the canonical `false`), every three-state
    /// observation, and with/without an operation error.
    fn arbitrary_wire_outcome() -> impl Strategy<Value = SlotResult> {
        (
            arbitrary_observation(),
            arbitrary_operation_error(),
            prop::bool::ANY,
            0u32..6,
        )
            .prop_map(|(observation, error, compensated, idx)| {
                let outcome = match idx {
                    0 => SlotOutcomeKind::Activated,
                    1 => SlotOutcomeKind::Restored,
                    2 => SlotOutcomeKind::Skipped,
                    3 => SlotOutcomeKind::Compensated,
                    _ => SlotOutcomeKind::Failed,
                };
                // Only `Failed` carries the generated compensation flag (the
                // wire's canonical shape for every other kind); every kind
                // may carry an operation error by generation but the domain
                // only KEEPS it on `Failed` — the other kinds canonicalize
                // to `error: None` on re-encode, so the domain fixed point
                // is preserved either way.
                let is_failed = matches!(outcome, SlotOutcomeKind::Failed);
                SlotResult {
                    slot_id: slot(0),
                    outcome,
                    observation: ObservationWire::from(&observation),
                    compensated: is_failed && compensated,
                    error,
                }
            })
    }

    /// MIRROR of the engine's post-observation pass (`src/push/engine.rs`'s
    /// `never_advanced` loop): apply a generated post-mutation observation
    /// to a wire [`SlotResult`], mutating ONLY the observation — the
    /// operation error (`error`) is NEVER touched. The engine loop is not
    /// cleanly reachable from a records-level unit test, so this helper
    /// mirrors its fixed logic.
    fn apply_post_observation(r: &mut SlotResult, observation: &Observation<ObservedGeneration>) {
        r.observation = ObservationWire::from(observation);
    }

    /// (a) An outcome carrying BOTH an operation error AND an `Unknown`
    /// observation round-trips preserving both — the two facts are
    /// INDEPENDENT on the wire (the old single-error wire could not carry a
    /// distinct operation error alongside a failed observation).
    #[test]
    fn operation_error_and_unknown_observation_round_trip_preserves_both() {
        let outcome = SlotOutcome::Failed {
            observation: Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
        };
        let wire = SlotResult::from_outcome(&slot(1), &outcome);
        assert_eq!(
            wire.observation,
            ObservationWire::Unknown(ObservationError {
                message: "status read failed: boom".to_string()
            }),
            "the Unknown observation is written to the wire's observation"
        );
        assert_eq!(
            wire.error,
            Some("swap failed: boom".to_string()),
            "the operation error is written to the wire's error field"
        );
        // A full serde_json round trip of the wire keeps both facts.
        let json = serde_json::to_string(&wire).unwrap();
        let wire_json: SlotResult = serde_json::from_str(&json).unwrap();
        assert_eq!(wire_json.error, Some("swap failed: boom".to_string()));
        assert_eq!(wire_json.observation, wire.observation);
        let back = SlotOutcome::from_wire(wire).unwrap();
        assert_eq!(
            back.error(),
            Some("swap failed: boom".to_string()),
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
    /// observation must NOT overwrite it (the old loop did both).
    #[test]
    fn post_observation_preserves_the_operation_error() {
        // A pre-swap FAILED outcome ALREADY carries its operation error; the
        // post-observation pass mutates only the observation.
        let mut known_absent = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            observation: ObservationWire::Known(ObservedGenerationWire {
                generation: GenerationId::new("desired-1".to_string()),
            }),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
        };
        apply_post_observation(&mut known_absent, &Observation::KnownAbsent);
        assert_eq!(
            known_absent.error,
            Some("swap failed: boom".to_string()),
            "KnownAbsent must NOT wipe the operation error"
        );
        assert_eq!(
            known_absent.observation,
            ObservationWire::KnownAbsent,
            "KnownAbsent is a unit on the wire"
        );

        let mut unknown = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            observation: ObservationWire::Known(ObservedGenerationWire {
                generation: GenerationId::new("desired-1".to_string()),
            }),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
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
        assert_eq!(
            unknown.observation,
            ObservationWire::Unknown(ObservationError {
                message: "status read failed: boom".to_string()
            }),
            "the observation error lands in the Unknown observation, never in error"
        );

        let mut known = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            observation: ObservationWire::Known(ObservedGenerationWire {
                generation: GenerationId::new("desired-1".to_string()),
            }),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
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
            known.observation,
            ObservationWire::Known(ObservedGenerationWire {
                generation: GenerationId::new("observed-1".to_string())
            }),
            "the observed generation lands in the Known observation"
        );
    }

    /// (b2) THE STRUCTURAL VARIANT + DERIVED TRANSITION: every variant
    /// derives the transition the old independently-stored field carried,
    /// and the wire round trip preserves the EXACT variant (a `Failed {
    /// compensated: true }` stays `Failed`, distinct from the reserved
    /// `Compensated`, even though both derive `Restored`).
    #[test]
    fn structural_variants_derive_the_transition_and_round_trip_exactly() {
        let cases: Vec<(SlotOutcome, SlotTransition)> = vec![
            (
                SlotOutcome::Activated {
                    observation: Observation::KnownAbsent,
                },
                SlotTransition::Advanced,
            ),
            (
                SlotOutcome::Restored {
                    observation: Observation::KnownAbsent,
                },
                SlotTransition::Restored,
            ),
            (
                SlotOutcome::Skipped {
                    observation: Observation::KnownAbsent,
                },
                SlotTransition::NeverAdvanced,
            ),
            (
                SlotOutcome::Failed {
                    observation: Observation::KnownAbsent,
                    compensated: false,
                    error: None,
                },
                SlotTransition::AdvanceUnknown,
            ),
            (
                SlotOutcome::Failed {
                    observation: Observation::KnownAbsent,
                    compensated: true,
                    error: Some("activation failed".to_string()),
                },
                SlotTransition::Restored,
            ),
            (
                SlotOutcome::Compensated {
                    observation: Observation::KnownAbsent,
                },
                SlotTransition::Restored,
            ),
        ];
        for (outcome, expected) in &cases {
            assert_eq!(
                outcome.transition(),
                *expected,
                "the derived transition must match the variant: {outcome:?}"
            );
            // Variant-preserving wire round trip: from_outcome → from_wire
            // reproduces the EXACT domain variant.
            let wire = SlotResult::from_outcome(&slot(0), outcome);
            let back = SlotOutcome::from_wire(wire.clone()).unwrap();
            assert_eq!(
                &back, outcome,
                "the wire round trip must preserve the EXACT variant"
            );
            assert_eq!(
                back.transition(),
                *expected,
                "the round-tripped variant derives the same transition"
            );
            // The encoded wire is canonical for the variant.
            assert_eq!(wire.compensated, outcome.compensated());
            assert_eq!(wire.error, outcome.error());
        }
    }

    impl SlotOutcome {
        /// TEST-ONLY helpers: the wire-visible facts of the structural
        /// variant (the compensated flag and the operation error — only
        /// `Failed` carries them).
        fn compensated(&self) -> bool {
            match self {
                Self::Failed { compensated, .. } => *compensated,
                _ => false,
            }
        }
        fn error(&self) -> Option<String> {
            match self {
                Self::Failed { error, .. } => error.clone(),
                _ => None,
            }
        }
    }

    proptest! {
        // THE USER'S PROPERTY: the operation error and the post-mutation
        // observation are TWO INDEPENDENT facts. (1) Every (operation_error,
        // observation) pair round-trips domain → wire → domain EXACTLY,
        // including a full serde_json round trip of the wire. (2) Failure
        // injection (the engine's post-observation pass, mirrored by
        // [`apply_post_observation`]) never rewrites the operation error and
        // reflects the observation. The cross product covers the directions
        // where the OLD code was wrong: an `Unknown` observation + a distinct
        // operation error both survive, and a `KnownAbsent` observation + an
        // operation error survives. Bounded 16 cases, fixed seed 0x5EED_5EED
        // (house style), no persistence.
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
            // A domain FAILED outcome carrying EXACTLY the two generated facts.
            let outcome = SlotOutcome::Failed {
                observation: observation.clone(),
                compensated: false,
                error: operation_error.clone(),
            };
            // Domain → wire: each fact lands in its OWN wire slot.
            let wire = SlotResult::from_outcome(&slot(0), &outcome);
            assert_eq!(
                wire.error,
                operation_error,
                "the operation error is written to the wire's error field"
            );
            assert_eq!(
                wire.observation,
                ObservationWire::from(&observation),
                "the observation is written to the wire's observation field"
            );
            // Wire → domain: both facts survive INDEPENDENTLY.
            let back = SlotOutcome::from_wire(wire.clone()).unwrap();
            assert_eq!(
                back.error(),
                operation_error.clone(),
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
            assert_eq!(wire2.error, operation_error.clone());
            assert_eq!(wire2.observation, wire.observation);
            let back2 = SlotOutcome::from_wire(wire2).unwrap();
            assert_eq!(back2.error(), operation_error);
            assert_eq!(back2.observation(), &observation);
        }

        #[test]
        fn post_observation_preserves_both_facts(
            operation_error in arbitrary_operation_error(),
            observation in arbitrary_observation(),
        ) {
            // A pre-swap FAILED wire outcome ALREADY carries the original
            // operation error (e.g. "swap failed: ..."); its desired
            // observation is about to be replaced by the observed post-state.
            let mut wire = SlotResult {
                slot_id: slot(0),
                outcome: SlotOutcomeKind::Failed,
                observation: ObservationWire::Known(ObservedGenerationWire {
                    generation: GenerationId::new("desired-0".to_string())}),
                compensated: false,
                error: operation_error.clone()};
            // Failure injection: the engine's post-observation pass.
            apply_post_observation(&mut wire, &observation);
            // The operation error is NEVER rewritten by the observation.
            assert_eq!(
                wire.error,
                operation_error.clone(),
                "the operation error must never be rewritten by the post-mutation observation"
            );
            // The wire observation reflects the observation EXACTLY.
            assert_eq!(
                wire.observation,
                ObservationWire::from(&observation),
                "the wire observation must reflect the generated observation"
            );
            // The injected wire still converts back to the SAME two facts.
            let back = SlotOutcome::from_wire(wire).unwrap();
            assert_eq!(
                back.error(),
                operation_error,
                "the operation error survives the injection untouched"
            );
            assert_eq!(
                back.observation(),
                &observation,
                "the observation survives the injection untouched"
            );
        }

        // THE FULL-VARIANT ROUND-TRIP PROPERTY (the spec's acceptance gate,
        // item 1): generate EVERY wire outcome variant — each
        // [`SlotOutcomeKind`], both `compensated` values on `Failed`, every
        // observation state, with/without an operation error — and assert
        // the full round trip `wire → from_wire → from_outcome → from_wire`
        // preserves the EXACT semantic variant and the same derived
        // `transition()` (the domain value is a FIXED POINT of the
        // conversion: the canonical re-encode is the variant's one wire
        // shape).
        #[test]
        fn every_wire_outcome_variant_round_trips_to_the_same_domain_value(
            wire in arbitrary_wire_outcome(),
        ) {
            let domain = SlotOutcome::from_wire(wire.clone()).unwrap();
            let domain_transition = domain.transition();
            let re_encoded = SlotResult::from_outcome(&wire.slot_id, &domain);
            let domain2 = SlotOutcome::from_wire(re_encoded).unwrap();
            assert_eq!(
                domain, domain2,
                "wire → from_wire → from_outcome → from_wire must preserve the EXACT semantic variant"
            );
            assert_eq!(
                domain2.transition(),
                domain_transition,
                "the derived transition must be preserved by the round trip"
            );
        }
    }
}

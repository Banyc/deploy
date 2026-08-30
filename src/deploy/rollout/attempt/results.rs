//! Result-table shaping: [`fill_skipped_slots`] makes every SELECTED slot
//! appear in the results; [`observe_actual_servers`] records the
//! post-mutation observation of each member slot.

use crate::deploy::plan::PlannedAssignment;
use crate::identity::{ArtifactRef, GenerationId, SlotId};
use crate::ledger::ActualSlotState;
use crate::ledger::Observation;
use crate::ledger::ObservationError;
use crate::ledger::ObservationWire;
use crate::ledger::ObservedGeneration;
use crate::ledger::ObservedGenerationWire;
use crate::ledger::SlotOutcomeKind;
use crate::ledger::SlotResult;
use crate::remote::helper::RemoteHelper;
use crate::remote::helper::RemoteStatus;
use std::collections::BTreeMap;
use std::collections::HashMap;

// Result-table shaping (A1 deployment semantics).
//
// The per-slot result table of a push attempt is shaped in two places:
//
// * [`fill_skipped_slots`] — every SELECTED slot appears in the results even
//   when the batch loop never started it (a later failed batch under
//   `stop_on_failure`): the filler inserts a `Skipped` outcome carrying the
//   slot's RECONCILED current assignment (the observed generation, never a
//   generated desired one). Extracted from the old `push::engine` batch loop
//   (the batching section above).
// * [`observe_actual_servers`] — the post-mutation observation of each
//   slot's REAL final state, read from the remote generation it currently
//   points at (never the desired plan values), as the two parallel tables
//   the terminal event and the never-advanced outcome fix-up consume.
//
// The never-advanced OUTCOME fix-up that consumes the generation-half
// observation ([`record_never_advanced_outcomes`])
// stays with the failure-policy pass (failure section), where
// the degraded derivation and the never-advanced handling are documented
// together; the final outcome-map assembly (the `results` clone feeding the
// terminal append) is spine glue in [`crate::deploy::push::push_inner`].

/// Any slot never started (e.g. skipped after an earlier failure under
/// `stop_on_failure`) still appears in the attempt, with its reconciled
/// current assignment rather than a generated desired generation.
pub(crate) fn fill_skipped_slots(
    results: &mut BTreeMap<SlotId, SlotResult>,
    assignments: &[PlannedAssignment],
    statuses: &HashMap<SlotId, RemoteStatus>,
) {
    for a in assignments {
        if !results.contains_key(&a.placement_slot) {
            let cur = statuses
                .get(&a.placement_slot)
                .and_then(|s| s.current_generation.clone());
            results.insert(
                a.placement_slot.clone(),
                SlotResult {
                    slot_id: a.placement_slot.clone(),
                    outcome: SlotOutcomeKind::Skipped,
                    observation: match cur {
                        Some(g) => ObservationWire::Known(ObservedGenerationWire { generation: g }),
                        // No reconciled current assignment: a skipped slot
                        // with no observed state reads back as `KnownAbsent`.
                        None => ObservationWire::KnownAbsent,
                    },
                    compensated: false,
                    error: None,
                },
            );
        }
    }
}

/// THE FOUR LIVE-OBSERVATION CASES [`observe_actual_servers`] distinguishes,
/// parameterized by the RAW facts — the PURE input of the actual↔observation
/// pairing (so the pairing is a total function the pairing property can
/// drive directly, and the engine path stays byte-exact with it):
///
/// * [`LiveObservationCase::Observed`] — a successful status read with a
///   current generation whose assignment read succeeds;
/// * [`LiveObservationCase::Absent`] — a successful status read showing no
///   state;
/// * [`LiveObservationCase::AssignmentError`] — a successful status read
///   with a current generation whose (SECOND) assignment read fails (a
///   TOCTOU race — `status()` already validated the assignment, so this is
///   the defensive path): the generation is KNOWN, the artifact is NOT;
/// * [`LiveObservationCase::StatusError`] — the status read itself failed.
///
/// The pairing is CONSISTENT: a desired artifact NEVER appears inside an
/// "actual" state unless the remote was observed carrying it, an `Unknown`
/// preserves its error (+ the generation hint when it is known), and
/// `Absent` is only ever a successful observation of absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveObservationCase {
    Observed {
        generation: GenerationId,
        artifact: ArtifactRef,
    },
    Absent,
    AssignmentError {
        generation: GenerationId,
        error: ObservationError,
    },
    StatusError {
        error: ObservationError,
    },
}

/// THE ACTUAL↔OBSERVATION PAIRING of one slot's live observation — the pure
/// mapping every slot's post-mutation actual + its GENERATION-HALF
/// observation come from (the observation is a DIFFERENT fact, feeding the
/// never-advanced outcomes below). `Observed{generation, artifact}` pairs
/// with `Known(ObservedGeneration { generation })`; `Absent` with
/// `KnownAbsent`; `AssignmentError{generation, error}` with the preserved
/// `Unknown(error)` AND the generation hint in the actual; `StatusError
/// { error }` with the preserved `Unknown(error)` and no hint.
pub(crate) fn pair_actual_state(
    case: &LiveObservationCase,
) -> (ActualSlotState, Observation<ObservedGeneration>) {
    match case {
        LiveObservationCase::Observed {
            generation,
            artifact,
        } => (
            ActualSlotState::Observed {
                artifact: artifact.clone(),
                generation: generation.clone(),
            },
            Observation::Known(ObservedGeneration {
                generation: generation.clone(),
            }),
        ),
        LiveObservationCase::Absent => (ActualSlotState::Absent, Observation::KnownAbsent),
        LiveObservationCase::AssignmentError { generation, error } => (
            ActualSlotState::Unknown {
                error: error.clone(),
                generation: Some(generation.clone()),
            },
            Observation::Unknown(error.clone()),
        ),
        LiveObservationCase::StatusError { error } => (
            ActualSlotState::Unknown {
                error: error.clone(),
                generation: None,
            },
            Observation::Unknown(error.clone()),
        ),
    }
}

/// Observe each slot's *real* final state, read from the remote generation it
/// currently points at, rather than the desired plan values.
/// Failed/skipped/restored slots therefore report their actual artifact
/// instead of the desired one. Each actual is the slot's state AS OBSERVED —
/// a DESIRED ARTIFACT NEVER appears inside an "actual" value unless the
/// remote was observed carrying it (the "pre-push build put the planned
/// artifact into an actual" bug is gone): a successful observation of
/// absence ([`ActualSlotState::Absent`]) and every failed read
/// ([`ActualSlotState::Unknown`]) carry no known artifact. The parallel
/// `actual_observations` map carries the GENERATION half of the observation
/// (a different fact, feeding the never-advanced outcomes below): a FAILED
/// post-mutation status read is `Unknown(error)`, never a `None` that
/// downstream code reads as "unchanged". The wire-shaped `actual_servers`
/// keeps the current on-disk shape — generation only — so the observation's
/// `Unknown` half is recorded into the never-advanced outcomes'
/// `observation_error` field, while the outcome's OWN operation error
/// (`error`) is left untouched.
pub(crate) fn observe_actual_servers(
    assignments: &[PlannedAssignment],
    helpers: &HashMap<SlotId, RemoteHelper>,
) -> (
    BTreeMap<SlotId, ActualSlotState>,
    BTreeMap<SlotId, Observation<ObservedGeneration>>,
) {
    let mut actual_servers: BTreeMap<SlotId, ActualSlotState> = BTreeMap::new();
    let mut actual_observations: BTreeMap<SlotId, Observation<ObservedGeneration>> =
        BTreeMap::new();
    for a in assignments {
        let sid = &a.placement_slot;
        let helper = &helpers[sid];
        let status = helper.status();
        let case = match status {
            Ok(s) => match s.current_generation {
                Some(g) => match helper.read_assignment(g.as_str()) {
                    Ok(asn) => LiveObservationCase::Observed {
                        generation: g.clone(),
                        artifact: asn.artifact,
                    },
                    Err(e) => LiveObservationCase::AssignmentError {
                        generation: g.clone(),
                        error: ObservationError {
                            message: format!("assignment read failed: {e}"),
                        },
                    },
                },
                None => LiveObservationCase::Absent,
            },
            Err(e) => LiveObservationCase::StatusError {
                error: ObservationError {
                    message: format!("status read failed: {e}"),
                },
            },
        };
        let (actual, observation) = pair_actual_state(&case);
        actual_servers.insert(sid.clone(), actual);
        actual_observations.insert(sid.clone(), observation);
    }
    (actual_servers, actual_observations)
}

#[cfg(test)]
mod tests_results {
    use super::*;
    use crate::identity::VariantName;
    use crate::identity::{test_generation_id, test_release_id, test_tree_digest};
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;

    fn artifact(tag: &str) -> ArtifactRef {
        ArtifactRef {
            release: test_release_id(tag),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest(tag),
        }
    }

    /// A generated ACTUAL STATE, mirroring the four cases the engine can
    /// produce: `Observed` (artifact + generation), `Absent`, `Unknown`
    /// (with/without a generation hint), `NotAttempted`.
    fn arbitrary_actual() -> impl Strategy<Value = ActualSlotState> {
        prop_oneof![
            (0..2usize, 0..2usize).prop_map(|(i, j)| ActualSlotState::Observed {
                artifact: artifact(&format!("art-{i}-{j}")),
                generation: test_generation_id(&format!("gen-{i}-{j}")),
            }),
            Just(ActualSlotState::Absent),
            (0..2usize, proptest::bool::ANY).prop_map(|(j, has_gen)| ActualSlotState::Unknown {
                error: ObservationError {
                    message: format!("read failed: case {j}"),
                },
                generation: has_gen.then(|| test_generation_id(&format!("gen-hint-{j}"))),
            }),
            Just(ActualSlotState::NotAttempted),
        ]
    }

    /// THE ACTUAL-STATE WELL-FORMEDNESS PROPERTY (spec item 4.3, the
    /// type-level half): every `Unknown` preserves its read failure (+ its
    /// generation hint, never collapsed into `Absent`/`Observed`); `Absent`
    /// is a successful observation of absence that never carries a known
    /// state; `Observed` ALWAYS carries BOTH the artifact AND the generation
    /// (never a desired artifact, never a missing generation).
    fn run_actual_state_case(state: &ActualSlotState) {
        match state {
            ActualSlotState::Observed {
                artifact,
                generation,
            } => {
                // Both halves are real observed facts — the artifact is a
                // validated identity (never a fabricated "desired" one) and
                // the generation is present.
                assert!(artifact.release.as_str().starts_with("rel-sha256-"));
                assert_eq!(artifact.variant.as_str(), "standard");
                assert!(generation.as_str().starts_with("gen-"));
            }
            ActualSlotState::Absent => {
                // The explicit successful observation of absence carries NO
                // known state (never a fabricated desired artifact).
                assert_eq!(state, &ActualSlotState::Absent);
            }
            ActualSlotState::Unknown { error, generation } => {
                // The failure is preserved, never collapsed; the generation
                // hint is present EXACTLY when the status read succeeded.
                assert!(error.message.starts_with("read failed:"));
                if let Some(g) = generation {
                    assert!(g.as_str().starts_with("gen-"));
                }
            }
            ActualSlotState::NotAttempted => {
                assert_eq!(state, &ActualSlotState::NotAttempted);
            }
        }
    }

    /// A generated LIVE-OBSERVATION CASE (the pure pairing input): the four
    /// distinguished cases with arbitrary raw facts.
    fn arbitrary_case() -> impl Strategy<Value = LiveObservationCase> {
        (0u8..4, 0..2usize).prop_map(|(kind, j)| match kind {
            0 => LiveObservationCase::Observed {
                generation: test_generation_id(&format!("gen-{j}")),
                artifact: artifact(&format!("art-{j}")),
            },
            1 => LiveObservationCase::Absent,
            2 => LiveObservationCase::AssignmentError {
                generation: test_generation_id(&format!("gen-{j}")),
                error: ObservationError {
                    message: format!("assignment read failed: case {j}"),
                },
            },
            _ => LiveObservationCase::StatusError {
                error: ObservationError {
                    message: format!("status read failed: case {j}"),
                },
            },
        })
    }

    /// THE ACTUAL↔OBSERVATION PAIRING PROPERTY (spec item 4.3, the pairing
    /// half): every case pairs to a CONSISTENT actual + observation — the
    /// observation derivable from the actual (its generation half) equals the
    /// paired observation, and the actual derivable from the observation (its
    /// error/generation facts) equals the paired actual. A desired artifact
    /// never appears in an actual; an `Unknown` always stays `Unknown` with
    /// its preserved error and its generation hint; `Absent` only ever comes
    /// from a successful observation of absence.
    fn run_pairing_case(case: &LiveObservationCase) {
        let (actual, observation) = pair_actual_state(case);
        // The observation implied by the ACTUAL (its generation half) equals
        // the paired observation.
        let implied: Observation<ObservedGeneration> = match &actual {
            ActualSlotState::Observed { generation, .. } => {
                Observation::Known(ObservedGeneration {
                    generation: generation.clone(),
                })
            }
            ActualSlotState::Absent => Observation::KnownAbsent,
            ActualSlotState::Unknown { error, .. } => Observation::Unknown(error.clone()),
            ActualSlotState::NotAttempted => unreachable!("NotAttempted is never paired"),
        };
        assert_eq!(
            implied, observation,
            "the actual must imply its observation"
        );

        // The ACTUAL implied by the observation + the case kind equals the
        // paired actual (error + generation-hint consistency).
        match case {
            LiveObservationCase::Observed {
                generation,
                artifact,
            } => {
                assert_eq!(
                    actual,
                    ActualSlotState::Observed {
                        artifact: artifact.clone(),
                        generation: generation.clone(),
                    }
                );
            }
            LiveObservationCase::Absent => assert_eq!(actual, ActualSlotState::Absent),
            LiveObservationCase::AssignmentError { generation, error } => {
                assert_eq!(
                    actual,
                    ActualSlotState::Unknown {
                        error: error.clone(),
                        generation: Some(generation.clone()),
                    }
                );
            }
            LiveObservationCase::StatusError { error } => {
                assert_eq!(
                    actual,
                    ActualSlotState::Unknown {
                        error: error.clone(),
                        generation: None,
                    }
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        /// THE ACTUAL-STATE WELL-FORMEDNESS PROPERTY (spec item 4.3): every
        /// generated [`ActualSlotState`] is a well-formed actual (Unknown
        /// keeps its failure + generation hint; Absent is an explicit
        /// successful absence; Observed carries BOTH artifact AND
        /// generation).
        #[test]
        fn actual_state_is_well_formed(state in arbitrary_actual()) {
            run_actual_state_case(&state);
        }

        /// THE ACTUAL↔OBSERVATION PAIRING PROPERTY (spec item 4.3): every
        /// distinguishable live-observation case pairs to a CONSISTENT
        /// (actual, observation) — each actual maps to a consistent
        /// observation and vice versa; a desired artifact never rides an
        /// actual; `Unknown` stays `Unknown`; `Absent` only comes from a
        /// successful observation of absence.
        #[test]
        fn actual_pairs_with_a_consistent_observation(case in arbitrary_case()) {
            run_pairing_case(&case);
        }
    }
}

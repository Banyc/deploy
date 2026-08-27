//! Result-table shaping: [`fill_skipped_slots`] makes every SELECTED slot
//! appear in the results; [`observe_actual_servers`] records the
//! post-mutation observation of each member slot.

use crate::deploy::plan::PlannedAssignment;
use crate::identity::SlotId;
use crate::ledger::Observation;
use crate::ledger::ObservationError;
use crate::ledger::ObservedGeneration;
use crate::ledger::SlotAttemptState;
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
                    generation: cur,
                    compensated: false,
                    error: None,
                    observation_error: None,
                },
            );
        }
    }
}

/// Observe each slot's *real* final state, read from the remote generation it
/// currently points at, rather than the desired plan values.
/// Failed/skipped/restored slots therefore report their actual artifact
/// instead of the desired one. The per-slot THREE-STATE OBSERVATION: the
/// actual's `artifact` is itself an [`Observation<ArtifactRef>`] — a FAILED
/// assignment read is `Observation::Unknown(error)`, a distinct value that
/// never looks like a known artifact (there is no sentinel artifact) — and
/// the parallel `actual_observations` map carries the GENERATION half of the
/// observation (a different fact, feeding the never-advanced outcomes below):
/// a FAILED post-mutation status read is `Unknown(error)`, never a `None`
/// that downstream code reads as "unchanged". The wire-shaped `actual_servers`
/// keeps the current on-disk shape — generation only — so the observation's
/// `Unknown` half is recorded into the never-advanced outcomes'
/// `observation_error` field, while the outcome's OWN operation error
/// (`error`) is left untouched.
pub(crate) fn observe_actual_servers(
    assignments: &[PlannedAssignment],
    helpers: &HashMap<SlotId, RemoteHelper>,
) -> (
    BTreeMap<SlotId, SlotAttemptState>,
    BTreeMap<SlotId, Observation<ObservedGeneration>>,
) {
    let mut actual_servers: BTreeMap<SlotId, SlotAttemptState> = BTreeMap::new();
    let mut actual_observations: BTreeMap<SlotId, Observation<ObservedGeneration>> =
        BTreeMap::new();
    for a in assignments {
        let sid = &a.placement_slot;
        let helper = &helpers[sid];
        let status = helper.status();
        let (actual, observation) = match status {
            Ok(s) => match s.current_generation {
                Some(g) => match helper.read_assignment(g.as_str()) {
                    Ok(asn) => (
                        SlotAttemptState {
                            artifact: Observation::Known(asn.artifact.clone()),
                            generation: Some(g.clone()),
                        },
                        Observation::Known(ObservedGeneration {
                            generation: g.clone(),
                        }),
                    ),
                    Err(e) => (
                        SlotAttemptState {
                            artifact: Observation::Unknown(ObservationError {
                                message: format!("assignment read failed: {e}"),
                            }),
                            generation: Some(g.clone()),
                        },
                        Observation::Unknown(ObservationError {
                            message: format!("assignment read failed: {e}"),
                        }),
                    ),
                },
                None => (
                    SlotAttemptState {
                        artifact: Observation::Known(a.artifact.clone()),
                        generation: None,
                    },
                    Observation::KnownAbsent,
                ),
            },
            Err(e) => (
                SlotAttemptState {
                    artifact: Observation::Known(a.artifact.clone()),
                    generation: None,
                },
                Observation::Unknown(ObservationError {
                    message: format!("status read failed: {e}"),
                }),
            ),
        };
        actual_servers.insert(sid.clone(), actual);
        actual_observations.insert(sid.clone(), observation);
    }
    (actual_servers, actual_observations)
}

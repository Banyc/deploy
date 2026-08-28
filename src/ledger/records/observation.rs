//! The TAGGED OBSERVED-ASSIGNMENT records of the deployment ledger (feature
//! area A3 "three-state observation"): [`ObservedAssignment`] (Absent |
//! Known | AssignmentUnknown | Unknown), the generic tri-state
//! [`Observation<T>`] (pre-push assignments, per-slot outcomes), and their
//! payload types ([`ObservedGeneration`], [`ObservationError`]), plus the
//! per-slot / per-target observed records ([`ObservedSlot`],
//! [`ObservedTarget`]). Re-exported by [`crate::remote::observed`].
//!
//! An assignment is EXACTLY ONE tagged variant — never a parallel
//! combination of independent generation/artifact/error fields that a raw
//! wire document could combine into a half-known, self-contradictory state.
//! [`ObservedSlot`] carries the assignment plus the ORTHOGONAL
//! `last_deployment` fact (the deployment that minted the LIVE assignment),
//! which lives ON THE SLOT RECORD, not inside the assignment.
//!
//! The single CONCERN of this module is the observed assignment itself;
//! every other facet consumes it (the shared core's pre-push assignments,
//! the intent's [`crate::ledger::records::PreviousGeneration`], the per-slot
//! outcomes, the rollback payload builder).

use crate::identity::{ArtifactRef, DeploymentId, GenerationId, SlotId, TargetName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// The THREE-STATE OBSERVATION of a slot's remote state: `KnownAbsent` (the
/// slot has no observed state — never deployed), `Known(state)` (a
/// successful read), or `Unknown(error)` (the read failed; the error is
/// preserved). An `Unknown` observation is NOT evidence of no change — the
/// slot may have changed; the failure just means we cannot see it. Every
/// consumer (the pre-push assignment observation, the terminal disposition's
/// per-slot outcomes, the remaining-changes derivation) must carry the
/// `Unknown` through rather than collapsing it into an absent/`None` that
/// downstream code reads as "unchanged".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Observation<T> {
    /// The slot has no observed state (never deployed).
    #[default]
    KnownAbsent,
    /// A successful read of the slot's observed state.
    Known(T),
    /// The read failed: the error is preserved. NOT evidence of no change.
    Unknown(ObservationError),
}

/// The OBSERVED ASSIGNMENT of a placement slot's remote state — EXACTLY ONE
/// tagged variant: there is no raw combination of parallel fields that can
/// represent a half-known assignment (a generation without an artifact, or
/// an artifact without a generation) and no field that fabricates one.
///
/// * `Absent` — the live status read succeeded and showed NO state: the slot
///   has no assignment (never deployed, or rotated away). A live absence
///   REPLACES a stale physical record.
/// * `Known { generation, artifact }` — a successful status + assignment
///   read: the slot is running this generation/artifact.
/// * `AssignmentUnknown { generation, error }` — the status read succeeded
///   (this generation EXISTS) but the ASSIGNMENT read failed: the generation
///   is known, the artifact is NOT — the preserved error records why. This
///   is NOT a fabrication: no artifact is invented.
/// * `Unknown { error }` — the STATUS read failed: the slot's state is
///   entirely unknown. NOT evidence of no change — the slot may have
///   changed; the failure just means we cannot see it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ObservedAssignment {
    /// The live read succeeded showing no state: the slot has no assignment.
    #[default]
    Absent,
    /// A successful status + assignment read: the slot is running this
    /// generation/artifact.
    Known {
        generation: GenerationId,
        artifact: ArtifactRef,
    },
    /// The status read succeeded but the ASSIGNMENT read failed: the
    /// generation is known, the artifact is not — the error is preserved.
    AssignmentUnknown {
        generation: GenerationId,
        error: ObservationError,
    },
    /// The status read failed: the slot's state is unknown; the error is
    /// preserved. NOT evidence of no change.
    Unknown { error: ObservationError },
}

/// The payload of a SUCCESSFUL observation of a slot's GENERATION — the
/// per-slot fact the terminal's outcomes carry (the remaining-changes
/// derivation compares it against pre_push).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedGeneration {
    pub generation: GenerationId,
}

/// The preserved error of a FAILED observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationError {
    pub message: String,
}

/// Observed remote state for one placement slot: the tagged assignment PLUS
/// the ORTHOGONAL minting deployment (`last_deployment` — the deployment
/// that minted the LIVE assignment, `Known` only). The assignment and the
/// minting deployment are independent facts: `last_deployment` rides the
/// SLOT RECORD (never inside the assignment, where a raw wire document could
/// split or recombine it with the assignment fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservedSlot {
    /// The tagged observed assignment (Absent | Known | AssignmentUnknown |
    /// Unknown).
    pub assignment: ObservedAssignment,
    /// The deployment that minted the LIVE assignment (`Known` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_deployment: Option<DeploymentId>,
}

/// Observed remote state for a whole target (`observed.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedTarget {
    pub target: TargetName,
    #[serde(default)]
    pub slots: BTreeMap<SlotId, ObservedSlot>,
}

impl Default for ObservedTarget {
    fn default() -> Self {
        Self {
            target: TargetName::parse("default").expect("default target is a safe segment"),
            slots: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        VariantName, test_deployment_id, test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::store::local::LocalStore;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use serde_json::json;

    /// A VALID artifact (the raw `artifact` field every accepted `Known`
    /// representation must carry; the acceptance rule never fabricates one).
    fn artifact_ref(tag: &str) -> ArtifactRef {
        ArtifactRef {
            release: test_release_id(tag),
            variant: VariantName::new("standard".to_string()),
            tree: test_tree_digest(tag),
        }
    }

    /// A RAW observed record as an arbitrary JSON-ish map: the parallel
    /// presence/absence of the PREVIOUS flat shape's fields — generation,
    /// artifact, error, and the slot-level last_deployment — next to a
    /// `state` tag. The tuple is (state tag, generation present, artifact
    /// present, error present, last_deployment present); 4 tags x 16 field
    /// combos = the 64-case space.
    fn arbitrary_raw_combo() -> impl Strategy<Value = (u8, bool, bool, bool, bool)> {
        (
            0u8..4,
            proptest::bool::ANY,
            proptest::bool::ANY,
            proptest::bool::ANY,
            proptest::bool::ANY,
        )
    }

    /// THE RAW-FIELD-COMBINATION PROPERTY: the new tagged wire accepts ONLY
    /// representations that correspond to EXACTLY ONE [`ObservedAssignment`]
    /// variant — `Known` needs generation+artifact, `AssignmentUnknown`
    /// needs generation+error, `Unknown` needs error, `Absent` needs none.
    /// EVERY other combination is REJECTED (fail closed): a raw document can
    /// never deserialize into a half-known assignment (a generation without
    /// an artifact, an artifact without a generation, an uncertainty without
    /// its preserved error) — serde's internally-tagged enum requires the
    /// variant's OWN fields, and a stray field is dropped rather than
    /// recombined into a partial state.
    fn run_raw_combo_case((tag_idx, gen_present, art, err, ld): (u8, bool, bool, bool, bool)) {
        let tag = match tag_idx {
            0 => "absent",
            1 => "known",
            2 => "assignment_unknown",
            _ => "unknown",
        };
        // The assignment half of the raw document: the flat fields next to
        // the state tag.
        let mut assignment = serde_json::Map::new();
        assignment.insert("state".to_string(), json!(tag));
        if gen_present {
            assignment.insert(
                "generation".to_string(),
                json!(test_generation_id("g").as_str()),
            );
        }
        if art {
            assignment.insert(
                "artifact".to_string(),
                json!({
                    "release": test_release_id("a").as_str(),
                    "variant": "standard",
                    "tree": test_tree_digest("a").as_str(),
                }),
            );
        }
        if err {
            assignment.insert(
                "error".to_string(),
                json!({ "message": "assignment read failed: boom" }),
            );
        }
        // The full slot record: the assignment plus the orthogonal
        // last_deployment at the SLOT level (its presence is always a valid
        // orthogonal fact — it never changes the assignment variant).
        let mut slot = serde_json::Map::new();
        slot.insert(
            "assignment".to_string(),
            serde_json::Value::Object(assignment),
        );
        if ld {
            slot.insert(
                "last_deployment".to_string(),
                json!(test_deployment_id("d").as_str()),
            );
        }
        let doc = serde_json::Value::Object(slot);

        // Accepted iff the tag names a variant whose OWN fields are all
        // present. `Absent` needs none (stray fields are dropped by serde,
        // never recombined into a half-known state).
        let valid = match tag {
            "absent" => true,
            "known" => gen_present && art,
            "assignment_unknown" => gen_present && err,
            _ => err,
        };
        let result: Result<ObservedSlot, _> = serde_json::from_value(doc.clone());
        if valid {
            let slot = result.unwrap_or_else(|e| panic!("valid combo must deserialize {doc}: {e}"));
            let expected = match tag {
                "absent" => ObservedAssignment::Absent,
                "known" => ObservedAssignment::Known {
                    generation: test_generation_id("g"),
                    artifact: artifact_ref("a"),
                },
                "assignment_unknown" => ObservedAssignment::AssignmentUnknown {
                    generation: test_generation_id("g"),
                    error: ObservationError {
                        message: "assignment read failed: boom".to_string(),
                    },
                },
                _ => ObservedAssignment::Unknown {
                    error: ObservationError {
                        message: "assignment read failed: boom".to_string(),
                    },
                },
            };
            assert_eq!(
                slot.assignment, expected,
                "the accepted representation is EXACTLY the tagged variant: {doc}"
            );
            assert_eq!(
                slot.last_deployment.is_some(),
                ld,
                "last_deployment round-trips as the orthogonal slot-level fact: {doc}"
            );
        } else {
            assert!(
                result.is_err(),
                "a half-known assignment must be REJECTED (fail closed), got: {doc}"
            );
        }
    }

    /// A single LIVE observation: one of the four states the observed
    /// projection can record — `Known` (generation + artifact + the LIVE
    /// assignment's minting deployment), `Absent` (a live read showing no
    /// state), `AssignmentUnknown` (generation known, artifact NOT read),
    /// `Unknown` (status read failed).
    fn arbitrary_live_observation() -> impl Strategy<Value = ObservedSlot> {
        prop_oneof![
            Just(ObservedSlot {
                assignment: ObservedAssignment::Absent,
                last_deployment: None,
            }),
            (0..3usize, 0..3usize).prop_map(|(i, j)| ObservedSlot {
                assignment: ObservedAssignment::Known {
                    generation: test_generation_id(&format!("gen-seq-{i}")),
                    artifact: artifact_ref(&format!("art-seq-{i}-{j}")),
                },
                last_deployment: Some(test_deployment_id(&format!("dep-seq-{i}-{j}"))),
            }),
            (0..3usize, 0..3usize).prop_map(|(i, j)| ObservedSlot {
                assignment: ObservedAssignment::AssignmentUnknown {
                    generation: test_generation_id(&format!("gen-seq-{i}")),
                    error: ObservationError {
                        message: format!("assignment read failed: case {j}"),
                    },
                },
                last_deployment: None,
            }),
            (0..3usize).prop_map(|j| ObservedSlot {
                assignment: ObservedAssignment::Unknown {
                    error: ObservationError {
                        message: format!("status read failed: case {j}"),
                    },
                },
                last_deployment: None,
            }),
        ]
    }

    /// THE SEQUENCE PROPERTY: apply a generated sequence of live observations
    /// to a slot's physical observed.json THROUGH THE REAL WRITE PATH (a
    /// [`LocalStore`] fixture + [`LocalStore::write_slot_observed`] /
    /// [`LocalStore::read_slot_observed`] — not a model). After every step
    /// the STORED projection equals the LATEST observation exactly: a live
    /// `Absent` overwrites a stale prior `Known` (the old generation /
    /// artifact / deployment are gone), a later `Known` overwrites an
    /// earlier `Absent`, and `Unknown` / `AssignmentUnknown` record the
    /// uncertainty — the stored record never retains stale state from an
    /// older observation.
    fn run_sequence_case(sequence: Vec<ObservedSlot>) {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let slot = SlotId::new("p1".to_string());
        for obs in &sequence {
            store.write_slot_observed(&slot, obs).unwrap();
            let read_back = store
                .read_slot_observed(&slot)
                .unwrap()
                .expect("a written observed record reads back");
            assert_eq!(
                &read_back, obs,
                "the STORED projection must equal the LATEST live observation (a live Absent \
                 overwrites a stale prior Known; a later Known overwrites an earlier Absent; \
                 Unknown/AssignmentUnknown record the uncertainty)"
            );
        }
        // The final physical record is EXACTLY the last observation, whatever
        // preceded it.
        assert_eq!(
            store.read_slot_observed(&slot).unwrap().as_ref(),
            sequence.last(),
            "the stored projection must equal the latest observation"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE USER'S RAW-FIELD-COMBINATION PROPERTY: every raw combination of
        // the previous flat shape's parallel fields deserializes into the new
        // tagged wire ONLY when it corresponds to exactly one variant —
        // everything else is rejected, never a half-known assignment.
        #[test]
        fn raw_field_combinations_accept_only_one_variant(
            combo in arbitrary_raw_combo(),
        ) {
            run_raw_combo_case(combo);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE USER'S SEQUENCE PROPERTY: a slot's stored observed projection
        // always equals the LATEST live observation (live Absent overwrites a
        // stale prior Known; a later Known overwrites an earlier Absent;
        // Unknown/AssignmentUnknown record the uncertainty) — through the
        // REAL store write path, not a model.
        #[test]
        fn stored_projection_equals_latest_observation(
            sequence in prop::collection::vec(arbitrary_live_observation(), 1..=8),
        ) {
            run_sequence_case(sequence);
        }
    }
}

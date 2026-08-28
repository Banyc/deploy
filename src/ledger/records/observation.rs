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
//! The deployment that minted a live assignment (`last_deployment`) is a
//! fact of the [`ObservedAssignment::Known`] variant ITSELF — there is NO
//! slot-level `last_deployment` field, so a raw wire document can never pair
//! a deployment with an `Absent`/`Unknown` assignment and never strip one
//! from a `Known`.
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
/// * `Known { generation, artifact, last_deployment }` — a successful
///   status + assignment read: the slot is running this generation/artifact,
///   and `last_deployment` is the deployment that MINTED the live
///   assignment — a fact of the KNOWN assignment ITSELF (never a parallel
///   slot-level field a raw document could pair with a different variant).
/// * `AssignmentUnknown { generation, error }` — the status read succeeded
///   (this generation EXISTS) but the ASSIGNMENT read failed: the generation
///   is known, the artifact is NOT — the preserved error records why. This
///   is NOT a fabrication: no artifact is invented.
/// * `Unknown { error }` — the STATUS read failed: the slot's state is
///   entirely unknown. NOT evidence of no change — the slot may have
///   changed; the failure just means we cannot see it.
///
/// ADJACENTLY TAGGED (`state` + `value`): serde's internally-tagged
/// representation ignores `deny_unknown_fields`, so a raw wire document
/// could smuggle stray keys into the record; the adjacently tagged wire
/// rejects any key that is not `state`/`value` AND, together with
/// `deny_unknown_fields`, any key inside the value that is not one of the
/// variant's OWN fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObservedAssignment {
    /// The live read succeeded showing no state: the slot has no assignment.
    #[default]
    Absent,
    /// A successful status + assignment read: the slot is running this
    /// generation/artifact, minted by `last_deployment`.
    Known {
        generation: GenerationId,
        artifact: ArtifactRef,
        /// The deployment that minted the LIVE assignment — a fact of the
        /// KNOWN assignment ONLY; there is no slot-level field a raw
        /// document could pair with another variant.
        last_deployment: DeploymentId,
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

/// The preserved error of a FAILED observation. The wire rejects any key
/// beyond `message`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationError {
    pub message: String,
}

/// Observed remote state for one placement slot: the tagged assignment. The
/// minting deployment of a live assignment (`last_deployment`) is a field of
/// the [`ObservedAssignment::Known`] variant ITSELF — the slot record has NO
/// parallel field, so a raw wire document can never pair a deployment with
/// an `Absent`/`Unknown` assignment (a self-contradictory state) and never
/// strip one from a `Known`. The wire rejects any key beyond `assignment`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ObservedSlot {
    /// The tagged observed assignment (Absent | Known | AssignmentUnknown |
    /// Unknown).
    pub assignment: ObservedAssignment,
}

impl ObservedSlot {
    /// The deployment that minted the LIVE assignment — the
    /// [`ObservedAssignment::Known`] variant's OWN `last_deployment` field,
    /// projected for consumers that only need that fact. `None` for every
    /// other variant: an `Absent`/`AssignmentUnknown`/`Unknown` assignment
    /// carries no minting deployment.
    pub fn last_deployment(&self) -> Option<&DeploymentId> {
        match &self.assignment {
            ObservedAssignment::Known {
                last_deployment, ..
            } => Some(last_deployment),
            _ => None,
        }
    }
}

/// Observed remote state for a whole target (`observed.json`). The wire
/// rejects any key beyond `target`/`slots`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// The EXACT wire representation of a valid `Known` assignment: the
    /// adjacently tagged value carrying generation + artifact +
    /// last_deployment and NOTHING else.
    fn known_value(g: &str, art: &str, dep: &str) -> serde_json::Value {
        json!({
            "generation": test_generation_id(g).as_str(),
            "artifact": {
                "release": test_release_id(art).as_str(),
                "variant": "standard",
                "tree": test_tree_digest(art).as_str(),
            },
            "last_deployment": test_deployment_id(dep).as_str(),
        })
    }

    /// A RAW observed record as an arbitrary JSON-ish map: a `state` tag
    /// plus an OPTIONAL `value` object (adjacently tagged wire) whose OWN
    /// fields — generation, artifact, error, last_deployment — are each
    /// optionally present, plus possibly an extra key inside the value. The
    /// tuple is (tag, value present, generation present, artifact present,
    /// error present, last_deployment present, extra key in value); 4 tags x
    /// 64 field combos = the 256-case space.
    fn arbitrary_raw_combo() -> impl Strategy<Value = (u8, bool, bool, bool, bool, bool, bool)> {
        (
            0u8..4,
            proptest::bool::ANY, // value present
            proptest::bool::ANY, // generation present
            proptest::bool::ANY, // artifact present
            proptest::bool::ANY, // error present
            proptest::bool::ANY, // last_deployment present
            proptest::bool::ANY, // extra key inside the value
        )
    }

    /// THE RAW-FIELD-COMBINATION PROPERTY: the wire accepts ONLY
    /// representations that correspond to EXACTLY ONE [`ObservedAssignment`]
    /// variant — `Known` needs generation + artifact + last_deployment,
    /// `AssignmentUnknown` needs generation + error, `Unknown` needs error,
    /// `Absent` needs NO value at all. EVERY other combination is REJECTED
    /// (fail closed): a raw document can never deserialize into a half-known
    /// assignment (a generation without an artifact, an uncertainty without
    /// its preserved error) and never into a self-contradictory one (a
    /// `Known` carrying a stray `error`, an `Absent` carrying any fields at
    /// all) — the adjacently tagged wire + `deny_unknown_fields` reject any
    /// missing required field, any extra/unknown field, and any field from
    /// another variant.
    fn run_raw_combo_case(
        (tag_idx, value_present, gen_present, art, err, ld, extra): (
            u8,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
        ),
    ) {
        let tag = match tag_idx {
            0 => "absent",
            1 => "known",
            2 => "assignment_unknown",
            _ => "unknown",
        };
        // The raw document: the `state` tag plus the optional `value`
        // object; inside the value every variant's field may or may not be
        // present, plus an extra key.
        let mut doc = serde_json::Map::new();
        doc.insert("state".to_string(), json!(tag));
        if value_present {
            let mut value = serde_json::Map::new();
            if gen_present {
                value.insert(
                    "generation".to_string(),
                    json!(test_generation_id("g").as_str()),
                );
            }
            if art {
                value.insert(
                    "artifact".to_string(),
                    json!({
                        "release": test_release_id("a").as_str(),
                        "variant": "standard",
                        "tree": test_tree_digest("a").as_str(),
                    }),
                );
            }
            if err {
                value.insert(
                    "error".to_string(),
                    json!({ "message": "assignment read failed: boom" }),
                );
            }
            if ld {
                value.insert(
                    "last_deployment".to_string(),
                    json!(test_deployment_id("d").as_str()),
                );
            }
            if extra {
                value.insert("bogus".to_string(), json!(1));
            }
            doc.insert("value".to_string(), serde_json::Value::Object(value));
        }
        // The full slot record wraps the assignment document under the
        // slot's `assignment` key.
        let mut slot = serde_json::Map::new();
        slot.insert("assignment".to_string(), serde_json::Value::Object(doc));
        let doc = serde_json::Value::Object(slot);

        // Accepted iff the value object carries EXACTLY the variant's OWN
        // fields — nothing missing, nothing extra (no other variant's field,
        // no unknown key). `Absent` accepts NO value at all (a unit cannot
        // take an object).
        let valid = match tag {
            "absent" => !value_present,
            "known" => value_present && gen_present && art && ld && !err && !extra,
            "assignment_unknown" => value_present && gen_present && err && !art && !ld && !extra,
            _ => value_present && err && !gen_present && !art && !ld && !extra,
        };
        let result: Result<ObservedSlot, _> = serde_json::from_value(doc.clone());
        if valid {
            let slot = result.unwrap_or_else(|e| panic!("valid combo must deserialize {doc}: {e}"));
            let expected = match tag {
                "absent" => ObservedAssignment::Absent,
                "known" => ObservedAssignment::Known {
                    generation: test_generation_id("g"),
                    artifact: artifact_ref("a"),
                    last_deployment: test_deployment_id("d"),
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
        } else {
            assert!(
                result.is_err(),
                "a representation that is not EXACTLY one variant must be REJECTED (fail \
                 closed), got: {doc}"
            );
        }
    }

    /// THE WIRE REJECTS UNKNOWN FIELDS AT EVERY LEVEL: the adjacently tagged
    /// enum denies any key next to `state`/`value`, the variant payload
    /// denies any key that is not one of its OWN fields, and the
    /// slot/target/error records deny any key beyond their declared fields.
    #[test]
    fn wire_rejects_unknown_fields_at_every_level() {
        let valid_known = json!({
            "state": "known",
            "value": known_value("g", "a", "d"),
        });
        // Positive control: the exact serialized shape round-trips.
        let parsed: ObservedAssignment = serde_json::from_value(valid_known.clone()).unwrap();
        assert_eq!(
            parsed,
            ObservedAssignment::Known {
                generation: test_generation_id("g"),
                artifact: artifact_ref("a"),
                last_deployment: test_deployment_id("d"),
            }
        );
        // An extra field NEXT TO the tag/content pair is rejected.
        let mut top_extra = valid_known.clone();
        if let serde_json::Value::Object(map) = &mut top_extra {
            map.insert("bogus".to_string(), json!(1));
        }
        assert!(
            serde_json::from_value::<ObservedAssignment>(top_extra).is_err(),
            "a key next to state/value must be REJECTED"
        );
        // An extra field INSIDE the variant's value is rejected.
        let mut value_extra = valid_known.clone();
        if let serde_json::Value::Object(map) = &mut value_extra
            && let Some(serde_json::Value::Object(value)) = map.get_mut("value")
        {
            value.insert("bogus".to_string(), json!(1));
        }
        assert!(
            serde_json::from_value::<ObservedAssignment>(value_extra).is_err(),
            "a key inside the variant value must be REJECTED"
        );
        // A slot record with an extra key is rejected.
        let slot_extra = json!({
            "assignment": valid_known,
            "bogus": 1,
        });
        assert!(
            serde_json::from_value::<ObservedSlot>(slot_extra).is_err(),
            "a key next to assignment must be REJECTED"
        );
        // A target record with an extra key is rejected.
        let target_extra = json!({
            "target": "production",
            "slots": {},
            "bogus": 1,
        });
        assert!(
            serde_json::from_value::<ObservedTarget>(target_extra).is_err(),
            "a key next to target/slots must be REJECTED"
        );
        // An error payload with an extra key is rejected.
        let error_extra = json!({ "message": "boom", "bogus": 1 });
        assert!(
            serde_json::from_value::<ObservationError>(error_extra).is_err(),
            "a key inside the error payload must be REJECTED"
        );
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
            }),
            (0..3usize, 0..3usize).prop_map(|(i, j)| ObservedSlot {
                assignment: ObservedAssignment::Known {
                    generation: test_generation_id(&format!("gen-seq-{i}")),
                    artifact: artifact_ref(&format!("art-seq-{i}-{j}")),
                    last_deployment: test_deployment_id(&format!("dep-seq-{i}-{j}")),
                },
            }),
            (0..3usize, 0..3usize).prop_map(|(i, j)| ObservedSlot {
                assignment: ObservedAssignment::AssignmentUnknown {
                    generation: test_generation_id(&format!("gen-seq-{i}")),
                    error: ObservationError {
                        message: format!("assignment read failed: case {j}"),
                    },
                },
            }),
            (0..3usize).prop_map(|j| ObservedSlot {
                assignment: ObservedAssignment::Unknown {
                    error: ObservationError {
                        message: format!("status read failed: case {j}"),
                    },
                },
            }),
        ]
    }

    /// THE BIJECTIVITY PROPERTY for a VALID observation: every generated
    /// [`ObservedAssignment`] (all four variants — `Known` with all three
    /// fields, `Absent`, `AssignmentUnknown`, `Unknown`) and every
    /// generated [`ObservedSlot`] round-trips EXACTLY: `to_value` then
    /// `from_value` reproduces the identical value.
    fn run_bijectivity_case(obs: ObservedSlot) {
        let assignment_json = serde_json::to_value(&obs.assignment).unwrap();
        let assignment_back: ObservedAssignment = serde_json::from_value(assignment_json.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "to_value -> from_value must round-trip the assignment {assignment_json}: {e}"
                )
            });
        assert_eq!(
            assignment_back, obs.assignment,
            "ObservedAssignment must round-trip bijectively (exact value)"
        );

        let slot_json = serde_json::to_value(&obs).unwrap();
        let slot_back: ObservedSlot =
            serde_json::from_value(slot_json.clone()).unwrap_or_else(|e| {
                panic!("to_value -> from_value must round-trip the slot {slot_json}: {e}")
            });
        assert_eq!(
            slot_back, obs,
            "ObservedSlot must round-trip bijectively (exact value)"
        );
    }

    /// THE SEQUENCE PROPERTY: apply a generated sequence of live observations
    /// to a slot's physical observed.json THROUGH THE REAL WRITE PATH (a
    /// [`LocalStore`] fixture + [`LocalStore::write_slot_observed`] /
    /// [`LocalStore::read_slot_observed`] — not a model). After every step
    /// the STORED projection equals the LATEST observation exactly: a live
    /// `Absent` overwrites a stale prior `Known` (the old generation /
    /// artifact / minting deployment are gone), a later `Known` overwrites
    /// an earlier `Absent`, and `Unknown` / `AssignmentUnknown` record the
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
        // tag and fields deserializes into the adjacently tagged wire ONLY
        // when the value carries EXACTLY one variant's own fields — missing
        // required fields, extra/unknown fields, and fields from other
        // variants are all REJECTED (fail closed).
        #[test]
        fn raw_field_combinations_accept_only_one_variant(
            combo in arbitrary_raw_combo(),
        ) {
            run_raw_combo_case(combo);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE USER'S BIJECTIVITY PROPERTY: every VALID observation — all four
        // variants (Known with all three fields, Absent, AssignmentUnknown,
        // Unknown) — serializes and deserializes back to the EXACT original
        // value, at both the assignment and the slot level.
        #[test]
        fn serialization_is_bijective(obs in arbitrary_live_observation()) {
            run_bijectivity_case(obs);
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

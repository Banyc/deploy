//! The TAGGED OBSERVED-ASSIGNMENT records of the deployment ledger (feature
//! area A3 "three-state observation"): [`ObservedAssignment`] (Absent |
//! Known | AssignmentUnknown | Unknown), the generic tri-state
//! [`Observation<T>`] (pre-push assignments, per-slot outcomes), and their
//! payload types ([`ObservedGeneration`], [`ObservationError`]), the STRICT
//! WIRE forms of the observation ([`ObservationWire`], [`ArtifactRefWire`],
//! [`ObservedGenerationWire`] — the adjacently tagged, deny-unknown-fields
//! shapes the PERSISTED ledger wire carries), plus the per-slot / per-target
//! observed records ([`ObservedSlot`], [`ObservedTarget`]). Re-exported by
//! [`crate::remote::observed`].
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
//! the intent's slot table, the per-slot outcomes, the derived resulting
//! snapshot).

use crate::error::{Error, Result};
use crate::identity::{
    ArtifactRef, DeploymentId, GenerationId, ReleaseId, SlotId, TargetName, TreeDigest, VariantName,
};
use crate::remote::helper::GenerationOwner;
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

/// THE STRICT WIRE FORM of an [`Observation`] — the adjacently tagged
/// representation the PERSISTED LEDGER WIRE carries (the pre-push
/// assignments' artifact and the per-slot outcomes' observation), the shape
/// where serde's `deny_unknown_fields` IS honored (the internally-tagged
/// [`Observation<T>`] IGNORES it — a raw wire document could smuggle stray
/// keys, or split/mix a variant's payload, into the permissive domain type).
/// The persisted wire uses THIS type; the permissive in-memory
/// [`Observation<T>`] stays the DOMAIN type. EXACTLY ONE representation per
/// variant deserializes: a missing required field, an extra/unknown field,
/// a wrong tag, a cross-variant field, or a wrong-typed value is REJECTED
/// at deserialization (fail closed) — never read as a half-known state.
///
/// ADJACENTLY TAGGED (`state` + `value`): serde's internally-tagged
/// representation ignores `deny_unknown_fields`, so a raw wire document
/// could smuggle stray keys into the record; the adjacently tagged wire
/// rejects any key that is not `state`/`value` AND, together with
/// `deny_unknown_fields`, any key inside the value that is not one of the
/// variant's OWN payload fields. The wire ↔ domain conversion is a BIJECTION
/// for the representable values ([`From<&Observation<T>>`] /
/// [`TryFrom<ObservationWire<T>>`]): every domain value has EXACTLY ONE wire
/// form and every deserialized wire value maps back to the identical domain
/// value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObservationWire<T> {
    /// The slot has no observed state (never deployed).
    KnownAbsent,
    /// A successful read of the slot's observed state.
    Known(T),
    /// The read failed: the error is preserved. NOT evidence of no change.
    Unknown(ObservationError),
}

/// THE STRICT WIRE PAYLOAD of an [`ObservationWire::Known`] artifact
/// observation — the persisted form of [`ArtifactRef`]: the (release,
/// variant, tree) triple with `deny_unknown_fields`, so the persisted
/// document rejects any field beyond the three. The DOMAIN [`ArtifactRef`]
/// (the in-memory type everywhere else) is unchanged; the wire payload
/// converts to/from it. The conversion is a bijection for the representable
/// values — the fields are VALIDATED identities ([`ReleaseId`],
/// [`VariantName`], [`TreeDigest`], all gated at deserialization), so every
/// deserialized wire payload is representable; the [`TryFrom`] keeps the
/// wire → domain boundary fail-closed by contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRefWire {
    pub release: ReleaseId,
    pub variant: VariantName,
    pub tree: TreeDigest,
}

/// THE STRICT WIRE PAYLOAD of an [`ObservationWire::Known`] generation
/// observation — the persisted form of [`ObservedGeneration`]: the single
/// `generation` field with `deny_unknown_fields`, so the persisted document
/// rejects any extra field. The DOMAIN [`ObservedGeneration`] is unchanged;
/// the wire payload converts to/from it (a bijection for the representable
/// values — the generation is a validated identity).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedGenerationWire {
    pub generation: GenerationId,
}

impl From<&ArtifactRef> for ArtifactRefWire {
    fn from(a: &ArtifactRef) -> Self {
        ArtifactRefWire {
            release: a.release.clone(),
            variant: a.variant.clone(),
            tree: a.tree.clone(),
        }
    }
}

impl TryFrom<ArtifactRefWire> for ArtifactRef {
    type Error = Error;
    fn try_from(w: ArtifactRefWire) -> Result<Self> {
        // Fail closed by contract: the wire payload's fields are validated
        // identities (gated by serde at deserialization), so a deserialized
        // payload is always representable; a hand-constructed payload is
        // still refused if it is not.
        Ok(ArtifactRef {
            release: w.release,
            variant: w.variant,
            tree: w.tree,
        })
    }
}

impl From<&ObservedGeneration> for ObservedGenerationWire {
    fn from(g: &ObservedGeneration) -> Self {
        ObservedGenerationWire {
            generation: g.generation.clone(),
        }
    }
}

impl TryFrom<ObservedGenerationWire> for ObservedGeneration {
    type Error = Error;
    fn try_from(w: ObservedGenerationWire) -> Result<Self> {
        Ok(ObservedGeneration {
            generation: w.generation,
        })
    }
}

impl From<&Observation<ArtifactRef>> for ObservationWire<ArtifactRefWire> {
    fn from(o: &Observation<ArtifactRef>) -> Self {
        match o {
            Observation::KnownAbsent => ObservationWire::KnownAbsent,
            Observation::Known(a) => ObservationWire::Known(ArtifactRefWire::from(a)),
            Observation::Unknown(e) => ObservationWire::Unknown(e.clone()),
        }
    }
}

impl TryFrom<ObservationWire<ArtifactRefWire>> for Observation<ArtifactRef> {
    type Error = Error;
    fn try_from(w: ObservationWire<ArtifactRefWire>) -> Result<Self> {
        Ok(match w {
            ObservationWire::KnownAbsent => Observation::KnownAbsent,
            ObservationWire::Known(a) => Observation::Known(a.try_into()?),
            ObservationWire::Unknown(e) => Observation::Unknown(e),
        })
    }
}

impl From<&Observation<ObservedGeneration>> for ObservationWire<ObservedGenerationWire> {
    fn from(o: &Observation<ObservedGeneration>) -> Self {
        match o {
            Observation::KnownAbsent => ObservationWire::KnownAbsent,
            Observation::Known(g) => ObservationWire::Known(ObservedGenerationWire::from(g)),
            Observation::Unknown(e) => ObservationWire::Unknown(e.clone()),
        }
    }
}

impl TryFrom<ObservationWire<ObservedGenerationWire>> for Observation<ObservedGeneration> {
    type Error = Error;
    fn try_from(w: ObservationWire<ObservedGenerationWire>) -> Result<Self> {
        Ok(match w {
            ObservationWire::KnownAbsent => Observation::KnownAbsent,
            ObservationWire::Known(g) => Observation::Known(g.try_into()?),
            ObservationWire::Unknown(e) => Observation::Unknown(e),
        })
    }
}

/// The OBSERVED ASSIGNMENT of a placement slot's remote state — EXACTLY ONE
/// tagged variant: there is no raw combination of parallel fields that can
/// represent a half-known assignment (a generation without an artifact, or
/// an artifact without a generation) and no field that fabricates one.
///
/// * `Absent` — the live status read succeeded and showed NO state: the slot
///   has no assignment (never deployed, or rotated away). A live absence
///   REPLACES a stale physical record.
/// * `Known { generation, artifact, last_deployment, owner, version }` — a
///   successful status + assignment read: the slot is running this
///   generation/artifact, `last_deployment` is the deployment that MINTED the
///   live assignment — a fact of the KNOWN assignment ITSELF (never a
///   parallel slot-level field a raw document could pair with a different
///   variant) — and `owner`/`version` are the ASSIGNMENT IDENTITY that
///   produced the projection: the VERIFIED owner at observation time plus a
///   read version/timestamp. A consumer comparing the projection against a
///   live assignment treats an owner/generation MISMATCH as STALE
///   ([`ObservedAssignment::is_stale_against`]) — a stale-owner or
///   stale-generation observation is never authoritative.
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
/// variant's OWN fields. The `owner`/`version` fields are OPTIONAL on the
/// wire (`#[serde(default)]`): a legacy observed record written before the
/// identity fields existed still loads (with `None` — and the FAIL-CLOSED
/// staleness rule below treats an unverifiable identity as STALE, never
/// authoritative).
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
        /// THE ASSIGNMENT IDENTITY (owner half): the VERIFIED owner the
        /// status/assignment read checked against at observation time. A read
        /// comparing the projection against the live assignment treats an
        /// owner mismatch as STALE ([`ObservedAssignment::is_stale_against`]).
        /// `None` only on a LEGACY record written before the identity fields
        /// existed — and an unverifiable identity is STALE (fail closed),
        /// never authoritative.
        #[serde(default)]
        owner: Option<GenerationOwner>,
        /// THE ASSIGNMENT IDENTITY (version half): the read version/timestamp
        /// (RFC 3339) that produced this projection — the freshness link to
        /// the remote source. `None` only on a legacy record (treated as
        /// stale, fail closed).
        #[serde(default)]
        version: Option<String>,
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

impl ObservedAssignment {
    /// FRESHNESS CHECK against the LIVE assignment identity (the live
    /// generation — `None` when the live status read shows absence — plus
    /// the VERIFIED owner of the live read): is this projection STALE?
    ///
    /// A projection is STALE exactly when its recorded assignment identity
    /// disagrees with the live one:
    ///
    /// * a `Known` projection whose recorded OWNER differs from the live
    ///   owner, or whose recorded generation differs from the live
    ///   generation, is STALE — a stale-owner or stale-generation
    ///   observation is never authoritative;
    /// * a `Known` projection with NO live generation (the slot is absent
    ///   now) is STALE;
    /// * an `Absent` projection with a LIVE generation is STALE;
    /// * FAIL CLOSED: a `Known` projection WITHOUT a recorded owner identity
    ///   (a legacy record written before the identity fields existed)
    ///   cannot be verified against the live assignment — it is STALE,
    ///   never authoritative; `AssignmentUnknown`/`Unknown` projections
    ///   carry no assignable identity and are never ground truth — STALE.
    ///
    /// A consumer that finds a STALE projection must skip it / refresh it,
    /// never decide on it.
    pub fn is_stale_against(
        &self,
        live_generation: Option<&GenerationId>,
        live_owner: &GenerationOwner,
    ) -> bool {
        match (self, live_generation) {
            (
                ObservedAssignment::Known {
                    generation,
                    owner: Some(recorded_owner),
                    ..
                },
                Some(live_gen),
            ) => recorded_owner != live_owner || generation != live_gen,
            (ObservedAssignment::Known { .. }, None) => {
                // The projection records state but the live assignment is
                // absent: stale.
                true
            }
            (ObservedAssignment::Absent, None) => {
                // Both absent: the projection is current.
                false
            }
            (ObservedAssignment::Absent, Some(_)) => {
                // The projection says absent but the live assignment is
                // present: stale.
                true
            }
            (ObservedAssignment::Known { owner: None, .. }, _) => {
                // A legacy record without a recorded owner identity cannot be
                // verified — fail closed: stale.
                true
            }
            (ObservedAssignment::AssignmentUnknown { .. }, _)
            | (ObservedAssignment::Unknown { .. }, _) => {
                // Uncertainty is never ground truth.
                true
            }
        }
    }
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

    /// FRESHNESS CHECK over the slot's projection: see
    /// [`ObservedAssignment::is_stale_against`].
    pub fn is_stale_against(
        &self,
        live_generation: Option<&GenerationId>,
        live_owner: &GenerationOwner,
    ) -> bool {
        self.assignment
            .is_stale_against(live_generation, live_owner)
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
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use serde_json::json;

    /// A VALID artifact (the raw `artifact` field every accepted `Known`
    /// representation must carry; the acceptance rule never fabricates one).
    fn artifact_ref(tag: &str) -> ArtifactRef {
        ArtifactRef {
            release: test_release_id(tag),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest(tag),
        }
    }

    /// A VALID owner for the tests' fixture assignments: the same owner the
    /// status/read fixtures carry (`application` `test-app`, slot `s1`).
    fn owner() -> GenerationOwner {
        crate::remote::helper::test_owner("test-app", "s1")
    }

    /// The EXACT wire representation of a valid `Known` assignment: the
    /// adjacently tagged value carrying generation + artifact +
    /// last_deployment + the assignment identity (owner + version) and
    /// NOTHING else.
    fn known_value(g: &str, art: &str, dep: &str) -> serde_json::Value {
        json!({
            "generation": test_generation_id(g).as_str(),
            "artifact": {
                "release": test_release_id(art).as_str(),
                "variant": "standard",
                "tree": test_tree_digest(art).as_str()},
            "last_deployment": test_deployment_id(dep).as_str(),
            "owner": {"application": "test-app", "slot": "s1"},
            "version": "2026-01-01T00:00:00Z"})
    }

    /// A RAW observed record as an arbitrary JSON-ish map: a `state` tag
    /// plus an OPTIONAL `value` object (adjacently tagged wire) whose OWN
    /// fields — generation, artifact, error, last_deployment, owner,
    /// version — are each optionally present, plus possibly an extra key
    /// inside the value. The tuple is (tag, value present, generation
    /// present, artifact present, error present, last_deployment present,
    /// owner present, version present, extra key in value); 4 tags x 128
    /// field combos = the 512-case space.
    fn arbitrary_raw_combo()
    -> impl Strategy<Value = (u8, bool, bool, bool, bool, bool, bool, bool, bool)> {
        (
            0u8..4,
            proptest::bool::ANY, // value present
            proptest::bool::ANY, // generation present
            proptest::bool::ANY, // artifact present
            proptest::bool::ANY, // error present
            proptest::bool::ANY, // last_deployment present
            proptest::bool::ANY, // owner present
            proptest::bool::ANY, // version present
            proptest::bool::ANY, // extra key inside the value
        )
    }

    /// THE RAW-FIELD-COMBINATION PROPERTY: the wire accepts ONLY
    /// representations that correspond to EXACTLY ONE [`ObservedAssignment`]
    /// variant — `Known` needs generation + artifact + last_deployment +
    /// the assignment identity (owner + version), `AssignmentUnknown` needs
    /// generation + error, `Unknown` needs error, `Absent` needs NO value at
    /// all. EVERY other combination is REJECTED (fail closed): a raw
    /// document can never deserialize into a half-known assignment (a
    /// generation without an artifact, an uncertainty without its preserved
    /// error) and never into a self-contradictory one (a `Known` carrying a
    /// stray `error`, an `Absent` carrying any fields at all) — the
    /// adjacently tagged wire + `deny_unknown_fields` reject any missing
    /// required field, any extra/unknown field, and any field from another
    /// variant. NOTE: a `Known` without the identity fields (a LEGACY
    /// record) still deserializes (owner/version default to `None` — the
    /// fail-closed staleness rule treats it as STALE, never authoritative).
    fn run_raw_combo_case(
        (tag_idx, value_present, gen_present, art, err, ld, owner_present, version_present, extra): (
            u8,
            bool,
            bool,
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
                        "tree": test_tree_digest("a").as_str()}),
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
            if owner_present {
                value.insert(
                    "owner".to_string(),
                    json!({ "application": "test-app", "slot": "s1" }),
                );
            }
            if version_present {
                value.insert("version".to_string(), json!("2026-01-01T00:00:00Z"));
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
        // take an object). A `Known` may omit the identity fields (a legacy
        // record loads with `None`); a `Known` that carries the identity
        // fields must carry BOTH.
        let valid = match tag {
            "absent" => !value_present,
            "known" => {
                value_present
                    && gen_present
                    && art
                    && ld
                    && !err
                    && !extra
                    && (owner_present == version_present)
            }
            "assignment_unknown" => {
                value_present
                    && gen_present
                    && err
                    && !art
                    && !ld
                    && !extra
                    && !owner_present
                    && !version_present
            }
            _ => {
                value_present
                    && err
                    && !gen_present
                    && !art
                    && !ld
                    && !extra
                    && !owner_present
                    && !version_present
            }
        };
        let result = serde_json::from_value::<ObservedSlot>(doc.clone());
        if valid {
            let slot = result.unwrap_or_else(|e| panic!("valid combo must deserialize {doc}: {e}"));
            let expected = match tag {
                "absent" => ObservedAssignment::Absent,
                "known" => ObservedAssignment::Known {
                    generation: test_generation_id("g"),
                    artifact: artifact_ref("a"),
                    last_deployment: test_deployment_id("d"),
                    owner: owner_present.then(owner),
                    version: version_present.then(|| "2026-01-01T00:00:00Z".to_string()),
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
            "value": known_value("g", "a", "d")});
        // Positive control: the exact serialized shape round-trips (including
        // the assignment identity — owner + version).
        let parsed: ObservedAssignment = serde_json::from_value(valid_known.clone()).unwrap();
        assert_eq!(
            parsed,
            ObservedAssignment::Known {
                generation: test_generation_id("g"),
                artifact: artifact_ref("a"),
                last_deployment: test_deployment_id("d"),
                owner: Some(owner()),
                version: Some("2026-01-01T00:00:00Z".to_string()),
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
            "bogus": 1});
        assert!(
            serde_json::from_value::<ObservedSlot>(slot_extra).is_err(),
            "a key next to assignment must be REJECTED"
        );
        // A target record with an extra key is rejected.
        let target_extra = json!({
            "target": "production",
            "slots": {},
            "bogus": 1});
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
    /// assignment's minting deployment + the assignment identity: owner +
    /// version), `Absent` (a live read showing no state), `AssignmentUnknown`
    /// (generation known, artifact NOT read), `Unknown` (status read failed).
    fn arbitrary_live_observation() -> impl Strategy<Value = ObservedSlot> {
        prop_oneof![
            Just(ObservedSlot {
                assignment: ObservedAssignment::Absent
            }),
            (0..3usize, 0..3usize).prop_map(|(i, j)| ObservedSlot {
                assignment: ObservedAssignment::Known {
                    generation: test_generation_id(&format!("gen-seq-{i}")),
                    artifact: artifact_ref(&format!("art-seq-{i}-{j}")),
                    last_deployment: test_deployment_id(&format!("dep-seq-{i}-{j}")),
                    owner: Some(owner()),
                    version: Some(format!("2026-01-0{}T00:00:00Z", (i + j) % 9 + 1))
                }
            }),
            (0..3usize, 0..3usize).prop_map(|(i, j)| ObservedSlot {
                assignment: ObservedAssignment::AssignmentUnknown {
                    generation: test_generation_id(&format!("gen-seq-{i}")),
                    error: ObservationError {
                        message: format!("assignment read failed: case {j}")
                    }
                }
            }),
            (0..3usize).prop_map(|j| ObservedSlot {
                assignment: ObservedAssignment::Unknown {
                    error: ObservationError {
                        message: format!("status read failed: case {j}")
                    }
                }
            }),
        ]
    }

    /// THE BIJECTIVITY PROPERTY for a VALID observation: every generated
    /// [`ObservedAssignment`] (all four variants — `Known` with all its
    /// fields including the assignment identity, `Absent`,
    /// `AssignmentUnknown`, `Unknown`) and every generated [`ObservedSlot`]
    /// round-trips EXACTLY: `to_value` then `from_value` reproduces the
    /// identical value.
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
        let slot = SlotId::parse("p1").unwrap();
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

    // ---- THE FRESHNESS/IDENTITY PROPERTY (the review's acceptance) --------

    /// An arbitrary OBSERVED projection: all four [`ObservedAssignment`]
    /// variants, with `Known` carrying the assignment identity (owner +
    /// version) or NONE (a legacy record written before the identity fields
    /// existed — the fail-closed staleness case).
    fn arbitrary_assignment() -> impl Strategy<Value = ObservedAssignment> {
        prop_oneof![
            Just(ObservedAssignment::Absent),
            (0..3usize, 0..3usize, proptest::bool::ANY).prop_map(|(i, j, with_identity)| {
                ObservedAssignment::Known {
                    generation: test_generation_id(&format!("gen-p-{i}")),
                    artifact: artifact_ref(&format!("art-p-{i}-{j}")),
                    last_deployment: test_deployment_id(&format!("dep-p-{i}-{j}")),
                    owner: with_identity.then(owner),
                    version: with_identity.then(|| "2026-01-01T00:00:00Z".to_string()),
                }
            }),
            (0..3usize).prop_map(|j| ObservedAssignment::AssignmentUnknown {
                generation: test_generation_id(&format!("gen-p-{j}")),
                error: ObservationError {
                    message: format!("assignment read failed: case {j}"),
                },
            }),
            (0..3usize).prop_map(|j| ObservedAssignment::Unknown {
                error: ObservationError {
                    message: format!("status read failed: case {j}"),
                },
            }),
        ]
    }

    /// An arbitrary LIVE assignment identity: the live generation (absent or
    /// one of the same `gen-p-*` ids the projections use, so equal and
    /// mismatched generations both occur) and the live VERIFIED owner (the
    /// same owner, a different application, or a different slot — so
    /// equal and mismatched owners both occur).
    fn arbitrary_live_identity() -> impl Strategy<Value = (Option<GenerationId>, GenerationOwner)> {
        (proptest::option::of(0..3usize), 0u8..3).prop_map(|(g, o)| {
            let live_gen = g.map(|i| test_generation_id(&format!("gen-p-{i}")));
            let owner = match o {
                0 => crate::remote::helper::test_owner("test-app", "s1"),
                1 => crate::remote::helper::test_owner("other-app", "s1"),
                _ => crate::remote::helper::test_owner("test-app", "s2"),
            };
            (live_gen, owner)
        })
    }

    /// THE STALENESS PROPERTY (the review's acceptance): generate an
    /// observed projection + a live assignment identity and assert the
    /// projection is STALE EXACTLY when its recorded assignment identity
    /// disagrees with the live one — a mismatched OWNER or GENERATION makes
    /// the projection STALE (the consumer refuses to treat it as current),
    /// never a silently-accepted stale view; a legacy projection without a
    /// recorded owner is STALE (fail closed — unverifiable, never
    /// authoritative); `Absent` is current only against a live absence.
    fn run_staleness_case(obs: ObservedAssignment, live: (Option<GenerationId>, GenerationOwner)) {
        let (live_gen, live_owner) = live;
        let stale = obs.is_stale_against(live_gen.as_ref(), &live_owner);
        let expected_stale = match &obs {
            ObservedAssignment::Known {
                generation,
                owner: Some(recorded_owner),
                ..
            } => live_gen.as_ref() != Some(generation) || recorded_owner != &live_owner,
            // A legacy Known without a recorded owner cannot be verified.
            ObservedAssignment::Known { owner: None, .. } => true,
            ObservedAssignment::Absent => live_gen.is_some(),
            ObservedAssignment::AssignmentUnknown { .. } | ObservedAssignment::Unknown { .. } => {
                true
            }
        };
        assert_eq!(
            stale, expected_stale,
            "a projection is STALE exactly when its recorded assignment identity (owner + \
             generation) disagrees with the live identity, or cannot be verified — a stale-owner \
             or stale-generation observation is never authoritative"
        );
        // The no-silent-stale-view corollary: whenever the projection is
        // STALE, its recorded (generation, owner) disagree with the live
        // identity — a consumer that compares them REFUSES the projection as
        // current (it never accepts a stale view silently).
        if stale {
            let silent_accept = match &obs {
                ObservedAssignment::Known {
                    generation,
                    owner: Some(recorded_owner),
                    ..
                } => live_gen.as_ref() == Some(generation) && recorded_owner == &live_owner,
                _ => false,
            };
            assert!(
                !silent_accept,
                "a stale projection must never carry an identity identical to the live one"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE REVIEW'S STALENESS PROPERTY: every generated projection + live
        // identity pair classifies STALE exactly on identity disagreement.
        #[test]
        fn projection_is_stale_exactly_on_identity_mismatch(
            obs in arbitrary_assignment(),
            live in arbitrary_live_identity(),
        ) {
            run_staleness_case(obs, live);
        }
    }

    // ---- THE STRICT WIRE ([`ObservationWire`]) PROP TESTS ----------------

    /// A RAW `ObservationWire<ObservedGenerationWire>` document as an
    /// arbitrary JSON-ish map: a `state` tag plus an OPTIONAL `value` object
    /// (adjacently tagged wire) whose OWN payload fields — generation,
    /// error — are each optionally present, plus an extra key next to
    /// `state`/`value` and an extra key inside the value. The tuple is (tag,
    /// value present, generation present, error present, extra key next to
    /// state/value, extra key in value); 3 tags x 32 field combos = the
    /// 96-case space.
    fn arbitrary_gen_wire_combo() -> impl Strategy<Value = (u8, bool, bool, bool, bool, bool)> {
        (
            0u8..3,
            proptest::bool::ANY, // value present
            proptest::bool::ANY, // generation present
            proptest::bool::ANY, // error present
            proptest::bool::ANY, // extra key next to state/value
            proptest::bool::ANY, // extra key inside the value
        )
    }

    /// A RAW `ObservationWire<ArtifactRefWire>` document: the `state` tag
    /// plus an OPTIONAL `value` object whose OWN payload fields — release,
    /// variant, tree, error — are each optionally present, plus an extra key
    /// next to `state`/`value` and an extra key inside the value. The tuple
    /// is (tag, value present, release present, variant present, tree
    /// present, error present, extra key next to state/value, extra key in
    /// value); 3 tags x 128 field combos = the 384-case space.
    fn arbitrary_artifact_wire_combo()
    -> impl Strategy<Value = (u8, bool, bool, bool, bool, bool, bool, bool)> {
        (
            0u8..3,
            proptest::bool::ANY, // value present
            proptest::bool::ANY, // release present
            proptest::bool::ANY, // variant present
            proptest::bool::ANY, // tree present
            proptest::bool::ANY, // error present
            proptest::bool::ANY, // extra key next to state/value
            proptest::bool::ANY, // extra key inside the value
        )
    }

    /// THE USER'S ONE-EXACT-REPRESENTATION PROPERTY (generation payload):
    /// the strict adjacently tagged wire accepts ONLY the representation
    /// that corresponds to EXACTLY ONE [`ObservationWire`] variant —
    /// `known_absent` is a bare unit (no value, no extra key), `known`
    /// carries the value object with the generation field and NOTHING else,
    /// `unknown` carries the value object with the error field and NOTHING
    /// else. EVERY other combination is REJECTED (fail closed): a missing
    /// required field, an extra/unknown field, a wrong tag, a cross-variant
    /// field, or a wrong-typed value can never deserialize into a half-known
    /// or self-contradictory observation.
    fn run_gen_wire_combo_case(
        (tag_idx, value_present, gen_present, err, top_extra, value_extra): (
            u8,
            bool,
            bool,
            bool,
            bool,
            bool,
        ),
    ) {
        let tag = match tag_idx {
            0 => "known_absent",
            1 => "known",
            _ => "unknown",
        };
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
            if err {
                value.insert("message".to_string(), json!("status read failed: boom"));
            }
            if value_extra {
                value.insert("bogus".to_string(), json!(1));
            }
            doc.insert("value".to_string(), serde_json::Value::Object(value));
        }
        if top_extra {
            doc.insert("bogus".to_string(), json!(1));
        }
        let doc = serde_json::Value::Object(doc);

        let valid = match tag {
            "known_absent" => !value_present && !top_extra,
            "known" => value_present && gen_present && !err && !value_extra && !top_extra,
            _ => value_present && err && !gen_present && !value_extra && !top_extra,
        };
        let result = serde_json::from_value::<ObservationWire<ObservedGenerationWire>>(doc.clone());
        if valid {
            let wire = result.unwrap_or_else(|e| panic!("valid combo must deserialize {doc}: {e}"));
            let expected = match tag {
                "known_absent" => ObservationWire::KnownAbsent,
                "known" => ObservationWire::Known(ObservedGenerationWire {
                    generation: test_generation_id("g"),
                }),
                _ => ObservationWire::Unknown(ObservationError {
                    message: "status read failed: boom".to_string(),
                }),
            };
            assert_eq!(
                wire, expected,
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

    /// THE USER'S ONE-EXACT-REPRESENTATION PROPERTY (artifact payload):
    /// like [`run_gen_wire_combo_case`] with the three-field strict payload
    /// [`ArtifactRefWire`] — `known` requires release + variant + tree and
    /// NOTHING else, `unknown` requires the error and NOTHING else,
    /// `known_absent` is a bare unit. Every missing/extra/mixed field is
    /// REJECTED.
    fn run_artifact_wire_combo_case(
        (tag_idx, value_present, release, variant, tree, err, top_extra, value_extra): (
            u8,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
        ),
    ) {
        let tag = match tag_idx {
            0 => "known_absent",
            1 => "known",
            _ => "unknown",
        };
        let mut doc = serde_json::Map::new();
        doc.insert("state".to_string(), json!(tag));
        if value_present {
            let mut value = serde_json::Map::new();
            if release {
                value.insert("release".to_string(), json!(test_release_id("r").as_str()));
            }
            if variant {
                value.insert("variant".to_string(), json!("standard"));
            }
            if tree {
                value.insert("tree".to_string(), json!(test_tree_digest("t").as_str()));
            }
            if err {
                value.insert("message".to_string(), json!("status read failed: boom"));
            }
            if value_extra {
                value.insert("bogus".to_string(), json!(1));
            }
            doc.insert("value".to_string(), serde_json::Value::Object(value));
        }
        if top_extra {
            doc.insert("bogus".to_string(), json!(1));
        }
        let doc = serde_json::Value::Object(doc);

        let valid = match tag {
            "known_absent" => !value_present && !top_extra,
            "known" => {
                value_present && release && variant && tree && !err && !value_extra && !top_extra
            }
            _ => {
                value_present && err && !release && !variant && !tree && !value_extra && !top_extra
            }
        };
        let result = serde_json::from_value::<ObservationWire<ArtifactRefWire>>(doc.clone());
        if valid {
            let wire = result.unwrap_or_else(|e| panic!("valid combo must deserialize {doc}: {e}"));
            let expected = match tag {
                "known_absent" => ObservationWire::KnownAbsent,
                "known" => ObservationWire::Known(ArtifactRefWire {
                    release: test_release_id("r"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("t"),
                }),
                _ => ObservationWire::Unknown(ObservationError {
                    message: "status read failed: boom".to_string(),
                }),
            };
            assert_eq!(
                wire, expected,
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

    /// THE WIRE REJECTS UNKNOWN TAGS, WRONG-TYPED VALUES, AND MISSING
    /// VALUES AT EVERY LEVEL: an unknown `state` tag, a value that is not an
    /// object, a payload field with the wrong type, a unit variant carrying
    /// a value, and a `known`/`unknown` variant missing its value are all
    /// REJECTED — only the EXACT representation per variant deserializes.
    #[test]
    fn observation_wire_rejects_unknown_tags_and_wrong_typed_values() {
        // An unknown tag is rejected.
        assert!(
            serde_json::from_value::<ObservationWire<ObservedGenerationWire>>(json!({
                "state": "bogus",
                "value": { "generation": test_generation_id("g").as_str() }}))
            .is_err(),
            "an unknown tag must be REJECTED"
        );
        // A wrong-typed value (not an object) is rejected.
        assert!(
            serde_json::from_value::<ObservationWire<ObservedGenerationWire>>(json!({
                "state": "known",
                "value": 42}))
            .is_err(),
            "a wrong-typed value must be REJECTED"
        );
        // A wrong-typed payload field is rejected.
        assert!(
            serde_json::from_value::<ObservationWire<ObservedGenerationWire>>(json!({
                "state": "known",
                "value": { "generation": 42 }}))
            .is_err(),
            "a wrong-typed payload field must be REJECTED"
        );
        // A unit variant carrying a value is rejected.
        assert!(
            serde_json::from_value::<ObservationWire<ObservedGenerationWire>>(json!({
                "state": "known_absent",
                "value": { "generation": test_generation_id("g").as_str() }}))
            .is_err(),
            "a unit variant carrying a value must be REJECTED"
        );
        // A `known` variant missing its value is rejected.
        assert!(
            serde_json::from_value::<ObservationWire<ObservedGenerationWire>>(json!({
                "state": "known"}))
            .is_err(),
            "a known variant missing its value must be REJECTED"
        );
        // The strict artifact payload rejects an extra field beyond the
        // (release, variant, tree) triple.
        assert!(
            serde_json::from_value::<ObservationWire<ArtifactRefWire>>(json!({
                "state": "known",
                "value": {
                    "release": test_release_id("r").as_str(),
                    "variant": "standard",
                    "tree": test_tree_digest("t").as_str(),
                    "bogus": 1}}))
            .is_err(),
            "a strict artifact payload with an extra field must be REJECTED"
        );
        // A cross-variant field (error on a known artifact) is rejected.
        assert!(
            serde_json::from_value::<ObservationWire<ArtifactRefWire>>(json!({
                "state": "known",
                "value": {
                    "release": test_release_id("r").as_str(),
                    "variant": "standard",
                    "tree": test_tree_digest("t").as_str(),
                    "error": { "message": "boom" }}}))
            .is_err(),
            "a cross-variant field must be REJECTED"
        );
    }

    /// A VALID DOMAIN artifact observation: all three [`Observation`]
    /// variants — `Known` with a valid artifact, `KnownAbsent`, `Unknown`
    /// with a preserved error.
    fn arbitrary_domain_artifact_observation() -> impl Strategy<Value = Observation<ArtifactRef>> {
        prop_oneof![
            Just(Observation::KnownAbsent),
            (0..3usize, 0..3usize).prop_map(|(i, j)| Observation::Known(ArtifactRef {
                release: test_release_id(&format!("rel-seq-{i}")),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest(&format!("tree-seq-{i}-{j}"))
            })),
            (0..3usize).prop_map(|j| Observation::Unknown(ObservationError {
                message: format!("status read failed: case {j}")
            })),
        ]
    }

    /// A VALID DOMAIN generation observation: all three [`Observation`]
    /// variants — `Known` with a valid generation, `KnownAbsent`, `Unknown`
    /// with a preserved error.
    fn arbitrary_domain_generation_observation()
    -> impl Strategy<Value = Observation<ObservedGeneration>> {
        prop_oneof![
            Just(Observation::KnownAbsent),
            (0..3usize).prop_map(|i| Observation::Known(ObservedGeneration {
                generation: test_generation_id(&format!("gen-seq-{i}"))
            })),
            (0..3usize).prop_map(|j| Observation::Unknown(ObservationError {
                message: format!("status read failed: case {j}")
            })),
        ]
    }

    /// THE USER'S WIRE↔DOMAIN BIJECTION PROPERTY (artifact): every
    /// generated DOMAIN [`Observation<ArtifactRef>`] maps to EXACTLY ONE
    /// strict wire form ([`ObservationWire<ArtifactRefWire>`]) whose JSON
    /// round-trips exactly through serde_json (the strict representation —
    /// nothing added, nothing dropped), and which converts BACK to the
    /// EXACT original domain value.
    fn run_artifact_bijection_case(obs: Observation<ArtifactRef>) {
        let wire = ObservationWire::from(&obs);
        let json = serde_json::to_value(&wire).unwrap();
        let wire_back: ObservationWire<ArtifactRefWire> = serde_json::from_value(json.clone())
            .unwrap_or_else(|e| panic!("the strict wire JSON must deserialize {json}: {e}"));
        assert_eq!(
            wire_back, wire,
            "the strict wire JSON must round-trip exactly: {json}"
        );
        let domain: Observation<ArtifactRef> = wire_back
            .try_into()
            .unwrap_or_else(|e| panic!("the strict wire must convert back to the domain: {e}"));
        assert_eq!(
            domain, obs,
            "wire -> domain must reproduce the EXACT domain value"
        );
    }

    /// THE USER'S WIRE↔DOMAIN BIJECTION PROPERTY (generation): every
    /// generated DOMAIN [`Observation<ObservedGeneration>`] maps to EXACTLY
    /// ONE strict wire form ([`ObservationWire<ObservedGenerationWire>`])
    /// whose JSON round-trips exactly through serde_json, and which
    /// converts BACK to the EXACT original domain value.
    fn run_generation_bijection_case(obs: Observation<ObservedGeneration>) {
        let wire = ObservationWire::from(&obs);
        let json = serde_json::to_value(&wire).unwrap();
        let wire_back: ObservationWire<ObservedGenerationWire> =
            serde_json::from_value(json.clone())
                .unwrap_or_else(|e| panic!("the strict wire JSON must deserialize {json}: {e}"));
        assert_eq!(
            wire_back, wire,
            "the strict wire JSON must round-trip exactly: {json}"
        );
        let domain: Observation<ObservedGeneration> = wire_back
            .try_into()
            .unwrap_or_else(|e| panic!("the strict wire must convert back to the domain: {e}"));
        assert_eq!(
            domain, obs,
            "wire -> domain must reproduce the EXACT domain value"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE USER'S ONE-EXACT-REPRESENTATION PROPERTY (generation payload):
        // every tag/value/field-presence/extra-field combination
        // deserializes into the strict adjacently-tagged wire ONLY when it
        // is EXACTLY one variant's representation.
        #[test]
        fn observation_wire_gen_combinations_accept_only_one_variant(
            combo in arbitrary_gen_wire_combo(),
        ) {
            run_gen_wire_combo_case(combo);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE USER'S ONE-EXACT-REPRESENTATION PROPERTY (artifact payload):
        // every tag/value/field-presence/extra-field combination with the
        // strict three-field payload struct deserializes ONLY when it is
        // EXACTLY one variant's representation.
        #[test]
        fn observation_wire_artifact_combinations_accept_only_one_variant(
            combo in arbitrary_artifact_wire_combo(),
        ) {
            run_artifact_wire_combo_case(combo);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE USER'S WIRE↔DOMAIN BIJECTION PROPERTY (artifact): every valid
        // DOMAIN observation maps to exactly one strict wire form that
        // round-trips exactly and converts back to the EXACT domain value.
        #[test]
        fn observation_wire_artifact_bijection(obs in arbitrary_domain_artifact_observation()) {
            run_artifact_bijection_case(obs);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        // THE USER'S WIRE↔DOMAIN BIJECTION PROPERTY (generation): every
        // valid DOMAIN observation maps to exactly one strict wire form that
        // round-trips exactly and converts back to the EXACT domain value.
        #[test]
        fn observation_wire_generation_bijection(
            obs in arbitrary_domain_generation_observation(),
        ) {
            run_generation_bijection_case(obs);
        }
    }
}

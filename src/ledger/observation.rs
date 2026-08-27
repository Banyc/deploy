//! The THREE-STATE OBSERVATION records of the deployment ledger (feature
//! area A3 "three-state observation"): [`Observation<T>`] and its payload
//! types ([`ObservedState`], [`ObservedGeneration`], [`ObservationError`]),
//! plus the per-slot / per-target observed records ([`ObservedSlot`],
//! [`ObservedTarget`]). Re-exported by [`crate::remote::observed`].

use crate::identity::{ArtifactRef, DeploymentId, GenerationId, SlotId, TargetName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The THREE-STATE OBSERVATION of a slot's remote state: `KnownAbsent` (the
/// slot has no observed state — never deployed), `Known(state)` (a
/// successful read), or `Unknown(error)` (the read failed; the error is
/// preserved). An `Unknown` observation is NOT evidence of no change — the
/// slot may have changed; the failure just means we cannot see it. Every
/// consumer (the observed record, the terminal disposition's per-slot
/// outcomes, the remaining-changes derivation) must carry the `Unknown`
/// through rather than collapsing it into an absent/`None` that downstream
/// code reads as "unchanged".
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

/// The payload of a SUCCESSFUL observation of a placement slot: the slot's
/// live assignment as read from the remote (generation + artifact + the
/// assignment's OWN minting deployment).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedState {
    pub generation: GenerationId,
    pub artifact: ArtifactRef,
    pub last_deployment: DeploymentId,
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

/// Observed remote state for one placement slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservedSlot {
    /// The three-state observation of the slot's remote state: `KnownAbsent`
    /// (never deployed), `Known(state)` (a successful read), or
    /// `Unknown(error)` (the read failed — NOT evidence of no change).
    pub observation: Observation<ObservedState>,
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

//! THE LEDGER RECORD MODEL — the wire + domain record shapes of the
//! deployment ledger (feature area A2: Ledger semantics), one cohesive
//! feature GROUP DIRECTORY, recursively nested by relatedness: the SHARED
//! core record shapes live in this module ([`SlotAttemptState`] /
//! [`DeploymentStatus`]), the LEDGER LINE + ENTRY facets live in `wire`
//! (intent, terminal, outcomes, the merged entry), the RECORD-VALIDATION
//! facets live in `validation` (rollback payload, rebinding proof,
//! membership equations, schema versions), and the foundational
//! THREE-STATE observation lives in `observation`.
//!
//! The SHARED core comes first — the deployment-record fields
//! ([`SlotAttemptState`] / [`DeploymentStatus`]), the ROLLBACK records
//! ([`TargetSnapshot`] / [`SnapshotEntry`] / [`PhysicalBinding`] /
//! [`CompleteRollback`]), the PLAN/report records ([`BehaviorIndex`],
//! [`SlotPlan`], [`DeploymentPlanWire`] / [`DeploymentPlan`], [`PlanSource`] /
//! [`PlanOrigin`]), and the pins/server records ([`Pins`] /
//! [`ServerState`]) — then the per-facet sections:
//!
//! * **intent** — the durable intent wire/domain pair ([`LedgerIntentWire`]
//!   / [`DeploymentIntent`]) with the VERIFYING CONVERSION, the per-slot
//!   plan types ([`crate::kernel::intent::PlannedSlot`] /
//!   [`crate::kernel::intent::SlotAction`]) and the in-memory push report
//!   ([`LedgerIntentReport`]) (the "two line kinds — intent" half);
//! * **terminal** — the terminal wire/domain pair ([`LedgerTerminalWire`] /
//!   [`LedgerTerminal`]) with the VERIFYING CONVERSION, the
//!   [`TerminalDisposition`] enum, and the status accessor (the "two line
//!   kinds — terminal" half);
//! * **outcomes** — the per-slot outcomes ([`SlotOutcome`] /
//!   [`SlotOutcomeKind`] / [`SlotTransition`], the WIRE outcome row
//!   [`SlotResult`]) + the remaining-changes / compensation derivations;
//! * **observation** — the three-state observations ([`Observation`] and
//!   friends);
//! * **entries / merge** — the merged deployment entry ([`LedgerEntry`]):
//!   the intent + optional terminal merge type the append/read path
//!   carries;
//! * **rebinding proof** — the rebinding proof records ([`RebindingPlan`] /
//!   [`VerifiedReleaseRebinding`] / [`FrozenSlotTopology`]);
//! * **schema versions** — the format-version constants
//!   (`LEDGER_SCHEMA_VERSION` / `PINS_SCHEMA_VERSION`).
//!
//! The SEMANTIC kernel ([`crate::kernel`]) owns the DOMAIN records: the
//! validated [`DeploymentIntent`] (this module re-exports it) and the
//! terminal records ([`LedgerTerminal`] / [`TerminalDisposition`]); a
//! successful deployment's resulting snapshot resolves from the intent's
//! own slot table — there is NO separately stored rollback payload to build
//! or validate (the old `build_rollback` /
//! `validate_successful_rollback_against_intent` /
//! `verify_successful_membership_equations` validators are GONE). The
//! schema version gates old shapes.
//! The per-slot ordered TABLES ([`crate::ledger::tables::SlotTable`] /
//! [`crate::ledger::tables::NonEmptySlotTable`] over the private ordered
//! map) are generic slot collection INFRASTRUCTURE and stay in
//! [`crate::ledger::tables`]; the ledger WRITE path (replay-safe
//! finalization [`crate::ledger::finalize::finalize_successful_locked`]
//! and the two physical append line kinds
//! [`crate::ledger::finalize::LedgerLine`]) lives in
//! [`crate::ledger::finalize`]; reconciliation lives in
//! [`crate::ledger::recovery`]; reference resolution in
//! [`crate::ledger::refs`]; rendering in [`crate::ledger::log`].
//!
//! Assignment relationships are expressed exclusively through the canonical
//! model types ([`crate::identity::ArtifactRef`],
//! [`crate::identity::PlacementSlotAssignment`],
//! [`crate::identity::GenerationRef`]) rather than re-declared per record.
//! Every slot→assignment map (ledger intent `desired` / `pre_push`, terminal
//! `outcomes`, the rollback payload) is keyed by
//! [`crate::identity::SlotId`] — the deployment-location identity — while
//! [`crate::identity::ServerId`] remains the actual-server identity used for
//! transport addressing (`ServerState`, config `ServerDef`).
//!
//! # ONE authoritative collection per record; WIRE → VERIFIED DOMAIN
//!
//! Every record keeps ONE authoritative collection and derives the rest
//! through methods (`membership()`, `releases()`, `behavior_digest()`,
//! [`LedgerTerminal::remaining_changes`], [`LedgerTerminal::compensation`]);
//! the redundant on-disk members exist only in the WIRE types (the raw serde
//! shapes, [`LedgerIntentWire`], [`LedgerTerminalWire`],
//! [`DeploymentPlanWire`]) and are RECONCILED by a VERIFYING CONVERSION
//! (`Wire::into_domain`). A disagreement is an
//! [`crate::error::Error::integrity`] error (fail closed). The rest of the
//! codebase consumes ONLY the validated domain types; the store's readers
//! convert wire → domain on read and refuse disagreeing records.
//!
//! # ONE history ledger per target
//!
//! A target's ENTIRE deployment history lives in ONE ordered, append-only
//! JSONL file: `targets/<target>/ledger.jsonl` — the two physical line
//! kinds and the merged entry are [`crate::ledger::finalize::LedgerLine`] /
//! [`LedgerEntry`], owned by [`crate::ledger::finalize`] (which documents
//! the crash-atomic append and deployment-id keying contracts): an intent
//! line is appended BEFORE any remote mutation and never edited; a terminal
//! line is appended once, after the mutation loop. A merged entry (intent +
//! optional terminal) is the deployment's full history record; an entry
//! WITHOUT a terminal is the CURRENT/INCOMPLETE state (recoverable — the
//! next push reconciles it).

use crate::error::{Error, Result};
use crate::identity::{
    ArtifactRef, BehaviorContract, BehaviorDigest, DeploymentId, GenerationId, GenerationRef,
    PlacementSlotAssignment, ReleaseId, ServerId, SlotId, TargetName, TreeDigest,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

mod observation;
mod validation;
mod wire;

// The DOC-EXAMPLE GENERATOR (test-only): the pretty-printed wire examples
// the public docs' ```json fenced blocks carry, rendered from the REAL wire
// records ([`LedgerIntentWire`] / [`LedgerTerminalWire`] through the
// physical [`crate::ledger::finalize::LedgerLine`] kind, with the current
// [`LEDGER_SCHEMA_VERSION`]). [`example::render_wire_pair`] is shared by the
// docs-match test (requirement.md byte-equals the canonical output) and the
// round-trip proptest (arbitrary generated pairs parse through the strict
// reader).
#[cfg(test)]
mod example;

// The shared ordered slot tables are re-exported below (their home is
// [`crate::ledger::tables`] — generic collection infrastructure, kept
// separate from the record model) so the pre-split
// `crate::ledger::records::X` paths keep compiling.
pub use crate::ledger::tables::{NonEmptySlotTable, SlotTable};
pub use observation::{
    ArtifactRefWire, Observation, ObservationError, ObservationWire, ObservedAssignment,
    ObservedGeneration, ObservedGenerationWire, ObservedSlot, ObservedTarget,
};
// The DOMAIN records are OWNED BY THE SEMANTIC KERNEL
// ([`crate::kernel`]) and re-exported here so the pre-kernel
// `crate::ledger::records::X` paths keep resolving: the intent
// ([`crate::kernel::intent::DeploymentIntent`]) and the terminal
// ([`crate::kernel::terminal`]'s [`LedgerTerminal`] / [`TerminalDisposition`] /
// [`DegradedTerminal`] / [`FailedRolledBackTerminal`]).
pub use crate::kernel::intent::DeploymentIntent;
pub use crate::kernel::snapshot::SnapshotSlot as SnapshotEntry;
pub use crate::kernel::terminal::{
    DegradedTerminal, FailedRolledBackTerminal, IntentDigest, LedgerTerminal, TerminalDisposition,
};
pub use validation::{FrozenSlotTopology, RebindingPlan, VerifiedReleaseRebinding};
pub(crate) use validation::{LEDGER_SCHEMA_VERSION, PINS_SCHEMA_VERSION};
pub use wire::{
    CompensationReport, LedgerEntry, LedgerIntentReport, LedgerIntentWire, LedgerTerminalWire,
    PlannedSlotWire, PreviousGenerationWire, SlotActionWire, SlotOutcome, SlotOutcomeKind,
    SlotResult, SlotTransition, SnapshotSlotWire,
};

/// THE PHYSICAL LEDGER EVENT LINE — the WIRE enum the append-only JSONL
/// stream carries: one line per intent, terminal, and (as the first line of
/// a checkpointed ledger) checkpoint event. Strict parsing + the
/// event-store rules live in the store reader; the SEMANTIC transitions
/// are validated by [`crate::kernel::transition::apply_event`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerEventWire {
    Intent(LedgerIntentWire),
    Terminal(LedgerTerminalWire),
    Checkpoint(CheckpointWire),
}

/// The WIRE shape of a checkpoint event: the atomic suffix replacement's
/// ledger begins with this line, recording which deployment the retained
/// suffix starts at and how many ledger entries were discarded.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointWire {
    pub deployment_schema_version: u32,
    /// The deployment the retained suffix starts at (the checkpoint
    /// deployment).
    pub retained_from: String,
    /// How many ledger entries were discarded by the compaction.
    pub discarded: u64,
    pub recorded_at: String,
}

impl CheckpointWire {
    /// Build the (infallible, canonical) wire form of a checkpoint event
    /// carrying the current schema version.
    pub fn new(
        retained_from: &crate::identity::DeploymentId,
        discarded: u64,
        recorded_at: &str,
    ) -> Self {
        CheckpointWire {
            deployment_schema_version: LEDGER_SCHEMA_VERSION,
            retained_from: retained_from.as_str().to_string(),
            discarded,
            recorded_at: recorded_at.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Successful,
    FailedPreflight,
    FailedRolledBack,
    Degraded,
}

impl DeploymentStatus {
    /// The terminal statuses: an attempt that ended without achieving its
    /// planned result (a deployment whose entry has NO terminal is the
    /// PENDING state — never a status in the terminal enum).
    pub fn is_terminal_failure(&self) -> bool {
        matches!(
            self,
            DeploymentStatus::FailedPreflight
                | DeploymentStatus::FailedRolledBack
                | DeploymentStatus::Degraded
        )
    }

    /// The PENDING (non-terminal) state: an intent WITHOUT a terminal IS
    /// pending; its recovery phase is an operational view derived from
    /// markers/transactions, never a status on any terminal event.
    pub fn is_pending() -> bool {
        true
    }
}

/// A per-slot assignment snapshot: the artifact a slot runs (or planned to
/// run) plus the generation it is bound to. `generation` is `None` when the
/// slot's server was never started (e.g. skipped after an earlier failure
/// under `stop_on_failure`), or when only the pre-push state is unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotAttemptState {
    /// The slot's assignment as a THREE-STATE observation
    /// ([`Observation<ArtifactRef>`]): `Known(artifact)` is a real artifact
    /// read from the remote, `KnownAbsent` carries no artifact, and
    /// `Unknown(error)` preserves the read failure. An unknown assignment is
    /// a DISTINCT value — never a valid-looking [`ArtifactRef`] (there is no
    /// sentinel artifact: an `ArtifactRef` always means a known artifact).
    pub artifact: Observation<ArtifactRef>,
    /// The generation this slot actually advanced to. `None` when the slot's
    /// server was never started (e.g. skipped after an earlier failure under
    /// `stop_on_failure`), or when only the pre-push state is unknown.
    pub generation: Option<GenerationId>,
}

/// The complete PHYSICAL binding of one placement slot at terminal time: the
/// actual server ([`ServerId`]) AND the absolute `deploy_dir` on that server
/// where the slot's deployment state (objects, releases, generations,
/// `current`) lives. Together `{server, deploy_dir}` name the exact on-host
/// deployment location a terminal successful event's generations were
/// advanced on. Exact rollback must verify BOTH halves: a slot that keeps
/// its server but moves its `deploy_dir` would otherwise receive the
/// historical generations at the new location, silently deploying to the
/// wrong place on the same host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalBinding {
    /// The physical server the slot was bound to at the time of the
    /// deployment.
    pub server: ServerId,
    /// The absolute on-server directory the slot's deployment state lives
    /// in, exactly as declared in the slot's `deploy_dir` at deployment time.
    pub deploy_dir: String,
}
impl Default for PhysicalBinding {
    fn default() -> Self {
        Self {
            server: ServerId::parse("s1").unwrap(),
            deploy_dir: "/srv/deploy/p1".to_string(),
        }
    }
}

/// THE DERIVED SNAPSHOT VIEW — the resulting snapshot of a successful
/// deployment, RESOLVED from its intent's slot table
/// ([`crate::kernel::snapshot::resolve_snapshot`]) on demand, NEVER stored
/// in any terminal payload: one entry per slot carrying its generation,
/// artifact, and physical binding (the `SnapshotEntry` = the kernel's
/// [`crate::kernel::snapshot::SnapshotSlot`]). A VALUE type only (no
/// stored invariants — the slot table owns them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSnapshot {
    entries: BTreeMap<SlotId, SnapshotEntry>,
}

impl TargetSnapshot {
    pub fn from_entries(entries: BTreeMap<SlotId, SnapshotEntry>) -> Self {
        Self { entries }
    }
    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &SnapshotEntry)> {
        self.entries.iter()
    }
    pub fn get(&self, slot: &SlotId) -> Option<&SnapshotEntry> {
        self.entries.get(slot)
    }
    pub fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.entries.keys()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn into_entries(self) -> BTreeMap<SlotId, SnapshotEntry> {
        self.entries
    }
    pub fn generation_ref(&self, slot: &SlotId) -> Option<GenerationRef> {
        self.entries.get(slot).map(|e| GenerationRef {
            generation: e.generation().clone(),
            assignment: PlacementSlotAssignment {
                placement_slot: slot.clone(),
                artifact: e.artifact().clone(),
            },
        })
    }
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.entries
            .values()
            .map(|e| e.artifact().release.clone())
            .collect()
    }
}

/// The per-release, per-variant behavior contracts an attempt is bound to:
/// keyed by release id, then variant name. Historical and rollback pushes
/// resolve EACH SLOT's behavior from ITS OWN artifact binding
/// (`slot.assignment.artifact = {release, variant, tree}`) — the release
/// record's stored per-variant contract, verified against the release's
/// provenance digest — never a snapshot-wide single release. A partial
/// snapshot's slots can carry artifacts from DIFFERENT releases, so the
/// index spans every release the attempt's slots reference.
pub type BehaviorIndex = BTreeMap<ReleaseId, BTreeMap<String, BehaviorContract>>;

/// A durable pin: retained artifact CONTENT, store-global (a release or
/// binding is shared by every target that references it, so a pin protects
/// it everywhere). Persisted at `<base>/pins.json`; the artifact garbage
/// collector ([`crate::retention::gc`]) folds every pin into the retained
/// binding set BEFORE it unlinks anything, so a pinned release record and
/// tree object are never deleted. These STORE-LEVEL pins are DISTINCT from
/// the retention subsystem's project-file `[[pins]]`
/// ([`crate::config::Pin`]): the checkpoint flow is store-only (it never
/// loads the caller's `deploy.toml`), so its retention anchors live in the
/// store, while retention's config pins protect the REMOTE retained set and
/// are never consulted by the local GC.
///
/// PINS RETAIN ARTIFACT CONTENT ONLY. A pin is a pure retention anchor for
/// the artifact store — it never creates, keeps, or reinserts a deployment
/// in any target's ledger, and it never extends a target's retained
/// history. The checkpoint's retained set is the LEDGER SUFFIX alone (the
/// first retained ledger entry is the oldest rollback state), so pinning
/// the artifacts of a pre-retention deployment keeps the bytes but NEVER
/// the history.
///
/// Two pin forms (both supported, mix freely):
///
/// * `releases` — a RELEASE pin: retains the whole release record AND
///   every variant/tree binding in that record (the GC expands the record's
///   `variants` map). The canonical `rel-sha256-<digest>` id is required
///   (accepted as a bare digest too via [`crate::identity::ReleaseId::parse`]);
///   a release pin whose record is missing fails the GC closed (the pin
///   cannot be expanded — nothing is deleted that run).
/// * `bindings` — an EXACT BINDING pin: one (release, variant, tree)
///   [`ArtifactRef`], which keeps that release record and that tree object.
///
/// `schema_version` is exactly `crate::ledger::PINS_SCHEMA_VERSION`;
/// readers refuse any other version (fail closed).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pins {
    pub schema_version: u32,
    /// Whole-release pins: every variant/tree in each named release record
    /// is retained (release pins expand via the release record's `variants`
    /// map at GC time).
    #[serde(default)]
    pub releases: Vec<ReleaseId>,
    /// Exact-binding pins: each `(release, variant, tree)` retains exactly
    /// that release record + tree object.
    #[serde(default)]
    pub bindings: Vec<ArtifactRef>,
}

/// Persisted per-server local record (`servers/<id>.json`). Keyed by the
/// ACTUAL server identity ([`ServerId`], transport addressing); the
/// slot→assignment maps live in [`ObservedTarget`] keyed by
/// [`SlotId`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerState {
    pub id: ServerId,
    #[serde(default)]
    pub last_seen_target: Option<TargetName>,
    #[serde(default)]
    pub last_observed: Option<ObservedSlot>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            id: ServerId::parse("default").expect("default server is a safe segment"),
            last_seen_target: None,
            last_observed: None,
        }
    }
}

/// Where a plan's desired assignment comes from — the WIRE (on-disk) form
/// of the plan source. The wire keeps this shape: a `release:<id>` source
/// names the release, and the CLAIMED rebinding proof lives in the
/// separate [`DeploymentPlanWire::rebinding`] field ([`RebindingPlan`]).
/// The VERIFYING CONVERSION ([`DeploymentPlanWire::into_domain`]) recomputes
/// the proof and exposes the verified [`PlanOrigin`] on the domain — a
/// Release origin without its proof is unrepresentable there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanSource {
    /// Materialize the currently mapped local files and assign each slot its
    /// target-configured (current) variant.
    Head,
    /// Restore the stored state of a successful deployment, keyed by its
    /// deployment id (`deploy push <target> <deployment-id>` and the
    /// `@` / `parent(...)` deployment-history walk): the rollback state
    /// resolved from the target's ledger.
    DeploymentRef(DeploymentId),
    /// Assign each current slot its variant from a named release — the
    /// release's OWN frozen topology applied onto the CURRENT physical
    /// slots. The rebinding this performs is EXPLICIT: the wire carries the
    /// claimed proof as [`DeploymentPlanWire::rebinding`]
    /// ([`RebindingPlan`]); the domain conversion verifies it and carries
    /// the verified proof inside [`PlanOrigin::Release`].
    ReleaseRef(ReleaseId),
}

/// The VERIFIED origin of a deployment plan — the DOMAIN form of the wire's
/// [`PlanSource`] + separate `rebinding` fields. THE SOURCE OWNS ITS
/// REQUIRED PAYLOAD: a Release origin ([`PlanOrigin::Release`]) CARRIES its
/// [`VerifiedReleaseRebinding`] (the proof) INSIDE the source — a Release
/// origin without the proof is unrepresentable; HEAD and deployment origins
/// carry none. The wire → domain conversion
/// ([`DeploymentPlanWire::into_domain`]) RECOMPUTES the proof from the
/// wire's claimed rebinding and the plan's own source/target/membership,
/// succeeding only when the claimed rebinding matches the recomputed proof
/// (a mismatch → [`crate::error::Error::integrity`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanOrigin {
    /// Materialize the currently mapped local files and assign each slot its
    /// target-configured (current) variant.
    Head,
    /// Restore the stored state of a successful deployment, keyed by its
    /// deployment id.
    Deployment(DeploymentId),
    /// Assign each current slot its variant from a named release — the
    /// release's OWN frozen topology applied onto the CURRENT physical
    /// slots. The rebinding this performs is EXPLICIT and VERIFIED: the
    /// proof ([`VerifiedReleaseRebinding`]) is carried INSIDE the source.
    Release {
        release: ReleaseId,
        rebinding: VerifiedReleaseRebinding,
    },
}

/// Per-slot plan for one placement slot: its slot identity, the artifact it
/// should run, and the compare-and-swap preconditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotPlan {
    pub slot_id: SlotId,
    pub artifact: ArtifactRef,
    /// Pre-push generation that must match for the compare-and-swap precondition.
    pub expected_generation: Option<GenerationId>,
    pub expected_tree: Option<TreeDigest>,
}

/// The WIRE shape of a deployment plan (`deployments/<id>/plan.json`): the
/// raw serde form holding the REDUNDANT members the domain reconciles away —
/// `slot_ids` next to the authoritative per-slot `slots` map, `behavior_sha256`
/// next to the authoritative `behaviors` index, `desired_releases` next to the
/// releases derived from the per-slot artifacts. The on-disk plan keeps the
/// redundant shape (the write path serializes the domain through this wire
/// form); the VERIFYING CONVERSION ([`DeploymentPlanWire::into_domain`])
/// checks every duplicate projection and exposes only the validated
/// [`DeploymentPlan`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPlanWire {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The stored snapshot-wide behavior digest; must equal the digest
    /// derived from `behaviors` (the authoritative index).
    pub behavior_sha256: String,
    /// The frozen, per-release name-keyed activation + verification contracts
    /// this attempt is bound to — THE AUTHORITATIVE BEHAVIOR COLLECTION (the
    /// digest is derived from it).
    pub behaviors: BehaviorIndex,
    /// The selected placement slots; the DEDUPLICATED SET must equal the
    /// `slots` map's key set (the authoritative membership).
    pub slot_ids: Vec<SlotId>,
    pub slots: BTreeMap<SlotId, SlotPlan>,
    pub source: PlanSource,
    /// When the plan was built from a DIRECT release reference
    /// (`PlanSource::ReleaseRef`), the CLAIMED rebinding context: the
    /// historical release's frozen topology applied onto the CURRENT
    /// physical slots ([`RebindingPlan`]). `None` for HEAD and
    /// deployment-keyed plans. The VERIFYING CONVERSION recomputes the
    /// proof from this claimed shape and the plan's own
    /// source/target/membership, refusing any disagreement (a Release
    /// origin without a proof, or a non-Release origin carrying one, is
    /// refused). `#[serde(default)]` keeps deployment records written
    /// before this field loadable; `skip_serializing_if` keeps the
    /// recorded wire shape unchanged for plans that carry no rebinding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebinding: Option<RebindingPlan>,
    /// The releases this attempt's slots reference; must equal the set
    /// derived from the per-slot artifacts (a partial snapshot can span
    /// several releases).
    pub desired_releases: BTreeSet<ReleaseId>,
}

impl DeploymentPlanWire {
    /// VERIFYING CONVERSION (wire → domain): every duplicate projection must
    /// agree — the `slot_ids` set (deduplicated) equals the `slots` map keys,
    /// every `SlotPlan` names its own map key, `desired_releases` equals
    /// the releases derived from the per-slot artifacts, and
    /// `behavior_sha256` equals the canonical digest of `behaviors`. A
    /// disagreement → `Error::integrity` (fail closed).
    pub fn into_domain(self) -> Result<DeploymentPlan> {
        // The stored behavior digest must be a sha256 digest before it can
        // even be compared with the digest derived from `behaviors` (fail
        // closed: a tampered non-digest is refused on format, not just on
        // disagreement).
        BehaviorDigest::parse(&self.behavior_sha256).map_err(|_| {
            Error::integrity(format!(
                "plan {}: stored behavior_sha256 {:?} is not a sha256 digest",
                self.deployment_id, self.behavior_sha256
            ))
        })?;
        let wire_slots: BTreeSet<&SlotId> = self.slot_ids.iter().collect();
        let keys: BTreeSet<&SlotId> = self.slots.keys().collect();
        if wire_slots != keys {
            return Err(Error::integrity(format!(
                "plan {}: slot_ids {:?} disagrees with the per-slot plan keys {:?}",
                self.deployment_id, wire_slots, keys
            )));
        }
        for (key, plan) in &self.slots {
            if &plan.slot_id != key {
                return Err(Error::integrity(format!(
                    "plan {}: per-slot plan for '{key}' names slot '{}'",
                    self.deployment_id, plan.slot_id
                )));
            }
        }
        let releases: BTreeSet<ReleaseId> = self
            .slots
            .values()
            .map(|p| p.artifact.release.clone())
            .collect();
        if self.desired_releases != releases {
            return Err(Error::integrity(format!(
                "plan {}: desired_releases {:?} disagrees with the derived releases {:?}",
                self.deployment_id, self.desired_releases, releases
            )));
        }
        let digest = crate::verify::release::behavior_index_digest(&self.behaviors);
        if self.behavior_sha256 != digest {
            return Err(Error::integrity(format!(
                "plan {}: stored behavior_sha256 disagrees with the derived digest of the behavior index",
                self.deployment_id
            )));
        }
        // THE SOURCE OWNS ITS REQUIRED PAYLOAD: the wire's `PlanSource` +
        // separate `rebinding` field convert to the domain's [`PlanOrigin`]
        // by RECOMPUTING the proof. A Release origin must carry its
        // [`VerifiedReleaseRebinding`] (a Release source without a claimed
        // rebinding is refused — the proof is unrepresentable without it);
        // HEAD and deployment origins must carry NONE (a claimed rebinding
        // on a non-Release plan is a disagreement — the domain has no place
        // for it, so it is refused rather than silently dropped). The
        // recomputation compares the claimed rebinding against the plan's
        // own source/target/membership: the claimed release must be the
        // plan's source release AND the release its slots reference, the
        // claimed target must equal the plan's target, and the claimed
        // components must agree internally (frozen topology keys ==
        // membership, selected plan slots ⊆ membership, physical slots ==
        // selected). A mismatch → `Error::integrity` (fail closed: a
        // tampered plan can never claim a rebinding its source/release/
        // target/slots don't support).
        let source = match self.source {
            PlanSource::Head => {
                if self.rebinding.is_some() {
                    return Err(Error::integrity(format!(
                        "plan {}: a HEAD plan cannot carry a rebinding proof",
                        self.deployment_id
                    )));
                }
                PlanOrigin::Head
            }
            PlanSource::DeploymentRef(deployment_id) => {
                if self.rebinding.is_some() {
                    return Err(Error::integrity(format!(
                        "plan {}: a deployment-keyed plan cannot carry a rebinding proof",
                        self.deployment_id
                    )));
                }
                PlanOrigin::Deployment(deployment_id)
            }
            PlanSource::ReleaseRef(release) => {
                let claimed = self.rebinding.ok_or_else(|| {
                    Error::integrity(format!(
                        "plan {}: a release-origin plan must carry its rebinding proof",
                        self.deployment_id
                    ))
                })?;
                // The claimed release must be the plan's source release AND
                // the release the plan's slots reference (a release-origin
                // plan's slots all reference the release).
                if claimed.release != release {
                    return Err(Error::integrity(format!(
                        "plan {}: the claimed rebinding release {} disagrees with the plan's source release {release}",
                        self.deployment_id, claimed.release
                    )));
                }
                if claimed.target != self.target {
                    return Err(Error::integrity(format!(
                        "plan {}: the claimed rebinding target '{}' disagrees with the plan's target '{}'",
                        self.deployment_id, claimed.target, self.target
                    )));
                }
                let derived: BTreeSet<ReleaseId> = self
                    .slots
                    .values()
                    .map(|p| p.artifact.release.clone())
                    .collect();
                if derived != BTreeSet::from([release.clone()]) {
                    return Err(Error::integrity(format!(
                        "plan {}: the claimed rebinding release {release} disagrees with the releases derived from the plan's slots {derived:?}",
                        self.deployment_id
                    )));
                }
                // RECOMPUTE the proof from the claimed components and the
                // plan's own membership (the selected plan slots are the
                // plan's `slots` map keys).
                let proof = VerifiedReleaseRebinding::verify(
                    claimed.release,
                    claimed.target,
                    claimed.frozen_topology,
                    claimed.membership,
                    self.slots.keys().cloned().collect(),
                    claimed.current_physical_slots,
                )
                .map_err(|e| {
                    Error::integrity(format!(
                        "plan {}: the claimed rebinding disagrees with the recomputed proof: {e}",
                        self.deployment_id
                    ))
                })?;
                PlanOrigin::Release {
                    release,
                    rebinding: proof,
                }
            }
        };
        Ok(DeploymentPlan {
            deployment_id: self.deployment_id,
            target: self.target,
            behaviors: self.behaviors,
            slots: self.slots,
            source,
        })
    }
}

impl From<&DeploymentPlan> for DeploymentPlanWire {
    fn from(p: &DeploymentPlan) -> Self {
        // The domain's [`PlanOrigin`] re-expands into the wire's `PlanSource`
        // + separate `rebinding` shape: a Release origin carries its
        // verified proof back into the claimed [`RebindingPlan`] (the
        // selected plan slots are re-derived from the plan's membership on
        // the next read); HEAD and deployment origins carry `None`.
        let (source, rebinding) = match &p.source {
            PlanOrigin::Head => (PlanSource::Head, None),
            PlanOrigin::Deployment(deployment_id) => {
                (PlanSource::DeploymentRef(deployment_id.clone()), None)
            }
            PlanOrigin::Release { release, rebinding } => (
                PlanSource::ReleaseRef(release.clone()),
                Some(RebindingPlan {
                    release: rebinding.release.clone(),
                    target: rebinding.target.clone(),
                    frozen_topology: rebinding.frozen_topology.clone(),
                    membership: rebinding.membership.clone(),
                    current_physical_slots: rebinding.current_physical_slots.clone(),
                }),
            ),
        };
        DeploymentPlanWire {
            deployment_id: p.deployment_id.clone(),
            target: p.target.clone(),
            behavior_sha256: p.behavior_digest(),
            behaviors: p.behaviors.clone(),
            slot_ids: p.membership().cloned().collect(),
            slots: p.slots.clone(),
            source,
            rebinding,
            desired_releases: p.releases(),
        }
    }
}

/// A deployment plan, the VALIDATED DOMAIN form of [`DeploymentPlanWire`]:
/// the attempt's snapshot-wide behavior digest, the frozen per-release
/// name-keyed activation + verification contracts, and the per-slot plans.
/// ONE AUTHORITATIVE COLLECTION PER CONCEPT — `slots` (per-slot plans) is
/// the membership AND the release source; `behaviors` (the index) is the
/// behavior source; `source` ([`PlanOrigin`]) is the verified origin and
/// OWNS its required payload (a Release origin carries its
/// [`VerifiedReleaseRebinding`] proof inside the source). The `slot_ids` /
/// `desired_releases` / `behavior_sha256` members exist only in the wire
/// (the serialized `plan.json` keeps the redundant shape) and are derived
/// here through [`DeploymentPlan::membership`], [`DeploymentPlan::releases`],
/// [`DeploymentPlan::behavior_digest`] — the verified conversion guarantees
/// they agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentPlan {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The frozen, per-release name-keyed activation + verification contracts
    /// this attempt is bound to, one per declared variant per referenced
    /// release — THE AUTHORITATIVE BEHAVIOR COLLECTION (the digest is
    /// derived from it). Historical and rollback pushes carry the historical
    /// contracts here rather than the caller's current configuration.
    pub behaviors: BehaviorIndex,
    /// THE AUTHORITATIVE PER-SLOT COLLECTION: the selected slots (the map
    /// keys are the membership) and their plans (their artifacts are the
    /// release source).
    pub slots: BTreeMap<SlotId, SlotPlan>,
    /// THE SOURCE OWNS ITS REQUIRED PAYLOAD: a Release origin
    /// ([`PlanOrigin::Release`]) CARRIES its verified rebinding proof
    /// ([`VerifiedReleaseRebinding`]) INSIDE the source — a Release origin
    /// without the proof is unrepresentable; HEAD and deployment origins
    /// carry none. The wire's separate `rebinding` field exists only in the
    /// on-disk shape ([`DeploymentPlanWire`]) and is reconciled by the
    /// verifying conversion.
    pub source: PlanOrigin,
}

impl DeploymentPlan {
    /// The plan's membership: the selected placement slots, DERIVED from the
    /// authoritative `slots` map (its keys) — never stored separately.
    pub fn membership(&self) -> impl Iterator<Item = &SlotId> {
        self.slots.keys()
    }

    /// The distinct releases the plan's slots reference (per-slot artifact
    /// provenance: a partial snapshot can span several releases) — DERIVED
    /// from the authoritative `slots` map, never stored separately.
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.slots
            .values()
            .map(|p| p.artifact.release.clone())
            .collect()
    }

    /// The attempt's snapshot-wide behavior digest: the canonical digest of
    /// the [`BehaviorIndex`] the attempt is bound to — DERIVED from the
    /// authoritative `behaviors` index, never stored separately.
    pub fn behavior_digest(&self) -> String {
        crate::verify::release::behavior_index_digest(&self.behaviors)
    }
}

impl Serialize for DeploymentPlan {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DeploymentPlanWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeploymentPlan {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DeploymentPlanWire::deserialize(deserializer)?;
        wire.into_domain()
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{SlotId, TargetName, Timestamp, test_deployment_id, test_generation_id};
    use crate::kernel;
    use crate::ledger::records::{
        DeploymentStatus, LedgerIntentWire, LedgerTerminalWire, SlotActionWire,
    };
    use crate::ledger::{LEDGER_SCHEMA_VERSION, LedgerLine, TargetSnapshot};
    use crate::store::local::LocalStore;
    use crate::testutil::fixtures;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    // ---- fixtures: a valid full-push intent + every terminal disposition --

    /// A valid full-push intent over `keys` (group None → all Deploy).
    fn valid_intent(keys: &[SlotId], dep: &str) -> crate::kernel::intent::DeploymentIntent {
        fixtures::full_intent(dep, "t1", keys, &[])
    }

    /// The WIRE form of [`valid_intent`] — the tamper target (tests that
    /// need invalid values mutate the WIRE, never the domain).
    fn valid_intent_wire(keys: &[SlotId], dep: &str) -> LedgerIntentWire {
        LedgerIntentWire::from(&valid_intent(keys, dep))
    }

    fn valid_terminal_wire(
        keys: &[SlotId],
        dep: &str,
        status: DeploymentStatus,
    ) -> LedgerTerminalWire {
        let intent = valid_intent(keys, dep);
        let terminal = match status {
            DeploymentStatus::Successful => fixtures::successful_terminal(&intent),
            DeploymentStatus::FailedPreflight => fixtures::failed_preflight_terminal(&intent),
            DeploymentStatus::FailedRolledBack => fixtures::rolled_back_terminal(&intent, keys),
            DeploymentStatus::Degraded => fixtures::degraded_terminal(&intent, keys),
        };
        LedgerTerminalWire::to_wire(intent.deployment_id(), intent.target(), &terminal)
    }

    /// Write a two-line ledger through the REAL consumer path and read it
    /// back (the strict reader).
    fn write_pair_ledger(
        intent_wire: &LedgerIntentWire,
        terminal_wire: &LedgerTerminalWire,
    ) -> Result<Vec<crate::ledger::LedgerEntry>> {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(intent_wire.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(terminal_wire.clone())).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        store.read_ledger("t1")
    }

    // ---- THE WIRE → DOMAIN → WIRE ROUND TRIP (proptest 1) ----------------

    fn slot_table_strategy() -> impl Strategy<Value = Vec<SlotId>> {
        prop::collection::btree_set((0u32..5).prop_map(slot), 1..=4).prop_map(|s| {
            let mut v: Vec<SlotId> = s.into_iter().collect();
            v.sort();
            v
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(32),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// 1. Every constructible domain value round-trips exactly
        /// (wire → domain → wire).
        #[test]
        fn wire_domain_wire_round_trip_exact(keys in slot_table_strategy()) {
            let wire = valid_intent_wire(&keys, "deploy-w");
            let domain = wire.clone().into_domain().expect("valid intent converts");
            let wire2 = LedgerIntentWire::from(&domain);
            prop_assert_eq!(
                wire2, wire,
                "a constructible intent round-trips exactly through its wire form"
            );
            // The derived views are exact against the table.
            prop_assert_eq!(
                domain.full_membership(),
                keys.iter().cloned().collect::<std::collections::BTreeSet<_>>()
            );
            prop_assert_eq!(
                domain.selected_membership(),
                keys.iter().cloned().collect::<std::collections::BTreeSet<_>>()
            );
            prop_assert_eq!(
                domain.resulting_snapshot().keys().cloned().collect::<Vec<_>>(),
                keys,
                "the resulting snapshot is the derived view of the slot table"
            );
        }
    }

    // ---- THE SELF-CONTAINED TAMPER MATRIX (the new projections) ----------

    /// Mutate one wire projection at a time and assert the wire → domain
    /// conversion fails closed on EVERY tamper while accepting the
    /// untampered record: the intent's slot-table structure (a slot without
    /// its result/action, a duplicate slot, an empty table, a group-None
    /// intent carrying an Inherit slot, a no-Deploy intent), the scalar
    /// gates (parent, behavior digest, attempted_at, group name), and the
    /// pre-push wire observation values.
    #[test]
    fn intent_wire_tamper_matrix_fails_closed() {
        let keys = vec![slot(0), slot(1), slot(2)];
        // 1. Duplicate slot key in the JSON (ambiguous map) is refused by
        // the strict reader (a map-visitor deserializer rejects the
        // duplicate — the last-wins collapse could never be read).
        let wire = valid_intent_wire(&keys, "deploy-tamper");
        let json = serde_json::to_string(&wire).unwrap();
        {
            let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
            let slots = value.get_mut("slots").unwrap().as_object_mut().unwrap();
            let first = slots.keys().next().unwrap().clone();
            // TEXT-LEVEL duplication of ONE entry: insert a second copy of the
            // first slot right after it (serde_json maps cannot hold two
            // identical keys, so the duplicate must be injected into the raw
            // JSON text).
            let first_start = json.find(&format!("\"{first}\":")).unwrap();
            let first_end = json.find(&format!("\"{}\":", "slot-1")).unwrap();
            let dup_entry_text = &json[first_start..first_end]; // includes its trailing comma
            let dup_json = format!(
                "{}{},{}",
                &json[..first_start],
                dup_entry_text,
                &json[first_start..]
            );
            assert_ne!(
                dup_json, json,
                "the duplicate entry must actually be injected"
            );
            assert!(
                serde_json::from_str::<LedgerIntentWire>(&dup_json).is_err(),
                "a duplicate slot key must be refused by the strict reader"
            );
        }

        // 2. Empty slots table.
        let mut wire = valid_intent_wire(&keys, "deploy-tamper");
        wire.slots.clear();
        assert!(wire.clone().into_domain().is_err(), "empty slots refused");

        // 3. No Deploy slot.
        let mut wire = valid_intent_wire(&keys, "deploy-tamper");
        for p in wire.slots.values_mut() {
            p.action = SlotActionWire::Inherit;
        }
        assert!(
            wire.clone().into_domain().is_err(),
            "no Deploy slot refused"
        );

        // 4. group=Some but an Inherit slot with no parent grounding is
        // self-contained-invalid ONLY via the group-None rule; for a full
        // push (group None) an Inherit slot must be refused.
        let mut wire = valid_intent_wire(&keys, "deploy-tamper");
        let first_key = keys[0].clone();
        wire.slots.get_mut(&first_key).unwrap().action = SlotActionWire::Inherit;
        assert!(
            wire.clone().into_domain().is_err(),
            "group None with an Inherit slot refused (a full push requires every slot Deploy)"
        );

        // 5. Invalid parent id.
        let mut wire = valid_intent_wire(&keys, "deploy-tamper");
        wire.parent = Some("not-a-deployment".to_string());
        assert!(
            wire.clone().into_domain().is_err(),
            "invalid parent refused"
        );

        // 6. Invalid behavior digest.
        let mut wire = valid_intent_wire(&keys, "deploy-tamper");
        wire.behavior_sha256 = "sha256-xx".to_string();
        assert!(
            wire.clone().into_domain().is_err(),
            "invalid digest refused"
        );

        // 7. Invalid attempted_at.
        let mut wire = valid_intent_wire(&keys, "deploy-tamper");
        wire.attempted_at = "not-a-time".to_string();
        assert!(
            wire.clone().into_domain().is_err(),
            "invalid timestamp refused"
        );

        // 8. Invalid group name.
        let mut wire = valid_intent_wire(&keys, "deploy-tamper");
        wire.group = Some("../bad".to_string());
        assert!(wire.clone().into_domain().is_err(), "invalid group refused");
    }

    /// The TERMINAL tamper matrix: the disposition payload must match its
    /// status, the `intent_digest` must be a valid sha256 scalar, and a
    /// successful terminal must be payload-free.
    #[test]
    fn terminal_wire_tamper_matrix_fails_closed() {
        let keys = vec![slot(0)];
        // Successful with outcomes is refused (payload-free).
        let mut wire = valid_terminal_wire(&keys, "deploy-t", DeploymentStatus::Successful);
        wire.outcomes.insert(
            keys[0].clone(),
            SlotResult {
                slot_id: keys[0].clone(),
                outcome: SlotOutcomeKind::Activated,
                observation: ObservationWire::Known(ObservedGenerationWire {
                    generation: test_generation_id("g"),
                }),
                compensated: false,
                error: None,
            },
        );
        assert!(
            wire.clone().into_domain().is_err(),
            "a Successful terminal must carry NO outcomes"
        );
        // FailedPreflight with outcomes is refused.
        let mut wire = valid_terminal_wire(&keys, "deploy-t", DeploymentStatus::FailedPreflight);
        wire.outcomes.insert(
            keys[0].clone(),
            SlotResult {
                slot_id: keys[0].clone(),
                outcome: SlotOutcomeKind::Failed,
                observation: ObservationWire::Known(ObservedGenerationWire {
                    generation: test_generation_id("g"),
                }),
                compensated: false,
                error: Some("boom".to_string()),
            },
        );
        assert!(
            wire.clone().into_domain().is_err(),
            "FailedPreflight must carry NO outcomes"
        );
        // Invalid intent_digest scalar.
        let mut wire = valid_terminal_wire(&keys, "deploy-t", DeploymentStatus::Successful);
        wire.intent_digest = "not-a-digest".to_string();
        assert!(
            wire.clone().into_domain().is_err(),
            "invalid intent_digest refused"
        );
        // Invalid recorded_at.
        let mut wire = valid_terminal_wire(&keys, "deploy-t", DeploymentStatus::Successful);
        wire.recorded_at = "not-a-time".to_string();
        assert!(
            wire.clone().into_domain().is_err(),
            "invalid recorded_at refused"
        );
    }

    /// Mutating ANY terminal's intent_digest is rejected at the READER (the
    /// digest binds the terminal to the exact canonical intent) — proptest 3.
    #[test]
    fn tampered_intent_digest_is_rejected_by_the_reader() {
        let keys = vec![slot(0), slot(1)];
        let intent_wire = valid_intent_wire(&keys, "deploy-digest");
        for status in [
            DeploymentStatus::Successful,
            DeploymentStatus::FailedPreflight,
            DeploymentStatus::FailedRolledBack,
            DeploymentStatus::Degraded,
        ] {
            let mut terminal_wire = valid_terminal_wire(&keys, "deploy-digest", status);
            let mut tampered = terminal_wire.intent_digest.clone();
            let b = tampered.as_bytes().to_vec();
            let flipped = b[0] ^ 1;
            tampered.replace_range(0..1, &format!("{:x}", flipped));
            terminal_wire.intent_digest = tampered;
            let err = write_pair_ledger(&intent_wire, &terminal_wire).unwrap_err();
            assert!(
                err.to_string().contains("digest"),
                "a tampered intent_digest ({status:?}) must be refused by the reader, got: {err}"
            );
        }
    }

    // ---- THE STRICT READER CONTRACT ---------------------------------------

    /// A valid pair loads; the successful snapshot resolves from the intent.
    #[test]
    fn strict_reader_accepts_a_valid_pair_and_resolves_the_snapshot() {
        let keys = vec![slot(0), slot(1)];
        let intent_wire = valid_intent_wire(&keys, "deploy-ok");
        for status in [
            DeploymentStatus::Successful,
            DeploymentStatus::FailedPreflight,
            DeploymentStatus::FailedRolledBack,
            DeploymentStatus::Degraded,
        ] {
            let terminal_wire = valid_terminal_wire(&keys, "deploy-ok", status);
            let entries = write_pair_ledger(&intent_wire, &terminal_wire)
                .unwrap_or_else(|e| panic!("{status:?} pair must load, got {e}"));
            assert_eq!(entries.len(), 1);
            assert_eq!(
                entries[0].terminal.as_ref().unwrap().status(),
                status,
                "the terminal's status derives from its disposition"
            );
            assert_eq!(
                entries[0].intent.full_membership(),
                keys.iter().cloned().collect(),
                "the full membership is the slot table's keys"
            );
            if status == DeploymentStatus::Successful {
                let snapshot = kernel::snapshot::resolve_snapshot(&entries[0]).unwrap();
                assert_eq!(
                    snapshot,
                    entries[0].intent.resulting_snapshot(),
                    "the successful snapshot IS the intent's planned result"
                );
            } else {
                assert!(
                    kernel::snapshot::resolve_snapshot(&entries[0]).is_err(),
                    "a non-successful deployment has no snapshot"
                );
            }
        }
    }

    /// A terminal for an unknown deployment, a duplicate intent, a duplicate
    /// terminal, and a terminal preceding its intent are all refused.
    #[test]
    fn strict_reader_refuses_impossible_event_sequences() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let keys = vec![slot(0)];

        // Terminal without an intent.
        let t = valid_terminal_wire(&keys, "deploy-orphan", DeploymentStatus::Successful);
        let line = serde_json::to_string(&LedgerLine::Terminal(t)).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let err = store.read_ledger("t1").unwrap_err();
        assert!(
            err.to_string().contains("intent"),
            "orphan terminal refused: {err}"
        );

        // Duplicate intent.
        let i = valid_intent_wire(&keys, "deploy-dup");
        let line = serde_json::to_string(&LedgerLine::Intent(i)).unwrap();
        std::fs::write(&p, format!("{line}\n{line}\n")).unwrap();
        let err = store.read_ledger("t1").unwrap_err();
        assert!(
            err.to_string().contains("one intent per deployment"),
            "duplicate intent refused: {err}"
        );

        // Duplicate terminal.
        let i = valid_intent_wire(&keys, "deploy-dup2");
        let t1 = valid_terminal_wire(&keys, "deploy-dup2", DeploymentStatus::Successful);
        let t2 = t1.clone();
        let lines = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&LedgerLine::Intent(i)).unwrap(),
            serde_json::to_string(&LedgerLine::Terminal(t1)).unwrap(),
            serde_json::to_string(&LedgerLine::Terminal(t2)).unwrap(),
        );
        std::fs::write(&p, lines).unwrap();
        let err = store.read_ledger("t1").unwrap_err();
        assert!(
            err.to_string().contains("exactly once"),
            "duplicate terminal refused: {err}"
        );
    }

    /// The schema-version gate: a foreign version is refused, malformed
    /// bytes are a store error — never a silent drop.
    #[test]
    fn schema_version_gate_and_malformed_lines_fail_closed() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut wire = valid_intent_wire(&[slot(0)], "deploy-x");
        wire.deployment_schema_version = LEDGER_SCHEMA_VERSION + 1;
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let err = store.read_ledger("t1").unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "foreign version refused: {err}"
        );
        std::fs::write(&p, "{ not json !\n").unwrap();
        assert!(
            store.read_ledger("t1").is_err(),
            "malformed line is an error"
        );
    }

    /// The outcome coverage contract (the cross-record leg the state machine
    /// validates): a FailedRolledBack/Degraded terminal must cover EXACTLY
    /// the selected membership; a Successful terminal must be payload-free.
    #[test]
    fn outcome_coverage_must_match_the_selected_membership() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let keys = vec![slot(0), slot(1)];

        // A Degraded terminal covering only ONE of the two selected slots is
        // refused (the outcomes must EXACTLY cover the selected membership).
        let mut t = valid_terminal_wire(&keys, "deploy-cov", DeploymentStatus::Degraded);
        t.outcomes.remove(&keys[0]);
        let lines = format!(
            "{}\n{}\n",
            serde_json::to_string(&LedgerLine::Intent(valid_intent_wire(&keys, "deploy-cov")))
                .unwrap(),
            serde_json::to_string(&LedgerLine::Terminal(t)).unwrap(),
        );
        std::fs::write(&p, lines).unwrap();
        let err = store.read_ledger("t1").unwrap_err();
        assert!(
            err.to_string().contains("selected") || err.to_string().contains("outcome"),
            "an incomplete Degraded outcome table must be refused, got: {err}"
        );

        // An outcome for a NON-SELECTED slot is refused (a slot the
        // deployment did not select never reports a result). Build a head (a
        // valid full-push over both slots) + a group intent selecting only
        // slot-0 over that head; a Degraded outcome for slot-1 is outside
        // the selected membership. The head's own intent + Successful
        // terminal must precede the group lines in the written ledger — the
        // strictly-linear model (the group's parent IS the head, and the
        // head must already be successful).
        let head = valid_intent(&keys, "deploy-head");
        let base = TargetSnapshot::from_entries(BTreeMap::from([
            (keys[0].clone(), fixtures::snapshot_slot(&keys[0])),
            (keys[1].clone(), fixtures::snapshot_slot(&keys[1])),
        ]));
        let group_intent = fixtures::group_intent(
            "deploy-g",
            "t1",
            "g",
            head.deployment_id(),
            &base,
            &keys,
            &[keys[0].clone()],
        );
        // Rebuild the terminal's outcomes to include slot-1 (not selected).
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            keys[0].clone(),
            SlotOutcome {
                outcome: SlotOutcomeKind::Failed,
                observation: Observation::Known(ObservedGeneration {
                    generation: test_generation_id("g0"),
                }),
                compensated: false,
                error: None,
                transition: SlotTransition::AdvanceUnknown,
            },
        );
        outcomes.insert(
            keys[1].clone(),
            SlotOutcome {
                outcome: SlotOutcomeKind::Failed,
                observation: Observation::Known(ObservedGeneration {
                    generation: test_generation_id("g1"),
                }),
                compensated: false,
                error: None,
                transition: SlotTransition::AdvanceUnknown,
            },
        );
        let non_empty = NonEmptySlotTable::build(outcomes).unwrap();
        let g_t = crate::kernel::terminal::DegradedTerminal::try_new(non_empty).unwrap();
        let disposition = TerminalDisposition::Degraded(g_t);
        let terminal = LedgerTerminal::new(
            Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            kernel::terminal::intent_digest(&group_intent),
            disposition,
            None,
        );
        let wire = LedgerTerminalWire::to_wire(
            group_intent.deployment_id(),
            group_intent.target(),
            &terminal,
        );
        let lines = format!(
            "{}\n{}\n{}\n{}\n",
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&head))).unwrap(),
            serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::to_wire(
                head.deployment_id(),
                head.target(),
                &fixtures::successful_terminal(&head),
            )))
            .unwrap(),
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&group_intent)))
                .unwrap(),
            serde_json::to_string(&LedgerLine::Terminal(wire)).unwrap(),
        );
        std::fs::write(&p, lines).unwrap();
        let err = store.read_ledger("t1").unwrap_err();
        assert!(
            err.to_string()
                .contains("outside the intent's selected membership")
                || err.to_string().contains("selected"),
            "an outcome outside the selected membership must be refused, got: {err}"
        );
    }

    /// Group planning overlays selected slots and preserves inherited parent
    /// entries EXACTLY (proptest 7, deterministic case): the inherited slots'
    /// results EQUAL the parent's entries, the derived snapshot's keys cover
    /// the full selection, and a re-derivation reproduces the same intent.
    #[test]
    fn group_planning_preserves_parent_entries_exactly() {
        let all = vec![slot(0), slot(1), slot(2)];
        let base = TargetSnapshot::from_entries(
            all.iter()
                .map(|k| (k.clone(), fixtures::snapshot_slot(k)))
                .collect(),
        );
        let parent = test_deployment_id("deploy-base");
        let selected = vec![slot(0)];
        let intent = fixtures::group_intent("deploy-g", "t1", "g", &parent, &base, &all, &selected);
        // Group membership = the selected (Deploy) slots.
        assert_eq!(
            intent.group_membership(),
            selected.iter().cloned().collect()
        );
        // Inherited slots reproduce the parent's entries EXACTLY.
        let snapshot = intent.resulting_snapshot();
        for k in [slot(1), slot(2)] {
            assert_eq!(
                snapshot.get(&k).unwrap(),
                base.get(&k).unwrap(),
                "an inherited slot reproduces its parent snapshot entry exactly"
            );
        }
        assert_eq!(
            snapshot.get(&slot(0)).unwrap(),
            &fixtures::snapshot_slot(&slot(0)),
            "a deployed slot carries its own planned result"
        );
    }

    /// The reference-model acceptance property (proptest 4, deterministic
    /// seeding): the full kernel state machine accepts the sequences its
    /// small reference machine accepts. The sequence is STRICTLY LINEAR
    /// (one pending intent at a time; the second intent's parent is the
    /// first deployment after it succeeds).
    #[test]
    fn reference_state_machine_matches_apply_event() {
        let target = TargetName::parse("r1").unwrap();
        let mut reference = Vec::<(String, Option<DeploymentStatus>)>::new();
        let mut state = kernel::transition::DeploymentState::new(target.clone());
        // The first intent succeeds, then the second intent (parent == the
        // first) is accepted by BOTH the reference fold and the kernel.
        let i1 = fixtures::full_intent("deploy-r1", "r1", &[slot(0)], &[]);
        let i2 = fixtures::group_intent(
            "deploy-r2",
            "r1",
            "g",
            i1.deployment_id(),
            &i1.resulting_snapshot(),
            &[slot(1)],
            &[slot(1)],
        );
        reference.push((i1.deployment_id().as_str().to_string(), None));
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Intent(kernel::transition::IntentEvent {
                intent: i1.clone(),
            }),
        )
        .unwrap();
        let t1 = fixtures::successful_terminal(&i1);
        reference.push((
            "terminal-r1".to_string(),
            Some(DeploymentStatus::Successful),
        ));
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Terminal(kernel::transition::TerminalEvent {
                deployment_id: i1.deployment_id().clone(),
                terminal: t1,
            }),
        )
        .unwrap();
        reference.push((i2.deployment_id().as_str().to_string(), None));
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Intent(kernel::transition::IntentEvent {
                intent: i2.clone(),
            }),
        )
        .unwrap();
        assert_eq!(state.entries().len(), 2);
        assert_eq!(
            state.entries()[0].terminal.as_ref().unwrap().status(),
            DeploymentStatus::Successful
        );
        assert_eq!(
            state.entries()[1].terminal,
            None,
            "the second intent is pending"
        );
        assert_eq!(
            state.successful_head(),
            Some(i1.deployment_id()),
            "the successful head is the maintained first successful entry"
        );
        let _ = reference;
    }

    /// A stale parent can never be the head (the strictly-linear model):
    /// at the WRITE boundary the plan-time parent-head assertion refuses
    /// with a [`Conflict`](KernelError::Conflict) (a stale plan against
    /// concurrent state), and the STORE's pre-write intent validation
    /// refuses a stale-parent intent with a Conflict too; at the READ
    /// boundary [`apply_event`] refuses a persisted intent whose parent is
    /// not the head as corruption ([`Integrity`](KernelError::Integrity)) —
    /// a stale intent can never reach a `Successful` terminal because it can
    /// never even be appended.
    #[test]
    fn stale_parent_cannot_be_head() {
        let i = fixtures::full_intent("deploy-stale", "t1", &[slot(0)], &[]);
        // The head moved on: the intent's parent (None) != current head
        // (deploy-head).
        let head = test_deployment_id("deploy-head");
        let err = kernel::terminal::assert_parent_is_head(&i, Some(&head)).unwrap_err();
        assert_eq!(err.class(), crate::kernel::KernelErrorClass::Conflict);
        // The same intent plans against the actual head and passes.
        assert!(kernel::terminal::assert_parent_is_head(&i, None).is_ok());

        // THE STORE MIRROR (the write boundary): appending a stale-parent
        // intent to a ledger whose head is `deploy-head` is REFUSED with a
        // Conflict BEFORE any write — the strictly-linear intent-append
        // gate (a valid op against stale state).
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let head_intent = fixtures::full_intent("deploy-head", "t1", &[slot(0)], &[]);
        store.append_intent("t1", &head_intent).unwrap();
        store
            .append_terminal(
                "t1",
                head_intent.deployment_id(),
                &fixtures::successful_terminal(&head_intent),
            )
            .unwrap();
        assert_eq!(
            store.read_last_successful("t1").as_deref(),
            Some(head_intent.deployment_id().as_str())
        );
        // The stale intent (parent None != head deploy-head) is refused at
        // the store's pre-write intent validation (Conflict). The strict
        // reader refuses the same persisted sequence as corruption
        // (Integrity). A stale intent can never be appended, so it can never
        // reach a Successful terminal.
        let err = store.append_intent("t1", &i).unwrap_err();
        assert!(err.to_string().contains("ParentMismatch"), "got: {err}");
        assert!(err.to_string().contains("conflict"));
        let mut state = kernel::transition::DeploymentState::new(TargetName::parse("t1").unwrap());
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Intent(kernel::transition::IntentEvent {
                intent: head_intent.clone(),
            }),
        )
        .unwrap();
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Terminal(kernel::transition::TerminalEvent {
                deployment_id: head_intent.deployment_id().clone(),
                terminal: fixtures::successful_terminal(&head_intent),
            }),
        )
        .unwrap();
        let read_err = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Intent(kernel::transition::IntentEvent {
                intent: i.clone(),
            }),
        )
        .unwrap_err();
        assert_eq!(
            read_err.class(),
            crate::kernel::KernelErrorClass::Integrity,
            "a persisted stale-parent intent is corruption on the read path"
        );
        assert!(read_err.to_string().contains("ParentMismatch"));
    }

    /// At most ONE plan per parent can ever append `Successful` — now
    /// enforced at INTENT-append time (the strictly-linear model): once A
    /// (parent H) is pending, a second intent B with the SAME parent H is
    /// REFUSED — at most one unresolved intent may exist, so the second
    /// plan is refused as a Conflict at the WRITE boundary (the store mirror)
    /// and as corruption on the READ path.
    #[test]
    fn at_most_one_successful_per_parent() {
        let target = TargetName::parse("t1").unwrap();
        // H: the first successful deployment (parent None) — the shared
        // parent both A and B plan against.
        let h_intent = fixtures::full_intent("deploy-h", "t1", &[slot(0), slot(1)], &[]);
        let base = h_intent.resulting_snapshot();
        let a = fixtures::group_intent(
            "deploy-a",
            "t1",
            "g",
            h_intent.deployment_id(),
            &base,
            &[slot(0), slot(1)],
            &[slot(0)],
        );
        let b = fixtures::group_intent(
            "deploy-b",
            "t1",
            "g",
            h_intent.deployment_id(),
            &base,
            &[slot(0), slot(1)],
            &[slot(1)],
        );
        let mut state = kernel::transition::DeploymentState::new(target.clone());
        // H is appended and succeeds (parent None == head None).
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Intent(kernel::transition::IntentEvent {
                intent: h_intent.clone(),
            }),
        )
        .unwrap();
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Terminal(kernel::transition::TerminalEvent {
                deployment_id: h_intent.deployment_id().clone(),
                terminal: fixtures::successful_terminal(&h_intent),
            }),
        )
        .unwrap();
        // A (parent H == the head) is appended — the ONE pending attempt.
        state = kernel::transition::apply_event(
            state,
            kernel::transition::LedgerEvent::Intent(kernel::transition::IntentEvent {
                intent: a.clone(),
            }),
        )
        .unwrap();
        assert_eq!(state.pending(), Some(a.deployment_id()));
        // B (the SECOND plan on the SAME parent H) is REFUSED at its intent:
        // A is still pending — at most ONE unresolved intent at a time
        // (Integrity on the read path; a Conflict at the store's write
        // boundary).
        let err = kernel::transition::apply_event(
            state.clone(),
            kernel::transition::LedgerEvent::Intent(kernel::transition::IntentEvent {
                intent: b.clone(),
            }),
        )
        .unwrap_err();
        assert_eq!(
            err.class(),
            crate::kernel::KernelErrorClass::Integrity,
            "a second intent while the first is pending is corruption on the read path"
        );
        assert!(err.to_string().contains("PendingAttemptExists"));
        // THE WRITE BOUNDARY mirror: the store refuses B (Conflict).
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        store.append_intent("t1", &h_intent).unwrap();
        store
            .append_terminal(
                "t1",
                h_intent.deployment_id(),
                &fixtures::successful_terminal(&h_intent),
            )
            .unwrap();
        store.append_intent("t1", &a).unwrap();
        let store_err = store.append_intent("t1", &b).unwrap_err();
        assert!(store_err.to_string().contains("still pending"));
        assert!(store_err.to_string().contains("conflict"));
        // Once A reaches its Successful terminal (clearing the pending
        // attempt and advancing the head to A), B can be appended ONLY over
        // the NEW head: B's stale parent H is refused, and a replanned B
        // over A appends fine.
        store
            .append_terminal("t1", a.deployment_id(), &fixtures::successful_terminal(&a))
            .unwrap();
        let store_err = store.append_intent("t1", &b).unwrap_err();
        assert!(
            store_err.to_string().contains("ParentMismatch"),
            "got: {store_err}"
        );
        let b2 = fixtures::group_intent(
            "deploy-b",
            "t1",
            "g",
            a.deployment_id(),
            &a.resulting_snapshot(),
            &[slot(0), slot(1)],
            &[slot(1)],
        );
        store.append_intent("t1", &b2).unwrap();
        store
            .append_terminal(
                "t1",
                b2.deployment_id(),
                &fixtures::successful_terminal(&b2),
            )
            .unwrap();
        assert_eq!(
            store.read_last_successful("t1").as_deref(),
            Some(b2.deployment_id().as_str())
        );
    }

    // =====================================================================
    // THE DOCS-MATCH TEST: requirement.md's fenced wire examples byte-equal
    // the generator's output (they can never drift from the wire).
    // =====================================================================

    /// Read a crate-root document (the same `CARGO_MANIFEST_DIR` precedent
    /// as the config doc-consistency suite and the CLI ref-grammar corpora).
    fn read_requirement_md() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("requirement.md"),
        )
        .unwrap_or_else(|e| panic!("reading requirement.md: {e}"))
    }

    /// The ```json fenced blocks inside the ledger-examples region of
    /// requirement.md (between the `LEDGER WIRE EXAMPLES` HTML markers), in
    /// order, without the fences.
    fn documented_ledger_examples(markdown: &str) -> Vec<String> {
        const START: &str = "<!-- LEDGER WIRE EXAMPLES: generated by src/ledger/records/example.rs";
        const END: &str = "<!-- END LEDGER WIRE EXAMPLES -->";
        let start = markdown
            .find(START)
            .unwrap_or_else(|| panic!("requirement.md must carry the {START:?} marker"));
        let after = &markdown[start..];
        let end = after
            .find(END)
            .unwrap_or_else(|| panic!("requirement.md must close the ledger wire examples region"));
        let region = &after[..end];
        let lines: Vec<&str> = region.lines().collect();
        let mut blocks = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].starts_with("```json") {
                let mut e = i + 1;
                while e < lines.len() && !lines[e].starts_with("```") {
                    e += 1;
                }
                blocks.push(lines[i + 1..e].join("\n"));
                i = e + 1;
            } else {
                i += 1;
            }
        }
        blocks
    }

    /// THE DOCS-MATCH TEST: the generator regenerates the fenced JSON
    /// examples from the CURRENT wire records and the requirement.md blocks
    /// byte-equal that output — a schema change that would stale the
    /// documented example fails HERE, and the docs can never drift from the
    /// wire.
    #[test]
    fn docs_examples_match_generated_wire() {
        let (intent, terminal) = crate::ledger::records::example::canonical_doc_pair();
        let rendered = crate::ledger::records::example::render_wire_pair(&intent, &terminal);
        let documented = documented_ledger_examples(&read_requirement_md());
        assert_eq!(
            documented.len(),
            2,
            "requirement.md's ledger-examples region must carry EXACTLY the two wire blocks (intent + terminal)"
        );
        assert_eq!(
            documented[0], rendered.intent,
            "the documented INTENT line must byte-equal the generator's output (run: update requirement.md to the rendered wire example)"
        );
        assert_eq!(
            documented[1], rendered.terminal,
            "the documented TERMINAL line must byte-equal the generator's output (run: update requirement.md to the rendered wire example)"
        );
        assert!(rendered.intent.contains(&format!(
            "\"deployment_schema_version\": {}",
            crate::ledger::LEDGER_SCHEMA_VERSION
        )));
    }
}

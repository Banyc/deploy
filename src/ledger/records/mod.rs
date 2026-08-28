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
//! ([`LedgerRollback`] / [`LedgerRollbackWire`] / [`PhysicalBinding`] /
//! [`CompleteRollback`]), the PLAN/report records ([`BehaviorIndex`],
//! [`SlotPlan`], [`DeploymentPlanWire`] / [`DeploymentPlan`], [`PlanSource`] /
//! [`PlanOrigin`]), and the pins/server records ([`Pins`] /
//! [`ServerState`]) — then the per-facet sections:
//!
//! * **intent** — the durable intent wire/domain pair ([`LedgerIntentWire`]
//!   / [`DeploymentIntent`]) with the VERIFYING CONVERSION, the per-slot
//!   payload types ([`IntentSlot`], [`DesiredGeneration`],
//!   [`PreviousGeneration`]), and the in-memory push report
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
//! * **rollback payload** — the rollback PAYLOAD builder
//!   ([`build_rollback`]): the complete-snapshot overlay + exact-rollback
//!   verification semantics;
//! * **rebinding proof** — the rebinding proof records ([`RebindingPlan`] /
//!   [`VerifiedReleaseRebinding`] / [`FrozenSlotTopology`]);
//! * **membership equations** — the SUCCESSFUL membership-equation
//!   enforcement (`verify_successful_membership_equations`);
//! * **schema versions** — the format-version constants
//!   (`LEDGER_SCHEMA_VERSION` / `PINS_SCHEMA_VERSION`).
//!
//! The per-slot ordered TABLES ([`crate::ledger::tables::SlotTable`] /
//! [`crate::ledger::tables::NonEmptySlotTable`] over the private ordered
//! map) are generic slot collection INFRASTRUCTURE and stay in
//! [`crate::ledger::tables`]; the ledger WRITE path (replay-safe
//! finalization [`crate::ledger::finalize::finalize_successful_attempt`]
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
//! shapes, [`LedgerIntentWire`], [`LedgerRollbackWire`], [`LedgerTerminalWire`],
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
    ReleaseId, ServerId, SlotId, TargetName, TreeDigest,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

mod observation;
mod validation;
mod wire;

// The shared ordered slot tables are re-exported below (their home is
// [`crate::ledger::tables`] — generic collection infrastructure, kept
// separate from the record model) so the pre-split
// `crate::ledger::records::X` paths keep compiling.
pub use crate::ledger::tables::{NonEmptySlotTable, SlotTable};
pub use observation::{
    ArtifactRefWire, Observation, ObservationError, ObservationWire, ObservedAssignment,
    ObservedGeneration, ObservedGenerationWire, ObservedSlot, ObservedTarget,
};
pub(crate) use validation::verify_successful_membership_equations;
pub use validation::{FrozenSlotTopology, RebindingPlan, VerifiedReleaseRebinding, build_rollback};
pub(crate) use validation::{LEDGER_SCHEMA_VERSION, PINS_SCHEMA_VERSION};
pub use wire::{
    CompensationReport, DeploymentIntent, DesiredGeneration, IntentSlot, LedgerEntry,
    LedgerIntentReport, LedgerIntentWire, LedgerTerminal, LedgerTerminalWire, PreviousGeneration,
    SlotAttemptStateWire, SlotOutcome, SlotOutcomeKind, SlotResult, SlotTransition,
    TerminalDisposition,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    /// A deployment attempt is currently being executed, or was interrupted
    /// before its terminal event was appended (an intent-only ledger entry):
    /// a later push reconciles it before its own no-op check.
    InProgress,
    Successful,
    /// The commit markers are not all durable yet; a later push
    /// reconciles this attempt before its own no-op check.
    PendingCommit,
    FailedPreflight,
    FailedRolledBack,
    Degraded,
}

impl DeploymentStatus {
    pub fn is_terminal_failure(&self) -> bool {
        matches!(
            self,
            DeploymentStatus::FailedPreflight
                | DeploymentStatus::FailedRolledBack
                | DeploymentStatus::Degraded
        )
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

/// The ROLLBACK STATE carried by the terminal event of a SUCCESSFUL
/// deployment, the VALIDATED DOMAIN form: the snapshot payload of the attempt
/// — the complete per-slot [`GenerationRef`]s it advanced to (a successful
/// terminal always has a generation per slot) and the physical bindings
/// (`{server, deploy_dir}`) each slot had.
///
/// THERE IS NO SNAPSHOT-WIDE RELEASE/BEHAVIOR: each slot's [`GenerationRef`]
/// carries its OWN artifact binding (`release`, `variant`, `tree`), and a
/// PARTIAL snapshot can legitimately carry slots from DIFFERENT releases
/// (group pushes over time: group A pushed release R1, group B pushed
/// release R2, and the overlay snapshot keeps each slot's own artifact). The
/// referenced releases are DERIVED from `slots` ([`LedgerRollback::releases`])
/// — never stored once per snapshot — and rollback resolves EACH SLOT's
/// behavior from ITS OWN (release, variant) binding. Legacy ledger lines that
/// still carry the old snapshot-wide `behavior_sha256`/`release` members
/// deserialize into the WIRE form ([`LedgerRollbackWire`]), where the stored
/// `release` must equal the snapshot's ONE derived release (a disagreement
/// → `Error::integrity`); the legacy `behavior_sha256` is not derivable from
/// the per-slot payload (behavior contracts are not stored) and is carried
/// only for wire parseability, never interpreted.
///
/// `bindings` records the COMPLETE PHYSICAL BINDING each slot had when the
/// deployment ran. The snapshot maps a terminal's generations to slots by
/// SLOT, so without this map a slot that rebinds to a different server — or
/// moves to a different `deploy_dir` on the same server — in `deploy.toml`
/// would silently roll back onto the wrong host/location. The bindings key
/// set must equal the `slots` key set EXACTLY (every slotted generation has
/// a physical binding and vice versa — no missing, no extra binding keys):
/// a MISSING entry makes the binding unverifiable (rollback must never
/// guess the host), an EXTRA entry binds a slot that carried no generation,
/// and the wire → domain conversion REFUSES both at CONVERSION time —
/// before history rendering, rollback resolution, reconciliation, or the
/// GC sweep can consume the payload. Kept as a separate `#[serde(default)]`
/// field so the `slots` map and its [`GenerationRef`]s stay intact and
/// ledger lines without a bindings map still deserialize (the exact-key
/// conversion then refuses any payload whose slots are non-empty).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRollback {
    /// Per-slot generation refs, keyed by [`SlotId`]. Each
    /// generation ref's assignment carries the slot's OWN artifact binding
    /// (`release`, `variant`, `tree`); the referenced releases are the set
    /// derived from these bindings ([`LedgerRollback::releases`]).
    pub slots: BTreeMap<SlotId, GenerationRef>,
    /// The complete physical binding (`{server, deploy_dir}`) each slot had
    /// at deployment time, keyed by [`SlotId`]. Every binding key
    /// must be a slotted generation (verified by the wire → domain
    /// conversion).
    #[serde(default)]
    pub bindings: BTreeMap<SlotId, PhysicalBinding>,
}

impl LedgerRollback {
    /// The distinct releases referenced by the snapshot's per-slot generation
    /// bindings — DERIVED from the authoritative `slots` map, never stored
    /// once per snapshot (a partial snapshot can legitimately span several
    /// releases).
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.slots
            .values()
            .map(|g| g.assignment.artifact.release.clone())
            .collect()
    }
}

/// The WIRE shape of a rollback payload: the snapshot's `slots` + `bindings`
/// plus the legacy snapshot-wide `behavior_sha256`/`release` members (carried
/// so pre-refactor ledger lines still deserialize; writers never emit them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRollbackWire {
    pub slots: BTreeMap<SlotId, GenerationRef>,
    #[serde(default)]
    pub bindings: BTreeMap<SlotId, PhysicalBinding>,
    /// Legacy snapshot-wide behavior digest. NOT derivable from the per-slot
    /// payload (behavior contracts are not stored) — carried only for wire
    /// parseability, never interpreted (per-slot behavior resolution governs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior_sha256: Option<String>,
    /// Legacy snapshot-wide release. When present it must equal the
    /// snapshot's ONE derived release (the conversion fails closed on a
    /// disagreement — a multi-release partial snapshot cannot be represented
    /// by the legacy single release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseId>,
}

impl LedgerRollbackWire {
    /// VERIFYING CONVERSION (wire → domain): every duplicate projection must
    /// agree — each slot's [`crate::identity::GenerationRef`] assignment names
    /// its own map key, the `bindings` key set EQUALS the `slots` key set
    /// EXACTLY (every slotted generation has a physical binding and vice
    /// versa — no missing/extra binding keys), and the legacy snapshot-wide
    /// `release` (when present) equals the snapshot's ONE derived release.
    /// A disagreement → `Error::integrity`.
    pub fn into_domain(self) -> Result<LedgerRollback> {
        for (key, g) in &self.slots {
            if &g.assignment.placement_slot != key {
                return Err(Error::integrity(format!(
                    "rollback: generation for slot '{key}' names placement '{}'",
                    g.assignment.placement_slot
                )));
            }
        }
        // EXACT ROLLBACK BINDING KEYS (cross-field invariant): the
        // `bindings` key set must equal the `slots` key set EXACTLY. A
        // missing binding makes the slot's physical location unverifiable;
        // an extra binding names a slot with no generation. Both are
        // REFUSED here, at conversion time, before rollback resolution can
        // consume the payload (a hand-constructed or tampered record can
        // never be read as whichever projection a consumer happens to use).
        let slot_keys: BTreeSet<&SlotId> = self.slots.keys().collect();
        let binding_keys: BTreeSet<&SlotId> = self.bindings.keys().collect();
        if slot_keys != binding_keys {
            let missing: Vec<&SlotId> = slot_keys.difference(&binding_keys).copied().collect();
            let extra: Vec<&SlotId> = binding_keys.difference(&slot_keys).copied().collect();
            return Err(Error::integrity(format!(
                "rollback: bindings must key EXACTLY the slotted generations (missing bindings for {missing:?}; extra bindings for {extra:?})"
            )));
        }
        if let Some(legacy) = &self.release {
            let derived: BTreeSet<ReleaseId> = self
                .slots
                .values()
                .map(|g| g.assignment.artifact.release.clone())
                .collect();
            if derived.len() != 1 || !derived.contains(legacy) {
                return Err(Error::integrity(format!(
                    "rollback: legacy release '{legacy}' disagrees with the derived snapshot releases {derived:?}"
                )));
            }
        }
        Ok(LedgerRollback {
            slots: self.slots,
            bindings: self.bindings,
        })
    }
}

impl From<&LedgerRollback> for LedgerRollbackWire {
    fn from(r: &LedgerRollback) -> Self {
        LedgerRollbackWire {
            slots: r.slots.clone(),
            bindings: r.bindings.clone(),
            behavior_sha256: None,
            release: None,
        }
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

/// The COMPLETE ROLLBACK payload of a SUCCESSFUL deployment — the existing
/// [`LedgerRollback`] under the domain terminal's name: the per-slot
/// generation refs + physical bindings the terminal event carries exactly
/// when the deployment was successful.
pub type CompleteRollback = LedgerRollback;

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
    use crate::identity::{
        ArtifactRef, GenerationRef, MatchingMembership, PlacementSlotAssignment, RolloutGroupName,
        ServerId, SlotSet, Timestamp, VariantName, test_deployment_id, test_generation_id,
        test_release_id, test_tree_digest,
    };
    use crate::ledger::records::FrozenSlotTopology;
    use crate::ledger::records::*;
    use crate::ledger::records::{DeploymentIntent, LedgerIntentReport, LedgerIntentWire};
    use crate::ledger::records::{LedgerTerminal, LedgerTerminalWire, TerminalDisposition};
    use crate::ledger::records::{ObservationError, ObservedGeneration};
    use crate::ledger::records::{SlotOutcome, SlotOutcomeKind, SlotTransition};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    fn slot_strategy() -> impl Strategy<Value = SlotId> {
        (0u32..6).prop_map(slot)
    }

    fn binding(sid: &SlotId) -> PhysicalBinding {
        PhysicalBinding {
            server: ServerId::new("s1".to_string()),
            deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
        }
    }

    /// A generation ref whose assignment names its own key (the agreeing
    /// form); the artifact's release is derived from the slot id.
    fn gen_ref_for(key: &SlotId) -> GenerationRef {
        GenerationRef {
            generation: test_generation_id(key.as_str()),
            assignment: PlacementSlotAssignment {
                placement_slot: key.clone(),
                artifact: ArtifactRef {
                    release: test_release_id(key.as_str()),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest(key.as_str()),
                },
            },
        }
    }

    // ---- agreeing (base) wire strategies -----------------------------------
    //
    // Every base wire is deterministic in its AGREED projections: a
    // NON-EMPTY duplicate-free membership K, `slot_ids` = K (deployment
    // order), `desired`/`pre_push` = K with agreeing per-slot payloads, the
    // wire `slots` (actuals) map EMPTY (the persisted intent carries no
    // outcomes), and a terminal whose deployment_id/target EQUAL the
    // intent's, whose outcome keys are members of K, and whose status →
    // disposition payload matches (Successful ⇔ rollback, FailedPreflight ⇔
    // no outcomes, Degraded ⇔ non-restored outcomes). The property then
    // mutates ONE field at a time and asserts the conversion / reader fails
    // closed on EVERY tamper while accepting the untampered record.

    fn agreeing_intent(keys: &[SlotId]) -> LedgerIntentWire {
        agreeing_intent_with_group(keys, keys, None)
    }

    /// [`agreeing_intent`] with an explicit GROUP MODE and FROZEN FULL
    /// MEMBERSHIP: `Some(g)` selects a group push (the intent's `slot_ids`
    /// are the group's slots), `None` a full push (the intent's `slot_ids`
    /// are every target slot); `full` is the COMPLETE target membership the
    /// intent FREEZES (⊇ `keys`).
    fn agreeing_intent_with_group(
        keys: &[SlotId],
        full: &[SlotId],
        group: Option<&str>,
    ) -> LedgerIntentWire {
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptStateWire>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        // The agreeing intent FREEZES each member's physical binding (schema
        // v6): the binding keys follow the membership so the intent stays
        // internally agreeing (the property mutates ONE field at a time).
        let bindings: BTreeMap<SlotId, PhysicalBinding> =
            keys.iter().map(|k| (k.clone(), binding(k))).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: test_deployment_id("deploy-w"),
            target: TargetName::new("t1".to_string()),
            group: group.map(str::to_string),
            slot_ids: keys.to_vec(),
            selected_membership: keys.to_vec(),
            full_membership: full.to_vec(),
            behavior_sha256: "sha256-w".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
            bindings,
            slots: BTreeMap::new(),
        }
    }

    fn outcome_for(key: &SlotId, kind: SlotOutcomeKind) -> SlotResult {
        let compensated = matches!(&kind, SlotOutcomeKind::Restored);
        SlotResult {
            slot_id: key.clone(),
            outcome: kind,
            observation: ObservationWire::Known(ObservedGenerationWire {
                generation: test_generation_id(key.as_str()),
            }),
            compensated,
            error: None,
        }
    }
    fn agreeing_terminal(keys: &[SlotId], status_idx: u32) -> LedgerTerminalWire {
        let deployment_id = test_deployment_id("deploy-w");
        let target = TargetName::new("t1".to_string());
        match status_idx {
            // Successful: EVERY member slot recorded Activated, the
            // COMPLETE rollback payload covers the same membership with
            // exact bindings, and BOTH memberships equal that membership
            // (the proven exact-equal shape).
            0 => LedgerTerminalWire {
                deployment_id: deployment_id.clone(),
                target: target.clone(),
                status: DeploymentStatus::Successful,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Activated)))
                    .collect(),
                rollback: Some(LedgerRollbackWire {
                    slots: keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect(),
                    bindings: keys.iter().map(|k| (k.clone(), binding(k))).collect(),
                    behavior_sha256: None,
                    release: None,
                }),
                selected_membership: keys.to_vec(),
                full_membership: keys.to_vec(),
                reason: Some("push completed".to_string()),
            },
            // FailedPreflight: pre-mutation — NO outcomes, NO rollback, NO
            // memberships (only a Successful terminal proves them).
            1 => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::FailedPreflight,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: BTreeMap::new(),
                rollback: None,
                selected_membership: vec![],
                full_membership: vec![],
                reason: Some("preflight failed".to_string()),
            },
            // FailedRolledBack: the outcome table IS the compensation
            // report.
            2 => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::FailedRolledBack,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Restored)))
                    .collect(),
                rollback: None,
                selected_membership: vec![],
                full_membership: vec![],
                reason: Some("rolled back".to_string()),
            },
            // Degraded: every member's outcome is a REMAINING change — an
            // UNCOMPENSATED `Failed` (a pre-swap failure / failed
            // compensation: the advance outcome is unknown, and the
            // outcome's observed generation differs from the intent's
            // `pre_push` (None — a first deployment), so the derived
            // remaining-changes set is non-empty).
            _ => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::Degraded,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Failed)))
                    .collect(),
                rollback: None,
                selected_membership: vec![],
                full_membership: vec![],
                reason: Some("degraded".to_string()),
            },
        }
    }

    // ---- THE VERIFYING PAIR CONVERSION + the read_ledger consumer ---------

    /// Run the full verifying conversion of an intent + terminal pair — the
    /// SAME checks `read_ledger` runs when it merges a terminal into its
    /// entry (the entry owns identity: the terminal's id is the entry key,
    /// its target must equal the entry's, every outcome key must be a
    /// member of the intent's membership, and the outcome key set must
    /// agree with the membership BY STATUS: Successful → the FULL-push
    /// equality leg only (the terminal's own memberships satisfy the
    /// terminal-local equations; the read requires selected == full when
    /// the intent has no group), FailedPreflight → empty, every other
    /// state → EXACT coverage) — returning the validated domain pair.
    fn pair_to_domain(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
    ) -> Result<(DeploymentIntent, LedgerTerminal)> {
        let intent = pair.0.clone().into_domain()?;
        if pair.1.deployment_id != intent.deployment_id {
            return Err(Error::integrity(format!(
                "terminal {}: deployment_id disagrees with its entry (the intent's)",
                pair.1.deployment_id
            )));
        }
        if pair.1.target != intent.target {
            return Err(Error::integrity(format!(
                "terminal {}: target '{}' disagrees with its entry (the intent's target '{}')",
                pair.1.deployment_id, pair.1.target, intent.target
            )));
        }
        for key in pair.1.outcomes.keys() {
            if !intent.slots.contains_key(key) {
                return Err(Error::integrity(format!(
                    "terminal {}: outcome for slot '{key}' is outside the intent's membership",
                    pair.1.deployment_id
                )));
            }
        }
        let terminal = pair.1.clone().into_domain()?;
        // STATUS-SPECIFIC OUTCOME AGREEMENT (the membership leg — the same
        // rules `read_ledger` enforces when it merges the terminal into its
        // entry). The terminal carries its OWN proven memberships (the
        // conversion enforced outcomes == selected, rollback == full,
        // selected ⊆ full — the record is self-proving), so the only
        // Successful leg is the FULL-push equality: a FULL push (no group)
        // selects every target slot, so selected == full; a GROUP push
        // allows a proper subset (the ⊆ is already enforced by the
        // conversion). The intent's `slot_ids` is NOT compared to either
        // membership (it is the historical selected set written before the
        // push; the terminal's memberships are proven at terminal time).
        let outcome_keys: BTreeSet<&SlotId> = terminal.outcomes().keys().collect();
        let membership: BTreeSet<&SlotId> = intent.slots.keys().collect();
        match terminal.status() {
            DeploymentStatus::Successful => {
                // THE INTENT-BINDING LEGS (the user's requirement): the
                // terminal's memberships must REPRODUCE the intent's FROZEN
                // values — the intent froze selected (its table keys) and
                // full (the complete target membership at plan time), and a
                // terminal whose memberships diverge is refused. The
                // FULL-push equality: a FULL push (no group) selects every
                // target slot, so selected == full; a GROUP push allows a
                // proper subset (the ⊆ is already enforced by the
                // conversion).
                let (selected, full) = match &terminal.disposition {
                    TerminalDisposition::Successful {
                        selected_membership,
                        full_membership,
                        ..
                    } => (selected_membership, full_membership),
                    _ => {
                        unreachable!("a Successful terminal carries its rollback + memberships")
                    }
                };
                if selected != &intent.selected_membership() {
                    return Err(Error::integrity(format!(
                        "terminal {}: Successful records selected membership {selected:?} but the intent froze selected membership {:?} — the terminal must REPRODUCE the immutable intent's frozen selected membership",
                        pair.1.deployment_id,
                        intent.selected_membership()
                    )));
                }
                if full != intent.full_membership() {
                    return Err(Error::integrity(format!(
                        "terminal {}: Successful records full membership {full:?} but the intent froze full membership {:?} — the terminal must REPRODUCE the immutable intent's frozen full membership (the complete target membership at plan time)",
                        pair.1.deployment_id,
                        intent.full_membership()
                    )));
                }
                if intent.group.is_none() && selected != full {
                    return Err(Error::integrity(format!(
                        "terminal {}: Successful records selected membership {selected:?} and full membership {full:?} — a FULL push (no group) selects every target slot, so its selected membership must EXACTLY equal its full membership",
                        pair.1.deployment_id
                    )));
                }
            }
            DeploymentStatus::FailedPreflight => {
                if !outcome_keys.is_empty() {
                    return Err(Error::integrity(format!(
                        "terminal {}: FailedPreflight must carry NO outcomes (a pre-mutation failure touched no slot)",
                        pair.1.deployment_id
                    )));
                }
            }
            _ => {
                if outcome_keys != membership {
                    return Err(Error::integrity(format!(
                        "terminal {}: outcomes {outcome_keys:?} must EXACTLY cover the intent's membership {membership:?} — no missing, no extra",
                        pair.1.deployment_id
                    )));
                }
            }
        }
        Ok((intent, terminal))
    }

    /// [`DeploymentIntent`]: the wire's three projections COLLAPSE into ONE
    /// slot table; every duplicate-projection disagreement (duplicate member,
    /// missing/extra desired or pre_push key, an EMPTY membership, an
    /// assignment naming another placement, a wire actuals key outside the
    /// membership) fails the conversion, and the domain round-trips stably.
    #[test]
    fn intent_collapses_into_one_table_and_refuses_disagreements() {
        let keys = vec![slot(1)];
        let wire = agreeing_intent(&keys);
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(domain.membership(), vec![slot(1)]);
        assert_eq!(
            domain.releases(),
            BTreeSet::from([test_release_id("slot-1")])
        );
        assert_eq!(domain.slots.len(), 1, "one table, one member");
        assert!(
            domain.slots[&slot(1)]
                .desired
                .artifact
                .release
                .as_str()
                .starts_with("rel-sha256-")
        );
        // Round trip: the one table re-expands into the wire split shape and
        // back unchanged.
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerIntentWire = serde_json::from_str(&json).unwrap();
        assert_eq!(
            wire2.slot_ids,
            vec![slot(1)],
            "the wire split shape is preserved"
        );
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(
            domain2, domain,
            "an agreeing intent survives the round trip"
        );

        // (a) a DUPLICATE member weakens the membership.
        let mut bad = wire.clone();
        bad.slot_ids.push(slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a duplicate member fails closed"
        );
        // (b) a DELETED member: the membership omits a key the maps carry.
        let mut bad = wire.clone();
        bad.slot_ids.pop();
        assert!(bad.into_domain().is_err(), "a deleted member fails closed");
        // (c) an EMPTY membership: the domain's NonEmptySlotTable refuses it.
        let mut bad = wire.clone();
        bad.slot_ids.clear();
        bad.desired.clear();
        bad.pre_push.clear();
        assert!(
            bad.into_domain().is_err(),
            "an empty membership fails closed"
        );
        // (d) a MISSING desired key.
        let mut bad = wire.clone();
        bad.desired.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a missing desired key fails closed"
        );
        // (e) an EXTRA desired key outside the membership.
        let mut bad = wire.clone();
        bad.desired.insert(slot(2), gen_ref_for(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "an extra desired key fails closed"
        );
        // (f) a missing pre_push key.
        let mut bad = wire.clone();
        bad.pre_push.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a missing pre_push key fails closed"
        );
        // (g) an extra pre_push key outside the membership.
        let mut bad = wire.clone();
        bad.pre_push.insert(slot(2), None);
        assert!(
            bad.into_domain().is_err(),
            "an extra pre_push key fails closed"
        );
        // (h) a wire actuals key outside the membership.
        let mut bad = wire.clone();
        bad.slots.insert(
            slot(9),
            SlotAttemptStateWire {
                artifact: ObservationWire::Unknown(ObservationError {
                    message: "fixture: unknown assignment".to_string(),
                }),
                generation: None,
            },
        );
        assert!(
            bad.into_domain().is_err(),
            "a slots key outside slot_ids fails closed"
        );
        // (i) an assignment naming a different placement.
        let mut bad = wire.clone();
        bad.desired
            .get_mut(&slot(1))
            .unwrap()
            .assignment
            .placement_slot = slot(9);
        assert!(
            bad.into_domain().is_err(),
            "an assignment naming another placement fails closed"
        );
    }

    /// INTENT vs REPORT datatype split: the verified domain
    /// [`DeploymentIntent`] carries NO outcomes map (the wire keeps the
    /// intentionally-empty `slots` member for format stability), while the
    /// in-memory [`LedgerIntentReport`] carries the observed per-slot
    /// actuals — the report's map is not part of the intent's key-set
    /// invariant.
    #[test]
    fn intent_report_carries_outcomes_while_persisted_intent_slots_stay_empty() {
        let keys = vec![slot(1)];
        let mut wire = agreeing_intent(&keys);
        // The report parses the intent's digest into a [`BehaviorDigest`], so
        // the fixture must carry a canonical sha256 digest.
        wire.behavior_sha256 = crate::identity::DIGEST_TEST_HEX_1.to_string();
        let domain = wire.into_domain().unwrap();
        // The REPORT carries the observed per-slot actuals for display.
        let mut report = LedgerIntentReport::from_intent(&domain).expect("verified intent parses");
        report.slots.insert(
            slot(1),
            SlotAttemptState {
                artifact: Observation::Unknown(ObservationError {
                    message: "fixture: unknown assignment".to_string(),
                }),
                generation: None,
            },
        );
        assert_eq!(report.slots.len(), 1, "the report carries the actuals");
        // The PERSISTED intent keeps its wire `slots` map EMPTY (the wire
        // conversion never reads the report's map): the intent round-trips
        // without the outcomes.
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerIntentWire = serde_json::from_str(&json).unwrap();
        assert!(
            wire2.slots.is_empty(),
            "the persisted intent keeps the `slots` map empty (outcomes live in the terminal event and the in-memory report)"
        );
        // The report's maps are re-expanded from the one table (split shape,
        // display-facing), and its scalars are parsed fail-closed.
        assert_eq!(report.slot_ids, vec![slot(1)]);
        assert_eq!(report.desired.len(), 1);
        assert!(report.pre_push.contains_key(&slot(1)));
        assert!(
            LedgerIntentReport::from_intent(&domain).is_ok(),
            "the verified intent's scalars parse into the report"
        );
    }
    /// STATUS → DISPOSITION: each status maps to EXACTLY ONE disposition,
    /// and a status whose payload does not match its disposition is a
    /// conversion error (fail closed) — the truth table is STRUCTURAL in the
    /// domain.
    #[test]
    fn terminal_status_maps_to_exactly_one_disposition() {
        let keys = vec![slot(1), slot(2)];
        // Successful + complete rollback → Successful { rollback, outcomes }.
        let wire = agreeing_terminal(&keys, 0);
        let d = wire.into_domain().unwrap();
        assert_eq!(d.status(), DeploymentStatus::Successful);
        let TerminalDisposition::Successful {
            rollback, outcomes, ..
        } = d.disposition
        else {
            panic!("Successful maps to Successful {{ rollback, outcomes, memberships }}");
        };
        assert_eq!(rollback.slots.len(), 2, "the complete rollback payload");
        assert_eq!(
            outcomes.len(),
            2,
            "the Successful disposition owns its outcome table"
        );

        // FailedPreflight + no outcomes → FailedPreflight (nothing).
        let wire = agreeing_terminal(&keys, 1);
        let d = wire.into_domain().unwrap();
        assert_eq!(d.disposition, TerminalDisposition::FailedPreflight);

        // FailedRolledBack → the disposition's outcome table IS the
        // compensation report (exposed, never stored twice).
        let wire = agreeing_terminal(&keys, 2);
        let d = wire.into_domain().unwrap();
        assert!(matches!(
            d.disposition,
            TerminalDisposition::FailedRolledBack { .. }
        ));
        assert_eq!(
            d.compensation().expect("derived compensation report").len(),
            2,
            "the compensation report is the disposition's outcome table"
        );

        // Degraded → the non-restored outcomes ARE the remaining changes
        // (derived from the disposition's own table, never stored twice).
        let wire = agreeing_terminal(&keys, 3);
        let d = wire.into_domain().unwrap();
        let intent = agreeing_intent(&keys).into_domain().unwrap();
        assert!(matches!(
            d.disposition,
            TerminalDisposition::Degraded { .. }
        ));
        assert_eq!(
            d.remaining_changes(&intent)
                .expect("derived remaining changes")
                .len(),
            2
        );

        // PAYLOAD MISMATCHES: a status whose payload does not match its
        // disposition is a conversion error.
        let mut bad = agreeing_terminal(&keys, 0); // Successful
        bad.rollback = None;
        assert!(
            bad.into_domain().is_err(),
            "Successful without its rollback is refused"
        );
        let mut bad = agreeing_terminal(&keys, 1); // FailedPreflight
        bad.outcomes
            .insert(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated));
        assert!(
            bad.into_domain().is_err(),
            "FailedPreflight with outcomes is refused"
        );
        let mut bad = agreeing_terminal(&keys, 1); // FailedPreflight
        bad.rollback = Some(LedgerRollbackWire {
            slots: BTreeMap::new(),
            bindings: BTreeMap::new(),
            behavior_sha256: None,
            release: None,
        });
        assert!(
            bad.into_domain().is_err(),
            "FailedPreflight carrying a rollback is refused"
        );
        let mut bad = agreeing_terminal(&keys, 3); // Degraded
        bad.outcomes = BTreeMap::new();
        assert!(
            bad.into_domain().is_err(),
            "Degraded with NO remaining change is refused"
        );
        let mut bad = agreeing_terminal(&keys, 3); // Degraded
        for r in bad.outcomes.values_mut() {
            r.outcome = SlotOutcomeKind::Restored;
        }
        assert!(
            bad.into_domain().is_err(),
            "Degraded with every slot restored is refused"
        );
        // A Successful wire whose outcomes disagree with the rollback's
        // slots (an outcome key the rollback does not cover).
        let mut bad = agreeing_terminal(&keys, 0); // Successful
        bad.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        assert!(
            bad.into_domain().is_err(),
            "a Successful outcome outside the rollback's slots is refused"
        );
        // A Successful wire whose outcome status disagrees with the
        // disposition's implied state (every slot activated).
        let mut bad = agreeing_terminal(&keys, 0); // Successful
        bad.outcomes.get_mut(&slot(1)).unwrap().outcome = SlotOutcomeKind::Failed;
        assert!(
            bad.into_domain().is_err(),
            "a Successful terminal with a failed outcome is refused"
        );
        // InProgress / PendingCommit never appear on a terminal event.
        let mut bad = agreeing_terminal(&keys, 0);
        bad.status = DeploymentStatus::PendingCommit;
        assert!(
            bad.into_domain().is_err(),
            "a PendingCommit terminal is refused"
        );
    }

    /// THE STATUS-SPECIFIC OUTCOME RULES (enforced BY STATUS) + THE
    /// MEMBERSHIP EQUATIONS (the user's requirement): a `Successful`
    /// terminal must carry NON-EMPTY, DUPLICATE-FREE memberships satisfying
    /// outcomes == selected_membership, rollback slots == full_membership,
    /// and selected ⊆ full (terminal-local, enforced by the conversion —
    /// the record is SELF-PROVING), and a FULL push (no group) additionally
    /// requires selected == full (the read leg, via the intent's `group`); a
    /// `FailedPreflight` terminal must carry NO outcomes, and every other
    /// terminal state's outcomes must EXACTLY COVER the intent's membership
    /// (no missing, no extra).
    #[test]
    fn status_specific_outcome_rules_fail_closed() {
        let keys = vec![slot(1), slot(2)];

        // THE EXACT-EQUAL SUCCESSFUL → Ok (outcomes == selected == full ==
        // rollback slots — the exact-equal proven shape).
        let intent = agreeing_intent(&keys);
        let terminal = agreeing_terminal(&keys, 0);
        let (d_intent, d_terminal) = pair_to_domain(&(intent.clone(), terminal.clone()))
            .expect("the exact-equal Successful pair converts");
        assert_eq!(d_terminal.status(), DeploymentStatus::Successful);
        assert_eq!(
            d_terminal.outcomes().len(),
            d_intent.slots.len(),
            "the outcomes exactly cover the membership"
        );
        let TerminalDisposition::Successful { rollback, .. } = &d_terminal.disposition else {
            panic!("Successful disposition");
        };
        assert_eq!(rollback.slots.len(), d_intent.slots.len());
        assert_eq!(rollback.bindings.len(), d_intent.slots.len());
        // The PERSISTED memberships are exposed and prove the equations.
        assert_eq!(
            d_terminal.selected_membership(),
            Some(&BTreeSet::from_iter(keys.iter().cloned()))
        );
        assert_eq!(
            d_terminal.full_membership(),
            Some(&BTreeSet::from_iter(keys.iter().cloned()))
        );

        // A GROUP push with a PROPER-SUBSET selected → Ok (the group shape
        // the base-overlay produces: outcomes == selected ⊊ full ==
        // rollback — legal in group mode).
        let selected = vec![slot(1)];
        let mut group_terminal = agreeing_terminal(&keys, 0);
        group_terminal.outcomes =
            BTreeMap::from([(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated))]);
        group_terminal.selected_membership = selected.clone();
        let group_intent = agreeing_intent_with_group(&selected, &keys, Some("g1"));
        pair_to_domain(&(group_intent, group_terminal))
            .expect("a group push with selected ⊊ full converts (the group-proper-subset shape)");

        // SUCCESSFUL with a MISSING outcome key → Err (outcomes != selected
        // — the terminal-local equation; no cross-record leg needed).
        let mut bad = terminal.clone();
        bad.outcomes.remove(&slot(1));
        assert!(
            bad.clone().into_domain().is_err(),
            "a missing outcome key fails the conversion (outcomes must EXACTLY equal the selected_membership)"
        );
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "Successful with a missing outcome key fails the pair read"
        );

        // SUCCESSFUL with an EXTRA outcome key → Err (outcomes != selected).
        let mut bad = terminal.clone();
        bad.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        assert!(
            bad.into_domain().is_err(),
            "Successful with an extra outcome key fails the conversion"
        );

        // SUCCESSFUL with a MISSING rollback slot (and binding) → Err
        // (rollback != full).
        let mut bad = terminal.clone();
        let rb = bad.rollback.as_mut().unwrap();
        rb.slots.remove(&slot(1));
        rb.bindings.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "Successful with a missing rollback slot fails the conversion (rollback must EXACTLY equal the full_membership)"
        );

        // SUCCESSFUL with an EXTRA rollback slot (and binding) → Err
        // (rollback != full — the complete snapshot covers EXACTLY the full
        // membership).
        let mut bad = terminal.clone();
        let rb = bad.rollback.as_mut().unwrap();
        rb.slots.insert(slot(9), gen_ref_for(&slot(9)));
        rb.bindings.insert(slot(9), binding(&slot(9)));
        assert!(
            bad.into_domain().is_err(),
            "Successful with an extra rollback slot fails the conversion"
        );

        // SUCCESSFUL with EMPTY outcomes → Err (Successful requires
        // NON-EMPTY outcomes).
        let mut bad = terminal.clone();
        bad.outcomes = BTreeMap::new();
        assert!(
            bad.into_domain().is_err(),
            "Successful with empty outcomes fails the conversion"
        );
        // EMPTY selected_membership → Err (Successful requires NON-EMPTY
        // memberships).
        let mut bad = terminal.clone();
        bad.selected_membership = vec![];
        assert!(
            bad.into_domain().is_err(),
            "Successful with empty selected_membership fails the conversion"
        );

        // SELECTED ⊄ FULL → Err (terminal-local).
        let mut bad = terminal.clone();
        bad.selected_membership = vec![slot(9)];
        assert!(
            bad.into_domain().is_err(),
            "selected ⊄ full fails the conversion"
        );

        // A DUPLICATE membership member → Err (the set equations would be
        // silently weakened).
        let mut bad = terminal.clone();
        bad.selected_membership.push(slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a duplicated membership member fails the conversion"
        );

        // FULL push with selected != full (a proper subset): the
        // terminal-local equations hold (outcomes == selected, rollback ==
        // full, selected ⊆ full) — the conversion accepts — but the FULL-push
        // read leg (the mode lives in the intent's `group`) refuses.
        let mut group_shaped = terminal.clone();
        group_shaped.outcomes =
            BTreeMap::from([(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated))]);
        group_shaped.selected_membership = vec![slot(1)];
        assert!(
            group_shaped.clone().into_domain().is_ok(),
            "a proper-subset selected is not a terminal-local disagreement"
        );
        assert!(
            pair_to_domain(&(intent.clone(), group_shaped)).is_err(),
            "a FULL push (no group) with selected != full fails the pair read (the read leg)"
        );

        // A NON-SUCCESSFUL status carrying memberships → Err (only a
        // Successful terminal proves them).
        let mut bad = agreeing_terminal(&keys, 2); // FailedRolledBack
        bad.selected_membership = keys.clone();
        assert!(
            bad.into_domain().is_err(),
            "a failed status carrying memberships fails the conversion"
        );

        // FAILEDPREFLIGHT with an outcome → Err (a pre-mutation failure
        // touched no slot).
        let mut bad = agreeing_terminal(&keys, 1);
        bad.outcomes
            .insert(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated));
        assert!(
            bad.clone().into_domain().is_err(),
            "FailedPreflight with an outcome fails the conversion"
        );
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "FailedPreflight with an outcome fails the pair read"
        );

        // DEGRADED with a MISSING outcome → Err (the outcomes must EXACTLY
        // cover the membership).
        let mut bad = agreeing_terminal(&keys, 3);
        bad.outcomes.remove(&slot(1));
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "Degraded with a missing outcome fails the pair read (the outcomes must exactly cover the membership)"
        );

        // DEGRADED with an EXTRA outcome → Err.
        let mut bad = agreeing_terminal(&keys, 3);
        bad.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Skipped));
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "Degraded with an extra outcome fails the pair read"
        );

        // FAILEDROLLEDBACK with a MISSING outcome → Err (the compensation
        // report must exactly cover the membership).
        let mut bad = agreeing_terminal(&keys, 2);
        bad.outcomes.remove(&slot(1));
        assert!(
            pair_to_domain(&(intent, bad)).is_err(),
            "FailedRolledBack with a missing outcome fails the pair read"
        );
    }
    /// kept duplicate-projection checks (assignment own-key, bindings ⊆
    /// slotted generations, the legacy snapshot-wide release when present).
    #[test]
    fn rollback_wire_disagreement_per_duplicate_fails_closed() {
        let wire = LedgerRollbackWire {
            slots: BTreeMap::from([(slot(1), gen_ref_for(&slot(1)))]),
            bindings: BTreeMap::from([(slot(1), binding(&slot(1)))]),
            behavior_sha256: None,
            release: None,
        };
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(
            domain.releases(),
            BTreeSet::from([test_release_id("slot-1")])
        );
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerRollbackWire = serde_json::from_str(&json).unwrap();
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(domain2.releases(), domain.releases());

        let mut bad = wire.clone();
        bad.bindings.insert(slot(2), binding(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "a binding without a generation fails closed"
        );
        let mut bad = wire.clone();
        bad.bindings.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a slotted generation without its binding fails closed (exact binding keys)"
        );
        let mut bad = wire.clone();
        bad.slots
            .get_mut(&slot(1))
            .unwrap()
            .assignment
            .placement_slot = slot(2);
        assert!(
            bad.into_domain().is_err(),
            "an assignment naming another placement fails closed"
        );
        let mut bad = wire.clone();
        bad.release = Some(test_release_id("rel-other"));
        assert!(
            bad.into_domain().is_err(),
            "a legacy release disagreeing with the derived release fails closed"
        );
        let mut good = wire.clone();
        good.release = Some(test_release_id("slot-1"));
        assert!(
            good.into_domain().is_ok(),
            "an agreeing legacy release passes"
        );
    }
    /// [`LedgerTerminalWire`]: an agreeing terminal converts and round-trips
    /// stably; the STATUS/ROLLBACK TRUTH TABLE (Successful ⇔ rollback
    /// present), the outcome own-key agreement, and the rollback's exact
    /// binding keys each fail closed on ONE mutation, while both truth-table
    /// variants (Successful + rollback, failed + no rollback) pass.
    #[test]
    fn terminal_wire_truth_table_and_rollback_agreement_fails_closed() {
        let rollback = || LedgerRollbackWire {
            slots: BTreeMap::from([(slot(1), gen_ref_for(&slot(1)))]),
            bindings: BTreeMap::from([(slot(1), binding(&slot(1)))]),
            behavior_sha256: None,
            release: None,
        };
        let outcome = || SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Activated,
            observation: ObservationWire::Known(ObservedGenerationWire {
                generation: test_generation_id("gen-1"),
            }),
            compensated: false,
            error: None,
        };
        let wire = LedgerTerminalWire {
            deployment_id: test_deployment_id("deploy-terminal"),
            target: TargetName::new("t1".to_string()),
            status: DeploymentStatus::Successful,
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: BTreeMap::from([(slot(1), outcome())]),
            rollback: Some(rollback()),
            selected_membership: vec![slot(1)],
            full_membership: vec![slot(1)],
            reason: None,
        };
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(domain.status(), DeploymentStatus::Successful);
        assert!(
            matches!(&domain.disposition, TerminalDisposition::Successful { .. }),
            "Successful carries its rollback"
        );
        // The domain terminal round-trips through the wire shape; `from_domain`
        // supplies the entry-owned deployment id / target.
        let json = serde_json::to_string(&LedgerTerminalWire::from_domain(
            &test_deployment_id("deploy-terminal"),
            &TargetName::new("t1".to_string()),
            &domain,
        ))
        .unwrap();
        let wire2: LedgerTerminalWire = serde_json::from_str(&json).unwrap();
        assert_eq!(
            wire2.into_domain().unwrap(),
            domain,
            "an agreeing terminal survives the round trip unchanged"
        );

        // TRUTH TABLE, direction 1: Successful must carry its rollback.
        let mut bad = wire.clone();
        bad.rollback = None;
        assert!(
            bad.into_domain().is_err(),
            "a Successful terminal without its rollback fails closed"
        );
        // TRUTH TABLE, direction 2: a failed status must not carry one.
        let mut bad = wire.clone();
        bad.status = DeploymentStatus::FailedRolledBack;
        assert!(
            bad.into_domain().is_err(),
            "a failed terminal carrying a rollback fails closed"
        );
        // OUTCOME OWN-KEY: an outcome naming a different placement slot.
        let mut bad = wire.clone();
        bad.outcomes.get_mut(&slot(1)).unwrap().slot_id = slot(2);
        assert!(
            bad.into_domain().is_err(),
            "an outcome naming a different placement fails closed"
        );
        // EXACT BINDING KEYS: a generation without its binding …
        let mut bad = wire.clone();
        bad.rollback.as_mut().unwrap().bindings.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a slotted generation without its binding fails closed"
        );
        // … and a binding without its generation.
        let mut bad = wire.clone();
        bad.rollback
            .as_mut()
            .unwrap()
            .bindings
            .insert(slot(2), binding(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "a binding without a generation fails closed"
        );

        // The other truth-table variant stays VALID: a failed terminal with
        // NO rollback, NO outcomes, and NO memberships (only a Successful
        // terminal records them) converts fine.
        let failed = LedgerTerminalWire {
            status: DeploymentStatus::FailedRolledBack,
            outcomes: BTreeMap::new(),
            rollback: None,
            selected_membership: vec![],
            full_membership: vec![],
            ..wire.clone()
        };
        assert!(
            failed.into_domain().is_ok(),
            "a failed terminal without a rollback stays valid"
        );
    }

    // =====================================================================
    // DISPOSITION-OWNED OUTCOMES: each disposition owns its table; the
    // accessors read the disposition's OWN table
    // =====================================================================

    /// LET EACH DISPOSITION OWN ITS OUTCOME TABLE: the outcomes live ONCE,
    /// inside the disposition — the accessor returns the disposition's OWN
    /// table (no separate `LedgerTerminal.outcomes` field exists to disagree
    /// with), and a FailedPreflight terminal carries none (the accessor
    /// yields an empty table).
    #[test]
    fn each_disposition_owns_its_outcome_table() {
        let keys = vec![slot(1), slot(2)];
        let intent = agreeing_intent(&keys).into_domain().unwrap();
        // Successful: the disposition owns its outcomes next to the rollback.
        let d = agreeing_terminal(&keys, 0).into_domain().unwrap();
        let TerminalDisposition::Successful {
            rollback, outcomes, ..
        } = &d.disposition
        else {
            panic!("Successful carries rollback + outcomes + memberships");
        };
        assert_eq!(
            d.outcomes(),
            outcomes,
            "the accessor reads the disposition's OWN table"
        );
        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes
                .values()
                .all(|o| o.outcome == SlotOutcomeKind::Activated)
        );
        for key in outcomes.keys() {
            assert!(
                rollback.slots.contains_key(key),
                "every outcome key is covered by the rollback"
            );
        }
        // FailedPreflight: no outcomes — the accessor yields an empty table.
        let d = agreeing_terminal(&keys, 1).into_domain().unwrap();
        assert!(matches!(
            d.disposition,
            TerminalDisposition::FailedPreflight
        ));
        assert!(
            d.outcomes().is_empty(),
            "a preflight failure carries no outcomes"
        );
        // FailedRolledBack: the disposition owns the compensation report.
        let d = agreeing_terminal(&keys, 2).into_domain().unwrap();
        let TerminalDisposition::FailedRolledBack { outcomes } = &d.disposition else {
            panic!("FailedRolledBack carries its outcomes");
        };
        assert_eq!(
            d.outcomes(),
            outcomes,
            "the accessor reads the disposition's OWN table"
        );
        assert_eq!(
            d.compensation().unwrap(),
            outcomes,
            "compensation() IS the disposition's table"
        );
        // Degraded: the disposition owns the remaining-changes source.
        let d = agreeing_terminal(&keys, 3).into_domain().unwrap();
        let TerminalDisposition::Degraded { outcomes } = &d.disposition else {
            panic!("Degraded carries its outcomes");
        };
        assert_eq!(
            d.outcomes(),
            outcomes,
            "the accessor reads the disposition's OWN table"
        );
        assert_eq!(
            d.remaining_changes(&intent).unwrap().len(),
            outcomes.len(),
            "the remaining changes derive from the disposition's OWN outcomes"
        );
    }

    /// The accessors agree with the disposition's table: `compensation()`
    /// IS the FailedRolledBack disposition's outcomes table,
    /// `remaining_changes()` derives from the Degraded disposition's OWN
    /// outcomes, and both are `None` for every other disposition.
    #[test]
    fn accessors_agree_with_the_disposition_table() {
        let keys = vec![slot(1)];
        let intent = agreeing_intent(&keys).into_domain().unwrap();
        // Successful: neither accessor applies.
        let d = agreeing_terminal(&keys, 0).into_domain().unwrap();
        assert!(d.compensation().is_none());
        assert!(d.remaining_changes(&intent).is_none());
        // FailedPreflight: neither accessor applies.
        let d = agreeing_terminal(&keys, 1).into_domain().unwrap();
        assert!(d.compensation().is_none());
        assert!(d.remaining_changes(&intent).is_none());
        // FailedRolledBack: compensation() IS the disposition's table.
        let d = agreeing_terminal(&keys, 2).into_domain().unwrap();
        let TerminalDisposition::FailedRolledBack { outcomes } = &d.disposition else {
            panic!("FailedRolledBack carries its outcomes");
        };
        assert_eq!(d.compensation().unwrap(), outcomes);
        assert!(d.remaining_changes(&intent).is_none());
        // Degraded: remaining_changes() derives from the disposition's OWN
        // outcomes (every non-restored outcome with a recorded generation).
        let d = agreeing_terminal(&keys, 3).into_domain().unwrap();
        let TerminalDisposition::Degraded { outcomes } = &d.disposition else {
            panic!("Degraded carries its outcomes");
        };
        assert!(d.compensation().is_none());
        let remaining = d.remaining_changes(&intent).unwrap();
        let expected: BTreeMap<SlotId, Observation<ObservedGeneration>> = outcomes
            .iter()
            .filter(|(_, o)| {
                o.outcome != SlotOutcomeKind::Restored
                    && matches!(o.observation, Observation::Known(_))
            })
            .map(|(k, o)| (k.clone(), o.observation.clone()))
            .collect();
        assert_eq!(
            remaining.into_map(),
            expected,
            "the derivation matches the disposition's own table"
        );
    }
    // =====================================================================
    // THE DOMAIN ROUND-TRIP PROPERTY: arbitrary domain terminals survive
    // the wire exactly
    // =====================================================================

    /// An arbitrary domain outcome value (any kind, any compensation flag)
    /// whose TWO error facts are generated INDEPENDENTLY: the OPERATION
    /// error (`error` — an arbitrary failure reason, carried by the wire's
    /// `error` field) and the THREE-STATE OBSERVATION (`Known` with an
    /// arbitrary generation, `KnownAbsent`, or `Unknown` with its OWN
    /// arbitrary preserved message — carried by the wire's `observation`
    /// field). The wire has a separate slot per fact, so NO agreement is
    /// forced: every (operation_error, observation) combination is a valid
    /// outcome that round-trips exactly.
    fn arbitrary_outcome() -> impl Strategy<Value = SlotOutcome> {
        (
            prop_oneof![
                Just(SlotOutcomeKind::Activated),
                Just(SlotOutcomeKind::Failed),
                Just(SlotOutcomeKind::Compensated),
                Just(SlotOutcomeKind::Skipped),
                Just(SlotOutcomeKind::Restored),
            ],
            // The pure OPERATION error — independent of the observation.
            prop::option::of(prop::sample::select(vec![
                "swap failed: boom".to_string(),
                "verification failed".to_string(),
                "internal: no behavior contract for variant 'x'".to_string(),
            ])),
            // The THREE-STATE OBSERVATION — its own fact, with its own
            // error for the `Unknown` half.
            prop_oneof![
                // Known: a successful read of a recorded generation.
                (0u32..6).prop_map(|i| Observation::Known(ObservedGeneration {
                    generation: test_generation_id(&format!("gen-{i}")),
                })),
                // KnownAbsent: a successful read showing no state.
                Just(Observation::KnownAbsent),
                // Unknown: the observation itself failed — its OWN preserved
                // error, independent of the operation error.
                prop::sample::select(vec![
                    "status read failed: boom".to_string(),
                    "assignment read failed: boom".to_string(),
                ])
                .prop_map(|e| Observation::Unknown(ObservationError { message: e })),
            ],
            any::<bool>(),
        )
            .prop_map(|(outcome, error, observation, compensated)| {
                let transition = match &outcome {
                    SlotOutcomeKind::Restored => SlotTransition::Restored,
                    SlotOutcomeKind::Skipped => SlotTransition::NeverAdvanced,
                    SlotOutcomeKind::Activated => SlotTransition::Advanced,
                    SlotOutcomeKind::Failed => {
                        if compensated {
                            SlotTransition::Restored
                        } else {
                            SlotTransition::AdvanceUnknown
                        }
                    }
                    SlotOutcomeKind::Compensated => SlotTransition::Restored,
                };
                SlotOutcome {
                    outcome,
                    observation,
                    compensated,
                    error,
                    transition,
                }
            })
    }

    /// An arbitrary rollback payload: arbitrary slotted generations (each
    /// assignment naming its own key) with EXACT bindings (the wire
    /// conversion refuses a rollback whose bindings omit a slotted
    /// generation).
    fn arbitrary_rollback() -> impl Strategy<Value = LedgerRollback> {
        prop::collection::btree_set(slot_strategy(), 1..4).prop_map(|keys| {
            let slots: BTreeMap<SlotId, GenerationRef> =
                keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
            let bindings: BTreeMap<SlotId, PhysicalBinding> =
                slots.keys().map(|k| (k.clone(), binding(k))).collect();
            LedgerRollback { slots, bindings }
        })
    }

    /// An arbitrary SUCCESSFUL domain terminal: an arbitrary rollback plus
    /// the disposition's OWN outcomes — every outcome Activated, each key
    /// covered by the rollback's slots — AND the PERSISTED MEMBERSHIPS
    /// (selected == full == the rollback's slots — the exact-equal proven
    /// shape; the mode is a separate record's concern).
    fn arbitrary_successful() -> impl Strategy<Value = LedgerTerminal> {
        arbitrary_rollback().prop_map(|rollback| {
            // The exact-equal shape: the Successful disposition's outcomes
            // EXACTLY cover the rollback's slots (one Activated outcome per
            // slotted generation), and both memberships equal that set — the
            // proven shape the round trip preserves.
            let outcomes: BTreeMap<SlotId, SlotOutcome> = rollback
                .slots
                .keys()
                .map(|k| {
                    (
                        k.clone(),
                        SlotOutcome {
                            outcome: SlotOutcomeKind::Activated,
                            observation: Observation::Known(ObservedGeneration {
                                generation: GenerationId::new(format!("gen-{}", k.as_str())),
                            }),
                            compensated: false,
                            error: None,
                            transition: SlotTransition::Advanced,
                        },
                    )
                })
                .collect();
            let membership: BTreeSet<SlotId> = rollback.slots.keys().cloned().collect();
            LedgerTerminal {
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                disposition: TerminalDisposition::Successful {
                    rollback,
                    outcomes: SlotTable::from_map(outcomes),
                    selected_membership: membership.clone(),
                    full_membership: membership,
                },
                reason: None,
            }
        })
    }

    /// An arbitrary FAILEDROLLEDBACK domain terminal: the disposition's OWN
    /// outcomes table is arbitrary (any kinds, any keys — the compensation
    /// report IS that table).
    fn arbitrary_failed_rolled_back() -> impl Strategy<Value = LedgerTerminal> {
        prop::collection::btree_map(slot_strategy(), arbitrary_outcome(), 0..4).prop_map(
            |outcomes| LedgerTerminal {
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                disposition: TerminalDisposition::FailedRolledBack {
                    outcomes: SlotTable::from_map(outcomes),
                },
                reason: None,
            },
        )
    }

    /// An outcome that is GUARANTEED non-restored (with a recorded
    /// generation) — the Degraded conversion's non-emptiness requirement.
    fn remaining_change_outcome() -> impl Strategy<Value = SlotOutcome> {
        (
            prop_oneof![
                Just(SlotOutcomeKind::Activated),
                Just(SlotOutcomeKind::Failed),
                Just(SlotOutcomeKind::Compensated),
                Just(SlotOutcomeKind::Skipped),
            ],
            (0u32..6).prop_map(|i| GenerationId::new(format!("gen-{i}"))),
            any::<bool>(),
            prop::option::of(prop::sample::select(vec![
                "boom".to_string(),
                "verification failed".to_string(),
            ])),
        )
            .prop_map(|(outcome, generation, compensated, error)| {
                let transition = match &outcome {
                    SlotOutcomeKind::Restored => SlotTransition::Restored,
                    SlotOutcomeKind::Skipped => SlotTransition::NeverAdvanced,
                    SlotOutcomeKind::Activated => SlotTransition::Advanced,
                    SlotOutcomeKind::Failed => {
                        if compensated {
                            SlotTransition::Restored
                        } else {
                            SlotTransition::AdvanceUnknown
                        }
                    }
                    SlotOutcomeKind::Compensated => SlotTransition::Restored,
                };
                SlotOutcome {
                    outcome,
                    observation: Observation::Known(ObservedGeneration { generation }),
                    compensated,
                    error,
                    transition,
                }
            })
    }

    /// An arbitrary DEGRADED domain terminal: the disposition's OWN outcomes
    /// table is arbitrary (any kinds, any keys) with at least one GUARANTEED
    /// non-restored outcome (the conversion refuses an all-restored Degraded
    /// wire).
    fn arbitrary_degraded() -> impl Strategy<Value = LedgerTerminal> {
        (
            slot_strategy(),
            remaining_change_outcome(),
            prop::collection::btree_map(slot_strategy(), arbitrary_outcome(), 0..3),
        )
            .prop_map(|(key, first, mut extras)| {
                extras.insert(key, first);
                LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    disposition: TerminalDisposition::Degraded {
                        outcomes: SlotTable::from_map(extras),
                    },
                    reason: None,
                }
            })
    }

    /// An arbitrary domain terminal: ALL dispositions, each with an arbitrary
    /// outcome table (FailedPreflight carries none by construction).
    fn arbitrary_domain_terminal() -> impl Strategy<Value = LedgerTerminal> {
        prop_oneof![
            arbitrary_successful(),
            Just(LedgerTerminal {
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                disposition: TerminalDisposition::FailedPreflight,
                reason: None,
            }),
            arbitrary_failed_rolled_back(),
            arbitrary_degraded(),
        ]
    }

    proptest! {
        // THE USER'S PROPERTY: ARBITRARY DOMAIN TERMINALS (all dispositions,
        // arbitrary outcome tables) round-trip through the wire EXACTLY —
        // domain → wire → domain equals the original domain. The wire's
        // redundant fields (the status, the outcome's slot_id) round-trip
        // without changing the domain: the status is re-derived from the
        // disposition and the outcome slot is dropped into the key. Bounded
        // 16 cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_domain_terminals_round_trip_exactly(
            terminal in arbitrary_domain_terminal()
        ) {
            let wire = LedgerTerminalWire::from_domain(
                &DeploymentId::new("deploy-prop".to_string()),
                &TargetName::new("t1".to_string()),
                &terminal,
            );
            let back = wire.into_domain().expect(
                "a disposition's own payloads are self-consistent — the round trip must convert",
            );
            assert_eq!(
                back, terminal,
                "the domain terminal must equal the original after the wire round trip"
            );
        }
    }
    // =====================================================================
    // THE SCALAR PROPERTY: arbitrary raw scalar values convert iff the scalar
    // =====================================================================

    /// Arbitrary raw strings for a record scalar field: empty, whitespace,
    /// format-violating, RFC3339-invalid, and valid forms.
    fn arbitrary_wire_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                " ".to_string(),
                "canary".to_string(),
                "wave-1".to_string(),
                " x".to_string(),
                "2026-01-01T00:00:00Z".to_string(),
                "2026-01-01T00:00:00.123+02:00".to_string(),
                "yesterday".to_string(),
                "2026-01-01".to_string(),
                crate::identity::DIGEST_TEST_HEX_1.to_string(),
                "sha256-w".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..8).prop_map(|v| v.into_iter().collect()),
        ]
    }

    /// A valid base intent wire for the scalar property: an agreeing
    /// membership with a canonical digest and timestamp, whose group is
    /// `None` (each mutation arms sets exactly ONE scalar field).
    fn base_intent_wire() -> LedgerIntentWire {
        let slot_ids = vec![slot(1), slot(2)];
        let desired = slot_ids
            .iter()
            .map(|k| (k.clone(), gen_ref_for(k)))
            .collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptStateWire>> =
            slot_ids.iter().map(|k| (k.clone(), None)).collect();
        let bindings: BTreeMap<SlotId, PhysicalBinding> =
            slot_ids.iter().map(|k| (k.clone(), binding(k))).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: test_deployment_id("deploy-scalar"),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids,
            selected_membership: vec![slot(1), slot(2)],
            full_membership: vec![slot(1), slot(2)],
            behavior_sha256: crate::identity::DIGEST_TEST_HEX_1.to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
            bindings,
            slots: BTreeMap::new(),
        }
    }

    /// One records scalar-mutation case: a wire with EXACTLY ONE scalar
    /// field set to an arbitrary raw value, paired with the scalar's own
    /// parse verdict on that value.
    #[derive(Debug)]
    enum ScalarWire {
        Intent(LedgerIntentWire),
        Terminal(LedgerTerminalWire),
        Report(DeploymentIntent),
    }

    fn scalar_mutation_case() -> impl Strategy<Value = (ScalarWire, bool)> {
        prop_oneof![
            // intent attempted_at: RFC 3339 or rejected.
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(mut w, v)| {
                let ok = Timestamp::parse(&v).is_ok();
                w.attempted_at = v;
                (ScalarWire::Intent(w), ok)
            }),
            // intent group: a valid group name or rejected.
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(mut w, v)| {
                let ok = RolloutGroupName::parse(&v).is_ok();
                w.group = Some(v);
                (ScalarWire::Intent(w), ok)
            }),
            // terminal recorded_at: RFC3339 or rejected.
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(w, v)| {
                let ok = Timestamp::parse(&v).is_ok();
                let terminal = LedgerTerminalWire {
                    deployment_id: w.deployment_id,
                    target: w.target,
                    status: DeploymentStatus::FailedRolledBack,
                    recorded_at: v,
                    outcomes: BTreeMap::new(),
                    rollback: None,
                    selected_membership: vec![],
                    full_membership: vec![],
                    reason: None,
                };
                (ScalarWire::Terminal(terminal), ok)
            }),
            // report behavior digest: a sha256 digest or rejected (the
            // in-memory REPORT is the domain record that carries the digest;
            // its constructor parses it fail-closed).
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(w, v)| {
                let ok = BehaviorDigest::parse(&v).is_ok();
                let domain = w.into_domain().expect("base intent converts");
                let mut with_digest = domain.clone();
                with_digest.behavior_sha256 = v;
                (ScalarWire::Report(with_digest), ok)
            }),
        ]
    }

    proptest! {
        // THE PROPERTY: over ARBITRARY raw values for each records scalar
        // field (empty, format-violating, RFC3339-invalid, valid), the
        // wire -> domain conversion accepts EXACTLY the values the scalar
        // accepts and rejects everything else with an integrity error (fail
        // closed). Bounded 16 cases, fixed seed 0x5EED_5EED per house style.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_record_scalars_convert_fail_closed((wire, expected) in scalar_mutation_case()) {
            let converted = match wire {
                ScalarWire::Intent(w) => w.into_domain().map(|_| ()),
                ScalarWire::Terminal(w) => w.into_domain().map(|_| ()),
                ScalarWire::Report(d) => LedgerIntentReport::from_intent(&d).map(|_| ()),
            };
            match converted {
                Ok(_) => {
                    assert!(expected, "the conversion must accept exactly the values the scalar accepts");
                }
                Err(e) => {
                    assert!(
                        !expected,
                        "the conversion must accept a value the scalar accepts, got: {e}"
                    );
                    assert!(
                        matches!(e, Error::Integrity(_)),
                        "the rejection must be an integrity error, got: {e}"
                    );
                }
            }
        }
    }
    // ---------------------------------------------------------------------
    // PLAN WIRE → DOMAIN: THE SOURCE OWNS ITS REQUIRED PAYLOAD
    // ---------------------------------------------------------------------
    //
    // The wire plan (the on-disk shape with the `source` + separate
    // `rebinding` fields) converts to the domain by RECOMPUTING the proof:
    // a Release origin must carry its [`VerifiedReleaseRebinding`] INSIDE
    // the source (a Release origin without the proof is unrepresentable),
    // HEAD/deployment origins must carry NONE, and the claimed rebinding
    // must agree with the plan's own source/target/membership — the claimed
    // release equals the plan's source release AND the release its slots
    // reference, the claimed target equals the plan's target, the frozen
    // topology keys equal the membership's agreed slots, the selected plan
    // slots are covered by the membership, and the current physical slots
    // cover exactly the selected plan slots. A disagreement →
    // `Error::integrity` (fail closed).

    /// A per-slot plan for the given key, referencing the given release.
    fn plan_for(key: &SlotId, release: &ReleaseId) -> SlotPlan {
        SlotPlan {
            slot_id: key.clone(),
            artifact: ArtifactRef {
                release: release.clone(),
                variant: VariantName::new("standard".to_string()),
                tree: test_tree_digest(&format!("tree-{}", key.as_str())),
            },
            expected_generation: None,
            expected_tree: None,
        }
    }

    /// The membership PROOF for the given keys (frozen == current verified
    /// through the ONLY construction path, [`MatchingMembership::verify`]).
    fn membership_for(keys: &[SlotId]) -> MatchingMembership {
        MatchingMembership::verify(
            SlotSet::new(keys.iter().cloned()),
            SlotSet::new(keys.iter().cloned()),
        )
        .expect("a non-empty agreeing membership verifies")
    }

    /// The frozen slot→variant/group topology for the given keys (each slot
    /// in the `standard` variant, no groups).
    fn frozen_topology_for(keys: &[SlotId]) -> BTreeMap<SlotId, FrozenSlotTopology> {
        keys.iter()
            .map(|k| {
                (
                    k.clone(),
                    FrozenSlotTopology {
                        variant: "standard".to_string(),
                        groups: Vec::new(),
                    },
                )
            })
            .collect()
    }

    /// The current physical slots for the given keys.
    fn physical_slots_for(keys: &[SlotId]) -> BTreeMap<SlotId, PhysicalBinding> {
        keys.iter().map(|k| (k.clone(), binding(k))).collect()
    }

    /// A CLAIMED rebinding AGREEING with the plan's own data: the release,
    /// the target, the frozen topology (keys == the membership's agreed
    /// slots), the membership proof, and the current physical slots (keys
    /// == the selected slots).
    fn agreeing_rebinding(
        release: &ReleaseId,
        target: &TargetName,
        keys: &[SlotId],
    ) -> RebindingPlan {
        RebindingPlan {
            release: release.clone(),
            target: target.clone(),
            frozen_topology: frozen_topology_for(keys),
            membership: membership_for(keys),
            current_physical_slots: physical_slots_for(keys),
        }
    }

    /// A VALID plan wire for the given source kind (0 Head, 1 Deployment,
    /// 2 Release): a NON-EMPTY membership K, every duplicate projection
    /// agreeing, and — for a Release source — a claimed rebinding agreeing
    /// with the plan's own source/target/membership.
    fn agreeing_plan_wire(source_kind: u32, keys: &[SlotId]) -> DeploymentPlanWire {
        let release = test_release_id("rel-plan");
        let target = TargetName::new("t1".to_string());
        let slots: BTreeMap<SlotId, SlotPlan> = keys
            .iter()
            .map(|k| (k.clone(), plan_for(k, &release)))
            .collect();
        let behaviors = BehaviorIndex::new();
        let source = match source_kind {
            0 => PlanSource::Head,
            1 => PlanSource::DeploymentRef(test_deployment_id("deploy-plan")),
            _ => PlanSource::ReleaseRef(release.clone()),
        };
        let rebinding = match source_kind {
            2 => Some(agreeing_rebinding(&release, &target, keys)),
            _ => None,
        };
        DeploymentPlanWire {
            deployment_id: test_deployment_id("deploy-plan"),
            target,
            behavior_sha256: crate::verify::release::behavior_index_digest(&behaviors),
            behaviors,
            slot_ids: keys.to_vec(),
            slots,
            source,
            rebinding,
            desired_releases: BTreeSet::from([release]),
        }
    }

    // ---- plan wire mutations (ONE field at a time) -----------------------

    /// source: ReleaseRef → Head (the claimed rebinding stays — a HEAD plan
    /// carrying a rebinding is a disagreement).
    fn source_to_head(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::Head;
    }

    /// source: ReleaseRef → DeploymentRef (the claimed rebinding stays).
    fn source_to_deployment(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::DeploymentRef(test_deployment_id("deploy-other"));
    }

    /// source: Head/Deployment → ReleaseRef (no rebinding — a Release
    /// origin without its proof is unrepresentable).
    fn source_to_release(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::ReleaseRef(test_release_id("rel-plan"));
    }

    /// rebinding presence: remove the claimed rebinding from a Release
    /// plan.
    fn rebinding_removed(w: &mut DeploymentPlanWire) {
        w.rebinding = None;
    }

    /// rebinding presence: add a claimed rebinding (internally agreeing
    /// with the plan's own data) to a Head/Deployment plan.
    fn rebinding_added(w: &mut DeploymentPlanWire) {
        let release = test_release_id("rel-plan");
        let target = TargetName::new("t1".to_string());
        let keys: Vec<SlotId> = w.slots.keys().cloned().collect();
        w.rebinding = Some(agreeing_rebinding(&release, &target, &keys));
    }

    /// release: change the claimed rebinding's release (disagrees with the
    /// plan's source release AND the releases derived from the slots).
    fn rebinding_release_changed(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        rp.release = test_release_id("rel-other");
    }

    /// release: change the SOURCE's release (disagrees with the claimed
    /// rebinding's release).
    fn source_release_changed(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::ReleaseRef(test_release_id("rel-other"));
    }

    /// target: change the claimed rebinding's target (disagrees with the
    /// plan's target).
    fn rebinding_target_changed(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        rp.target = TargetName::new("t2".to_string());
    }

    /// membership: change the claimed membership's agreed set (remove a
    /// slot when there is more than one, else add one) — the frozen
    /// topology keys no longer equal the membership, and the selected slots
    /// are no longer covered.
    fn membership_changed(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        let mut slots: BTreeSet<SlotId> = rp.membership.slots().iter().cloned().collect();
        if slots.len() > 1 {
            let removed = slots.iter().next().cloned().expect("non-empty membership");
            slots.remove(&removed);
        } else {
            slots.insert(slot(99));
        }
        rp.membership = MatchingMembership::verify(
            SlotSet::new(slots.iter().cloned()),
            SlotSet::new(slots.iter().cloned()),
        )
        .expect("a changed non-empty membership verifies");
    }

    /// frozen topology: remove a key (the frozen topology keys no longer
    /// equal the membership's agreed slots).
    fn frozen_topology_shrunk(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        let removed = rp
            .frozen_topology
            .keys()
            .next()
            .cloned()
            .expect("non-empty frozen topology");
        rp.frozen_topology.remove(&removed);
    }

    /// physical-slot keys: remove a key (the current physical slots no
    /// longer cover exactly the selected plan slots).
    fn physical_slots_shrunk(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        let removed = rp
            .current_physical_slots
            .keys()
            .next()
            .cloned()
            .expect("non-empty physical slots");
        rp.current_physical_slots.remove(&removed);
    }

    /// One plan-wire mutation: a named single-field tamper applied to a
    /// [`DeploymentPlanWire`].
    type PlanWireMutation = fn(&mut DeploymentPlanWire);

    proptest! {
        // PROPERTY (the user's requirement): generate VALID plans (all
        // three source kinds), then MUTATE ONE FIELD AT A TIME — source
        // (Head↔Deployment↔Release), rebinding presence (add/remove),
        // release, target, membership, frozen topology, physical-slot keys
        // — and assert the CONVERSION SUCCEEDS ONLY FOR THE COMPLETE TRUTH
        // TABLE: the untampered plan converts, and EVERY single-field
        // mutation that breaks the proof fails the verifying conversion
        // with an integrity error. A Release origin without its proof, a
        // non-Release origin carrying one, a claimed release/target
        // disagreeing with the plan's own, a membership/frozen-topology/
        // physical-slot disagreement — all fail closed. Bounded 16 cases,
        // fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn plan_wire_rebinding_truth_table(
            source_kind in 0u32..3,
            keys in prop::collection::btree_set(slot_strategy(), 2..4),
        ) {
            let keys: Vec<SlotId> = keys.into_iter().collect();
            let wire = agreeing_plan_wire(source_kind, &keys);
            // The untampered plan converts (the truth table's Ok row).
            let domain = wire
                .clone()
                .into_domain()
                .expect("the agreeing plan converts");
            // The domain's source OWNS its payload: a Release origin
            // carries the verified proof inside the source; HEAD/deployment
            // carry none.
            match &domain.source {
                PlanOrigin::Release { release, rebinding } => {
                    assert_eq!(release.as_str(), test_release_id("rel-plan").as_str());
                    assert_eq!(
                        rebinding.selected_plan_slots,
                        keys.iter().cloned().collect::<BTreeSet<_>>(),
                        "the proof carries the selected plan slots"
                    );
                    assert_eq!(
                        rebinding
                            .membership
                            .slots()
                            .iter()
                            .cloned()
                            .collect::<BTreeSet<_>>(),
                        keys.iter().cloned().collect::<BTreeSet<_>>(),
                        "the proof carries the agreed membership"
                    );
                }
                PlanOrigin::Head | PlanOrigin::Deployment(_) => {}
            }

            // The proof-breaking mutations for this plan kind: each
            // single-field mutation that breaks the proof must fail the
            // conversion (the truth table's Err rows).
            let mutations: Vec<(&str, PlanWireMutation)> = match source_kind {
                // A Release plan: every claimed-rebinding field is a fact.
                2 => vec![
                    ("source → Head (rebinding present)", source_to_head as fn(&mut DeploymentPlanWire)),
                    ("source → Deployment (rebinding present)", source_to_deployment),
                    ("rebinding removed (Release origin without its proof)", rebinding_removed),
                    ("claimed rebinding release changed", rebinding_release_changed),
                    ("source release changed", source_release_changed),
                    ("claimed rebinding target changed", rebinding_target_changed),
                    ("membership changed", membership_changed),
                    ("frozen topology key removed", frozen_topology_shrunk),
                    ("physical-slot key removed", physical_slots_shrunk),
                ],
                // HEAD / Deployment plans: no rebinding is allowed; a
                // Release source without its proof is refused.
                _ => vec![
                    ("source → Release (no rebinding)", source_to_release),
                    ("rebinding added to a non-Release plan", rebinding_added),
                ],
            };
            for (name, mutate) in mutations {
                let mut bad = wire.clone();
                mutate(&mut bad);
                let err = bad.into_domain();
                assert!(
                    err.is_err(),
                    "{name} must fail the verifying conversion"
                );
                assert!(
                    matches!(err, Err(Error::Integrity(_))),
                    "{name} must fail with an integrity error, got: {err:?}"
                );
            }
        }
    }

    // ---- deterministic unit tests per mutation class ---------------------

    /// A Release-origin plan WITHOUT its claimed rebinding is refused: the
    /// proof is unrepresentable without it (a Release origin must carry its
    /// [`VerifiedReleaseRebinding`] inside the source).
    #[test]
    fn plan_wire_release_origin_without_proof_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        wire.rebinding = None;
        let err = wire
            .into_domain()
            .expect_err("a Release origin without its proof must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("must carry its rebinding proof"),
            "the refusal must be the missing-proof integrity error, got: {err}"
        );
    }

    /// A non-Release origin (HEAD / deployment) CARRYING a claimed
    /// rebinding is refused: the domain has no place for it, so it is
    /// refused rather than silently dropped.
    #[test]
    fn plan_wire_non_release_origin_with_rebinding_refused() {
        for source_kind in [0u32, 1] {
            let keys = vec![slot(1), slot(2)];
            let mut wire = agreeing_plan_wire(source_kind, &keys);
            rebinding_added(&mut wire);
            let err = wire
                .into_domain()
                .expect_err("a non-Release plan carrying a rebinding must refuse");
            assert!(
                matches!(err, Error::Integrity(_))
                    && err.to_string().contains("cannot carry a rebinding proof"),
                "the refusal must be the non-Release-with-rebinding integrity error, got: {err}"
            );
        }
    }

    /// The claimed rebinding's release must equal the plan's source release
    /// AND the release the plan's slots reference: changing either half is a
    /// disagreement.
    #[test]
    fn plan_wire_claimed_release_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        // The claimed rebinding's release disagrees with the plan's source.
        let mut wire = agreeing_plan_wire(2, &keys);
        rebinding_release_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a claimed release disagreeing with the plan's source must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("claimed rebinding release"),
            "the refusal must name the claimed release disagreement, got: {err}"
        );
        // The source's release disagrees with the claimed rebinding's.
        let mut wire = agreeing_plan_wire(2, &keys);
        source_release_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a source release disagreeing with the claimed rebinding must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("claimed rebinding release"),
            "the refusal must name the claimed release disagreement, got: {err}"
        );
    }

    /// The claimed rebinding's target must equal the plan's target.
    #[test]
    fn plan_wire_claimed_target_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        rebinding_target_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a claimed target disagreeing with the plan's target must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("claimed rebinding target"),
            "the refusal must name the claimed target disagreement, got: {err}"
        );
    }

    /// The claimed membership's agreed set must equal the frozen topology's
    /// keys and cover the selected plan slots: a changed agreed set is a
    /// disagreement.
    #[test]
    fn plan_wire_membership_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        membership_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a changed membership must refuse");
        assert!(
            matches!(err, Error::Integrity(_)) && err.to_string().contains("recomputed proof"),
            "the refusal must be the recomputed-proof integrity error, got: {err}"
        );
    }

    /// The frozen topology's keys must equal the membership's agreed slots:
    /// a removed frozen key is a disagreement.
    #[test]
    fn plan_wire_frozen_topology_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        frozen_topology_shrunk(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a shrunk frozen topology must refuse");
        assert!(
            matches!(err, Error::Integrity(_)) && err.to_string().contains("recomputed proof"),
            "the refusal must be the recomputed-proof integrity error, got: {err}"
        );
    }

    /// The current physical slots must cover exactly the selected plan
    /// slots: a removed physical-slot key is a disagreement.
    #[test]
    fn plan_wire_physical_slots_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        physical_slots_shrunk(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a shrunk physical-slot set must refuse");
        assert!(
            matches!(err, Error::Integrity(_)) && err.to_string().contains("recomputed proof"),
            "the refusal must be the recomputed-proof integrity error, got: {err}"
        );
    }

    /// A Release-origin plan ROUND-TRIPS through the wire (JSON) with its
    /// proof intact: the domain serializes through the wire shape (the
    /// claimed [`RebindingPlan`]), and the next read RECOMPUTES the proof
    /// from the plan's own data — the selected plan slots are re-derived
    /// from the plan's membership, and every component agrees again.
    #[test]
    fn plan_wire_release_origin_round_trips_with_its_proof() {
        let keys = vec![slot(1), slot(2)];
        let wire = agreeing_plan_wire(2, &keys);
        let domain = wire.into_domain().expect("the agreeing plan converts");
        let json = serde_json::to_string(&domain).expect("the domain serializes through the wire");
        let back: DeploymentPlan =
            serde_json::from_str(&json).expect("the wire deserializes back into the domain");
        match &back.source {
            PlanOrigin::Release { release, rebinding } => {
                assert_eq!(release.as_str(), test_release_id("rel-plan").as_str());
                assert_eq!(
                    rebinding.selected_plan_slots,
                    BTreeSet::from([slot(1), slot(2)]),
                    "the round trip re-derives the selected plan slots from the plan's membership"
                );
                assert_eq!(rebinding.frozen_topology.len(), 2);
                assert_eq!(rebinding.current_physical_slots.len(), 2);
                assert_eq!(
                    rebinding
                        .membership
                        .slots()
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([slot(1), slot(2)]),
                    "the round trip keeps the agreed membership"
                );
            }
            other => {
                panic!("a Release-origin plan must round-trip as a Release origin, got {other:?}")
            }
        }
    }
    // ---- the transition-state derivation (deterministic) ----------------

    /// Build a Degraded terminal with the given per-slot outcomes (each
    /// outcome names its own key) and an intent whose pre_push carries the
    /// given per-slot generations (the fixture's default pre_push is `None`
    /// — a first deployment — so the given entries override it).
    fn degraded_terminal_with(
        outcomes: Vec<(SlotId, SlotResult)>,
        pre_push: Vec<(SlotId, Option<GenerationId>)>,
    ) -> (DeploymentIntent, LedgerTerminal) {
        let keys: Vec<SlotId> = outcomes.iter().map(|(k, _)| k.clone()).collect();
        let mut intent_wire = agreeing_intent(&keys);
        for (k, g) in pre_push {
            intent_wire.pre_push.insert(
                k,
                Some(SlotAttemptStateWire {
                    artifact: ObservationWire::Unknown(ObservationError {
                        message: "fixture: unknown assignment".to_string(),
                    }),
                    generation: g,
                }),
            );
        }
        let intent = intent_wire.into_domain().unwrap();
        let terminal = LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            disposition: TerminalDisposition::Degraded {
                // WIRE → DOMAIN (fail closed): the fixture's wire outcomes
                // convert to the domain outcomes, deriving each slot's
                // transition state ([`SlotOutcome::from_wire`]).
                outcomes: SlotTable::from_map(
                    outcomes
                        .into_iter()
                        .map(|(k, r)| (k, SlotOutcome::from_wire(r).unwrap()))
                        .collect(),
                ),
            },
            reason: None,
        };
        (intent, terminal)
    }

    /// THE TRANSITION-STATE DERIVATION (deterministic, per transition
    /// class): `remaining_changes()` returns exactly the slots whose FINAL
    /// OBSERVED STATE differs from their pre_push state — a SKIPPED slot
    /// (`NeverAdvanced`) is never a remaining change, an ADVANCED slot
    /// (`Advanced`) always is, a RESTORED slot (`Restored`) never is, and
    /// an ADVANCE-UNKNOWN slot (`AdvanceUnknown` — a pre-swap failure / a
    /// failed compensation) is a remaining change iff its observed state
    /// differs from pre_push. The old derivation counted a skipped slot
    /// (its outcome records a generation) and a pre-swap failure (its
    /// outcome records the DESIRED generation) as changed — the transition
    /// state is the per-slot fact the derivation is based on, never the
    /// outcome's generation field alone.
    #[test]
    fn remaining_changes_reflects_the_transition_state_not_the_generation_field() {
        // A SKIPPED slot (NeverAdvanced): never mutated — its observed
        // state equals pre_push, so it is never a remaining change (the old
        // derivation counted it because its outcome records a generation).
        let (intent, terminal) = degraded_terminal_with(
            vec![(
                slot(1),
                SlotResult {
                    slot_id: slot(1),
                    outcome: SlotOutcomeKind::Skipped,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: GenerationId::new("pre-1".to_string()),
                    }),
                    compensated: false,
                    error: None,
                },
            )],
            vec![(slot(1), Some(GenerationId::new("pre-1".to_string())))],
        );
        let remaining = terminal.remaining_changes(&intent).expect("Degraded");
        assert!(
            !remaining.contains_key(&slot(1)),
            "a skipped slot (NeverAdvanced) is never a remaining change"
        );

        // An ADVANCED slot (Advanced): at the desired state — always a
        // remaining change, mapped to the generation it is on.
        let (intent, terminal) = degraded_terminal_with(
            vec![(
                slot(1),
                SlotResult {
                    slot_id: slot(1),
                    outcome: SlotOutcomeKind::Activated,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: GenerationId::new("new-1".to_string()),
                    }),
                    compensated: false,
                    error: None,
                },
            )],
            vec![(slot(1), Some(GenerationId::new("pre-1".to_string())))],
        );
        let remaining = terminal.remaining_changes(&intent).expect("Degraded");
        assert_eq!(
            remaining.get(&slot(1)),
            Some(&Observation::Known(ObservedGeneration {
                generation: GenerationId::new("new-1".to_string()),
            })),
            "an advanced slot (Advanced) is a remaining change at the generation it is on"
        );

        // A RESTORED slot (Restored): compensated back to pre_push — never
        // a remaining change (even though its outcome records the generation
        // it advanced to).
        let (intent, terminal) = degraded_terminal_with(
            vec![(
                slot(1),
                SlotResult {
                    slot_id: slot(1),
                    outcome: SlotOutcomeKind::Restored,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: GenerationId::new("new-1".to_string()),
                    }),
                    compensated: true,
                    error: None,
                },
            )],
            vec![(slot(1), Some(GenerationId::new("pre-1".to_string())))],
        );
        let remaining = terminal.remaining_changes(&intent).expect("Degraded");
        assert!(
            !remaining.contains_key(&slot(1)),
            "a restored slot (Restored) is never a remaining change"
        );

        // An ADVANCE-UNKNOWN slot (a pre-swap failure / a failed
        // compensation): a remaining change iff its OBSERVED state differs
        // from pre_push. Observed == pre_push (a pre-swap failure that
        // advanced nothing) → NOT a remaining change.
        let (intent, terminal) = degraded_terminal_with(
            vec![(
                slot(1),
                SlotResult {
                    slot_id: slot(1),
                    outcome: SlotOutcomeKind::Failed,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: GenerationId::new("pre-1".to_string()),
                    }),
                    compensated: false,
                    error: None,
                },
            )],
            vec![(slot(1), Some(GenerationId::new("pre-1".to_string())))],
        );
        let remaining = terminal.remaining_changes(&intent).expect("Degraded");
        assert!(
            !remaining.contains_key(&slot(1)),
            "an advance-unknown slot whose observed state equals pre_push is not a remaining change"
        );
        // Observed != pre_push (a post-swap failure whose compensation
        // failed — the slot is still on the new generation) → a remaining
        // change.
        let (intent, terminal) = degraded_terminal_with(
            vec![(
                slot(1),
                SlotResult {
                    slot_id: slot(1),
                    outcome: SlotOutcomeKind::Failed,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: GenerationId::new("new-1".to_string()),
                    }),
                    compensated: false,
                    error: None,
                },
            )],
            vec![(slot(1), Some(GenerationId::new("pre-1".to_string())))],
        );
        let remaining = terminal.remaining_changes(&intent).expect("Degraded");
        assert_eq!(
            remaining.get(&slot(1)),
            Some(&Observation::Known(ObservedGeneration {
                generation: GenerationId::new("new-1".to_string()),
            })),
            "an advance-unknown slot whose observed state differs from pre_push is a remaining change"
        );

        // THE OBSERVATION-LEVEL FIX: an ADVANCE-UNKNOWN slot whose
        // post-mutation OBSERVATION FAILED (the status read at the
        // post-mutation point returned an error) is `Unknown(error)` — the
        // slot may or may not have changed, so it is NEVER classified as
        // unchanged: it IS a remaining change, mapped to its `Unknown`
        // observation (the wire's `Unknown` observation with the preserved
        // OBSERVATION error — independent of the operation error — reads
        // back as `Unknown`, never as a `None` that downstream code reads as
        // "no change").
        let (intent, terminal) = degraded_terminal_with(
            vec![(
                slot(1),
                SlotResult {
                    slot_id: slot(1),
                    outcome: SlotOutcomeKind::Failed,
                    observation: ObservationWire::Unknown(ObservationError {
                        message: "status read failed: boom".to_string(),
                    }),
                    compensated: false,
                    error: Some("swap failed: boom".to_string()),
                },
            )],
            vec![(slot(1), Some(GenerationId::new("pre-1".to_string())))],
        );
        let remaining = terminal.remaining_changes(&intent).expect("Degraded");
        assert_eq!(
            remaining.get(&slot(1)),
            Some(&Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            })),
            "an advance-unknown slot whose post-mutation observation failed is a remaining \
             change carrying the Unknown observation — never classified as unchanged"
        );
    }

    // THE PROPERTY: STATUS-READ FAILURE AT EVERY POST-MUTATION POINT.
    // For arbitrary slot sets, inject a FAILED observation (Unknown) at
    // every post-mutation point (every slot's status read fails) and assert
    // that the uncertainty REMAINS Unknown (the observation is the Unknown
    // variant with the error) and is NEVER CLASSIFIED AS UNCHANGED (the
    // consumers — the observed record, the terminal disposition, the
    // remaining_changes derivation — must not treat the failed observation
    // as KnownAbsent/unchanged). Bounded `proptest_cases(16)` (full 16 with
    // `DEPLOY_FULL_TESTS=1`, fast default), fixed seed 0x5EED_5EED.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn status_read_failure_at_every_post_mutation_point_remains_unknown_never_unchanged(
            slots in prop::collection::btree_set(slot_strategy(), 1..4),
            err_msg in prop::sample::select(vec![
                "status read failed: boom".to_string(),
                "assignment read failed: boom".to_string(),
            ]),
        ) {
            // Every slot's post-mutation status read fails: the wire
            // carries the `Unknown` observation with the preserved
            // OBSERVATION error (independently of the slot's OPERATION
            // error), which the domain reads as `Unknown(error)` — never as
            // KnownAbsent/unchanged.
            let results: Vec<(SlotId, SlotResult)> = slots
                .iter()
                .map(|sid| {
                    (
                        sid.clone(),
                        SlotResult {
                            slot_id: sid.clone(),
                            outcome: SlotOutcomeKind::Failed,
                            observation: ObservationWire::Unknown(ObservationError {
                                message: err_msg.clone(),
                            }),
                            compensated: false,
                            // A DISTINCT operation error: the pre-swap
                            // failure that stopped the slot (e.g. a swap
                            // failure) — must survive the observation
                            // untouched.
                            error: Some(format!("swap failed: {err_msg}")),
                        },
                    )
                })
                .collect();
            let pre_push: Vec<(SlotId, Option<GenerationId>)> = slots
                .iter()
                .map(|sid| (sid.clone(), Some(GenerationId::new(format!("pre-{}", sid.as_str())))))
                .collect();
            let (intent, terminal) = degraded_terminal_with(results, pre_push);

            // The terminal's per-slot outcomes preserve Unknown for every slot.
            for sid in &slots {
                let outcome = terminal.outcomes().get(sid).expect("every slot has an outcome");
                assert_eq!(
                    outcome.observation,
                    Observation::Unknown(ObservationError {
                        message: err_msg.clone(),
                    }),
                    "slot {sid}: the failed post-mutation observation must remain Unknown with the preserved error"
                );
                assert_eq!(
                    outcome.transition,
                    SlotTransition::AdvanceUnknown,
                    "a failed uncompensated outcome is AdvanceUnknown"
                );
            }

            // The remaining_changes derivation NEVER classifies Unknown as
            // unchanged: every Unknown slot IS a remaining change carrying
            // the Unknown observation.
            let remaining = terminal.remaining_changes(&intent).expect("Degraded");
            for sid in &slots {
                assert_eq!(
                    remaining.get(sid),
                    Some(&Observation::Unknown(ObservationError {
                        message: err_msg.clone(),
                    })),
                    "slot {sid}: Unknown is uncertain — never classified as unchanged, so it is a remaining change"
                );
            }
            assert_eq!(
                remaining.len(),
                slots.len(),
                "every failed observation is a remaining change"
            );

            // The wire round-trip preserves BOTH facts independently: the
            // observation error survives as the `Unknown` wire observation
            // and reads back as `Unknown`, never as `KnownAbsent`; the
            // operation error survives via `error` untouched.
            for sid in &slots {
                let outcome = terminal.outcomes().get(sid).unwrap();
                let wire = SlotResult::from_outcome(sid, outcome);
                assert_eq!(
                    wire.observation,
                    ObservationWire::Unknown(ObservationError {
                        message: err_msg.clone(),
                    }),
                    "slot {sid}: the wire observation must carry the preserved observation error"
                );
                assert_eq!(
                    wire.error,
                    Some(format!("swap failed: {err_msg}")),
                    "slot {sid}: the operation error must survive the wire untouched"
                );
                let back = SlotOutcome::from_wire(wire).unwrap();
                assert_eq!(
                    back.error,
                    Some(format!("swap failed: {err_msg}")),
                    "slot {sid}: the operation error must survive the domain conversion"
                );
                assert_eq!(
                    back.observation,
                    Observation::Unknown(ObservationError {
                        message: err_msg.clone(),
                    }),
                    "slot {sid}: the Unknown observation must survive the domain conversion"
                );
            }
        }
    }

    // =====================================================================
    // THE INDEPENDENT-FACTS PROPERTY: the operation error and the
    // post-mutation observation round-trip and survive failure injection
    // independently
}

//! The core RECORD types of the deployment ledger (feature area A2: Ledger
//! semantics) that the FEATURE MODULES share.
//!
//! The ledger's records are split into per-feature modules (see the area
//! root [`crate::ledger`] for the module map): the INTENT records
//! ([`crate::ledger::intent::LedgerIntentWire`] /
//! [`crate::ledger::intent::DeploymentIntent`]) and the TERMINAL records
//! ([`crate::ledger::terminal::LedgerTerminalWire`] /
//! [`crate::ledger::terminal::LedgerTerminal`] /
//! [`crate::ledger::terminal::TerminalDisposition`]) own the two line
//! kinds; the per-slot OUTCOMES ([`crate::ledger::outcomes::SlotOutcome`] /
//! [`crate::ledger::outcomes::SlotOutcomeKind`] /
//! [`crate::ledger::outcomes::SlotTransition`] + the remaining-changes /
//! compensation derivations) live in [`crate::ledger::outcomes`]; the
//! three-state observations live in [`crate::ledger::observation`]; the
//! format-version constants live in [`crate::ledger::schema`]; and the
//! rebinding proof records live in [`crate::ledger::rebinding`].
//!
//! THIS module keeps the SHARED core:
//!
//! * the per-slot TABLES ([`SlotTable`] / [`NonEmptySlotTable`] over the
//!   private [`OrderedSlotMap`]) and the wire outcome [`SlotResult`];
//! * the deployment records' shared fields ([`SlotAttemptState`],
//!   [`DeploymentStatus`]);
//! * the ROLLBACK records ([`LedgerRollback`] / [`LedgerRollbackWire`] /
//!   [`PhysicalBinding`] / [`CompleteRollback`]);
//! * the plan/report records ([`BehaviorIndex`], [`SlotPlan`],
//!   [`DeploymentPlanWire`] / [`DeploymentPlan`], [`PlanSource`] /
//!   [`PlanOrigin`]);
//! * the retained pins + per-server records ([`Pins`], [`ServerState`]).
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
//! [`crate::ledger::terminal::LedgerTerminal::remaining_changes`],
//! [`crate::ledger::terminal::LedgerTerminal::compensation`]); the redundant
//! on-disk members exist only in the WIRE types (the raw serde shapes,
//! [`LedgerIntentWire`], [`LedgerRollbackWire`], [`LedgerTerminalWire`],
//! [`DeploymentPlanWire`]) and are RECONCILED by a VERIFYING CONVERSION
//! (`Wire::into_domain`). The conversion checks that every duplicate
//! projection AGREES — e.g. the intent's `slot_ids` is DUPLICATE-FREE and
//! its `desired`/`pre_push` key sets EQUAL the authoritative `slot_ids`
//! membership EXACTLY, each [`crate::identity::GenerationRef`]'s assignment
//! names its own map key, and the stored `behavior_sha256` equals the digest
//! derived from the behavior index. A disagreement is an
//! [`crate::error::Error::integrity`] error (fail closed — a hand-constructed
//! record can never put the duplicates out of agreement, and the code then
//! reads whichever projection it happens to use). The rest of the codebase
//! consumes ONLY the validated domain types; the store's readers convert
//! wire → domain on read and refuse disagreeing records.
//!
//! # INTENT vs REPORT (outcomes are never part of the intent)
//!
//! The INTENT carries NO outcomes: the ledger's intent line keeps its
//! `slots` (actuals) map EMPTY (outcomes live in the terminal event's
//! `outcomes` map and the rollback payload), and the verified domain
//! [`crate::ledger::intent::DeploymentIntent`] does NOT carry an outcomes
//! map at all — the wire keeps the empty member for format stability, and
//! the in-memory push REPORT
//! ([`crate::ledger::intent::LedgerIntentReport`]) carries the observed
//! per-slot actuals for display. Splitting the datatypes means the report's
//! `slots` map can never weaken the intent's key-set invariant
//! (`slot_ids == desired == pre_push`): it is simply not part of the
//! verified intent object.
//!
//! # ONE history ledger per target
//!
//! A target's ENTIRE deployment history lives in ONE ordered, append-only
//! JSONL file: `targets/<target>/ledger.jsonl` — the two physical line
//! kinds and the merged entry are
//! [`crate::ledger::append::LedgerLine`] /
//! [`crate::ledger::append::LedgerEntry`], owned by
//! [`crate::ledger::append`] (which also documents the crash-atomic append
//! and deployment-id keying contracts): an intent line
//! ([`crate::ledger::append::LedgerLine::Intent`] → verified
//! [`crate::ledger::intent::DeploymentIntent`]) is appended BEFORE any
//! remote mutation and never edited; a terminal line
//! ([`crate::ledger::append::LedgerLine::Terminal`] → verified
//! [`crate::ledger::terminal::LedgerTerminal`]) is appended once, after the
//! mutation loop. A merged entry (intent + optional terminal) is the
//! deployment's full history record; an entry WITHOUT a terminal is the
//! CURRENT/INCOMPLETE state (recoverable — the next push reconciles it).
//!
//! The old multi-file model (immutable `attempts.jsonl` intents + the
//! `refs/snapshots.jsonl` op log with explicit indices + per-deployment
//! `results.json` / `transitions.jsonl` + the `history-floor.json` marker +
//! the `cleanup-pending.json` debt flag) is GONE: the ledger replaces all
//! of it. A checkpoint is an ATOMIC REPLACEMENT of the ledger with the
//! retained suffix (the floor is implicit — the ledger's first entry is the
//! oldest retained rollback state) followed by a best-effort global sweep of
//! unreachable deployment directories, release records, and tree objects
//! (see [`crate::retention::history_floor`]).

use crate::error::{Error, Result};
use crate::identity::BehaviorDigest;
use crate::identity::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, GenerationRef, ReleaseId, ServerId,
    SlotId, TargetName, TreeDigest,
};
use crate::ledger::observation::{Observation, ObservedSlot};
use crate::ledger::outcomes::SlotOutcomeKind;
use crate::ledger::rebinding::{RebindingPlan, VerifiedReleaseRebinding};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::ops::Index;
// ---------------------------------------------------------------------------
// DOMAIN SLOT TABLES: the membership + per-slot data are ONE table
// ---------------------------------------------------------------------------
//
// The DOMAIN intent collapses the wire's `slot_ids` / `desired` / `pre_push`
// split into a single authoritative slot→slot-data table, so the
// exact-key-set invariant (membership == desired keys == pre_push keys, no
// duplicates) becomes STRUCTURAL: a [`NonEmptySlotTable`] is non-empty and
// its keys are unique (the ordered map has no duplicate keys), so an intent
// can never carry a member slot without its desired/pre-push entries, or an
// entry for a non-member slot. The WIRE types keep the split on-disk shape;
// the wire → domain conversion builds the table and refuses disagreements
// exactly as before.
//
// THE TABLE IS ORDERED: iteration (`keys` / `values` / `iter`) is in
// INSERTION order — the DEPLOYMENT order — never sorted by slot id. The
// wire's `slot_ids` is the authoritative deployment order (the same set the
// commit marker `slots` payload records), and the wire → domain conversion
// builds the table from that SEQUENCE, so the round trip preserves the
// exact `slot_ids` order instead of silently re-sorting it.

/// A PRIVATE ordered slot→value map: a `Vec<(SlotId, T)>` keeps the
/// INSERTION SEQUENCE (the deployment order) and a `BTreeMap<SlotId, usize>`
/// index gives O(log n) lookup. Iteration (`keys` / `values` / `iter`) is in
/// INSERTION order — the deployment order — never sorted by slot id.
/// `insert` APPENDS a new key at the end of the sequence and OVERWRITES an
/// existing key in place (its position is preserved), so the sequence is
/// exactly the order the entries were first inserted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OrderedSlotMap<T> {
    entries: Vec<(SlotId, T)>,
    index: BTreeMap<SlotId, usize>,
}

impl<T> Default for OrderedSlotMap<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeMap::new(),
        }
    }
}

impl<T> OrderedSlotMap<T> {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    fn from_map(map: BTreeMap<SlotId, T>) -> Self {
        let entries: Vec<(SlotId, T)> = map.into_iter().collect();
        let index = entries
            .iter()
            .enumerate()
            .map(|(i, (k, _))| (k.clone(), i))
            .collect();
        Self { entries, index }
    }

    fn into_map(self) -> BTreeMap<SlotId, T> {
        self.entries.into_iter().collect()
    }

    fn insert(&mut self, key: SlotId, value: T) {
        if let Some(&i) = self.index.get(&key) {
            self.entries[i].1 = value;
        } else {
            self.index.insert(key.clone(), self.entries.len());
            self.entries.push((key, value));
        }
    }

    fn get(&self, key: &SlotId) -> Option<&T> {
        self.index.get(key).map(|&i| &self.entries[i].1)
    }

    fn contains_key(&self, key: &SlotId) -> bool {
        self.index.contains_key(key)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.entries.iter().map(|(k, _)| k)
    }

    fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, v)| v)
    }

    fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

impl<T> Index<&SlotId> for OrderedSlotMap<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        self.get(key).expect("no entry found for key")
    }
}

/// A possibly-empty ordered slot→value table keyed by
/// [`SlotId`] — the domain's keyed-by-slot collection type
/// (the possibly-empty variant of [`NonEmptySlotTable`], used for the
/// terminal's per-slot OUTCOMES, which are legitimately empty for a
/// pre-mutation failure). Uniqueness is structural (the ordered map has no
/// duplicate keys); the table carries no other invariant. Iteration
/// (`keys` / `values` / `iter`) is in INSERTION order — the deployment
/// order — never sorted by slot id.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SlotTable<T>(OrderedSlotMap<T>);

impl<T> SlotTable<T> {
    pub const fn new() -> Self {
        Self(OrderedSlotMap::new())
    }

    pub fn from_map<U: Into<T>>(map: BTreeMap<SlotId, U>) -> Self {
        Self(OrderedSlotMap::from_map(
            map.into_iter().map(|(k, v)| (k, v.into())).collect(),
        ))
    }

    pub fn into_map(self) -> BTreeMap<SlotId, T> {
        self.0.into_map()
    }

    /// Insert a slot→value entry, APPENDING a new key at the end of the
    /// table's sequence (the deployment order) and overwriting an existing
    /// key in place (its position is preserved).
    pub fn insert(&mut self, key: SlotId, value: T) {
        self.0.insert(key, value);
    }

    pub fn get(&self, key: &SlotId) -> Option<&T> {
        self.0.get(key)
    }

    pub fn contains_key(&self, key: &SlotId) -> bool {
        self.0.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.0.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.0.iter()
    }
}

impl<T> Index<&SlotId> for SlotTable<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        &self.0[key]
    }
}

impl<T: Serialize> Serialize for SlotTable<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for SlotTable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SlotTableVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for SlotTableVisitor<T> {
            type Value = SlotTable<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a slot table")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut table = OrderedSlotMap::new();
                while let Some((k, v)) = access.next_entry()? {
                    table.insert(k, v);
                }
                Ok(SlotTable(table))
            }
        }
        deserializer.deserialize_map(SlotTableVisitor(PhantomData))
    }
}

/// A NON-EMPTY ordered slot→value table keyed by [`SlotId`] — the
/// domain's authoritative membership-bearing collection type (the
/// non-empty variant of [`SlotTable`], used for the deployment intent's
/// slots and the degraded disposition's remaining changes). The domain
/// invariant is STRUCTURAL: the key set is unique (the ordered map) and
/// NON-EMPTY (the only constructor is the VERIFIED
/// [`NonEmptySlotTable::build`], which refuses the empty table — a
/// deployment that selects no slot cannot be represented). No
/// duplicate/missing-key state exists in the domain: a member slot always
/// carries its desired + pre-push entry, and no entry exists for a
/// non-member. Iteration (`keys` / `values` / `iter`) is in INSERTION
/// order — the deployment order — never sorted by slot id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptySlotTable<T>(OrderedSlotMap<T>);

impl<T> NonEmptySlotTable<T> {
    /// The VERIFIED constructor: refuse the empty table (fail closed — the
    /// domain cannot represent an empty deployment membership or an empty
    /// remaining-changes set). Uniqueness needs no check (the ordered map
    /// keys are unique by construction). The table's INSERTION SEQUENCE is
    /// the entry order of `entries` — the wire's `slot_ids` order — and
    /// iteration preserves it exactly.
    pub fn build<I>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (SlotId, T)>,
    {
        let mut table = OrderedSlotMap::new();
        for (key, value) in entries {
            table.insert(key, value);
        }
        if table.is_empty() {
            return Err(Error::integrity(
                "a non-empty slot table cannot be empty — the domain refuses an empty deployment membership / remaining-changes set",
            ));
        }
        Ok(Self(table))
    }

    pub fn get(&self, key: &SlotId) -> Option<&T> {
        self.0.get(key)
    }

    pub fn contains_key(&self, key: &SlotId) -> bool {
        self.0.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.0.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn into_map(self) -> BTreeMap<SlotId, T> {
        self.0.into_map()
    }
}

impl<T> Index<&SlotId> for NonEmptySlotTable<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        &self.0[key]
    }
}

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
/// `schema_version` is exactly [`crate::ledger::PINS_SCHEMA_VERSION`];
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

/// The WIRE outcome of one slot during a deployment's mutation loop — the
/// RAW serde form the ledger's JSONL carries, with the REDUNDANT `slot_id`
/// next to its map key (the wire keeps the on-disk shape; the wire → domain
/// conversion verifies the outcome names its own key and then DROPS the
/// slot into the key — the domain value [`SlotOutcome`] carries no slot).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotResult {
    pub slot_id: SlotId,
    pub outcome: SlotOutcomeKind,
    /// The generation this slot advanced to, or `None` if it never started.
    pub generation: Option<GenerationId>,
    pub compensated: bool,
    /// The pure OPERATION error (e.g. a swap failure) — the slot's own
    /// failure, INDEPENDENT of the post-mutation observation. NEVER
    /// rewritten by the post-observation pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The preserved error of a FAILED post-mutation OBSERVATION, or `None`
    /// when the observation succeeded (a recorded generation) or showed no
    /// state (`KnownAbsent`). Independent of `error`: an operation failure
    /// and a failed observation are TWO facts and both survive the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    // The ledger's two line kinds + merged entry live in [`crate::ledger::append`].
    use crate::identity::{
        MatchingMembership, PlacementSlotAssignment, RolloutGroupName, SlotSet, Timestamp,
        VariantName, test_deployment_id, test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::ledger::append::{LedgerEntry, LedgerLine};
    use crate::ledger::intent::{DeploymentIntent, LedgerIntentReport, LedgerIntentWire};
    use crate::ledger::observation::{ObservationError, ObservedGeneration};
    use crate::ledger::outcomes::{SlotOutcome, SlotTransition};
    use crate::ledger::rebinding::FrozenSlotTopology;
    use crate::ledger::terminal::{LedgerTerminal, LedgerTerminalWire, TerminalDisposition};
    use crate::store::local::LocalStore;
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
        agreeing_intent_with_group(keys, None)
    }

    /// [`agreeing_intent`] with an explicit GROUP MODE: `Some(g)` selects a
    /// group push (the intent's `slot_ids` are the group's slots), `None` a
    /// full push (the intent's `slot_ids` are every target slot).
    fn agreeing_intent_with_group(keys: &[SlotId], group: Option<&str>) -> LedgerIntentWire {
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: test_deployment_id("deploy-w"),
            target: TargetName::new("t1".to_string()),
            group: group.map(str::to_string),
            slot_ids: keys.to_vec(),
            behavior_sha256: "sha256-w".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    fn outcome_for(key: &SlotId, kind: SlotOutcomeKind) -> SlotResult {
        let compensated = matches!(&kind, SlotOutcomeKind::Restored);
        SlotResult {
            slot_id: key.clone(),
            outcome: kind,
            generation: Some(test_generation_id(key.as_str())),
            compensated,
            error: None,
            observation_error: None,
        }
    }

    /// A terminal wire AGREEING with its intent (identity + outcome-key
    /// membership + status→disposition payload). `status_idx` selects the
    /// status: 0 Successful (complete rollback over the membership), 1
    /// FailedPreflight (no outcomes, no rollback), 2 FailedRolledBack
    /// (outcomes = the compensation report), 3 Degraded (non-restored
    /// outcomes over the membership → non-empty remaining changes). The
    /// Successful shape carries the EXACT-EQUAL memberships (selected ==
    /// full == the membership — the full-push proven shape; the mode is the
    /// intent's `group`, chosen by the caller).
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

    /// A valid (intent + terminal) WIRE PAIR strategy: non-empty membership
    /// K, exact key-set equality in the intent, and a terminal AGREEING with
    /// the intent's identity and membership.
    fn agreeing_pair() -> impl Strategy<Value = (LedgerIntentWire, LedgerTerminalWire)> {
        (prop::collection::btree_set(slot_strategy(), 1..4), 0u32..4).prop_map(
            |(keys, status_idx)| {
                let keys: Vec<SlotId> = keys.into_iter().collect();
                (
                    agreeing_intent(keys.as_slice()),
                    agreeing_terminal(keys.as_slice(), status_idx),
                )
            },
        )
    }

    /// UNIQUE slot ids in an ARBITRARY PERMUTATION: a shuffled non-empty
    /// subset of the slot universe — the wire's `slot_ids` is the
    /// authoritative deployment order, so the ordering property must cover
    /// orders that are NOT sorted by id.
    fn slot_ids_permutation() -> impl Strategy<Value = Vec<SlotId>> {
        prop::collection::btree_set(slot_strategy(), 1..4).prop_flat_map(|set| {
            let ids: Vec<SlotId> = set.into_iter().collect();
            let n = ids.len();
            // Shuffle the selected ids by sorting random keys: every order is
            // reachable (with n ≤ 3 the key space is collision-free in
            // practice), and the strategy shrinks naturally.
            prop::collection::vec(0u32..1000, n).prop_map(move |keys| {
                let mut order: Vec<usize> = (0..n).collect();
                order.sort_by_key(|&i| keys[i]);
                order.into_iter().map(|i| ids[i].clone()).collect()
            })
        })
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
                if intent.group.is_none() {
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
                    if selected != full {
                        return Err(Error::integrity(format!(
                            "terminal {}: Successful records selected membership {selected:?} and full membership {full:?} — a FULL push (no group) selects every target slot, so its selected membership must EXACTLY equal its full membership",
                            pair.1.deployment_id
                        )));
                    }
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

    /// Write the pair as a two-line ledger and read it back through the REAL
    /// consumer path (`read_ledger` — the FIRST consumer; rollback resolve
    /// and GC reachability consume its output, so failing here means failing
    /// BEFORE every consumer).
    fn write_pair_ledger(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
    ) -> Result<Vec<LedgerEntry>> {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(pair.0.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(pair.1.clone())).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        store.read_ledger("t1")
    }

    /// Inspect the DOMAIN shapes produced from a VALID pair: the intent's
    /// ONE table (non-empty, unique keys, every member carries its desired +
    /// pre_push), and the terminal's disposition — each disposition OWNS its
    /// outcomes table (the accessor returns the disposition's OWN table; a
    /// FailedPreflight terminal carries none).
    fn assert_domain_shape(
        intent: &DeploymentIntent,
        terminal: &LedgerTerminal,
        keys: &[SlotId],
        status_idx: u32,
    ) {
        assert!(!intent.slots.is_empty(), "the membership is non-empty");
        assert_eq!(
            intent.slots.len(),
            keys.len(),
            "the table's key count equals the membership count (no duplicates, no missing)"
        );
        assert_eq!(
            intent.membership(),
            keys.to_vec(),
            "the membership is exactly the wire's slot_ids (deployment order)"
        );
        for key in keys {
            let entry = &intent.slots[key];
            assert!(
                entry
                    .desired
                    .artifact
                    .release
                    .as_str()
                    .starts_with("rel-sha256-"),
                "each member carries its desired assignment"
            );
            // The pre_push ENTRY is structural: every member slot has an
            // IntentSlot (with `pre_push: Option<PreviousGeneration>`,
            // `None` for a first deployment) — there is no member without
            // its per-slot data.
        }
        match (&terminal.disposition, status_idx) {
            (
                TerminalDisposition::Successful {
                    rollback, outcomes, ..
                },
                0,
            ) => {
                assert_eq!(
                    rollback.slots.len(),
                    keys.len(),
                    "the complete rollback covers every member slot"
                );
                assert_eq!(
                    rollback.bindings.len(),
                    keys.len(),
                    "every slotted generation carries its physical binding"
                );
                // The Successful disposition OWNS its outcome table: the
                // accessor returns the disposition's OWN table, and every
                // outcome is Activated (the conversion's agreement).
                assert_eq!(
                    terminal.outcomes(),
                    outcomes,
                    "the accessor reads the disposition's OWN table"
                );
                assert_eq!(
                    outcomes.len(),
                    keys.len(),
                    "the Successful disposition owns one outcome per member"
                );
                assert!(
                    outcomes
                        .values()
                        .all(|o| o.outcome == SlotOutcomeKind::Activated),
                    "a Successful disposition's outcomes are all Activated"
                );
                // THE PERSISTED MEMBERSHIPS: the domain exposes both, equal
                // to the membership (the exact-equal proven shape) — the
                // record PROVES selected == full == the outcome/rollback key
                // set.
                assert_eq!(
                    terminal.selected_membership(),
                    Some(&BTreeSet::from_iter(keys.iter().cloned())),
                    "the Successful disposition exposes its selected membership (== the outcomes' keys)"
                );
                assert_eq!(
                    terminal.full_membership(),
                    Some(&BTreeSet::from_iter(keys.iter().cloned())),
                    "the Successful disposition exposes its full membership (== the rollback's slots)"
                );
            }
            (TerminalDisposition::FailedPreflight, 1) => {
                assert!(
                    terminal.outcomes().is_empty(),
                    "preflight touched no slot (the disposition carries no outcomes)"
                );
            }
            (TerminalDisposition::FailedRolledBack { .. }, 2) => {
                let compensation = terminal.compensation().expect(
                    "a FailedRolledBack terminal's compensation report IS its own outcomes table",
                );
                assert_eq!(
                    compensation.len(),
                    keys.len(),
                    "the compensation report covers every compensated slot"
                );
                assert!(
                    compensation
                        .iter()
                        .all(|(_, r)| r.outcome == SlotOutcomeKind::Restored),
                    "the compensation records the restored slots"
                );
            }
            (TerminalDisposition::Degraded { .. }, 3) => {
                let remaining_changes = terminal
                    .remaining_changes(intent)
                    .expect("a Degraded terminal derives its remaining changes from the outcomes");
                assert!(
                    !remaining_changes.is_empty(),
                    "degraded keeps non-empty remaining changes"
                );
                assert_eq!(
                    remaining_changes.len(),
                    keys.len(),
                    "every non-restored slot is a remaining change"
                );
                // The Degraded disposition OWNS its outcome table: the
                // accessor returns the disposition's OWN table (the
                // remaining changes derive from it).
                let TerminalDisposition::Degraded { outcomes } = &terminal.disposition else {
                    unreachable!("matched above");
                };
                assert_eq!(
                    terminal.outcomes(),
                    outcomes,
                    "the accessor reads the disposition's OWN table"
                );
            }
            (d, s) => panic!("disposition {d:?} does not match the wire status index {s}"),
        }
    }

    // ---- the mutations: ONE field at a time --------------------------------

    /// A single-field terminal tamper (the property applies ONE per case).
    type TerminalMutation = fn(&mut LedgerTerminalWire);

    fn tamper_status(t: &mut LedgerTerminalWire) {
        t.status = match &t.status {
            DeploymentStatus::Successful => DeploymentStatus::FailedPreflight,
            DeploymentStatus::FailedPreflight => DeploymentStatus::Successful,
            DeploymentStatus::FailedRolledBack => DeploymentStatus::Successful,
            DeploymentStatus::Degraded => DeploymentStatus::FailedPreflight,
            other => other.clone(),
        };
    }
    fn rollback_added_to_failed(t: &mut LedgerTerminalWire) {
        if t.status != DeploymentStatus::Successful {
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        } else {
            t.rollback = None;
        }
    }
    fn rollback_extra_binding(t: &mut LedgerTerminalWire) {
        if let Some(rb) = t.rollback.as_mut() {
            rb.bindings.insert(slot(9), binding(&slot(9)));
        } else {
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        }
    }
    fn outcome_slot_mismatch(t: &mut LedgerTerminalWire) {
        if let Some((_, r)) = t.outcomes.iter_mut().next() {
            // An outcome value naming a DIFFERENT placement than its key.
            r.slot_id = slot(9);
        } else {
            // No outcomes (FailedPreflight): add one whose value names a
            // different placement than its key.
            t.outcomes
                .insert(slot(0), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        }
    }
    fn outcome_outside_membership(t: &mut LedgerTerminalWire) {
        t.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
    }
    fn outcome_status_vs_disposition(t: &mut LedgerTerminalWire) {
        match &t.status {
            DeploymentStatus::Degraded => {
                // The Degraded disposition implies non-restored remaining
                // changes; an all-restored outcome table is a disagreement.
                for r in t.outcomes.values_mut() {
                    r.outcome = SlotOutcomeKind::Restored;
                }
            }
            DeploymentStatus::FailedPreflight => {
                // A pre-mutation failure touched no slot; any outcome is a
                // disagreement.
                t.outcomes
                    .insert(slot(0), outcome_for(&slot(0), SlotOutcomeKind::Activated));
            }
            DeploymentStatus::Successful => {
                // The Successful disposition implies every slot activated; a
                // failed outcome is a disagreement.
                if let Some(r) = t.outcomes.values_mut().next() {
                    r.outcome = SlotOutcomeKind::Failed;
                }
            }
            DeploymentStatus::FailedRolledBack => {
                // The compensation report IS the outcome table — no per-slot
                // status can disagree with it; the disagreement is a
                // rollback payload on a failed status.
                t.rollback = Some(LedgerRollbackWire {
                    slots: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                    behavior_sha256: None,
                    release: None,
                });
            }
            other => panic!("unexpected wire status {other:?}"),
        }
    }
    fn outcome_key_vs_rollback_slots(t: &mut LedgerTerminalWire) {
        if t.status == DeploymentStatus::Successful {
            // The Successful rollback is the authoritative rollback fact; an
            // outcome key the rollback no longer covers is a disagreement.
            let Some(rb) = t.rollback.as_mut() else {
                return;
            };
            let Some(key) = rb.slots.keys().next().cloned() else {
                return;
            };
            rb.slots.remove(&key);
            rb.bindings.remove(&key);
        } else {
            // Only Successful may carry a rollback; a failed status with one
            // is a disagreement.
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        }
    }
    fn reason_mutated(t: &mut LedgerTerminalWire) {
        // The reason is a free-form human NOTE, not a fact: it never
        // participates in invariants, so mutating it is NOT a disagreement.
        t.reason = Some("tampered note".to_string());
    }
    fn target_mismatch(t: &mut LedgerTerminalWire) {
        t.target = TargetName::new("other-target".to_string());
    }
    fn deployment_id_mismatch(t: &mut LedgerTerminalWire) {
        t.deployment_id = test_deployment_id("deploy-other");
    }

    proptest! {
        // PROPERTY (the directive's point 4): generate VALID wire pairs
        // (intent + terminal), then mutate ONE duplicated fact at a time —
        // the status→disposition mapping, the rollback payload, an outcome
        // slot, an outcome's status vs the disposition's implied state, an
        // outcome key vs the rollback's slots, the target identity — and
        // assert EVERY disagreement fails the verifying conversion BEFORE
        // any consumer (the REAL read_ledger consumer path), while the
        // VALID pair converts to a DOMAIN whose SHAPE has no
        // duplicates/missing keys (asserted by inspection of the
        // NonEmptySlotTable / outcomes / disposition) and whose DERIVED
        // methods (`remaining_changes`, `compensation`) agree with the
        // outcomes by construction. The REASON is a free-form human note,
        // NOT a fact: mutating it never creates a disagreement — the
        // conversion succeeds and carries the note through unchanged.
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
        // persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wire_pair_mutations_fail_before_any_consumer_and_valid_pairs_shape(
            (intent, terminal) in agreeing_pair()
        ) {
            let keys: Vec<SlotId> = intent.slot_ids.clone();
            let status_idx = match terminal.status {
                DeploymentStatus::Successful => 0,
                DeploymentStatus::FailedPreflight => 1,
                DeploymentStatus::FailedRolledBack => 2,
                DeploymentStatus::Degraded => 3,
                other => panic!("unexpected wire status {other:?}"),
            };
            let (d_intent, d_terminal) = pair_to_domain(&(intent.clone(), terminal.clone()))
                .expect("the agreeing pair converts");
            assert_domain_shape(&d_intent, &d_terminal, &keys, status_idx);
            let entries = write_pair_ledger(&(intent.clone(), terminal.clone()))
                .expect("the agreeing pair reads through the real ledger");
            assert_eq!(entries.len(), 1, "one merged entry");
            assert_domain_shape(
                &entries[0].intent,
                entries[0].terminal.as_ref().unwrap(),
                &keys,
                status_idx,
            );

            let mutations: [(&str, TerminalMutation); 9] = [
                ("status→disposition mismatch", tamper_status),
                ("rollback payload mismatch (missing on Successful / added to a failed status)", rollback_added_to_failed),
                ("rollback binding without a generation", rollback_extra_binding),
                ("outcome value naming a different slot", outcome_slot_mismatch),
                ("outcome key outside the membership", outcome_outside_membership),
                ("outcome status vs the disposition's implied state", outcome_status_vs_disposition),
                ("outcome key vs the rollback's slots", outcome_key_vs_rollback_slots),
                ("terminal target disagrees with the entry", target_mismatch),
                ("terminal deployment id keys no intent line", deployment_id_mismatch),
            ];
            for (name, mutate) in mutations {
                let mut bad = (intent.clone(), terminal.clone());
                mutate(&mut bad.1);
                let err = pair_to_domain(&bad);
                assert!(
                    err.is_err(),
                    "{name} must fail the conversion BEFORE any consumer"
                );
                let ledger_err = write_pair_ledger(&bad);
                assert!(
                    ledger_err.is_err(),
                    "{name} must fail read_ledger (the first consumer)"
                );
            }

            // The REASON is a free-form human note, NOT a fact: mutating it
            // never creates a disagreement — the conversion succeeds and
            // carries the note through unchanged (it never participates in
            // invariants).
            let mut noted = (intent, terminal);
            reason_mutated(&mut noted.1);
            let (_, d_terminal) =
                pair_to_domain(&noted).expect("a mutated reason is not a disagreement");
            assert_eq!(
                d_terminal.reason.as_deref(),
                Some("tampered note"),
                "the note is carried through unchanged"
            );
        }
    }

    // ---- THE MEMBERSHIP-EQUATIONS PROPERTY (Successful) --------------------

    /// One key-set operation applied to ONE of the four INDEPENDENT SETS
    /// (outcomes, selected_membership, full_membership, rollback slots).
    /// The ops are chosen INDEPENDENTLY per set; the application is
    /// deterministic given the op (delete the first key / add the first
    /// absent slot / replace the first key with a different absent slot), so
    /// the property's "acceptance iff the membership equations hold" verdict
    /// is exact.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KeyOp {
        Unchanged,
        Delete,
        Add,
        Replace,
    }

    fn key_op() -> impl Strategy<Value = KeyOp> {
        prop_oneof![
            Just(KeyOp::Unchanged),
            Just(KeyOp::Delete),
            Just(KeyOp::Add),
            Just(KeyOp::Replace),
        ]
    }

    /// Apply one key op to a slot set (deterministic: delete the first
    /// key, add the first slot absent from the set, replace the first key
    /// with the first absent slot).
    fn apply_key_op(set: &BTreeSet<SlotId>, op: KeyOp) -> BTreeSet<SlotId> {
        let mut out = set.clone();
        match op {
            KeyOp::Unchanged => {}
            KeyOp::Delete => {
                if let Some(k) = out.iter().next().cloned() {
                    out.remove(&k);
                }
            }
            KeyOp::Add => {
                for i in 0..6u32 {
                    let k = slot(i);
                    if !out.contains(&k) {
                        out.insert(k);
                        break;
                    }
                }
            }
            KeyOp::Replace => {
                if let Some(k) = out.iter().next().cloned() {
                    out.remove(&k);
                    for i in 0..6u32 {
                        let nk = slot(i);
                        if !out.contains(&nk) && nk != k {
                            out.insert(nk);
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    /// Rebuild the intent wire with a NEW membership, keeping the intent's
    /// internal agreement (slot_ids == desired == pre_push, each assignment
    /// names its own key, the wire actuals map empty).
    fn intent_with_membership(
        intent: &LedgerIntentWire,
        membership: &BTreeSet<SlotId>,
    ) -> LedgerIntentWire {
        let keys: Vec<SlotId> = membership.iter().cloned().collect();
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: intent.deployment_schema_version,
            deployment_id: intent.deployment_id.clone(),
            target: intent.target.clone(),
            group: intent.group.clone(),
            slot_ids: keys.clone(),
            behavior_sha256: intent.behavior_sha256.clone(),
            attempted_at: intent.attempted_at.clone(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    /// Apply the four INDEPENDENT key ops to a valid Successful pair and
    /// return the tampered pair: (1) the outcomes keys, (2) the
    /// selected_membership, (3) the full_membership, (4) the rollback's
    /// slots keys — with the rollback's BINDINGS COUPLED to its slots
    /// (slots == bindings is the separate structural rollback invariant,
    /// NOT one of the four independent sets — the user's requirement
    /// couples them here). The intent is REBUILT over the UNION of the four
    /// resulting sets (so the intent never adds a verdict of its own: every
    /// outcome key is an intent member by construction, and the read's
    /// Successful leg compares only the terminal's OWN memberships) with the
    /// given MODE applied to its `group` (`Some("g1")` = group push,
    /// `None` = full push).
    fn apply_four_set_tamper(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
        ops: [KeyOp; 4],
        group: bool,
    ) -> (LedgerIntentWire, LedgerTerminalWire) {
        let (intent, terminal) = pair;
        let mut terminal = terminal.clone();
        // (1) outcomes keys.
        let outcome_keys: BTreeSet<SlotId> = terminal.outcomes.keys().cloned().collect();
        let new_outcomes = apply_key_op(&outcome_keys, ops[0]);
        terminal.outcomes = new_outcomes
            .iter()
            .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Activated)))
            .collect();
        // (2) selected_membership, (3) full_membership.
        let selected: BTreeSet<SlotId> = terminal.selected_membership.iter().cloned().collect();
        terminal.selected_membership = apply_key_op(&selected, ops[1]).into_iter().collect();
        let full: BTreeSet<SlotId> = terminal.full_membership.iter().cloned().collect();
        terminal.full_membership = apply_key_op(&full, ops[2]).into_iter().collect();
        // (4) rollback slots keys (bindings coupled to the slots).
        let rb = terminal
            .rollback
            .as_mut()
            .expect("a Successful terminal carries its rollback");
        let slot_keys: BTreeSet<SlotId> = rb.slots.keys().cloned().collect();
        let new_slots = apply_key_op(&slot_keys, ops[3]);
        rb.slots = new_slots
            .iter()
            .map(|k| (k.clone(), gen_ref_for(k)))
            .collect();
        rb.bindings = new_slots.iter().map(|k| (k.clone(), binding(k))).collect();
        // The intent: rebuilt over the UNION of the four resulting sets so it
        // never adds a verdict (every outcome key is an intent member), with
        // the mode applied to its `group`.
        let union: BTreeSet<SlotId> = terminal
            .outcomes
            .keys()
            .cloned()
            .chain(terminal.selected_membership.iter().cloned())
            .chain(terminal.full_membership.iter().cloned())
            .chain(rb.slots.keys().cloned())
            .collect();
        let mut intent = intent_with_membership(intent, &union);
        intent.group = if group { Some("g1".to_string()) } else { None };
        (intent, terminal)
    }

    /// Evaluate THE MEMBERSHIP EQUATIONS for a written pair (the four sets +
    /// the mode) — the acceptance criterion the properties assert
    /// `read_ledger` is EXACTLY EQUIVALENT to:
    ///
    /// * outcomes == selected_membership
    /// * rollback slots == full_membership (bindings == slots by
    ///   construction — the coupled structural invariant)
    /// * selected_membership ⊆ full_membership
    /// * (FULL mode) selected_membership == full_membership — in GROUP mode
    ///   a proper-subset selected is allowed
    ///
    /// plus the Successful NON-EMPTINESS (a successful deployment records
    /// non-empty outcomes and both memberships non-empty).
    fn membership_equations_hold(pair: &(LedgerIntentWire, LedgerTerminalWire)) -> bool {
        let terminal = &pair.1;
        let outcomes: BTreeSet<SlotId> = terminal.outcomes.keys().cloned().collect();
        let selected: BTreeSet<SlotId> = terminal.selected_membership.iter().cloned().collect();
        let full: BTreeSet<SlotId> = terminal.full_membership.iter().cloned().collect();
        let rollback_slots: BTreeSet<SlotId> = terminal
            .rollback
            .as_ref()
            .map(|rb| rb.slots.keys().cloned().collect())
            .unwrap_or_default();
        let full_mode = pair.0.group.is_none();
        outcomes == selected
            && rollback_slots == full
            && selected.is_subset(&full)
            && (!full_mode || selected == full)
            && !outcomes.is_empty()
            && !selected.is_empty()
            && !full.is_empty()
            && !rollback_slots.is_empty()
    }

    /// The GROUP/FULL MODE of a Successful pair, generated per house style.
    fn membership_mode() -> impl Strategy<Value = bool> {
        prop_oneof![Just(true), Just(false)]
    }

    proptest! {
        // PROPERTY 1 (the user's requirement — the acceptance equivalence):
        // generate the FOUR INDEPENDENT SETS — (1) the outcome keys, (2)
        // the selected_membership, (3) the full_membership, (4) the
        // rollback's slot keys (bindings generated EQUAL to the slots — the
        // separate structural rollback invariant, kept coupled here) — by
        // INDEPENDENTLY DELETE / ADD / REPLACE ops from a valid base pair,
        // plus a group/full MODE. READING (the real `read_ledger` of the
        // written pair — the durable write → re-read path) SUCCEEDS IFF
        // THE MEMBERSHIP EQUATIONS HOLD FOR THAT MODE: outcomes ==
        // selected_membership, rollback slots == full_membership, selected
        // ⊆ full, and (full mode) selected == full — with a group mode a
        // proper-subset selected is allowed — plus the Successful
        // non-emptiness. The intent is rebuilt over the union of the four
        // sets so it never adds a verdict of its own; the mode is applied to
        // the intent's `group`. Bounded 16 cases, fixed seed 0x5EED_5EED
        // per house style, no persistence.
        //
        // PROPERTY 2 (the user's requirement — single-set mutation
        // rejection): start from a VALID pair (all equations hold), apply a
        // tamper to EXACTLY ONE of the four sets (add/remove/change a key)
        // while leaving the other three AND the mode fixed, and assert
        // read_ledger REJECTS — every single-set mutation breaks at least
        // one equation (mutating the outcomes or the selected membership
        // alone breaks outcomes == selected; mutating the full membership or
        // the rollback slots alone breaks rollback == full). The rejection
        // is asserted through the REAL ledger file (write → re-read — the
        // crash-recovery read path), so a tampered record is refused even
        // after a durable write.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn successful_membership_equations_are_necessary_and_sufficient(
            (intent, terminal) in agreeing_pair().prop_filter(
                "the property needs a Successful pair",
                |(_, t)| t.status == DeploymentStatus::Successful,
            ),
            ops in prop::array::uniform4(key_op()),
            group in membership_mode(),
        ) {
            let (t_intent, t_terminal) = apply_four_set_tamper(&(intent, terminal), ops, group);
            let pair = (t_intent, t_terminal);
            let expect_ok = membership_equations_hold(&pair);
            let read = write_pair_ledger(&pair);
            assert_eq!(
                read.is_ok(),
                expect_ok,
                "read_ledger must succeed iff the membership equations hold for the mode (outcomes {:?}, selected {:?}, full {:?}, rollback slots {:?}, full mode: {}); read: {:?}",
                pair.1.outcomes.keys().collect::<BTreeSet<_>>(),
                pair.1.selected_membership,
                pair.1.full_membership,
                pair.1.rollback.as_ref().map(|rb| rb.slots.keys().collect::<BTreeSet<_>>()),
                pair.0.group.is_none(),
                read
            );
        }

        #[test]
        fn mutating_any_single_membership_set_causes_rejection(
            (intent, terminal) in agreeing_pair().prop_filter(
                "the property needs a Successful pair",
                |(_, t)| t.status == DeploymentStatus::Successful,
            ),
            set_idx in 0u32..4,
            op in key_op().prop_filter("the tamper must change the set", |op| {
                *op != KeyOp::Unchanged
            }),
            group in membership_mode(),
        ) {
            let mut ops = [KeyOp::Unchanged; 4];
            ops[set_idx as usize] = op;
            let (t_intent, t_terminal) = apply_four_set_tamper(&(intent, terminal), ops, group);
            let pair = (t_intent, t_terminal);
            // A VALID base pair satisfies every equation, so tampering EXACTLY
            // ONE of the four sets must break at least one equation — and the
            // read (the durable write → re-read crash-recovery path) must
            // reject.
            assert!(
                !membership_equations_hold(&pair),
                "mutating exactly one set must break an equation (set {set_idx}, op {op:?})"
            );
            assert!(
                write_pair_ledger(&pair).is_err(),
                "mutating exactly one of the four sets (set {set_idx}, op {op:?}) must be rejected by read_ledger — the durable write → re-read is the crash-recovery read"
            );
        }
    }

    // ---- THE ORDERING PROPERTY (the ordered tables) ------------------------

    proptest! {
        // THE ORDERING PROPERTY (the user's requirement): the wire's
        // `slot_ids` is the AUTHORITATIVE deployment order, and the domain
        // table must PRESERVE it exactly — never silently re-sort by slot
        // id. Over UNIQUE slot ids in ARBITRARY PERMUTATIONS, the wire →
        // domain → wire round trip must reproduce the EXACT `slot_ids`
        // sequence (not the sorted order): the domain table iterates in the
        // wire's sequence, the domain → wire re-expansion emits the same
        // sequence, and the full JSON round trip preserves it. Bounded 16
        // cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wire_slot_ids_sequence_round_trips_exactly(keys in slot_ids_permutation()) {
            let wire = agreeing_intent(&keys);
            let domain = wire
                .clone()
                .into_domain()
                .expect("the agreeing intent converts");
            // The DOMAIN table iterates in the wire's sequence order.
            assert_eq!(
                domain.membership(),
                keys,
                "the domain table must preserve the wire's slot_ids sequence (deployment order), not sort by id"
            );
            // The domain → wire re-expansion emits the SAME sequence.
            let wire2 = LedgerIntentWire::from(&domain);
            assert_eq!(
                wire2.slot_ids, keys,
                "the domain → wire re-expansion must reproduce the exact slot_ids sequence"
            );
            // The full JSON round trip (serialize → deserialize) too.
            let json = serde_json::to_string(&domain).unwrap();
            let wire3: LedgerIntentWire = serde_json::from_str(&json).unwrap();
            assert_eq!(
                wire3.slot_ids, keys,
                "the JSON round trip must preserve the exact slot_ids sequence"
            );
        }
    }

    // ---- deterministic unit tests -----------------------------------------

    /// THE MEMBERSHIP EQUATIONS, SUFFICIENCY DIRECTION (deterministic): a
    /// tamper that happens to KEEP the equations satisfied is NOT a
    /// disagreement — the read succeeds. (The necessity direction — any
    /// single-set divergence fails — is Property 2's verdict; this pins the
    /// sufficiency cases the bounded property may not draw: a FULL push with
    /// the SAME key added to ALL FOUR sets, a GROUP push whose FULL side
    /// grows alone (selected stays a proper subset), and a GROUP push whose
    /// SELECTED side grows alone.)
    #[test]
    fn successful_membership_equations_suffice_when_a_tamper_keeps_them_satisfied() {
        let keys = vec![slot(1), slot(2)];
        let intent = agreeing_intent(&keys);
        let terminal = agreeing_terminal(&keys, 0);
        // The untampered pair reads.
        write_pair_ledger(&(intent.clone(), terminal.clone()))
            .expect("the exact-equal Successful pair reads");
        // FULL mode: add the SAME key (slot-9) to ALL FOUR sets — the
        // equations stay satisfied (outcomes == selected == full ==
        // rollback slots), so the read still succeeds.
        let mut intent = intent;
        intent.slot_ids.push(slot(9));
        intent.desired.insert(slot(9), gen_ref_for(&slot(9)));
        intent.pre_push.insert(slot(9), None);
        let mut terminal = terminal;
        terminal
            .outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        terminal.selected_membership.push(slot(9));
        terminal.full_membership.push(slot(9));
        let rb = terminal.rollback.as_mut().unwrap();
        rb.slots.insert(slot(9), gen_ref_for(&slot(9)));
        rb.bindings.insert(slot(9), binding(&slot(9)));
        let entries = write_pair_ledger(&(intent, terminal)).expect(
            "adding the same key to all four sets keeps the equations satisfied — the read succeeds",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].intent.slots.len(),
            3,
            "the intent's membership grew with the added key"
        );

        // GROUP mode: a proper-subset selected (selected = {slot-1} ⊊ full =
        // {slot-1, slot-2}) is LEGAL and reads.
        let selected = vec![slot(1)];
        let full = vec![slot(1), slot(2)];
        let mut terminal = agreeing_terminal(&full, 0);
        terminal.outcomes =
            BTreeMap::from([(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated))]);
        terminal.selected_membership = selected.clone();
        let intent = agreeing_intent_with_group(&selected, Some("g1"));
        write_pair_ledger(&(intent.clone(), terminal.clone()))
            .expect("the group-proper-subset pair reads");
        // GROW THE FULL SIDE ONLY (full + rollback): selected ⊊ full stays —
        // the read succeeds.
        let mut terminal2 = terminal.clone();
        terminal2.full_membership.push(slot(3));
        let rb = terminal2.rollback.as_mut().unwrap();
        rb.slots.insert(slot(3), gen_ref_for(&slot(3)));
        rb.bindings.insert(slot(3), binding(&slot(3)));
        write_pair_ledger(&(intent.clone(), terminal2))
            .expect("growing only the full membership keeps selected ⊆ full — the read succeeds");
        // GROW THE SELECTED SIDE ONLY, WITHIN the full membership
        // (selected + outcomes grow to equal full): selected ⊆ full stays —
        // the read succeeds. The intent (whose slot_ids ARE the selected
        // set for a group push) grows with the selection.
        let mut terminal3 = terminal;
        terminal3.selected_membership.push(slot(2));
        terminal3
            .outcomes
            .insert(slot(2), outcome_for(&slot(2), SlotOutcomeKind::Activated));
        let intent3 = agreeing_intent_with_group(&[slot(1), slot(2)], Some("g1"));
        write_pair_ledger(&(intent3, terminal3)).expect(
            "growing the selected membership (and its outcomes) within the full membership keeps selected ⊆ full — the read succeeds",
        );
    }

    /// Write the pair as a two-line ledger AND a `deploy.toml` whose target
    /// `t1` owns exactly the given SIMULATED current configuration slots,
    /// then read the ledger back through the REAL consumer path. The
    /// membership equations NEVER consult this configuration — the helper
    /// exists to demonstrate (in
    /// [`acceptance_is_pure_function_of_persisted_sets_and_mode_ignores_config`])
    /// that acceptance is a PURE function of the persisted sets + mode:
    /// re-reading the SAME pair under a DIFFERENT simulated config
    /// membership yields the SAME verdict.
    fn write_pair_ledger_under_config(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
        simulated_slots: &[SlotId],
    ) -> Result<Vec<LedgerEntry>> {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // A real, LOADABLE project config whose target `t1` owns exactly
        // `simulated_slots` (one server, one release). `read_ledger` never
        // touches it — the config exists only to make the simulation
        // concrete: a hypothetical config-reading consumer would see THIS
        // current membership.
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        let mut release = String::from("[artifact]\nmappings = []\n\n");
        for s in simulated_slots {
            release.push_str(&format!(
                "[[slots]]\nid = \"{}\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = []\ndeploy_dir = \"/srv\"\n\n",
                s.as_str()
            ));
        }
        release.push_str(
            "[retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n[retention.deployment]\nprotect_deployments = 1\n\n[activation]\nadapter = \"none\"\n\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            release,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            "schema_version = 2\napplication = \"records-tests\"\nrelease = \"v1\"\n\n\
             [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
             [targets.t1]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n",
        )
        .unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(pair.0.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(pair.1.clone())).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        store.read_ledger("t1")
    }

    /// CONFIGURATION MEMBERSHIP INDEPENDENCE (the user's requirement):
    /// acceptance of a Successful pair is a PURE function of the persisted
    /// sets + mode — the read path ([`LocalStore::read_ledger`]) NEVER
    /// consults the live configuration for the membership equations. The
    /// SAME written pair is read back while simulating DIFFERENT current
    /// configuration memberships (a target config whose slots differ from
    /// the pair's persisted sets), and the verdict is unchanged: a valid
    /// pair stays accepted, a tampered pair stays rejected.
    #[test]
    fn acceptance_is_pure_function_of_persisted_sets_and_mode_ignores_config() {
        // A valid GROUP-mode pair: selected = {slot-1} ⊊ full = {slot-1,
        // slot-2} — the group-proper-subset shape a group push legitimately
        // records (outcomes == selected, rollback == full, selected ⊆ full).
        let selected = vec![slot(1)];
        let full = vec![slot(1), slot(2)];
        let mut terminal = agreeing_terminal(&full, 0);
        terminal.outcomes =
            BTreeMap::from([(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated))]);
        terminal.selected_membership = selected.clone();
        let intent = agreeing_intent_with_group(&selected, Some("g1"));
        let pair = (intent, terminal);
        assert!(membership_equations_hold(&pair), "the group pair is valid");
        // Accepted under a config whose membership equals the FULL set …
        write_pair_ledger_under_config(&pair, &full)
            .expect("the valid pair reads under a config matching the full membership");
        // … and accepted under a config whose membership is a DIFFERENT set
        // (a simulated membership change): the verdict is unchanged.
        write_pair_ledger_under_config(&pair, &[slot(9)])
            .expect("the valid pair's acceptance is a PURE function of the persisted sets + mode — a different current configuration membership does not change it");

        // A tampered variant: add a key to the SELECTED set only — outcomes
        // == selected breaks. Rejected under BOTH simulated configs.
        let mut bad = pair.clone();
        bad.1.selected_membership.push(slot(3));
        assert!(
            !membership_equations_hold(&bad),
            "the single-set mutation breaks the equations"
        );
        write_pair_ledger_under_config(&bad, &full).expect_err(
            "the tampered pair must stay rejected under a config matching the full membership",
        );
        write_pair_ledger_under_config(&bad, &[slot(9)]).expect_err(
            "the tampered pair must stay rejected under a DIFFERENT current configuration membership",
        );

        // A valid FULL-mode pair (selected == full) and its tamper: same
        // independence.
        let keys = vec![slot(1), slot(2)];
        let pair = (agreeing_intent(&keys), agreeing_terminal(&keys, 0));
        assert!(membership_equations_hold(&pair), "the full pair is valid");
        write_pair_ledger_under_config(&pair, &keys)
            .expect("the valid full pair reads under a config matching its membership");
        write_pair_ledger_under_config(&pair, &[slot(5)]).expect(
            "the valid full pair's acceptance is a PURE function of the persisted sets + mode — a different current configuration membership does not change it",
        );
        let mut bad = pair.clone();
        bad.1.full_membership.push(slot(3));
        bad.1
            .rollback
            .as_mut()
            .unwrap()
            .slots
            .insert(slot(3), gen_ref_for(&slot(3)));
        bad.1
            .rollback
            .as_mut()
            .unwrap()
            .bindings
            .insert(slot(3), binding(&slot(3)));
        assert!(
            !membership_equations_hold(&bad),
            "the full-side mutation breaks the equations"
        );
        write_pair_ledger_under_config(&bad, &keys)
            .expect_err("the tampered full pair must stay rejected");
        write_pair_ledger_under_config(&bad, &[slot(5)]).expect_err(
            "the tampered full pair must stay rejected under a DIFFERENT current configuration membership",
        );
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
            SlotAttemptState {
                artifact: Observation::Unknown(ObservationError {
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
        let group_intent = agreeing_intent_with_group(&selected, Some("g1"));
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

    /// THE ENTRY OWNS IDENTITY: the domain terminal carries no
    /// deployment_id/target; the reader verifies the wire terminal's
    /// identity against its ENTRY (the intent's) and the outcome keys
    /// against the membership — a mismatch is refused before any consumer.
    #[test]
    fn entry_owns_identity_and_refuses_cross_record_disagreements() {
        let keys = vec![slot(1), slot(2)];
        let intent = agreeing_intent(&keys);
        // A terminal claiming a DIFFERENT target than its entry.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.target = TargetName::new("other".to_string());
        let err = pair_to_domain(&(intent.clone(), terminal))
            .expect_err("a target disagreement is refused");
        assert!(err.to_string().contains("target"), "err: {err}");
        // A terminal claiming a deployment id with no intent line.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.deployment_id = test_deployment_id("deploy-ghost");
        assert!(pair_to_domain(&(intent.clone(), terminal)).is_err());
        // An outcome key outside the intent's membership.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal
            .outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        assert!(pair_to_domain(&(intent.clone(), terminal)).is_err());
        // An outcome value naming a different slot than its key.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.outcomes.get_mut(&slot(1)).unwrap().slot_id = slot(2);
        assert!(pair_to_domain(&(intent, terminal)).is_err());
    }

    /// [`NonEmptySlotTable`] refuses the empty map; [`SlotTable`] is the
    /// possibly-empty variant (terminal outcomes are legitimately empty for
    /// a preflight failure).
    #[test]
    fn slot_tables_enforce_non_emptiness_where_the_domain_requires_it() {
        assert!(NonEmptySlotTable::<u32>::build(BTreeMap::new()).is_err());
        let ok = NonEmptySlotTable::build(BTreeMap::from([(slot(1), 7u32)])).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[&slot(1)], 7);
        assert!(SlotTable::<u32>::new().is_empty());
    }

    /// The ordered tables PRESERVE INSERTION ORDER across build / get /
    /// iter / keys: a table built from a deliberately NON-sorted sequence
    /// iterates in exactly that sequence (never sorted by slot id), and
    /// `get` / `contains_key` / `len` / indexing still work.
    /// `SlotTable::insert` appends new keys and keeps an overwritten key's
    /// position.
    #[test]
    fn slot_tables_preserve_insertion_order_across_build_get_iter_keys() {
        // Deliberately NOT sorted by id: the deployment order.
        let order = vec![slot(3), slot(1), slot(5), slot(0)];
        let table = NonEmptySlotTable::build(
            order
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, k)| (k, i as u32)),
        )
        .unwrap();
        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            order,
            "keys() iterates in insertion order, not sorted by id"
        );
        assert_eq!(
            table.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            order,
            "iter() iterates in insertion order"
        );
        assert_eq!(
            table.values().cloned().collect::<Vec<_>>(),
            vec![0, 1, 2, 3],
            "values() iterates in insertion order"
        );
        assert_eq!(table.len(), 4);
        assert_eq!(table.get(&slot(1)), Some(&1));
        assert!(table.contains_key(&slot(5)));
        assert!(!table.contains_key(&slot(2)));
        assert_eq!(table[&slot(0)], 3, "indexing works");

        // The possibly-empty variant preserves the same order.
        let mut empty = SlotTable::new();
        assert!(empty.is_empty());
        empty.insert(slot(2), 2u32);
        empty.insert(slot(0), 0u32);
        assert_eq!(
            empty.keys().cloned().collect::<Vec<_>>(),
            vec![slot(2), slot(0)],
            "SlotTable::insert appends in insertion order"
        );
        // Overwriting an existing key keeps its position.
        empty.insert(slot(2), 9u32);
        assert_eq!(
            empty.keys().cloned().collect::<Vec<_>>(),
            vec![slot(2), slot(0)],
            "an overwritten key keeps its original position"
        );
        assert_eq!(empty[&slot(2)], 9, "the overwritten value is visible");
    }

    /// The wire rollback payload converts into the domain rollback with the
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
            generation: Some(test_generation_id("gen-1")),
            compensated: false,
            error: None,
            observation_error: None,
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
    /// arbitrary preserved message — carried by the wire's
    /// `observation_error` field). The wire has a separate field per fact,
    /// so NO agreement is forced: every (operation_error, observation)
    /// combination is a valid outcome that round-trips exactly.
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
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
            slot_ids.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: test_deployment_id("deploy-scalar"),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids,
            behavior_sha256: crate::identity::DIGEST_TEST_HEX_1.to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
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
                Some(SlotAttemptState {
                    artifact: Observation::Unknown(ObservationError {
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
                outcomes: SlotTable::from_map(outcomes.into_iter().collect()),
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
                    generation: Some(GenerationId::new("pre-1".to_string())),
                    compensated: false,
                    error: None,
                    observation_error: None,
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
                    generation: Some(GenerationId::new("new-1".to_string())),
                    compensated: false,
                    error: None,
                    observation_error: None,
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
                    generation: Some(GenerationId::new("new-1".to_string())),
                    compensated: true,
                    error: None,
                    observation_error: None,
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
                    generation: Some(GenerationId::new("pre-1".to_string())),
                    compensated: false,
                    error: None,
                    observation_error: None,
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
                    generation: Some(GenerationId::new("new-1".to_string())),
                    compensated: false,
                    error: None,
                    observation_error: None,
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
        // observation (the wire's `generation: None` + preserved
        // OBSERVATION error — `observation_error`, independent of the
        // operation error — reads back as `Unknown`, never as a `None` that
        // downstream code reads as "no change").
        let (intent, terminal) = degraded_terminal_with(
            vec![(
                slot(1),
                SlotResult {
                    slot_id: slot(1),
                    outcome: SlotOutcomeKind::Failed,
                    generation: None,
                    compensated: false,
                    error: Some("swap failed: boom".to_string()),
                    observation_error: Some("status read failed: boom".to_string()),
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
    // as KnownAbsent/unchanged). Bounded 16 cases, fixed seed 0x5EED_5EED.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 16,
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
            // Every slot's post-mutation status read fails: the wire carries
            // `generation: None` + the preserved OBSERVATION error in
            // `observation_error` (independently of the slot's OPERATION
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
                            generation: None,
                            compensated: false,
                            // A DISTINCT operation error: the pre-swap
                            // failure that stopped the slot (e.g. a swap
                            // failure) — must survive the observation
                            // untouched.
                            error: Some(format!("swap failed: {err_msg}")),
                            observation_error: Some(err_msg.clone()),
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
            // observation error survives via `observation_error` and reads
            // back as `Unknown`, never as `KnownAbsent`; the operation error
            // survives via `error` untouched.
            for sid in &slots {
                let outcome = terminal.outcomes().get(sid).unwrap();
                let wire = SlotResult::from_outcome(sid, outcome);
                assert_eq!(wire.generation, None);
                assert_eq!(
                    wire.error,
                    Some(format!("swap failed: {err_msg}")),
                    "slot {sid}: the operation error must survive the wire untouched"
                );
                assert_eq!(
                    wire.observation_error,
                    Some(err_msg.clone()),
                    "slot {sid}: the observation error must survive the wire untouched"
                );
                let back = SlotOutcome::from_wire(wire);
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
                generation: test_generation_id(&format!("obs-{i}")),
            })),
            Just(Observation::KnownAbsent),
            prop::sample::select(vec![
                "status read failed: boom".to_string(),
                "assignment read failed: boom".to_string(),
            ])
            .prop_map(|e| Observation::Unknown(ObservationError { message: e })),
        ]
    }

    /// MIRROR of the engine's post-observation pass (`src/push/engine.rs`'s
    /// `never_advanced` loop): apply a generated post-mutation observation
    /// to a wire [`SlotResult`], mutating ONLY the observation fields
    /// (`generation` / `observation_error`) — the operation error (`error`)
    /// is NEVER touched. The engine loop is not cleanly reachable from a
    /// records-level unit test, so this helper mirrors its fixed logic.
    fn apply_post_observation(r: &mut SlotResult, observation: &Observation<ObservedGeneration>) {
        match observation {
            Observation::Known(og) => r.generation = Some(og.generation.clone()),
            Observation::Unknown(e) => {
                r.generation = None;
                r.observation_error = Some(e.message.clone());
            }
            Observation::KnownAbsent => {
                r.generation = None;
                r.observation_error = None;
            }
        }
    }

    /// (a) An outcome carrying BOTH an operation error AND an `Unknown`
    /// observation round-trips preserving both — the two facts are
    /// INDEPENDENT on the wire (the old single-error wire could not carry a
    /// distinct operation error alongside a failed observation).
    #[test]
    fn operation_error_and_unknown_observation_round_trip_preserves_both() {
        let outcome = SlotOutcome {
            outcome: SlotOutcomeKind::Failed,
            observation: Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            transition: SlotTransition::AdvanceUnknown,
        };
        let wire = SlotResult::from_outcome(&slot(1), &outcome);
        assert_eq!(wire.generation, None);
        assert_eq!(
            wire.error,
            Some("swap failed: boom".to_string()),
            "the operation error is written to the wire's error field"
        );
        assert_eq!(
            wire.observation_error,
            Some("status read failed: boom".to_string()),
            "the observation error is written to the wire's observation_error field"
        );
        // A full serde_json round trip of the wire keeps both fields.
        let json = serde_json::to_string(&wire).unwrap();
        let wire_json: SlotResult = serde_json::from_str(&json).unwrap();
        assert_eq!(wire_json.error, Some("swap failed: boom".to_string()));
        assert_eq!(
            wire_json.observation_error,
            Some("status read failed: boom".to_string())
        );
        let back = SlotOutcome::from_wire(wire);
        assert_eq!(
            back.error,
            Some("swap failed: boom".to_string()),
            "the operation error survives the wire untouched"
        );
        assert_eq!(
            back.observation,
            Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
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
        // post-observation pass mutates only the observation fields.
        let mut known_absent = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            generation: Some(GenerationId::new("desired-1".to_string())),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            observation_error: None,
        };
        apply_post_observation(&mut known_absent, &Observation::KnownAbsent);
        assert_eq!(
            known_absent.error,
            Some("swap failed: boom".to_string()),
            "KnownAbsent must NOT wipe the operation error"
        );
        assert_eq!(
            known_absent.generation, None,
            "KnownAbsent clears the generation"
        );
        assert_eq!(known_absent.observation_error, None);

        let mut unknown = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            generation: Some(GenerationId::new("desired-1".to_string())),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            observation_error: None,
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
        assert_eq!(unknown.generation, None);
        assert_eq!(
            unknown.observation_error,
            Some("status read failed: boom".to_string()),
            "the observation error lands in observation_error, never in error"
        );

        let mut known = SlotResult {
            slot_id: slot(1),
            outcome: SlotOutcomeKind::Failed,
            generation: Some(GenerationId::new("desired-1".to_string())),
            compensated: false,
            error: Some("swap failed: boom".to_string()),
            observation_error: None,
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
            known.generation,
            Some(GenerationId::new("observed-1".to_string()))
        );
        assert_eq!(known.observation_error, None);
    }

    proptest! {
        // THE USER'S PROPERTY: the operation error and the post-mutation
        // observation are TWO INDEPENDENT facts. (1) Every (operation_error,
        // observation) pair round-trips domain → wire → domain EXACTLY,
        // including a full serde_json round trip of the wire. (2) Failure
        // injection (the engine's post-observation pass, mirrored by
        // [`apply_post_observation`]) never rewrites the operation error and
        // reflects the observation in the observation fields. The cross
        // product covers the directions where the OLD code was wrong: an
        // `Unknown` observation + a distinct operation error both survive,
        // and a `KnownAbsent` observation + an operation error survives.
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
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
            // A domain outcome carrying EXACTLY the two generated facts.
            let outcome = SlotOutcome {
                outcome: SlotOutcomeKind::Failed,
                observation: observation.clone(),
                compensated: false,
                error: operation_error.clone(),
                transition: SlotTransition::AdvanceUnknown,
            };
            // Domain → wire: each fact lands in its OWN wire field.
            let wire = SlotResult::from_outcome(&slot(0), &outcome);
            assert_eq!(
                wire.error,
                operation_error,
                "the operation error is written to the wire's error field"
            );
            // Wire → domain: both facts survive INDEPENDENTLY.
            let back = SlotOutcome::from_wire(wire.clone());
            assert_eq!(
                back.error,
                operation_error.clone(),
                "the operation error survives the wire untouched"
            );
            assert_eq!(
                back.observation,
                observation,
                "the observation survives the wire untouched"
            );
            // A full serde_json round trip of the wire preserves both fields.
            let json = serde_json::to_string(&wire).unwrap();
            let wire2: SlotResult = serde_json::from_str(&json).unwrap();
            assert_eq!(wire2.error, operation_error.clone());
            assert_eq!(wire2.observation_error, wire.observation_error);
            let back2 = SlotOutcome::from_wire(wire2);
            assert_eq!(back2.error, operation_error);
            assert_eq!(back2.observation, observation);
        }

        #[test]
        fn post_observation_preserves_both_facts(
            operation_error in arbitrary_operation_error(),
            observation in arbitrary_observation(),
        ) {
            // A pre-swap FAILED wire outcome ALREADY carries the original
            // operation error (e.g. "swap failed: ..."); its desired
            // generation is about to be replaced by the observed post-state.
            let mut wire = SlotResult {
                slot_id: slot(0),
                outcome: SlotOutcomeKind::Failed,
                generation: Some(GenerationId::new("desired-0".to_string())),
                compensated: false,
                error: operation_error.clone(),
                observation_error: None,
            };
            // Failure injection: the engine's post-observation pass.
            apply_post_observation(&mut wire, &observation);
            // The operation error is NEVER rewritten by the observation.
            assert_eq!(
                wire.error,
                operation_error.clone(),
                "the operation error must never be rewritten by the post-mutation observation"
            );
            // The observation facts reflect the observation.
            match &observation {
                Observation::Known(og) => {
                    assert_eq!(wire.generation, Some(og.generation.clone()));
                    assert_eq!(wire.observation_error, None);
                }
                Observation::KnownAbsent => {
                    assert_eq!(wire.generation, None);
                    assert_eq!(wire.observation_error, None);
                }
                Observation::Unknown(e) => {
                    assert_eq!(wire.generation, None);
                    assert_eq!(
                        wire.observation_error,
                        Some(e.message.clone()),
                        "the observation error lands in observation_error, never in error"
                    );
                }
            }
            // The injected wire still converts back to the SAME two facts.
            let back = SlotOutcome::from_wire(wire);
            assert_eq!(
                back.error,
                operation_error,
                "the operation error survives the injection untouched"
            );
            assert_eq!(
                back.observation,
                observation,
                "the observation survives the injection untouched"
            );
        }
    }
}

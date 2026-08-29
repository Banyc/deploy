//! The wire FORMAT-VERSION constants of the ledger and pins records (feature
//! area A2 "schema versions"): [`LEDGER_SCHEMA_VERSION`] versions every
//! deployment record; [`PINS_SCHEMA_VERSION`] versions the `pins.json`
//! record. Both are re-exported at the area root ([`crate::ledger`]) and
//! consumed by the store reader's wire-version gates — the format GATE is a
//! record-validation concern of [`crate::ledger::records::validation`].
/// The deployment LEDGER format version — the version every deployment
/// record carries (`LedgerIntentWire.deployment_schema_version`, validated on
/// every read in [`crate::store::local::LocalStore::read_ledger`]). Every
/// ledger writer emits exactly `LEDGER_SCHEMA_VERSION`; every ledger reader
/// refuses any other version (fail closed — a mismatched record is never
/// silently interpreted). This is INDEPENDENT of
/// [`crate::config::raw::CONFIG_SCHEMA_VERSION`]: the deployment records
/// version themselves separately from the configuration format, so bumping
/// one never invalidates the other.
///
/// The current format is version 8 (the ONLY version writers emit and
/// readers accept): the intent freezes the COMPLETE resulting snapshot
/// (`resulting_snapshot` — every target slot's generation+artifact+binding,
/// keys = full membership) plus the selected slots' pre-push states;
/// the intent wire drops `selected_membership`/`full_membership`/`desired`/
/// `bindings`; the terminal wire drops `full_membership`. The deployment
/// records still use the canonical placement-slot-keyed shape
/// (`BTreeMap<SlotId, _>` maps, nested artifact/generation refs), carry
/// the exclusive owning target + the optional rollout group, and the
/// STRICT WIRE OBSERVATIONS — the pre-push assignments' artifact and the
/// per-slot outcomes' post-mutation observation serialize as the
/// ADJACENTLY-TAGGED [`crate::ledger::records::ObservationWire`]
/// (`state` + `value`, `deny_unknown_fields`) with the STRICT payload
/// structs [`crate::ledger::records::ArtifactRefWire`] /
/// [`crate::ledger::records::ObservedGenerationWire`] (also
/// `deny_unknown_fields`) — so a persisted document rejects any field that
/// is not exactly one variant's own, never the permissive
/// internally-tagged in-memory [`crate::ledger::Observation<T>`].
///
/// THE VERSION HISTORY — what each version added. Every version BEFORE the
/// current one is REJECTED on read (no compatibility fallback), so a
/// record is interpreted only under exactly the schema that wrote it:
///
/// * version 8 (CURRENT): the INTENT record FREEZES the COMPLETE resulting
///   snapshot (`resulting_snapshot: TargetSnapshotWire` — every target slot's
///   generation+artifact+binding, keys = full membership) plus the selected
///   slots' pre-push states (`selected` table); the intent wire DROPS the
///   redundant duplicate projections (`selected_membership`,
///   `full_membership`, `desired`, `bindings`); the TERMINAL wire DROPS its
///   `full_membership` (derivable from the snapshot keys).
/// * version 7: the rollback payload is a single `entries: BTreeMap<SlotId, SnapshotEntry>` map (generation + artifact + binding per slot) serialized directly; the schema version gates old shapes.
/// * version 6: the INTENT record FREEZES each selected slot's
///   PHYSICAL BINDING — a required `bindings: BTreeMap<SlotId,
///   PhysicalBinding>` projection whose key set must EQUAL the selected
///   membership EXACTLY. The plan-time `{server, deploy_dir}` is now a
///   durable historical fact: recovery compares each slot's LIVE binding
///   against the frozen value and finalizes from the FROZEN binding on
///   equality or marks the attempt Degraded on drift (a server rebound or
///   a moved `deploy_dir` can never be recorded as the historical location
///   the attempt was planned against).
/// * version 5: the LEDGER WIRE OBSERVATION became STRICT — the intent's
///   `pre_push` artifact and the terminal's per-slot outcomes carry their
///   THREE-STATE observation as the adjacently tagged
///   [`crate::ledger::records::ObservationWire`] with strict payload
///   structs ([`crate::ledger::records::ArtifactRefWire`] /
///   [`crate::ledger::records::ObservedGenerationWire`]), so a persisted
///   document could no longer smuggle extra fields, split/mix a variant's
///   payload, or deserialize into a half-known state (the in-memory
///   [`crate::ledger::Observation<T>`] domain type is unchanged and stays
///   permissive). REJECTED on read: a version 5 record's intent is
///   WITHOUT the frozen bindings, its `pre_push` keeps the raw artifact,
///   and its outcome rows keep the flat `generation` /
///   `observation_error` fields.
/// * version 4: the INTENT record persisted BOTH FROZEN memberships —
///   `selected_membership` (== the intent's `slot_ids` table keys, the
///   AUTHORITATIVE selected set) and `full_membership` (the COMPLETE target
///   membership resolved AT PLAN TIME, when the immutable intent was
///   written). The intent became SELF-PROVING: the terminal must REPRODUCE
///   the intent's frozen values (the ledger read refuses a terminal whose
///   memberships diverge), and RECOVERY finalizes from the frozen values —
///   never from the live configuration, which may have changed arbitrarily
///   since the intent was written. REJECTED on read: a version 4 record's
///   intent is WITHOUT the frozen memberships (and predates the strict
///   observations + frozen bindings of versions 5/6).
/// * version 3: a SUCCESSFUL terminal event persisted BOTH memberships —
///   `selected_membership` (the slots the push actually deployed) and
///   `full_membership` (the complete target membership at terminal time) —
///   so the terminal record PROVED the membership equations (outcomes ==
///   selected, rollback == full, selected ⊆ full) instead of implying
///   them. REJECTED on read: a version 3 record's intent is WITHOUT the
///   frozen memberships, and its terminal's membership fields are not yet
///   REQUIRED.
/// * version 2: the per-location maps were REKEYED to PLACEMENT SLOTS with
///   the NESTED artifact triple (`release` / `variant` / `tree`) — the
///   canonical placement-slot-keyed shape. REJECTED on read: a version 2
///   record's terminal carries NO persisted memberships (required since
///   version 3, no serde default).
/// * version 1: the multi-target `targets` membership shape — the maps
///   keyed by SERVER ID with the artifact triple as FLAT fields (the
///   pre-rekeying shape). REJECTED on read: a record of that shape is NOT
///   the current schema and never loads.
///
/// Every non-current version is REJECTED on read — no compatibility
/// fallback: the intent-line version check refuses a foreign
/// `deployment_schema_version` with an error naming it, and an old-shape
/// intent/terminal line fails deserialization (the memberships and the
/// frozen bindings are REQUIRED, no serde default). A hypothetical
/// pre-rekeying shape that keyed these maps by server ID with flat
/// artifact fields is NOT the current schema and never loads.
pub(crate) const LEDGER_SCHEMA_VERSION: u32 = 8;

/// The `pins.json` record format version (`Pins.schema_version`). Pins are
/// durable, store-global retention anchors for artifact CONTENT ONLY (see
/// [`Pins`]): a pin never retains or reinserts an old deployment, attempt,
/// or snapshot in history. Readers refuse any other version (fail closed — a
/// pins file from a different schema is never silently interpreted).
pub(crate) const PINS_SCHEMA_VERSION: u32 = 1;

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
/// The current format is version 5: deployment records use the canonical
/// placement-slot-keyed shape (`BTreeMap<SlotId, _>` maps, nested
/// artifact/generation refs), carry the exclusive owning target + the
/// optional rollout group of the attempt, the PERSISTED MEMBERSHIPS
/// (since version 3 the terminal half, since version 4 the intent half),
/// and — since version 5 — the STRICT WIRE OBSERVATIONS: the pre-push
/// assignments' artifact and the per-slot outcomes' post-mutation
/// observation serialize as the ADJACENTLY-TAGGED
/// [`crate::ledger::records::ObservationWire`]
/// (`state` + `value`, `deny_unknown_fields`) with the STRICT payload
/// structs [`crate::ledger::records::ArtifactRefWire`] /
/// [`crate::ledger::records::ObservedGenerationWire`] (also
/// `deny_unknown_fields`), so a persisted document rejects any field that
/// is not exactly one variant's own — never the permissive
/// internally-tagged in-memory [`crate::ledger::Observation<T>`]:
///
/// * version 3: a SUCCESSFUL terminal event persists BOTH memberships —
///   `selected_membership` (the slots the push actually deployed) and
///   `full_membership` (the complete target membership at terminal time) —
///   so the terminal record PROVES the membership equations (outcomes ==
///   selected, rollback == full, selected ⊆ full) instead of implying them;
/// * version 4: the INTENT record persists BOTH FROZEN memberships too —
///   `selected_membership` (== the intent's `slot_ids` table keys, the
///   AUTHORITATIVE selected set) and `full_membership` (the COMPLETE target
///   membership resolved AT PLAN TIME, when the immutable intent was
///   written). The intent is now SELF-PROVING: the terminal must REPRODUCE
///   the intent's frozen values (the ledger read refuses a terminal whose
///   memberships diverge), and RECOVERY finalizes from the frozen values —
///   never from the live configuration, which may have changed arbitrarily
///   since the intent was written;
/// * version 5: the LEDGER WIRE OBSERVATION becomes STRICT — the intent's
///   `pre_push` artifact and the terminal's per-slot outcomes carry their
///   THREE-STATE observation as the adjacently tagged
///   [`crate::ledger::records::ObservationWire`]
///   with strict payload structs ([`crate::ledger::records::ArtifactRefWire`] /
///   [`crate::ledger::records::ObservedGenerationWire`]), so a persisted
///   document can no longer
///   smuggle extra fields, split/mix a variant's payload, or deserialize
///   into a half-known state (the in-memory
///   [`crate::ledger::Observation<T>`] domain type
///   is unchanged and stays permissive).
///
/// Version 4 records (the raw-artifact `pre_push`, the outcome rows with
/// flat `generation` / `observation_error` fields), version 3 records (the
/// intent shape WITHOUT the frozen memberships), version 2 records (the
/// terminal shape without persisted memberships) — and version 1 records,
/// the multi-target `targets` membership shape — are REJECTED on read —
/// no compatibility fallback: the intent-line version check refuses a
/// foreign `deployment_schema_version`, and an old-shape intent/terminal
/// line fails deserialization (the membership fields are REQUIRED, no
/// serde default). A hypothetical pre-rekeying shape that keyed these maps
/// by server ID with flat artifact fields is NOT the current schema and
/// never loads.
pub(crate) const LEDGER_SCHEMA_VERSION: u32 = 5;

/// The `pins.json` record format version (`Pins.schema_version`). Pins are
/// durable, store-global retention anchors for artifact CONTENT ONLY (see
/// [`Pins`]): a pin never retains or reinserts an old deployment, attempt,
/// or snapshot in history. Readers refuse any other version (fail closed — a
/// pins file from a different schema is never silently interpreted).
pub(crate) const PINS_SCHEMA_VERSION: u32 = 1;

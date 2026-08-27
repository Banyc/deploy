//! The wire FORMAT-VERSION constants of the ledger and pins records (feature
//! area A2 "schema versions"): [`LEDGER_SCHEMA_VERSION`] versions every
//! deployment record; [`PINS_SCHEMA_VERSION`] versions the `pins.json`
//! record. Both are re-exported at the area root ([`crate::ledger`]) and
//! consumed by the store reader's wire-version gates.

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
/// The current format is version 3: deployment records use the canonical
/// placement-slot-keyed shape (`BTreeMap<SlotId, _>` maps, nested
/// artifact/generation refs) and carry the exclusive owning target + the
/// optional rollout group of the attempt. Version 3 carries BOTH reshaping
/// changes:
///
/// * the intent's `pre_push` per-slot state carries the pre-push ASSIGNMENT
///   as a three-state observation ([`crate::ledger::Observation<ArtifactRef>`]
///   — `Known` / `KnownAbsent` / `Unknown`) instead of a raw artifact, so an
///   unreadable pre-push assignment is a DISTINCT `Unknown` value, never a
///   valid-looking artifact (version 2 = the pre-observation `pre_push`
///   shape that carried a raw artifact, including the removed
///   `unknown_artifact()` sentinel);
/// * a SUCCESSFUL terminal event persists BOTH memberships —
///   `selected_membership` (the slots the push actually deployed) and
///   `full_membership` (the complete target membership at terminal time) —
///   so the record PROVES the membership equations (outcomes == selected,
///   rollback == full, selected ⊆ full, full-push selected == full) instead
///   of implying them.
///
/// Version 2 records (the shape WITHOUT the persisted memberships and the
/// raw-artifact `pre_push` — and version 1 records, the multi-target
/// `targets` membership shape) are REJECTED on read — no compatibility
/// fallback: the intent-line version check refuses a foreign
/// `deployment_schema_version`, and an old-shape terminal line fails
/// deserialization (the new membership fields are REQUIRED, no serde
/// default). A hypothetical pre-rekeying shape that keyed these maps by
/// server ID with flat artifact fields is NOT the current schema and never
/// loads.
pub(crate) const LEDGER_SCHEMA_VERSION: u32 = 3;

/// The `pins.json` record format version (`Pins.schema_version`). Pins are
/// durable, store-global retention anchors for artifact CONTENT ONLY (see
/// [`Pins`]): a pin never retains or reinserts an old deployment, attempt,
/// or snapshot in history. Readers refuse any other version (fail closed — a
/// pins file from a different schema is never silently interpreted).
pub(crate) const PINS_SCHEMA_VERSION: u32 = 1;

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
/// The current format is version 4: deployment records use the canonical
/// placement-slot-keyed shape (`BTreeMap<SlotId, _>` maps, nested
/// artifact/generation refs), carry the exclusive owning target + the
/// optional rollout group of the attempt, and — since version 3 — carry
/// the PERSISTED MEMBERSHIPS. Version 3 carried the terminal half of the
/// memberships; version 4 carries the INTENT half:
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
///   since the intent was written.
///
/// Version 3 records (the intent shape WITHOUT the frozen memberships) and
/// version 2 records (the raw-artifact `pre_push`, the terminal shape
/// without persisted memberships) — and version 1 records, the
/// multi-target `targets` membership shape — are REJECTED on read — no
/// compatibility fallback: the intent-line version check refuses a foreign
/// `deployment_schema_version`, and an old-shape intent/terminal line
/// fails deserialization (the membership fields are REQUIRED, no serde
/// default). A hypothetical pre-rekeying shape that keyed these maps by
/// server ID with flat artifact fields is NOT the current schema and never
/// loads.
pub(crate) const LEDGER_SCHEMA_VERSION: u32 = 4;

/// The `pins.json` record format version (`Pins.schema_version`). Pins are
/// durable, store-global retention anchors for artifact CONTENT ONLY (see
/// [`Pins`]): a pin never retains or reinserts an old deployment, attempt,
/// or snapshot in history. Readers refuse any other version (fail closed — a
/// pins file from a different schema is never silently interpreted).
pub(crate) const PINS_SCHEMA_VERSION: u32 = 1;

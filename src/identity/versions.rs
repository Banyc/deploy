//! The `*_SCHEMA_VERSION` constants.
//!
//! NOTE: these are PARKED here during the encapsulation restructure. Each
//! constant belongs to the area that owns its format and will be MOVED to
//! its owning area in a later pass: `CONFIG_SCHEMA_VERSION` to the config
//! area, `LEDGER_SCHEMA_VERSION` to the ledger area, `RELEASE_PAYLOAD_`
//! /`RELEASE_RECORD_SCHEMA_VERSION` to the release area,
//! `TREE_SCHEMA_VERSION` to the tree area, and `PINS_SCHEMA_VERSION` to the
//! records/retention area. They live here for now so no constant is dropped
//! while the area modules are being carved out.

/// The configuration format version understood by this implementation
/// (`ProjectConfig.schema_version`, validated by the raw -> domain conversion in
/// [`crate::config::ProjectConfig::load`]). Every config writer emits exactly
/// `CONFIG_SCHEMA_VERSION`; the config reader refuses any other version
/// (fail closed — a `deploy.toml` from a different schema is never
/// silently interpreted). This is INDEPENDENT of [`LEDGER_SCHEMA_VERSION`]:
/// the configuration and the deployment records version themselves
/// separately, so bumping one never invalidates the other.
///
/// The current format is version 2.
pub const CONFIG_SCHEMA_VERSION: u32 = 2;

/// The deployment LEDGER format version — the version every deployment
/// record carries (`LedgerIntentWire.deployment_schema_version`, validated on
/// every read in [`crate::store::local::LocalStore::read_ledger`]). Every
/// ledger writer emits exactly `LEDGER_SCHEMA_VERSION`; every ledger reader
/// refuses any other version (fail closed — a mismatched record is never
/// silently interpreted). This is INDEPENDENT of [`CONFIG_SCHEMA_VERSION`]:
/// the deployment records version themselves separately from the
/// configuration format, so bumping one never invalidates the other.
///
/// The current format is version 3: deployment records use the canonical
/// placement-slot-keyed shape (`BTreeMap<SlotId, _>` maps, nested
/// artifact/generation refs) and carry the exclusive owning target + the
/// optional rollout group of the attempt. Version 3 carries BOTH reshaping
/// changes:
///
/// * the intent's `pre_push` per-slot state carries the pre-push ASSIGNMENT
///   as a three-state observation ([`crate::records::Observation<ArtifactRef>`]
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
pub const LEDGER_SCHEMA_VERSION: u32 = 3;

/// The canonical release identity PAYLOAD version
/// (`CanonicalReleasePayload.schema_version`), FROZEN INTO the release
/// digest: the field is part of the hashed identity payload, so its value
/// can never change without producing a new release ID. Version 3 is the
/// exclusive-ownership payload: the per-variant canonical slot declaration
/// digest (`slots_digest`) now carries each slot's ONE owning target and
/// its rollout groups (replacing the multi-target `targets` membership
/// list). Read-side enforcement is implicit and fail-closed:
/// `verify_release_identity` recomputes the digest using exactly this
/// version, so a release whose identity was derived from any other payload
/// version fails the recompute-and-verify check.
pub const RELEASE_PAYLOAD_SCHEMA_VERSION: u32 = 3;

/// The `release.json` record format version
/// (`ReleaseRecord.release_schema_version`). `build_release` emits exactly
/// this value and [`crate::release::verify_release_identity`] refuses any
/// other version (fail closed) on every write and read path. Version 2
/// records the exclusive-ownership canonical slot snapshot (each slot's one
/// `target` + `groups`); version 1 records (the multi-target `targets`
/// shape) are rejected on read — no compatibility fallback.
pub const RELEASE_RECORD_SCHEMA_VERSION: u32 = 2;

/// The `tree.json` metadata format version (`TreeMetadata.tree_schema_version`).
/// [`crate::tree::canonicalize_tree`] emits exactly this value and
/// [`crate::store::local::LocalStore::read_tree_meta`] refuses any other
/// version (fail closed).
pub const TREE_SCHEMA_VERSION: u32 = 1;

/// The `pins.json` record format version (`Pins.schema_version`). Pins are
/// durable, store-global retention anchors for artifact CONTENT ONLY (see
/// `crate::records::Pins`): a pin never retains or reinserts an old
/// deployment, attempt, or snapshot in history. Readers refuse any other
/// version (fail closed — a pins file from a different schema is never
/// silently interpreted).
pub const PINS_SCHEMA_VERSION: u32 = 1;

//! Filesystem-backed local store.
//!
//! Record contract: `targets/<target>/attempts.jsonl` holds the IMMUTABLE
//! attempt INTENT (persisted before any remote mutation; no status, no
//! outcomes); `deployments/<id>/results.json` holds the per-slot OUTCOMES
//! (written once after the mutation loop); `deployments/<id>/transitions.jsonl`
//! is the append-only STATUS lifecycle (the latest transition is the current
//! status).
//!
//! ```text
//! <base>/
//!   objects/sha256/<digest>/root/ , tree.json
//!   releases/<release-id>/mapping.toml, behavior.json, release.json
//!   targets/<target>/rotation-debt.json, attempts.jsonl,
//!     refs/last-successful, refs/snapshots.jsonl, refs/history-floor.json,
//!     refs/cleanup-pending.json
//!   slots/<slot-id>/observed.json   (the slot's ONE physical observed state)
//!   servers/<server-id>.json
//!   deployments/<deployment-id>/plan.json, results.json, transitions.jsonl
//!   pins.json (store-global artifact retention pins)
//! ```
//!
//! Observed state is stored ONCE per placement slot (`slots/<slot-id>/observed.json`),
//! never per target: targets are SELECTION VIEWS over the global slot map
//! (see [`LocalStore::read_observed`]), so a slot shared across several
//! targets has a single physical record and every target's view agrees with
//! it by construction.
//!
//! # Test-only fault injection (per-fixture registry)
//!
//! Under `#[cfg(test)]` each [`LocalStore`] owns a per-fixture
//! [`crate::testutil::test_faults::FaultRegistry`] (created empty by
//! [`LocalStore::with_base`]); the store methods consult ONLY that registry
//! (`self.fault_registry.consume(...)`). Tests arm the fixture's registry via
//! [`LocalStore::fault_registry`] (`store.fault_registry().arm_append_attempt(id)`
//! etc.). There are NO process-global fault slots and NO shared fault lock:
//! two fixtures' registries are disjoint by construction, so a fault armed by
//! one test can never fire in another's push — structural isolation that
//! holds under any parallel `cargo test` interleaving.

use crate::error::{Error, Result};
use crate::layout;
use crate::model::{
    BehaviorContract, DeploymentId, PlacementSlotId, ReleaseId, ReleaseRecord, SCHEMA_VERSION,
    TREE_SCHEMA_VERSION, TreeDigest, TreeMetadata,
};
use crate::records::{
    DeploymentAttempt, DeploymentPlan, DeploymentResults, DeploymentSnapshot, DeploymentStatus,
    DeploymentTransition, ObservedServer, ObservedTarget, Pins, ServerState,
};
use crate::store::atomic::{
    copy_dir_recursive, ensure_private_dir, path_state, read_json, set_private,
    write_atomic_replace,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::model::CLEANUP_PENDING_SCHEMA_VERSION;
#[cfg(test)]
use crate::records::{CleanupPending, HistoryFloor};
#[cfg(test)]
use crate::testutil::step17_hook::Step17Hook;
#[cfg(test)]
use crate::testutil::test_faults::{FaultKind, FaultRegistry};
#[cfg(test)]
use std::sync::Arc;

fn default_base() -> PathBuf {
    let data = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    data.join("simple-deploy")
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::store(format!("serialize {}: {e}", path.display())))?;
    let mut f = std::fs::File::create(path)
        .map_err(|e| Error::store(format!("create {}: {e}", path.display())))?;
    f.write_all(&bytes)
        .map_err(|e| Error::store(format!("write {}: {e}", path.display())))?;
    drop(f);
    set_private(path)
}

/// Install immutable content-addressed file bytes (release records, mapping,
/// and behavior snapshots) with create-or-compare semantics.
///
/// * If the file does not exist yet, the bytes are written to a temporary file
///   in the same directory and atomically renamed into place, so a reader never
///   observes a partially written snapshot.
/// * If the file already exists, its contents must be byte-identical: an
///   identical rewrite is an idempotent success, and any attempt to replace the
///   existing snapshot with different content fails. Snapshots are bound to
///   release identity by digest; they are never mutable in place.
///
/// Callers serialize writes per store with the application-store lock; the
/// temporary name additionally carries the process id to stay collision-free.
fn write_atomic_cas(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    if path.exists() {
        let existing = std::fs::read(path)
            .map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(Error::store(format!(
            "refusing to replace existing {} with different content",
            path.display()
        )));
    }
    // Durability protocol for immutable records: write + fsync a UNIQUE temp
    // file, install atomically WITHOUT replacement (link(2) fails on EEXIST,
    // so a racing loser can never clobber a winner and no reader ever sees a
    // torn record), unlink the temp name, then fsync the parent directory.
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", tmp.display())))?;
    }
    let installed = match std::fs::hard_link(&tmp, path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::store(format!("install {}: {e}", path.display())));
        }
    };
    let _ = std::fs::remove_file(&tmp);
    if !installed {
        // Lost the race: the winner's content must match ours or refuse.
        let existing = std::fs::read(path)
            .map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
        if existing != bytes {
            return Err(Error::store(format!(
                "refusing to replace existing {} with different content",
                path.display()
            )));
        }
        return Ok(());
    }
    set_private(path)?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub struct LocalStore {
    base: PathBuf,
    /// Per-fixture one-shot fault registry (test-only). Created EMPTY by
    /// [`LocalStore::with_base`]; tests that want an injected store fault arm
    /// it via [`LocalStore::fault_registry`]. There are no process-global
    /// fault slots and no shared fault lock: the store's methods consult ONLY
    /// this fixture's registry, so two fixtures can never interfere regardless
    /// of threading. See `src/testutil.rs` for the design.
    #[cfg(test)]
    fault_registry: Arc<FaultRegistry>,
    /// Per-fixture one-shot step-17 phase hook (test-only). Created EMPTY by
    /// [`LocalStore::with_base`]; a test arms it via [`LocalStore::step17_hook`]
    /// right before the push under test. Like the fault registry it lives on
    /// THIS store (never a process-global slot), so a hook armed by one
    /// fixture can never fire in another's push. The engine consults it via
    /// [`LocalStore::step17_hook_barrier`] immediately before each
    /// step-17-equivalent lock acquisition. See `src/testutil.rs`.
    #[cfg(test)]
    step17_hook: Arc<Step17Hook>,
}

impl LocalStore {
    /// Create a store rooted at `<data>/simple-deploy/<application>` with private
    /// permissions, creating the directory tree if needed.
    pub fn new(application: &str) -> Result<LocalStore> {
        let base = default_base().join(application);
        Self::with_base(base)
    }

    /// Create a store rooted at an explicit base (used in tests).
    pub fn with_base(base: PathBuf) -> Result<LocalStore> {
        ensure_private_dir(&base)?;
        ensure_private_dir(&base.join(layout::objects()))?;
        ensure_private_dir(&base.join(layout::RELEASES))?;
        ensure_private_dir(&base.join("targets"))?;
        ensure_private_dir(&base.join("slots"))?;
        ensure_private_dir(&base.join("servers"))?;
        ensure_private_dir(&base.join("deployments"))?;
        ensure_private_dir(&base.join("staging"))?;
        Ok(LocalStore {
            base,
            #[cfg(test)]
            fault_registry: Arc::new(FaultRegistry::default()),
            #[cfg(test)]
            step17_hook: Arc::new(Step17Hook::default()),
        })
    }

    /// The fixture's per-fixture one-shot fault registry. A test arms faults
    /// here (`store.fault_registry().arm_append_attempt(id)` etc.) and the
    /// store methods consume them from the SAME registry — never from any
    /// other fixture's, and never from a process-global slot.
    #[cfg(test)]
    pub(crate) fn fault_registry(&self) -> &Arc<FaultRegistry> {
        &self.fault_registry
    }

    /// The fixture's per-fixture step-17 phase hook slot. A test arms it via
    /// [`Step17Hook::arm`] right before the push under test, so the engine
    /// parks at its step-17 lock acquisition until the test holds the
    /// competing guard and releases the engine — deterministic lock
    /// contention, per fixture (never a process-global slot).
    #[cfg(test)]
    pub(crate) fn step17_hook(&self) -> &Arc<Step17Hook> {
        &self.step17_hook
    }

    /// ENGINE-side step-17 phase barrier, called immediately BEFORE a
    /// step-17-equivalent lock acquisition (the per-slot rotation block and
    /// the deferred-maintenance retry that shares it), tagged with the
    /// [`HookPhase`] being entered so the test can tell the fresh step-17
    /// rotation from the deferred-maintenance retry. A no-op in unarmed
    /// stores and non-matching deployment ids; the call sites in
    /// `src/push/engine.rs` are `#[cfg(test)]`, so production builds never
    /// reach this method.
    #[cfg(test)]
    pub(crate) fn step17_hook_barrier(
        &self,
        deployment_id: &DeploymentId,
        phase: crate::testutil::step17_hook::HookPhase,
    ) {
        self.step17_hook.barrier(deployment_id, phase);
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.base.join("staging")
    }

    // ---- objects ----------------------------------------------------------

    pub fn object_root(&self, digest: &TreeDigest) -> PathBuf {
        self.base
            .join(layout::objects())
            .join(digest.as_str())
            .join("root")
    }

    pub fn object_tree_json(&self, digest: &TreeDigest) -> PathBuf {
        self.base
            .join(layout::objects())
            .join(digest.as_str())
            .join("tree.json")
    }

    pub fn object_exists(&self, digest: &TreeDigest) -> bool {
        self.object_root(digest).exists()
    }

    /// Store (or reuse) a tree object. Verifies the digest after copy. Reusing an
    /// existing object requires its contents to verify.
    pub fn store_object(&self, digest: &TreeDigest, src_root: &Path) -> Result<()> {
        let root = self.object_root(digest);
        if root.exists() {
            // Verify existing object integrity before reuse.
            let existing = std::fs::read_dir(&root)
                .map_err(|e| Error::integrity(format!("read object {}: {e}", digest.as_str())))?;
            if existing.count() > 0 {
                let meta = crate::tree::canonicalize_tree(&root)?;
                if meta.tree_sha256 != digest.as_str() {
                    return Err(Error::integrity(format!(
                        "existing object {} failed verification",
                        digest.as_str()
                    )));
                }
                return Ok(()); // reuse
            }
        }
        copy_dir_recursive(src_root, &root)?;
        let meta = crate::tree::canonicalize_tree(&root)?;
        if meta.tree_sha256 != digest.as_str() {
            let _ = std::fs::remove_dir_all(&root);
            return Err(Error::integrity(format!(
                "stored object digest mismatch for {}",
                digest.as_str()
            )));
        }
        write_atomic_cas(
            &self.object_tree_json(digest),
            &serde_json::to_vec(&meta)
                .map_err(|e| Error::store(format!("serialize tree.json: {e}")))?,
        )?;
        Ok(())
    }

    pub fn read_tree_meta(&self, digest: &TreeDigest) -> Result<TreeMetadata> {
        let meta: TreeMetadata = read_json(&self.object_tree_json(digest))?;
        // Fail closed on the tree metadata format version: only
        // `TREE_SCHEMA_VERSION` is accepted, any other version is refused
        // (a tree.json written by a different schema is never interpreted).
        if meta.tree_schema_version != TREE_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "tree {} carries unsupported tree_schema_version {} (expected {TREE_SCHEMA_VERSION}): only TREE_SCHEMA_VERSION is accepted",
                digest.as_str(),
                meta.tree_schema_version
            )));
        }
        Ok(meta)
    }

    // ---- releases ---------------------------------------------------------

    pub fn release_dir(&self, id: &ReleaseId) -> PathBuf {
        self.base.join(layout::RELEASES).join(sanitize(id.as_str()))
    }

    pub fn release_exists(&self, id: &ReleaseId) -> bool {
        self.release_dir(id).join("release.json").exists()
    }

    /// Write an immutable release record. Replacing an existing ID with
    /// different content fails.
    ///
    /// The INCOMING record is verified from its OWN content BEFORE anything
    /// is written: an unverifiable record (digest fields inconsistent with
    /// the slot snapshot/bindings/provenance, or an empty slot snapshot) is
    /// never persisted — fail closed before the release directory or file is
    /// created. When the directory already exists, the EXISTING record is
    /// verified from its content as well, and the comparison is between the
    /// two content-verified identities (each record's `release_sha256` after
    /// recompute-and-verify): a same-id record with different content still
    /// fails, but never by trusting the stored digest fields.
    pub fn write_release(&self, rec: &ReleaseRecord) -> Result<()> {
        // (a) Verify the incoming record from its content before any write.
        crate::release::verify_release_identity(rec)?;
        let dir = self.release_dir(&ReleaseId::new(rec.release_id.clone()));
        if dir.exists() {
            // (b) Verify the EXISTING record from its content too, then
            // compare the recomputed identities (both records verified above,
            // so `release_sha256` equals the recomputed digest in each).
            let existing: ReleaseRecord = read_json(&dir.join("release.json"))?;
            crate::release::verify_release_identity(&existing)?;
            if existing.release_sha256 != rec.release_sha256 {
                return Err(Error::store(format!(
                    "release {} already exists with different content",
                    rec.release_id
                )));
            }
            return Ok(()); // idempotent
        }
        ensure_private_dir(&dir)?;
        let bytes = serde_json::to_vec_pretty(rec)
            .map_err(|e| Error::store(format!("serialize release: {e}")))?;
        write_atomic_cas(&dir.join("release.json"), &bytes)
    }

    /// Read and verify a release record by its canonical id.
    ///
    /// The record's identity is recomputed from its OWN content (slot
    /// snapshot, bindings, provenance digests), never trusted from the stored
    /// `release_sha256`/`release_id` fields — a tampered record whose content
    /// was edited while the digest fields were left unchanged fails closed
    /// with an integrity error. An empty slot snapshot is rejected outright
    /// (a current-format record must persist its slot declarations).
    ///
    /// Additionally, the STORED record's `release_id` must equal the `id` the
    /// caller asked for (the directory path): a record swapped into the wrong
    /// release directory — its `release_id` edited to a consistent-but-
    /// different id, or the file relocated — is refused with an integrity
    /// error naming both ids instead of being returned as if it were `id`.
    pub fn read_release(&self, id: &ReleaseId) -> Result<ReleaseRecord> {
        let rec: ReleaseRecord = read_json(&self.release_dir(id).join("release.json"))?;
        // Recompute-and-verify: the release's canonical digest is derived from
        // its own content (slot snapshot, bindings, provenance digests), never
        // trusted from the stored `release_sha256`/`release_id` fields. A
        // tampered record whose content was edited while the digest fields
        // were left unchanged fails closed with an integrity error, and an
        // empty slot snapshot is rejected outright.
        crate::release::verify_release_identity(&rec)?;
        // Bind the record to the read path: the stored record must actually
        // BE the release the caller asked for.
        if rec.release_id != id.as_str() {
            return Err(Error::integrity(format!(
                "release record read from {id} declares release_id {}: the stored record's identity does not match the requested release id (a record swapped into the wrong release directory)",
                rec.release_id
            )));
        }
        Ok(rec)
    }

    pub fn write_release_aux(
        &self,
        id: &ReleaseId,
        mapping_toml: &str,
        behavior_json: &serde_json::Value,
    ) -> Result<()> {
        let dir = self.release_dir(id);
        ensure_private_dir(&dir)?;
        write_atomic_cas(&dir.join("mapping.toml"), mapping_toml.as_bytes())?;
        let bytes = serde_json::to_vec_pretty(behavior_json)
            .map_err(|e| Error::store(format!("serialize behavior: {e}")))?;
        write_atomic_cas(&dir.join("behavior.json"), &bytes)?;
        Ok(())
    }

    /// Read the name-keyed per-variant behavior contracts stored alongside a
    /// release record.
    ///
    /// The release record is read and identity-verified FIRST (its canonical
    /// digest is recomputed from its own content); its provenance
    /// `behavior_sha256` — itself part of the release identity — is then the
    /// digest the `behavior.json` snapshot must match. The snapshot is parsed
    /// and re-digested and compared against that provenance digest: a
    /// tampered `behavior.json` whose canonical contract set digests to
    /// anything else fails closed with an integrity error naming the release
    /// and the expected vs recomputed digest, and an unparseable snapshot
    /// fails closed too. Only a payload that yields the SAME canonical
    /// contract set (e.g. JSON key reordering) passes — the historical
    /// contract is never returned unverified.
    pub fn read_release_behaviors(
        &self,
        id: &ReleaseId,
    ) -> Result<BTreeMap<String, BehaviorContract>> {
        // Verify the release record first: its provenance `behavior_sha256` is
        // the canonical digest the behavior snapshot must match, and the
        // record's own identity is recomputed-and-verified before its
        // provenance is trusted.
        let rec = self.read_release(id)?;
        let p = self.release_dir(id).join("behavior.json");
        let bytes = std::fs::read(&p)
            .map_err(|e| Error::store(format!("read behavior {}: {e}", p.display())))?;
        crate::release::verify_behavior_json(
            &bytes,
            &rec.release_id,
            &rec.provenance.behavior_sha256,
        )
    }

    // ---- targets ----------------------------------------------------------

    pub fn target_dir(&self, target: &str) -> PathBuf {
        self.base.join("targets").join(sanitize(target))
    }

    // ---- slots: the ONE physical observed state ---------------------------

    /// Path of a placement slot's single physical observed record
    /// (`slots/<slot-id>/observed.json`). Observed state is stored EXACTLY
    /// ONCE per placement slot — never replicated per target: targets are
    /// selection views over the global slot map (see
    /// [`LocalStore::read_observed`]).
    pub fn slot_observed_path(&self, slot: &PlacementSlotId) -> PathBuf {
        self.base
            .join("slots")
            .join(sanitize(slot.as_str()))
            .join("observed.json")
    }

    /// Write ONE placement slot's physical observed state. The engine's
    /// post-commit observed-refresh writes each advanced slot EXACTLY ONCE
    /// (never once per member target), so a slot shared across several
    /// targets has a single record and every target's view of it agrees with
    /// the physical record by construction.
    ///
    /// Post-commit observed-refresh fault injection: the observed refresh
    /// runs AFTER the deployment is durably committed, so a fault here is
    /// reported as a maintenance warning by the engine, never a push error.
    /// The fault is keyed by (deployment id, SLOT id) — one write selects
    /// exactly one slot's physical record.
    pub fn write_slot_observed(
        &self,
        slot: &PlacementSlotId,
        observed: &ObservedServer,
    ) -> Result<()> {
        #[cfg(test)]
        if let Some(d) = observed.last_deployment.as_ref()
            && self.fault_registry.consume_target(
                FaultKind::WriteObserved,
                d.as_str(),
                slot.as_str(),
            )
        {
            return Err(Error::store(
                "test fault: write_slot_observed forced to fail once",
            ));
        }
        let p = self.slot_observed_path(slot);
        let dir = p
            .parent()
            .expect("a slot observed record always sits inside a slot directory");
        ensure_private_dir(dir)?;
        write_json(&p, observed)
    }

    /// Read one placement slot's physical observed record. `None` when the
    /// slot has never been observed (or its record was removed). Tri-state:
    /// only a genuine NotFound is "no observed record"; a stat failure
    /// propagates as a Store error (a permission error on the record must
    /// not read as "never observed").
    pub fn read_slot_observed(&self, slot: &PlacementSlotId) -> Result<Option<ObservedServer>> {
        let p = self.slot_observed_path(slot);
        if path_state(&p)? {
            read_json(&p).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The GLOBAL physical slot map: every placement slot's single observed
    /// record (`slots/<slot-id>/observed.json`), keyed by [`PlacementSlotId`].
    /// This is the ONE physical state the per-target views are filtered
    /// from — a shared slot exists here exactly once.
    pub fn read_global_observed(&self) -> Result<BTreeMap<PlacementSlotId, ObservedServer>> {
        let root = self.base.join("slots");
        let mut out = BTreeMap::new();
        let entries = match std::fs::read_dir(&root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::store(format!("read slots {}: {e}", root.display()))),
        };
        for entry in entries {
            let entry = entry.map_err(|e| Error::store(format!("read slots: {e}")))?;
            let rec = entry.path().join("observed.json");
            if !path_state(&rec)? {
                continue;
            }
            let observed: ObservedServer = read_json(&rec)?;
            out.insert(
                PlacementSlotId::new(entry.file_name().to_string_lossy().into_owned()),
                observed,
            );
        }
        Ok(out)
    }

    /// The TARGET VIEW over the single physical slot state: the global slot
    /// map ([`LocalStore::read_global_observed`]) filtered to the target's
    /// member slots. Membership is DERIVED from the config's slot-declaration
    /// `targets` lists (as everywhere in the codebase): `deploy status
    /// <target>` and every other consumer see exactly the physical records of
    /// the target's member slots — never a replicated per-target copy, so
    /// every member target's view of a shared slot agrees with the ONE
    /// physical record (generation, artifact, last_deployment). A member
    /// slot with no physical record yet is simply absent from the view.
    pub fn read_observed(
        &self,
        target: &str,
        config: &crate::config::Config,
    ) -> Result<ObservedTarget> {
        let members: std::collections::HashSet<&str> = config
            .slot_defs()
            .iter()
            .filter(|s| s.targets.iter().any(|t| t == target))
            .map(|s| s.id.as_str())
            .collect();
        let slots = self
            .read_global_observed()?
            .into_iter()
            .filter(|(id, _)| members.contains(id.as_str()))
            .collect();
        Ok(ObservedTarget {
            target: crate::model::TargetName::new(target.to_string()),
            slots,
        })
    }

    // ---- rotation maintenance debt ---------------------------------------

    /// Path of the target's deferred-rotation debt marker file.
    ///
    /// Rotation is POST-COMMIT maintenance: a rotation failure after the
    /// deployment already committed must not change the reported outcome.
    /// Instead the failure is recorded here — keyed by target (the file's
    /// location under `targets/<target>/`) and by placement slot (the map
    /// key) — so later pushes retry the maintenance and clear the marker
    /// once the rotation succeeds. The marker is intentionally a separate,
    /// small record: it does not ride along in `observed.json` (which
    /// describes the deployed state, not pending controller work) and it
    /// survives across pushes.
    pub fn rotation_debt_path(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("rotation-debt.json")
    }

    /// Read the target's deferred-rotation markers: a map of placement slot
    /// id to the reason the rotation was deferred. Empty when no maintenance
    /// is pending.
    pub fn read_rotation_debt(&self, target: &str) -> Result<BTreeMap<String, String>> {
        // Post-commit maintenance fault injection, keyed by target (the debt
        // file lives under `targets/<target>/`). Absorbs the debt-I/O
        // sibling agent's `arm_read_rotation_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::ReadRotationDebt, target)
        {
            return Err(Error::store(
                "test fault: read_rotation_debt forced to fail once",
            ));
        }
        let p = self.rotation_debt_path(target);
        // Tri-state: only a genuine NotFound is "no maintenance debt" (the
        // empty map); a stat failure propagates as a Store error (an
        // unreadable debt marker must not read as "no debt").
        if path_state(&p)? {
            read_json(&p)
        } else {
            Ok(BTreeMap::new())
        }
    }

    /// Persist the target's deferred-rotation markers. An EMPTY map removes
    /// the marker file, so a fully-serviced target leaves no trace.
    pub fn write_rotation_debt(&self, target: &str, debt: &BTreeMap<String, String>) -> Result<()> {
        // Post-commit maintenance write fault, keyed by target. Absorbs the
        // debt-I/O sibling agent's `arm_write_rotation_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::WriteRotationDebt, target)
        {
            return Err(Error::store(
                "test fault: write_rotation_debt forced to fail once",
            ));
        }
        let p = self.rotation_debt_path(target);
        if debt.is_empty() {
            // Tri-state removal decision: a genuine NotFound is nothing to
            // remove; any other stat error propagates (an unreadable marker
            // must not silently survive as a stale "debt" record).
            if path_state(&p)? {
                std::fs::remove_file(&p).map_err(|e| {
                    Error::store(format!("remove rotation debt {}: {e}", p.display()))
                })?;
            }
            return Ok(());
        }
        write_json(&p, debt)
    }

    pub fn append_attempt(&self, target: &str, attempt: &DeploymentAttempt) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendAttempt, attempt.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_attempt forced to fail once",
            ));
        }
        let dir = self.target_dir(target);
        ensure_private_dir(&dir)?;
        let p = dir.join("attempts.jsonl");
        let mut f = if p.exists() {
            std::fs::OpenOptions::new().append(true).open(&p)
        } else {
            std::fs::File::create(&p)
        }
        .map_err(|e| Error::store(format!("open attempts: {e}")))?;
        let line = serde_json::to_string(attempt)
            .map_err(|e| Error::store(format!("serialize attempt: {e}")))?;
        writeln!(f, "{line}").map_err(|e| Error::store(format!("write attempt: {e}")))?;
        drop(f);
        set_private(&p)
    }

    /// Read the FULL attempt history UNFILTERED by any history floor. This is
    /// the physical view of `attempts.jsonl` (never a below-floor escape
    /// hatch for consumers: every public read goes through
    /// [`LocalStore::read_attempts`]); the checkpoint compaction and the
    /// discard preview use it to compute the exact suffix at/after a floor,
    /// and index allocation must see the full log so compaction can never
    /// reuse an index. Crate-private: non-crate consumers must use the
    /// floor-gated [`LocalStore::read_attempts`].
    pub(crate) fn read_attempts_raw(&self, target: &str) -> Result<Vec<DeploymentAttempt>> {
        let p = self.target_dir(target).join("attempts.jsonl");
        // Tri-state: only a genuine NotFound is "no attempts log" (the
        // empty list); a stat failure propagates as a Store error (an
        // unreadable log must not read as "no history" — the floor binding
        // would then fail open below the floor).
        if !path_state(&p)? {
            return Ok(vec![]);
        }
        let text =
            std::fs::read_to_string(&p).map_err(|e| Error::store(format!("read attempts: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let attempt: DeploymentAttempt = serde_json::from_str(line)
                .map_err(|e| Error::store(format!("parse attempt: {e}")))?;
            // Fail closed on the record schema version: only `SCHEMA_VERSION`
            // is accepted, any other version is refused with an error naming
            // the version (a record from a different schema is never
            // silently interpreted).
            if attempt.deployment_schema_version != SCHEMA_VERSION {
                return Err(Error::store(format!(
                    "attempt {} carries unsupported deployment_schema_version {} (expected {SCHEMA_VERSION}): only SCHEMA_VERSION is accepted",
                    attempt.deployment_id, attempt.deployment_schema_version
                )));
            }
            out.push(attempt);
        }
        Ok(out)
    }

    /// Read the attempts log as the FLOOR-GATED history: only the suffix
    /// beginning at the checkpoint's own attempt (everything before it —
    /// failed attempts included — was discarded when the checkpoint was
    /// established). No floor marker: the full log. The checkpoint's own
    /// deployment is always retained, so its attempt is the first line the
    /// readers expose; attempts AFTER it (including later failed attempts)
    /// remain visible. The floor marker is integrity-bound
    /// ([`LocalStore::read_history_floor`]): a corrupted/tampered marker
    /// makes this read FAIL CLOSED with an integrity error — it is never
    /// silently treated as "no floor" (which would expose the below-floor
    /// prefix).
    pub fn read_attempts(&self, target: &str) -> Result<Vec<DeploymentAttempt>> {
        let mut out = self.read_attempts_raw(target)?;
        if let Some(floor) = self.read_history_floor(target)?
            && let Some(pos) = out
                .iter()
                .position(|a| a.deployment_id == floor.deployment_id)
        {
            out.drain(..pos);
        }
        Ok(out)
    }

    // ---- rollback snapshots (refs) --------------------------------------

    pub(crate) fn refs_dir(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("refs")
    }

    pub fn write_last_successful(&self, target: &str, deployment_id: &str) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::WriteLastSuccessful, deployment_id)
        {
            return Err(Error::store(
                "test fault: write_last_successful forced to fail once",
            ));
        }
        let dir = self.refs_dir(target);
        ensure_private_dir(&dir)?;
        let p = dir.join("last-successful");
        std::fs::write(&p, deployment_id)
            .map_err(|e| Error::store(format!("write last-successful: {e}")))?;
        set_private(&p)
    }

    pub fn read_last_successful(&self, target: &str) -> Option<String> {
        let p = self.refs_dir(target).join("last-successful");
        std::fs::read_to_string(p)
            .ok()
            .filter(|s| !s.trim().is_empty())
    }

    /// Append a terminal successful snapshot (`refs/snapshots.jsonl`),
    /// one JSON line per entry. Snapshots are the immutable rollback source
    /// (referenced as a snapshot index `sN`, e.g. `deploy push <target> sN`);
    /// only successful deployments produce them.
    pub fn append_snapshot(&self, target: &str, entry: &DeploymentSnapshot) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendSnapshot, entry.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_snapshot forced to fail once",
            ));
        }
        let dir = self.refs_dir(target);
        ensure_private_dir(&dir)?;
        let p = dir.join("snapshots.jsonl");
        let mut f = if p.exists() {
            std::fs::OpenOptions::new().append(true).open(&p)
        } else {
            std::fs::File::create(&p)
        }
        .map_err(|e| Error::store(format!("open snapshots: {e}")))?;
        let line = serde_json::to_string(entry)
            .map_err(|e| Error::store(format!("serialize snapshot: {e}")))?;
        writeln!(f, "{line}").map_err(|e| Error::store(format!("write snapshot: {e}")))?;
        drop(f);
        set_private(&p)
    }

    /// Read the FULL snapshot log UNFILTERED by any checkpoint floor. This
    /// is the physical view of `refs/snapshots.jsonl` (never a below-floor
    /// escape hatch for consumers: [`LocalStore::read_snapshots`] is the
    /// gated read). Index allocation and the compaction suffix use it, so
    /// compacted logs never reuse an index. Crate-private: non-crate
    /// consumers must use the floor-gated [`LocalStore::read_snapshots`].
    pub(crate) fn read_snapshots_raw(&self, target: &str) -> Result<Vec<DeploymentSnapshot>> {
        let p = self.refs_dir(target).join("snapshots.jsonl");
        // Tri-state: only a genuine NotFound is "no snapshots log" (the
        // empty vector); a stat failure propagates as a Store error (an
        // unreadable log must not read as "no history" — a floor binding
        // check would then fail open).
        if !path_state(&p)? {
            return Ok(vec![]);
        }
        let text = std::fs::read_to_string(&p)
            .map_err(|e| Error::store(format!("read snapshots: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str::<DeploymentSnapshot>(line)
                    .map_err(|e| Error::store(format!("parse snapshot: {e}")))?,
            );
        }
        Ok(out)
    }

    /// Read the snapshot log as the FLOORED history: only the suffix
    /// beginning at the checkpoint deployment's POSITION in the log (the
    /// deployment-keyed analog of the old `index >= floor.snapshot_index`
    /// filter — positions are DERIVED from the log order, never stored). The
    /// checkpoint deployment itself stays resolvable; everything before it
    /// was discarded. The floor marker gates this read even when the
    /// physical log has not been compacted yet (an interrupted compaction),
    /// so history below the durable floor is never exposed. The marker is
    /// verified ([`LocalStore::read_history_floor`]): a corrupted/tampered
    /// marker makes this read fail closed with an integrity error — never a
    /// silent downgrade to "no floor" (which would expose the below-floor
    /// prefix).
    pub fn read_snapshots(&self, target: &str) -> Result<Vec<DeploymentSnapshot>> {
        let mut out = self.read_snapshots_raw(target)?;
        if let Some(floor) = self.read_history_floor(target)?
            && let Some(pos) = out
                .iter()
                .position(|s| s.deployment_id == floor.deployment_id)
        {
            out.drain(..pos);
        }
        Ok(out)
    }

    // ---- servers ----------------------------------------------------------

    pub fn write_server(&self, state: &ServerState) -> Result<()> {
        // Post-commit observed-refresh fault injection, keyed by the recorded
        // deployment id AND target (see `write_slot_observed`).
        #[cfg(test)]
        if let (Some(deployment_id), Some(target)) = (
            state
                .last_observed
                .as_ref()
                .and_then(|o| o.last_deployment.as_ref()),
            state.last_seen_target.as_ref(),
        ) && self.fault_registry.consume_target(
            FaultKind::WriteServer,
            deployment_id.as_str(),
            target.as_str(),
        ) {
            return Err(Error::store("test fault: write_server forced to fail once"));
        }
        let p = self
            .base
            .join("servers")
            .join(format!("{}.json", sanitize(state.id.as_str())));
        write_json(&p, state)
    }

    pub fn read_server(&self, id: &str) -> Result<ServerState> {
        let p = self
            .base
            .join("servers")
            .join(format!("{id}.json", id = sanitize(id)));
        read_json(&p)
    }

    pub fn server_exists(&self, id: &str) -> bool {
        self.base
            .join("servers")
            .join(format!("{}.json", sanitize(id)))
            .exists()
    }

    // ---- deployments ------------------------------------------------------

    pub fn deployment_dir(&self, id: &str) -> PathBuf {
        self.base.join("deployments").join(sanitize(id))
    }

    pub fn write_plan<T: Serialize>(&self, id: &str, plan: &T) -> Result<()> {
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        // The recorded plan of an attempt is immutable: deployment IDs are
        // unique, so a conflicting same-ID rewrite is corruption and must fail
        // rather than silently rewrite history.
        let bytes = serde_json::to_vec_pretty(plan)
            .map_err(|e| Error::store(format!("serialize plan: {e}")))?;
        write_atomic_cas(&dir.join("plan.json"), &bytes)
    }

    pub fn write_results(&self, id: &str, results: &DeploymentResults) -> Result<()> {
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::WriteResults, id) {
            return Err(Error::store(
                "test fault: write_results forced to fail once",
            ));
        }
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        // Same immutability rule as the plan: recorded once per deployment ID.
        let bytes = serde_json::to_vec_pretty(results)
            .map_err(|e| Error::store(format!("serialize results: {e}")))?;
        write_atomic_cas(&dir.join("results.json"), &bytes)
    }

    pub fn read_results(&self, id: &str) -> Result<DeploymentResults> {
        let p = self.deployment_dir(id).join("results.json");
        read_json(&p)
    }

    /// Append one status event to the deployment's append-only transition
    /// stream (`deployments/<id>/transitions.jsonl`). The current status of a
    /// deployment is the LATEST transition; this replaces the old single
    /// mutable `deployments/<id>/status` file. `reason` carries optional
    /// human context (e.g. "recovery finalization", "metadata phase
    /// interrupted").
    pub fn append_transition(
        &self,
        id: &str,
        status: &DeploymentStatus,
        reason: Option<&str>,
    ) -> Result<()> {
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::AppendTransition, id) {
            return Err(Error::store(
                "test fault: append_transition forced to fail once",
            ));
        }
        #[cfg(test)]
        if status == &DeploymentStatus::Successful
            && self
                .fault_registry
                .consume(FaultKind::AppendTransitionSuccessful, id)
        {
            return Err(Error::store(
                "test fault: append_transition(Successful) forced to fail once",
            ));
        }
        #[cfg(test)]
        if status == &DeploymentStatus::PendingCommit
            && self
                .fault_registry
                .consume(FaultKind::AppendTransitionPending, id)
        {
            return Err(Error::store(
                "test fault: append_transition(PendingCommit) forced to fail once",
            ));
        }
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        let p = dir.join("transitions.jsonl");
        let transition = DeploymentTransition {
            deployment_id: DeploymentId::new(id.to_string()),
            status: status.clone(),
            recorded_at: crate::remote::helper::now_rfc3339(),
            reason: reason.map(str::to_string),
        };
        let mut f = if p.exists() {
            std::fs::OpenOptions::new().append(true).open(&p)
        } else {
            std::fs::File::create(&p)
        }
        .map_err(|e| Error::store(format!("open transitions: {e}")))?;
        let line = serde_json::to_string(&transition)
            .map_err(|e| Error::store(format!("serialize transition: {e}")))?;
        writeln!(f, "{line}").map_err(|e| Error::store(format!("write transition: {e}")))?;
        drop(f);
        set_private(&p)
    }

    /// Read the full append-only transition stream for a deployment.
    pub fn read_transitions(&self, id: &str) -> Result<Vec<DeploymentTransition>> {
        let p = self.deployment_dir(id).join("transitions.jsonl");
        // Tri-state: only a genuine NotFound is "no transition stream" (the
        // empty vector); a stat failure propagates as a Store error (an
        // unreadable log must not read as "no history").
        if !path_state(&p)? {
            return Ok(vec![]);
        }
        let text = std::fs::read_to_string(&p)
            .map_err(|e| Error::store(format!("read transitions: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str::<DeploymentTransition>(line)
                    .map_err(|e| Error::store(format!("parse transition: {e}")))?,
            );
        }
        Ok(out)
    }

    /// The latest transition of a deployment, or `None` when no transition
    /// has been recorded yet.
    pub fn latest_transition(&self, id: &str) -> Result<Option<DeploymentTransition>> {
        Ok(self.read_transitions(id)?.pop())
    }

    /// The current status of a deployment: the status of its LATEST
    /// transition, or `None` when no transition has been recorded yet.
    pub fn latest_status(&self, id: &str) -> Result<Option<DeploymentStatus>> {
        Ok(self.latest_transition(id)?.map(|t| t.status))
    }

    /// Read a deployment's recorded plan (`deployments/<id>/plan.json`),
    /// the immutable intent record written BEFORE any server mutation. The
    /// plan is the artifact-reference source the garbage collector reads for
    /// every RETAINED deployment record (its per-slot [`ArtifactRef`]s,
    /// `desired_release`, and plan source): a retained record's plan is
    /// authoritative for what its deployment may still need locally.
    pub(crate) fn read_plan(&self, id: &str) -> Result<DeploymentPlan> {
        read_json(&self.deployment_dir(id).join("plan.json"))
    }

    // ---- pins ------------------------------------------------------------

    /// Path of the store-global pins record (`pins.json`, at the store
    /// root). Pins are GLOBAL, not per-target: a release or binding is
    /// shared by every target that references it, and the artifact garbage
    /// collector is global too, so a pin protects content everywhere.
    pub fn pins_path(&self) -> PathBuf {
        self.base.join("pins.json")
    }

    /// Write the store's pins durably (atomic temp + rename + parent-dir
    /// fsync via [`write_atomic_replace`](crate::store::atomic::write_atomic_replace):
    /// replacing the pin set is a mutable user operation, so the file is
    /// replaced atomically, never CAS'd). A no-op in the sense that the
    /// file may be absent entirely — [`LocalStore::read_pins`] treats a
    /// missing file as the empty pin set.
    pub fn write_pins(&self, pins: &Pins) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(pins)
            .map_err(|e| Error::store(format!("serialize pins: {e}")))?;
        write_atomic_replace(&self.pins_path(), &bytes)
    }

    /// Read the store's pins record, or the DEFAULT (empty) pin set when no
    /// pins file exists. FAILS CLOSED on every integrity violation,
    /// mirroring the other marker readers:
    ///
    /// * `schema_version` must be exactly [`PINS_SCHEMA_VERSION`]; any other
    ///   version fails with an error naming the version (a pins file written
    ///   by a different schema is never silently interpreted).
    /// * a present but MALFORMED pins file is a parse failure (semantic
    ///   corruption) — [`Error::store`] is reserved for mechanical
    ///   filesystem I/O.
    ///
    /// The garbage collector treats a failed read as a failed scan: it must
    /// never delete anything while a pin it could not read might have
    /// protected it.
    pub fn read_pins(&self) -> Result<Pins> {
        let p = self.pins_path();
        // Tri-state: only a genuine NotFound is the default (no pins); a
        // stat failure propagates as a Store error (an unreadable pins file
        // must not read as "no pins" — the GC would then delete content a
        // pin might protect).
        if !path_state(&p)? {
            return Ok(Pins {
                schema_version: crate::model::PINS_SCHEMA_VERSION,
                releases: Vec::new(),
                bindings: Vec::new(),
            });
        }
        let pins: Pins = read_json(&p)?;
        if pins.schema_version != crate::model::PINS_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "pins file carries unsupported schema_version {} (expected {}): only PINS_SCHEMA_VERSION is accepted",
                pins.schema_version,
                crate::model::PINS_SCHEMA_VERSION
            )));
        }
        Ok(pins)
    }
}
/// Sanitize a name for use as a directory/file component.
///
/// The character filter is not enough on its own: `.` and `..` pass through
/// unchanged (dots are legal in ids), and a component named `..` would make
/// `targets/..` (or `deployments/..`) resolve to the STORE ROOT — a target or
/// deployment named `..` must never escape the intended layout.
pub fn sanitize(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out == "." || out == ".." {
        out = "_".to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeploymentId, GenerationId, PlacementSlotId, TargetName};

    /// `sanitize` must neutralize path-traversal components. `.` and `..` are
    /// the one case the character filter lets through untouched (dots are
    /// legal in ids), and an unsuffixed component named `..` would make
    /// `slots/..` resolve to the STORE ROOT — the `..`/`.` names are
    /// reachable via the CLI (`deploy status ..`) or a quoted TOML target key
    /// (`[targets.".."]`), so escaping the layout must be impossible.
    #[test]
    fn sanitize_neutralizes_path_traversal_components() {
        assert_eq!(sanitize(".."), "_");
        assert_eq!(sanitize("."), "_");
        assert_eq!(sanitize(""), "_");
        // Separators and any other non-id characters become underscores.
        assert_eq!(sanitize("../evil"), ".._evil");
        assert_eq!(sanitize("a/b"), "a_b");
        assert_eq!(sanitize("a\\b"), "a_b");
        // Ordinary ids pass through unchanged.
        assert_eq!(sanitize("normal-name_1.x"), "normal-name_1.x");

        // End-to-end: a SLOT id named `..` must stay inside the slot tree,
        // never resolve to the store root (the slot's ONE physical observed
        // record lives at `slots/<slot-id>/observed.json`).
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let evil = PlacementSlotId::new("..".to_string());
        assert_eq!(
            store.slot_observed_path(&evil),
            dir.path()
                .join("store")
                .join("slots")
                .join("_")
                .join("observed.json"),
            "a '..' slot must be confined to its own slot dir, not the store root"
        );
        let observed = ObservedServer {
            generation: Some(GenerationId::new("g-..".to_string())),
            artifact: None,
            last_deployment: None,
        };
        store.write_slot_observed(&evil, &observed).unwrap();
        assert!(
            !dir.path().join("store").join("observed.json").exists(),
            "observed state for a '..' slot must never land at the store root"
        );
        assert_eq!(
            store.read_slot_observed(&evil).unwrap(),
            Some(observed.clone()),
            "the sanitized path must not corrupt the recorded slot identity"
        );
        let global = store.read_global_observed().unwrap();
        assert_eq!(
            global.get(&PlacementSlotId::new("_".to_string())),
            Some(&observed),
            "the global slot map keys by the SANITIZED slot directory name"
        );
        assert!(
            !global.contains_key(&evil),
            "an unsanitized '..' id never appears as a global key"
        );
    }

    /// A canonical behavior fixture: adapter `systemd` (a NON-default value,
    /// so deleting `activation.adapter` changes the contract), a system scope,
    /// one managed unit, and a command verification with a distinctive argv.
    /// `behavior_digest` is its canonical name-sorted per-variant digest.
    fn behavior_fixture() -> (BTreeMap<String, BehaviorContract>, String) {
        let contracts: BTreeMap<String, BehaviorContract> = BTreeMap::from([(
            "standard".to_string(),
            BehaviorContract {
                activation: crate::config::ActivationConfig {
                    adapter: "systemd".to_string(),
                    scope: crate::config::ActivationScope::System,
                    reconcile_managed_units: true,
                    units: vec![crate::config::UnitDef {
                        name: "app.service".to_string(),
                        artifact_path: "integration/systemd/app.service".to_string(),
                        enable: true,
                        restart: true,
                    }],
                },
                verification: crate::config::VerificationConfig {
                    adapter: "command".to_string(),
                    argv: vec!["true".to_string()],
                    timeout_seconds: 30,
                    attempts: 2,
                    interval_seconds: 1,
                },
            },
        )]);
        let sha = crate::release::variant_behaviors_digest(&contracts);
        (contracts, sha)
    }

    /// Store a release record whose provenance `behavior_sha256` matches the
    /// canonical digest of [`behavior_fixture`] and write its aux snapshot.
    fn write_behavior_fixture(
        store: &LocalStore,
    ) -> (ReleaseId, BTreeMap<String, BehaviorContract>, String) {
        let (contracts, sha) = behavior_fixture();
        let variants: BTreeMap<crate::model::VariantName, crate::model::TreeDigest> =
            BTreeMap::from([(
                crate::model::VariantName::new("standard"),
                crate::model::TreeDigest::new("t1"),
            )]);
        let slots: BTreeMap<String, Vec<crate::config::SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![crate::config::SlotDef {
                id: "p1".to_string(),
                server: "s1".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/p1"),
                targets: vec!["t1".to_string()],
            }],
        )]);
        let rec = crate::release::build_release("m", &sha, &variants, &slots, Path::new("."));
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        let behavior_json = serde_json::to_value(&contracts).unwrap();
        store
            .write_release_aux(&id, "mapping", &behavior_json)
            .expect("behavior snapshot writes");
        (id, contracts, sha)
    }

    #[test]
    fn release_aux_snapshots_are_immutable_and_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let (id, _contracts, _sha) = write_behavior_fixture(&store);
        let behavior = serde_json::to_value(behavior_fixture().0).unwrap();

        // Identical rewrite is an idempotent success.
        store
            .write_release_aux(&id, "mapping", &behavior)
            .expect("identical rewrite must succeed");

        // Replacing the behavior snapshot with different content fails...
        let conflicting = serde_json::json!({
            "standard": {
                "activation": { "adapter": "none", "scope": "user", "reconcile_managed_units": true, "units": [] },
                "verification": {
                    "adapter": "command",
                    "argv": ["true"],
                    "timeout_seconds": 5,
                    "attempts": 1,
                    "interval_seconds": 0
                }
            }
        });
        let err = store
            .write_release_aux(&id, "mapping", &conflicting)
            .expect_err("conflicting rewrite must fail");
        assert!(
            err.to_string().contains("different content"),
            "error must name the immutability violation, got: {err}"
        );

        // ...and the stored snapshot is untouched (no torn write).
        let read = store.read_release_behaviors(&id).expect("snapshot exists");
        assert_eq!(read["standard"].activation.adapter, "systemd");
    }

    /// Mutation matrix over a stored release's `behavior.json`: deleting each
    /// required field, changing each identity-bearing field, or corrupting the
    /// bytes must make the historical read FAIL CLOSED with an integrity error
    /// (the canonical digest no longer matches the release's provenance
    /// `behavior_sha256`), while a mutation that keeps the canonical contract
    /// set equal (JSON key reordering) MUST PASS — that is the "unless the
    /// canonical behavior digest remains equal" clause.
    #[test]
    fn read_release_behaviors_verifies_behavior_json_digest() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let (id, _contracts, _sha) = write_behavior_fixture(&store);
        let path = store.release_dir(&id).join("behavior.json");

        // Baseline: the pristine snapshot reads.
        store.read_release_behaviors(&id).expect("pristine reads");

        let write = |v: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec_pretty(v).unwrap()).unwrap()
        };
        let read = |label: &str| {
            let err = store
                .read_release_behaviors(&id)
                .expect_err("a digest-changing mutation must fail closed");
            let msg = err.to_string();
            assert!(
                msg.contains("digest mismatch") || msg.contains("malformed"),
                "mutation '{label}' must fail with an integrity error, got: {msg}"
            );
        };

        // Required-field deletions: activation.adapter (default "none" now
        // differs from the stored "systemd"), verification.argv (missing
        // required field -> unparseable).
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut del = v.clone();
        del["standard"]["activation"]
            .as_object_mut()
            .unwrap()
            .remove("adapter");
        write(&del);
        read("delete activation.adapter");
        let mut del = v.clone();
        del["standard"]["verification"]
            .as_object_mut()
            .unwrap()
            .remove("argv");
        write(&del);
        read("delete verification.argv");
        let mut del = v.clone();
        del.as_object_mut().unwrap().remove("standard");
        write(&del);
        read("delete a whole variant's contract");
        let mut del = v.clone();
        del.as_object_mut().unwrap().remove("standard");
        write(&del);
        read("delete the variant key itself");

        // Identity-bearing field changes: adapter, argv element, timeout,
        // scope, variant renamed.
        let mut c = v.clone();
        c["standard"]["activation"]["adapter"] = serde_json::json!("none");
        write(&c);
        read("change activation.adapter");
        let mut c = v.clone();
        c["standard"]["verification"]["argv"][0] = serde_json::json!("false");
        write(&c);
        read("change verification.argv element");
        let mut c = v.clone();
        c["standard"]["verification"]["timeout_seconds"] = serde_json::json!(31);
        write(&c);
        read("change verification.timeout_seconds");
        let mut c = v.clone();
        c["standard"]["activation"]["scope"] = serde_json::json!("user");
        write(&c);
        read("change activation.scope");
        let mut c = v.clone();
        let standard = v["standard"].clone();
        c.as_object_mut().unwrap().remove("standard");
        c["renamed"] = standard;
        write(&c);
        read("rename the variant");

        // Corrupt bytes: unparseable -> fail closed.
        std::fs::write(&path, b"{ not json !").unwrap();
        let err = store
            .read_release_behaviors(&id)
            .expect_err("corrupt bytes must fail closed");
        assert!(
            err.to_string().contains("malformed"),
            "error must name the malformed snapshot, got: {err}"
        );

        // Digest-equal mutation: reorder JSON keys so the bytes differ but the
        // parsed contract set is identical. The canonical digest stays equal,
        // so the read MUST PASS.
        let reordered = br#"{"standard":{"verification":{"adapter":"command","argv":["true"],"timeout_seconds":30,"attempts":2,"interval_seconds":1},"activation":{"adapter":"systemd","scope":"system","reconcile_managed_units":true,"units":[{"name":"app.service","artifact_path":"integration/systemd/app.service","enable":true,"restart":true}]}}}"#;
        std::fs::write(&path, reordered).unwrap();
        let read = store
            .read_release_behaviors(&id)
            .expect("a digest-equal key reorder must pass");
        assert_eq!(read["standard"].activation.adapter, "systemd");
        assert_eq!(read["standard"].verification.timeout_seconds, 30);
    }

    /// `read_release` recomputes the canonical digest from the record's own
    /// content and verifies it against BOTH stored identity fields: a pristine
    /// record reads fine, while a record whose slot declaration was edited with
    /// the old `release_sha256`/`release_id` retained fails closed with an
    /// integrity error naming the mismatch.
    #[test]
    fn read_release_recomputes_and_verifies_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let variants: BTreeMap<crate::model::VariantName, crate::model::TreeDigest> =
            BTreeMap::from([(
                crate::model::VariantName::new("standard"),
                crate::model::TreeDigest::new("t1"),
            )]);
        let slots: BTreeMap<String, Vec<crate::config::SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![crate::config::SlotDef {
                id: "p1".to_string(),
                server: "s1".to_string(),
                deploy_dir: PathBuf::from("/srv/deploy/p1"),
                targets: vec!["t1".to_string()],
            }],
        )]);
        let rec = crate::release::build_release("m", "b", &variants, &slots, Path::new("."));
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();

        // Positive case: the unmodified record reads fine.
        let read = store.read_release(&id).unwrap();
        assert_eq!(read.release_sha256, rec.release_sha256);
        assert_eq!(read.release_id, rec.release_id);

        // Tamper: change a slot's deploy_dir in the STORED record while
        // retaining the old digest fields (the bug: content edited, digest
        // trusted). `write_release` now verifies the incoming record from its
        // content before any write, so the tampered record must be installed
        // by writing the file directly.
        let mut tampered = read.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        assert_eq!(
            tampered.release_sha256, rec.release_sha256,
            "digest retained"
        );
        assert_eq!(tampered.release_id, rec.release_id, "release id retained");
        let path = store.release_dir(&id).join("release.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();

        let err = store
            .read_release(&id)
            .expect_err("tampered record must fail verification");
        let msg = err.to_string();
        assert!(
            msg.contains("identity mismatch"),
            "error must name the mismatch, got: {msg}"
        );
        assert!(
            msg.contains(&rec.release_sha256),
            "error must name the stored digest, got: {msg}"
        );
    }

    /// `write_release` verifies the INCOMING record from its OWN content
    /// before any write: a record whose content was edited while the digest
    /// fields were retained is refused with an integrity error, and NOTHING
    /// is written — the release directory is never even created. An incoming
    /// record with an EMPTY slot snapshot is refused the same way (fail
    /// closed: a current-format record must persist its slot declarations).
    #[test]
    fn write_release_rejects_tampered_incoming_record_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let rec = crate::release::build_release(
            "m",
            "b",
            &BTreeMap::from([(
                crate::model::VariantName::new("standard"),
                crate::model::TreeDigest::new("t1"),
            )]),
            &BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotDef {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: PathBuf::from("/srv/deploy/p1"),
                    targets: vec!["t1".to_string()],
                }],
            )]),
            Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());

        // Tampered incoming: content edited, digest fields retained.
        let mut tampered = rec.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        assert_eq!(
            tampered.release_sha256, rec.release_sha256,
            "digest retained"
        );
        let err = store
            .write_release(&tampered)
            .expect_err("a tampered incoming record must be refused before any write");
        assert!(
            err.to_string().contains("identity mismatch"),
            "error must name the content-vs-digest mismatch, got: {err}"
        );
        assert!(
            !store.release_dir(&id).exists(),
            "nothing may be written for a tampered incoming record"
        );

        // Empty slot snapshot: rejected outright, nothing written.
        let mut empty = rec.clone();
        empty.slots.clear();
        let err = store
            .write_release(&empty)
            .expect_err("an empty slot snapshot must be refused before any write");
        assert!(
            err.to_string().contains("fail closed"),
            "error must explain the fail-closed rejection, got: {err}"
        );
        assert!(
            !store.release_dir(&id).exists(),
            "nothing may be written for an empty-slot-snapshot record"
        );

        // The pristine record still writes fine afterwards.
        store.write_release(&rec).expect("pristine record writes");
        assert!(store.release_dir(&id).exists());
    }

    /// `write_release` on an already-existing directory verifies the EXISTING
    /// record from its content before comparing identities: an existing record
    /// that was tampered (content edited, digest fields retained) fails with
    /// an integrity error even when the incoming record is pristine — the
    /// same-id comparison never trusts the stored digest fields.
    #[test]
    fn write_release_verifies_existing_record_before_comparing() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let rec = crate::release::build_release(
            "m",
            "b",
            &BTreeMap::from([(
                crate::model::VariantName::new("standard"),
                crate::model::TreeDigest::new("t1"),
            )]),
            &BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotDef {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: PathBuf::from("/srv/deploy/p1"),
                    targets: vec!["t1".to_string()],
                }],
            )]),
            Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).expect("pristine record writes");

        // Tamper the EXISTING record on disk: content edited, digests
        // retained (written directly, since write_release refuses it now).
        let mut tampered = rec.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        let path = store.release_dir(&id).join("release.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();

        let err = store
            .write_release(&rec)
            .expect_err("a tampered existing record must fail content verification");
        assert!(
            err.to_string().contains("identity mismatch"),
            "error must name the existing record's content-vs-digest mismatch, got: {err}"
        );

        // A genuinely different (but self-consistent) record with the same id
        // is impossible under verification, so the same-id idempotent rewrite
        // of the pristine record still passes after restoring it.
        std::fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();
        store
            .write_release(&rec)
            .expect("identical rewrite of the restored record is idempotent");
    }

    /// `read_release(id)` must verify that the STORED record's `release_id`
    /// equals the `id` the caller asked for (the directory path): a record
    /// relocated into (or swapped into) a different release directory passes
    /// content verification but is refused with an integrity error naming
    /// both ids instead of being returned as if it were `id`.
    #[test]
    fn read_release_binds_stored_release_id_to_the_read_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let rec = crate::release::build_release(
            "m",
            "b",
            &BTreeMap::from([(
                crate::model::VariantName::new("standard"),
                crate::model::TreeDigest::new("t1"),
            )]),
            &BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotDef {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: PathBuf::from("/srv/deploy/p1"),
                    targets: vec!["t1".to_string()],
                }],
            )]),
            Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).expect("pristine record writes");
        store
            .read_release(&id)
            .expect("the record reads fine from its own directory");

        // Plant the same (content-verified) record under a DIFFERENT release
        // directory: its release_id still names `id`, not the read path.
        let other = ReleaseId::new("rel-sha256-swapped".to_string());
        assert_ne!(other.as_str(), id.as_str());
        let other_dir = store.release_dir(&other);
        std::fs::create_dir_all(&other_dir).unwrap();
        std::fs::write(
            other_dir.join("release.json"),
            serde_json::to_vec_pretty(&rec).unwrap(),
        )
        .unwrap();

        let err = store
            .read_release(&other)
            .expect_err("a record whose release_id differs from the read path must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("rel-sha256-swapped") && msg.contains(&rec.release_id),
            "error must name the requested id and the record's actual release_id, got: {msg}"
        );
    }

    /// A recorded attempt's plan and results are immutable: deployment IDs are
    /// unique, so a same-ID rewrite with different content is corruption and
    /// must fail instead of silently rewriting history.
    #[test]
    fn recorded_plan_and_results_are_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        let plan = serde_json::json!({ "target": "t1" });
        store
            .write_plan("deploy-1", &plan)
            .expect("first plan write");
        store
            .write_plan("deploy-1", &plan)
            .expect("identical rewrite is idempotent");
        let err = store
            .write_plan("deploy-1", &serde_json::json!({ "target": "t2" }))
            .expect_err("conflicting plan rewrite must fail");
        assert!(err.to_string().contains("different content"));

        let results = DeploymentResults {
            deployment_id: DeploymentId::from("deploy-1".to_string()),
            target: TargetName::from("t1".to_string()),
            slots: Default::default(),
        };
        store
            .write_results("deploy-1", &results)
            .expect("first results");
        let conflicting = DeploymentResults {
            deployment_id: DeploymentId::from("deploy-1".to_string()),
            target: TargetName::from("t2".to_string()),
            slots: Default::default(),
        };
        assert!(store.write_results("deploy-1", &conflicting).is_err());
    }

    /// The floor marker gates the READER reads even when the physical logs
    /// are NOT yet compacted (an interrupted compaction): `read_attempts` /
    /// `read_snapshots` expose only the suffix at/after the floor while the
    /// raw readers still see the full physical log (never a below-floor
    /// escape hatch). The marker also fails closed on a foreign
    /// `schema_version`.
    #[test]
    fn history_floor_gates_reads_before_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t-floor";
        // deploy-a, deploy-b (both successful — rollback payloads), and
        // deploy-c (failed — no snapshot).
        let base_attempt = |id: &str| DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        for (n, id) in ["deploy-a", "deploy-b", "deploy-c"].iter().enumerate() {
            store.append_attempt(target, &base_attempt(id)).unwrap();
            if n < 2 {
                store
                    .append_snapshot(
                        target,
                        &DeploymentSnapshot {
                            deployment_id: DeploymentId::new(id.to_string()),
                            target: TargetName::new(target.to_string()),
                            behavior_sha256: "sha256-aa".to_string(),
                            slots: BTreeMap::new(),
                            bindings: BTreeMap::new(),
                        },
                    )
                    .unwrap();
            }
        }

        // Write the floor marker WITHOUT compacting (durable-first ordering;
        // the physical cleanup is still pending — the interrupted state).
        let floor = HistoryFloor {
            schema_version: SCHEMA_VERSION,
            target: TargetName::new(target.to_string()),
            deployment_id: DeploymentId::from("deploy-b".to_string()),
            established_at: "2026-01-01T00:00:00Z".to_string(),
        };
        store.write_history_floor(target, &floor).unwrap();

        // Readers gate on the durable floor: only the suffix is visible
        // (deploy-b onward; deploy-c failed and carries no snapshot).
        let snaps = store.read_snapshots(target).unwrap();
        assert_eq!(snaps.len(), 1, "only deploy-b is visible");
        assert_eq!(snaps[0].deployment_id.as_str(), "deploy-b");
        let attempts = store.read_attempts(target).unwrap();
        assert_eq!(attempts.len(), 2, "deploy-b and deploy-c are visible");
        assert_eq!(attempts[0].deployment_id.as_str(), "deploy-b");
        assert_eq!(attempts[1].deployment_id.as_str(), "deploy-c");

        // The raw (physical) view still shows the full log: the key space is
        // the deployment-id space, and no below-floor history is exposed to
        // readers.
        assert_eq!(store.read_snapshots_raw(target).unwrap().len(), 2);
        assert_eq!(store.read_attempts_raw(target).unwrap().len(), 3);

        // The floor round-trips and fails closed on a foreign schema version.
        let read = store.read_history_floor(target).unwrap().unwrap();
        assert_eq!(read, floor);
        let mut foreign = floor.clone();
        foreign.schema_version = SCHEMA_VERSION + 1;
        write_json(&store.history_floor_path(target), &foreign).unwrap();
        let err = store.read_history_floor(target).unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "a foreign floor schema version must fail closed, got: {err}"
        );
    }

    /// The cleanup-pending debt FLAG (the post-commit half of a
    /// checkpoint) round-trips, clears, fails closed on a foreign
    /// `schema_version` — including the legacy version-1 shape that carried
    /// `pending_deployments` — and is INTEGRITY-BOUND like the history
    /// floor: a marker with a foreign `target`, or (when a floor is given)
    /// a `deployment_id` that does not EXACTLY match the floor's, fails
    /// closed with an integrity error. The marker is a flag only: the
    /// removed `pending_deployments` worklist is gone by construction (the
    /// logs retain the worklist), so a corrupted marker can never name
    /// retained or unrelated deployment dirs.
    #[test]
    fn cleanup_pending_marker_roundtrips_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t-pending";
        let id = DeploymentId::new("deploy-1".to_string());
        let floor = HistoryFloor {
            schema_version: SCHEMA_VERSION,
            target: TargetName::new(target.to_string()),
            deployment_id: id.clone(),
            established_at: "2026-01-01T00:00:00Z".to_string(),
        };
        assert!(
            store
                .read_cleanup_pending(target, Some(&floor))
                .unwrap()
                .is_none(),
            "no marker before any pending cleanup"
        );

        let pending = CleanupPending {
            schema_version: CLEANUP_PENDING_SCHEMA_VERSION,
            target: TargetName::new(target.to_string()),
            deployment_id: id.clone(),
            established_at: "2026-01-01T00:00:00Z".to_string(),
        };
        store.write_cleanup_pending(target, &pending).unwrap();
        let read = store
            .read_cleanup_pending(target, Some(&floor))
            .unwrap()
            .unwrap();
        assert_eq!(read, pending);
        // The flag binds to the floor it accompanies: the same marker read
        // WITHOUT a floor passes the target binding (no anchor to check);
        // with a DIFFERENT floor it fails closed.
        store
            .read_cleanup_pending(target, None)
            .unwrap()
            .expect("the target binding alone holds without a floor");
        let foreign_floor = HistoryFloor {
            deployment_id: DeploymentId::new("deploy-other".to_string()),
            ..floor.clone()
        };
        let err = store
            .read_cleanup_pending(target, Some(&foreign_floor))
            .unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "a marker whose anchor does not match the floor must fail closed, got: {err}"
        );

        // Clear removes the marker entirely.
        store.clear_cleanup_pending(target).unwrap();
        assert!(
            store
                .read_cleanup_pending(target, Some(&floor))
                .unwrap()
                .is_none()
        );
        assert!(!store.cleanup_pending_path(target).exists());

        // A foreign schema version fails closed naming it.
        store.write_cleanup_pending(target, &pending).unwrap();
        let mut foreign = pending.clone();
        foreign.schema_version = CLEANUP_PENDING_SCHEMA_VERSION + 1;
        write_json(&store.cleanup_pending_path(target), &foreign).unwrap();
        let err = store
            .read_cleanup_pending(target, Some(&floor))
            .unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "a foreign cleanup-pending schema version must fail closed, got: {err}"
        );

        // The LEGACY version-1 shape (the removed `pending_deployments`
        // field) must NOT silently parse as a valid flag-only marker:
        // serde would ignore the extra field, so the version gate is what
        // refuses it — a stale marker is then cleared by the converging
        // retry, never trusted.
        let legacy = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "deployment_id": "deploy-1",
            "established_at": "2026-01-01T00:00:00Z",
            "snapshot_index": 1,
            "pending_deployments": ["deploy-0", "deploy-foreign"],
        });
        write_json(&store.cleanup_pending_path(target), &legacy).unwrap();
        let err = store
            .read_cleanup_pending(target, Some(&floor))
            .unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "a legacy v1 marker carrying pending_deployments must fail closed on the version, got: {err}"
        );

        // The TARGET binding: a marker naming another target fails closed
        // even though its version is current.
        let mut retargeted = pending.clone();
        retargeted.target = TargetName::new("staging".to_string());
        write_json(&store.cleanup_pending_path(target), &retargeted).unwrap();
        let err = store
            .read_cleanup_pending(target, Some(&floor))
            .unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "a cleanup marker naming a foreign target must fail closed, got: {err}"
        );
    }

    /// Enumerate EVERY corruption mutation for a checkpoint marker's
    /// serialized JSON. The mutation space is small and CLOSED, so the
    /// property below runs it EXHAUSTIVELY (deterministic, no sampling):
    ///
    /// * TRUNCATION: cut the serialized bytes at several prefix lengths
    ///   (0 = empty file, 1, mid, len-1);
    /// * MISSING FIELDS: drop each field of the JSON object;
    /// * WRONG TYPES: `schema_version` as a string, `deployment_id` as a
    ///   number, `snapshot_index` as a bool (present but wrong type);
    /// * EVERY NON-CURRENT SCHEMA VERSION: `0..SCHEMA_VERSION`,
    ///   `SCHEMA_VERSION + 1`, and `u32::MAX` — the set is DERIVED from the
    ///   CURRENT constant so it stays exhaustive if the schema version
    ///   changes (a sibling cleanup-marker hardening may introduce a
    ///   marker-specific constant at merge time; the keep-both resolution
    ///   should point this at whichever constant the reader enforces).
    ///
    /// Every mutation must classify as `Error::Integrity` — NEVER
    /// `Error::Store` (that class is reserved for filesystem I/O).
    fn marker_corruption_mutations(valid: &serde_json::Value, current_schema: u32) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let bytes = serde_json::to_vec(valid).expect("a valid marker serializes");

        // Truncations (deduped prefix lengths; all < bytes.len()).
        let mut cuts = vec![0usize, 1, bytes.len() / 2, bytes.len().saturating_sub(1)];
        cuts.sort_unstable();
        cuts.dedup();
        for cut in cuts {
            out.push(bytes[..cut].to_vec());
        }

        let obj = match valid {
            serde_json::Value::Object(o) => o,
            _ => panic!("a marker must serialize as a JSON object"),
        };

        // Missing fields: drop each field in turn (serde fails on the
        // absent field → Integrity via the parse-sensitive helper).
        for field in obj.keys() {
            let mut m = obj.clone();
            m.remove(field);
            out.push(serde_json::to_vec(&serde_json::Value::Object(m)).unwrap());
        }

        // Wrong types: the field is PRESENT but carries the wrong JSON
        // type (both markers share these field names — `snapshot_index` is
        // an ignored legacy key now, so the wrong-type pair uses the
        // identity/age fields instead).
        let mut as_string = obj.clone();
        as_string.insert("schema_version".into(), serde_json::Value::from("1"));
        out.push(serde_json::to_vec(&serde_json::Value::Object(as_string)).unwrap());

        let mut as_number = obj.clone();
        as_number.insert("deployment_id".into(), serde_json::Value::from(7));
        out.push(serde_json::to_vec(&serde_json::Value::Object(as_number)).unwrap());

        let mut as_bool = obj.clone();
        as_bool.insert("established_at".into(), serde_json::Value::from(true));
        out.push(serde_json::to_vec(&serde_json::Value::Object(as_bool)).unwrap());

        // Every non-current schema version the current reader must refuse.
        for v in non_current_schema_versions(current_schema) {
            let mut m = obj.clone();
            m.insert("schema_version".into(), serde_json::Value::from(v));
            out.push(serde_json::to_vec(&serde_json::Value::Object(m)).unwrap());
        }

        out
    }

    /// Every `u32` schema version the current reader must refuse:
    /// `0..SCHEMA_VERSION`, `SCHEMA_VERSION + 1`, `u32::MAX` (derived from
    /// the CURRENT constant — see [`marker_corruption_mutations`]).
    fn non_current_schema_versions(current: u32) -> Vec<u32> {
        let mut v: Vec<u32> = (0..current).collect();
        v.push(current.wrapping_add(1));
        v.push(u32::MAX);
        v.sort_unstable();
        v
    }

    /// Run the corruption-classification property for one marker reader:
    /// the INTACT marker reads as `Ok(Some(_))`; EVERY corruption mutation
    /// fails with EXACTLY the `Error::Integrity` variant — asserted via
    /// `matches!` on the ENUM, never message text; a genuine filesystem
    /// I/O failure (the marker path is a DIRECTORY, so open/read fails at
    /// the OS level) stays `Error::Store`; an absent marker is `Ok(None)`.
    /// Both checkpoint markers go through the shared parse-sensitive
    /// [`read_json_marker`] helper, so one generic property covers both.
    fn assert_marker_corruption_classification<T: std::fmt::Debug>(
        path: &Path,
        valid: &serde_json::Value,
        mutations: &[Vec<u8>],
        read: impl Fn() -> Result<Option<T>>,
    ) {
        // Control: the intact marker parses AND passes the schema check.
        std::fs::write(path, serde_json::to_vec(valid).unwrap()).unwrap();
        assert!(
            read().expect("the intact marker must read").is_some(),
            "the intact marker must read as Ok(Some(_))"
        );

        // Every corruption mutation → Integrity (semantic corruption), never
        // Store (mechanical I/O) — the class split this feature enforces.
        for m in mutations {
            std::fs::write(path, m).unwrap();
            match read() {
                Err(Error::Integrity(_)) => {}
                other => panic!(
                    "marker corruption must classify as Error::Integrity, got: {other:?}\n  bytes: {}",
                    String::from_utf8_lossy(m)
                ),
            }
        }

        // Class split: a real filesystem I/O failure (marker path is a
        // directory → EISDIR on open/read) stays Error::Store.
        std::fs::remove_file(path).unwrap();
        std::fs::create_dir(path).unwrap();
        match read() {
            Err(Error::Store(_)) => {}
            other => {
                panic!("a filesystem I/O failure must classify as Error::Store, got: {other:?}")
            }
        }
        std::fs::remove_dir(path).unwrap();

        // Absent marker → Ok(None), never an error.
        assert!(
            read().expect("an absent marker must be Ok(None)").is_none(),
            "an absent marker must read as Ok(None)"
        );
    }

    /// THE BYTE/JSON MUTATION PROPERTY: present-but-malformed marker
    /// CONTENT (truncated JSON, wrong field types, missing fields) and
    /// unsupported marker SCHEMAS classify as `Error::Integrity` for BOTH
    /// checkpoint marker readers, while `Error::Store` stays reserved for
    /// actual filesystem I/O. The mutation space is small and closed, so
    /// the property enumerates it exhaustively over fresh fixtures
    /// (deterministic — every mutation in the family runs every time).
    #[test]
    fn marker_corruption_is_integrity_and_io_is_store() {
        // ---- history floor marker ----
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t-floor";
        let floor_id = DeploymentId::new("deploy-floor".to_string());
        // Seed the attempt + snapshot the intact marker binds to, so the
        // control (`Ok(Some(_))`) passes the snapshot-pair and attempt
        // binding checks in `read_history_floor` (those checks are ALREADY
        // Integrity — this property exercises the parse/schema branch).
        store
            .append_attempt(
                target,
                &DeploymentAttempt {
                    deployment_schema_version: SCHEMA_VERSION,
                    deployment_id: floor_id.clone(),
                    target: TargetName::new(target.to_string()),
                    slot_ids: vec![],
                    behavior_sha256: "sha256-aa".to_string(),
                    attempted_at: "2026-01-01T00:00:00Z".to_string(),
                    desired: BTreeMap::new(),
                    pre_push: BTreeMap::new(),
                    slots: BTreeMap::new(),
                },
            )
            .unwrap();
        store
            .append_snapshot(
                target,
                &DeploymentSnapshot {
                    deployment_id: floor_id.clone(),
                    target: TargetName::new(target.to_string()),
                    behavior_sha256: "sha256-aa".to_string(),
                    slots: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                },
            )
            .unwrap();
        let floor = HistoryFloor {
            schema_version: SCHEMA_VERSION,
            target: TargetName::new(target.to_string()),
            deployment_id: floor_id,
            established_at: "2026-01-01T00:00:00Z".to_string(),
        };
        store.write_history_floor(target, &floor).unwrap();

        let floor_valid = serde_json::to_value(&floor).unwrap();
        let floor_mutations = marker_corruption_mutations(&floor_valid, SCHEMA_VERSION);
        assert!(
            !floor_mutations.is_empty(),
            "the mutation family must be non-empty"
        );
        assert_marker_corruption_classification(
            &store.history_floor_path(target),
            &floor_valid,
            &floor_mutations,
            || store.read_history_floor(target),
        );

        // ---- cleanup-pending marker: the same property through the shared
        // parse-sensitive helper (no binding checks to seed here).
        let target2 = "t-pending";
        let pending = CleanupPending {
            schema_version: CLEANUP_PENDING_SCHEMA_VERSION,
            target: TargetName::new(target2.to_string()),
            deployment_id: DeploymentId::new("deploy-1".to_string()),
            established_at: "2026-01-01T00:00:00Z".to_string(),
        };
        store.write_cleanup_pending(target2, &pending).unwrap();

        let pending_valid = serde_json::to_value(&pending).unwrap();
        let pending_mutations =
            marker_corruption_mutations(&pending_valid, CLEANUP_PENDING_SCHEMA_VERSION);
        assert_marker_corruption_classification(
            &store.cleanup_pending_path(target2),
            &pending_valid,
            &pending_mutations,
            || store.read_cleanup_pending(target2, None),
        );
    }

    /// The one-shot intent/outcomes faults are deployment-id keyed and
    /// status-qualified: `arm_append_attempt` fails the NEXT `append_attempt`
    /// for that id exactly once; `arm_write_results` fails the next
    /// `write_results`; `arm_append_transition_pending` fails ONLY the first
    /// `PendingCommit` transition append (the recoverable finalize marker) —
    /// an earlier `InProgress` (or any other status) append passes through.
    ///
    /// Faults are armed on THIS store's per-fixture registry
    /// ([`LocalStore::fault_registry`]); no process-global slot is involved,
    /// so no lock window is needed.
    #[test]
    fn new_fault_arms_are_one_shot_and_status_qualified() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let registry = store.fault_registry().clone();
        let target = "t1";
        let id = "deploy-fault-arms";
        let attempt = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // arm_append_attempt: one-shot, fails once, then passes.
        registry.arm_append_attempt(id);
        let err = store.append_attempt(target, &attempt).unwrap_err();
        assert!(err.to_string().contains("append_attempt"));
        store.append_attempt(target, &attempt).expect("disarmed");

        // arm_write_results: one-shot.
        registry.arm_write_results(id);
        let results = DeploymentResults {
            deployment_id: DeploymentId::from(id.to_string()),
            target: TargetName::from(target.to_string()),
            slots: Default::default(),
        };
        let err = store.write_results(id, &results).unwrap_err();
        assert!(err.to_string().contains("write_results"));
        store.write_results(id, &results).expect("disarmed");

        // arm_append_transition_pending: status-qualified — an InProgress
        // append passes through; the first PendingCommit append fails once.
        registry.arm_append_transition_pending(id);
        store
            .append_transition(id, &DeploymentStatus::InProgress, Some("attempt started"))
            .expect("InProgress append passes through untouched");
        let err = store
            .append_transition(
                id,
                &DeploymentStatus::PendingCommit,
                Some("finalization started"),
            )
            .unwrap_err();
        assert!(err.to_string().contains("append_transition"));
        store
            .append_transition(id, &DeploymentStatus::PendingCommit, None)
            .expect("disarmed");
    }

    /// The transition stream is append-only JSONL: every appended event is
    /// preserved in order, the LATEST event is the deployment's current
    /// status, and the `reason` is carried (or omitted) as recorded.
    #[test]
    fn transition_stream_is_append_only_and_latest_wins() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let id = "deploy-transitions";

        assert_eq!(store.latest_status(id).unwrap(), None, "no transitions yet");
        assert_eq!(store.read_transitions(id).unwrap().len(), 0);

        store
            .append_transition(id, &DeploymentStatus::InProgress, Some("attempt started"))
            .unwrap();
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .unwrap();

        // Append-only: both events survive, in order.
        let transitions = store.read_transitions(id).unwrap();
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].status, DeploymentStatus::InProgress);
        assert_eq!(transitions[0].reason.as_deref(), Some("attempt started"));
        assert_eq!(transitions[1].status, DeploymentStatus::Successful);
        assert_eq!(transitions[1].reason, None);
        assert_eq!(
            transitions[0].deployment_id,
            DeploymentId::new(id.to_string())
        );
        assert!(!transitions[1].recorded_at.is_empty());

        // Latest transition wins: an append overlays, never rewrites history.
        assert_eq!(
            store.latest_status(id).unwrap(),
            Some(DeploymentStatus::Successful)
        );
        store
            .append_transition(
                id,
                &DeploymentStatus::Degraded,
                Some("marker integrity conflict"),
            )
            .unwrap();
        assert_eq!(
            store.latest_status(id).unwrap(),
            Some(DeploymentStatus::Degraded)
        );
        assert_eq!(store.read_transitions(id).unwrap().len(), 3);
    }

    /// The attempts stream is append-only: appending a SECOND record with the
    /// SAME deployment id (the engine never does — ids are minted fresh)
    /// appends rather than replacing, so the log always preserves every
    /// recorded intent. Deployment IDs are unique by construction, so the
    /// duplicate case exercises corruption-tolerant append semantics, not a
    /// rewrite.
    #[test]
    fn attempts_stream_is_append_only_for_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let attempt = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-dup".to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        store.append_attempt(target, &attempt).unwrap();
        let second = DeploymentAttempt {
            attempted_at: "2026-01-02T00:00:00Z".to_string(),
            ..attempt.clone()
        };
        store.append_attempt(target, &second).unwrap();

        let attempts = store.read_attempts(target).unwrap();
        assert_eq!(
            attempts.len(),
            2,
            "append-only: a duplicate id appends a second record, never replaces"
        );
        assert_eq!(attempts[0].deployment_id, attempts[1].deployment_id);
        assert_eq!(attempts[0].attempted_at, "2026-01-01T00:00:00Z");
        assert_eq!(attempts[1].attempted_at, "2026-01-02T00:00:00Z");
    }

    /// The schema-version property for DEPLOYMENT records: generate arbitrary
    /// `u32` versions and write an `attempts.jsonl` line carrying each one
    /// directly into the store. ONLY `SCHEMA_VERSION` loads; every other
    /// version fails closed with a store error naming the version — never a
    /// panic, never silent acceptance.
    #[test]
    fn read_attempts_accepts_only_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let p = store.target_dir(target).join("attempts.jsonl");
        let base = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-versions".to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        // Representative arbitrary-u32 set: 0, SCHEMA_VERSION - 1,
        // SCHEMA_VERSION, SCHEMA_VERSION + 1, 3, u32::MAX (duplicates in the
        // set are harmless).
        let versions = [
            0u32,
            SCHEMA_VERSION.wrapping_sub(1),
            SCHEMA_VERSION,
            SCHEMA_VERSION.wrapping_add(1),
            3,
            u32::MAX,
        ];
        for v in versions {
            // A fresh stream per version: one line carrying exactly `v`.
            std::fs::remove_file(&p).ok();
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let attempt = DeploymentAttempt {
                deployment_schema_version: v,
                ..base.clone()
            };
            std::fs::write(
                &p,
                format!("{}\n", serde_json::to_string(&attempt).unwrap()),
            )
            .unwrap();
            if v == SCHEMA_VERSION {
                let read = store.read_attempts(target).unwrap();
                assert_eq!(read.len(), 1, "the canonical version loads");
                assert_eq!(read[0].deployment_schema_version, SCHEMA_VERSION);
            } else {
                let err = store.read_attempts(target).unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.contains("deployment_schema_version"),
                    "error must name the version field, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{v}")),
                    "error must name the stored version {v}, got: {msg}"
                );
                assert!(
                    msg.contains("SCHEMA_VERSION"),
                    "error must name the accepted version, got: {msg}"
                );
            }
        }
    }

    /// The schema-version property for TREE metadata: generate arbitrary `u32`
    /// `tree_schema_version` values in a stored `tree.json`; ONLY
    /// `TREE_SCHEMA_VERSION` loads, every other version fails closed with an
    /// integrity error naming the version.
    #[test]
    fn read_tree_meta_accepts_only_tree_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let digest = TreeDigest::new("t-versions".to_string());
        let p = store.object_tree_json(&digest);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let versions = [
            0u32,
            TREE_SCHEMA_VERSION.wrapping_sub(1),
            TREE_SCHEMA_VERSION,
            TREE_SCHEMA_VERSION.wrapping_add(1),
            3,
            u32::MAX,
        ];
        for v in versions {
            let meta = TreeMetadata {
                tree_schema_version: v,
                hash_algorithm: "sha256".to_string(),
                tree_sha256: "x".to_string(),
                entries: vec![],
            };
            std::fs::write(&p, serde_json::to_vec(&meta).unwrap()).unwrap();
            if v == TREE_SCHEMA_VERSION {
                store
                    .read_tree_meta(&digest)
                    .expect("the canonical tree schema version reads");
            } else {
                let err = store.read_tree_meta(&digest).unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.contains("tree_schema_version"),
                    "error must name the version field, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{v}")),
                    "error must name the stored version {v}, got: {msg}"
                );
            }
        }
    }

    /// `arm_append_transition_successful` is status-qualified and one-shot:
    /// non-`Successful` appends (the recoverable `PendingCommit` marker, an
    /// `InProgress` overlay) pass through untouched, the FIRST `Successful`
    /// append fails, and a later `Successful` append passes. The arm lives on
    /// this store's own per-fixture registry; no lock window is needed.
    #[test]
    fn transition_successful_fault_is_status_qualified_and_one_shot() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let registry = store.fault_registry().clone();
        let id = "deploy-txn-success-fault";

        registry.arm_append_transition_successful(id);
        // The recoverable finalize marker passes through (status-qualified).
        store
            .append_transition(
                id,
                &DeploymentStatus::PendingCommit,
                Some("finalization started"),
            )
            .expect("PendingCommit append passes through untouched");
        // The FIRST Successful append fires the fault.
        let err = store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .unwrap_err();
        assert!(err.to_string().contains("append_transition"));
        // A later Successful append passes (one-shot, disarmed).
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .expect("disarmed");

        // Re-arm: an InProgress overlay must not consume the arm.
        registry.arm_append_transition_successful(id);
        store
            .append_transition(id, &DeploymentStatus::InProgress, None)
            .expect("InProgress append does not consume the arm");
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .expect_err("first Successful append fires again");
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .expect("disarmed again");
    }

    /// Two DISTINCT fault keys (two deployment ids) armed on ONE fixture,
    /// consumed in interleaved order through the real store methods. Oracle:
    /// each fault fires EXACTLY ONCE and only for its own key; the other
    /// operation passes through untouched (even when interleaved), and a
    /// re-run of the same consume does NOT fire again (one-shot). The store
    /// records exactly one attempt per id — the post-fault re-runs — so the
    /// observable history also matches the oracle.
    #[test]
    fn two_key_interleaved_store_faults_fire_exactly_once_per_matching_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let registry = store.fault_registry();
        let target = "t1";
        let id_a = "deploy-key-a";
        let id_b = "deploy-key-b";
        let attempt = |id: &str| DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // Arm TWO distinct keys on the same registry.
        registry.arm_append_attempt(id_a);
        registry.arm_append_attempt(id_b);
        assert_eq!(registry.armed_len(), 2, "both faults armed");

        // Interleaved consume, B FIRST: B's append fires B and must NOT fire
        // (or disarm) A.
        let err = store.append_attempt(target, &attempt(id_b)).unwrap_err();
        assert!(err.to_string().contains("append_attempt"), "B fired");
        assert!(
            registry.is_armed(FaultKind::AppendAttempt, id_a),
            "A stays armed"
        );
        assert!(
            !registry.is_armed(FaultKind::AppendAttempt, id_b),
            "B disarmed"
        );

        // Then A's append fires A exactly once.
        let err = store.append_attempt(target, &attempt(id_a)).unwrap_err();
        assert!(err.to_string().contains("append_attempt"), "A fired");
        assert!(
            !registry.is_armed(FaultKind::AppendAttempt, id_a),
            "A disarmed"
        );

        // Re-running the same consumes does NOT fire again (one-shot), and a
        // matching-store operation for a NEVER-armed third key passes through.
        store
            .append_attempt(target, &attempt(id_b))
            .expect("B disarmed");
        store
            .append_attempt(target, &attempt(id_a))
            .expect("A disarmed");
        store
            .append_attempt(target, &attempt("deploy-key-c"))
            .expect("never-armed key passes through");

        // Observable oracle: exactly one durable attempt per key (the post-
        // fault re-runs), never a duplicate from the faulted calls.
        let attempts = store.read_attempts(target).unwrap();
        let mut ids: Vec<_> = attempts.iter().map(|a| a.deployment_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["deploy-key-a", "deploy-key-b", "deploy-key-c"]);
        assert_eq!(registry.armed_len(), 0, "no arms left");
    }

    /// The structural isolation property: arming a fault on fixture 1's
    /// registry cannot be consumed by fixture 2's store — even with the SAME
    /// deployment id — and survives for fixture 1's own store to fire.
    #[test]
    fn arming_one_fixture_cannot_be_consumed_by_another_fixtures_store() {
        let dir = tempfile::tempdir().unwrap();
        let store_a = LocalStore::with_base(dir.path().join("a")).unwrap();
        let store_b = LocalStore::with_base(dir.path().join("b")).unwrap();
        let id = "deploy-cross-fixture";
        let attempt = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new("t1".to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // Fixture A arms; fixture B's store is its OWN empty registry.
        store_a.fault_registry().arm_append_attempt(id);
        assert!(
            !store_b
                .fault_registry()
                .is_armed(FaultKind::AppendAttempt, id),
            "B's registry is disjoint from A's"
        );

        // B's identical append passes through untouched, and A's arm SURVIVES.
        store_b
            .append_attempt("t1", &attempt)
            .expect("B passes through");
        assert!(
            store_a
                .fault_registry()
                .is_armed(FaultKind::AppendAttempt, id),
            "A's arm must not have been consumed by B's push"
        );
        // A's OWN matching append fires exactly once.
        store_a
            .append_attempt("t1", &attempt)
            .expect_err("A's own append fires the fault");
        assert!(
            !store_a
                .fault_registry()
                .is_armed(FaultKind::AppendAttempt, id)
        );
    }

    /// Threaded interleaving across TWO fixtures: each thread arms its own
    /// key on its OWN store's registry, then both consume through the real
    /// store methods concurrently (a barrier maximizes overlap). Oracle: each
    /// fault fires EXACTLY ONCE in its own fixture and NEVER in the other's;
    /// each store ends with exactly one durable attempt for its own id.
    #[test]
    fn two_key_threaded_interleaving_isolation_between_fixtures() {
        let dir = tempfile::tempdir().unwrap();
        let store_a = LocalStore::with_base(dir.path().join("a")).unwrap();
        let store_b = LocalStore::with_base(dir.path().join("b")).unwrap();
        let (id_a, id_b) = ("deploy-thread-a", "deploy-thread-b");
        let attempt = |id: &str| DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new("t1".to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        std::thread::scope(|s| {
            for (store, id) in [(&store_a, id_a), (&store_b, id_b)] {
                let barrier = barrier.clone();
                s.spawn(move || {
                    // Arm on THIS fixture's registry, then consume through
                    // THIS fixture's store — the other thread is doing the
                    // same concurrently, and the registries are disjoint.
                    store.fault_registry().arm_append_attempt(id);
                    barrier.wait();
                    let err = store
                        .append_attempt("t1", &attempt(id))
                        .expect_err("the matching append fires exactly once");
                    assert!(err.to_string().contains("append_attempt"));
                    store
                        .append_attempt("t1", &attempt(id))
                        .expect("disarmed: the re-run passes");
                });
            }
            barrier.wait();
        });

        // Both faults fired exactly once in their OWN fixture; the other
        // fixture was never affected: each store holds exactly one attempt,
        // its own id.
        let only = |store: &LocalStore| {
            let attempts = store.read_attempts("t1").unwrap();
            assert_eq!(attempts.len(), 1, "exactly one durable attempt");
            attempts[0].deployment_id.as_str().to_string()
        };
        assert_eq!(only(&store_a), id_a);
        assert_eq!(only(&store_b), id_b);
    }
}

//! Filesystem-backed local store.
//!
//! Record contract: ONE ordered deployment ledger per target
//! (`targets/<target>/ledger.jsonl`, append-only JSON lines). An entry starts
//! as the DURABLE INTENT ([`crate::records::LedgerIntent`], appended BEFORE
//! any remote mutation — the append-attempt contract) and its TERMINAL EVENT
//! ([`crate::records::LedgerTerminal`], appended after the mutation loop)
//! carries the status, the per-slot outcomes, and — when successful — the
//! rollback state ([`crate::records::LedgerRollback`]). The append order IS
//! the history order; the deployment id keys each entry. There is no
//! separate floor marker, snapshot op log, per-deployment results/transition
//! stream, or cleanup-debt flag: the ledger replaces all of them.
//!
//! DURABILITY: every append is a CRASH-ATOMIC whole-ledger rewrite through
//! the same protocol as the checkpoint's suffix replacement
//! ([`crate::store::atomic::write_atomic_replace`]: unique same-directory
//! temp file, chmod-private BEFORE visible, temp fsync, atomic rename, then
//! a fail-closed parent-directory fsync). The ledger is bounded — the
//! checkpoint's suffix compaction keeps it small, and even an
//! un-checkpointed ledger is one small file per target — so the O(n)
//! rewrite cost per append is acceptable, and the atomic rename gives the
//! append the SAME whole-or-nothing guarantee the checkpoint has: a reader
//! (or a fresh store after a crash) sees a wholly OLD or wholly NEW ledger,
//! never a torn partial line, and an append that returned `Ok` is durable.
//! Appends are serialized under the target lock (push and checkpoint both
//! acquire the application-store lock then the target lock), so the
//! read-modify-write cannot interleave with another writer. See
//! [`LocalStore::append_ledger_atomic`] for the staged protocol and the
//! test-only fault surface.
//!
//! ```text
//! <base>/
//!   objects/sha256/<digest>/root/ , tree.json
//!   releases/<release-id>/mapping.toml, behavior.json, release.json
//!   targets/<target>/observed.json, rotation-debt.json, ledger.jsonl
//!   slots/<slot-id>/observed.json   (the slot's ONE physical observed state)
//!   servers/<server-id>.json
//!   deployments/<deployment-id>/plan.json
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
//! etc. — including the four atomic-append STAGE faults of
//! [`LocalStore::append_ledger_atomic`]). There are NO process-global fault
//! slots and NO shared fault lock:
//! two fixtures' registries are disjoint by construction, so a fault armed by
//! one test can never fire in another's push — structural isolation that
//! holds under any parallel `cargo test` interleaving.

use crate::error::{Error, Result};
use crate::layout;
use crate::model::{
    BehaviorContract, PlacementSlotId, ReleaseId, ReleaseRecord, SCHEMA_VERSION,
    TREE_SCHEMA_VERSION, TreeDigest, TreeMetadata,
};

#[cfg(test)]
use crate::model::DeploymentId;
use crate::records::{
    DeploymentStatus, LedgerEntry, LedgerIntent, LedgerLine, LedgerTerminal, ObservedServer,
    ObservedTarget, Pins, ServerState,
};
use crate::store::atomic::{
    copy_dir_recursive, ensure_private_dir, path_state, read_json, set_private, sync_parent_dir,
    temp_name_for, write_atomic_replace,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    /// `target` field (as everywhere in the codebase): `deploy status
    /// <target>` and every other consumer see exactly the physical records of
    /// the target's member slots — never a replicated per-target copy. A
    /// slot has EXACTLY ONE owning target, so its single physical record
    /// serves exactly that target's view. A member slot with no physical
    /// record yet is simply absent from the view.
    pub fn read_observed(
        &self,
        target: &str,
        config: &crate::config::Config,
    ) -> Result<ObservedTarget> {
        let members: std::collections::HashSet<&str> = config
            .slot_defs()
            .iter()
            .filter(|s| s.target == target)
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

    // ---- the store-global sweep debt (checkpoint sweep maintenance) ------

    /// Path of the store-global sweep-debt marker (`<base>/sweep-debt.json`).
    /// The checkpoint's best-effort GLOBAL sweep is POST-COMMIT maintenance:
    /// an incomplete sweep records a durable marker here (the reason the
    /// sweep did not complete) so the NEXT PUSH — not just the next
    /// checkpoint — retries the sweep (recomputing reachability fresh, no
    /// persisted deletion worklist) and clears the marker once it completes.
    /// The marker is store-global because the sweep is global: release
    /// records and tree objects are content-addressed and shared across
    /// targets, so a pending sweep is a property of the whole store, not of
    /// one target's ledger.
    pub fn sweep_debt_path(&self) -> PathBuf {
        self.base.join("sweep-debt.json")
    }

    /// Read the store-global sweep-debt marker: `Some(reason)` when a sweep
    /// is pending, `None` when no maintenance is outstanding. Tri-state:
    /// only a genuine NotFound is "no debt"; a stat failure propagates (an
    /// unreadable marker must not read as "no debt").
    pub fn read_sweep_debt(&self) -> Result<Option<String>> {
        // Post-commit maintenance fault injection, keyed by the empty global
        // key (the sweep debt is store-global, not target-keyed).
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::ReadSweepDebt, "") {
            return Err(Error::store(
                "test fault: read_sweep_debt forced to fail once",
            ));
        }
        let p = self.sweep_debt_path();
        if path_state(&p)? {
            let v: serde_json::Value = read_json(&p)?;
            Ok(v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        } else {
            Ok(None)
        }
    }

    /// Persist (or clear) the store-global sweep-debt marker. `None` removes
    /// the marker file, so a fully-serviced store leaves no trace.
    pub fn write_sweep_debt(&self, reason: Option<&str>) -> Result<()> {
        // Post-commit maintenance write fault, keyed by the empty global key.
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::WriteSweepDebt, "") {
            return Err(Error::store(
                "test fault: write_sweep_debt forced to fail once",
            ));
        }
        let p = self.sweep_debt_path();
        match reason {
            None => {
                // Tri-state removal decision: a genuine NotFound is nothing
                // to remove; any other stat error propagates (an unreadable
                // marker must not silently survive as a stale "debt" record).
                if path_state(&p)? {
                    std::fs::remove_file(&p).map_err(|e| {
                        Error::store(format!("remove sweep debt {}: {e}", p.display()))
                    })?;
                }
                Ok(())
            }
            Some(r) => write_json(&p, &serde_json::json!({ "reason": r })),
        }
    }

    // ---- the per-target deployment LEDGER --------------------------------

    /// Path of the target's ONE ordered deployment ledger
    /// (`targets/<target>/ledger.jsonl`). The ledger holds every deployment
    /// event of the target: each entry starts as the DURABLE INTENT line
    /// (written BEFORE any remote mutation) and its TERMINAL EVENT line
    /// (appended after the mutation loop) carries the status, outcomes, and
    /// — when successful — the rollback state. The append order IS the
    /// history order; there is no separate floor marker, snapshot op log,
    /// or per-deployment results/transition stream.
    pub fn ledger_path(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("ledger.jsonl")
    }

    /// Append the DURABLE INTENT of one deployment to the target's ledger
    /// (one `{"kind":"intent", ...}` JSON line), BEFORE any remote
    /// mutation: a crash after servers advanced to new generations can never
    /// lose the deployment (the intent is already durable and the next push
    /// reconciles it). The append is a CRASH-ATOMIC whole-ledger rewrite
    /// (temp + fsync + chmod + rename + parent-dir fsync, see
    /// [`LocalStore::append_ledger_atomic`]): a successful append is durable
    /// and a crash can never leave a torn line. Fail-closed keying: the
    /// deployment id keys the entry, so a second intent for the same id (a
    /// corrupted duplicate) is refused rather than silently merged. The
    /// duplicate guard scans EVERY parsed ledger entry (`read_ledger`), not
    /// just the first one.
    pub fn append_intent(&self, target: &str, intent: &LedgerIntent) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendAttempt, intent.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_attempt (ledger intent) forced to fail once",
            ));
        }
        let dir = self.target_dir(target);
        ensure_private_dir(&dir)?;
        // The intent is the entry's durable key: a duplicate intent for the
        // same deployment id is corruption (deployment ids are unique per
        // push) and must fail closed rather than append a second entry. The
        // guard scans EVERY parsed entry (`read_ledger` is the source of
        // truth and fails closed on malformed lines) — a duplicate at any
        // position, not just the first entry, is refused.
        if self
            .read_ledger(target)?
            .iter()
            .any(|e| e.deployment_id == intent.deployment_id)
        {
            return Err(Error::store(format!(
                "refusing to append a second intent for deployment '{}' (the ledger is keyed by deployment id)",
                intent.deployment_id
            )));
        }
        let line = serde_json::to_string(&LedgerLine::Intent(intent.clone()))
            .map_err(|e| Error::store(format!("serialize ledger intent: {e}")))?;
        self.append_ledger_atomic(target, intent.deployment_id.as_str(), &line)
    }

    /// Append the TERMINAL EVENT of one deployment to the target's ledger
    /// ("`{"kind":"terminal", ...}`" JSON line), after the mutation loop.
    /// The terminal carries the status, the per-slot outcomes, and — when
    /// successful — the rollback state. Like the intent it is appended via
    /// the crash-atomic whole-ledger rewrite (see
    /// [`LocalStore::append_ledger_atomic`]). Fail-closed key contract: the
    /// deployment's intent must already exist in the ledger (a terminal for
    /// an unknown deployment is corruption) and the entry must not already
    /// have a terminal (the terminal event is written exactly once;
    /// replay-safety is handled by the finalizer checking the entry first).
    pub fn append_terminal(&self, target: &str, terminal: &LedgerTerminal) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendTerminal, terminal.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_terminal forced to fail once",
            ));
        }
        let dir = self.target_dir(target);
        ensure_private_dir(&dir)?;
        let entries = self.read_ledger(target)?;
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == terminal.deployment_id)
            .ok_or_else(|| {
                Error::integrity(format!(
                    "append_terminal for deployment '{}': no ledger intent exists for it — a terminal event requires its durable intent (a terminal without an intent is corruption)",
                    terminal.deployment_id
                ))
            })?;
        if entry.terminal.is_some() {
            return Err(Error::integrity(format!(
                "append_terminal for deployment '{}': the entry already carries a terminal event (a terminal is written exactly once)",
                terminal.deployment_id
            )));
        }
        let line = serde_json::to_string(&LedgerLine::Terminal(terminal.clone()))
            .map_err(|e| Error::store(format!("serialize ledger terminal: {e}")))?;
        self.append_ledger_atomic(target, terminal.deployment_id.as_str(), &line)
    }

    /// Read the FULL deployment ledger of a target: every merged
    /// [`LedgerEntry`] (intent + optional terminal), in append order. This is
    /// the SINGLE history read — it replaces the old `read_attempts` /
    /// `read_snapshots` pair (and their raw variants): there is no floor to
    /// gate (the checkpoint replaced the ledger with the retained suffix
    /// atomically) and no separate snapshot log. Fail closed on malformed
    /// lines, foreign `deployment_schema_version`, an intent-less terminal,
    /// a duplicate intent, or a duplicate terminal.
    pub fn read_ledger(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        let p = self.ledger_path(target);
        // Tri-state: only a genuine NotFound is "no ledger" (the empty
        // vector); a stat failure propagates as a Store error (an unreadable
        // ledger must not read as "no history").
        if !path_state(&p)? {
            return Ok(vec![]);
        }
        let text =
            std::fs::read_to_string(&p).map_err(|e| Error::store(format!("read ledger: {e}")))?;
        let mut out: Vec<LedgerEntry> = Vec::new();
        let mut index: BTreeMap<String, usize> = BTreeMap::new();
        for (seq, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<LedgerLine>(line)
                .map_err(|e| Error::store(format!("parse ledger line: {e}")))?
            {
                LedgerLine::Intent(intent) => {
                    // Fail closed on the record schema version: only
                    // `SCHEMA_VERSION` is accepted, any other version is
                    // refused with an error naming the version (a record
                    // from a different schema is never silently
                    // interpreted).
                    if intent.deployment_schema_version != SCHEMA_VERSION {
                        return Err(Error::store(format!(
                            "intent {} carries unsupported deployment_schema_version {} (expected {SCHEMA_VERSION}): only SCHEMA_VERSION is accepted",
                            intent.deployment_id, intent.deployment_schema_version
                        )));
                    }
                    let id = intent.deployment_id.as_str().to_string();
                    if index.contains_key(&id) {
                        return Err(Error::integrity(format!(
                            "ledger for target '{target}' has two intent lines for deployment '{id}' — the ledger is keyed by deployment id (one intent per entry)"
                        )));
                    }
                    index.insert(id.clone(), out.len());
                    out.push(LedgerEntry {
                        deployment_id: intent.deployment_id.clone(),
                        target: intent.target.clone(),
                        intent,
                        terminal: None,
                        seq: seq as u64,
                    });
                }
                LedgerLine::Terminal(terminal) => {
                    let id = terminal.deployment_id.as_str();
                    let pos = index.get(id).copied().ok_or_else(|| {
                        Error::integrity(format!(
                            "ledger of target '{target}': a terminal event for deployment '{id}' has no intent line — a terminal event requires its durable intent (a closed-DB corruption)"
                        ))
                    })?;
                    let entry = &mut out[pos];
                    if entry.terminal.is_some() {
                        return Err(Error::integrity(format!(
                            "ledger of target '{target}': two terminal events for deployment '{id}' — a terminal event is written exactly once"
                        )));
                    }
                    entry.terminal = Some(terminal);
                }
            }
        }
        Ok(out)
    }

    /// The target's LATEST SUCCESSFUL deployment id, derived from the ledger
    /// (the newest entry whose terminal event is `Successful`). The old
    /// `refs/last-successful` mutable ref file is GONE: the derived read is
    /// exact by construction — no stale-ref crash corner exists anymore.
    pub fn read_last_successful(&self, target: &str) -> Option<String> {
        self.read_ledger(target)
            .ok()?
            .into_iter()
            .rev()
            .find_map(|e| {
                (e.terminal.as_ref().map(|t| t.status.clone())
                    == Some(DeploymentStatus::Successful))
                .then(|| e.deployment_id.as_str().to_string())
            })
    }

    /// The current status of a deployment: the status of its TERMINAL EVENT
    /// in the target's ledger, or — when the entry exists but has no
    /// terminal yet — `Some(PendingCommit)` (the recoverable in-progress /
    /// pending-commit state: the intent is durable, the finalization never
    /// completed). `None` when no ledger entry carries the deployment id at
    /// all. Scans every target's ledger (the deployment id does not name its
    /// target; the entry's own intent does).
    pub fn latest_status(&self, id: &str) -> Result<Option<DeploymentStatus>> {
        let targets_dir = self.base.join("targets");
        if !path_state(&targets_dir)? {
            return Ok(None);
        }
        for dir in std::fs::read_dir(&targets_dir)
            .map_err(|e| Error::store(format!("read_dir targets: {e}")))?
        {
            let dir = dir.map_err(|e| Error::store(format!("target entry: {e}")))?;
            let name = dir.file_name().to_string_lossy().into_owned();
            if !dir.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            for e in self.read_ledger(&name)? {
                if e.deployment_id.as_str() == id {
                    return Ok(e
                        .terminal
                        .map(|t| t.status)
                        .or(Some(DeploymentStatus::PendingCommit)));
                }
            }
        }
        Ok(None)
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

    /// Write the recorded deployment plan (`deployments/<id>/plan.json`). The
    /// plan is the deployment's immutable plan artifact (deployment IDs are
    /// unique, so a conflicting same-ID rewrite is corruption and must fail
    /// rather than silently rewrite history). The outcomes and status of a
    /// deployment live in the LEDGER's terminal event, not here — this file
    /// is purely the plan snapshot the deployment was planned from (the
    /// checkpoint sweep deletes unreachable `deployments/<id>/` dirs).
    pub fn write_plan<T: Serialize>(&self, id: &str, plan: &T) -> Result<()> {
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        let bytes = serde_json::to_vec_pretty(plan)
            .map_err(|e| Error::store(format!("serialize plan: {e}")))?;
        write_atomic_cas(&dir.join("plan.json"), &bytes)
    }
}

impl LocalStore {
    /// The ledger APPEND's durability protocol: atomically rewrite the WHOLE
    /// ledger (read-modify-write) through the same four-stage sequence as
    /// [`crate::store::atomic::write_atomic_replace`] — a UNIQUE temp file in
    /// the same directory, chmod-private BEFORE it can become visible, temp
    /// fsync, atomic rename (a reader sees wholly OLD or wholly NEW, never a
    /// torn line), then a FAIL-CLOSED parent-directory fsync (the durability
    /// commit point: the new ledger must survive power loss before the append
    /// reports success).
    ///
    /// The stages are materialized here — rather than a single
    /// `write_atomic_replace` call — so the per-fixture test registry can
    /// fault each one ([`FaultKind::AppendWrite`] / [`FaultKind::AppendSync`]
    /// / [`FaultKind::AppendRename`] / [`FaultKind::AppendDirSync`]), keyed
    /// by the deployment id being appended. The first three fault stages
    /// abort BEFORE the rename: the visible ledger is wholly OLD (a leftover
    /// dot-prefixed temp is invisible to every read). The dir-sync fault
    /// fires AFTER the rename: the ledger is wholly NEW — only the directory
    /// entry is unsynced — and the append returns `Err` (the same
    /// post-commit window the checkpoint's [`FaultKind::LedgerReplaceAfter`]
    /// models).
    ///
    /// Appends are serialized by the caller's target lock (push and
    /// checkpoint both acquire the application-store lock then the target
    /// lock before any ledger write), so the read-modify-write cannot
    /// interleave with a concurrent rewrite.
    fn append_ledger_atomic(&self, target: &str, _deployment_id: &str, line: &str) -> Result<()> {
        let p = self.ledger_path(target);
        // Read-modify-write: the whole current ledger + the new line.
        let mut buf = String::new();
        if path_state(&p)? {
            buf = std::fs::read_to_string(&p)
                .map_err(|e| Error::store(format!("read ledger: {e}")))?;
            // A legacy in-place append (pre-durability-fix) may have crashed
            // WITHOUT a trailing newline; give that tail its own newline so
            // the new line is never FUSED into it (the pre-existing torn
            // tail still fails closed on read — this append neither drops
            // nor amplifies it).
            if !buf.is_empty() && !buf.ends_with('\n') {
                buf.push('\n');
            }
        }
        buf.push_str(line);
        buf.push('\n');

        // Stage 1: the temp write.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendWrite, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (temp write) forced to fail once",
            ));
        }
        let tmp = temp_name_for(&p);
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
            f.write_all(buf.as_bytes())
                .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
        }
        // Stage 2: the temp fsync.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendSync, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (temp sync) forced to fail once",
            ));
        }
        {
            let f = std::fs::File::open(&tmp)
                .map_err(|e| Error::store(format!("open {}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| Error::store(format!("fsync {}: {e}", tmp.display())))?;
        }
        // Private BEFORE visible: the temp carries 0o600 before the rename.
        set_private(&tmp)?;
        // Stage 3: the atomic rename (the commit point).
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendRename, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (rename) forced to fail once",
            ));
        }
        std::fs::rename(&tmp, &p)
            .map_err(|e| Error::store(format!("rename {}: {e}", p.display())))?;
        // Stage 4: the FAIL-CLOSED parent-directory fsync, AFTER the rename:
        // the new ledger is already visible, but not durable across power
        // loss until its directory entry is synced.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendDirSync, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (parent-dir sync) forced to fail once",
            ));
        }
        sync_parent_dir(&p)?;
        Ok(())
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactRef, GenerationId, GenerationRef, PlacementSlotAssignment, PlacementSlotId,
        ReleaseId, TargetName, VariantName,
    };
    use crate::records::{
        LedgerIntent, LedgerLine, LedgerRollback, LedgerTerminal, ServerOutcomeKind, ServerResult,
    };
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    fn intent(id: &str, target: &str) -> LedgerIntent {
        LedgerIntent {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            group: None,
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    fn successful_terminal(id: &str, target: &str) -> LedgerTerminal {
        LedgerTerminal {
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            status: DeploymentStatus::Successful,
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                ServerResult {
                    slot_id: PlacementSlotId::new("p1".to_string()),
                    outcome: ServerOutcomeKind::Activated,
                    generation: Some(GenerationId::new("gen-1".to_string())),
                    compensated: false,
                    error: None,
                },
            )]),
            rollback: Some(LedgerRollback {
                slots: BTreeMap::from([(
                    PlacementSlotId::new("p1".to_string()),
                    GenerationRef {
                        generation: GenerationId::new("gen-1".to_string()),
                        assignment: PlacementSlotAssignment {
                            placement_slot: PlacementSlotId::new("p1".to_string()),
                            artifact: ArtifactRef {
                                release: ReleaseId::new("rel-sha256-a".to_string()),
                                variant: VariantName::new("standard".to_string()),
                                tree: TreeDigest::new("t1".to_string()),
                            },
                        },
                    },
                )]),
                bindings: BTreeMap::from([(
                    PlacementSlotId::new("p1".to_string()),
                    crate::records::PhysicalBinding {
                        server: crate::model::ServerId::new("s1".to_string()),
                        deploy_dir: "/srv/deploy/p1".to_string(),
                    },
                )]),
            }),
            reason: None,
        }
    }

    fn seed_successful(store: &LocalStore, target: &str, id: &str) {
        store.append_intent(target, &intent(id, target)).unwrap();
        store
            .append_terminal(target, &successful_terminal(id, target))
            .unwrap();
    }

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

    /// The ledger round-trips: intent + terminal merge into ONE entry per
    /// deployment id, in append order, with the terminal carrying status,
    /// outcomes, and the rollback state. A terminal without its intent, a
    /// duplicate intent, or a duplicate terminal FAILS CLOSED (integrity).
    #[test]
    fn ledger_merges_intent_and_terminal_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        seed_successful(&store, target, "deploy-a");
        seed_successful(&store, target, "deploy-b");
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 2, "one merged entry per deployment");
        assert_eq!(entries[0].deployment_id.as_str(), "deploy-a");
        assert_eq!(entries[1].deployment_id.as_str(), "deploy-b");
        assert!(entries[0].terminal.is_some());
        assert_eq!(
            entries[0].terminal.as_ref().unwrap().status,
            DeploymentStatus::Successful
        );
        assert_eq!(
            entries[0].terminal.as_ref().unwrap().outcomes[&PlacementSlotId::new("p1")].outcome,
            ServerOutcomeKind::Activated
        );
        assert_eq!(
            entries[0]
                .terminal
                .as_ref()
                .unwrap()
                .rollback
                .as_ref()
                .unwrap()
                .slots[&PlacementSlotId::new("p1")]
                .assignment
                .artifact
                .release
                .as_str(),
            "rel-sha256-a"
        );
        // A terminal without its intent is refused (fail closed).
        let err = store
            .append_terminal(target, &successful_terminal("deploy-ghost", target))
            .unwrap_err();
        assert!(err.to_string().contains("no ledger intent"));
        // A duplicate intent is refused (the deployment id keys the entry).
        let err = store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("second intent"));
        // A duplicate terminal is refused.
        let err = store
            .append_terminal(target, &successful_terminal("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("already carries a terminal"));
    }

    /// The duplicate-intent guard scans EVERY ledger entry, not just the
    /// first one: a second intent whose deployment id duplicates the FIRST,
    /// a MIDDLE, or the LAST entry is refused (the deployment id keys the
    /// ledger), while a genuinely NEW id still appends fine.
    #[test]
    fn append_intent_duplicate_guard_scans_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        seed_successful(&store, target, "deploy-first");
        seed_successful(&store, target, "deploy-mid");
        seed_successful(&store, target, "deploy-last");
        for id in ["deploy-first", "deploy-mid", "deploy-last"] {
            let err = store
                .append_intent(target, &intent(id, target))
                .unwrap_err();
            assert!(
                err.to_string().contains("second intent"),
                "a duplicate of the {id} entry must be refused at any position, got: {err}"
            );
        }
        // A NEW unique id still appends fine (the guard rejects only
        // duplicates, never over-rejects).
        seed_successful(&store, target, "deploy-new");
        assert_eq!(
            store.read_ledger(target).unwrap().len(),
            4,
            "a fresh id appends as a fourth entry"
        );
    }

    /// A foreign `deployment_schema_version` on an intent line fails closed
    /// (only `SCHEMA_VERSION` is accepted), and a malformed line is a store
    /// error, never a silent drop.
    #[test]
    fn ledger_accepts_only_schema_version_and_rejects_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let mut foreign = intent("deploy-x", target);
        foreign.deployment_schema_version = SCHEMA_VERSION + 1;
        let line = serde_json::to_string(&LedgerLine::Intent(foreign)).unwrap();
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "a foreign schema version must fail closed, got: {err}"
        );
        // Malformed bytes are a store error, never silently dropped.
        std::fs::write(&p, "{ not json !\n").unwrap();
        assert!(store.read_ledger(target).is_err());
    }

    /// `latest_status` derives from the ledger: the terminal's status for a
    /// settled entry, `PendingCommit` for an intent-only (recoverable) entry,
    /// and `None` for an unknown deployment.
    #[test]
    fn latest_status_derives_from_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-pending", target))
            .unwrap();
        seed_successful(&store, target, "deploy-ok");
        store
            .append_intent(target, &intent("deploy-deg", target))
            .unwrap();
        store
            .append_terminal(
                target,
                &LedgerTerminal {
                    deployment_id: DeploymentId::new("deploy-deg".to_string()),
                    target: TargetName::new(target.to_string()),
                    status: DeploymentStatus::Degraded,
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    outcomes: BTreeMap::new(),
                    rollback: None,
                    reason: Some("boom".to_string()),
                },
            )
            .unwrap();
        assert_eq!(
            store.latest_status("deploy-pending").unwrap(),
            Some(DeploymentStatus::PendingCommit),
            "an intent-only entry is the recoverable pending state"
        );
        assert_eq!(
            store.latest_status("deploy-ok").unwrap(),
            Some(DeploymentStatus::Successful)
        );
        assert_eq!(
            store.latest_status("deploy-deg").unwrap(),
            Some(DeploymentStatus::Degraded)
        );
        assert_eq!(store.latest_status("deploy-nope").unwrap(), None);
    }

    /// `read_last_successful` is DERIVED from the ledger (the newest
    /// `Successful` terminal) — no separate ref file exists anymore.
    #[test]
    fn last_successful_is_derived() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        assert_eq!(store.read_last_successful(target), None);
        seed_successful(&store, target, "deploy-a");
        seed_successful(&store, target, "deploy-b");
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some("deploy-b"),
            "the newest successful entry is the derived last-successful"
        );
        // A later failed deployment does not move the pointer.
        store
            .append_intent(target, &intent("deploy-fail", target))
            .unwrap();
        store
            .append_terminal(
                target,
                &LedgerTerminal {
                    deployment_id: DeploymentId::new("deploy-fail".to_string()),
                    target: TargetName::new(target.to_string()),
                    status: DeploymentStatus::FailedRolledBack,
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    outcomes: BTreeMap::new(),
                    rollback: None,
                    reason: None,
                },
            )
            .unwrap();
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some("deploy-b")
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
        let variants: BTreeMap<crate::model::VariantName, TreeDigest> = BTreeMap::from([(
            crate::model::VariantName::new("standard"),
            TreeDigest::new("t1"),
        )]);
        let slots: BTreeMap<String, Vec<crate::config::SlotDef>> = BTreeMap::from([(
            "standard".to_string(),
            vec![crate::config::SlotDef {
                id: "p1".to_string(),
                server: "s1".to_string(),
                deploy_dir: std::path::PathBuf::from("/srv/deploy/p1"),
                target: "t1".to_string(),
                groups: Vec::new(),
            }],
        )]);
        let rec =
            crate::release::build_release("m", &sha, &variants, &slots, std::path::Path::new("."));
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

    /// `read_release` recomputes the canonical digest from the record's own
    /// content and verifies it against the stored identity fields: a pristine
    /// record reads fine, while an edited slot declaration fails closed.
    #[test]
    fn read_release_recomputes_and_verifies_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let (id, _c, _sha) = write_behavior_fixture(&store);
        let read = store.read_release(&id).unwrap();
        assert_eq!(read.release_id, id.as_str());
        let mut tampered = read.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        let path = store.release_dir(&id).join("release.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
        let err = store
            .read_release(&id)
            .expect_err("tampered record must fail verification");
        assert!(err.to_string().contains("identity mismatch"), "got: {err}");
    }

    /// A recorded plan is immutable: deployment IDs are unique, so a
    /// same-ID rewrite with different content is corruption.
    #[test]
    fn recorded_plan_is_immutable() {
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
    }

    /// One-shot faults are status-qualified and consumed exactly once (the
    /// terminal append fault fires on the matching deployment id only).
    #[test]
    fn append_terminal_fault_is_one_shot_and_id_qualified() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap();
        store
            .append_intent(target, &intent("deploy-b", target))
            .unwrap();
        store.fault_registry().arm_append_terminal("deploy-a");
        // The fault fires exactly once on the matching id...
        store
            .append_terminal(target, &successful_terminal("deploy-a", target))
            .expect_err("the armed terminal fault fires");
        // ...before any append (the entry is still intent-only) and is then
        // disarmed: the retry succeeds.
        store
            .append_terminal(target, &successful_terminal("deploy-a", target))
            .expect("the disarmed retry appends the terminal");
        // A second terminal for the SAME deployment is refused (exactly-once).
        store
            .append_terminal(target, &successful_terminal("deploy-a", target))
            .expect_err("a second terminal is refused (exactly-once contract)");
        // A different deployment is never faulted.
        store
            .append_terminal(target, &successful_terminal("deploy-b", target))
            .expect("a different deployment's terminal passes");
    }

    /// Two fixtures' fault registries are structurally isolated: an arm on
    /// one store can never be consumed by another store.
    #[test]
    fn arming_one_fixture_cannot_be_consumed_by_another_fixtures_store() {
        let dir = tempfile::tempdir().unwrap();
        let s1 = LocalStore::with_base(dir.path().join("s1")).unwrap();
        let s2 = LocalStore::with_base(dir.path().join("s2")).unwrap();
        s1.fault_registry().arm_append_terminal("deploy-a");
        s2.fault_registry().arm_append_terminal("deploy-b");
        for t in ["t1", "t2"] {
            for s in [&s1, &s2] {
                s.append_intent(t, &intent("deploy-a", t)).unwrap();
                s.append_intent(t, &intent("deploy-b", t)).unwrap();
            }
        }
        // The s1 arm fires on s1's deploy-a terminal...
        s1.append_terminal("t1", &successful_terminal("deploy-a", "t1"))
            .expect_err("s1's own arm fires");
        // ...and never leaks into s2 (its deploy-b arm is untouched).
        s2.append_terminal("t1", &successful_terminal("deploy-b", "t1"))
            .expect_err("s2's own arm fires");
    }

    // ---------------------------------------------------------------------
    // Ledger append durability (crash-atomic whole-ledger rewrite)
    // ---------------------------------------------------------------------

    /// A fault at ANY of the four atomic-append stages leaves the visible
    /// ledger wholly OLD (pre-append) or wholly NEW (post-append): the
    /// atomic rename means no crash window can ever leave a torn partial
    /// line. The pre-rename stages ([`FaultKind::AppendWrite`] /
    /// [`FaultKind::AppendSync`] / [`FaultKind::AppendRename`]) abort
    /// BEFORE the rename: wholly OLD. The [`FaultKind::AppendDirSync`] fault
    /// fires AFTER the rename: the ledger is wholly NEW (only the directory
    /// entry is unsynced) and the append returns `Err`.
    #[test]
    fn ledger_append_faults_leave_wholly_old_or_wholly_new() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap();
        store
            .append_terminal(target, &successful_terminal("deploy-a", target))
            .unwrap();
        for (i, (stage, kind, landed)) in [
            ("temp write", FaultKind::AppendWrite, false),
            ("temp sync", FaultKind::AppendSync, false),
            ("rename", FaultKind::AppendRename, false),
            ("dir sync", FaultKind::AppendDirSync, true),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("deploy-fault-{i}");
            store.append_intent(target, &intent(&id, target)).unwrap();
            let before = store.read_ledger_lines(target).unwrap();
            store.fault_registry().arm(kind, &id);
            let err = store
                .append_terminal(target, &successful_terminal(&id, target))
                .expect_err("the armed stage fault fires");
            assert!(
                err.to_string().contains("test fault"),
                "the fault must fail the append, got: {err}"
            );
            let after = store.read_ledger_lines(target).unwrap();
            if landed {
                assert_eq!(
                    after.len(),
                    before.len() + 1,
                    "{stage}: the dir-sync fault leaves the wholly NEW ledger (the rename landed)"
                );
                assert_eq!(
                    after[..before.len()],
                    before,
                    "{stage}: the wholly-new ledger extends the old content in order"
                );
                assert_eq!(
                    after.last().unwrap(),
                    &serde_json::to_string(&LedgerLine::Terminal(successful_terminal(&id, target)))
                        .unwrap(),
                    "{stage}: the wholly-new ledger's last line is the appended terminal"
                );
            } else {
                assert_eq!(
                    after, before,
                    "{stage}: a pre-rename fault leaves the wholly OLD ledger"
                );
            }
            // Every line of the visible ledger parses (never torn).
            store.read_ledger(target).unwrap();
        }
    }

    /// The append-intent guard FAILS CLOSED on a crafted torn trailing line
    /// (a crash from the OLD in-place append protocol): `read_ledger` — the
    /// guard's source of truth — refuses the malformed ledger, so the
    /// append returns the parse error and the file bytes stay EXACTLY the
    /// crafted torn tail: never fused, never appended over, never mutated.
    #[test]
    fn append_guard_fails_closed_on_a_crafted_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        // A crafted torn trailing line — exactly what the old in-place
        // append could leave behind after a crash mid-write.
        let torn = r#"{"kind":"intent","deployment_id":"deploy-torn""#;
        std::fs::write(&p, torn).unwrap();
        // The append fails closed at the guard (the ledger does not parse)
        // and the file bytes are untouched — the corruption is surfaced,
        // never silently fused or amplified.
        let err = store
            .append_intent(target, &intent("deploy-fresh", target))
            .unwrap_err();
        assert!(
            err.to_string().contains("parse ledger line"),
            "the guard must propagate the parse failure, got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            torn,
            "a refused append must leave the crafted torn ledger byte-identical"
        );
    }

    /// A SUCCESSFUL ledger append is durable: after appends (including an
    /// append that FAILED at the dir-sync stage — the rename already landed
    /// — and one that failed at a pre-rename stage), a FRESH store over the
    /// same base reads exactly the committed lines: every append that
    /// returned `Ok` is visible, in order, and no torn line exists.
    #[test]
    fn successful_ledger_appends_are_visible_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap();
        store
            .append_terminal(target, &successful_terminal("deploy-a", target))
            .unwrap();
        store
            .append_intent(target, &intent("deploy-b", target))
            .unwrap();
        // A pre-rename fault: the intent of deploy-c never lands.
        store.fault_registry().arm_append_rename("deploy-c");
        store
            .append_intent(target, &intent("deploy-c", target))
            .expect_err("the armed rename fault aborts before the rename");
        // The dir-sync fault on deploy-d's terminal: the rename DOES land
        // (the ledger is wholly new) though the append returns `Err`.
        store
            .append_intent(target, &intent("deploy-d", target))
            .unwrap();
        store.fault_registry().arm_append_dir_sync("deploy-d");
        store
            .append_terminal(target, &successful_terminal("deploy-d", target))
            .expect_err("the armed dir-sync fault still leaves the ledger wholly new");
        drop(store);
        let reopened = LocalStore::with_base(base).unwrap();
        let visible = reopened.read_ledger_lines(target).unwrap();
        assert_eq!(visible.len(), 5);
        assert_eq!(
            visible[0],
            serde_json::to_string(&LedgerLine::Intent(intent("deploy-a", target))).unwrap()
        );
        assert_eq!(
            visible[1],
            serde_json::to_string(&LedgerLine::Terminal(successful_terminal(
                "deploy-a", target
            )))
            .unwrap()
        );
        assert_eq!(
            visible[2],
            serde_json::to_string(&LedgerLine::Intent(intent("deploy-b", target))).unwrap()
        );
        assert_eq!(
            visible[3],
            serde_json::to_string(&LedgerLine::Intent(intent("deploy-d", target))).unwrap()
        );
        assert_eq!(
            visible[4],
            serde_json::to_string(&LedgerLine::Terminal(successful_terminal(
                "deploy-d", target
            )))
            .unwrap()
        );
        // Every line parses and merges into consistent entries.
        let entries = reopened.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(
            entries
                .iter()
                .any(|e| e.deployment_id.as_str() == "deploy-a" && e.terminal.is_some())
        );
        assert!(
            entries
                .iter()
                .any(|e| e.deployment_id.as_str() == "deploy-b" && e.terminal.is_none())
        );
        assert!(
            entries
                .iter()
                .any(|e| e.deployment_id.as_str() == "deploy-d" && e.terminal.is_some())
        );
    }

    // ---- the reopen durability property -------------------------------

    /// One generated ledger-history operation: the INTENT of a fresh
    /// deployment (`Intent`), the terminal of the OLDEST still-open
    /// deployment (`CloseOldest`), or the NEWEST (`CloseNewest`). The paired
    /// [`AppendStage`] selects the single atomic-append stage fault armed for
    /// that operation (`None` = no fault).
    #[derive(Clone, Copy, Debug)]
    enum LedgerOp {
        Intent,
        CloseOldest,
        CloseNewest,
    }

    /// The four atomic-append rewrite stages a fault can be injected at.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AppendStage {
        Write,
        Sync,
        Rename,
        DirSync,
    }

    fn ledger_history_strategy() -> impl Strategy<Value = Vec<(LedgerOp, Option<AppendStage>)>> {
        prop::collection::vec(
            (
                prop::sample::select(vec![
                    LedgerOp::Intent,
                    LedgerOp::CloseOldest,
                    LedgerOp::CloseNewest,
                ]),
                prop::sample::select(vec![
                    None,
                    Some(AppendStage::Write),
                    Some(AppendStage::Sync),
                    Some(AppendStage::Rename),
                    Some(AppendStage::DirSync),
                ]),
            ),
            0..=8,
        )
    }

    /// Arm the generated stage fault on the fixture's per-fixture registry,
    /// keyed by the deployment id of the append under test.
    fn arm_append_stage(store: &LocalStore, stage: AppendStage, id: &str) {
        match stage {
            AppendStage::Write => store.fault_registry().arm_append_write(id),
            AppendStage::Sync => store.fault_registry().arm_append_sync(id),
            AppendStage::Rename => store.fault_registry().arm_append_rename(id),
            AppendStage::DirSync => store.fault_registry().arm_append_dir_sync(id),
        }
    }

    /// Replay one generated history against a FRESH fixture, then REOPEN
    /// with a fresh store over the same base and assert the durability
    /// contract:
    ///
    /// * the reopened ledger is EXACTLY the lines of the appends whose
    ///   atomic rename LANDED, in order — a whole file of whole lines: no
    ///   append can leave a torn/partial line, every line parses, and the
    ///   intent/terminal structure is consistent;
    /// * a SUCCESSFUL append (one that returned `Ok`) is ALWAYS present
    ///   after the reopen, regardless of what failed afterward.
    ///
    /// Each operation arms ONE stage fault (keyed by the deployment id)
    /// when its generated spec says so. The fault fires once at that stage:
    /// `Write`/`Sync`/`Rename` abort before the rename (wholly OLD);
    /// [`AppendStage::DirSync`] fires after the rename (wholly NEW — the
    /// error returns but the new ledger is already durable).
    fn run_ledger_durability_history(history: &[(LedgerOp, Option<AppendStage>)]) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap();
        let target = "t1";
        // The committed model: the ledger lines whose append's rename
        // landed, in order; the still-open (intent-only) deployment ids; and
        // every append that returned `Ok` (the visibility contract).
        let mut committed: Vec<String> = Vec::new();
        let mut open: Vec<String> = Vec::new();
        let mut ok_appends: Vec<(String, bool)> = Vec::new();
        let mut seq = 0u64;
        for (op, stage) in history {
            match op {
                LedgerOp::Intent => {
                    let id = format!("dep-{seq}");
                    seq += 1;
                    let intent = intent(&id, target);
                    let line = serde_json::to_string(&LedgerLine::Intent(intent.clone())).unwrap();
                    if let Some(stage) = stage {
                        arm_append_stage(&store, *stage, &id);
                    }
                    match store.append_intent(target, &intent) {
                        Ok(()) => {
                            committed.push(line);
                            open.push(id.clone());
                            ok_appends.push((id, true));
                        }
                        Err(e) if e.to_string().contains("test fault") => {
                            // The faulted append: committed ONLY when the
                            // rename already landed (the dir-sync stage).
                            if matches!(stage, Some(AppendStage::DirSync)) {
                                committed.push(line);
                                open.push(id);
                            }
                        }
                        Err(e) => panic!("unexpected append_intent error for {id}: {e}"),
                    }
                }
                LedgerOp::CloseOldest | LedgerOp::CloseNewest => {
                    let Some(id) = (if matches!(op, LedgerOp::CloseOldest) {
                        open.first()
                    } else {
                        open.last()
                    })
                    .cloned() else {
                        continue; // nothing open: the op is a valid no-op
                    };
                    let terminal = successful_terminal(&id, target);
                    let line =
                        serde_json::to_string(&LedgerLine::Terminal(terminal.clone())).unwrap();
                    if let Some(stage) = stage {
                        arm_append_stage(&store, *stage, &id);
                    }
                    match store.append_terminal(target, &terminal) {
                        Ok(()) => {
                            committed.push(line);
                            open.retain(|o| o != &id);
                            ok_appends.push((id, false));
                        }
                        Err(e) if e.to_string().contains("test fault") => {
                            if matches!(stage, Some(AppendStage::DirSync)) {
                                committed.push(line);
                                open.retain(|o| o != &id);
                            }
                        }
                        Err(e) => panic!("unexpected append_terminal error for {id}: {e}"),
                    }
                }
            }
        }
        // After REOPENING, the ledger is the wholly-written committed model:
        // never a torn line, and the successful appends are all visible.
        drop(store);
        let reopened = LocalStore::with_base(base).unwrap();
        assert_eq!(
            reopened.read_ledger_lines(target).unwrap(),
            committed,
            "the reopened ledger is exactly the committed lines in order — every append is whole or absent, never torn"
        );
        let entries = reopened.read_ledger(target).unwrap();
        for (id, is_intent) in &ok_appends {
            let entry = entries
                .iter()
                .find(|e| e.deployment_id.as_str() == id)
                .unwrap_or_else(|| panic!("a successful append for {id} is missing after reopen"));
            if !is_intent {
                assert!(
                    entry.terminal.is_some(),
                    "a successful terminal append for {id} is visible after reopen"
                );
            }
        }
    }

    proptest! {
        // The main property: ORDINARY RANDOMIZED SEEDS with failure
        // persistence (proptest's defaults) — a failing vector writes to
        // `proptest-regressions/local.txt` and is replayed on the next run
        // (commit it so CI keeps reproducing the regression until fixed).
        // The case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION: the deterministic floor for CI. The same
        // generator under the pinned 0x5EED_5EED seed with no persistence
        // runs the IDENTICAL vectors on every invocation, so the suite stays
        // reproducible even when no failure has ever been persisted by the
        // main test. The case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_fixed_seed_regression(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    // ---- the duplicate-intent guard property ---------------------------

    /// Generate a NONEMPTY deployment sequence of UNIQUE ids (`dep-0` ..
    /// `dep-{N-1}`, the ledger's N intents) together with a position in
    /// `0..=N`: an IN-ledger position (`0` = first, middles, `N-1` = last)
    /// or the position JUST BEYOND the last entry (`N`). The ids are unique
    /// by construction (derived from distinct indices).
    fn unique_ledger_strategy() -> impl Strategy<Value = (Vec<String>, usize)> {
        (1usize..=4, 0usize..=4)
            .prop_map(|(n, pos)| ((0..n).map(|i| format!("dep-{i}")).collect(), pos.min(n)))
    }

    proptest! {
        // FIXED-SEED REGRESSION for the duplicate guard: the guard must
        // scan EVERY parsed ledger entry, so re-appending the id of ANY
        // in-ledger position (first, middle, last) is refused and the ledger
        // file BYTES are EXACTLY unchanged (no torn/partial append, no
        // mutation). The id JUST BEYOND the last entry — a genuinely fresh
        // id — still appends one whole line; appending it AGAIN is then a
        // duplicate and is refused with bytes unchanged. The pinned
        // 0x5EED_5EED seed with no persistence runs the IDENTICAL vectors on
        // every invocation; the case count is bounded so the suite stays
        // fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn duplicate_intent_scan_leaves_ledger_bytes_unchanged(ledger in unique_ledger_strategy()) {
            let (ids, pos) = ledger;
            let dir = tempfile::tempdir().unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let target = "t1";
            for id in &ids {
                store.append_intent(target, &intent(id, target)).unwrap();
            }
            let p = store.ledger_path(target);
            let before = std::fs::read(&p).unwrap();
            if pos == ids.len() {
                // The position JUST BEYOND the last entry: the fresh id is
                // not in the ledger, so the first append SUCCEEDS — one
                // whole line appended after the existing newline-terminated
                // content (atomic, never torn) — proving the every-entry
                // scan does not over-reject a new id.
                let fresh = format!("dep-{}", ids.len());
                let line =
                    serde_json::to_string(&LedgerLine::Intent(intent(&fresh, target))).unwrap();
                store.append_intent(target, &intent(&fresh, target)).unwrap();
                let mut after = before.clone();
                after.extend_from_slice(format!("{line}\n").as_bytes());
                assert_eq!(
                    std::fs::read(&p).unwrap(),
                    after,
                    "a fresh id appends exactly one whole line, never torn"
                );
                // Appending the fresh id AGAIN is now a duplicate at the NEW
                // last position: refused, bytes unchanged.
                let err = store
                    .append_intent(target, &intent(&fresh, target))
                    .unwrap_err();
                assert!(err.to_string().contains("second intent"));
                assert_eq!(std::fs::read(&p).unwrap(), after);
            } else {
                // An IN-ledger position (first, any middle, last): the id is
                // a duplicate — the append must FAIL and leave the ledger
                // bytes IDENTICAL (no torn/partial append, no mutation).
                let err = store
                    .append_intent(target, &intent(&ids[pos], target))
                    .unwrap_err();
                assert!(err.to_string().contains("second intent"));
                assert_eq!(
                    std::fs::read(&p).unwrap(),
                    before,
                    "a refused duplicate must leave the ledger bytes untouched"
                );
            }
        }
    }
}

//! Filesystem-backed local store.
//!
//! Record contract: ONE ordered deployment ledger per target
//! (`targets/<target>/ledger.jsonl`, append-only JSON lines). An entry starts
//! as the DURABLE INTENT ([`crate::records::DeploymentIntent`], appended BEFORE
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
//!   targets/<target>/observed.json, retention-debt.json, ledger.jsonl
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
    BehaviorContract, DeploymentId, LEDGER_SCHEMA_VERSION, ReleaseId, ReleaseRecord, SlotId,
    TREE_SCHEMA_VERSION, TreeDigest, TreeMetadata,
};
use crate::records::{
    DeploymentIntent, DeploymentStatus, LedgerEntry, LedgerIntentWire, LedgerLine, LedgerTerminal,
    LedgerTerminalWire, ObservedSlot, ObservedTarget, Pins, ServerState,
};
use crate::scalar::ApplicationStoreKey;
use crate::store::atomic::{
    copy_dir_recursive, ensure_private_dir, ensure_private_dir_durable, path_state, read_json,
    set_private, sync_parent_dir, temp_name_for, write_atomic_replace,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::testutil::step17_hook::Step17Hook;
#[cfg(test)]
use crate::testutil::test_faults::{FaultKind, FaultRegistry};
#[cfg(test)]
use std::sync::Arc;

pub(crate) fn default_base() -> PathBuf {
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
    /// Create a store rooted at `<data>/simple-deploy/<key>` with private
    /// permissions, creating the directory tree if needed. The application
    /// STORE KEY is the ONLY way in: the key is a validated single safe
    /// path segment ([`crate::scalar::ApplicationStoreKey`]), so the store
    /// path is `default_base().join(key)` — exactly ONE component appended
    /// — and an application name can never escape the store base.
    pub fn new(application: &ApplicationStoreKey) -> Result<LocalStore> {
        let base = default_base().join(application.as_str());
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
    /// step-17-equivalent lock acquisition (the per-slot retention block and
    /// the deferred-maintenance retry that shares it), tagged with the
    /// [`HookPhase`] being entered so the test can tell the fresh step-17
    /// retention from the deferred-maintenance retry. A no-op in unarmed
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

    /// DURABLE creation of a target's directory on the LEDGER-APPEND path
    /// (the reported durability bug: the FIRST `append_intent` for a new
    /// target created `targets/<target>/` — and the store open's `targets/` —
    /// WITHOUT syncing their directory entries, so a power loss right after a
    /// reported-successful first append could lose the new directories
    /// entirely). The pure creation + syncs live in
    /// [`ensure_private_dir_durable`](crate::store::atomic::ensure_private_dir_durable):
    /// every component this call created gets a parent-directory fsync — at
    /// minimum `targets/` (the new target dir's entry) and the store base
    /// (the `targets/` entry) — before the ledger write below. The helper's
    /// created flag feeds the test-only fault surface below: the per-target
    /// dir-sync boundaries fire ONLY on the creation path (an EXISTING
    /// target's append creates and syncs nothing, so the arms never fire
    /// there).
    ///
    /// The engine and checkpoint ALSO call this BEFORE acquiring the target
    /// lock ([`crate::push::engine::push`], [`crate::push::checkpoint`]): the
    /// lock file lives INSIDE the target dir, so the lock path used to create
    /// it with a plain unsynced mkdir that bypassed this helper — the
    /// lock-path pre-creation makes the directory durable BEFORE the lock is
    /// taken (the lock's own parent creation then no-ops), and the append's
    /// later call finds it existing. The [`FaultKind::LockMkdir`] arm below
    /// models a crash at that lock-path mkdir step: it fires BEFORE the
    /// helper runs, leaving the prior state with NO target directory.
    pub(crate) fn ensure_target_dir_durable(&self, target: &str) -> Result<()> {
        // Test-only: the LOCK-PATH dir-creation boundary (the durable
        // pre-creation the engine/checkpoint run before the target lock) —
        // fires BEFORE the durable helper creates anything, modeling a crash
        // at the mkdir step: recovery finds the PRIOR STATE with no target
        // directory (a first target) and no ledger.
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::LockMkdir, target) {
            return Err(Error::store(
                "test fault: the lock-path target-dir creation forced to fail once",
            ));
        }
        let created = ensure_private_dir_durable(&self.target_dir(target))?;
        // Test-only: the two dir-sync boundaries of a FIRST append, keyed by
        // target. They fire after the durable helper returned (the directory
        // entries ARE created and synced — the modeled loss is the boundary
        // between the dir syncs and the ledger write: the append reports `Err`
        // and crash recovery finds the PRIOR STATE, never a reported success
        // with the target directory missing).
        #[cfg(test)]
        if created
            && self
                .fault_registry
                .consume(FaultKind::SyncNewTargetDir, target)
        {
            return Err(Error::store(
                "test fault: the new target dir's entry sync forced to fail once",
            ));
        }
        #[cfg(test)]
        if created
            && self
                .fault_registry
                .consume(FaultKind::SyncTargetsDir, target)
        {
            return Err(Error::store(
                "test fault: the targets dir's entry sync forced to fail once",
            ));
        }
        #[cfg(not(test))]
        let _ = created;
        Ok(())
    }

    // ---- slots: the ONE physical observed state ---------------------------

    /// Path of a placement slot's single physical observed record
    /// (`slots/<slot-id>/observed.json`). Observed state is stored EXACTLY
    /// ONCE per placement slot — never replicated per target: targets are
    /// selection views over the global slot map (see
    /// [`LocalStore::read_observed`]).
    pub fn slot_observed_path(&self, slot: &SlotId) -> PathBuf {
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
    pub fn write_slot_observed(&self, slot: &SlotId, observed: &ObservedSlot) -> Result<()> {
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
    pub fn read_slot_observed(&self, slot: &SlotId) -> Result<Option<ObservedSlot>> {
        let p = self.slot_observed_path(slot);
        if path_state(&p)? {
            read_json(&p).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The GLOBAL physical slot map: every placement slot's single observed
    /// record (`slots/<slot-id>/observed.json`), keyed by [`SlotId`].
    /// This is the ONE physical state the per-target views are filtered
    /// from — a shared slot exists here exactly once.
    pub fn read_global_observed(&self) -> Result<BTreeMap<SlotId, ObservedSlot>> {
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
            let observed: ObservedSlot = read_json(&rec)?;
            out.insert(
                SlotId::new(entry.file_name().to_string_lossy().into_owned()),
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
        config: &crate::config::ProjectConfig,
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

    // ---- retention maintenance debt ---------------------------------------

    /// Path of the target's deferred-retention debt marker file.
    ///
    /// Retention is POST-COMMIT maintenance: a retention failure after the
    /// deployment already committed must not change the reported outcome.
    /// Instead the failure is recorded here — keyed by target (the file's
    /// location under `targets/<target>/`) and by placement slot (the map
    /// key) — so later pushes retry the maintenance and clear the marker
    /// once the retention succeeds. The marker is intentionally a separate,
    /// small record: it does not ride along in `observed.json` (which
    /// describes the deployed state, not pending controller work) and it
    /// survives across pushes.
    pub fn retention_debt_path(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("retention-debt.json")
    }

    /// Read the target's deferred-retention markers: a map of placement slot
    /// id to the reason the retention was deferred. Empty when no maintenance
    /// is pending.
    pub fn read_retention_debt(&self, target: &str) -> Result<BTreeMap<String, String>> {
        // Post-commit maintenance fault injection, keyed by target (the debt
        // file lives under `targets/<target>/`). Absorbs the debt-I/O
        // sibling agent's `arm_read_retention_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::ReadRetentionDebt, target)
        {
            return Err(Error::store(
                "test fault: read_retention_debt forced to fail once",
            ));
        }
        let p = self.retention_debt_path(target);
        // Tri-state: only a genuine NotFound is "no maintenance debt" (the
        // empty map); a stat failure propagates as a Store error (an
        // unreadable debt marker must not read as "no debt").
        if path_state(&p)? {
            read_json(&p)
        } else {
            Ok(BTreeMap::new())
        }
    }

    /// Persist the target's deferred-retention markers. An EMPTY map removes
    /// the marker file, so a fully-serviced target leaves no trace.
    pub fn write_retention_debt(
        &self,
        target: &str,
        debt: &BTreeMap<String, String>,
    ) -> Result<()> {
        // Post-commit maintenance write fault, keyed by target. Absorbs the
        // debt-I/O sibling agent's `arm_write_retention_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::WriteRetentionDebt, target)
        {
            return Err(Error::store(
                "test fault: write_retention_debt forced to fail once",
            ));
        }
        let p = self.retention_debt_path(target);
        if debt.is_empty() {
            // Tri-state removal decision: a genuine NotFound is nothing to
            // remove; any other stat error propagates (an unreadable marker
            // must not silently survive as a stale "debt" record).
            if path_state(&p)? {
                std::fs::remove_file(&p).map_err(|e| {
                    Error::store(format!("remove retention debt {}: {e}", p.display()))
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
    pub fn append_intent(&self, target: &str, intent: &DeploymentIntent) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendAttempt, intent.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_attempt (ledger intent) forced to fail once",
            ));
        }
        self.ensure_target_dir_durable(target)?;
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
        let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(intent)))
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
    /// Append the TERMINAL EVENT of one deployment to the target's ledger
    /// ("`{"kind":"terminal", ...}`" JSON line), after the mutation loop.
    /// The terminal carries the disposition (status), the per-slot outcomes,
    /// and — when successful — the rollback state. Like the intent it is
    /// appended via the crash-atomic whole-ledger rewrite (see
    /// [`LocalStore::append_ledger_atomic`]). Fail-closed key contract: the
    /// deployment's intent must already exist in the ledger (a terminal for
    /// an unknown deployment is corruption) and the entry must not already
    /// have a terminal (the terminal event is written exactly once;
    /// replay-safety is handled by the finalizer checking the entry first).
    ///
    /// LET THE ENCLOSING OBJECT OWN IDENTITY: the DOMAIN [`LedgerTerminal`]
    /// carries no `deployment_id` / `target` — the caller supplies the
    /// deployment id (the wire record keeps the on-disk identity members;
    /// the reader verifies them equal to the enclosing entry's).
    pub fn append_terminal(
        &self,
        target: &str,
        deployment_id: &DeploymentId,
        terminal: &LedgerTerminal,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendTerminal, deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_terminal forced to fail once",
            ));
        }
        self.ensure_target_dir_durable(target)?;
        let entries = self.read_ledger(target)?;
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == *deployment_id)
            .ok_or_else(|| {
                Error::integrity(format!(
                    "append_terminal for deployment '{deployment_id}': no ledger intent exists for it — a terminal event requires its durable intent (a terminal without an intent is corruption)"
                ))
            })?;
        if entry.terminal.is_some() {
            return Err(Error::integrity(format!(
                "append_terminal for deployment '{deployment_id}': the entry already carries a terminal event (a terminal is written exactly once)"
            )));
        }
        let line = serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::from_domain(
            deployment_id,
            &entry.target,
            terminal,
        )))
        .map_err(|e| Error::store(format!("serialize ledger terminal: {e}")))?;
        self.append_ledger_atomic(target, deployment_id.as_str(), &line)
    }

    /// Read the FULL deployment ledger of a target: every merged
    /// [`LedgerEntry`] (intent + optional terminal), in append order. This is
    /// the SINGLE history read — it replaces the old `read_attempts` /
    /// `read_snapshots` pair (and their raw variants): there is no floor to
    /// gate (the checkpoint replaced the ledger with the retained suffix
    /// atomically) and no separate snapshot log. Every parsed wire line is
    /// converted through the VERIFYING CONVERSION
    /// ([`LedgerIntentWire::into_domain`] / [`LedgerTerminalWire::into_domain`])
    /// and the CROSS-RECORD invariants are enforced where the intent and the
    /// terminal merge: a record whose duplicate projections disagree (e.g. a
    /// `desired` key outside the authoritative `slot_ids` membership, a
    /// rollback whose legacy release disagrees with the derived releases, a
    /// Successful terminal without its rollback, an outcome whose value
    /// names a different slot, a rollback whose binding keys are not exactly
    /// its generation keys), or whose cross-record claims disagree (the
    /// terminal's target vs the read path / its intent, the outcome key set
    /// vs the intent's `slot_ids` — BY STATUS: a Successful terminal's
    /// outcomes must EXACTLY equal its membership (the four-set equality:
    /// outcomes == rollback slots == rollback bindings == intent
    /// membership, non-empty), a FailedPreflight terminal must carry NO
    /// outcomes, and every other terminal state's outcomes must EXACTLY
    /// cover the membership), is REFUSED with an integrity
    /// error — a hand-constructed or tampered record is never read as
    /// whichever projection a consumer happens to use. Fail closed on
    /// malformed lines, foreign `deployment_schema_version`, an intent-less
    /// terminal, a duplicate intent, a duplicate terminal, or a disagreeing
    /// record.
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
                LedgerLine::Intent(wire) => {
                    // Fail closed on the record schema version: only
                    // `LEDGER_SCHEMA_VERSION` is accepted, any other version
                    // is refused with an error naming the version (a record
                    // from a different schema is never silently
                    // interpreted).
                    if wire.deployment_schema_version != LEDGER_SCHEMA_VERSION {
                        return Err(Error::store(format!(
                            "intent {} carries unsupported deployment_schema_version {} (expected {LEDGER_SCHEMA_VERSION}): only LEDGER_SCHEMA_VERSION is accepted",
                            wire.deployment_id, wire.deployment_schema_version
                        )));
                    }
                    // VERIFYING CONVERSION (wire → domain): every duplicate
                    // projection (desired/pre_push/slots key sets vs the
                    // authoritative `slot_ids`, each generation assignment's
                    // slot) must agree — a disagreement is refused (fail
                    // closed) rather than read as whichever projection a
                    // consumer happens to use.
                    let intent = wire.into_domain().map_err(|e| {
                        Error::integrity(format!(
                            "ledger for target '{target}' refuses an intent line: {e}"
                        ))
                    })?;
                    // TARGET EQUALITY (cross-record invariant, intent leg):
                    // the intent's own `target` must equal the ledger path it
                    // was read from — a record written into the wrong
                    // target's ledger would otherwise be rendered and swept
                    // under the wrong target's history.
                    if intent.target.as_str() != target {
                        return Err(Error::integrity(format!(
                            "ledger for target '{target}' refuses an intent line: deployment '{}' names target '{}'",
                            intent.deployment_id, intent.target
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
                LedgerLine::Terminal(wire) => {
                    // LET THE ENCLOSING OBJECT OWN IDENTITY: the terminal
                    // wire's `deployment_id` is the ENTRY KEY (the terminal
                    // merges into the entry that carries that id — a
                    // terminal whose id matches no intent is corruption),
                    // and its `target` must EQUAL the entry's target (the
                    // intent's): a terminal claiming a different target than
                    // its own deployment's intent is a disagreement, refused
                    // here against the ENTRY's identity (the domain terminal
                    // itself carries no identity).
                    let id = wire.deployment_id.clone();
                    let pos = index.get(id.as_str()).copied().ok_or_else(|| {
                        Error::integrity(format!(
                            "ledger of target '{target}': a terminal event for deployment '{id}' has no intent line — a terminal event requires its durable intent (a closed-DB corruption)"
                        ))
                    })?;
                    if wire.target != out[pos].target {
                        return Err(Error::integrity(format!(
                            "ledger of target '{target}': terminal {id} claims target '{}' but its entry (intent) is for target '{}' — the enclosing entry owns identity",
                            wire.target, out[pos].target
                        )));
                    }
                    // OUTCOME AGREEMENT (cross-record half): every outcome
                    // key must be a MEMBER of the intent's authoritative
                    // membership — an outcome for a slot outside the
                    // deployment is a disagreement (a slot the deployment
                    // never touched cannot report a result).
                    for key in wire.outcomes.keys().cloned().collect::<Vec<_>>() {
                        if !out[pos].intent.slots.contains_key(&key) {
                            return Err(Error::integrity(format!(
                                "ledger of target '{target}': terminal {id} records an outcome for slot '{key}' outside the intent's membership — every outcome must name a member slot"
                            )));
                        }
                    }
                    // VERIFYING CONVERSION (wire → domain): the rollback
                    // payload's duplicate projections (each generation
                    // assignment's slot, the bindings' slot set, the legacy
                    // snapshot-wide release) must agree, the status must map
                    // to exactly one disposition whose payload matches, and
                    // each outcome's value must name its own key — a
                    // disagreeing record is refused.
                    let terminal = wire.into_domain().map_err(|e| {
                        Error::integrity(format!(
                            "ledger for target '{target}' refuses a terminal line: {e}"
                        ))
                    })?;
                    let entry = &mut out[pos];
                    if entry.terminal.is_some() {
                        return Err(Error::integrity(format!(
                            "ledger of target '{target}': two terminal events for deployment '{id}' — a terminal event is written exactly once"
                        )));
                    }
                    // TARGET EQUALITY (cross-record invariant, terminal
                    // leg): already verified on the WIRE against the ENTRY
                    // above (`wire.target` vs the entry's target) — the DOMAIN
                    // terminal carries no identity (the enclosing entry owns
                    // it), so there is nothing further to check here.
                    // OUTCOME KEY SET AGREEMENT (cross-record invariant,
                    // outcome leg): when the terminal carries outcomes, its
                    // outcome key set must equal the intent's AUTHORITATIVE
                    // membership EXACTLY — every member slot has one outcome,
                    // no extras, no missing. An EMPTY outcome map is the
                    // documented pre-mutation / legacy no-outcomes state
                    // (e.g. a preflight failure that touched no slot) and
                    // stays valid; a PARTIAL outcome map — the shape that
                    // would let a consumer absorb only some members — is
                    // always refused.
                    // outcome leg), BY STATUS: the terminal's outcome key
                    // set must agree with the intent's AUTHORITATIVE
                    // membership EXACTLY —
                    // - Successful: the four sets (outcomes, rollback
                    //   slots, rollback bindings, intent membership) are
                    //   EXACTLY EQUAL and NON-EMPTY — the terminal-local
                    //   three-set equality is enforced by the wire → domain
                    //   conversion; the membership leg is enforced here.
                    // - FailedPreflight: outcomes EMPTY (a pre-mutation
                    //   failure touched no slot).
                    // - every other terminal state (FailedRolledBack,
                    //   Degraded): the outcomes EXACTLY COVER the
                    //   membership — every member slot has one outcome, no
                    //   extras, no missing.
                    let outcome_keys: BTreeSet<&SlotId> = terminal.outcomes.keys().collect();
                    let membership: BTreeSet<&SlotId> = entry.intent.slots.keys().collect();
                    match terminal.status() {
                        DeploymentStatus::Successful => {
                            if outcome_keys != membership {
                                return Err(Error::integrity(format!(
                                    "ledger of target '{target}': Successful terminal for deployment '{id}' carries outcomes for slots {outcome_keys:?} but its intent's slot_ids are {membership:?} — a successful deployment's outcomes must EXACTLY equal its membership (the rollback's slots and bindings equal them by the conversion)"
                                )));
                            }
                        }
                        DeploymentStatus::FailedPreflight => {
                            if !outcome_keys.is_empty() {
                                return Err(Error::integrity(format!(
                                    "ledger of target '{target}': FailedPreflight terminal for deployment '{id}' carries outcomes for slots {outcome_keys:?} — a pre-mutation failure touched no slot"
                                )));
                            }
                        }
                        _ => {
                            if outcome_keys != membership {
                                return Err(Error::integrity(format!(
                                    "ledger of target '{target}': terminal for deployment '{id}' carries outcomes for slots {outcome_keys:?} but its intent's slot_ids are {membership:?} — every member slot has exactly one outcome, no extras"
                                )));
                            }
                        }
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
                e.terminal
                    .as_ref()
                    .is_some_and(|t| t.status() == DeploymentStatus::Successful)
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
                        .map(|t| t.status())
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
        // Durable target-dir creation (the FIRST append's reported bug): the
        // `targets/<target>/` — and `targets/` — directory entries must be
        // fsynced before the ledger write can report success. An existing
        // target's dir is the helper's fast path (created nothing, syncs
        // nothing).
        self.ensure_target_dir_durable(target)?;
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
    use crate::config::ProjectConfig;
    use crate::model::{
        ArtifactRef, GenerationId, GenerationRef, PlacementSlotAssignment, ReleaseId, ServerId,
        SlotId, TargetName, VariantName,
    };
    use crate::push::lock::FileLock;
    use crate::records::{
        DeploymentIntent, DesiredGeneration, IntentSlot, LedgerIntentWire, LedgerLine,
        LedgerRollback, LedgerTerminal, LedgerTerminalWire, NonEmptySlotTable, PhysicalBinding,
        PreviousGeneration, SlotOutcomeKind, SlotResult, SlotTable, TerminalDisposition,
    };
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    /// The store path is `default_base().join(key)`: a clean store key
    /// places the store DIRECTLY under the base with exactly ONE component
    /// appended (no traversal), and every escape class is rejected at the
    /// key parse — an invalid name can never reach the store construction
    /// (the key type is the only way in).
    #[test]
    fn new_places_store_under_base_plus_single_component() {
        // Hermetic store base: `LocalStore::new` resolves `default_base()`
        // from the process-global `XDG_DATA_HOME`, so it is pointed at a
        // temp dir under ENV_LOCK (the house env-mutation invariant).
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let data_home = dir.path().join("data");
        unsafe { std::env::set_var("XDG_DATA_HOME", &data_home) };

        // A clean name → Ok, and the store path is `<base>/<name>` with no
        // traversal: exactly ONE component (the key) appended.
        let key = ApplicationStoreKey::parse("my-app").expect("clean name parses");
        let store = LocalStore::new(&key).expect("a valid store key constructs a store");
        assert_eq!(store.base().parent(), Some(default_base().as_path()));
        assert_eq!(
            store.base().file_name(),
            Some(std::ffi::OsStr::new("my-app"))
        );
        assert_eq!(store.base(), default_base().join("my-app"));

        // Every escape class is rejected at the KEY parse — the store
        // construction takes the key type, so an invalid name can never
        // reach it.
        for bad in [
            "a/b", "a\\b", "..", ".", "../x", "x/..", " x", "x ", "", "\u{0}",
        ] {
            ApplicationStoreKey::parse(bad).expect_err("unsafe store key rejected");
        }

        unsafe { std::env::remove_var("XDG_DATA_HOME") };
    }

    fn intent(id: &str, target: &str) -> DeploymentIntent {
        let p1 = SlotId::new("p1".to_string());
        // ONE slot table: the membership AND the desired/pre-push entries
        // (the exact-key-set invariant is structural in the domain).
        let slots = BTreeMap::from([(
            p1.clone(),
            IntentSlot {
                desired: DesiredGeneration {
                    generation: GenerationId::new("gen-1".to_string()),
                    artifact: ArtifactRef {
                        release: ReleaseId::new("rel-1".to_string()),
                        variant: VariantName::new("standard".to_string()),
                        tree: TreeDigest::new("tree-1".to_string()),
                    },
                },
                pre_push: None,
            },
        )]);
        DeploymentIntent {
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            group: None,
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a seeded deployment always has at least one slot"),
        }
    }

    fn successful_terminal() -> LedgerTerminal {
        LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: SlotTable::from_map(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                SlotResult {
                    slot_id: SlotId::new("p1".to_string()),
                    outcome: SlotOutcomeKind::Activated,
                    generation: Some(GenerationId::new("gen-1".to_string())),
                    compensated: false,
                    error: None,
                },
            )])),
            // A Successful disposition ALWAYS carries its complete rollback
            // payload (the truth table is structural in the domain).
            disposition: TerminalDisposition::Successful {
                rollback: LedgerRollback {
                    slots: BTreeMap::from([(
                        SlotId::new("p1".to_string()),
                        GenerationRef {
                            generation: GenerationId::new("gen-1".to_string()),
                            assignment: PlacementSlotAssignment {
                                placement_slot: SlotId::new("p1".to_string()),
                                artifact: ArtifactRef {
                                    release: ReleaseId::new("rel-sha256-a".to_string()),
                                    variant: VariantName::new("standard".to_string()),
                                    tree: TreeDigest::new("t1".to_string()),
                                },
                            },
                        },
                    )]),
                    bindings: BTreeMap::from([(
                        SlotId::new("p1".to_string()),
                        crate::records::PhysicalBinding {
                            server: crate::model::ServerId::new("s1".to_string()),
                            deploy_dir: "/srv/deploy/p1".to_string(),
                        },
                    )]),
                },
            },
            reason: None,
        }
    }

    fn seed_successful(store: &LocalStore, target: &str, id: &str) {
        store.append_intent(target, &intent(id, target)).unwrap();
        store
            .append_terminal(
                target,
                &DeploymentId::new(id.to_string()),
                &successful_terminal(),
            )
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
        let evil = SlotId::new("..".to_string());
        assert_eq!(
            store.slot_observed_path(&evil),
            dir.path()
                .join("store")
                .join("slots")
                .join("_")
                .join("observed.json"),
            "a '..' slot must be confined to its own slot dir, not the store root"
        );
        let observed = ObservedSlot {
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
            global.get(&SlotId::new("_".to_string())),
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
            entries[0].terminal.as_ref().unwrap().status(),
            DeploymentStatus::Successful
        );
        assert_eq!(
            entries[0].terminal.as_ref().unwrap().outcomes[&SlotId::new("p1")].outcome,
            SlotOutcomeKind::Activated
        );
        assert_eq!(
            match &entries[0].terminal.as_ref().unwrap().disposition {
                TerminalDisposition::Successful { rollback } => rollback,
                _ => panic!("the successful terminal carries its rollback"),
            }
            .slots[&SlotId::new("p1")]
                .assignment
                .artifact
                .release
                .as_str(),
            "rel-sha256-a"
        );
        // A terminal without its intent is refused (fail closed).
        let err = store
            .append_terminal(
                target,
                &DeploymentId::new("deploy-ghost".to_string()),
                &successful_terminal(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("no ledger intent"));
        // A duplicate intent is refused (the deployment id keys the entry).
        let err = store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("second intent"));
        // A duplicate terminal is refused.
        let err = store
            .append_terminal(
                target,
                &DeploymentId::new("deploy-a".to_string()),
                &successful_terminal(),
            )
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
    /// (only `LEDGER_SCHEMA_VERSION` is accepted), and a malformed line is a store
    /// error, never a silent drop.
    #[test]
    fn ledger_accepts_only_ledger_schema_version_and_rejects_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let foreign = intent("deploy-x", target);
        let mut wire = LedgerIntentWire::from(&foreign);
        wire.deployment_schema_version = LEDGER_SCHEMA_VERSION + 1;
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
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

    /// The read path runs the VERIFYING CONVERSION: a ledger line whose
    /// duplicate projections disagree (e.g. a `desired` key outside the
    /// authoritative `slot_ids` membership) is REFUSED with an integrity
    /// error rather than read as whichever projection a consumer happens to
    /// use; the same record with an AGREEING membership reads fine.
    #[test]
    fn read_ledger_refuses_disagreeing_records() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();

        // A DISAGREEING intent: `desired` names a slot the membership omits.
        let mut wire = LedgerIntentWire::from(&intent("deploy-x", target));
        wire.desired.insert(
            SlotId::new("not-a-member".to_string()),
            GenerationRef {
                generation: GenerationId::new("gen-1".to_string()),
                assignment: PlacementSlotAssignment {
                    placement_slot: SlotId::new("not-a-member".to_string()),
                    artifact: ArtifactRef {
                        release: ReleaseId::new("rel-1".to_string()),
                        variant: VariantName::new("standard".to_string()),
                        tree: TreeDigest::new("t1".to_string()),
                    },
                },
            },
        );
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            err.to_string().contains("refuses"),
            "a disagreeing intent line must be refused, got: {err}"
        );

        // The same record with an AGREEING membership reads fine: the extra
        // slot joins slot_ids AND both per-slot maps (EXACT key-set equality
        // — every member slot has exactly one desired + one pre_push entry).
        let mut wire = LedgerIntentWire::from(&intent("deploy-x", target));
        let extra = SlotId::new("not-a-member".to_string());
        wire.slot_ids.push(extra.clone());
        wire.desired.insert(
            extra.clone(),
            GenerationRef {
                generation: GenerationId::new("gen-2".to_string()),
                assignment: PlacementSlotAssignment {
                    placement_slot: extra.clone(),
                    artifact: ArtifactRef {
                        release: ReleaseId::new("rel-2".to_string()),
                        variant: VariantName::new("standard".to_string()),
                        tree: TreeDigest::new("t2".to_string()),
                    },
                },
            },
        );
        wire.pre_push.insert(extra, None);
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 1, "the agreeing line loads");
        assert_eq!(entries[0].intent.membership().len(), 2);
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
                &DeploymentId::new("deploy-deg".to_string()),
                &LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    // The degraded terminal records the slot that REMAINS
                    // changed (never restored): the conversion derives the
                    // Degraded disposition's non-empty remaining changes
                    // from it.
                    outcomes: SlotTable::from_map(BTreeMap::from([(
                        SlotId::new("p1".to_string()),
                        SlotResult {
                            slot_id: SlotId::new("p1".to_string()),
                            outcome: SlotOutcomeKind::Skipped,
                            generation: Some(GenerationId::new("gen-1".to_string())),
                            compensated: false,
                            error: None,
                        },
                    )])),
                    disposition: TerminalDisposition::Degraded,
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
                &DeploymentId::new("deploy-fail".to_string()),
                &LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    // The FailedRolledBack compensation report IS the outcome
                    // table — it must EXACTLY cover the membership (the
                    // status-specific outcome rule).
                    outcomes: SlotTable::from_map(BTreeMap::from([(
                        SlotId::new("p1".to_string()),
                        SlotResult {
                            slot_id: SlotId::new("p1".to_string()),
                            outcome: SlotOutcomeKind::Restored,
                            generation: Some(GenerationId::new("gen-1".to_string())),
                            compensated: true,
                            error: None,
                        },
                    )])),
                    disposition: TerminalDisposition::FailedRolledBack,
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
        let slots: BTreeMap<String, Vec<crate::config::SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![crate::config::SlotConfig {
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
            .append_terminal(
                target,
                &DeploymentId::new("deploy-a".to_string()),
                &successful_terminal(),
            )
            .expect_err("the armed terminal fault fires");
        // ...before any append (the entry is still intent-only) and is then
        // disarmed: the retry succeeds.
        store
            .append_terminal(
                target,
                &DeploymentId::new("deploy-a".to_string()),
                &successful_terminal(),
            )
            .expect("the disarmed retry appends the terminal");
        // A second terminal for the SAME deployment is refused (exactly-once).
        store
            .append_terminal(
                target,
                &DeploymentId::new("deploy-a".to_string()),
                &successful_terminal(),
            )
            .expect_err("a second terminal is refused (exactly-once contract)");
        // A different deployment is never faulted.
        store
            .append_terminal(
                target,
                &DeploymentId::new("deploy-b".to_string()),
                &successful_terminal(),
            )
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
        s1.append_terminal(
            "t1",
            &DeploymentId::new("deploy-a".to_string()),
            &successful_terminal(),
        )
        .expect_err("s1's own arm fires");
        // ...and never leaks into s2 (its deploy-b arm is untouched).
        s2.append_terminal(
            "t1",
            &DeploymentId::new("deploy-b".to_string()),
            &successful_terminal(),
        )
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
            .append_terminal(
                target,
                &DeploymentId::new("deploy-a".to_string()),
                &successful_terminal(),
            )
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
                .append_terminal(
                    target,
                    &DeploymentId::new(id.clone()),
                    &successful_terminal(),
                )
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
                    &serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::from_domain(
                        &DeploymentId::new(id.clone()),
                        &TargetName::new(target.to_string()),
                        &successful_terminal(),
                    ),))
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
            .append_terminal(
                target,
                &DeploymentId::new("deploy-a".to_string()),
                &successful_terminal(),
            )
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
            .append_terminal(
                target,
                &DeploymentId::new("deploy-d".to_string()),
                &successful_terminal(),
            )
            .expect_err("the armed dir-sync fault still leaves the ledger wholly new");
        drop(store);
        let reopened = LocalStore::with_base(base).unwrap();
        let visible = reopened.read_ledger_lines(target).unwrap();
        assert_eq!(visible.len(), 5);
        assert_eq!(
            visible[0],
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                "deploy-a", target
            ))))
            .unwrap()
        );
        assert_eq!(
            visible[1],
            serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::from_domain(
                &DeploymentId::new("deploy-a".to_string()),
                &TargetName::new(target.to_string()),
                &successful_terminal(),
            )))
            .unwrap()
        );
        assert_eq!(
            visible[2],
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                "deploy-b", target
            ))))
            .unwrap()
        );
        assert_eq!(
            visible[3],
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                "deploy-d", target
            ))))
            .unwrap()
        );
        assert_eq!(
            visible[4],
            serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::from_domain(
                &DeploymentId::new("deploy-d".to_string()),
                &TargetName::new(target.to_string()),
                &successful_terminal(),
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
            0..=6,
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
                    let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(
                        &intent.clone(),
                    )))
                    .unwrap();
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
                    let terminal = successful_terminal();
                    let deployment_id = DeploymentId::new(id.clone());
                    let line = serde_json::to_string(&LedgerLine::Terminal(
                        LedgerTerminalWire::from_domain(
                            &deployment_id,
                            &TargetName::new(target.to_string()),
                            &terminal,
                        ),
                    ))
                    .unwrap();
                    if let Some(stage) = stage {
                        arm_append_stage(&store, *stage, &id);
                    }
                    match store.append_terminal(target, &deployment_id, &terminal) {
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

    // ---- the first-append durable dir-creation (the reported bug) ------

    /// The reported durability bug: the FIRST `append_intent` for a NEW target
    /// created `targets/<target>/` — and the store open's `targets/` — WITHOUT
    /// syncing their directory entries, so a power loss right after a
    /// reported-successful first append could lose the new directories
    /// entirely (crash recovery would find NEITHER the new ledger NOR the
    /// prior state). The fix routes the append path through
    /// [`crate::store::atomic::ensure_private_dir_durable`]: every directory
    /// entry the creation makes is fsynced before the ledger write. This test
    /// pins the boundary contract per sync: with EACH of the two dir-sync
    /// faults armed (and both), the first append reports `Err` and crash
    /// recovery finds the PRIOR STATE — the target directory exists (created
    /// before the sync boundary) but no ledger was written — and the
    /// prior-state case then re-appends cleanly on the same base. With no
    /// fault, the append reports success and the complete new ledger is
    /// retained.
    #[test]
    fn first_append_dir_sync_fault_leaves_prior_state_or_full_durable() {
        let cases: &[&[FaultKind]] = &[
            &[],
            &[FaultKind::SyncNewTargetDir],
            &[FaultKind::SyncTargetsDir],
            &[FaultKind::SyncNewTargetDir, FaultKind::SyncTargetsDir],
        ];
        for kinds in cases {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("store");
            let store = LocalStore::with_base(base.clone()).unwrap();
            let target = "t1";
            for kind in *kinds {
                store.fault_registry().arm(*kind, target);
            }
            let result = store.append_intent(target, &intent("dep-x", target));
            drop(store);
            let reopened = LocalStore::with_base(base.clone()).unwrap();
            assert!(
                reopened.target_dir(target).exists(),
                "the first append creates the target dir BEFORE any sync — it is never missing (kinds: {kinds:?})"
            );
            let entries = reopened.read_ledger(target).unwrap();
            if kinds.is_empty() {
                assert!(result.is_ok(), "an un-faulted first append reports success");
                assert_eq!(
                    entries.len(),
                    1,
                    "a reported success retains the complete new ledger"
                );
            } else {
                assert!(
                    result.is_err(),
                    "a faulted dir-sync must fail the first append (kinds: {kinds:?})"
                );
                assert!(
                    entries.is_empty(),
                    "a faulted dir-sync leaves the PRIOR STATE — the append did not commit (kinds: {kinds:?})"
                );
                // The prior-state case re-appends cleanly (crash recovery +
                // retry over the same base).
                let store2 = LocalStore::with_base(base.clone()).unwrap();
                store2
                    .append_intent(target, &intent("dep-x", target))
                    .unwrap();
                assert_eq!(
                    store2.read_ledger(target).unwrap().len(),
                    1,
                    "the prior-state case re-appends cleanly"
                );
            }
        }
    }

    /// Run one model case of the first-append dir-sync property: a fresh
    /// fixture, optionally pre-seeded as an EXISTING target (its dir + first
    /// ledger entry already written), with the per-target dir-sync faults
    /// armed per the vector; then ONE `append_intent`, a fresh-store reopen
    /// over the same base, and the coherent-state assertions:
    ///
    /// * the target directory is NEVER missing after a reported success;
    /// * an EXISTING target's append creates no directory, so the dir-sync
    ///   arms never fire — the append reports success and retains the new
    ///   entry;
    /// * a FIRST target's faulted sync returns `Err` and recovery finds the
    ///   PRIOR STATE (the dir was created, no ledger — the append did not
    ///   commit);
    /// * a FIRST target's un-faulted append reports success and recovery
    ///   retains the complete new ledger.
    fn run_first_append_dir_sync_model(
        existing_target: bool,
        sync_new_target_dir: bool,
        sync_targets_dir: bool,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap();
        let target = "t1";
        if existing_target {
            // The EXISTING-target model: the target dir and a first ledger
            // entry exist before the append under test.
            store
                .append_intent(target, &intent("dep-0", target))
                .unwrap();
        }
        if sync_new_target_dir {
            store.fault_registry().arm_sync_new_target_dir(target);
        }
        if sync_targets_dir {
            store.fault_registry().arm_sync_targets_dir(target);
        }
        let id = if existing_target { "dep-1" } else { "dep-0" };
        let result = store.append_intent(target, &intent(id, target));
        drop(store);
        let reopened = LocalStore::with_base(base.clone()).unwrap();
        assert!(
            reopened.target_dir(target).exists(),
            "the target directory is never missing (existing={existing_target}, new_target_sync={sync_new_target_dir}, targets_sync={sync_targets_dir})"
        );
        let entries = reopened.read_ledger(target).unwrap();
        if existing_target {
            // No durable creation happens (the dir exists): the dir-sync
            // arms cannot fire, the append reports success and the new
            // entry is retained beside the seeded one.
            assert!(
                result.is_ok(),
                "an existing target's append creates no dir, so the dir-sync arms never fire (sync_new={sync_new_target_dir}, sync_targets={sync_targets_dir})"
            );
            assert_eq!(entries.len(), 2);
            assert!(entries.iter().any(|e| e.deployment_id.as_str() == id));
        } else if sync_new_target_dir || sync_targets_dir {
            // A FIRST target with a faulted dir-sync boundary: the append
            // reports `Err` and recovery finds the prior state — the target
            // dir exists (created before the boundary), but the append did
            // not commit, so the ledger is absent.
            assert!(
                result.is_err(),
                "a faulted dir-sync must fail the first append"
            );
            assert!(
                entries.is_empty(),
                "a faulted first append did not commit — no ledger"
            );
            // The prior-state case re-appends cleanly on the same base.
            let store2 = LocalStore::with_base(base.clone()).unwrap();
            store2.append_intent(target, &intent(id, target)).unwrap();
            assert!(
                store2
                    .read_ledger(target)
                    .unwrap()
                    .iter()
                    .any(|e| e.deployment_id.as_str() == id)
            );
        } else {
            // A REPORTED SUCCESS for the first append: recovery retains the
            // complete new ledger and the target directory is present.
            assert!(result.is_ok(), "an un-faulted first append reports success");
            assert_eq!(entries.len(), 1);
            assert!(entries.iter().any(|e| e.deployment_id.as_str() == id));
        }
    }

    proptest! {
        // The main property split into PARALLEL SUBTESTS: the harness runs
        // each test in its own thread, but proptest runs a test's cases
        // sequentially in that one thread — so the randomized-with-
        // persistence leg (8 cases) is SPLIT into four subtests of
        // `cases: 8/4 = 2` each with DISTINCT FIXED seeds. The four
        // subtests run concurrently on different harness threads, dividing
        // this leg's wall time, while the fixed seeds keep every subtest
        // deterministic (CI-reproducible). FAILURE PERSISTENCE stays on
        // THIS subtest only: the shared `proptest-regressions/local.txt`
        // is keyed per source FILE, so every subtest with persistence
        // would replay ALL persisted vectors — duplicating the replay K
        // times — so only `_0` carries the persistence (any persisted
        // vectors replay exactly once, in `_0`), while `_1`..`_3` run the
        // same generator + assertions under their fixed seeds. The
        // deterministic fixed-seed leg below stays ONE test (the
        // deterministic floor).
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0011),
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_0(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // The second slice of the split randomized leg: the same generator
        // + assertions under a DISTINCT fixed seed (deterministic; no
        // persistence — the fixed seed makes any failure reproducible).
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0012),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_1(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // The third slice of the split randomized ledger, distinct seed.
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0013),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_2(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // The fourth slice of the split randomized ledger, distinct seed.
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0014),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_3(history in ledger_history_strategy()) {
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
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_fixed_seed_regression(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // FIXED-SEED PROPERTY for the FIRST-append durable dir-creation
        // (the reported bug): model FIRST vs EXISTING targets with a fault
        // at each dir-sync boundary. A REPORTED SUCCESS must imply that
        // crash recovery (a fresh store over the same base) retains the
        // complete new ledger with the target directory present — NEVER a
        // missing target directory after a reported success; a faulted
        // sync returns `Err` (prior state: the target dir was created, no
        // ledger — the append did not commit) and the prior-state case
        // re-appends cleanly. EXISTING targets create nothing (the durable
        // helper's fast path), so their dir-sync arms never fire and the
        // append always reports success. The pinned 0x5EED_5EED seed with
        // no persistence runs the IDENTICAL 16 vectors on every invocation;
        // the case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn first_append_dir_sync_durability(
            (existing, sync_new, sync_targets) in (any::<bool>(), any::<bool>(), any::<bool>()),
        ) {
            run_first_append_dir_sync_model(existing, sync_new, sync_targets);
        }
    }

    // ---- the lock-path target-dir creation (the reported lock bypass) --

    /// The crashable boundary of the COMPLETE first-push sequence — store
    /// open → target lock acquisition → intent append — that the property
    /// below injects a fault at. The lock-path mkdir boundary
    /// ([`LockPathBoundary::LockMkdir`]) and the two durable dir-sync
    /// boundaries ([`LockPathBoundary::SyncNewTargetDir`] /
    /// [`LockPathBoundary::SyncTargetsDir`]) fire on the target-dir creation
    /// the engine/checkpoint run BEFORE the target lock; the four atomic-
    /// append stage boundaries fire on the ledger write inside the append.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LockPathBoundary {
        /// No fault: the sequence reports success.
        None,
        /// The LOCK-PATH mkdir step: the durable pre-creation crashes
        /// before it creates anything — recovery finds NO target directory
        /// (a first target) and no ledger.
        LockMkdir,
        /// The sync of the NEW TARGET DIR's entry (`targets/`), on the
        /// lock-path pre-creation: the dir exists, no ledger.
        SyncNewTargetDir,
        /// The sync of `targets/`'s OWN entry (the store base), on the
        /// lock-path pre-creation: the dir exists, no ledger.
        SyncTargetsDir,
        /// The ledger append's TEMP-WRITE stage: the visible ledger is
        /// wholly prior.
        AppendWrite,
        /// The ledger append's TEMP-SYNC stage: wholly prior.
        AppendSync,
        /// The ledger append's RENAME stage: wholly prior.
        AppendRename,
        /// The ledger append's PARENT-DIR-SYNC stage: the rename already
        /// landed — the ledger is wholly new, though the append returns
        /// `Err`.
        AppendDirSync,
    }

    /// The eight crash boundaries of the complete sequence, for the
    /// deterministic unit test and the fixed-seed property generator.
    fn lock_path_boundaries() -> Vec<LockPathBoundary> {
        vec![
            LockPathBoundary::None,
            LockPathBoundary::LockMkdir,
            LockPathBoundary::SyncNewTargetDir,
            LockPathBoundary::SyncTargetsDir,
            LockPathBoundary::AppendWrite,
            LockPathBoundary::AppendSync,
            LockPathBoundary::AppendRename,
            LockPathBoundary::AppendDirSync,
        ]
    }

    /// Run one model case of the lock-path durability property: a fresh
    /// fixture, optionally pre-seeded as an EXISTING target (its dir + first
    /// ledger entry already written), with the boundary fault armed per the
    /// spec; then the COMPLETE SEQUENCE — store open, the durable target-dir
    /// pre-creation + target lock acquisition exactly as the engine's lock
    /// block runs it ([`crate::push::engine::push`]: local lock, then
    /// `ensure_target_dir_durable`, then the target lock), then the intent
    /// append — a fresh-store reopen over the same base, and the durability
    /// contract:
    ///
    /// * a REPORTED SUCCESS recovers with the COMPLETE ledger AND the target
    ///   directory present — never a missing target directory after an `Ok`;
    /// * a faulted boundary returns `Err` and recovery finds the PRIOR
    ///   STATE: the `LockMkdir` crash leaves NO target dir (the pre-creation
    ///   never ran, for a first target); every later boundary leaves the
    ///   target dir present with the prior ledger (or the wholly-new
    ///   committed ledger when the append's rename already landed);
    /// * the prior-state cases re-append cleanly on the same base (the
    ///   landed dir-sync case is fail-closed: the recovered ledger already
    ///   holds the entry and the duplicate guard refuses the replay).
    fn run_lock_path_durability_model(existing: bool, boundary: LockPathBoundary) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap(); // store open
        let target = "t1";
        if existing {
            store
                .append_intent(target, &intent("dep-0", target))
                .unwrap();
        }
        let id = if existing { "dep-1" } else { "dep-0" };
        // Arm the boundary fault: the dir-creation kinds key by target (the
        // lock-path pre-creation and the append's `ensure_target_dir_durable`
        // consume them); the append-stage kinds key by deployment id.
        match boundary {
            LockPathBoundary::None => {}
            LockPathBoundary::LockMkdir => store.fault_registry().arm_lock_mkdir(target),
            LockPathBoundary::SyncNewTargetDir => {
                store.fault_registry().arm_sync_new_target_dir(target)
            }
            LockPathBoundary::SyncTargetsDir => store.fault_registry().arm_sync_targets_dir(target),
            LockPathBoundary::AppendWrite => store.fault_registry().arm_append_write(id),
            LockPathBoundary::AppendSync => store.fault_registry().arm_append_sync(id),
            LockPathBoundary::AppendRename => store.fault_registry().arm_append_rename(id),
            LockPathBoundary::AppendDirSync => store.fault_registry().arm_append_dir_sync(id),
        }
        // THE COMPLETE SEQUENCE: store open → target lock acquisition →
        // intent append, mirroring the engine's lock block exactly (local
        // store lock first, then the durable target-dir pre-creation, then
        // the target lock, then the append).
        let result = (|| -> Result<()> {
            let local = FileLock::acquire(&store.base().join("operation.lock"), "op-1")?;
            store.ensure_target_dir_durable(target)?;
            let target_lock =
                FileLock::acquire(&store.target_dir(target).join("operation.lock"), "op-1")?;
            store.append_intent(target, &intent(id, target))?;
            drop(target_lock);
            drop(local);
            Ok(())
        })();
        drop(store);
        let reopened = LocalStore::with_base(base.clone()).unwrap();
        let entries = reopened.read_ledger(target).unwrap();
        let id_present = entries.iter().any(|e| e.deployment_id.as_str() == id);
        if result.is_ok() {
            assert!(
                reopened.target_dir(target).exists(),
                "a reported success never loses the target directory (existing={existing}, boundary={boundary:?})"
            );
            assert!(
                id_present,
                "a reported success always retains the complete ledger (existing={existing}, boundary={boundary:?})"
            );
        } else {
            // The faulted boundary's contract, per crash point.
            match boundary {
                LockPathBoundary::LockMkdir => {
                    // The crash hit BEFORE the durable helper created
                    // anything: a FIRST target recovers with NO target
                    // directory; an existing one keeps its pre-existing dir.
                    // Either way the ledger is the prior one.
                    if existing {
                        assert!(reopened.target_dir(target).exists());
                        assert_eq!(entries.len(), 1, "the prior ledger is intact");
                    } else {
                        assert!(
                            !reopened.target_dir(target).exists(),
                            "the crashed lock-path mkdir leaves NO target dir (boundary={boundary:?})"
                        );
                        assert!(entries.is_empty());
                    }
                }
                LockPathBoundary::AppendDirSync => {
                    // The append's rename already landed: the ledger is
                    // wholly NEW (the committed entry is present) even
                    // though the append reported `Err`.
                    assert!(reopened.target_dir(target).exists());
                    assert!(id_present, "the landed rename is wholly new");
                }
                _ => {
                    // A dir-sync or pre-rename boundary: the target dir was
                    // durably created before any crashable boundary (present)
                    // and the ledger is the PRIOR one (the append did not
                    // commit).
                    assert!(reopened.target_dir(target).exists());
                    assert!(!id_present, "the append did not commit ({boundary:?})");
                }
            }
            // A faulted step recovers to a re-appendable state: a fresh
            // store over the same base re-appends the same intent cleanly
            // when the entry did not land; when the rename already landed
            // (dir-sync), the recovered ledger already holds the entry and
            // the fail-closed duplicate guard refuses the replay.
            let retry = LocalStore::with_base(base.clone()).unwrap();
            if id_present {
                let err = retry
                    .append_intent(target, &intent(id, target))
                    .unwrap_err();
                assert!(
                    err.to_string().contains("second intent"),
                    "a landed entry is fail-closed against a duplicate replay ({boundary:?})"
                );
            } else {
                retry.append_intent(target, &intent(id, target)).unwrap();
                assert!(
                    retry
                        .read_ledger(target)
                        .unwrap()
                        .iter()
                        .any(|e| e.deployment_id.as_str() == id)
                );
            }
        }
    }

    /// The DETERMINISTIC unit test of the complete sequence: every crash
    /// boundary faulted, on a first AND an existing target. This is the exact
    /// sequence the reported bug bypassed — store open → target lock
    /// acquisition → intent append — with each boundary faulted in turn, and
    /// the durability contract above (a reported success recovers with the
    /// complete ledger AND the target directory present; a faulted step
    /// returns `Err` with the prior state; a retry re-appends cleanly).
    #[test]
    fn lock_path_dir_creation_each_boundary_faulted() {
        for existing in [false, true] {
            for boundary in lock_path_boundaries() {
                run_lock_path_durability_model(existing, boundary);
            }
        }
    }

    proptest! {
        // FIXED-SEED PROPERTY for the lock-path target-dir creation (the
        // reported bug): the COMPLETE sequence — store open → target lock
        // acquisition → intent append — is faulted at EVERY mkdir / fsync /
        // rename boundary (the durable-dir kinds
        // [`FaultKind::SyncNewTargetDir`] / [`FaultKind::SyncTargetsDir`], the
        // lock-path mkdir kind [`FaultKind::LockMkdir`], and the four
        // atomic-append stages), on first AND existing targets. Every
        // REPORTED SUCCESS must recover (a fresh store over the same base)
        // with the COMPLETE ledger AND the target directory present — NEVER a
        // missing target directory after a reported success; a faulted step
        // returns `Err` with the prior state (no target dir or the prior
        // ledger) and a retry re-appends cleanly. The pinned 0x5EED_5EED seed
        // with no persistence runs the IDENTICAL vectors on every invocation;
        // the case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn lock_path_dir_creation_durability(
            (existing, boundary) in (any::<bool>(), prop::sample::select(lock_path_boundaries())),
        ) {
            run_lock_path_durability_model(existing, boundary);
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
            cases: 4,
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
                    serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                        &fresh, target,
                    ))))
                    .unwrap();
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

    // ---- terminal cross-field / cross-record invariants -------------------

    /// A canonical generation ref whose assignment names its own map key.
    fn gen_ref(slot: &SlotId) -> GenerationRef {
        GenerationRef {
            generation: GenerationId::new(format!("gen-{}", slot.as_str())),
            assignment: PlacementSlotAssignment {
                placement_slot: slot.clone(),
                artifact: ArtifactRef::default(),
            },
        }
    }

    /// A binding for a slot (server `s1`, the canonical deploy dir).
    fn binding_for(slot: &SlotId) -> PhysicalBinding {
        PhysicalBinding {
            server: ServerId::new("s1".to_string()),
            deploy_dir: format!("/srv/eng/{}", slot.as_str()),
        }
    }

    /// An EXACT intent (the domain's ONE slot table — the membership AND
    /// the desired/pre-push entries are the same [`NonEmptySlotTable`], so
    /// the exact-key-set invariant is STRUCTURAL): `slot_count` members,
    /// every member desired + pre-push.
    fn exact_intent(id: &str, target: &str, slot_count: u32) -> DeploymentIntent {
        let slot_ids: Vec<SlotId> = (0..slot_count)
            .map(|i| SlotId::new(format!("slot-{i}")))
            .collect();
        let slots: Vec<(SlotId, IntentSlot)> = slot_ids
            .iter()
            .map(|k| {
                (
                    k.clone(),
                    IntentSlot {
                        desired: DesiredGeneration {
                            generation: GenerationId::new(format!("gen-{}", k.as_str())),
                            artifact: ArtifactRef::default(),
                        },
                        pre_push: Some(PreviousGeneration {
                            artifact: ArtifactRef::default(),
                            generation: Some(GenerationId::new("gen-0".to_string())),
                        }),
                    },
                )
            })
            .collect();
        DeploymentIntent {
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            group: None,
            behavior_sha256: "sha256-pair".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a seeded deployment always has at least one slot"),
        }
    }

    /// The terminal for an attempt: FULL per-slot outcomes (every member
    /// slot has one outcome, each value naming its own key) and — when
    /// `successful` — a `Successful` disposition whose rollback bindings key
    /// its slotted generations EXACTLY; otherwise a `FailedRolledBack`
    /// disposition carrying the outcome table as its compensation report.
    fn terminal_for_intent(
        intent: &DeploymentIntent,
        id: &str,
        successful: bool,
    ) -> LedgerTerminal {
        let outcomes: BTreeMap<SlotId, SlotResult> = intent
            .slots
            .keys()
            .cloned()
            .map(|k| {
                (
                    k.clone(),
                    SlotResult {
                        slot_id: k,
                        outcome: SlotOutcomeKind::Activated,
                        generation: Some(GenerationId::new(format!("gen-{id}"))),
                        compensated: false,
                        error: None,
                    },
                )
            })
            .collect();
        let disposition = if successful {
            TerminalDisposition::Successful {
                rollback: LedgerRollback {
                    slots: intent
                        .slots
                        .keys()
                        .map(|k| (k.clone(), gen_ref(k)))
                        .collect(),
                    bindings: intent
                        .slots
                        .keys()
                        .map(|k| (k.clone(), binding_for(k)))
                        .collect(),
                },
            }
        } else {
            TerminalDisposition::FailedRolledBack
        };
        LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: SlotTable::from_map(outcomes),
            disposition,
            reason: None,
        }
    }

    /// Append a valid pair (intent + terminal) to a fresh ledger. The
    /// terminal's wire identity (deployment id / target) comes from the
    /// ENTRY (the append path supplies the intent's identity — the domain
    /// terminal carries none).
    fn append_pair(
        store: &LocalStore,
        target: &str,
        intent: &DeploymentIntent,
        terminal: &LedgerTerminal,
    ) {
        store.append_intent(target, intent).unwrap();
        store
            .append_terminal(target, &intent.deployment_id, terminal)
            .unwrap();
    }

    /// Write an intent + terminal WIRE pair directly to the ledger file: the
    /// append API only accepts DOMAIN objects, so wire-level violations that
    /// are UNREPRESENTABLE in the domain (the status→disposition truth
    /// table, the terminal's wire target) are crafted at the wire and must
    /// still be refused by the read path.
    fn write_wire_pair(
        store: &LocalStore,
        target: &str,
        intent: &LedgerIntentWire,
        terminal: &LedgerTerminalWire,
    ) {
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(intent.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(terminal.clone())).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
    }

    /// The minimal project config the consumer checks need (the GC
    /// reachability scan reads `config.pins` — an empty pin set here). One
    /// config per test case; every store of the case reuses it.
    fn consumer_config(base: &std::path::Path) -> ProjectConfig {
        let project = base.join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            "[artifact]\nmappings = []\n\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = []\ndeploy_dir = \"/srv\"\n\n[retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n[retention.deployment]\nprotect_deployments = 1\n\n[activation]\nadapter = \"none\"\n\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            "schema_version = 2\napplication = \"store-tests\"\nrelease = \"v1\"\n\n\
             [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
             [targets.t1]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n",
        )
        .unwrap();
        ProjectConfig::load(&project.join("deploy.toml")).unwrap()
    }

    /// Every consumer of a target's ledger goes through the SAME read
    /// ([`LocalStore::read_ledger`]), so a conversion-time refusal precedes
    /// ALL of them: the direct read, a rollback resolve
    /// ([`crate::history::resolve_deployment`]), and the GC reachability
    /// scan ([`LocalStore::reachable_set`]). `why` names the mutation for
    /// the failure messages.
    fn assert_consumers_refuse_with_integrity(
        store: &LocalStore,
        config: &ProjectConfig,
        target: &str,
        id: &str,
        why: &str,
    ) {
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "{why}: read_ledger must refuse with an integrity error before any consumer sees the line, got: {err}"
        );
        let err = crate::history::resolve_deployment(
            store,
            &TargetName::new(target.to_string()),
            &DeploymentId::new(id.to_string()),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "{why}: a rollback resolve must refuse with the same integrity error before resolving, got: {err}"
        );
        let err = store.reachable_set(config, None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "{why}: the GC reachability scan must refuse with the same integrity error before sweeping, got: {err}"
        );
    }

    /// ONE-FIELD mutations of a valid terminal, expressed on the DOMAIN
    /// object (the truth-table and identity states are STRUCTURAL in the
    /// domain — they cannot be constructed — so those refusals are crafted
    /// at the WIRE in the deterministic test below): a BINDING key
    /// (add / remove / rename), or an OUTCOME key (rename — the value keeps
    /// naming its old slot — or an extra key outside the membership).
    /// Returns the mutated terminal + a reason naming the mutated field.
    fn one_field_mutations(terminal: &LedgerTerminal) -> Vec<(LedgerTerminal, String)> {
        let mut out: Vec<(LedgerTerminal, String)> = Vec::new();
        // (1) BINDING KEY — add one, remove one, move (rename) one. Only
        // meaningful when the disposition carries a rollback.
        if let TerminalDisposition::Successful { rollback } = &terminal.disposition {
            let first = rollback.bindings.keys().next().cloned().unwrap();
            // (1a) an EXTRA binding key (no generation for it)
            let mut t = terminal.clone();
            let TerminalDisposition::Successful { rollback } = &mut t.disposition else {
                unreachable!("cloned above");
            };
            rollback.bindings.insert(
                SlotId::new("ghost-slot".to_string()),
                PhysicalBinding {
                    server: ServerId::new("s9".to_string()),
                    deploy_dir: "/srv/ghost".to_string(),
                },
            );
            out.push((
                t,
                "binding key ADDED (extra binding, no generation)".to_string(),
            ));
            // (1b) a MISSING binding key (a generation without its binding)
            let mut t = terminal.clone();
            let TerminalDisposition::Successful { rollback } = &mut t.disposition else {
                unreachable!("cloned above");
            };
            rollback.bindings.remove(&first);
            out.push((
                t,
                "binding key REMOVED (a generation without its binding)".to_string(),
            ));
            // (1c) a binding key RENAMED (moved out of the slot set)
            let mut t = terminal.clone();
            let TerminalDisposition::Successful { rollback } = &mut t.disposition else {
                unreachable!("cloned above");
            };
            let value = rollback.bindings.remove(&first).unwrap();
            rollback
                .bindings
                .insert(SlotId::new("renamed-slot".to_string()), value);
            out.push((t, "binding key RENAMED (missing + extra pair)".to_string()));
        }
        // (2) OUTCOME KEY — rename an outcome's KEY (its value keeps naming
        // the old slot: the outcome own-key agreement fails, and the key set
        // no longer matches the intent's membership).
        if let Some((key, _)) = terminal.outcomes.iter().next() {
            let mut t = terminal.clone();
            let mut map = t.outcomes.clone().into_map();
            let result = map.remove(key).unwrap();
            map.insert(SlotId::new("renamed-outcome".to_string()), result);
            t.outcomes = SlotTable::from_map(map);
            out.push((
                t,
                "outcome key RENAMED (the value still names its old slot)".to_string(),
            ));
        }
        out
    }

    /// THE USER'S PROPERTY: VALID LEDGER PAIRS (an EXACT intent + a
    /// SUCCESSFUL and a NON-SUCCESSFUL terminal derived from it) load and
    /// every consumer accepts them; mutating ONE FIELD at a time — a binding
    /// key (add/remove/rename) or an outcome key (rename) — makes EVERY
    /// consumer refuse the line with `Error::integrity` BEFORE any consumer
    /// logic runs: the direct read, a rollback resolve, and the GC
    /// reachability scan all fail on the SAME refusal.
    /// Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
    /// persistence.
    fn ledger_pair_mutation_case(intent: &DeploymentIntent) {
        let tmp = tempfile::tempdir().unwrap();
        let config = consumer_config(tmp.path());
        let target = intent.target.as_str();
        for (variant, successful) in [("successful", true), ("failed", false)] {
            let terminal = terminal_for_intent(intent, "deploy-pair", successful);
            // THE VALID PAIR: the store loads and every consumer accepts it.
            let store =
                LocalStore::with_base(tmp.path().join(format!("store-{variant}-valid"))).unwrap();
            append_pair(&store, target, intent, &terminal);
            assert_eq!(
                store.read_ledger(target).unwrap().len(),
                1,
                "the valid pair merges into one entry"
            );
            store.reachable_set(&config, None).unwrap();
            let resolved = crate::history::resolve_deployment(
                &store,
                &TargetName::new(target.to_string()),
                &DeploymentId::new("deploy-pair".to_string()),
            );
            match successful {
                true => {
                    resolved.expect("a Successful pair resolves to its rollback");
                }
                false => {
                    assert!(
                        matches!(resolved, Err(Error::Ref(_))),
                        "a FailedRolledBack pair never resolves as a deployment ref (a ref refusal, not a record refusal)"
                    );
                }
            }
            // ONE mutation at a time — EVERY mutation must be refused by
            // every consumer.
            for (n, (mutated, why)) in one_field_mutations(&terminal).into_iter().enumerate() {
                let store =
                    LocalStore::with_base(tmp.path().join(format!("store-{variant}-mut-{n}")))
                        .unwrap();
                append_pair(&store, target, intent, &mutated);
                assert_consumers_refuse_with_integrity(
                    &store,
                    &config,
                    target,
                    "deploy-pair",
                    &why,
                );
            }
        }
    }

    proptest! {
        // THE USER'S PROPERTY: valid ledger pairs load; ONE-FIELD mutations
        // of the terminal — a binding key (add/remove/rename) or an outcome
        // key (rename) — are ALL refused with `Error::integrity` at
        // conversion time, before read_ledger, a rollback resolve, or the
        // GC reachability scan can consume the line. Bounded 16 cases, fixed
        // seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_pair_one_field_mutations_are_refused_at_conversion(
            slot_count in 1u32..4,
        ) {
            let intent = exact_intent("deploy-pair", "t1", slot_count);
            ledger_pair_mutation_case(&intent);
        }
    }

    /// The CROSS-RECORD invariants, deterministically: a valid pair loads;
    /// ONE mutation per invariant — the truth table (both directions) and
    /// the terminal target equality, crafted at the WIRE (states the DOMAIN
    /// cannot represent — the domain enforces them structurally), plus the
    /// exact binding keys, the outcome key set vs the intent's membership,
    /// the outcome own-key rule, and the intent-leg target equality — is
    /// refused with `Error::integrity` by the read path.
    #[test]
    fn read_ledger_refuses_terminal_cross_field_and_cross_record_violations() {
        let tmp = tempfile::tempdir().unwrap();
        let config = consumer_config(tmp.path());
        let intent = exact_intent("deploy-unit", "t1", 2);
        let terminal = terminal_for_intent(&intent, "deploy-unit", true);
        let id = "deploy-unit";
        let target = "t1";

        // THE VALID PAIR loads; the resolve and the GC scan accept it.
        let store = LocalStore::with_base(tmp.path().join("store-valid")).unwrap();
        append_pair(&store, target, &intent, &terminal);
        assert_eq!(store.read_ledger(target).unwrap().len(), 1);
        crate::history::resolve_deployment(
            &store,
            &TargetName::new(target.to_string()),
            &DeploymentId::new(id.to_string()),
        )
        .unwrap();
        store.reachable_set(&config, None).unwrap();

        // (a) TRUTH TABLE, direction 1 (wire): a Successful terminal
        // without its rollback payload.
        let mut bad = LedgerTerminalWire::from_domain(
            &DeploymentId::new(id.to_string()),
            &TargetName::new(target.to_string()),
            &terminal,
        );
        bad.rollback = None;
        assert_wire_terminal_refused(&tmp, target, &intent, &bad, "a");
        // (b) TRUTH TABLE, direction 2 (wire): a failed status carrying a
        // rollback.
        let mut bad = LedgerTerminalWire::from_domain(
            &DeploymentId::new(id.to_string()),
            &TargetName::new(target.to_string()),
            &terminal,
        );
        bad.status = DeploymentStatus::Degraded;
        assert_wire_terminal_refused(&tmp, target, &intent, &bad, "b");
        // (c) TARGET EQUALITY, terminal leg (wire): the terminal names a
        // different target than the path and its entry.
        let mut bad = LedgerTerminalWire::from_domain(
            &DeploymentId::new(id.to_string()),
            &TargetName::new(target.to_string()),
            &terminal,
        );
        bad.target = TargetName::new("other-target".to_string());
        assert_wire_terminal_refused(&tmp, target, &intent, &bad, "c");
        // (d) EXACT BINDING KEYS: a generation without its binding.
        let mut bad = terminal.clone();
        let TerminalDisposition::Successful { rollback } = &mut bad.disposition else {
            unreachable!("the fixture terminal is Successful");
        };
        let first = rollback.bindings.keys().next().cloned().unwrap();
        rollback.bindings.remove(&first);
        assert_terminal_refused(&tmp, target, &intent, &bad, "d");
        // (e) OUTCOME KEY SET == membership: an outcome for a non-member
        // slot (extra — the value names its own key, so only the
        // cross-record equality fails).
        let mut bad = terminal.clone();
        let mut outcomes = bad.outcomes.clone().into_map();
        outcomes.insert(
            SlotId::new("extra-slot".to_string()),
            SlotResult {
                slot_id: SlotId::new("extra-slot".to_string()),
                outcome: SlotOutcomeKind::Activated,
                generation: Some(GenerationId::new("gen-x".to_string())),
                compensated: false,
                error: None,
            },
        );
        bad.outcomes = SlotTable::from_map(outcomes);
        assert_terminal_refused(&tmp, target, &intent, &bad, "e");
        // (f) OUTCOME OWN-KEY: an outcome whose value names a DIFFERENT
        // slot than its map key.
        let mut bad = terminal.clone();
        let mut map = bad.outcomes.clone().into_map();
        let first = map.keys().next().cloned().unwrap();
        let result = map.remove(&first).unwrap();
        map.insert(SlotId::new("renamed-outcome".to_string()), result);
        bad.outcomes = SlotTable::from_map(map);
        assert_terminal_refused(&tmp, target, &intent, &bad, "f");
        // (g) TARGET EQUALITY, intent leg: the intent names a different
        // target than the path.
        let mut bad_intent = intent.clone();
        bad_intent.target = TargetName::new("other-target".to_string());
        assert_intent_refused(&tmp, target, &bad_intent);
    }

    /// Append a valid intent + a MUTATED terminal to a fresh store and
    /// assert the read path refuses with an integrity error. `tag` keeps
    /// each mutation's store directory unique.
    fn assert_terminal_refused(
        tmp: &tempfile::TempDir,
        target: &str,
        intent: &DeploymentIntent,
        mutated: &LedgerTerminal,
        tag: &str,
    ) {
        let store = LocalStore::with_base(tmp.path().join(format!("refuse-t-{tag}"))).unwrap();
        append_pair(&store, target, intent, mutated);
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "a terminal violating the invariants must be refused with an integrity error, got: {err}"
        );
    }

    /// Write a valid intent wire + a MUTATED terminal wire to a fresh store
    /// and assert the store refuses with an integrity error.
    fn assert_wire_terminal_refused(
        tmp: &tempfile::TempDir,
        target: &str,
        intent: &DeploymentIntent,
        mutated: &LedgerTerminalWire,
        tag: &str,
    ) {
        let store = LocalStore::with_base(tmp.path().join(format!("refuse-w-{tag}"))).unwrap();
        write_wire_pair(&store, target, &LedgerIntentWire::from(intent), mutated);
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "a terminal violating the invariants must be refused with an integrity error, got: {err}"
        );
    }

    /// Append a MUTATED intent to a fresh store and assert the store refuses
    /// with an integrity error. The refusal fires on the intent line itself
    /// (before any terminal is appended).
    fn assert_intent_refused(tmp: &tempfile::TempDir, target: &str, mutated: &DeploymentIntent) {
        let store = LocalStore::with_base(tmp.path().join("refuse-i")).unwrap();
        store.append_intent(target, mutated).unwrap();
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "an intent violating the target equality must be refused with an integrity error, got: {err}"
        );
    }
}

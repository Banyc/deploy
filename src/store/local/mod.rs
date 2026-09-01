//! Filesystem-backed local store: the [`LocalStore`] struct, its
//! constructors, the store base, and the shared I/O primitives
//! (`write_json`, `write_atomic_cas`, [`sanitize`]). The per-feature
//! record I/O lives in sibling modules ([`super::ledger`], [`super::objects`],
//! [`super::observed`], [`super::deployments`], [`super::debt`],
//! [`super::layout`], [`super::pins`], [`super::releases`]) as inherent
//! `impl LocalStore` blocks on this type; this module re-exports
//! `default_base` so callers keep the `crate::store::local::default_base`
//! path.
//!
//! # Submodules (the per-feature record I/O)
//!
//! Each sibling module is one facet of the [`LocalStore`] as inherent
//! `impl LocalStore` blocks: [`ledger`] (A2 target ledger), [`objects`] (A3
//! content-addressed store + recovery), [`observed`] (slot observed state),
//! [`deployments`] (deployment dirs), [`debt`] (sweep-debt marker I/O),
//! [`layout`] (store layout paths), [`pins`] (durable release pins), and
//! [`releases`] (release records). The generic atomic-write infra stays at
//! [`crate::store::atomic`].
//!
//! # Test-only fault injection (per-fixture registry)
//!
//! Under `#[cfg(test)]` each [`LocalStore`] owns a per-fixture
//! `crate::testutil::test_faults::FaultRegistry` (created empty by
//! [`LocalStore::with_base`]); the store methods consult ONLY that registry
//! (`self.fault_registry.consume(...)`). Tests arm the fixture's registry via
//! `LocalStore::fault_registry` (`store.fault_registry().arm_append_attempt(id)`
//! etc.). There are NO process-global fault slots and NO shared fault lock:
//! two fixtures' registries are disjoint by construction, so a fault armed by
//! one test can never fire in another's push — structural isolation that
//! holds under any parallel `cargo test` interleaving.

use crate::env::SysEnv;
use crate::error::{Error, Result};
use crate::identity::ApplicationStoreKey;
use crate::remote::layout as remote_layout;
use crate::store::atomic::{ReplaceOutcome, ensure_private_dir, read_json_fd};
use serde::Serialize;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::identity::DeploymentId;
#[cfg(test)]
use crate::store::atomic::ReplaceStage;
#[cfg(test)]
use crate::testutil::step17_hook::Step17Hook;
#[cfg(test)]
use crate::testutil::test_faults::{FaultKind, FaultRegistry};
#[cfg(test)]
use std::sync::Arc;

pub(crate) use self::layout::default_base;

mod owned_root;
pub use owned_root::OwnedRoot;

pub mod debt;
pub mod deployments;
pub mod layout;
pub mod ledger;
pub mod objects;
pub mod observed;
pub mod pins;
pub mod releases;

/// Read a KEYED JSON record and verify its embedded identity equals the
/// storage key (path) it was read from — the binding between a durable
/// record's EMBEDDED identity and its STORAGE KEY. A record swapped into the
/// wrong storage location (its file relocated, or its embedded identity
/// edited to a consistent-but-different value) is REFUSED with an
/// [`Error::integrity`] failure naming BOTH identities — never returned as
/// if it were the requested key. `extract` projects the record's embedded
/// identity (the value that must equal the path key). The read resolves
/// DESCRIPTOR-RELATIVE to `dir_fd` (component-wise `openat(O_NOFOLLOW)` — a
/// symlink injected into any path component is refused, never followed).
pub(crate) fn read_keyed_json_fd<T>(
    dir_fd: &OwnedFd,
    rel: &Path,
    key: &str,
    extract: impl Fn(&T) -> &str,
) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let rec: T = read_json_fd(dir_fd, rel)?;
    let embedded = extract(&rec);
    if embedded != key {
        return Err(Error::integrity(format!(
            "record read from {} declares identity {embedded:?}: the stored record's identity does not match the requested key {key:?} (a record swapped into the wrong storage location)",
            rel.display()
        )));
    }
    Ok(rec)
}

impl LocalStore {
    /// Write a KEYED JSON record, refusing to persist a record whose embedded
    /// identity differs from the storage key it is being written under — the
    /// write-side half of the embedded-identity binding. The check is an
    /// [`Error::integrity`] failure naming BOTH identities, and it runs BEFORE
    /// any bytes are written (fail closed: a mismatched record is never
    /// persisted). The write itself goes through the same atomic-replace
    /// protocol as [`LocalStore::write_json`] (the test seam faults each
    /// replacement stage from the caller's per-fixture registry), resolved
    /// DESCRIPTOR-RELATIVE to the store's owned root.
    pub(crate) fn write_keyed_json<T>(
        &self,
        path: &Path,
        key: &str,
        value: &T,
        extract: impl Fn(&T) -> &str,
        #[cfg(test)] fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let embedded = extract(value);
        if embedded != key {
            return Err(Error::integrity(format!(
                "refusing to write a record declaring identity {embedded:?} under key {key:?} at {}: the record's embedded identity does not match its storage key",
                path.display()
            )));
        }
        #[cfg(test)]
        {
            self.write_json_seam(path, value, fault)
        }
        #[cfg(not(test))]
        {
            self.write_json(path, value)
        }
    }

    /// Durably write a MUTABLE JSON record via the atomic-replace protocol
    /// ([`crate::store::atomic::write_atomic_replace_fd`]: unique temp in the
    /// same directory → write → fsync → chmod private → atomic rename →
    /// parent-directory fsync), resolved DESCRIPTOR-RELATIVE to the store's
    /// owned root. A reader never observes a torn record (the rename is atomic
    /// on POSIX — wholly old or wholly new).
    ///
    /// FAIL CLOSED ON UNCONFIRMED DURABILITY: a
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`] outcome — the new record
    /// IS visible but the parent-directory fsync failed — is DOWNGRADED to
    /// `Err`, never reported as success (the pins-write precedent
    /// [`LocalStore::write_pins`]): the caller has no facility to report
    /// "visible but unconfirmed", so failure is the only safe answer.
    #[cfg(not(test))]
    pub(crate) fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| Error::store(format!("serialize {}: {e}", path.display())))?;
        match self.write_atomic_replace_at(path, &bytes)? {
            ReplaceOutcome::ReplacedDurable => Ok(()),
            ReplaceOutcome::ReplacedDurabilityUnknown { error } => Err(error),
        }
    }

    /// TEST-ONLY seam: the same atomic JSON-record write as [`LocalStore::write_json`]
    /// with a per-stage fault hook, so a per-fixture registry can inject a failure
    /// at EVERY atomic-replacement stage ([`ReplaceStage`]) of a mutable
    /// record write (the `write_slot_observed` / `write_server` /
    /// `write_retention_debt` / `write_sweep_debt` writers) and the property
    /// can assert the stage→outcome mapping. Not part of the production
    /// surface — production builds keep the exact `write_json` signature.
    #[cfg(test)]
    pub(crate) fn write_json_seam<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
        fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
    ) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| Error::store(format!("serialize {}: {e}", path.display())))?;
        match self.write_atomic_replace_seam_at(path, &bytes, fault)? {
            ReplaceOutcome::ReplacedDurable => Ok(()),
            ReplaceOutcome::ReplacedDurabilityUnknown { error } => Err(error),
        }
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
    /// The write resolves DESCRIPTOR-RELATIVE to the store's owned root (a
    /// symlink injected at the final component is refused, never followed).
    pub(crate) fn write_atomic_cas(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::write_atomic_cas_fd(&self.root_fd, rel, bytes)
    }
}

pub struct LocalStore {
    pub(crate) base: PathBuf,
    /// The SEALED ownership root (production stores): holds the canonical
    /// root's registration in the process-global ownership registry
    /// ([`OwnedRoot`]), released when the store is dropped. `None` for
    /// test-only [`LocalStore::with_base`] stores (which bypass ownership
    /// registration). The field is never READ — its only job is to keep the
    /// [`OwnedRoot`] alive so its `Drop` releases the registration.
    #[allow(dead_code)]
    root: Option<OwnedRoot>,
    /// The open directory descriptor on the owned root, opened with
    /// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`. Every store mutation resolves
    /// paths relative to this descriptor (component-wise `openat(O_NOFOLLOW)`,
    /// see [`crate::store::atomic`]'s `_fd` primitives), so a symlink
    /// injected into a path component can never redirect a mutation outside
    /// the owned root.
    root_fd: OwnedFd,
    /// Per-fixture one-shot fault registry (test-only). Created EMPTY by
    /// [`LocalStore::with_base`]; tests that want an injected store fault arm
    /// it via [`LocalStore::fault_registry`]. There are no process-global
    /// fault slots and no shared fault lock: the store's methods consult ONLY
    /// this fixture's registry, so two fixtures can never interfere regardless
    /// of threading. See `src/testutil.rs` for the design.
    #[cfg(test)]
    pub(crate) fault_registry: Arc<FaultRegistry>,
    /// Per-fixture one-shot step-17 phase hook (test-only). Created EMPTY by
    /// [`LocalStore::with_base`]; a test arms it via [`LocalStore::step17_hook`]
    /// right before the push under test. Like the fault registry it lives on
    /// THIS store (never a process-global slot), so a hook armed by one
    /// fixture can never fire in another's push. The engine consults it via
    /// [`LocalStore::step17_hook_barrier`] immediately before each
    /// step-17-equivalent lock acquisition. See `src/testutil.rs`.
    #[cfg(test)]
    pub(crate) step17_hook: Arc<Step17Hook>,
}

impl LocalStore {
    /// Create a store rooted at `<data>/simple-deploy/<key>` with private
    /// permissions, creating the directory tree if needed. The application
    /// STORE KEY is the ONLY way in: the key is a validated single safe
    /// path segment ([`crate::identity::ApplicationStoreKey`]), so the store
    /// path is `default_base().join(key)` — exactly ONE component appended
    /// — and an application name can never escape the store base.
    ///
    /// Entry-point convenience: snapshots the process environment ONCE
    /// ([`SysEnv::from_process`]) and delegates to [`LocalStore::new_in`].
    /// Subsystem code that already holds the boundary snapshot passes it to
    /// [`LocalStore::new_in`] instead — never reads the process env itself.
    pub fn new(application: &ApplicationStoreKey) -> Result<LocalStore> {
        Self::new_in(&SysEnv::from_process(), application)
    }

    /// Create a store rooted at `default_base(env).join(key)` with private
    /// permissions, creating the directory tree if needed. The application
    /// STORE KEY is the ONLY way in (see [`LocalStore::new`]); the store
    /// base is resolved PURELY from the caller's environment snapshot —
    /// never from a live process read.
    ///
    /// The store is constructed from a SEALED [`OwnedRoot`] on the local
    /// endpoint: the base tree is created first (idempotent — a second
    /// store on an overlapping root creates nothing new), then the owned
    /// root is constructed from the now-existing canonical directory. The
    /// overlap refusal (equal / ancestor / descendant roots on the same
    /// endpoint) happens at the [`OwnedRoot::parse`] construction, before
    /// any store record is created or deleted.
    pub fn new_in(env: &SysEnv, application: &ApplicationStoreKey) -> Result<LocalStore> {
        let base = default_base(env).join(application.as_str());
        // The ownership gate needs a real canonical directory: create the
        // base tree first (idempotent), then construct the owned root from
        // the now-existing canonical directory.
        ensure_private_dir(&base)?;
        let root = OwnedRoot::parse(&OwnedRoot::local_endpoint()?, &base)?;
        Self::from_owned_root(root)
    }

    /// The production constructor: from a validated, registered
    /// [`OwnedRoot`]. The store's base is the root's canonical directory;
    /// the store opens a descriptor on it (with `O_DIRECTORY | O_NOFOLLOW |
    /// O_CLOEXEC`) and creates the private layout tree. Every subsequent
    /// store mutation resolves paths relative to that descriptor
    /// (component-wise `openat(O_NOFOLLOW)`), so a symlink injected into a
    /// path component can never redirect a mutation outside the owned root.
    pub fn from_owned_root(root: OwnedRoot) -> Result<LocalStore> {
        let base = root.canonical().to_path_buf();
        let root_fd = open_root_fd(&base)?;
        ensure_private_dir(&base.join(remote_layout::objects()))?;
        ensure_private_dir(&base.join(remote_layout::RELEASES))?;
        ensure_private_dir(&base.join("targets"))?;
        ensure_private_dir(&base.join("slots"))?;
        ensure_private_dir(&base.join("servers"))?;
        ensure_private_dir(&base.join("deployments"))?;
        ensure_private_dir(&base.join("staging"))?;
        Ok(LocalStore {
            base,
            root: Some(root),
            root_fd,
            #[cfg(test)]
            fault_registry: Arc::new(FaultRegistry::new()),
            #[cfg(test)]
            step17_hook: Arc::new(Step17Hook::new()),
        })
    }

    /// The SEALED filesystem-ownership root this store owns — the canonical
    /// root the store's mutations are confined to. `None` for test-only
    /// [`LocalStore::with_base`] stores (which bypass ownership
    /// registration). The validated project's provisioned topology binds
    /// every slot to this root.
    pub(crate) fn owned_root(&self) -> Option<&OwnedRoot> {
        self.root.as_ref()
    }

    /// The SEALED filesystem-ownership root for the validated project's
    /// provisioned topology: the store's OWNED root when this is a
    /// production store, or a freshly-parsed root on the store's base for
    /// test-only [`LocalStore::with_base`] stores (which bypass ownership
    /// registration — the parsed root registers for the project's
    /// lifetime and is released when the project drops).
    pub(crate) fn owned_root_for_project(&self) -> Result<OwnedRoot> {
        match self.owned_root() {
            Some(root) => Ok(root.clone()),
            None => OwnedRoot::parse(&OwnedRoot::local_endpoint()?, &self.base),
        }
    }

    /// TEST-ONLY: create a store rooted at an explicit base (used in
    /// tests). Bypasses the ownership registry (a test may create and
    /// reopen stores over the same base freely); the store still opens a
    /// descriptor on the base, so its mutations are descriptor-relative
    /// like production stores. PRODUCTION CODE MUST NOT USE THIS — the
    /// production constructors are [`LocalStore::new`] /
    /// [`LocalStore::new_in`] / [`LocalStore::from_owned_root`], which
    /// construct the store from a sealed [`OwnedRoot`]. This constructor is
    /// `#[doc(hidden)]` because it exists only for test fixtures (the lib's
    /// unit tests and the integration tests in `tests/`, which compile
    /// against the library without `#[cfg(test)]`).
    #[doc(hidden)]
    pub fn with_base(base: PathBuf) -> Result<LocalStore> {
        ensure_private_dir(&base)?;
        ensure_private_dir(&base.join(remote_layout::objects()))?;
        ensure_private_dir(&base.join(remote_layout::RELEASES))?;
        ensure_private_dir(&base.join("targets"))?;
        ensure_private_dir(&base.join("slots"))?;
        ensure_private_dir(&base.join("servers"))?;
        ensure_private_dir(&base.join("deployments"))?;
        ensure_private_dir(&base.join("staging"))?;
        let root_fd = open_root_fd(&base)?;
        Ok(LocalStore {
            base,
            root: None,
            root_fd,
            #[cfg(test)]
            fault_registry: Arc::new(FaultRegistry::new()),
            #[cfg(test)]
            step17_hook: Arc::new(Step17Hook::new()),
        })
    }

    /// The path relative to the owned root (for descriptor-relative I/O).
    /// Every store path is built from `self.base`, so the prefix strip is
    /// exact; a path outside the root is a store error (fail closed).
    fn rel<'a>(&self, path: &'a Path) -> Result<&'a Path> {
        path.strip_prefix(&self.base).map_err(|_| {
            Error::store(format!(
                "path {} is outside the owned root {}",
                path.display(),
                self.base.display()
            ))
        })
    }

    /// The descriptor-relative atomic replace (see
    /// [`crate::store::atomic::write_atomic_replace_fd`]).
    fn write_atomic_replace_at(&self, path: &Path, bytes: &[u8]) -> Result<ReplaceOutcome> {
        let rel = self.rel(path)?;
        crate::store::atomic::write_atomic_replace_fd(&self.root_fd, rel, bytes, &mut |_| None)
    }

    /// The descriptor-relative atomic replace with the per-stage fault hook
    /// (test seam).
    #[cfg(test)]
    fn write_atomic_replace_seam_at(
        &self,
        path: &Path,
        bytes: &[u8],
        fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
    ) -> Result<ReplaceOutcome> {
        let rel = self.rel(path)?;
        crate::store::atomic::write_atomic_replace_fd(&self.root_fd, rel, bytes, fault)
    }

    /// The descriptor-relative private-directory creation (see
    /// [`crate::store::atomic::ensure_private_dir_fd`]).
    fn ensure_private_dir_at(&self, path: &Path) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::ensure_private_dir_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative DURABLE private-directory creation (see
    /// [`crate::store::atomic::ensure_private_dir_durable_fd`]).
    fn ensure_private_dir_durable_at(&self, path: &Path) -> Result<bool> {
        let rel = self.rel(path)?;
        crate::store::atomic::ensure_private_dir_durable_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative parent-directory fsync (see
    /// [`crate::store::atomic::sync_parent_dir_fd`]).
    fn sync_parent_dir_at(&self, path: &Path) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::sync_parent_dir_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative private chmod (see
    /// [`crate::store::atomic::set_private_fd`]).
    fn set_private_at(&self, path: &Path) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::set_private_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative remove of a single file (see
    /// [`crate::store::atomic::remove_file_fd`]).
    fn remove_file_at(&self, path: &Path) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::remove_file_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative rename of a path under the root (see
    /// [`crate::store::atomic::renameat_paths`]).
    fn rename_at(&self, from: &Path, to: &Path) -> Result<()> {
        let from_rel = self.rel(from)?;
        let to_rel = self.rel(to)?;
        crate::store::atomic::renameat_paths(&self.root_fd, from_rel, to_rel)
    }

    /// The descriptor-relative recursive removal of a directory tree (see
    /// [`crate::store::atomic::remove_dir_all_fd`]).
    fn remove_dir_all_at(&self, path: &Path) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::remove_dir_all_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative recursive tree copy (see
    /// [`crate::store::atomic::copy_dir_recursive_fd`]).
    fn copy_dir_recursive_at(&self, src: &Path, dst: &Path) -> Result<()> {
        let dst_rel = self.rel(dst)?;
        crate::store::atomic::copy_dir_recursive_fd(&self.root_fd, src, dst_rel)
    }

    /// The descriptor-relative recursive tree fsync (see
    /// [`crate::store::atomic::fsync_tree_recursive_fd`]).
    fn fsync_tree_recursive_at(&self, path: &Path) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::fsync_tree_recursive_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative plain file write (see
    /// [`crate::store::atomic::write_file_fd`]).
    fn write_file_at(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let rel = self.rel(path)?;
        crate::store::atomic::write_file_fd(&self.root_fd, rel, bytes)
    }

    /// The descriptor-relative whole-file read (see
    /// [`crate::store::atomic::read_fd`]).
    fn read_fd_at(&self, path: &Path) -> Result<Vec<u8>> {
        let rel = self.rel(path)?;
        crate::store::atomic::read_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative JSON read (see
    /// [`crate::store::atomic::read_json_fd`]).
    fn read_json_at<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let rel = self.rel(path)?;
        crate::store::atomic::read_json_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative tri-state existence check (see
    /// [`crate::store::atomic::path_state_fd`]).
    fn path_state_at(&self, path: &Path) -> Result<bool> {
        let rel = self.rel(path)?;
        crate::store::atomic::path_state_fd(&self.root_fd, rel)
    }

    /// The descriptor-relative keyed JSON read (see
    /// [`crate::store::atomic::read_json_fd`] + the embedded-identity
    /// binding in [`read_keyed_json_fd`]).
    fn read_keyed_json_at<T>(
        &self,
        path: &Path,
        key: &str,
        extract: impl Fn(&T) -> &str,
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let rel = self.rel(path)?;
        read_keyed_json_fd(&self.root_fd, rel, key, extract)
    }

    /// The fixture's per-fixture one-shot fault registry. A test arms faults
    /// here (`store.fault_registry().arm_append_attempt(id)` etc.) and the
    /// store methods consume them from the SAME registry — never from any
    /// other fixture's, and never from a process-global slot.
    #[cfg(test)]
    pub(crate) fn fault_registry(&self) -> &Arc<FaultRegistry> {
        &self.fault_registry
    }

    /// TEST-ONLY: build the per-stage fault hook for a mutable-record
    /// atomic replacement ([`write_json_seam`]). The hook consumes from
    /// THIS fixture's own registry (never a process-global slot), mapping
    /// each [`ReplaceStage`] to the caller's per-resource fault kinds
    /// (`observed_replace_kind` / `server_replace_kind` / the debt kinds),
    /// keyed by the resource's natural id (slot id / server id / target /
    /// the empty global key). The pre-rename stages (write / sync / rename)
    /// propagate the fault as `Err` — the visible record is wholly OLD;
    /// the post-rename parent-directory stage surfaces as
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`], which the record
    /// writers downgrade to `Err` (fail closed — never a silent success
    /// while the directory entry is unsynced).
    #[cfg(test)]
    fn replace_stage_hook(
        &self,
        key: &str,
        kind: fn(ReplaceStage) -> FaultKind,
    ) -> impl FnMut(ReplaceStage) -> Option<Error> + '_ {
        let reg = std::sync::Arc::clone(self.fault_registry());
        let key = key.to_string();
        move |stage| {
            let kind = kind(stage);
            if reg.consume(kind, &key) {
                Some(Error::store(format!(
                    "test fault: atomic JSON record replacement faulted at the {stage:?} stage"
                )))
            } else {
                None
            }
        }
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
}

/// Open a directory descriptor on `base` with `O_DIRECTORY | O_NOFOLLOW |
/// O_CLOEXEC`: the descriptor pins the owned root, and every store mutation
/// resolves paths relative to it (component-wise `openat(O_NOFOLLOW)`), so a
/// symlink injected into a path component can never redirect a mutation
/// outside the owned root. `O_NOFOLLOW` refuses a symlink at the FINAL
/// component (the root itself must be a real directory); intermediate
/// components are resolved normally (the root is canonical by construction
/// in production, and test bases are real directories).
fn open_root_fd(base: &Path) -> Result<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let f = opts
        .open(base)
        .map_err(|e| Error::store(format!("open root {}: {e}", base.display())))?;
    Ok(f.into())
}

/// Sanitize a name for use as a directory/file component — retained ONLY
/// for the raw-name entry points that can receive UNVALIDATED strings
/// ([`LocalStore::target_dir`]'s raw target argument, the GC's raw-name
/// entry). On the VALIDATED identity grammar (the rule behind
/// [`crate::identity::SlotId`], [`crate::identity::ServerId`],
/// [`crate::identity::TargetName`], [`crate::identity::VariantName`],
/// [`crate::identity::ApplicationStoreKey`], ...) this
/// function is the IDENTITY: every valid name is already ASCII-safe and
/// passes through unchanged, so the validated-ID store paths are built
/// VERBATIM (no re-encoding) and two distinct valid names always map to two
/// distinct paths. The re-encoding here only ever applies to junk outside
/// the grammar, where confinement (never an escape, never a separator)
/// matters more than injectivity.
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
    use crate::identity::{
        ApplicationStoreKey, ArtifactRef, DeploymentId, ReleaseId, ReleaseRecord, ServerId, SlotId,
        TargetName, TreeDigest, VariantName, test_deployment_id, test_generation_id,
        test_release_id, test_tree_digest,
    };
    use crate::ledger::{BehaviorIndex, DeploymentPlan, PlanOrigin, SlotPlan};
    use crate::ledger::{ObservedAssignment, ObservedSlot, ServerState};
    use crate::store::local::debt::SweepDebt;
    use crate::testutil::test_faults::FaultKind;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;

    /// A valid name in the filesystem-safe ASCII grammar
    /// ([`crate::identity::valid_name`]): `[a-zA-Z0-9._-]`+ (non-empty, not
    /// `.`/`..`, never a leading dash).
    fn valid_segment() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                prop::char::range('a', 'z'),
                prop::char::range('A', 'Z'),
                prop::char::range('0', '9'),
                Just('-'),
                Just('_'),
                Just('.'),
            ],
            1..16,
        )
        .prop_filter("not a traversal component, no leading dash", |s| {
            s.first() != Some(&'-') && s.as_slice() != ['.'] && s.as_slice() != ['.', '.']
        })
        .prop_map(|v| v.into_iter().collect())
    }
    /// `sanitize` must neutralize path-traversal components. `.` and `..` are
    /// the one case the character filter lets through untouched (dots are
    /// legal in ids), and an unsuffixed component named `..` would make
    /// `slots/..` resolve to the STORE ROOT. THE TRAVERSAL CLASS IS NOW
    /// UNCONSTRUCTIBLE AT THE TYPE LEVEL: the identity grammar
    /// ([`crate::identity::valid_name`]) rejects `.`/`..`/separators before a
    /// value of the id type can exist, and the validated-ID store paths
    /// store the name VERBATIM — so the `sanitize` confinement shown here
    /// applies only to RAW string entry points (`target_dir`,
    /// `release_dir_named`), never to validated identities.
    #[test]
    fn sanitize_neutralizes_path_traversal_components() {
        assert_eq!(sanitize(".."), "_");
        assert_eq!(sanitize("."), "_");
        assert_eq!(sanitize(""), "_");
        // Separators and any other non-id characters become underscores.
        assert_eq!(sanitize("../evil"), ".._evil");
        assert_eq!(sanitize("a/b"), "a_b");
        assert_eq!(sanitize("a\\b"), "a_b");
        // Ordinary valid names pass through unchanged (identity on the
        // valid grammar — the store stores them verbatim).
        assert_eq!(sanitize("normal-name_1.x"), "normal-name_1.x");

        // End-to-end: the traversal class can never reach the store path —
        // `..` is rejected at the ID parse, so a slot id named `..` is
        // unconstructible through the validated constructor (only the
        // test-only unchecked `new` can build it, and the raw-path
        // confinement above shows what a raw string would do).
        assert!(
            SlotId::parse("..").is_err(),
            "a '..' slot id must be rejected"
        );
        assert!(
            SlotId::parse(".").is_err(),
            "a '.' slot id must be rejected"
        );
        assert!(
            SlotId::parse("a/b").is_err(),
            "a '/' slot id must be rejected"
        );

        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // A VALID slot's record lives at `slots/<slot-id>/observed.json`
        // with the id stored VERBATIM.
        let ok_slot = SlotId::parse("ok-slot").unwrap();
        assert_eq!(
            store.slot_observed_path(&ok_slot),
            dir.path()
                .join("store")
                .join("slots")
                .join("ok-slot")
                .join("observed.json"),
            "a valid slot id is stored verbatim under its own slot dir"
        );
        let observed = ObservedSlot {
            slot: ok_slot.clone(),
            assignment: ObservedAssignment::Known {
                generation: test_generation_id("evil"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-sha256-evil"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("evil"),
                },
                last_deployment: test_deployment_id("evil"),
                owner: crate::remote::helper::test_owner("test-app", "evil"),
                version: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            },
        };
        store.write_slot_observed(&ok_slot, &observed).unwrap();
        assert!(
            !dir.path().join("store").join("observed.json").exists(),
            "observed state for a slot must never land at the store root"
        );
        assert_eq!(
            store.read_slot_observed(&ok_slot).unwrap(),
            Some(observed.clone()),
            "the verbatim path must not corrupt the recorded slot identity"
        );
        let global = store.read_global_observed().unwrap();
        assert_eq!(
            global.get(&ok_slot),
            Some(&observed),
            "the global slot map keys by the stored (verbatim) slot id"
        );
        // The RAW target-dir entry point still confines traversal junk.
        assert_eq!(
            store.target_dir("../evil"),
            dir.path().join("store").join("targets").join(".._evil"),
            "a raw traversal name must be confined inside the targets namespace"
        );
    }

    // -------------------------------------------------------------------
    // THE INJECTIVITY PROPERTY (the review's acceptance): over pairs of
    // ARBITRARY VALID resource keys (applications, slots, servers,
    // targets, deployments, releases), every pair of DISTINCT keys maps to
    // DISTINCT local store paths — the filesystem identifiers are injective
    // (valid names are stored verbatim; `sanitize` is the identity on the
    // valid grammar, so no two valid names can ever collide onto one
    // encoded name). Bounded 64 cases (16 fast, 64 with
    // DEPLOY_FULL_TESTS=1), fixed seed 0x5EED_5EED per house style.
    // -------------------------------------------------------------------
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn distinct_valid_keys_map_to_distinct_store_paths(
            a in valid_segment(),
            b in valid_segment(),
        ) {
            // `sanitize` is the IDENTITY on the valid grammar: the store
            // stores valid names verbatim (the re-encoding never fires).
            assert_eq!(sanitize(&a), a, "sanitize must be the identity on valid names");
            assert_eq!(sanitize(&b), b, "sanitize must be the identity on valid names");

            let slot_a = SlotId::parse(&a).expect("valid segment parses as slot id");
            let slot_b = SlotId::parse(&b).expect("valid segment parses as slot id");
            let app_a = ApplicationStoreKey::parse(&a).expect("valid segment parses as store key");
            let app_b = ApplicationStoreKey::parse(&b).expect("valid segment parses as store key");
            let server_a = ServerId::parse(&a).expect("valid segment parses as server id");
            let server_b = ServerId::parse(&b).expect("valid segment parses as server id");
            let target_a = TargetName::parse(&a).expect("valid segment parses as target name");
            let target_b = TargetName::parse(&b).expect("valid segment parses as target name");

            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            if a != b {
                // Distinct valid keys => distinct store paths, on EVERY
                // store path family (slots, servers, targets).
                assert_ne!(
                    store.slot_observed_path(&slot_a),
                    store.slot_observed_path(&slot_b),
                    "distinct slot ids must map to distinct slot dirs: {a:?} vs {b:?}"
                );
                assert_ne!(
                    store.target_dir(target_a.as_str()),
                    store.target_dir(target_b.as_str()),
                    "distinct target names must map to distinct target dirs: {a:?} vs {b:?}"
                );
                assert_ne!(
                    store.base.join("servers").join(format!("{}.json", server_a.as_str())),
                    store.base.join("servers").join(format!("{}.json", server_b.as_str())),
                    "distinct server ids must map to distinct server records: {a:?} vs {b:?}"
                );
                // The same name under DIFFERENT path families is never a
                // cross-family collision (each family has its own directory).
                assert_ne!(
                    store.slot_observed_path(&slot_a),
                    store.target_dir(target_a.as_str()),
                    "slot and target namespaces must not alias"
                );
                // Distinct application keys => distinct store bases.
                assert_ne!(
                    app_a.as_str(),
                    app_b.as_str(),
                    "distinct application keys must be distinct strings"
                );
            } else {
                // The same valid name maps to the SAME path (determinism).
                assert_eq!(
                    store.slot_observed_path(&slot_a),
                    store.slot_observed_path(&slot_b)
                );
                assert_eq!(app_a, app_b);
            }
        }

        #[test]
        fn distinct_deployment_and_release_ids_map_to_distinct_dirs(
            tag_a in "[a-z0-9]{1,12}",
            tag_b in "[a-z0-9]{1,12}",
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let dep_a = test_deployment_id(&tag_a);
            let dep_b = test_deployment_id(&tag_b);
            let rel_a = crate::identity::test_release_id(&tag_a);
            let rel_b = crate::identity::test_release_id(&tag_b);
            if dep_a != dep_b {
                assert_ne!(
                    store.deployment_dir(&dep_a),
                    store.deployment_dir(&dep_b),
                    "distinct deployment ids must map to distinct dirs"
                );
            } else {
                assert_eq!(
                    store.deployment_dir(&dep_a),
                    store.deployment_dir(&dep_b),
                    "the same deployment id must map to the same dir (determinism)"
                );
            }
            if rel_a != rel_b {
                assert_ne!(
                    store.release_dir(&rel_a),
                    store.release_dir(&rel_b),
                    "distinct release ids must map to distinct dirs"
                );
            } else {
                assert_eq!(
                    store.release_dir(&rel_a),
                    store.release_dir(&rel_b),
                    "the same release id must map to the same dir (determinism)"
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // THE UNIFORM CRASH-CONSISTENCY PROPERTY (the review's acceptance):
    // every store write is atomic — mutable records (observed / server /
    // retention-debt / sweep-debt) via the atomic-replace protocol, immutable
    // trees via the staged publish — so a fault at EVERY filesystem boundary
    // (the temp write, the temp fsync, the rename, the parent-dir sync, and
    // the staged-tree copy/sync/rename) leaves every resource WHOLLY OLD
    // (pre-commit fault), WHOLLY NEW (post-commit dir-sync fault — the new
    // content IS visible; the writer failed closed on the unconfirmed
    // durability), or WHOLLY ABSENT (no old state + pre-commit fault) —
    // NEVER partial (a torn/malformed record or a half-copied object tree).
    // After each fault the store is REOPENED (a fresh [`LocalStore`] over
    // the same base) and every resource is required to parse as one of
    // those three, and never to durably reference missing content (a
    // record that names an artifact must have that artifact's tree present
    // and whole).
    // -------------------------------------------------------------------

    /// One stage of a mutable-record atomic replacement.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReplaceBoundary {
        Write,
        Sync,
        Rename,
        DirSync,
    }

    /// One stage of the immutable tree-object staged publish.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PublishBoundary {
        Copy,
        Sync,
        Rename,
        DirSync,
    }

    /// ONE filesystem boundary of ONE store write protocol.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StoreBoundary {
        Observed(ReplaceBoundary),
        Server(ReplaceBoundary),
        Debt(ReplaceBoundary),
        Sweep(ReplaceBoundary),
        Object(PublishBoundary),
    }

    /// The exhaustive boundary table: every mutable-record replacement
    /// stage of all four record writers plus every staged-publish stage.
    const ALL_BOUNDARIES: [StoreBoundary; 20] = [
        StoreBoundary::Observed(ReplaceBoundary::Write),
        StoreBoundary::Observed(ReplaceBoundary::Sync),
        StoreBoundary::Observed(ReplaceBoundary::Rename),
        StoreBoundary::Observed(ReplaceBoundary::DirSync),
        StoreBoundary::Server(ReplaceBoundary::Write),
        StoreBoundary::Server(ReplaceBoundary::Sync),
        StoreBoundary::Server(ReplaceBoundary::Rename),
        StoreBoundary::Server(ReplaceBoundary::DirSync),
        StoreBoundary::Debt(ReplaceBoundary::Write),
        StoreBoundary::Debt(ReplaceBoundary::Sync),
        StoreBoundary::Debt(ReplaceBoundary::Rename),
        StoreBoundary::Debt(ReplaceBoundary::DirSync),
        StoreBoundary::Sweep(ReplaceBoundary::Write),
        StoreBoundary::Sweep(ReplaceBoundary::Sync),
        StoreBoundary::Sweep(ReplaceBoundary::Rename),
        StoreBoundary::Sweep(ReplaceBoundary::DirSync),
        StoreBoundary::Object(PublishBoundary::Copy),
        StoreBoundary::Object(PublishBoundary::Sync),
        StoreBoundary::Object(PublishBoundary::Rename),
        StoreBoundary::Object(PublishBoundary::DirSync),
    ];

    /// Build a small materialized tree (one deterministic file) and return
    /// its canonical digest.
    fn make_tree(root: &Path, tag: &str) -> String {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join("file.txt"), format!("content-{tag}")).unwrap();
        crate::remote::canonical::canonicalize_tree(root)
            .unwrap()
            .tree_sha256
    }

    /// A `Known` observed assignment whose artifact names `tree`.
    fn observed_record(tree: &str, gen_tag: &str, dep: &str) -> ObservedSlot {
        ObservedSlot {
            slot: SlotId::new("p1".to_string()),
            assignment: ObservedAssignment::Known {
                generation: test_generation_id(gen_tag),
                artifact: ArtifactRef {
                    release: test_release_id(&format!("rel-{tree}")),
                    variant: VariantName::new("standard"),
                    tree: TreeDigest::new(tree.to_string()),
                },
                last_deployment: test_deployment_id(dep),
                owner: crate::remote::helper::test_owner("test-app", "p1"),
                version: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            },
        }
    }

    /// A server record whose `last_observed` names `tree` (the server
    /// record's artifact reference is checked like the slot record's).
    fn server_state(id: ServerId, tree: &str, dep: &str) -> ServerState {
        ServerState {
            id,
            last_seen_target: TargetName::parse("t1").unwrap(),
            last_observed: Some(observed_record(tree, &format!("gen-{dep}"), dep)),
        }
    }

    /// The fault kind of a mutable-record replacement stage.
    fn replace_kind(
        write: FaultKind,
        sync: FaultKind,
        rename: FaultKind,
        dir_sync: FaultKind,
        stage: ReplaceBoundary,
    ) -> FaultKind {
        match stage {
            ReplaceBoundary::Write => write,
            ReplaceBoundary::Sync => sync,
            ReplaceBoundary::Rename => rename,
            ReplaceBoundary::DirSync => dir_sync,
        }
    }

    /// The fault kind of a staged-publish stage.
    fn publish_kind(stage: PublishBoundary) -> FaultKind {
        match stage {
            PublishBoundary::Copy => FaultKind::StoreObjectCopy,
            PublishBoundary::Sync => FaultKind::StoreObjectSync,
            PublishBoundary::Rename => FaultKind::StoreObjectRename,
            PublishBoundary::DirSync => FaultKind::StoreObjectDirSync,
        }
    }

    /// THE BODY: one (boundary, old-present) case. Commit the old state via
    /// the SUCCESSFUL protocol, arm the boundary's fault on the fixture's
    /// own registry, perform the NEW write (which MUST fail at the
    /// boundary), REOPEN the store over the same base, and assert every
    /// resource is wholly old / wholly new / wholly absent — never partial,
    /// never a durable reference to missing content.
    fn run_crash_consistency_case(boundary: StoreBoundary, old_present: bool) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap();

        let slot = SlotId::new("p1".to_string());
        let server = ServerId::parse("s1").unwrap();
        let target = "t1";
        let old_tree_dir = dir.path().join("tree-old");
        let new_tree_dir = dir.path().join("tree-new");
        let old_tree = make_tree(&old_tree_dir, "old");
        let new_tree = make_tree(&new_tree_dir, "new");

        let obs_old = observed_record(&old_tree, "gen-old", "deploy-old");
        let obs_new = observed_record(&new_tree, "gen-new", "deploy-new");
        let server_old = server_state(server.clone(), &old_tree, "deploy-old");
        let server_new = server_state(server.clone(), &new_tree, "deploy-new");
        let debt_old: BTreeMap<String, String> =
            BTreeMap::from([("p1".to_string(), "old-reason".to_string())]);
        let debt_new: BTreeMap<String, String> =
            BTreeMap::from([("p1".to_string(), "new-reason".to_string())]);
        let sweep_old = Some(SweepDebt::Ready {
            target: TargetName::parse(target).unwrap(),
            retained_from: test_deployment_id("deploy-old"),
        });
        let sweep_new = Some(SweepDebt::AwaitingCheckpointDurability {
            target: TargetName::parse(target).unwrap(),
            retained_from: test_deployment_id("deploy-new"),
        });

        // The tree objects records may reference are stored FIRST via the
        // successful protocol — a durable record must never name missing
        // content. The OLD artifact's tree (when an old record exists) and,
        // for RECORD boundaries, the NEW artifact's tree (a post-commit
        // fault may leave the new record durable). The OBJECT boundaries
        // fault the NEW tree's PUBLISH itself, so it is deliberately NOT
        // pre-stored there.
        if old_present {
            store
                .store_object(&TreeDigest::new(old_tree.clone()), &old_tree_dir)
                .unwrap();
        }
        if !matches!(boundary, StoreBoundary::Object(_)) {
            store
                .store_object(&TreeDigest::new(new_tree.clone()), &new_tree_dir)
                .unwrap();
        }
        if old_present {
            store.write_slot_observed(&slot, &obs_old).unwrap();
            store.write_server(&server_old).unwrap();
            store
                .write_retention_debt(&TargetName::parse(target).unwrap(), &debt_old)
                .unwrap();
            store.write_sweep_debt(sweep_old.as_ref()).unwrap();
        }

        // Arm THIS boundary's fault on the fixture's own registry (the key
        // the faulted write consumes).
        let (kind, key): (FaultKind, &str) = match boundary {
            StoreBoundary::Observed(s) => (
                replace_kind(
                    FaultKind::ObservedReplaceWrite,
                    FaultKind::ObservedReplaceSync,
                    FaultKind::ObservedReplaceRename,
                    FaultKind::ObservedReplaceDirSync,
                    s,
                ),
                slot.as_str(),
            ),
            StoreBoundary::Server(s) => (
                replace_kind(
                    FaultKind::ServerReplaceWrite,
                    FaultKind::ServerReplaceSync,
                    FaultKind::ServerReplaceRename,
                    FaultKind::ServerReplaceDirSync,
                    s,
                ),
                server.as_str(),
            ),
            StoreBoundary::Debt(s) => (
                replace_kind(
                    FaultKind::RetentionDebtReplaceWrite,
                    FaultKind::RetentionDebtReplaceSync,
                    FaultKind::RetentionDebtReplaceRename,
                    FaultKind::RetentionDebtReplaceDirSync,
                    s,
                ),
                target,
            ),
            StoreBoundary::Sweep(s) => (
                replace_kind(
                    FaultKind::SweepDebtReplaceWrite,
                    FaultKind::SweepDebtReplaceSync,
                    FaultKind::SweepDebtReplaceRename,
                    FaultKind::SweepDebtReplaceDirSync,
                    s,
                ),
                "",
            ),
            StoreBoundary::Object(s) => (publish_kind(s), new_tree.as_str()),
        };
        store.fault_registry().arm(kind, key);

        // The faulted write MUST fail (the fault fires at the boundary).
        let res = match boundary {
            StoreBoundary::Observed(_) => store.write_slot_observed(&slot, &obs_new),
            StoreBoundary::Server(_) => store.write_server(&server_new),
            StoreBoundary::Debt(_) => {
                store.write_retention_debt(&TargetName::parse(target).unwrap(), &debt_new)
            }
            StoreBoundary::Sweep(_) => store.write_sweep_debt(sweep_new.as_ref()),
            StoreBoundary::Object(_) => {
                store.store_object(&TreeDigest::new(new_tree.clone()), &new_tree_dir)
            }
        };
        assert!(res.is_err(), "{boundary:?} must fail at its boundary");
        // The fault FIRED (was consumed) — the write actually reached the
        // intended boundary.
        assert_eq!(
            store.fault_registry().armed_len(),
            0,
            "{boundary:?} must consume its armed fault"
        );

        // REOPEN the store over the same base — the crash boundary.
        let reopened = LocalStore::with_base(base.clone()).unwrap();

        // THE FAULTED RESOURCE: wholly OLD (pre-commit fault), wholly NEW
        // (post-commit dir-sync fault — the new content IS visible under its
        // final name; the writer failed closed on the unconfirmed
        // durability), or wholly ABSENT (no old state + pre-commit fault).
        // NEVER partial: every read must PARSE (a torn record would fail
        // closed).
        match boundary {
            StoreBoundary::Observed(_) => {
                let read = reopened
                    .read_slot_observed(&slot)
                    .expect("the observed record must parse after a crash (never a torn record)");
                assert!(
                    read == Some(obs_old.clone())
                        || read == Some(obs_new.clone())
                        || (read.is_none() && !old_present),
                    "{boundary:?}: the observed record must be wholly old/new/absent, got {read:?}"
                );
            }
            StoreBoundary::Server(_) => {
                let p = reopened.base.join("servers").join("s1.json");
                if crate::store::atomic::path_state(&p).expect("stat must not fail") {
                    let read: ServerState = crate::store::atomic::read_json(&p)
                        .expect("the server record must parse after a crash (never a torn record)");
                    assert!(
                        read == server_old || read == server_new,
                        "{boundary:?}: the server record must be wholly old or new, got {read:?}"
                    );
                } else {
                    assert!(
                        !old_present,
                        "{boundary:?}: an absent server record requires an absent old state"
                    );
                }
            }
            StoreBoundary::Debt(_) => {
                let read = reopened
                    .read_retention_debt(&TargetName::parse(target).unwrap())
                    .expect(
                        "the retention-debt marker must parse after a crash (never a torn record)",
                    );
                assert!(
                    read == debt_old || read == debt_new || (read.is_empty() && !old_present),
                    "{boundary:?}: the retention-debt marker must be wholly old/new/absent, got {read:?}"
                );
            }
            StoreBoundary::Sweep(_) => {
                let read = reopened
                    .read_sweep_debt()
                    .expect("the sweep-debt marker must parse after a crash (never a torn record)");
                assert!(
                    read == sweep_old || read == sweep_new || (read.is_none() && !old_present),
                    "{boundary:?}: the sweep-debt marker must be wholly old/new/absent, got {read:?}"
                );
            }
            StoreBoundary::Object(_) => {
                let obj_dir = reopened
                    .base
                    .join(crate::remote::layout::objects())
                    .join(&new_tree);
                if crate::store::atomic::path_state(&obj_dir).expect("stat must not fail") {
                    reopened
                        .verify_object(&TreeDigest::new(new_tree.clone()), &obj_dir)
                        .expect("a present final object must be WHOLE (never a half-copied tree)");
                }
                // Absent is fine: a pre-publish fault leaves the final
                // location wholly ABSENT (at most a disposable dot-prefixed
                // staging dir, invisible to every read).
            }
        }

        // EVERY OTHER resource is untouched by the faulted write: still
        // wholly OLD (or wholly absent when the old state was never
        // committed).
        if !matches!(boundary, StoreBoundary::Observed(_)) {
            let read = reopened.read_slot_observed(&slot).unwrap();
            assert_eq!(
                read,
                if old_present {
                    Some(obs_old.clone())
                } else {
                    None
                },
                "{boundary:?} must not touch the observed record"
            );
        }
        if !matches!(boundary, StoreBoundary::Server(_)) {
            let p = reopened.base.join("servers").join("s1.json");
            if crate::store::atomic::path_state(&p).expect("stat must not fail") {
                let read: ServerState =
                    crate::store::atomic::read_json(&p).expect("the server record must parse");
                assert_eq!(
                    read, server_old,
                    "{boundary:?} must not touch the server record"
                );
            } else {
                assert!(
                    !old_present,
                    "{boundary:?} must not touch the server record"
                );
            }
        }
        if !matches!(boundary, StoreBoundary::Debt(_)) {
            let read = reopened
                .read_retention_debt(&TargetName::parse(target).unwrap())
                .unwrap();
            assert_eq!(
                read,
                if old_present {
                    debt_old.clone()
                } else {
                    BTreeMap::new()
                },
                "{boundary:?} must not touch the retention-debt marker"
            );
        }
        if !matches!(boundary, StoreBoundary::Sweep(_)) {
            let read = reopened.read_sweep_debt().unwrap();
            assert_eq!(
                read,
                if old_present { sweep_old.clone() } else { None },
                "{boundary:?} must not touch the sweep-debt marker"
            );
        }
        // The OLD object (when committed) survives untouched; the NEW object
        // is wholly absent or wholly present — never partial.
        let old_obj_dir = reopened
            .base
            .join(crate::remote::layout::objects())
            .join(&old_tree);
        if old_present {
            reopened
                .verify_object(&TreeDigest::new(old_tree.clone()), &old_obj_dir)
                .expect("the old object must survive untouched");
        } else {
            assert!(
                !crate::store::atomic::path_state(&old_obj_dir).expect("stat must not fail"),
                "{boundary:?}: no old object may exist without an old state"
            );
        }
        if !matches!(boundary, StoreBoundary::Object(_)) {
            let new_obj_dir = reopened
                .base
                .join(crate::remote::layout::objects())
                .join(&new_tree);
            reopened
                .verify_object(&TreeDigest::new(new_tree.clone()), &new_obj_dir)
                .expect("the pre-stored new object must survive untouched");
        }

        // NEVER A DURABLE REFERENCE TO MISSING CONTENT: every observed
        // record that survived the crash names a tree object that is
        // PRESENT and whole.
        for rec in reopened.read_global_observed().unwrap().values() {
            if let ObservedAssignment::Known { artifact, .. } = &rec.assignment {
                let obj_dir = reopened
                    .base
                    .join(crate::remote::layout::objects())
                    .join(artifact.tree.as_str());
                reopened
                    .verify_object(
                        &TreeDigest::new(artifact.tree.as_str().to_string()),
                        &obj_dir,
                    )
                    .expect("a durable observed record must name a present, whole object");
            }
        }
        let server_path = reopened.base.join("servers").join("s1.json");
        if crate::store::atomic::path_state(&server_path).expect("stat must not fail") {
            let read: ServerState = crate::store::atomic::read_json(&server_path)
                .expect("the server record must parse");
            if let Some(ObservedSlot {
                slot: _,
                assignment: ObservedAssignment::Known { artifact, .. },
                ..
            }) = read.last_observed
            {
                let obj_dir = reopened
                    .base
                    .join(crate::remote::layout::objects())
                    .join(artifact.tree.as_str());
                reopened
                    .verify_object(
                        &TreeDigest::new(artifact.tree.as_str().to_string()),
                        &obj_dir,
                    )
                    .expect("a durable server record must name a present, whole object");
            }
        }
    }

    /// EXHAUSTIVE acceptance: every filesystem boundary of every store write
    /// protocol, with and without a pre-existing old state, is faulted, the
    /// store is reopened, and every resource is required to be wholly old /
    /// wholly new / wholly absent — never partial, never a durable
    /// reference to missing content.
    #[test]
    fn crash_consistency_every_boundary_exhaustive() {
        for boundary in ALL_BOUNDARIES {
            for old_present in [true, false] {
                run_crash_consistency_case(boundary, old_present);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE HOUSE-STYLE RANDOMIZED VIEW of the same property: a fault at
        /// ANY boundary (with or without an old state) leaves every resource
        /// wholly old / wholly new / wholly absent after a reopen — the
        /// deterministic exhaustive loop above guarantees every boundary;
        /// this sampling explores the same invariant surface randomly.
        #[test]
        fn store_crash_consistency_every_boundary(
            idx in 0u32..ALL_BOUNDARIES.len() as u32,
            old_present in prop::bool::ANY,
        ) {
            run_crash_consistency_case(ALL_BOUNDARIES[idx as usize], old_present);
        }
    }

    // -------------------------------------------------------------------
    // THE EMBEDDED-IDENTITY BINDING PROPERTY (the review's acceptance):
    // write valid records for two DISTINCT keys of every keyed record
    // family (releases, tree objects, servers, slot observed state,
    // retention debt, deployment plans), PERMUTE each record file into the
    // OTHER key's storage path, and require every non-identity permutation
    // to FAIL — the read returns an integrity error naming both identities
    // (a record swapped into the wrong storage location is never returned
    // as if it were the requested key), and the write refuses to persist a
    // record under a key its embedded identity does not match. The identity
    // permutation (each record at its own key's path) succeeds. Bounded 16
    // cases, fixed seed 0x5EED_5EED per house style.
    // -------------------------------------------------------------------

    /// A valid release record whose identity digest is derived from `tag`
    /// (distinct tags => distinct release ids).
    fn release_fixture(tag: &str) -> ReleaseRecord {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), test_tree_digest(tag))]);
        let slots: BTreeMap<String, Vec<crate::config::SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![crate::config::SlotConfig::new(
                "p1".to_string(),
                "s1".to_string(),
                std::path::PathBuf::from("/srv/deploy/p1"),
                "t1".to_string(),
                Vec::new(),
            )],
        )]);
        crate::verify::release::build_release(
            "m",
            crate::identity::DIGEST_TEST_HEX_1,
            &variants,
            &slots,
            std::path::Path::new("."),
        )
    }

    /// An `Absent` observed record carrying its own slot identity (the
    /// storage key it is bound to).
    fn observed_for_slot(slot: &SlotId) -> ObservedSlot {
        ObservedSlot {
            slot: slot.clone(),
            assignment: ObservedAssignment::Absent,
        }
    }

    /// A minimal valid plan for one slot carrying the given deployment id.
    fn plan_fixture(id: &DeploymentId) -> DeploymentPlan {
        let slot = SlotId::parse("p1").unwrap();
        let mut slots = BTreeMap::new();
        slots.insert(
            slot.clone(),
            SlotPlan {
                slot_id: slot,
                artifact: ArtifactRef {
                    release: test_release_id("r"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("t"),
                },
                expected_generation: Some(test_generation_id("g")),
            },
        );
        DeploymentPlan::new(
            id.clone(),
            TargetName::parse("t1").unwrap(),
            BehaviorIndex::new(),
            slots,
            PlanOrigin::Head,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE EMBEDDED-IDENTITY BINDING PROPERTY (the review's acceptance):
        /// write valid records for two DISTINCT keys of every keyed record
        /// family, PERMUTE each record file into the OTHER key's storage
        /// path, and require every non-identity permutation to FAIL — the
        /// read returns an integrity error naming both identities, and the
        /// write refuses to persist a record under a key its embedded
        /// identity does not match. The identity permutation (each record at
        /// its own key's path) succeeds.
        #[test]
        fn permuted_records_fail_the_embedded_identity_binding(
            tag_a in "[a-z0-9]{1,8}",
            tag_b in "[a-z0-9]{1,8}",
        ) {
            prop_assume!(tag_a != tag_b);
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();

            // ---- releases: `releases/<id>/release.json` embeds
            // `release_id` (the read-side binding; the write derives its key
            // from the record's own id, so a mismatched write is
            // structurally unrepresentable)
            {
                let rec_a = release_fixture(&tag_a);
                let rec_b = release_fixture(&tag_b);
                let id_a = ReleaseId::new(rec_a.release_id.clone());
                let id_b = ReleaseId::new(rec_b.release_id.clone());
                prop_assume!(id_a != id_b);
                store.write_release(&rec_a).unwrap();
                store.write_release(&rec_b).unwrap();
                // The identity permutation succeeds.
                store.read_release(&id_a).unwrap();
                // Permute: move A's record into B's path.
                let path_a = store.release_dir(&id_a).join("release.json");
                let path_b = store.release_dir(&id_b).join("release.json");
                std::fs::rename(&path_a, &path_b).unwrap();
                // The non-identity permutation FAILS (integrity, naming both
                // identities).
                let err = store.read_release(&id_b).expect_err(
                    "a release record swapped into the wrong release directory must fail",
                );
                assert!(
                    err.to_string()
                        .contains("does not match the requested release id"),
                    "the refusal must name the identity binding, got: {err}"
                );
            }

            // ---- tree objects: `objects/sha256/<digest>/tree.json` embeds
            // `tree_sha256` (the read-side binding; the write verifies the
            // staged tree canonicalizes to the digest before publishing)
            {
                let tree_dir_a = dir.path().join("tree-a");
                let tree_dir_b = dir.path().join("tree-b");
                let tree_a = make_tree(&tree_dir_a, &tag_a);
                let tree_b = make_tree(&tree_dir_b, &tag_b);
                let digest_a = TreeDigest::new(tree_a.clone());
                let digest_b = TreeDigest::new(tree_b.clone());
                prop_assume!(digest_a != digest_b);
                store.store_object(&digest_a, &tree_dir_a).unwrap();
                store.store_object(&digest_b, &tree_dir_b).unwrap();
                // The identity permutation succeeds.
                store.read_tree_meta(&digest_a).unwrap();
                // Permute: move A's tree.json into B's path.
                let path_a = store.object_tree_json(&digest_a);
                let path_b = store.object_tree_json(&digest_b);
                std::fs::rename(&path_a, &path_b).unwrap();
                // The non-identity permutation FAILS.
                let err = store.read_tree_meta(&digest_b).expect_err(
                    "a tree metadata record swapped into the wrong digest's directory must fail",
                );
                assert!(
                    err.to_string().contains("does not match"),
                    "the refusal must name the identity binding, got: {err}"
                );
            }

            // ---- servers: `servers/<id>.json` embeds `id` (the read-side
            // binding; the write derives its key from the record's own id)
            {
                let server_a = ServerId::parse(&tag_a).unwrap();
                let server_b = ServerId::parse(&tag_b).unwrap();
                let state_a = ServerState {
                    id: server_a.clone(),
                    last_seen_target: TargetName::parse("t1").unwrap(),
                    last_observed: None,
                };
                let state_b = ServerState {
                    id: server_b.clone(),
                    last_seen_target: TargetName::parse("t1").unwrap(),
                    last_observed: None,
                };
                store.write_server(&state_a).unwrap();
                store.write_server(&state_b).unwrap();
                // The identity permutation succeeds.
                store.read_server(&server_a).unwrap();
                // Permute: move A's record into B's path.
                let path_a = store
                    .base
                    .join("servers")
                    .join(format!("{}.json", server_a.as_str()));
                let path_b = store
                    .base
                    .join("servers")
                    .join(format!("{}.json", server_b.as_str()));
                std::fs::rename(&path_a, &path_b).unwrap();
                // The non-identity permutation FAILS.
                let err = store
                    .read_server(&server_b)
                    .expect_err("a server record swapped into the wrong server file must fail");
                assert!(
                    err.to_string().contains("does not match"),
                    "the refusal must name the identity binding, got: {err}"
                );
            }

            // ---- slot observed state: `slots/<slot>/observed.json` embeds
            // `slot` (BOTH directions: the read refuses a swapped record and
            // the write refuses a record whose embedded identity differs
            // from the key)
            {
                let slot_a = SlotId::parse(&tag_a).unwrap();
                let slot_b = SlotId::parse(&tag_b).unwrap();
                let obs_a = observed_for_slot(&slot_a);
                let obs_b = observed_for_slot(&slot_b);
                store.write_slot_observed(&slot_a, &obs_a).unwrap();
                store.write_slot_observed(&slot_b, &obs_b).unwrap();
                // The identity permutation succeeds.
                store.read_slot_observed(&slot_a).unwrap();
                // The write REFUSES a record whose embedded identity differs
                // from the key it is written under.
                let err = store.write_slot_observed(&slot_b, &obs_a).expect_err(
                    "a write of a record under a key its embedded identity does not match must refuse",
                );
                assert!(
                    err.to_string().contains("does not match its storage key"),
                    "the refusal must name the identity binding, got: {err}"
                );
                // Permute: move A's record into B's path.
                let path_a = store.slot_observed_path(&slot_a);
                let path_b = store.slot_observed_path(&slot_b);
                std::fs::rename(&path_a, &path_b).unwrap();
                // The non-identity permutation FAILS.
                let err = store.read_slot_observed(&slot_b).expect_err(
                    "an observed record swapped into the wrong slot directory must fail",
                );
                assert!(
                    err.to_string().contains("does not match"),
                    "the refusal must name the identity binding, got: {err}"
                );
            }

            // ---- retention debt: `targets/<target>/retention-debt.json`
            // embeds `target` (the read-side binding; the write builds the
            // record from the key, so a mismatched write is structurally
            // unrepresentable)
            {
                let target_a = TargetName::parse(&tag_a).unwrap();
                let target_b = TargetName::parse(&tag_b).unwrap();
                let debt_a = BTreeMap::from([("p1".to_string(), format!("reason-{tag_a}"))]);
                let debt_b = BTreeMap::from([("p1".to_string(), format!("reason-{tag_b}"))]);
                store.write_retention_debt(&target_a, &debt_a).unwrap();
                store.write_retention_debt(&target_b, &debt_b).unwrap();
                // The identity permutation succeeds.
                store.read_retention_debt(&target_a).unwrap();
                // Permute: move A's marker into B's path.
                let path_a = store.retention_debt_path(&target_a);
                let path_b = store.retention_debt_path(&target_b);
                std::fs::rename(&path_a, &path_b).unwrap();
                // The non-identity permutation FAILS.
                let err = store.read_retention_debt(&target_b).expect_err(
                    "a retention-debt marker swapped into the wrong target's directory must fail",
                );
                assert!(
                    err.to_string().contains("does not match"),
                    "the refusal must name the identity binding, got: {err}"
                );
            }

            // ---- deployment plans: `deployments/<id>/plan.json` embeds
            // `deployment_id` (write-only — the write refuses a mismatched
            // embedded identity)
            {
                let id_a = test_deployment_id(&format!("deploy-{tag_a}"));
                let id_b = test_deployment_id(&format!("deploy-{tag_b}"));
                prop_assume!(id_a != id_b);
                let plan_a = plan_fixture(&id_a);
                let plan_b = plan_fixture(&id_b);
                store.write_plan(&id_a, &plan_a).unwrap();
                store.write_plan(&id_b, &plan_b).unwrap();
                // The identity permutation succeeds (idempotent rewrite).
                store.write_plan(&id_a, &plan_a).unwrap();
                // The write REFUSES a plan whose embedded deployment id
                // differs from the key it is written under.
                let err = store.write_plan(&id_b, &plan_a).expect_err(
                    "a write of a plan under a key its embedded identity does not match must refuse",
                );
                assert!(
                    err.to_string().contains("does not match its storage key"),
                    "the refusal must name the identity binding, got: {err}"
                );
            }
        }
    }
}

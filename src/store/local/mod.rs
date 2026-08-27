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
use crate::store::atomic::{ensure_private_dir, set_private};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::identity::DeploymentId;
#[cfg(test)]
use crate::testutil::step17_hook::Step17Hook;
#[cfg(test)]
use crate::testutil::test_faults::FaultRegistry;
#[cfg(test)]
use std::sync::Arc;

pub(crate) use self::layout::default_base;

pub mod debt;
pub mod deployments;
pub mod layout;
pub mod ledger;
pub mod objects;
pub mod observed;
pub mod pins;
pub mod releases;

pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
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
pub(crate) fn write_atomic_cas(path: &Path, bytes: &[u8]) -> Result<()> {
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
    pub(crate) base: PathBuf,
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
    pub fn new_in(env: &SysEnv, application: &ApplicationStoreKey) -> Result<LocalStore> {
        let base = default_base(env).join(application.as_str());
        Self::with_base(base)
    }

    /// Create a store rooted at an explicit base (used in tests).
    pub fn with_base(base: PathBuf) -> Result<LocalStore> {
        ensure_private_dir(&base)?;
        ensure_private_dir(&base.join(remote_layout::objects()))?;
        ensure_private_dir(&base.join(remote_layout::RELEASES))?;
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
    use crate::identity::{
        ArtifactRef, SlotId, VariantName, test_deployment_id, test_generation_id, test_tree_digest,
    };
    use crate::ledger::{Observation, ObservedSlot, ObservedState};
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
            observation: Observation::Known(ObservedState {
                generation: test_generation_id("evil"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-sha256-evil"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("evil"),
                },
                last_deployment: test_deployment_id("evil"),
            }),
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
}

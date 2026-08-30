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
#[cfg(not(test))]
use crate::store::atomic::write_atomic_replace;
use crate::store::atomic::{ReplaceOutcome, ensure_private_dir, set_private, sync_parent_dir};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::identity::DeploymentId;
#[cfg(test)]
use crate::store::atomic::{ReplaceStage, write_atomic_replace_impl};
#[cfg(test)]
use crate::testutil::step17_hook::Step17Hook;
#[cfg(test)]
use crate::testutil::test_faults::{FaultKind, FaultRegistry};
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

/// Durably write a MUTABLE JSON record via the atomic-replace protocol
/// ([`crate::store::atomic::write_atomic_replace`]: unique temp in the
/// same directory → write → fsync → chmod private → atomic rename →
/// parent-directory fsync). A reader never observes a torn record (the
/// rename is atomic on POSIX — wholly old or wholly new).
///
/// FAIL CLOSED ON UNCONFIRMED DURABILITY: a
/// [`ReplaceOutcome::ReplacedDurabilityUnknown`] outcome — the new record
/// IS visible but the parent-directory fsync failed — is DOWNGRADED to
/// `Err`, never reported as success (the pins-write precedent
/// [`LocalStore::write_pins`]): the caller has no facility to report
/// "visible but unconfirmed", so failure is the only safe answer.
#[cfg(not(test))]
pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::store(format!("serialize {}: {e}", path.display())))?;
    match write_atomic_replace(path, &bytes)? {
        ReplaceOutcome::ReplacedDurable => Ok(()),
        ReplaceOutcome::ReplacedDurabilityUnknown { error } => Err(error),
    }
}

/// TEST-ONLY seam: the same atomic JSON-record write as [`write_json`] with
/// a per-stage fault hook, so a per-fixture registry can inject a failure
/// at EVERY atomic-replacement stage ([`ReplaceStage`]) of a mutable
/// record write (the `write_slot_observed` / `write_server` /
/// `write_retention_debt` / `write_sweep_debt` writers) and the property
/// can assert the stage→outcome mapping. Not part of the production
/// surface — production builds keep the exact `write_json` signature.
#[cfg(test)]
pub(crate) fn write_json_seam<T: Serialize>(
    path: &Path,
    value: &T,
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::store(format!("serialize {}: {e}", path.display())))?;
    match write_atomic_replace_impl(path, &bytes, fault)? {
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
    // THE DURABILITY COMMIT POINT — FAIL CLOSED: the parent-directory
    // open/fsync failure must PROPAGATE (never a silent `Ok` — the new
    // content IS installed under its final name, but its durability across
    // power loss is UNCONFIRMED, and reporting durable success for an
    // unsynced directory entry would be a false durability claim). The
    // installed file stays (create-or-compare: a retry sees the identical
    // content and is an idempotent success), exactly like the ledger
    // append's post-rename dir-sync contract.
    sync_parent_dir(path)?;
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
        ApplicationStoreKey, ArtifactRef, ServerId, SlotId, TargetName, TreeDigest, VariantName,
        test_deployment_id, test_generation_id, test_release_id, test_tree_digest,
    };
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
            assignment: ObservedAssignment::Known {
                generation: test_generation_id("evil"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-sha256-evil"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("evil"),
                },
                last_deployment: test_deployment_id("evil"),
                owner: Some(crate::remote::helper::test_owner("test-app", "evil")),
                version: Some("2026-01-01T00:00:00Z".to_string()),
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
                    store.deployment_dir(dep_a.as_str()),
                    store.deployment_dir(dep_b.as_str()),
                    "distinct deployment ids must map to distinct dirs"
                );
            } else {
                assert_eq!(
                    store.deployment_dir(dep_a.as_str()),
                    store.deployment_dir(dep_b.as_str()),
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
            assignment: ObservedAssignment::Known {
                generation: test_generation_id(gen_tag),
                artifact: ArtifactRef {
                    release: test_release_id(&format!("rel-{tree}")),
                    variant: VariantName::new("standard"),
                    tree: TreeDigest::new(tree.to_string()),
                },
                last_deployment: test_deployment_id(dep),
                owner: Some(crate::remote::helper::test_owner("test-app", "p1")),
                version: Some("2026-01-01T00:00:00Z".to_string()),
            },
        }
    }

    /// A server record whose `last_observed` names `tree` (the server
    /// record's artifact reference is checked like the slot record's).
    fn server_state(id: ServerId, tree: &str, dep: &str) -> ServerState {
        ServerState {
            id,
            last_seen_target: Some(TargetName::parse("t1").unwrap()),
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
            store.write_retention_debt(target, &debt_old).unwrap();
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
            StoreBoundary::Debt(_) => store.write_retention_debt(target, &debt_new),
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
                let read = reopened.read_retention_debt(target).expect(
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
            let read = reopened.read_retention_debt(target).unwrap();
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
}

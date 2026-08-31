//! THE DURABILITY CRASH/FAILURE MODEL for the five durable remote mutations
//! ([`HeldSlotLock::durable_publish_tree`],
//! [`HeldSlotLock::durable_publish_release`],
//! [`HeldSlotLock::durable_generation_install`],
//! [`RemoteHelper::durable_record_replace`],
//! [`HeldSlotLock::durable_symlink_swap`]).
//!
//! Each durable mutation follows the protocol **stage → fsync contents →
//! rename → fsync every changed parent directory**, and reports success ONLY
//! after the parent-directory fsync succeeds (fail closed: a parent-fsync
//! failure is an `Err`, never a reported success). The property below
//! injects a one-shot failure/crash at EVERY boundary of each protocol — each
//! write, each fsync, each rename, each parent-fsync (and the symlink-swap's
//! stage step) — and asserts that REOPENING the remote observes either the
//! COMPLETE OLD state or the COMPLETE NEW state, never a torn/partial state.
//!
//! The fault is a per-fixture one-shot arm on a transport wrapper
//! ([`DurableFaultRemote`], the house pattern — never a process-global slot,
//! so two fixtures' faults can never interact). The fault is armed AFTER the
//! slot lock is acquired, so the lock's own durable create-new can never
//! consume it; the operation then runs exactly once and the remote is
//! re-opened and inspected.

use crate::error::{Error, Result};
use crate::identity::{
    ArtifactRef, TargetName, VariantName, test_deployment_id, test_generation_id,
    test_operation_id, test_release_id, test_tree_digest,
};
use crate::remote::helper::{
    ExpectedCurrent, GenerationAssignment, GenerationOwner, GenerationSpec, RemoteHelper,
    SlotRemote,
};
use crate::remote::layout;
use crate::remote::transport::{
    CreateNewVerdict, ExecOutcome, FsBytes, LocalTransport, Remote, RemoteEntry, RemoteMeta,
    RootedRelativePath,
};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use std::path::Path;

/// The durability boundary to fault: each write, each fsync, each rename,
/// each parent-fsync — plus the symlink-swap's stage step (a symlink has no
/// content to write/fsync; its stage is the atomic `symlink(2)` that creates
/// the temp link). The fault is armed for EXACTLY ONE matching operation and
/// fires ONCE (then disarms), per fixture (owned by the wrapper, never a
/// process-global slot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableFault {
    /// Fail the next `write` (a staged member/record write).
    Write,
    /// Fail the next `fsync_tree` (the staged-contents fsync).
    Fsync,
    /// Fail the next `rename` (the atomic install).
    Rename,
    /// Fail the next `fsync_parent` (the parent-directory fsync).
    ParentFsync,
    /// Fail the next `symlink` (the symlink-swap's stage step).
    Symlink,
}

/// A transport wrapper that fails EXACTLY ONE matching durability operation
/// once, letting the durability proptests fault every boundary of every
/// durable mutation deterministically. The fault is per-fixture (owned by the
/// wrapper, never a process-global slot); a non-matching call passes through
/// untouched.
struct DurableFaultRemote {
    inner: LocalTransport,
    fault: std::sync::Mutex<Option<DurableFault>>,
}

impl DurableFaultRemote {
    fn new(env: &crate::env::SysEnv, base: std::path::PathBuf) -> Result<Self> {
        Ok(DurableFaultRemote {
            inner: LocalTransport::new(env, base)?,
            fault: std::sync::Mutex::new(None),
        })
    }

    /// Arm the one-shot fault (called AFTER the slot lock is acquired, so the
    /// lock's own durable create-new can never consume it).
    fn arm(&self, fault: DurableFault) {
        *self.fault.lock().unwrap() = Some(fault);
    }

    /// Consume the fault if it matches `kind`; returns `true` when it fired
    /// (and disarmed).
    fn consume(&self, kind: DurableFault) -> bool {
        let mut f = self.fault.lock().unwrap();
        match f.as_ref() {
            Some(k) if *k == kind => {
                *f = None;
                true
            }
            _ => false,
        }
    }
}

impl Remote for DurableFaultRemote {
    fn root(&self) -> &Path {
        self.inner.root()
    }
    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        self.inner.read(rel)
    }
    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        if self.consume(DurableFault::Write) {
            return Err(Error::remote(
                "DurableFaultRemote: write forced to fail (once)",
            ));
        }
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
        self.inner.try_write_new(rel, data)
    }
    fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        self.inner.create_dir(rel)
    }
    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        self.inner.create_dir_all(rel)
    }
    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        self.inner.set_mode(rel, mode)
    }
    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        self.inner.list(rel)
    }
    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        if self.consume(DurableFault::Rename) {
            return Err(Error::remote(
                "DurableFaultRemote: rename forced to fail (once)",
            ));
        }
        self.inner.rename(from, to)
    }
    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        if self.consume(DurableFault::Symlink) {
            return Err(Error::remote(
                "DurableFaultRemote: symlink forced to fail (once)",
            ));
        }
        self.inner.symlink(target, link)
    }
    fn read_link(&self, rel: &RootedRelativePath) -> Result<std::path::PathBuf> {
        self.inner.read_link(rel)
    }
    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        self.inner.remove_file(rel)
    }
    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        self.inner.remove_dir_all(rel)
    }
    fn fsync_tree(&self, rel: &RootedRelativePath) -> Result<()> {
        if self.consume(DurableFault::Fsync) {
            return Err(Error::remote(
                "DurableFaultRemote: fsync forced to fail (once)",
            ));
        }
        self.inner.fsync_tree(rel)
    }
    fn fsync_parent(&self, rel: &RootedRelativePath) -> Result<()> {
        if self.consume(DurableFault::ParentFsync) {
            return Err(Error::remote(
                "DurableFaultRemote: parent fsync forced to fail (once)",
            ));
        }
        self.inner.fsync_parent(rel)
    }
    fn exists(&self, rel: &RootedRelativePath) -> bool {
        self.inner.exists(rel)
    }
    fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
        self.inner.metadata(rel)
    }
    fn exec(&self, argv: &[String], timeout: std::time::Duration) -> Result<ExecOutcome> {
        self.inner.exec(argv, timeout)
    }
    fn filesystem_bytes(&self) -> Result<FsBytes> {
        self.inner.filesystem_bytes()
    }
}

/// The expected owner the fixture records carry: application `test-app`,
/// slot `s1` (the same owner the status/read paths verify against).
fn owner() -> GenerationOwner {
    crate::remote::helper::test_owner("test-app", "s1")
}

/// The durability boundary strategy for the staged operations: each write,
/// each fsync, each rename, each parent-fsync.
fn durable_fault() -> impl Strategy<Value = DurableFault> {
    prop_oneof![
        Just(DurableFault::Write),
        Just(DurableFault::Fsync),
        Just(DurableFault::Rename),
        Just(DurableFault::ParentFsync),
    ]
}

/// The durability boundary strategy for the symlink swap: the stage step
/// (the temp `symlink(2)`), the rename, and the parent-fsync (a symlink has
/// no content to write/fsync).
fn swap_fault() -> impl Strategy<Value = DurableFault> {
    prop_oneof![
        Just(DurableFault::Symlink),
        Just(DurableFault::Rename),
        Just(DurableFault::ParentFsync),
    ]
}

/// A small deterministic host tree (a file, a nested file) whose canonical
/// digest is the publish target.
fn build_host_tree(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a"), b"alpha\n").unwrap();
    std::fs::write(root.join("sub/b"), b"beta\n").unwrap();
}

/// A generation spec for `gen_id` (the fixture shape the current/assignment
/// tests use).
fn generation_spec(gen_id: &crate::identity::GenerationId) -> GenerationSpec {
    GenerationSpec {
        deployment_id: test_deployment_id("deploy-1"),
        generation_id: gen_id.clone(),
        artifact: ArtifactRef {
            release: test_release_id("rel-sha256-x"),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest("tree-a"),
        },
        behavior_sha256: crate::identity::test_behavior_digest("b"),
        prior_generation: None,
        created_at: crate::identity::Timestamp::parse("2020-01-01T00:00:00Z").unwrap(),
        target: TargetName::new("t1"),
    }
}

proptest! {
    // THE DURABILITY PROPERTY — one property per durable mutation, every
    // boundary: a one-shot fault at each write, each fsync, each rename,
    // each parent-fsync (and the swap's stage step); REOPENING the remote
    // must observe either the COMPLETE OLD state or the COMPLETE NEW state,
    // never a torn/partial state. Bounded 16 cases, fixed seed 0x5EED_5EED
    // (house style), no failure persistence.
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(16),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// `durable_publish_tree`: after a publish under a fault at EVERY
    /// boundary (each staged write, the staged fsync, the atomic install
    /// rename, each parent fsync), the digest path is either WHOLLY ABSENT
    /// (the complete old state) or contains EXACTLY the required canonical
    /// tree (the complete new state) — never a partial/corrupt object.
    #[test]
    fn durable_publish_tree_reopens_old_or_new(fault in durable_fault()) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote = DurableFaultRemote::new(
            &crate::testutil::fixture_env(),
            dir.path().join("remote"),
        )
        .unwrap();
        let helper = RemoteHelper::new(&remote);
        let host = dir.path().join("host");
        build_host_tree(&host);
        let host_meta = crate::remote::canonical::canonicalize_tree(&host).unwrap();
        let digest = crate::identity::TreeDigest::parse(&host_meta.tree_sha256).unwrap();

        // Acquire the lock BEFORE arming the fault (the lock's own durable
        // create-new must never consume it).
        let held = SlotRemote::new(&helper, owner())
            .acquire_lock_guard(&test_operation_id("op-1"))
            .unwrap();
        remote.arm(fault);
        let _ = held.durable_publish_tree(&digest, &host);
        drop(held);

        // THE PROPERTY: reopening observes either the complete old state (no
        // tree at the digest path) or the complete new state (the digest
        // path canonicalizes to the digest) — never a torn/partial object.
        let final_path = remote.root().join(layout::tree_root(&digest));
        match std::fs::symlink_metadata(&final_path) {
            Err(_) => {}
            Ok(_) => {
                let meta = crate::remote::canonical::canonicalize_tree(&final_path)
                    .expect("a present digest path must canonicalize (the complete new state)");
                prop_assert_eq!(
                    meta.tree_sha256,
                    digest.as_str(),
                    "a present digest path must carry exactly the required canonical tree"
                );
            }
        }
    }

    /// `durable_publish_release`: after a publish under a fault at EVERY
    /// boundary (each member write, the staged fsync, the atomic install
    /// rename, the parent fsync), the final release directory is either
    /// WHOLLY ABSENT (the complete old state) or COMPLETE AND READABLE (the
    /// complete new state) — never a partial directory.
    #[test]
    fn durable_publish_release_reopens_old_or_new(fault in durable_fault()) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote = DurableFaultRemote::new(
            &crate::testutil::fixture_env(),
            dir.path().join("remote"),
        )
        .unwrap();
        let helper = RemoteHelper::new(&remote);
        let bundle = super::mutation::publish::tests_publish::publish_fixture_bundle();

        let held = SlotRemote::new(&helper, owner())
            .acquire_lock_guard(&test_operation_id("op-1"))
            .unwrap();
        remote.arm(fault);
        let _ = held.durable_publish_release(&bundle);
        drop(held);

        // THE PROPERTY: the final release directory is either wholly absent
        // or complete and readable — never a partial directory.
        let final_path = remote.root().join(layout::remote_release(bundle.release_id()));
        match std::fs::symlink_metadata(&final_path) {
            Err(_) => {}
            Ok(_) => {
                let release_json = std::fs::read(final_path.join("release.json"))
                    .expect("a present release directory must carry a readable release.json");
                let rec: crate::identity::ReleaseRecord = serde_json::from_slice(&release_json)
                    .expect("a present release directory must carry a parseable release.json");
                crate::verify::release::verify_release_identity(&rec).expect(
                    "a present release directory must carry an identity-verified record",
                );
                let behavior_json = std::fs::read(final_path.join("behavior.json")).expect(
                    "a present release directory must carry a readable behavior.json",
                );
                crate::verify::release::verify_behavior_json(
                    &behavior_json,
                    &rec.release_id,
                    &rec.provenance.behavior_sha256,
                )
                .expect(
                    "a present release directory must carry a digest-consistent behavior.json",
                );
            }
        }
    }

    /// `durable_generation_install`: after an install under a fault at EVERY
    /// boundary (each staged write, the staged fsync, the atomic install
    /// rename, the parent fsync), the generation directory is either WHOLLY
    /// ABSENT (the complete old state) or COMPLETE (the assignment parses
    /// with the matching generation id and owner marker, and the `root`
    /// symlink is present) — never a partial generation.
    #[test]
    fn durable_generation_install_reopens_old_or_new(fault in durable_fault()) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote = DurableFaultRemote::new(
            &crate::testutil::fixture_env(),
            dir.path().join("remote"),
        )
        .unwrap();
        let helper = RemoteHelper::new(&remote);
        let spec = generation_spec(&test_generation_id("gen-1"));

        let held = SlotRemote::new(&helper, owner())
            .acquire_lock_guard(&test_operation_id("op-1"))
            .unwrap();
        remote.arm(fault);
        let _ = held.durable_generation_install(&spec);
        drop(held);

        // THE PROPERTY: the generation directory is either wholly absent or
        // complete — never a partial generation.
        let gen_dir = remote.root().join(layout::generation(&spec.generation_id));
        match std::fs::symlink_metadata(&gen_dir) {
            Err(_) => {}
            Ok(_) => {
                let assignment = std::fs::read(gen_dir.join("assignment.json"))
                    .expect("a present generation must carry a readable assignment.json");
                let a: GenerationAssignment = serde_json::from_slice(&assignment)
                    .expect("a present generation must carry a parseable assignment.json");
                prop_assert_eq!(
                    a.generation_id,
                    spec.generation_id,
                    "a present generation must carry the matching generation id"
                );
                prop_assert_eq!(
                    a.application,
                    owner().application,
                    "a present generation must carry the guard's owner marker (application)"
                );
                prop_assert_eq!(
                    a.slot,
                    owner().slot,
                    "a present generation must carry the guard's owner marker (slot)"
                );
                let root_meta = std::fs::symlink_metadata(gen_dir.join("root"))
                    .expect("a present generation must carry its root symlink");
                prop_assert!(
                    root_meta.file_type().is_symlink(),
                    "a present generation's root entry must be a symlink"
                );
            }
        }
    }

    /// `durable_record_replace`: after a replace under a fault at EVERY
    /// boundary (the temp write, the temp fsync, the atomic rename, the
    /// parent fsync), the record is either the COMPLETE OLD bytes or the
    /// COMPLETE NEW bytes — never torn/partial.
    #[test]
    fn durable_record_replace_reopens_old_or_new(fault in durable_fault()) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote = DurableFaultRemote::new(
            &crate::testutil::fixture_env(),
            dir.path().join("remote"),
        )
        .unwrap();
        let helper = RemoteHelper::new(&remote);
        let rel = layout::transaction_record(&test_operation_id("op-rec"));
        let old = b"{\"state\":\"prepared\"}".to_vec();
        let new = b"{\"state\":\"committed\"}".to_vec();
        // The OLD record is installed durably first (no fault armed), so the
        // replace has a meaningful complete-old state to fall back to.
        helper.durable_record_replace(&rel, &old, 0o644).unwrap();
        remote.arm(fault);
        let _ = helper.durable_record_replace(&rel, &new, 0o644);

        // THE PROPERTY: the record is either the complete old bytes or the
        // complete new bytes — never torn/partial.
        let p = remote.root().join(rel.as_path());
        let bytes = std::fs::read(&p)
            .expect("the record must exist (the old install succeeded)");
        prop_assert!(
            bytes == old || bytes == new,
            "the record must be the complete old or complete new bytes, got {bytes:?}"
        );
    }

    /// `durable_symlink_swap`: after a swap under a fault at EVERY boundary
    /// (the stage step — the temp `symlink(2)` — the atomic rename, the
    /// parent fsync), the `current` link is either ABSENT (the complete old
    /// state) or points at the EXACT canonical target of the new generation
    /// (the complete new state) — never a torn/partial link.
    #[test]
    fn durable_symlink_swap_reopens_old_or_new(fault in swap_fault()) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote = DurableFaultRemote::new(
            &crate::testutil::fixture_env(),
            dir.path().join("remote"),
        )
        .unwrap();
        let helper = RemoteHelper::new(&remote);
        let slot = SlotRemote::new(&helper, owner());
        let new_gen = test_generation_id("gen-new");
        // The NEW generation must exist (verify-before-swap) — install it
        // durably first (no fault armed), and create its tree object.
        let held = slot
            .acquire_lock_guard(&test_operation_id("op-1"))
            .unwrap();
        held.durable_generation_install(&generation_spec(&new_gen))
            .unwrap();
        helper
            .remote()
            .create_dir_all(&layout::tree_root(&test_tree_digest("tree-a")))
            .unwrap();
        drop(held);

        // The swap under the fault (the old state is genuine absence — the
        // first-deployment path).
        let held = slot
            .acquire_lock_guard(&test_operation_id("op-2"))
            .unwrap();
        remote.arm(fault);
        let _ = held.durable_symlink_swap(&ExpectedCurrent::Absent, &new_gen, "op-2");
        drop(held);

        // THE PROPERTY: `current` is either absent (the complete old state)
        // or points at the exact canonical target of the new generation (the
        // complete new state) — never a torn/partial link.
        let current = remote.root().join("current");
        if let Ok(target) = std::fs::read_link(&current) {
            let new_target = layout::generation(&new_gen).join("root").unwrap();
            prop_assert_eq!(
                target,
                new_target.as_path(),
                "a present current must point at the exact canonical new-generation target"
            );
        }
    }
}

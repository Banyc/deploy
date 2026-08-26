//! Capacity preflight.
//!
//! Coarse per-server headroom check (`capacity_preflight`) plus the on-host
//! tree-size walker (`tree_size_on_host`), resolved from the caller's current
//! `deploy.toml` capacity policy. Extracted from `push::engine`.

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::model::{DeploymentId, OperationId, SlotId};
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::FsBytes;
use crate::retention::compute_retained;
use crate::store::local::LocalStore;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Coarse capacity preflight: ensure each server has room for the new trees plus
/// the configured safety headroom, running protected retention first if needed.
///
/// Capacity headroom is a per-server policy declared on the top-level
/// `[[servers]]` entry (`ServerDef.capacity`) and is ALWAYS resolved from the
/// caller's current `deploy.toml` — for HEAD pushes and historical/rollback
/// pushes alike. Servers have no per-release history, so capacity is never
/// part of the release snapshot: the release identity covers mappings,
/// behavior, and trees only. Retention (used for the protected pre-retention) is
/// target-level configuration from `deploy.toml`; a shared slot's retained set
/// is the union of every member target's policy.
pub(crate) fn capacity_preflight(
    store: &LocalStore,
    assignments: &[crate::push::plan::PlannedAssignment],
    helpers: &HashMap<SlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    config: &ProjectConfig,
) -> Result<()> {
    for a in assignments {
        // Resolve the server's CURRENT capacity policy for this assignment.
        // Capacity is a per-server policy resolved from the caller's current
        // config (never a release snapshot). The assignment names a placement
        // slot; the slot binds one server. A miss is an internal invariant
        // violation: the assignment was planned against this config.
        let slot = config
            .slot_defs()
            .into_iter()
            .find(|s| s.id.as_str() == a.placement_slot.as_str())
            .expect("assignment slot present in config");
        let server = config
            .servers()
            .find(|s| s.id.as_str() == slot.server)
            .expect("slot's server present in config");
        let capacity = &server.capacity;
        let reserve_bytes = capacity.reserve_bytes;
        let reserve_percent = capacity.reserve_percent.get() as u64;
        let helper = helpers.get(&a.placement_slot).expect("helper present");
        if helper.tree_exists(a.artifact.tree.as_str()) {
            continue;
        }
        let need = tree_size_on_host(&store.object_root(&a.artifact.tree));
        let fs = helper.remote().filesystem_bytes().unwrap_or(FsBytes {
            total: 0,
            available: 0,
        });
        // `reserve_percent` is a percentage of the filesystem's TOTAL size
        // (requirement.md: "reserve_percent of the destination filesystem"),
        // not of the currently available space: a small available amount on a
        // large filesystem must still reserve `total * percent / 100`.
        let reserve = reserve_bytes.max(percent_of_total(fs.total, reserve_percent));
        // Overflow-free decision: `need + reserve` could wrap u64 (e.g.
        // `reserve_bytes = u64::MAX`), silently passing a push that must fail —
        // or panicking in a debug build. `capacity_fits` never adds (see the
        // helper for the disjunctive form).
        if !capacity_fits(need, reserve, fs.available) {
            // Run protected retention under the slot's ONE policy — the
            // policy of the slot's OWNING VARIANT (a slot has exactly one
            // retention policy; its member targets own rollout behavior
            // only), then recheck capacity directly rather than failing the
            // restore. Best-effort by design: retention is only an
            // optimization to free capacity, and the hard capacity check below
            // decides the outcome — a retention failure (compute_retained
            // abort or mark-and-sweep failure) is not recoverable at this
            // point, so it is skipped and the recheck fails the push loudly
            // if space is genuinely short. A compute_retained abort — e.g. an
            // un-honorable pinned release whose record is missing, unreadable,
            // or identity-unverifiable — must NEVER hard-fail the push here:
            // the post-commit step-17 retention defers it to the retention-debt
            // machinery (a durable marker + warning, retried on the next push
            // once the pinned release is repaired).
            //
            // The mutation lock is held via an RAII guard for the whole
            // retention block, so EVERY exit path releases it on drop. A manual
            // acquire/release pair would leak the lock, stranding every later
            // operation on this slot with "mutation lock held by ...".
            if let Ok(_guard) = helper.acquire_lock_guard(op_id.as_str()) {
                let retention = config
                    .slot_retention(&slot.id)
                    .expect("the assignment's slot is declared by its owning variant");
                // Best-effort by design (compute_retained failure INCLUDED):
                // retention is only an optimization to free capacity, and the
                // hard capacity check below decides the outcome. The recheck
                // below still fails the push loudly if space is genuinely
                // short.
                if let Ok(retained) = compute_retained(helper, config.pins(), store, retention) {
                    let active = HashSet::from([deployment_id.as_str().to_string()]);
                    helper.rotate(&retained, &active).ok();
                }
            }
            let fs2 = helper.remote().filesystem_bytes().unwrap_or(FsBytes {
                total: 0,
                available: 0,
            });
            let reserve2 = reserve_bytes.max(percent_of_total(fs2.total, reserve_percent));
            // Same overflow-free decision as the primary check above.
            if !capacity_fits(need, reserve2, fs2.available) {
                return Err(Error::preflight(format!(
                    "insufficient capacity on slot {}: need {} + reserve {} > avail {}",
                    a.placement_slot, need, reserve2, fs2.available
                )));
            }
        }
    }
    Ok(())
}

/// Overflow-free headroom decision: `true` exactly when `need + reserve` fits
/// in `available`, computed WITHOUT any u64 addition that could wrap. The
/// disjunctive form never adds: the first arm short-circuits on
/// `reserve > available`, and the second arm `need > available - reserve` is
/// only evaluated when `reserve <= available`, so the subtraction cannot
/// underflow. Mathematically `!(reserve > avail || need > avail - reserve)`
/// is equivalent to `need + reserve <= avail` computed in wider integers
/// (the u128 reference model the Bounds property tests compare against).
pub(crate) fn capacity_fits(need: u64, reserve: u64, available: u64) -> bool {
    !(reserve > available || need > available - reserve)
}

/// `total * percent / 100` in u128 so a large filesystem size times a
/// percentage cannot overflow u64.
fn percent_of_total(total: u64, percent: u64) -> u64 {
    ((total as u128 * percent as u128) / 100) as u64
}

fn tree_size_on_host(root: &Path) -> u64 {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()).map(|m| m.len()))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactRef, DeploymentId, OperationId, ReleaseId, SlotId, VariantName, test_tree_digest,
    };
    use crate::push::plan::PlannedAssignment;
    use crate::remote::helper::RemoteHelper;
    use crate::remote::transport::{
        ExecOutcome, FsBytes, LocalTransport, Remote, RemoteEntry, RemoteMeta,
    };
    use crate::store::local::LocalStore;
    use std::path::{Path, PathBuf};

    /// A transport wrapper that reports FIXED total and available filesystem
    /// bytes, letting a test control the headroom the capacity check sees
    /// deterministically.
    struct FakeCapacityRemote {
        inner: LocalTransport,
        total: u64,
        avail: u64,
    }

    impl FakeCapacityRemote {
        fn build(base: PathBuf, total: u64, avail: u64) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FakeCapacityRemote {
                inner: LocalTransport::new(base)?,
                total,
                avail,
            }))
        }
    }

    impl Remote for FakeCapacityRemote {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn read(&self, rel: &Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<bool> {
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &Path, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &Path) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &Path) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &Path) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &Path) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(&self, argv: &[String], timeout: std::time::Duration) -> Result<ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<FsBytes> {
            Ok(FsBytes {
                total: self.total,
                available: self.avail,
            })
        }
    }

    fn cfg() -> ProjectConfig {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let variant_toml = r#"
[artifact]
mappings = []

[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv"

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
        let deploy_toml = r#"
schema_version = 2
application = "cap"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml).unwrap();
        ProjectConfig::load(&p).unwrap()
    }

    /// The capacity headroom is the LARGER of `reserve_bytes` and
    /// `reserve_percent` of the filesystem's TOTAL size (requirement.md:
    /// "reserves the larger of capacity.reserve_bytes and capacity.reserve_percent
    /// of the destination filesystem"). The fake reports a 100000-byte
    /// filesystem with only 10000 bytes available, so the percent half is
    /// computed against the TOTAL: 10% reserves 10000 bytes, not 10% of the
    /// 10000 available (1000). With a 6000-byte tree, 4500 bytes of headroom
    /// fails while the equivalent 1% (1000 bytes) would pass; 10% (10000
    /// bytes of total) fails while 1000 bytes would pass — pinning that BOTH
    /// halves of the max() participate, that the percent half is a percentage
    /// of the TOTAL filesystem size, and that neither is ignored.
    #[test]
    fn capacity_reserves_the_larger_of_bytes_and_percent() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // Fabricate a local object whose tree totals exactly 6000 bytes.
        let tree = test_tree_digest("tree-6000");
        let obj_root = store.object_root(&tree);
        std::fs::create_dir_all(obj_root.join("app")).unwrap();
        std::fs::write(obj_root.join("app/file"), vec![b'x'; 6000]).unwrap();

        // A remote reporting a 100000-byte filesystem with 10000 bytes
        // available; provisioned so the protected-retention pass inside the
        // failing branch can run.
        let remote = FakeCapacityRemote::build(dir.path().join("remote"), 100_000, 10_000).unwrap();
        remote.provision_layout().unwrap();
        let helper = RemoteHelper::new(remote.as_ref());
        let helpers = HashMap::from([(SlotId::new("p1".to_string()), helper)]);

        let mut config = cfg();
        let assignment = PlannedAssignment {
            placement_slot: SlotId::new("p1".to_string()),
            artifact: ArtifactRef {
                release: ReleaseId::new("rel-sha256-cap".to_string()),
                variant: VariantName::new("standard".to_string()),
                tree: tree.clone(),
            },
        };
        let op_id = OperationId::generate();
        let deployment_id = DeploymentId::generate();

        // Comfortable: 1000 bytes / 1% of total (1000) -> reserve 1000 ->
        // 7000 <= 10000.
        config = config
            .with_server_capacity(
                "s1",
                crate::config::CapacityConfig {
                    reserve_bytes: 1000,
                    reserve_percent: crate::scalar::CapacityPercent::new(1).expect("1 is in range"),
                },
            )
            .unwrap();
        capacity_preflight(
            &store,
            std::slice::from_ref(&assignment),
            &helpers,
            &op_id,
            &deployment_id,
            &config,
        )
        .expect("small reserve fits");

        // reserve_bytes dominates: 4500 bytes -> 10500 > 10000 fails, while
        // the 1% (1000 bytes) alone would fit.
        config = config
            .with_server_capacity(
                "s1",
                crate::config::CapacityConfig {
                    reserve_bytes: 4500,
                    reserve_percent: crate::scalar::CapacityPercent::new(1).expect("1 is in range"),
                },
            )
            .unwrap();
        let err = capacity_preflight(
            &store,
            std::slice::from_ref(&assignment),
            &helpers,
            &op_id,
            &deployment_id,
            &config,
        )
        .expect_err("bytes-half must be honored");
        assert!(
            err.to_string().contains("insufficient capacity"),
            "expected a capacity preflight failure, got: {err}"
        );

        // reserve_percent dominates AND is a percentage of the TOTAL: 10% of
        // the 100000-byte filesystem is 10000 bytes -> 16000 > 10000 fails,
        // while the 1000 bytes alone would fit. The old avail-based math (10%
        // of the 10000 available = 1000) would have PASSED this case, so this
        // assertion pins the percent-of-total semantics.
        config = config
            .with_server_capacity(
                "s1",
                crate::config::CapacityConfig {
                    reserve_bytes: 1000,
                    reserve_percent: crate::scalar::CapacityPercent::new(10)
                        .expect("10 is in range"),
                },
            )
            .unwrap();
        let err = capacity_preflight(
            &store,
            std::slice::from_ref(&assignment),
            &helpers,
            &op_id,
            &deployment_id,
            &config,
        )
        .expect_err("percent-half must be honored against the total");
        assert!(
            err.to_string().contains("insufficient capacity"),
            "expected a capacity preflight failure, got: {err}"
        );

        // A tree ALREADY on the server skips the headroom check entirely.
        remote
            .create_dir_all(&crate::layout::tree_root(tree.as_str()))
            .unwrap();
        config = config
            .with_server_capacity(
                "s1",
                crate::config::CapacityConfig {
                    reserve_bytes: u64::MAX,
                    reserve_percent: crate::scalar::CapacityPercent::new(100)
                        .expect("100 is in range"),
                },
            )
            .unwrap();
        capacity_preflight(
            &store,
            std::slice::from_ref(&assignment),
            &helpers,
            &op_id,
            &deployment_id,
            &config,
        )
        .expect("an already-present tree skips the headroom check");
    }

    /// Run `capacity_preflight` against a fresh 6000-byte tree with the given
    /// filesystem total/available bytes and capacity policy, returning the
    /// result. The fake remote reports fixed bytes, so retention's recheck sees
    /// the same numbers as the primary check.
    fn run_preflight(
        total: u64,
        avail: u64,
        reserve_bytes: u64,
        reserve_percent: u8,
    ) -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // Fabricate a local object whose tree totals exactly 6000 bytes.
        let tree = test_tree_digest("tree-6000");
        let obj_root = store.object_root(&tree);
        std::fs::create_dir_all(obj_root.join("app")).unwrap();
        std::fs::write(obj_root.join("app/file"), vec![b'x'; 6000]).unwrap();

        let remote = FakeCapacityRemote::build(dir.path().join("remote"), total, avail).unwrap();
        remote.provision_layout().unwrap();
        let helper = RemoteHelper::new(remote.as_ref());
        let helpers = HashMap::from([(SlotId::new("p1".to_string()), helper)]);

        let mut config = cfg();
        config = config
            .with_server_capacity(
                "s1",
                crate::config::CapacityConfig {
                    reserve_bytes,
                    reserve_percent: crate::scalar::CapacityPercent::new(reserve_percent)
                        .expect("fixture percent in range"),
                },
            )
            .unwrap();
        let assignment = PlannedAssignment {
            placement_slot: SlotId::new("p1".to_string()),
            artifact: ArtifactRef {
                release: ReleaseId::new("rel-sha256-cap".to_string()),
                variant: VariantName::new("standard".to_string()),
                tree,
            },
        };
        let op_id = OperationId::generate();
        let deployment_id = DeploymentId::generate();
        capacity_preflight(
            &store,
            &[assignment],
            &helpers,
            &op_id,
            &deployment_id,
            &config,
        )
    }

    /// `reserve_bytes = u64::MAX` must fail the preflight LOUDLY, not wrap:
    /// the old `need + reserve` arithmetic would overflow u64 (panic in a
    /// debug build, silently pass in a release build) and let an impossible
    /// push through. The overflow-free form `reserve > available || need >
    /// available - reserve` fails immediately because MAX > available, and
    /// the retention recheck reports the same fixed available bytes.
    #[test]
    fn reserve_u64_max_fails_without_overflow() {
        let err = run_preflight(100_000, 10_000, u64::MAX, 0)
            .expect_err("u64::MAX reserve must fail the preflight");
        assert!(
            err.to_string().contains("insufficient capacity"),
            "expected a capacity preflight failure, got: {err}"
        );
    }

    /// Boundary of the overflow-free comparison against a u64::MAX-sized
    /// filesystem: `reserve = available - need` exactly fits, and
    /// `reserve = available - need + 1` must fail. The old `need + reserve`
    /// form would overflow for the failing case (`6000 + (u64::MAX - 5999)`
    /// wraps past u64::MAX), so this pins the new arithmetic on both sides
    /// of the line.
    #[test]
    fn reserve_boundary_on_max_filesystem_is_exact() {
        run_preflight(u64::MAX, u64::MAX, u64::MAX - 6000, 0)
            .expect("reserve exactly available - need fits");

        let err = run_preflight(u64::MAX, u64::MAX, u64::MAX - 5999, 0)
            .expect_err("reserve available - need + 1 must fail");
        assert!(
            err.to_string().contains("insufficient capacity"),
            "expected a capacity preflight failure, got: {err}"
        );
    }
}

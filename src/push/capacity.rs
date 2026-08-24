//! Capacity preflight.
//!
//! Coarse per-server headroom check (`capacity_preflight`) plus the on-host
//! tree-size walker (`tree_size_on_host`), resolved from the caller's current
//! `deploy.toml` capacity policy. Extracted from `push::engine`.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::model::{DeploymentId, OperationId, PlacementSlotId};
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::FsBytes;
use crate::rotation::compute_retained;
use crate::store::local::LocalStore;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Coarse capacity preflight: ensure each server has room for the new trees plus
/// the configured safety headroom, running protected rotation first if needed.
///
/// Capacity headroom is a per-server policy declared on the top-level
/// `[[servers]]` entry (`ServerDef.capacity`) and is ALWAYS resolved from the
/// caller's current `deploy.toml` — for HEAD pushes and historical/rollback
/// pushes alike. Servers have no per-release history, so capacity is never
/// part of the release snapshot: the release identity covers mappings,
/// behavior, and trees only. Rotation (used for the protected pre-rotation) is
/// target-level configuration from `deploy.toml`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capacity_preflight(
    store: &LocalStore,
    assignments: &[crate::push::plan::PlannedAssignment],
    helpers: &HashMap<PlacementSlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    config: &Config,
    rotation: &crate::config::RotationConfig,
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
            .servers
            .iter()
            .find(|s| s.id == slot.server)
            .expect("slot's server present in config");
        let capacity = &server.capacity;
        let reserve_bytes = capacity.reserve_bytes;
        let reserve_percent = capacity.reserve_percent as u64;
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
        if need + reserve > fs.available {
            // Run protected rotation using the target's rotation policy, then
            // recheck capacity directly rather than failing the restore.
            // Best-effort by design: rotation is only an optimization to free
            // capacity, and the hard capacity check below decides the outcome.
            // A rotation failure is not recoverable at this point (the push
            // would have to abort mid-preflight), and the recheck fails the
            // push loudly if space is genuinely short.
            if helper.acquire_lock(op_id.as_str(), false).is_ok() {
                let retained = compute_retained(helper, &config.pins, store, rotation)?;
                let active = HashSet::from([deployment_id.as_str().to_string()]);
                helper.rotate(&retained, &active).ok();
                helper.release_lock(op_id.as_str()).ok();
            }
            let fs2 = helper.remote().filesystem_bytes().unwrap_or(FsBytes {
                total: 0,
                available: 0,
            });
            let reserve2 = reserve_bytes.max(percent_of_total(fs2.total, reserve_percent));
            if need + reserve2 > fs2.available {
                return Err(Error::preflight(format!(
                    "insufficient capacity on slot {}: need {} + reserve {} > avail {}",
                    a.placement_slot, need, reserve2, fs2.available
                )));
            }
        }
    }
    Ok(())
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
        ArtifactRef, DeploymentId, OperationId, PlacementSlotId, ReleaseId, TreeDigest, VariantName,
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

    fn cfg() -> Config {
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
schema_version = 1
application = "cap"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 1

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
        Config::load(&p).unwrap()
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
        let tree = TreeDigest::new("tree-6000".to_string());
        let obj_root = store.object_root(&tree);
        std::fs::create_dir_all(obj_root.join("app")).unwrap();
        std::fs::write(obj_root.join("app/file"), vec![b'x'; 6000]).unwrap();

        // A remote reporting a 100000-byte filesystem with 10000 bytes
        // available; provisioned so the protected-rotation pass inside the
        // failing branch can run.
        let remote = FakeCapacityRemote::build(dir.path().join("remote"), 100_000, 10_000).unwrap();
        remote.provision_layout().unwrap();
        let helper = RemoteHelper::new(remote.as_ref());
        let helpers = HashMap::from([(PlacementSlotId::new("p1".to_string()), helper)]);

        let mut config = cfg();
        let rotation = config.targets["t1"].rotation.clone();
        let assignment = PlannedAssignment {
            placement_slot: PlacementSlotId::new("p1".to_string()),
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
        config.servers[0].capacity = crate::config::CapacityConfig {
            reserve_bytes: 1000,
            reserve_percent: 1,
        };
        capacity_preflight(
            &store,
            &[assignment.clone()],
            &helpers,
            &op_id,
            &deployment_id,
            &config,
            &rotation,
        )
        .expect("small reserve fits");

        // reserve_bytes dominates: 4500 bytes -> 10500 > 10000 fails, while
        // the 1% (1000 bytes) alone would fit.
        config.servers[0].capacity = crate::config::CapacityConfig {
            reserve_bytes: 4500,
            reserve_percent: 1,
        };
        let err = capacity_preflight(
            &store,
            &[assignment.clone()],
            &helpers,
            &op_id,
            &deployment_id,
            &config,
            &rotation,
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
        config.servers[0].capacity = crate::config::CapacityConfig {
            reserve_bytes: 1000,
            reserve_percent: 10,
        };
        let err = capacity_preflight(
            &store,
            &[assignment.clone()],
            &helpers,
            &op_id,
            &deployment_id,
            &config,
            &rotation,
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
        config.servers[0].capacity = crate::config::CapacityConfig {
            reserve_bytes: u64::MAX,
            reserve_percent: 100,
        };
        capacity_preflight(
            &store,
            &[assignment.clone()],
            &helpers,
            &op_id,
            &deployment_id,
            &config,
            &rotation,
        )
        .expect("an already-present tree skips the headroom check");
    }
}

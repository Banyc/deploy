//! End-to-end integration test exercising the full push transaction against a
//! local (filesystem) transport that mirrors the SSH remote layout.

use deploy::config::Config;
use deploy::error::Result;
use deploy::model::{ServerId, TreeDigest};
use deploy::push::engine::{PushOptions, push};
use deploy::records::DeploymentStatus;
use deploy::remote::transport::{LocalTransport, Remote};
use deploy::store::local::LocalStore;
use std::path::Path;

/// Shared per-variant policy body. It uses only `{{ variant }}` interpolation,
/// so the same file content describes both the `standard` and `high-capacity`
/// variants; their trees differ via `deployment/variants/<variant>/`. Rotation
/// is not a variant setting: it lives at the top level of `deploy.toml`.
const VARIANT_BODY: &str = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/variants/{{ variant }}/"
to = "app/"
recursive = true
conflict = "replace"

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0

[capacity]
reserve_bytes = 0
reserve_percent = 0
"#;

const CONFIG: &str = r#"
schema_version = 1
application = "example"
release = "v1"

[targets.production.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.production.rotation.fleet]
protect_deployments = 2

[[servers]]
id = "server-01"
address = "server-01.example.com"
user = "deploy"

[[servers]]
id = "server-02"
address = "server-02.example.com"
user = "deploy"

[[servers]]
id = "server-03"
address = "server-03.example.com"
user = "deploy"

[[pods]]
id = "p1"
server = "server-01"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[[pods]]
id = "p2"
server = "server-02"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[[pods]]
id = "p3"
server = "server-03"
variant = "high-capacity"
deploy_dir = "/srv/deploy/example"

[targets.production]
rollout = { batch_size = 2, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1", "p2", "p3"]
"#;

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// Write a sibling variant file into the release directory selected by the
/// deploy config (`releases/v1`).
fn write_variant_file(proj: &Path, name: &str, body: &str) {
    let release_dir = proj.join("releases").join("v1");
    write_file(&release_dir.join(format!("{name}.toml")), body);
}

fn setup(proj: &Path) -> (Config, std::path::PathBuf) {
    write_file(&proj.join("deploy.toml"), CONFIG);
    write_variant_file(proj, "standard", VARIANT_BODY);
    write_variant_file(proj, "high-capacity", VARIANT_BODY);
    // Artifact sources live beneath the release directory's `artifacts` tree.
    let artifacts = proj.join("releases").join("v1").join("artifacts");
    write_file(&artifacts.join("build/output/app/server"), "server-v1\n");
    write_file(&artifacts.join("deployment/common/README"), "common\n");
    write_file(
        &artifacts.join("deployment/variants/standard/extra"),
        "std\n",
    );
    write_file(
        &artifacts.join("deployment/variants/high-capacity/extra"),
        "hc\n",
    );
    let config = Config::load(&proj.join("deploy.toml")).unwrap();
    (config, proj.join("deploy.toml"))
}

#[test]
fn end_to_end_push_rollback() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store_base = tmp.path().join("store");
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let (config, config_path) = setup(&proj);
    let store = LocalStore::with_base(store_base.clone())?;

    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        let p = remotes_base.join(&s.id);
        Ok(Box::new(LocalTransport::new(p)?))
    };

    // First push (f0).
    let r0 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(
        r0.status,
        Some(DeploymentStatus::Successful),
        "first push should succeed"
    );
    let attempt0 = r0.attempt.expect("attempt recorded");
    let std_v1: TreeDigest = attempt0.servers[&ServerId::new("server-01")].tree.clone();
    let hc_v1: TreeDigest = attempt0.servers[&ServerId::new("server-03")].tree.clone();
    assert_ne!(std_v1, hc_v1, "standard and high-capacity trees differ");

    // Up-to-date push should be a no-op (no attempt created).
    let r_up = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert!(r_up.status.is_none(), "re-push with no change is a no-op");
    assert_eq!(r_up.message, "Everything up to date");

    // Change content and push again (f1). The artifact source lives beneath the
    // release directory's `artifacts` tree, not the project root.
    write_file(
        &proj
            .join("releases")
            .join("v1")
            .join("artifacts")
            .join("build/output/app/server"),
        "server-v2\n",
    );
    let r1 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r1.status, Some(DeploymentStatus::Successful));
    let attempt1 = r1.attempt.expect("attempt recorded");
    let std_v2: TreeDigest = attempt1.servers[&ServerId::new("server-01")].tree.clone();
    assert_ne!(
        std_v1, std_v2,
        "standard tree changed after editing content"
    );
    // The high-capacity tree also includes the shared source file, so it changes
    // too; what matters is that it is faithfully restored by rollback below.

    // Rollback to fleet snapshot f0 restores the original standard tree.
    let rrb = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: Some("production@f0".to_string()),
        },
    )?;
    assert_eq!(
        rrb.status,
        Some(DeploymentStatus::Successful),
        "rollback succeeds"
    );
    let observed = store.read_observed("production")?;
    let restored = observed.servers[&ServerId::new("server-01")]
        .tree
        .clone()
        .unwrap();
    assert_eq!(restored, std_v1, "server-01 rolled back to original tree");
    let hc_restored = observed.servers[&ServerId::new("server-03")]
        .tree
        .clone()
        .unwrap();
    assert_eq!(
        hc_restored, hc_v1,
        "server-03 still on its tree (restored from f0)"
    );

    // History should contain all three attempts.
    let attempts = store.read_attempts("production")?;
    assert_eq!(attempts.len(), 3, "three deployment attempts recorded");

    // Reflog should contain the two successful fleet deployments (f0, f1); the
    // rollback is also successful and appended, but only successful ones count.
    let reflog = store.read_reflog("production")?;
    assert_eq!(reflog.len(), 3, "three successful fleet snapshots");

    Ok(())
}

/// Deploy variant `old`, replace it with `new` in the configuration (the old
/// variant file is removed entirely), then restore the `@f0` fleet snapshot.
/// Historical capacity policies must resolve from the immutable
/// release record, not the caller's current configuration.
#[test]
fn fleet_rollback_after_variant_rename_succeeds() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store_base = tmp.path().join("store");
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    fn config_toml(variant: &str) -> String {
        format!(
            r#"
schema_version = 1
application = "example"
release = "v1"

[[servers]]
id = "server-01"
address = "server-01.example.com"
user = "deploy"

[[pods]]
id = "p1"
server = "server-01"
variant = "{variant}"
deploy_dir = "/srv/deploy/example"

[targets.production]
rollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }}
pods = ["p1"]
"#
        )
    }

    // f0: deploy variant `old`.
    let config_path = write_string(&proj.join("deploy.toml"), &config_toml("old"));
    write_variant_file(&proj, "old", VARIANT_BODY);
    let artifacts = proj.join("releases").join("v1").join("artifacts");
    write_file(&artifacts.join("build/output/app/server"), "v1\n");
    write_file(&artifacts.join("deployment/common/README"), "common\n");
    write_file(&artifacts.join("deployment/variants/old/extra"), "old\n");

    let config0 = Config::load(&config_path)?;
    let store = LocalStore::with_base(store_base)?;
    let rf = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
    };

    let r0 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config0,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r0.status, Some(DeploymentStatus::Successful));
    let attempt0 = r0.attempt.expect("attempt recorded");
    let old_server = &attempt0.servers[&ServerId::new("server-01")];
    let old_tree = old_server.tree.clone();
    let old_release = old_server.release.clone();

    // The old release persists its per-variant capacity policies.
    let policies = store.read_release_policies(&old_release)?;
    assert!(
        policies.as_ref().is_some_and(|p| p.contains_key("old")),
        "release record carries the `old` variant policy snapshot"
    );

    // Rename the variant: the configuration now declares `new`, and the
    // `old.toml` variant file is removed entirely.
    write_string(&proj.join("deploy.toml"), &config_toml("new"));
    write_variant_file(&proj, "new", VARIANT_BODY);
    write_file(&artifacts.join("deployment/variants/new/extra"), "new\n");
    std::fs::remove_file(proj.join("releases").join("v1").join("old.toml")).unwrap();
    let config1 = Config::load(&config_path)?;
    assert!(
        config1.variant("old").is_err(),
        "current configuration no longer declares `old`"
    );

    // f1: deploy variant `new`.
    let r1 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config1,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r1.status, Some(DeploymentStatus::Successful));
    let new_tree = r1.attempt.expect("attempt recorded").servers[&ServerId::new("server-01")]
        .tree
        .clone();
    assert_ne!(
        old_tree, new_tree,
        "renamed variant materializes a new tree"
    );

    // Roll back to the f0 fleet snapshot: restores variant `old` even though the
    // current configuration neither declares it nor ships its variant file.
    let rrb = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config1,
        &PushOptions {
            dry_run: false,
            ref_token: Some("production@f0".to_string()),
        },
    )?;
    assert_eq!(
        rrb.status,
        Some(DeploymentStatus::Successful),
        "exact fleet rollback must succeed after the variant was renamed"
    );
    let observed = store.read_observed("production")?;
    let restored = &observed.servers[&ServerId::new("server-01")];
    assert_eq!(
        restored.tree.as_ref(),
        Some(&old_tree),
        "tree restored from f0"
    );
    assert_eq!(
        restored.variant.as_ref().map(|v| v.as_str()),
        Some("old"),
        "variant restored from f0"
    );
    assert_eq!(
        restored.release.as_ref(),
        Some(&old_release),
        "release restored from f0"
    );
    Ok(())
}

#[test]
fn dry_run_reports_plan() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let (config, config_path) = setup(&proj);
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        let p = remotes_base.join(&s.id);
        Ok(Box::new(LocalTransport::new(p)?))
    };
    let r = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: true,
            ref_token: None,
        },
    )?;
    assert!(r.dry_run);
    assert!(r.attempt.is_none(), "dry-run creates no attempt");
    assert!(r.message.contains("dry-run plan"), "reports a plan");

    // No remote state should have been created.
    let observed = store.read_observed("production")?;
    assert!(
        observed.servers.is_empty(),
        "dry-run leaves no observed state"
    );
    Ok(())
}

// ===========================================================================
// Additional tests for the hardening findings (1, 2, 4, 5, 6).
// ===========================================================================

use deploy::records::ServerOutcomeKind;
use deploy::release;
use deploy::remote::create_remote;
use deploy::remote::helper::{GenerationAssignment, RemoteHelper};
use deploy::remote::transport::{ExecOutcome, RemoteEntry, RemoteMeta};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// A read-only spy remote: all mutation/exec operations are forbidden. Any call
/// to one increments `mutations` and returns an error. Reads delegate to an
/// inner `LocalTransport`.
struct SpyRemote {
    inner: LocalTransport,
    mutations: Arc<AtomicUsize>,
}

impl SpyRemote {
    fn build(base: std::path::PathBuf, mutations: Arc<AtomicUsize>) -> Result<Box<dyn Remote>> {
        Ok(Box::new(SpyRemote {
            inner: LocalTransport::new(base)?,
            mutations,
        }))
    }
}

impl Remote for SpyRemote {
    fn root(&self) -> &Path {
        self.inner.root()
    }
    fn read(&self, rel: &Path) -> deploy::error::Result<Vec<u8>> {
        self.inner.read(rel)
    }
    fn write(&self, _rel: &Path, _data: &[u8], _mode: u32) -> deploy::error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: write is forbidden",
        ))
    }
    fn try_write_new(&self, _rel: &Path, _data: &[u8]) -> deploy::error::Result<bool> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: write is forbidden",
        ))
    }
    fn create_dir(&self, _rel: &Path) -> deploy::error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: create_dir is forbidden",
        ))
    }
    fn create_dir_all(&self, _rel: &Path) -> deploy::error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: create_dir_all is forbidden",
        ))
    }
    fn list(&self, rel: &Path) -> deploy::error::Result<Vec<RemoteEntry>> {
        self.inner.list(rel)
    }
    fn rename(&self, _from: &Path, _to: &Path) -> deploy::error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: rename is forbidden",
        ))
    }
    fn symlink(&self, _target: &Path, _link: &Path) -> deploy::error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: symlink is forbidden",
        ))
    }
    fn read_link(&self, rel: &Path) -> deploy::error::Result<std::path::PathBuf> {
        self.inner.read_link(rel)
    }
    fn remove_file(&self, _rel: &Path) -> deploy::error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: remove_file is forbidden",
        ))
    }
    fn remove_dir_all(&self, _rel: &Path) -> deploy::error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote(
            "SpyRemote: remove_dir_all is forbidden",
        ))
    }
    fn exists(&self, rel: &Path) -> bool {
        self.inner.exists(rel)
    }
    fn metadata(&self, rel: &Path) -> deploy::error::Result<RemoteMeta> {
        self.inner.metadata(rel)
    }
    fn exec(&self, _argv: &[String], _timeout: Duration) -> deploy::error::Result<ExecOutcome> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(deploy::error::Error::remote("SpyRemote: exec is forbidden"))
    }
    fn available_bytes(&self) -> deploy::error::Result<u64> {
        self.inner.available_bytes()
    }
}

/// A remote that fails specific operations after the lock is acquired, to
/// exercise post-lock error handling (finding 6).
struct FaultRemote {
    inner: LocalTransport,
    fail_rename: bool,
    fail_write: bool,
    fail_exec: bool,
    /// Fail only the durable `committed` transaction-record write (path
    /// `transactions/<op>.json`, content carries `"committed"`).
    fail_committed_txn: bool,
    /// Fail only the fleet-commit marker write (path `state/commits/...`).
    fail_commit_marker: bool,
    attempted: Arc<AtomicUsize>,
}

impl FaultRemote {
    fn build(
        base: std::path::PathBuf,
        fail_rename: bool,
        fail_write: bool,
        fail_exec: bool,
        attempted: Arc<AtomicUsize>,
    ) -> Result<Box<dyn Remote>> {
        Ok(Box::new(FaultRemote {
            inner: LocalTransport::new(base)?,
            fail_rename,
            fail_write,
            fail_exec,
            fail_committed_txn: false,
            fail_commit_marker: false,
            attempted,
        }))
    }
    /// Build a `FaultRemote` that fails the durable `committed`
    /// transaction-record write (finding 6: the last bookkeeping write).
    fn build_committed_fault(
        base: std::path::PathBuf,
        attempted: Arc<AtomicUsize>,
    ) -> Result<Box<dyn Remote>> {
        Ok(Box::new(FaultRemote {
            inner: LocalTransport::new(base)?,
            fail_rename: false,
            fail_write: false,
            fail_exec: false,
            fail_committed_txn: true,
            fail_commit_marker: false,
            attempted,
        }))
    }
    /// Build a `FaultRemote` that fails the fleet-commit marker write
    /// (finding 6: the fleet bookkeeping write).
    fn build_commit_marker_fault(
        base: std::path::PathBuf,
        attempted: Arc<AtomicUsize>,
    ) -> Result<Box<dyn Remote>> {
        Ok(Box::new(FaultRemote {
            inner: LocalTransport::new(base)?,
            fail_rename: false,
            fail_write: false,
            fail_exec: false,
            fail_committed_txn: false,
            fail_commit_marker: true,
            attempted,
        }))
    }
}

impl Remote for FaultRemote {
    fn root(&self) -> &Path {
        self.inner.root()
    }
    fn read(&self, rel: &Path) -> deploy::error::Result<Vec<u8>> {
        self.inner.read(rel)
    }
    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> deploy::error::Result<()> {
        self.attempted.fetch_add(1, Ordering::SeqCst);
        if self.fail_write {
            return Err(deploy::error::Error::remote(
                "FaultRemote: write forced to fail",
            ));
        }
        // Targeted fault injection for finding 6's bookkeeping writes.
        if self.fail_committed_txn && String::from_utf8_lossy(data).contains("\"committed\"") {
            return Err(deploy::error::Error::remote(
                "FaultRemote: committed transaction record write forced to fail",
            ));
        }
        if self.fail_commit_marker && rel.to_string_lossy().starts_with("state/commits/") {
            return Err(deploy::error::Error::remote(
                "FaultRemote: commit marker write forced to fail",
            ));
        }
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> deploy::error::Result<bool> {
        self.attempted.fetch_add(1, Ordering::SeqCst);
        if self.fail_write {
            return Err(deploy::error::Error::remote(
                "FaultRemote: write forced to fail",
            ));
        }
        // Targeted fault injection mirrors `write`: markers are installed via
        // exclusive create, so the failure must be observable there too.
        if self.fail_commit_marker && rel.to_string_lossy().starts_with("state/commits/") {
            return Err(deploy::error::Error::remote(
                "FaultRemote: commit marker create forced to fail",
            ));
        }
        self.inner.try_write_new(rel, data)
    }
    fn create_dir(&self, rel: &Path) -> deploy::error::Result<()> {
        self.inner.create_dir(rel)
    }
    fn create_dir_all(&self, rel: &Path) -> deploy::error::Result<()> {
        self.inner.create_dir_all(rel)
    }
    fn list(&self, rel: &Path) -> deploy::error::Result<Vec<RemoteEntry>> {
        self.inner.list(rel)
    }
    fn rename(&self, from: &Path, to: &Path) -> deploy::error::Result<()> {
        self.attempted.fetch_add(1, Ordering::SeqCst);
        if self.fail_rename {
            return Err(deploy::error::Error::remote(
                "FaultRemote: rename forced to fail",
            ));
        }
        self.inner.rename(from, to)
    }
    fn symlink(&self, target: &Path, link: &Path) -> deploy::error::Result<()> {
        self.inner.symlink(target, link)
    }
    fn read_link(&self, rel: &Path) -> deploy::error::Result<std::path::PathBuf> {
        self.inner.read_link(rel)
    }
    fn remove_file(&self, rel: &Path) -> deploy::error::Result<()> {
        self.inner.remove_file(rel)
    }
    fn remove_dir_all(&self, rel: &Path) -> deploy::error::Result<()> {
        self.inner.remove_dir_all(rel)
    }
    fn exists(&self, rel: &Path) -> bool {
        self.inner.exists(rel)
    }
    fn metadata(&self, rel: &Path) -> deploy::error::Result<RemoteMeta> {
        self.inner.metadata(rel)
    }
    fn exec(&self, argv: &[String], timeout: Duration) -> deploy::error::Result<ExecOutcome> {
        self.attempted.fetch_add(1, Ordering::SeqCst);
        if self.fail_exec {
            return Err(deploy::error::Error::remote(
                "FaultRemote: exec forced to fail",
            ));
        }
        self.inner.exec(argv, timeout)
    }
    fn available_bytes(&self) -> deploy::error::Result<u64> {
        self.inner.available_bytes()
    }
}

/// A remote that fails fleet-commit marker writes exactly once: the first
/// write/create under `state/commits/` errors (leaving the marker absent), then
/// the wrapper behaves normally. Lets a test record a `PendingCommit` attempt
/// on the first push and observe the next push's reconciliation completing the
/// markers with the ORIGINAL deployment ID. Lock acquisition writes
/// `state/operation.lock` — a different path — so locking is unaffected.
struct FailOnceMarkerRemote {
    inner: LocalTransport,
    armed: Arc<AtomicBool>,
}

impl FailOnceMarkerRemote {
    fn build(base: std::path::PathBuf, armed: Arc<AtomicBool>) -> Result<Box<dyn Remote>> {
        Ok(Box::new(FailOnceMarkerRemote {
            inner: LocalTransport::new(base)?,
            armed,
        }))
    }
    fn fail_marker(&self, rel: &Path) -> bool {
        self.armed.load(Ordering::SeqCst) && rel.to_string_lossy().starts_with("state/commits/")
    }
}

impl Remote for FailOnceMarkerRemote {
    fn root(&self) -> &Path {
        self.inner.root()
    }
    fn provision_layout(&self) -> Result<()> {
        self.inner.provision_layout()
    }
    fn read(&self, rel: &Path) -> Result<Vec<u8>> {
        self.inner.read(rel)
    }
    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        if self.fail_marker(rel) {
            self.armed.store(false, Ordering::SeqCst);
            return Err(deploy::error::Error::remote(
                "FailOnceMarkerRemote: commit marker write forced to fail (once)",
            ));
        }
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<bool> {
        if self.fail_marker(rel) {
            self.armed.store(false, Ordering::SeqCst);
            return Err(deploy::error::Error::remote(
                "FailOnceMarkerRemote: commit marker create forced to fail (once)",
            ));
        }
        self.inner.try_write_new(rel, data)
    }
    fn create_dir(&self, rel: &Path) -> Result<()> {
        self.inner.create_dir(rel)
    }
    fn create_dir_all(&self, rel: &Path) -> Result<()> {
        self.inner.create_dir_all(rel)
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
    fn read_link(&self, rel: &Path) -> Result<std::path::PathBuf> {
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
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
        self.inner.exec(argv, timeout)
    }
    fn available_bytes(&self) -> Result<u64> {
        self.inner.available_bytes()
    }
}

/// Per-variant policy body for the single-variant helpers.
fn single_variant_body(verify_argv: &str) -> String {
    format!(
        r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["{verify_argv}"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0

[capacity]
reserve_bytes = 0
reserve_percent = 0
"#
    )
}

/// Minimal deploy.toml body with a single `standard` variant and
/// `activation: none`. Rotation is a top-level setting of `deploy.toml`.
fn single_target_toml(stop_on_failure: bool, batch_size: u32) -> String {
    format!(
        r#"
schema_version = 1
application = "example"
release = "v1"

[targets.production.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.production.rotation.fleet]
protect_deployments = 2

[[servers]]
id = "server-01"
address = "server-01.example.com"
user = "deploy"

[[pods]]
id = "p1"
server = "server-01"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[targets.production]
rollout = {{ batch_size = {batch_size}, stop_on_failure = {stop_on_failure}, failure_policy = "rollback_changed" }}
pods = ["p1"]
"#
    )
}

/// Build the single-variant project (deploy.toml + `standard.toml` variant
/// file + source inputs) and load its config.
fn setup_single(proj: &Path, verify_argv: &str, stop_on_failure: bool, batch_size: u32) -> Config {
    let p = write_string(
        &proj.join("deploy.toml"),
        &single_target_toml(stop_on_failure, batch_size),
    );
    write_variant_file(proj, "standard", &single_variant_body(verify_argv));
    let artifacts = proj.join("releases").join("v1").join("artifacts");
    write_file(&artifacts.join("build/output/app/server"), "v1\n");
    write_file(&artifacts.join("deployment/common/README"), "common\n");
    Config::load(&p).unwrap()
}

// ---- Finding 1: production CLI must target the configured remote endpoint --

#[test]
fn cli_reaches_configured_endpoint() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store_base = tmp.path().join("store");
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();
    let endpoints = tmp.path().join("endpoints");
    std::fs::create_dir_all(&endpoints).unwrap();

    // Addresses are explicit `local://` paths: the configured endpoint, NOT the
    // application store's `remotes/` directory. Rotation is a top-level setting
    // of `deploy.toml`.
    let config_toml = r#"
schema_version = 1
application = "example"
release = "v1"

[targets.production.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.production.rotation.fleet]
protect_deployments = 2

[[servers]]
id = "server-01"
address = "local:///dev/null/should-not-be-used"
user = "deploy"

[[pods]]
id = "p1"
server = "server-01"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1"]
"#;
    let variant_toml = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0

[capacity]
reserve_bytes = 0
reserve_percent = 0
"#;
    write_file(&proj.join("deploy.toml"), config_toml);
    write_variant_file(&proj, "standard", variant_toml);
    let artifacts = proj.join("releases").join("v1").join("artifacts");
    write_file(&artifacts.join("build/output/app/server"), "v1\n");
    write_file(&artifacts.join("deployment/common/README"), "common\n");

    let mut config = Config::load(&proj.join("deploy.toml"))?;
    let store = LocalStore::with_base(store_base.clone())?;

    // Plug the real endpoint directory into the server address and use the real
    // CLI remote factory (create_remote), which routes `local://` addresses to
    // the configured endpoint rather than the application store's remotes/.
    config
        .servers
        .iter_mut()
        .find(|s| s.id == "server-01")
        .unwrap()
        .address = format!("local://{}", endpoints.join("server-01").display());

    let factory = move |s: &deploy::config::ServerDef,
                        pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> { create_remote(s, &pod.deploy_dir) };

    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r.status, Some(DeploymentStatus::Successful));

    // The configured endpoint now carries the remote layout ...
    let ep = endpoints.join("server-01");
    assert!(ep.join("objects/sha256").exists(), "endpoint has objects");
    assert!(ep.join("generations").exists(), "endpoint has generations");
    assert!(ep.join("current").exists(), "endpoint has current symlink");

    // ... and the store's `remotes/` directory was NOT used as the target.
    assert!(
        !remotes_base.join("server-01").exists(),
        "store remotes/ must not be the deployment target"
    );
    Ok(())
}

// ---- Finding 2: dry-run must not mutate store or remote -------------------

#[test]
fn dry_run_does_not_mutate() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remote_base = tmp.path().join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();

    let config = setup_single(&proj, "true", true, 1);

    let mutations = Arc::new(AtomicUsize::new(0));
    let m = mutations.clone();
    let rb = remote_base.clone();
    let factory =
        move |s: &deploy::config::ServerDef,
              _pod: &deploy::config::PodDef|
              -> Result<Box<dyn Remote>> { SpyRemote::build(rb.join(&s.id), m.clone()) };

    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: true,
            ref_token: None,
        },
    )?;
    assert!(r.dry_run);
    assert!(r.attempt.is_none());

    // No mutating remote operation was attempted.
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        0,
        "dry-run must not mutate the remote"
    );

    // No artifact content was written to the store object store or the remote.
    let obj_root = store.base().join("objects/sha256");
    let stored: Vec<_> = std::fs::read_dir(&obj_root)
        .map(|d| d.flatten().collect())
        .unwrap_or_default();
    assert!(stored.is_empty(), "dry-run must not store objects");
    let remote_objs = remote_base.join("server-01/objects/sha256");
    let remote_stored: Vec<_> = std::fs::read_dir(&remote_objs)
        .map(|d| d.flatten().collect())
        .unwrap_or_default();
    assert!(
        remote_stored.is_empty(),
        "dry-run must not publish to remote"
    );
    assert!(
        !remote_base.join("server-01/current").exists(),
        "dry-run must not create current"
    );
    Ok(())
}

// ---- Finding 4: historical rollback uses the historical behavior ---------

#[test]
fn historical_rollback_uses_historical_behavior() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    // Behavior A: verification succeeds.
    let config_a = setup_single(&proj, "true", true, 1);
    let a_var = config_a
        .variant("standard")
        .expect("standard variant present");
    let a_digest = release::behavior_digest(&a_var.activation, &a_var.verification);
    let b_digest = {
        // Behavior B: verification command differs (so its digest differs).
        let config_b = setup_single(&proj, "false", true, 1);
        let b_var = config_b
            .variant("standard")
            .expect("standard variant present");
        release::behavior_digest(&b_var.activation, &b_var.verification)
    };
    assert_ne!(a_digest, b_digest, "behaviors must differ");

    let rb = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rb.join(&s.id))?))
    };

    // Deploy with behavior A (f0).
    let r0 = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config_a,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r0.status, Some(DeploymentStatus::Successful));

    // Change the configuration to behavior B, then roll back to f0.
    let config_b = setup_single(&proj, "false", true, 1);
    let rrb = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config_b,
        &PushOptions {
            dry_run: false,
            ref_token: Some("production@f0".to_string()),
        },
    )?;
    assert_eq!(rrb.status, Some(DeploymentStatus::Successful));

    // The rolled-back generation must carry behavior A's digest, NOT B's.
    let remote = LocalTransport::new(remotes_base.join("server-01"))?;
    let helper = RemoteHelper::new(&remote);
    let status = helper.status()?;
    let gen_id = status
        .current_generation
        .expect("rollback produced a current generation");
    let assignment: GenerationAssignment = serde_json::from_slice(
        &remote
            .read(
                &Path::new("generations")
                    .join(&gen_id)
                    .join("assignment.json"),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        assignment.behavior_sha256, a_digest,
        "rollback must use the historical (A) behavior"
    );
    assert_ne!(
        assignment.behavior_sha256, b_digest,
        "rollback must NOT use the current (B) behavior"
    );

    // The historical release's remote `behavior.json` must NOT be overwritten by
    // the current (B) config. Read the release that f0 published and confirm it
    // still describes behavior A (verification argv "true").
    let hist_release = r0
        .attempt
        .as_ref()
        .unwrap()
        .servers
        .get(&ServerId::new("server-01"))
        .unwrap()
        .release
        .as_str()
        .to_string();
    let behavior_path = Path::new("releases")
        .join(&hist_release)
        .join("behavior.json");
    let behavior: serde_json::Value =
        serde_json::from_slice(&remote.read(&behavior_path).unwrap()).unwrap();
    let verify_argv = behavior["standard"]["verification"]["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        verify_argv,
        vec!["true".to_string()],
        "historical release behavior.json must keep behavior A, not be overwritten with B"
    );
    Ok(())
}

// ---- Finding 7: a historical/rollback push whose immutable historical
// behavior cannot be read must fail closed in preflight, NOT silently fall back
// to the caller's current configuration.

#[test]
fn historical_behavior_unavailable_fails_preflight() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    // Deploy behavior A (verification succeeds) as f0.
    let config_a = setup_single(&proj, "true", true, 1);

    let rb = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rb.join(&s.id))?))
    };

    let r0 = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config_a,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r0.status, Some(DeploymentStatus::Successful));

    // The historical release published by f0.
    let hist_release = r0
        .attempt
        .as_ref()
        .unwrap()
        .servers
        .get(&ServerId::new("server-01"))
        .unwrap()
        .release
        .as_str()
        .to_string();

    // Remove the historical release's immutable behavior.json, then attempt a
    // rollback to f0 with a DIFFERENT current configuration (behavior B). The
    // push must fail closed (preflight) rather than deploy behavior B.
    let behavior_path = store
        .base()
        .join("releases")
        .join(&hist_release)
        .join("behavior.json");
    assert!(
        behavior_path.exists(),
        "historical behavior.json must exist"
    );
    std::fs::remove_file(&behavior_path)
        .map_err(|e| deploy::error::Error::store(format!("rm {e}")))?;

    let config_b = setup_single(&proj, "false", true, 1);
    let rrb = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config_b,
        &PushOptions {
            dry_run: false,
            ref_token: Some("production@f0".to_string()),
        },
    );
    assert!(
        rrb.is_err(),
        "rollback with unavailable historical behavior must fail closed, got {:?}",
        rrb.map(|r| r.status)
    );
    Ok(())
}

// ---- A corrupted historical behavior snapshot that PARSSES but is missing a
// planned variant's contract must fail in preflight BEFORE any remote mutation,
// rather than panic mid-rollout after staging.

/// Snapshot of a remote directory: sorted (relative path, kind+content digest)
/// pairs, including symlink targets. Two fingerprints are equal iff the
/// directory trees are identical.
fn remote_fingerprint(root: &Path) -> Vec<(String, String)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        entries.sort();
        for p in entries {
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let ft = std::fs::symlink_metadata(&p).unwrap().file_type();
            if ft.is_symlink() {
                let target = std::fs::read_link(&p)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, format!("symlink:{target}")));
            } else if ft.is_dir() {
                out.push((rel, "dir".to_string()));
                walk(root, &p, out);
            } else {
                let data = std::fs::read(&p).unwrap();
                out.push((rel, format!("file:{}", deploy::digest::sha256_bytes(&data))));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn incomplete_historical_behavior_fails_preflight_without_remote_mutation() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    // Deploy behavior A (verification succeeds) as f0.
    let config_a = setup_single(&proj, "true", true, 1);

    let rb = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rb.join(&s.id))?))
    };

    let r0 = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config_a,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r0.status, Some(DeploymentStatus::Successful));
    let hist_release = r0
        .attempt
        .as_ref()
        .unwrap()
        .servers
        .get(&ServerId::new("server-01"))
        .unwrap()
        .release
        .as_str()
        .to_string();

    // Corrupt the historical release's immutable behavior.json so it PARSEs but
    // does not cover the planned `standard` variant.
    let behavior_path = store
        .base()
        .join("releases")
        .join(&hist_release)
        .join("behavior.json");
    assert!(
        behavior_path.exists(),
        "historical behavior.json must exist"
    );
    std::fs::write(&behavior_path, "{}\n").unwrap();

    // Fingerprint every server remote before the rollback attempt.
    let before = remote_fingerprint(&remotes_base);
    let attempts_before = store.read_attempts("production")?.len();

    // Roll back to f0 under a DIFFERENT current configuration (behavior B). The
    // push must fail closed in preflight, NOT fall back to B and NOT panic.
    let config_b = setup_single(&proj, "false", true, 1);
    let rrb = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config_b,
        &PushOptions {
            dry_run: false,
            ref_token: Some("production@f0".to_string()),
        },
    );
    let err = match rrb {
        Err(e) => e.to_string(),
        Ok(r) => panic!(
            "rollback with an incomplete behavior snapshot must fail, got {:?}",
            r.status
        ),
    };
    assert!(
        err.contains("preflight"),
        "failure must be a preflight error, got: {err}"
    );
    assert!(
        err.contains("incomplete") && err.contains("standard"),
        "error must name the missing variant and the incomplete snapshot, got: {err}"
    );

    // No remote state changed: the fingerprint is byte-for-byte identical.
    let after = remote_fingerprint(&remotes_base);
    assert_eq!(
        before, after,
        "preflight failure must leave every remote untouched"
    );
    // And no deployment attempt was recorded.
    assert_eq!(
        store.read_attempts("production")?.len(),
        attempts_before,
        "preflight failure must not record an attempt"
    );
    Ok(())
}

// ---- Finding 5: stop_on_failure must not panic; later servers untouched --

#[test]
fn stop_on_failure_records_all_servers() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    // Three servers; verification always fails so the first server fails.
    let deploy_toml = r#"
schema_version = 1
application = "example"
release = "v1"

[targets.production.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.production.rotation.fleet]
protect_deployments = 2

[[servers]]
id = "server-01"
address = "a"
user = "u"

[[servers]]
id = "server-02"
address = "b"
user = "u"

[[servers]]
id = "server-03"
address = "c"
user = "u"

[[pods]]
id = "p1"
server = "server-01"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[[pods]]
id = "p2"
server = "server-02"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[[pods]]
id = "p3"
server = "server-03"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1", "p2", "p3"]
"#;
    let variant_toml = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0

[capacity]
reserve_bytes = 0
reserve_percent = 0
"#;
    write_file(&proj.join("deploy.toml"), deploy_toml);
    write_variant_file(&proj, "standard", variant_toml);
    let artifacts = proj.join("releases").join("v1").join("artifacts");
    write_file(&artifacts.join("build/output/app/server"), "v1\n");

    let config = Config::load(&proj.join("deploy.toml"))?;
    let rf = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
    };

    // Must not panic.
    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;

    let attempt = r.attempt.expect("attempt must be recorded even on failure");
    let results = store.read_results(attempt.deployment_id.as_str())?;
    // All three servers appear in the attempt.
    assert_eq!(attempt.server_ids.len(), 3);
    for sid in ["server-01", "server-02", "server-03"] {
        assert!(
            attempt.servers.contains_key(&ServerId::new(sid)),
            "server {sid} missing from attempt"
        );
    }
    // First server failed; later servers were never started (Skipped).
    assert_eq!(
        results.servers[&ServerId::new("server-01")].outcome,
        ServerOutcomeKind::Failed
    );
    assert_eq!(
        results.servers[&ServerId::new("server-02")].outcome,
        ServerOutcomeKind::Skipped
    );
    assert_eq!(
        results.servers[&ServerId::new("server-03")].outcome,
        ServerOutcomeKind::Skipped
    );
    // Later servers were left untouched (no `current` pointer was ever created).
    assert!(!remotes_base.join("server-02/current").exists());
    assert!(!remotes_base.join("server-03/current").exists());

    // The attempt is recorded as a failure, not lost.
    assert!(
        matches!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack) | Some(DeploymentStatus::Degraded)
        ),
        "unexpected status {:?}",
        r.status
    );
    Ok(())
}

// ---- Finding 6: post-lock failure releases the lock and records attempt --

#[test]
fn post_lock_failure_releases_lock_and_records() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let config = setup_single(&proj, "true", true, 1);

    // Fail the rename that performs the tree publish, AFTER the mutation lock is
    // acquired.
    let attempted = Arc::new(AtomicUsize::new(0));
    let at = attempted.clone();
    let remotes_for_factory = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        FaultRemote::build(
            remotes_for_factory.join(&s.id),
            true,
            false,
            false,
            at.clone(),
        )
    };

    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert!(
        attempted.load(Ordering::SeqCst) > 0,
        "a mutating op was attempted"
    );

    // The attempt was still recorded (the error did not bypass it).
    let attempts = store.read_attempts("production")?;
    assert_eq!(attempts.len(), 1, "attempt must be recorded");
    assert!(
        matches!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack) | Some(DeploymentStatus::Degraded)
        ),
        "unexpected status {:?}",
        r.status
    );

    // The server mutation lock was released despite the post-lock failure.
    assert!(
        !remotes_base.join("server-01/state/operation.lock").exists(),
        "mutation lock must be released after post-lock failure"
    );
    Ok(())
}

// ---- Finding 6: a failed committed-transaction write must not be reported as
// a successful (fully bookkept) deployment. The service is active, but the
// attempt must be marked `PendingCommit` (recoverable metadata failure).

#[test]
fn committed_txn_write_failure_pends_commit() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let config = setup_single(&proj, "true", true, 1);

    let attempted = Arc::new(AtomicUsize::new(0));
    let at = attempted.clone();
    let remotes_for_factory = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        FaultRemote::build_committed_fault(remotes_for_factory.join(&s.id), at.clone())
    };

    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert!(
        attempted.load(Ordering::SeqCst) > 0,
        "the committed transaction record write was attempted"
    );

    // The service is active (current was advanced) but the bookkeeping write
    // failed, so the attempt must NOT be `Successful`.
    assert_eq!(
        r.status,
        Some(DeploymentStatus::PendingCommit),
        "failed committed-transaction write must yield PendingCommit, got {:?}",
        r.status
    );

    // The attempt is still recorded (the error did not bypass it).
    let attempts = store.read_attempts("production")?;
    assert_eq!(attempts.len(), 1, "attempt must be recorded");

    // Remote mutation lock released despite the bookkeeping failure.
    assert!(
        !remotes_base.join("server-01/state/operation.lock").exists(),
        "mutation lock must be released"
    );
    Ok(())
}

// ---- Finding 6: a failed fleet-commit marker write must not be silently
// upgraded to `Successful`; it must be marked `PendingCommit`.

#[test]
fn commit_marker_write_failure_pends_commit() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let config = setup_single(&proj, "true", true, 1);

    let attempted = Arc::new(AtomicUsize::new(0));
    let at = attempted.clone();
    let remotes_for_factory = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        FaultRemote::build_commit_marker_fault(remotes_for_factory.join(&s.id), at.clone())
    };

    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;

    // All servers activated and the committed-transaction write succeeded, but
    // the fleet-commit marker write failed: do not report `Successful`.
    assert_eq!(
        r.status,
        Some(DeploymentStatus::PendingCommit),
        "failed commit-marker write must yield PendingCommit, got {:?}",
        r.status
    );

    let attempts = store.read_attempts("production")?;
    assert_eq!(attempts.len(), 1, "attempt must be recorded");
    assert!(
        !remotes_base.join("server-01/state/operation.lock").exists(),
        "mutation lock must be released"
    );
    Ok(())
}

// ---- Pending-commit reconciliation: a push that left the fleet-commit
// markers incomplete records a `PendingCommit` attempt, and the NEXT push must
// reconcile it BEFORE its no-op path: verify membership + recorded
// generations, create the missing markers with the original deployment ID, and
// finalize the mutable status/reflog. A diverged attempt must be `Degraded`.

#[test]
fn pending_commit_attempt_reconciled_on_next_push() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let config = setup_single(&proj, "true", true, 1);

    // Push 1: the fleet-commit marker write fails once -> PendingCommit.
    let armed = Arc::new(AtomicBool::new(true));
    let armed_for_factory = armed.clone();
    let rf = remotes_base.clone();
    let fault_factory = move |s: &deploy::config::ServerDef,
                              _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        FailOnceMarkerRemote::build(rf.join(&s.id), armed_for_factory.clone())
    };
    let r1 = push(
        &proj.join("deploy.toml"),
        &store,
        &fault_factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(
        r1.status,
        Some(DeploymentStatus::PendingCommit),
        "failed marker write must yield PendingCommit"
    );
    let attempt1 = r1.attempt.expect("attempt recorded");

    let marker = remotes_base
        .join("server-01/state/commits")
        .join(format!("{}.json", attempt1.deployment_id.as_str()));
    assert!(
        !marker.exists(),
        "marker must be absent after the failed commit-marker push"
    );
    assert!(
        store.read_reflog("production")?.is_empty(),
        "no reflog entry for a pending attempt"
    );
    assert!(
        store.read_last_successful("production").is_none(),
        "last-successful must not point at a pending attempt"
    );

    // Push 2 with a healthy remote: reconciliation must run BEFORE the no-op
    // path, create the missing marker with attempt 1's ORIGINAL deployment ID,
    // and finalize -- even though this push itself is an up-to-date no-op.
    let rf2 = remotes_base.clone();
    let clean_factory = move |s: &deploy::config::ServerDef,
                              _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rf2.join(&s.id))?))
    };
    let r2 = push(
        &proj.join("deploy.toml"),
        &store,
        &clean_factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(
        r2.status, None,
        "reconciliation must not fabricate a new attempt for an up-to-date push"
    );
    assert_eq!(r2.message, "Everything up to date");

    // The missing marker now exists, bound to attempt 1's deployment ID and
    // carrying the generation the attempt recorded for the server.
    let marker_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    assert_eq!(
        marker_json["deployment_id"].as_str().unwrap(),
        attempt1.deployment_id.as_str(),
        "marker must carry the ORIGINAL pending attempt's deployment id"
    );
    assert_eq!(marker_json["committed"].as_bool(), Some(true));
    let recorded_gen = attempt1.desired[&ServerId::new("server-01")]
        .generation
        .as_ref()
        .expect("attempt records the minted generation");
    assert_eq!(
        marker_json["generation"].as_str().unwrap(),
        recorded_gen.as_str(),
        "marker generation must be the attempt's recorded generation"
    );

    // Finalized: mutable status Successful, reflog + last-successful advanced
    // to attempt 1; the append-only attempts record keeps the original ID.
    let status = std::fs::read_to_string(
        store
            .deployment_dir(attempt1.deployment_id.as_str())
            .join("status"),
    )?;
    assert_eq!(status, "Successful", "mutable status must be finalized");
    let reflog = store.read_reflog("production")?;
    assert_eq!(reflog.len(), 1, "exactly one successful fleet snapshot");
    assert_eq!(reflog[0].deployment_id, attempt1.deployment_id);
    assert_eq!(
        store.read_last_successful("production").as_deref(),
        Some(attempt1.deployment_id.as_str())
    );
    let attempts = store.read_attempts("production")?;
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].deployment_id, attempt1.deployment_id);

    // Push 3 with the same healthy remote: the attempt was already finalized
    // on push 2, so reconciliation must SKIP it (eligibility is the MUTABLE
    // status, now Successful, not the append-only attempts.jsonl record which
    // still says PendingCommit). No re-reconciliation, no duplicate reflog
    // entry, no ref churn, no marker rewrite.
    let marker_before = std::fs::read(&marker)?;
    let last_successful_before = store.read_last_successful("production").unwrap();
    let r3 = push(
        &proj.join("deploy.toml"),
        &store,
        &clean_factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r3.status, None);
    assert_eq!(r3.message, "Everything up to date");
    let reflog = store.read_reflog("production")?;
    assert_eq!(
        reflog.len(),
        1,
        "reconciled attempt must remain eligible for the reflog only once"
    );
    assert_eq!(reflog[0].deployment_id, attempt1.deployment_id);
    assert_eq!(
        store.read_last_successful("production").as_deref(),
        Some(last_successful_before.as_str()),
        "last-successful must be unchanged by a redundant push"
    );
    assert_eq!(
        std::fs::read(&marker)?,
        marker_before,
        "marker must be untouched by a redundant push"
    );
    let status = std::fs::read_to_string(
        store
            .deployment_dir(attempt1.deployment_id.as_str())
            .join("status"),
    )?;
    assert_eq!(
        status, "Successful",
        "mutable status must remain Successful after the redundant push"
    );
    let attempts = store.read_attempts("production")?;
    assert_eq!(attempts.len(), 1, "no new attempt on a redundant push");
    Ok(())
}

#[test]
fn pending_commit_diverged_generation_is_degraded_not_successful() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let config = setup_single(&proj, "true", true, 1);

    // Push 1: marker write fails once -> PendingCommit with no markers.
    let armed = Arc::new(AtomicBool::new(true));
    let armed_for_factory = armed.clone();
    let rf = remotes_base.clone();
    let fault_factory = move |s: &deploy::config::ServerDef,
                              _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        FailOnceMarkerRemote::build(rf.join(&s.id), armed_for_factory.clone())
    };
    let r1 = push(
        &proj.join("deploy.toml"),
        &store,
        &fault_factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r1.status, Some(DeploymentStatus::PendingCommit));
    let attempt1 = r1.attempt.expect("attempt recorded");
    let marker = remotes_base
        .join("server-01/state/commits")
        .join(format!("{}.json", attempt1.deployment_id.as_str()));
    assert!(!marker.exists());

    // Simulate another controller advancing the server: re-point `current` at a
    // generation the pending attempt did not mint, and change the pushed
    // content so this push is a real deployment (a fresh release) rather than
    // an up-to-date no-op.
    let cur = remotes_base.join("server-01/current");
    std::fs::remove_file(&cur)?;
    std::os::unix::fs::symlink("generations/manual-diverge/root", &cur)?;
    write_file(
        &proj
            .join("releases")
            .join("v1")
            .join("artifacts")
            .join("build/output/app/server"),
        "v2\n",
    );

    // Push 2 with a healthy remote: the recorded generation no longer matches
    // (current points at the foreign generation), so recovery must finalize
    // attempt 1 as Degraded (no markers, no reflog entry) and the push itself
    // proceeds as a normal deployment of v2.
    let rf2 = remotes_base.clone();
    let clean_factory = move |s: &deploy::config::ServerDef,
                              _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rf2.join(&s.id))?))
    };
    let r2 = push(
        &proj.join("deploy.toml"),
        &store,
        &clean_factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    let attempt2 = r2.attempt.expect("new attempt recorded");
    assert_eq!(
        r2.status,
        Some(DeploymentStatus::Successful),
        "the push itself proceeds after degrading the diverged pending attempt"
    );

    let status = std::fs::read_to_string(
        store
            .deployment_dir(attempt1.deployment_id.as_str())
            .join("status"),
    )?;
    assert_eq!(
        status, "Degraded",
        "a diverged pending attempt must finalize as Degraded"
    );
    assert!(
        !marker.exists(),
        "no markers may be written for a degraded attempt"
    );
    let reflog = store.read_reflog("production")?;
    assert_eq!(reflog.len(), 1, "only the new push is in the reflog");
    assert_ne!(
        reflog[0].deployment_id, attempt1.deployment_id,
        "the diverged attempt must never enter the reflog"
    );
    assert_eq!(reflog[0].deployment_id, attempt2.deployment_id);
    assert_eq!(
        store.read_last_successful("production").as_deref(),
        Some(attempt2.deployment_id.as_str())
    );
    Ok(())
}

fn write_string(path: &Path, content: &str) -> std::path::PathBuf {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
    path.to_path_buf()
}

// ---- Capacity policy snapshots: identity binding + fail-closed resolution --

/// Changing ONLY `[capacity]` in a variant file must produce a NEW release
/// identity (the canonical policy digest is part of the release payload) while
/// keeping the tree bytes identical, and both releases must retain their own
/// immutable capacity snapshots.
#[test]
fn capacity_only_change_produces_new_release_identity() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store_base = tmp.path().join("store");
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let (config, config_path) = {
        let p = write_string(&proj.join("deploy.toml"), &single_target_toml(true, 1));
        write_variant_file(&proj, "standard", &single_variant_body("true"));
        let artifacts = proj.join("releases").join("v1").join("artifacts");
        write_file(&artifacts.join("build/output/app/server"), "v1\n");
        write_file(&artifacts.join("deployment/common/README"), "common\n");
        (Config::load(&p).unwrap(), p)
    };
    let store = LocalStore::with_base(store_base.clone())?;
    let rf = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
    };

    // f0: deploy with reserve_bytes = 0.
    let r0 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r0.status, Some(DeploymentStatus::Successful));
    let first = r0.attempt.expect("attempt recorded").servers[&ServerId::new("server-01")].clone();
    assert_eq!(first.variant.as_str(), "standard");

    // Capacity-only change: identical bytes except `reserve_bytes`.
    let variant_path = proj.join("releases").join("v1").join("standard.toml");
    let body = std::fs::read_to_string(&variant_path)?;
    let changed = body.replace(
        "[capacity]\nreserve_bytes = 0",
        "[capacity]\nreserve_bytes = 4096",
    );
    assert_ne!(body, changed, "capacity line must exist in fixture");
    std::fs::write(&variant_path, changed).unwrap();
    let config2 = Config::load(&config_path)?;

    let r1 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config2,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r1.status, Some(DeploymentStatus::Successful));
    let second = r1.attempt.expect("attempt recorded").servers[&ServerId::new("server-01")].clone();

    // New release identity, same tree bytes.
    assert_ne!(
        second.release, first.release,
        "a capacity-only change must produce a new release id"
    );
    assert_eq!(
        second.tree, first.tree,
        "tree bytes must be unchanged by a capacity-only change"
    );

    // Each release retains its own immutable snapshot.
    let old_policies = store
        .read_release_policies(&first.release)?
        .expect("old release keeps its snapshot");
    assert_eq!(old_policies["standard"].capacity.reserve_bytes, 0);
    let new_policies = store
        .read_release_policies(&second.release)?
        .expect("new release persists its snapshot");
    assert_eq!(new_policies["standard"].capacity.reserve_bytes, 4096);
    Ok(())
}

/// A corrupt historical policies.json must fail the attempt during preflight —
/// never fall back to current configuration or defaults — and must leave every
/// server untouched.
#[test]
fn corrupt_historical_policies_fail_preflight_without_remote_mutation() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store_base = tmp.path().join("store");
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let (config, config_path) = {
        let p = write_string(&proj.join("deploy.toml"), &single_target_toml(true, 1));
        write_variant_file(&proj, "standard", &single_variant_body("true"));
        let artifacts = proj.join("releases").join("v1").join("artifacts");
        write_file(&artifacts.join("build/output/app/server"), "v1\n");
        write_file(&artifacts.join("deployment/common/README"), "common\n");
        (Config::load(&p).unwrap(), p)
    };
    let store = LocalStore::with_base(store_base.clone())?;
    let rf = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
    };

    let r0 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r0.status, Some(DeploymentStatus::Successful));
    let release = r0.attempt.expect("attempt recorded").servers[&ServerId::new("server-01")]
        .release
        .clone();

    // Deploy different content so the fleet advances to f1 and a rollback to
    // f0 becomes real work instead of an up-to-date no-op.
    write_file(
        &proj
            .join("releases")
            .join("v1")
            .join("artifacts")
            .join("build/output/app/server"),
        "v2\n",
    );
    let config_v2 = Config::load(&config_path)?;
    let r1 = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config_v2,
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r1.status, Some(DeploymentStatus::Successful));
    assert_ne!(
        r1.attempt.expect("attempt recorded").servers[&ServerId::new("server-01")].release,
        release,
        "changed inputs must produce a new release"
    );

    // Snapshot of healthy remote state before corruption.
    let current_before = std::fs::read_link(remotes_base.join("server-01/current"))?;

    // Corrupt the historical snapshot.
    let policies_path = store_base
        .join("releases")
        .join(release.as_str())
        .join("policies.json");
    std::fs::write(&policies_path, b"{ this is not json").unwrap();

    // Rollback to @f0 now fails during preflight...
    let err = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: false,
            ref_token: Some("production@f0".to_string()),
        },
    )
    .err()
    .expect("corrupt policy snapshot must fail the push");
    let msg = err.to_string();
    assert!(
        msg.contains("polic") && msg.to_lowercase().contains("preflight"),
        "error must name the policy preflight failure, got: {msg}"
    );

    // ...and no server was touched.
    let current_after = std::fs::read_link(remotes_base.join("server-01/current"))?;
    assert_eq!(
        current_before, current_after,
        "`current` must be unchanged by the failed attempt"
    );
    Ok(())
}

// ---- Dry-run must leave NO trace: byte-identical tempdir fingerprint ------

/// A single-pod project (via `setup_single`) with store, project, and remotes
/// all under ONE tempdir root. The whole tempdir is fingerprinted before and
/// after a dry-run push: a dry run must mutate nothing — no remote layout, no
/// store objects, and no leftover disposable staging.
#[test]
fn dry_run_leaves_no_trace_fingerprint() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let proj = root.join("proj");
    std::fs::create_dir_all(&proj).unwrap();

    let config = setup_single(&proj, "true", true, 1);
    let store = LocalStore::with_base(root.join("store"))?;
    let rb = root.join("remotes");

    let factory = move |s: &deploy::config::ServerDef,
                        _pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rb.join(&s.id))?))
    };

    let before = remote_fingerprint(root);
    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: true,
            ref_token: None,
        },
    )?;
    assert!(r.dry_run && r.attempt.is_none());
    assert_eq!(
        before,
        remote_fingerprint(root),
        "a successful dry run must not change a single byte on disk"
    );

    // Remove the artifact source so the NEXT dry run fails during planning.
    // Deleting `releases/v1/artifacts/build/output/app/server` alone would only
    // change the tree contents (the mapping source is the parent directory),
    // so the whole mapped source subtree is removed: materialization must fail
    // closed BEFORE any mutation, and the RAII staging guard must still have
    // removed every disposable byte.
    let deleted_file = proj.join("releases/v1/artifacts/build/output/app/server");
    assert!(deleted_file.exists(), "fixture artifact must exist");
    std::fs::remove_dir_all(proj.join("releases/v1/artifacts/build/output"))?;

    let mid = remote_fingerprint(root);
    let r2 = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: true,
            ref_token: None,
        },
    );
    assert!(
        r2.is_err(),
        "dry run with vanished artifact source must fail, got {:?}",
        r2.map(|rep| rep.dry_run)
    );
    assert_eq!(
        mid,
        remote_fingerprint(root),
        "a FAILED dry run must also not change a single byte on disk"
    );

    // No disposable staging leftovers from either run.
    let staging_entries: Vec<_> = std::fs::read_dir(store.staging_dir())
        .map(|d| d.flatten().collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        staging_entries.is_empty(),
        "<store>/staging must contain no entries after a dry run"
    );
    Ok(())
}

/// A factory that fails for every server aborts the dry run during remote-handle
/// construction; that must not mutate anything either.
#[test]
fn dry_run_factory_failure_mutates_nothing() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let proj = root.join("proj");
    std::fs::create_dir_all(&proj).unwrap();

    let config = setup_single(&proj, "true", true, 1);
    let store = LocalStore::with_base(root.join("store"))?;

    let factory = |_s: &deploy::config::ServerDef,
                   _pod: &deploy::config::PodDef|
     -> Result<Box<dyn Remote>> {
        Err(deploy::error::Error::remote("factory forced failure"))
    };

    let before = remote_fingerprint(root);
    let r = push(
        &proj.join("deploy.toml"),
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: true,
            ref_token: None,
        },
    );
    assert!(r.is_err(), "push with a failing factory must return Err");
    assert_eq!(
        before,
        remote_fingerprint(root),
        "a factory failure during a dry run must not mutate anything"
    );
    Ok(())
}

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

const CONFIG: &str = r#"
schema_version: 1
application: example
remote_root: /srv/deploy/example
variants:
  standard: {}
  high-capacity: {}
artifact:
  mappings:
    - from: build/output/
      to: app/
      recursive: true
    - from: deployment/common/
      to: app/
      recursive: true
    - from: "deployment/variants/{{ variant }}/"
      to: app/
      recursive: true
      conflict: replace
activation:
  adapter: none
verification:
  adapter: command
  argv:
    - "true"
  timeout_seconds: 5
  attempts: 1
  interval_seconds: 0
capacity:
  reserve_bytes: 0
  reserve_percent: 0
rotation:
  per_server:
    keep_distinct_artifacts: 5
    keep_days: 14
    protect_previous: true
  fleet:
    protect_deployments: 2
targets:
  production:
    rollout:
      batch_size: 2
      stop_on_failure: true
      failure_policy: rollback_changed
    servers:
      - id: server-01
        address: server-01.example.com
        user: deploy
        variant: standard
      - id: server-02
        address: server-02.example.com
        user: deploy
        variant: standard
      - id: server-03
        address: server-03.example.com
        user: deploy
        variant: high-capacity
"#;

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn setup(proj: &Path) -> (Config, std::path::PathBuf) {
    write_file(&proj.join("deploy.yaml"), CONFIG);
    write_file(&proj.join("build/output/app/server"), "server-v1\n");
    write_file(&proj.join("deployment/common/README"), "common\n");
    write_file(&proj.join("deployment/variants/standard/extra"), "std\n");
    write_file(
        &proj.join("deployment/variants/high-capacity/extra"),
        "hc\n",
    );
    let config = Config::load(&proj.join("deploy.yaml")).unwrap();
    (config, proj.join("deploy.yaml"))
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

    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        let p = remotes_base.join(&s.id);
        Ok(Box::new(LocalTransport::new(p)?))
    };

    // First push (f0).
    let r0 = push(
        &config,
        &config_path,
        &store,
        &factory,
        "production",
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
        &config,
        &config_path,
        &store,
        &factory,
        "production",
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert!(r_up.status.is_none(), "re-push with no change is a no-op");
    assert_eq!(r_up.message, "Everything up to date");

    // Change content and push again (f1).
    write_file(&proj.join("build/output/app/server"), "server-v2\n");
    let r1 = push(
        &config,
        &config_path,
        &store,
        &factory,
        "production",
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
        &config,
        &config_path,
        &store,
        &factory,
        "production",
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

#[test]
fn dry_run_reports_plan() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    let (config, config_path) = setup(&proj);
    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        let p = remotes_base.join(&s.id);
        Ok(Box::new(LocalTransport::new(p)?))
    };
    let r = push(
        &config,
        &config_path,
        &store,
        &factory,
        "production",
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
use std::sync::atomic::{AtomicUsize, Ordering};
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
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> deploy::error::Result<bool> {
        self.attempted.fetch_add(1, Ordering::SeqCst);
        if self.fail_write {
            return Err(deploy::error::Error::remote(
                "FaultRemote: write forced to fail",
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

/// Minimal target with a single variant and `activation: none`.
fn single_target_yaml(verify_argv: &str, stop_on_failure: bool, batch_size: u32) -> String {
    format!(
        r#"
schema_version: 1
application: example
remote_root: /srv/deploy/example
variants:
  standard: {{}}
artifact:
  mappings:
    - from: build/output/
      to: app/
      recursive: true
    - from: deployment/common/
      to: app/
      recursive: true
activation: {{ adapter: none }}
verification:
  adapter: command
  argv:
    - {verify_argv}
  timeout_seconds: 5
  attempts: 1
  interval_seconds: 0
capacity:
  reserve_bytes: 0
  reserve_percent: 0
rotation:
  per_server:
    keep_distinct_artifacts: 5
    keep_days: 14
    protect_previous: true
  fleet:
    protect_deployments: 2
targets:
  production:
    rollout:
      batch_size: {batch_size}
      stop_on_failure: {stop_on_failure}
      failure_policy: rollback_changed
    servers:
      - id: server-01
        address: server-01.example.com
        user: deploy
        variant: standard
"#
    )
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
    // application store's `remotes/` directory.
    let config_yaml = r#"
schema_version: 1
application: example
remote_root: /srv/deploy/example
variants:
  standard: {}
artifact:
  mappings:
    - from: build/output/
      to: app/
      recursive: true
activation: { adapter: none }
verification: { adapter: command, argv: ["true"], timeout_seconds: 5, attempts: 1, interval_seconds: 0 }
capacity: { reserve_bytes: 0, reserve_percent: 0 }
rotation: { per_server: { keep_distinct_artifacts: 5, keep_days: 14, protect_previous: true }, fleet: { protect_deployments: 2 } }
targets:
  production:
    rollout: { batch_size: 1, stop_on_failure: true, failure_policy: rollback_changed }
    servers:
      - id: server-01
        address: local:///dev/null/should-not-be-used
        user: deploy
        variant: standard
"#;
    write_file(&proj.join("deploy.yaml"), config_yaml);
    write_file(&proj.join("build/output/app/server"), "v1\n");
    write_file(&proj.join("deployment/common/README"), "common\n");

    let mut config = Config::load(&proj.join("deploy.yaml"))?;
    let store = LocalStore::with_base(store_base.clone())?;

    // Plug the real endpoint directory into the server address and use the real
    // CLI remote factory (create_remote), which routes `local://` addresses to
    // the configured endpoint rather than the application store's remotes/.
    config.targets.get_mut("production").unwrap().servers[0].address =
        format!("local://{}", endpoints.join("server-01").display());

    let factory_config = config.clone();
    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        create_remote(&factory_config, s)
    };

    let r = push(
        &config,
        &proj.join("deploy.yaml"),
        &store,
        &factory,
        "production",
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

    let config = Config::load(&write_string(
        &proj.join("deploy.yaml"),
        &single_target_yaml("true", true, 1),
    ))?;
    write_file(&proj.join("build/output/app/server"), "v1\n");
    write_file(&proj.join("deployment/common/README"), "common\n");

    let mutations = Arc::new(AtomicUsize::new(0));
    let m = mutations.clone();
    let rb = remote_base.clone();
    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        SpyRemote::build(rb.join(&s.id), m.clone())
    };

    let r = push(
        &config,
        &proj.join("deploy.yaml"),
        &store,
        &factory,
        "production",
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
    let config_a = Config::load(&write_string(
        &proj.join("deploy.yaml"),
        &single_target_yaml("true", true, 1),
    ))?;
    write_file(&proj.join("build/output/app/server"), "v1\n");
    write_file(&proj.join("deployment/common/README"), "common\n");
    let a_digest = release::behavior_digest(&config_a.activation, &config_a.verification);
    let b_digest = {
        // Behavior B: verification command differs (so its digest differs).
        let config_b = Config::load(&write_string(
            &proj.join("deploy.yaml"),
            &single_target_yaml("false", true, 1),
        ))?;
        release::behavior_digest(&config_b.activation, &config_b.verification)
    };
    assert_ne!(a_digest, b_digest, "behaviors must differ");

    let rb = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rb.join(&s.id))?))
    };

    // Deploy with behavior A (f0).
    let r0 = push(
        &config_a,
        &proj.join("deploy.yaml"),
        &store,
        &factory,
        "production",
        &PushOptions {
            dry_run: false,
            ref_token: None,
        },
    )?;
    assert_eq!(r0.status, Some(DeploymentStatus::Successful));

    // Change the configuration to behavior B, then roll back to f0.
    let config_b = Config::load(&write_string(
        &proj.join("deploy.yaml"),
        &single_target_yaml("false", true, 1),
    ))?;
    let rrb = push(
        &config_b,
        &proj.join("deploy.yaml"),
        &store,
        &factory,
        "production",
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
    let verify_argv = behavior["verification"]["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        verify_argv, vec!["true".to_string()],
        "historical release behavior.json must keep behavior A, not be overwritten with B"
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
    let yaml = r#"
schema_version: 1
application: example
remote_root: /srv/deploy/example
variants:
  standard: {}
artifact:
  mappings:
    - from: build/output/
      to: app/
      recursive: true
activation: { adapter: none }
verification: { adapter: command, argv: ["false"], timeout_seconds: 5, attempts: 1, interval_seconds: 0 }
capacity: { reserve_bytes: 0, reserve_percent: 0 }
rotation: { per_server: { keep_distinct_artifacts: 5, keep_days: 14, protect_previous: true }, fleet: { protect_deployments: 2 } }
targets:
  production:
    rollout: { batch_size: 1, stop_on_failure: true, failure_policy: rollback_changed }
    servers:
      - id: server-01
        address: a
        user: u
        variant: standard
      - id: server-02
        address: b
        user: u
        variant: standard
      - id: server-03
        address: c
        user: u
        variant: standard
"#;
    write_file(&proj.join("deploy.yaml"), yaml);
    write_file(&proj.join("build/output/app/server"), "v1\n");

    let config = Config::load(&proj.join("deploy.yaml"))?;
    let rf = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(rf.join(&s.id))?))
    };

    // Must not panic.
    let r = push(
        &config,
        &proj.join("deploy.yaml"),
        &store,
        &factory,
        "production",
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

    let config = Config::load(&write_string(
        &proj.join("deploy.yaml"),
        &single_target_yaml("true", true, 1),
    ))?;
    write_file(&proj.join("build/output/app/server"), "v1\n");
    write_file(&proj.join("deployment/common/README"), "common\n");

    // Fail the rename that performs the tree publish, AFTER the mutation lock is
    // acquired.
    let attempted = Arc::new(AtomicUsize::new(0));
    let at = attempted.clone();
    let remotes_for_factory = remotes_base.clone();
    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        FaultRemote::build(
            remotes_for_factory.join(&s.id),
            true,
            false,
            false,
            at.clone(),
        )
    };

    let r = push(
        &config,
        &proj.join("deploy.yaml"),
        &store,
        &factory,
        "production",
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

fn write_string(path: &Path, content: &str) -> std::path::PathBuf {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
    path.to_path_buf()
}

//! End-to-end integration test exercising the full push transaction against a
//! local (filesystem) transport that mirrors the SSH remote layout.

use deploy::config::Config;
use deploy::error::Result;
use deploy::model::{ServerId, TreeDigest};
use deploy::push::engine::{push, PushOptions};
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
    assert_eq!(r0.status, Some(DeploymentStatus::Successful), "first push should succeed");
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
    assert_ne!(std_v1, std_v2, "standard tree changed after editing content");
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
    assert_eq!(rrb.status, Some(DeploymentStatus::Successful), "rollback succeeds");
    let observed = store.read_observed("production")?;
    let restored = observed.servers[&ServerId::new("server-01")].tree.clone().unwrap();
    assert_eq!(restored, std_v1, "server-01 rolled back to original tree");
    let hc_restored = observed.servers[&ServerId::new("server-03")].tree.clone().unwrap();
    assert_eq!(hc_restored, hc_v1, "server-03 still on its tree (restored from f0)");

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
    assert!(observed.servers.is_empty(), "dry-run leaves no observed state");
    Ok(())
}

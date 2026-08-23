//! Round-trip: `deploy init` scaffolds a project, and the scaffolded project
//! pushes end-to-end (dry-run, then real) through the same engine path the CLI
//! uses — with zero SSH, because the scaffold defaults to a `local://`
//! endpoint inside the project.
//!
//! The CLI arm is exercised for `init` (`cli::run_with`), while the push is
//! driven through `push::engine::push` with the real `create_remote` factory
//! and an isolated store, mirroring the other integration suites. The store
//! reads backing `deploy log`/`deploy status` are asserted at the end.

use deploy::cli;
use deploy::config::Config;
use deploy::error::Result;
use deploy::layout;
use deploy::push::engine::{PushOptions, push};
use deploy::records::DeploymentStatus;
use deploy::remote::create_remote;
use deploy::remote::helper::RemoteHelper;
use deploy::remote::transport::{LocalTransport, Remote};
use deploy::store::local::LocalStore;
use std::path::Path;

const PLACEHOLDER: &str = "Hello from deploy!\n\
\n\
This placeholder is mapped into the artifact as `app/hello` by the\n\
`standard` variant (see releases/v1/standard.toml). Add or replace files\n\
under releases/v1/artifacts/ and run `deploy push production` again.\n";

#[test]
fn cli_init_then_push_roundtrip() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("roundtrip-app");

    // 1. `deploy init <path>` through the real CLI argv path.
    cli::run_with(["deploy", "init", proj.to_str().unwrap()])?;

    // 2. The scaffolded layout is exactly the documented one.
    let expected_files = [
        "deploy.toml",
        "releases/v1/standard.toml",
        "releases/v1/artifacts/build/output/app/hello",
        ".gitignore",
    ];
    for f in expected_files {
        assert!(
            proj.join(f).is_file(),
            "missing scaffolded file {f} (at {})",
            proj.join(f).display()
        );
    }
    assert!(
        proj.join(".deploy-remote").is_dir(),
        "local endpoint created"
    );
    assert!(
        !proj.join(".deploy-remote/current").exists(),
        "init creates no deployment state"
    );

    // 3. The scaffolded config loads and validates (strict rules: absolute
    // deploy_dir, unique server ids, known variant, non-empty target).
    let config_path = proj.join("deploy.toml");
    let config = Config::load(&config_path)?;
    assert_eq!(config.application, "roundtrip-app");
    assert_eq!(config.release.as_str(), "v1");
    assert_eq!(config.targets["production"].pods, vec!["app-1"]);
    assert_eq!(config.targets["production"].rollout.batch_size, 1);
    let variant = config.variant("standard")?;
    assert_eq!(variant.verification.argv, vec!["true"]);
    assert_eq!(variant.capacity.reserve_bytes, 0);
    assert_eq!(
        variant.activation.adapter, "none",
        "activation none is the zero-infrastructure default"
    );
    let addr = &config.servers[0].address;
    assert!(
        addr.starts_with("local://")
            && Path::new(addr.trim_start_matches("local://")).is_absolute(),
        "local-first address must be an absolute local:// path, got {addr}"
    );

    // 4. Dry-run: plans the deployment, touches neither store nor endpoint.
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let factory = move |s: &deploy::config::ServerDef,
                        pod: &deploy::config::PodDef|
          -> Result<Box<dyn Remote>> { create_remote(s, &pod.deploy_dir) };

    let r_dry = push(
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
    assert!(r_dry.dry_run);
    assert!(r_dry.attempt.is_none(), "dry-run creates no attempt");
    assert!(
        r_dry.message.contains("dry-run plan"),
        "dry-run reports a plan: {}",
        r_dry.message
    );
    assert!(
        !proj.join(".deploy-remote/current").exists(),
        "dry-run leaves the endpoint untouched"
    );
    assert_eq!(store.read_attempts("production")?.len(), 0);

    // 5. Real push: successful deployment end-to-end.
    let r = push(
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
        r.status,
        Some(DeploymentStatus::Successful),
        "scaffolded project deploys successfully: {}",
        r.message
    );
    let attempt = r.attempt.expect("attempt recorded");
    assert_eq!(attempt.server_ids.len(), 1);
    let srv = &attempt.servers[&deploy::model::ServerId::new("server-01")];
    let generation = srv.generation.as_ref().expect("generation assigned");

    // 6. Remote state: the local endpoint now carries the full layout, the
    // `current` symlink points at the new generation, and the mapped artifact
    // is present with the placeholder content.
    let endpoint = LocalTransport::new(proj.join(".deploy-remote"))?;
    let helper = RemoteHelper::new(&endpoint);
    let status = helper.status()?;
    assert_eq!(
        status.current_generation.as_deref(),
        Some(generation.as_str()),
        "current symlink points at the deployed generation"
    );
    let tree_path = layout::objects().join(srv.tree.as_str()).join("root");
    assert!(
        endpoint.exists(&tree_path.join("app/hello")),
        "artifact mapped to app/hello"
    );
    let hello = String::from_utf8(endpoint.read(&tree_path.join("app/hello"))?).unwrap();
    assert_eq!(hello, PLACEHOLDER, "placeholder content round-trips");

    // 7. History, reflog, and observed state back `deploy log` / `deploy status`.
    let attempts = store.read_attempts("production")?;
    assert_eq!(attempts.len(), 1, "one attempt in `deploy log production`");
    assert_eq!(
        attempts[0].deployment_id, attempt.deployment_id,
        "attempt is durable"
    );
    let reflog = store.read_reflog("production")?;
    assert_eq!(
        reflog.len(),
        1,
        "one successful fleet snapshot (production@f0)"
    );
    assert_eq!(reflog[0].index, 0);

    let observed = store.read_observed("production")?;
    let obs = &observed.servers[&deploy::model::ServerId::new("server-01")];
    assert_eq!(
        obs.generation.as_ref(),
        Some(generation),
        "`deploy status` shows the deployed generation"
    );
    assert_eq!(obs.variant.as_ref().map(|v| v.as_str()), Some("standard"));
    assert_eq!(obs.tree.as_ref(), Some(&srv.tree));

    // A second push with identical content is a no-op (no new attempt).
    let r2 = push(
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
    assert_eq!(r2.message, "Everything up to date");
    assert_eq!(store.read_attempts("production")?.len(), 1);

    // 8. Fail closed: a second `deploy init` refuses to clobber.
    let err = cli::run_with(["deploy", "init", proj.to_str().unwrap()]).unwrap_err();
    assert!(
        err.to_string().contains("clobber"),
        "second init must refuse: {err}"
    );

    Ok(())
}

/// `deploy init --name` and `--address` overrides land in deploy.toml.
#[test]
fn cli_init_flags_reach_config() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("flagged-app");
    cli::run_with([
        "deploy",
        "init",
        proj.to_str().unwrap(),
        "--name",
        "backend",
        "--user",
        "ops",
    ])?;
    let config = Config::load(&proj.join("deploy.toml"))?;
    assert_eq!(config.application, "backend");
    assert_eq!(config.servers[0].user, "ops");
    Ok(())
}

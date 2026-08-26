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
        "releases/v1/systemd.toml",
        "releases/v1/artifacts/build/output/app/hello",
        "releases/v1/artifacts/systemd/example.service",
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
    assert_eq!(config.release().as_str(), "v1");
    // Membership is derived from the slots' `targets` lists (the slot is
    // declared inside releases/v1/standard.toml, bound to `production`).
    assert_eq!(config.target_slot_ids("production")?, vec!["app-1"]);
    assert_eq!(config.targets["production"].rollout.batch_size, 1);
    let variant = config.variant("standard")?;
    assert_eq!(variant.verification.argv, vec!["true"]);
    assert_eq!(
        variant.activation,
        deploy::config::Activation::None,
        "activation none is the zero-infrastructure default"
    );
    // The scaffold also ships the `systemd` example variant with a real unit
    // artifact; it declares no slots, so the real push below stays
    // adapter-agnostic (no systemctl on the local endpoint).
    let systemd = config.variant("systemd")?;
    let deploy::config::Activation::Systemd(sa) = &systemd.activation else {
        return Err(deploy::error::Error::internal(
            "systemd variant must carry the systemd activation",
        ));
    };
    assert_eq!(sa.scope, deploy::config::ActivationScope::User);
    assert_eq!(sa.units.len(), 1);
    assert_eq!(sa.units[0].name, "example.service");
    assert_eq!(sa.units[0].artifact_path, "app/example.service");
    assert!(
        proj.join("releases/v1/artifacts/systemd/example.service")
            .is_file(),
        "the unit artifact is scaffolded"
    );
    // Capacity is a per-server policy: the scaffold puts it on the server
    // entry (0/0 by default), and the variant file has no `[capacity]` block.
    assert_eq!(config.servers[0].capacity.reserve_bytes, 0);
    assert_eq!(config.servers[0].capacity.reserve_percent, 0);
    let addr = &config.servers[0].address;
    assert!(
        addr.starts_with("local://")
            && Path::new(addr.trim_start_matches("local://")).is_absolute(),
        "local-first address must be an absolute local:// path, got {addr}"
    );

    // 4. Dry-run: plans the deployment, touches neither store nor endpoint.
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let factory = move |s: &deploy::config::ServerDef,
                        slot: &deploy::config::SlotDef|
          -> Result<Box<dyn Remote>> { create_remote(s, &slot.deploy_dir) };

    let r_dry = push(
        &config_path,
        &store,
        &factory,
        "production",
        &config,
        &PushOptions {
            dry_run: true,
            ref_token: None,
            group: None,
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
    assert_eq!(store.read_ledger("production")?.len(), 0);

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
            group: None,
        },
    )?;
    assert_eq!(
        r.status,
        Some(DeploymentStatus::Successful),
        "scaffolded project deploys successfully: {}",
        r.message
    );
    let attempt = r.attempt.expect("attempt recorded");
    assert_eq!(attempt.slot_ids.len(), 1);
    let srv = &attempt.slots[&deploy::model::PlacementSlotId::new("app-1")];
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
    let tree_path = layout::objects()
        .join(srv.artifact.tree.as_str())
        .join("root");
    assert!(
        endpoint.exists(&tree_path.join("app/hello")),
        "artifact mapped to app/hello"
    );
    let hello = String::from_utf8(endpoint.read(&tree_path.join("app/hello"))?).unwrap();
    assert_eq!(hello, PLACEHOLDER, "placeholder content round-trips");

    // 7. History, snapshot log, and observed state back `deploy log` /
    // `deploy status`.
    let attempts = store.read_ledger("production")?;
    assert_eq!(attempts.len(), 1, "one entry in `deploy log production`");
    assert_eq!(
        attempts[0].deployment_id, attempt.deployment_id,
        "attempt is durable"
    );
    // The latest transition is the attempt's status (Successful after a full
    // push), carried in `deployments/<id>/transitions.jsonl`.
    assert_eq!(
        store.latest_status(attempt.deployment_id.as_str())?,
        Some(DeploymentStatus::Successful),
        "latest transition must be Successful"
    );
    // The successful entries (the old snapshot log) are the ledger entries
    // whose terminal is Successful with a rollback payload.
    let snapshots: Vec<_> = store
        .read_ledger("production")?
        .into_iter()
        .filter(|e| {
            e.terminal
                .as_ref()
                .is_some_and(|t| t.status == DeploymentStatus::Successful && t.rollback.is_some())
        })
        .collect();
    assert_eq!(
        snapshots.len(),
        1,
        "one successful snapshot (keyed by the deployment id)"
    );
    assert_eq!(
        snapshots[0].deployment_id, attempt.deployment_id,
        "the snapshot is keyed by the deployment that produced it"
    );

    // `deploy log production` renders one line per attempt, each PREFIXED
    // with the DEPLOYMENT ID of the snapshot that attempt produced — the
    // exact rollback key the push reference grammar accepts.
    let log_lines = cli::render_log(&store, "production", &attempts)?;
    assert_eq!(log_lines.len(), 1, "one line in `deploy log production`");
    assert!(
        log_lines[0].starts_with(&format!("{}  ", attempt.deployment_id)),
        "log line must be prefixed with the rollback deployment id: {}",
        log_lines[0]
    );

    let observed = store.read_observed("production", &config)?;
    let obs = &observed.slots[&deploy::model::PlacementSlotId::new("app-1")];
    assert_eq!(
        obs.generation.as_ref(),
        Some(generation),
        "`deploy status` shows the deployed generation"
    );
    assert_eq!(
        obs.artifact.as_ref().map(|a| a.variant.as_str()),
        Some("standard")
    );
    assert_eq!(
        obs.artifact.as_ref().map(|a| &a.tree),
        Some(&srv.artifact.tree)
    );

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
            group: None,
        },
    )?;
    assert_eq!(r2.message, "Everything up to date");
    assert_eq!(store.read_ledger("production")?.len(), 1);

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

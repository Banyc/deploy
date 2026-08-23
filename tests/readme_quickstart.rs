//! The Quick Start example in `README.md` stays a working configuration, not
//! merely prose: the fixture tree under `tests/fixtures/quickstart/` mirrors
//! the documented example and must parse, validate, and materialize under the
//! current schema (via a full dry-run push), so a schema change cannot silently
//! invalidate the documented configuration.

use deploy::config::Config;
use deploy::error::Result;
use deploy::push::engine::{PushOptions, push};
use deploy::remote::transport::{LocalTransport, Remote};
use deploy::store::local::LocalStore;
use std::path::Path;

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn copy_tree(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let from = entry.unwrap().path();
        let to = dst.join(from.file_name().unwrap());
        if from.is_dir() {
            std::fs::create_dir_all(&to).unwrap();
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

#[test]
fn quickstart_fixture_parses_and_plans() -> Result<()> {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("my-project");
    std::fs::create_dir_all(&proj).unwrap();
    copy_tree(
        &Path::new(MANIFEST).join("tests/fixtures/quickstart"),
        &proj,
    );

    let config_path = proj.join("deploy.toml");
    let config = Config::load(&config_path)?;
    assert_eq!(config.release.as_str(), "v1");
    assert!(
        config.release_root(&config_path).ends_with("releases/v1"),
        "release directory is forced beneath releases/"
    );
    assert_eq!(config.targets["production"].slots.len(), 2);
    let variant = config.variant("standard")?;
    assert_eq!(
        &variant.artifact.mappings[0].from,
        "artifacts/build/output/"
    );
    // The `systemd` example variant ships a real unit file as an artifact; it
    // is not bound to any slot, so the dry-run push stays adapter-agnostic.
    let systemd = config.variant("systemd")?;
    assert_eq!(systemd.activation.adapter, "systemd");
    assert_eq!(
        systemd.activation.scope,
        deploy::config::ActivationScope::User
    );
    assert_eq!(systemd.activation.reconcile_managed_units, true);
    assert_eq!(systemd.activation.units.len(), 1, "one managed unit");
    assert_eq!(systemd.activation.units[0].name, "example.service");
    assert_eq!(
        systemd.activation.units[0].artifact_path,
        "app/example.service"
    );
    assert!(
        proj.join("releases/v1/artifacts/systemd/example.service")
            .is_file(),
        "the unit artifact ships with the fixture"
    );
    // Capacity is a per-server policy, not a variant one.
    assert_eq!(config.servers[0].capacity.reserve_bytes, 1_073_741_824);
    assert_eq!(config.servers[1].capacity.reserve_bytes, 1_073_741_824);

    // A dry-run materializes the release's artifacts and builds the full plan:
    // the documented example stays a working configuration, not merely
    // parseable TOML.
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();
    let factory = move |s: &deploy::config::ServerDef,
                        _slot: &deploy::config::SlotDef|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(remotes_base.join(&s.id))?))
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
    assert!(r.message.contains("dry-run plan"));
    assert!(r.message.contains("app-1"));
    assert!(r.message.contains("app-2"));
    Ok(())
}

//! The Quick Start example in `README.md` stays a working configuration, not
//! merely prose: the fixture tree under `tests/fixtures/quickstart/` mirrors
//! the documented example and must parse, validate, and materialize under the
//! current schema (via a full dry-run push), so a schema change cannot silently
//! invalidate the documented configuration.

use deploy::config::ProjectConfig;
use deploy::deploy::{PushOptions, push};
use deploy::error::Result;
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
    let config = ProjectConfig::load(&config_path)?;
    assert_eq!(config.release().as_str(), "v1");
    assert!(
        config.release_root(&config_path).ends_with("releases/v1"),
        "release directory is forced beneath releases/"
    );
    // Membership is DERIVED from the slots' `target` fields: the two slots
    // are declared inside releases/v1/standard.toml and both bind to
    // `production`.
    assert_eq!(config.target_slot_ids("production")?.len(), 2);
    let std_slots = &config.variant("standard")?.slots;
    assert_eq!(std_slots.len(), 2, "standard.toml declares app-1 and app-2");
    assert!(
        std_slots.iter().all(|s| s.target == "production"),
        "both slots bind to target `production`"
    );
    let variant = config.variant("standard")?;
    assert_eq!(
        &variant.artifact.mappings[0].from,
        "artifacts/build/output/"
    );
    // The `systemd` example variant ships a real unit file as an artifact; it
    // declares no slots (you add a slot with a `target` field to bind it), so
    // the dry-run push stays adapter-agnostic.
    let systemd = config.variant("systemd")?;
    let deploy::config::Activation::Systemd(sa) = &systemd.activation else {
        return Err(deploy::error::Error::internal(
            "systemd variant must carry the systemd activation",
        ));
    };
    assert_eq!(sa.scope(), &deploy::config::ActivationScope::User);
    assert!(sa.reconcile_managed_units());
    assert_eq!(sa.units().count(), 1, "one managed unit");
    assert_eq!(sa.units().next().unwrap().name(), "example.service");
    assert_eq!(
        sa.units().next().unwrap().artifact_path(),
        "app/example.service"
    );
    assert!(
        proj.join("releases/v1/artifacts/systemd/example.service")
            .is_file(),
        "the unit artifact ships with the fixture"
    );
    // Capacity is a per-server policy, not a variant one.
    assert_eq!(
        config.servers().next().unwrap().capacity.reserve_bytes,
        1_073_741_824
    );
    assert_eq!(
        config.servers().nth(1).unwrap().capacity.reserve_bytes,
        1_073_741_824
    );
    // SSH-shaped addresses carry exactly one host-identity source (the
    // placeholder fingerprint in the fixture), so the documented example stays
    // valid under the exactly-one rule — the domain holds it as a single
    // `HostIdentity::Fingerprint`, never an option pair.
    for s in config.servers() {
        assert!(
            matches!(s.identity(), deploy::config::HostIdentity::Fingerprint(_)),
            "server '{}' must have exactly one identity form",
            s.id
        );
    }

    // A dry-run materializes the release's artifacts and builds the full plan:
    // the documented example stays a working configuration, not merely
    // parseable TOML.
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();
    let factory = move |s: &deploy::config::ServerDef,
                        _slot: &deploy::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(
            &deploy::env::SysEnv::from_process(),
            remotes_base.join(s.id.as_str()),
        )?))
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
            group: None,
        },
    )?;
    assert!(r.dry_run);
    assert!(r.message.contains("dry-run plan"));
    assert!(r.message.contains("app-1"));
    assert!(r.message.contains("app-2"));
    Ok(())
}

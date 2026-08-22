//! The Quick Start example in `README.md` is a checked fixture, not prose:
//!
//! * Fenced blocks marked `<!-- fixture: <path> -->` must match the files under
//!   `tests/fixtures/quickstart/` byte for byte, so the docs cannot drift from
//!   something compilable.
//! * The fixture tree must parse, validate, and materialize under the current
//!   schema (via a full dry-run push), so a schema change cannot silently
//!   invalidate the documented configuration.

use deploy::config::Config;
use deploy::error::Result;
use deploy::push::engine::{PushOptions, push};
use deploy::remote::transport::{LocalTransport, Remote};
use deploy::store::local::LocalStore;
use std::path::{Path, PathBuf};

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn fixture_marker(line: &str) -> Option<PathBuf> {
    let inner = line.trim().strip_prefix("<!-- fixture: ")?.strip_suffix(" -->")?;
    Some(Path::new(MANIFEST).join(inner))
}

/// Extract every `<!-- fixture: path -->` marker and the fenced block that
/// immediately follows it.
fn readme_fixtures(md: &str) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut lines = md.lines();
    while let Some(line) = lines.next() {
        let Some(path) = fixture_marker(line) else { continue };
        let fence = lines.next().unwrap_or_default();
        assert!(
            fence.trim_start().starts_with("```"),
            "fixture marker for {} must be followed by a fenced block",
            path.display()
        );
        let mut body = String::new();
        for l in lines.by_ref() {
            if l.trim_start().starts_with("```") {
                break;
            }
            body.push_str(l);
            body.push('\n');
        }
        out.push((path, body));
    }
    out
}

#[test]
fn readme_examples_match_fixture_files() {
    let md = std::fs::read_to_string(Path::new(MANIFEST).join("README.md")).unwrap();
    let found = readme_fixtures(&md);
    assert!(
        found.len() >= 2,
        "expected the Quick Start deploy.toml and standard.toml fixture blocks"
    );
    for (path, body) in &found {
        let disk = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(
            *body, disk,
            "README example drifted from {}; update both sides together",
            path.display()
        );
    }
}

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
    assert_eq!(config.targets["production"].servers.len(), 2);
    let variant = config.variant("standard")?;
    assert_eq!(&variant.artifact.mappings[0].from, "artifacts/build/output/");
    assert_eq!(variant.capacity.reserve_bytes, 1_073_741_824);

    // A dry-run materializes the release's artifacts and builds the full plan:
    // the documented example stays a working configuration, not merely
    // parseable TOML.
    let store = LocalStore::with_base(tmp.path().join("store"))?;
    let remotes_base = tmp.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();
    let factory = move |s: &deploy::config::ServerDef| -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::new(remotes_base.join(&s.id))?))
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
    assert!(r.message.contains("dry-run plan"));
    assert!(r.message.contains("server-01"));
    assert!(r.message.contains("server-02"));
    Ok(())
}

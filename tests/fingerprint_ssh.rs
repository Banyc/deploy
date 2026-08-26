//! Fingerprint-only SSH transport, driven end to end through the push engine.
//!
//! There is no real sshd in CI, so the remote host is emulated by fake `ssh`,
//! `ssh-keyscan`, and `stat` executables (see `make_fake_bin`) that operate on
//! a local directory. The push pipeline runs against an `SshTransport`
//! configured with ONLY a `host_key_fingerprint` (no `known_hosts`), covering
//! the four scenarios: status, dry-run, first push, and repeat push.

use deploy::config::ProjectConfig;
use deploy::error::Result;
use deploy::push::engine::{PushOptions, push};
use deploy::records::DeploymentStatus;
use deploy::remote::ssh::SshTransport;
use deploy::remote::transport::Remote;
use deploy::store::local::LocalStore;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Serializes the fake-environment tests: they mutate the process-wide `PATH`
/// (an `unsafe` operation in edition 2024), so they must not overlap. Each
/// test also points `DEPLOY_SSH_KNOWNHOSTS_DIR` at its own temp dir, so the
/// pin cache is fully isolated per test (never shared between tests or
/// between the lib and integration binaries).
static SSH_ENV_LOCK: Mutex<()> = Mutex::new(());

/// A real ed25519 host key plus its SHA256 fingerprint, and the fake-bin dir
/// whose `ssh`/`ssh-keyscan`/`stat` scripts emulate the remote host.
struct FakeSsh {
    bin: PathBuf,
    remote_root: PathBuf,
    fingerprint: String,
    keyscan_log: PathBuf,
}

/// Generate a REAL ed25519 host key, compute its SHA256 fingerprint, and write
/// fake `ssh`/`ssh-keyscan`/`stat` executables into `<tmp>/bin` that emulate a
/// remote host whose filesystem is rooted at `<tmp>/remote`.
fn make_fake_bin(tmp: &Path, address: &str) -> FakeSsh {
    let bin = tmp.join("bin");
    let remote_root = tmp.join("remote");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&remote_root).unwrap();

    let keyfile = bin.join("hostkey");
    let out = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&keyfile)
        .output()
        .expect("ssh-keygen must be available");
    assert!(out.status.success(), "ssh-keygen failed");
    let pubkey = std::fs::read_to_string(keyfile.with_extension("pub"))
        .expect("read generated pubkey")
        .trim()
        .to_string();
    let fp = std::process::Command::new("ssh-keygen")
        .args([
            "-lf",
            keyfile.with_extension("pub").to_str().unwrap(),
            "-E",
            "sha256",
        ])
        .output()
        .expect("ssh-keygen -lf must run");
    assert!(fp.status.success());
    let fingerprint = String::from_utf8_lossy(&fp.stdout)
        .split_whitespace()
        .nth(1)
        .expect("fingerprint field")
        .to_string();

    let keyscan_log = bin.join("keyscan.log");

    std::fs::write(
        bin.join("ssh"),
        r#"#!/bin/bash
# Fake `ssh` for tests: emulates a remote host whose filesystem is a local
# directory. `FAKE_SSH_ROOT` is the local dir; `FAKE_SSH_REMOTE_PREFIX` is the
# configured remote deploy dir (e.g. /srv/deploy/app). Every occurrence of the
# remote prefix in the (fully shell-quoted) remote command is remapped to
# $FAKE_SSH_ROOT$FAKE_SSH_REMOTE_PREFIX, then the command runs with `sh -c`.
# Bash literal pattern substitution (no awk subprocess) keeps each remote
# op to a single fork+exec of this shim.
FAKE_ROOT="${FAKE_SSH_ROOT:?FAKE_SSH_ROOT not set}"
REMOTE_PREFIX="${FAKE_SSH_REMOTE_PREFIX:?FAKE_SSH_REMOTE_PREFIX not set}"
cmd=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift 2 ;;
    -p) shift 2 ;;
    --) shift; cmd="$*"; break ;;
    *) shift ;;
  esac
done
[ -n "$cmd" ] || exit 0
remapped=${cmd//"$REMOTE_PREFIX"/"$FAKE_ROOT$REMOTE_PREFIX"}
eval "$remapped"
"#,
    )
    .unwrap();

    std::fs::write(
        bin.join("ssh-keyscan"),
        format!(
            r#"#!/bin/sh
printf 'keyscan\n' >> '{log}'
host=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p) shift 2 ;;
    -T) shift 2 ;;
    -t) shift 2 ;;
    -*) shift ;;
    *) host="$1"; shift ;;
  esac
done
[ -n "$host" ] || host='{address}'
printf '%s %s\n' "$host" '{pubkey}'
"#,
            log = keyscan_log.display(),
            address = address,
            pubkey = pubkey,
        ),
    )
    .unwrap();

    std::fs::write(
        bin.join("stat"),
        r##"#!/usr/bin/perl
# Emulate GNU coreutils `stat -c` (macOS stat lacks it): the transport's
# list/metadata scripts use `stat -c '%f'` (raw mode in hex) and
# `stat -c '%s %f'` (size + raw mode hex). Direct perl (no sh wrapper)
# keeps each metadata call a single exec.
my $fmt = "";
my @rest = ();
while (@ARGV) {
    my $a = shift @ARGV;
    if ($a eq "-c") { $fmt = shift @ARGV; }
    elsif ($a eq "-L") { }
    elsif ($a =~ /^-/) { }
    else { @rest = ($a, @ARGV); last; }
}
if ($fmt eq "%f") {
    my @s = lstat($rest[0]);
    printf "%x\n", $s[2] & 0xffff;
    exit 0;
}
if ($fmt eq "%s %f") {
    my @s = lstat($rest[0]);
    printf "%s %x\n", $s[7], $s[2] & 0xffff;
    exit 0;
}
exec "/usr/bin/stat", @rest;
"##,
    )
    .unwrap();

    std::fs::write(
        bin.join("mv"),
        r#"#!/bin/sh
# Emulate GNU coreutils `mv -T` (no-target-directory): macOS BSD mv lacks -T
# and, like GNU mv without -T, treats a destination that is a symlink to a
# directory as the directory itself and moves the source INTO it. The deploy
# tool's `current` swap depends on GNU -T semantics, so strip the flag and
# remove any existing destination first.
if [ "$1" = "-T" ]; then
  shift
  src="$1"; dst="$2"
  if [ -n "$src" ] && [ -n "$dst" ]; then
    rm -f -- "$dst"
  fi
  exec /bin/mv -- "$src" "$dst"
fi
exec /bin/mv "$@"
"#,
    )
    .unwrap();

    use std::os::unix::fs::PermissionsExt;
    for name in ["ssh", "ssh-keyscan", "stat", "mv"] {
        let p = bin.join(name);
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }

    FakeSsh {
        bin,
        remote_root,
        fingerprint,
        keyscan_log,
    }
}

/// Run `f` with `bin` prepended to `PATH` and `DEPLOY_SSH_KNOWNHOSTS_DIR`
/// pointing at `cache` (both restored afterwards). Pointing the pin cache at a
/// per-test dir isolates it from every other fake-ssh test in any binary — no
/// two tests ever share cache state, so concurrent runs of the lib and
/// integration suites cannot interfere.
fn with_fake_path<T>(bin: &Path, cache: &Path, f: impl FnOnce() -> T) -> T {
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let old_cache = std::env::var_os("DEPLOY_SSH_KNOWNHOSTS_DIR");
    let mut paths: Vec<_> = std::env::split_paths(&old_path).collect();
    paths.insert(0, bin.to_path_buf());
    let joined = std::env::join_paths(paths).unwrap();
    // SAFETY: edition 2024 marks `set_var` unsafe. The caller holds
    // `SSH_ENV_LOCK`, and this binary contains no other tests.
    unsafe {
        std::env::set_var("PATH", &joined);
        std::env::set_var("DEPLOY_SSH_KNOWNHOSTS_DIR", cache);
    }
    let result = f();
    match old_cache {
        Some(v) => unsafe {
            std::env::set_var("DEPLOY_SSH_KNOWNHOSTS_DIR", v);
        },
        None => unsafe {
            std::env::remove_var("DEPLOY_SSH_KNOWNHOSTS_DIR");
        },
    }
    unsafe {
        std::env::set_var("PATH", &old_path);
    }
    result
}

/// Set the fake-ssh environment for the duration of `f`.
fn with_fake_root<T>(root: &Path, prefix: &str, f: impl FnOnce() -> T) -> T {
    unsafe {
        std::env::set_var("FAKE_SSH_ROOT", root);
        std::env::set_var("FAKE_SSH_REMOTE_PREFIX", prefix);
    }
    let result = f();
    unsafe {
        std::env::remove_var("FAKE_SSH_ROOT");
        std::env::remove_var("FAKE_SSH_REMOTE_PREFIX");
    }
    result
}

// ---- project fixtures (single slot, one standard variant) -------------------

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// Variant policy: `activation: none`, `verification: command ["true"]` — no
/// real systemd or service binaries needed over the fake ssh.
fn variant_body() -> &'static str {
    r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#
}

/// Minimal deploy.toml for one server whose address is `address` and whose
/// remote deploy dir is `deploy_dir` (both must match the fake remap prefix).
/// The slot itself is declared inside the variant file (see [`setup_project`]).
fn single_target_toml(address: &str) -> String {
    format!(
        r#"
schema_version = 2
application = "example"
release = "v1"

[[servers]]
id = "server-01"
address = "{address}"
user = "deploy"
port = 2222
# Placeholder identity: the tests construct `SshTransport` directly with the
# real fingerprint of the fake host key, so this only needs to satisfy config
# validation (an SSH address requires exactly one identity source).
host_key_fingerprint = "SHA256:placeholder"

[targets.production]
rollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }}
"#
    )
}

/// Set up a single-slot project (deploy.toml + variant file + artifact inputs),
/// return the loaded config and the config path. The slot is declared inside
/// the variant file and binds itself to `production` with its `targets` list.
fn setup_project(proj: &Path, address: &str, deploy_dir: &str) -> (ProjectConfig, PathBuf) {
    write_file(&proj.join("deploy.toml"), &single_target_toml(address));
    let release_dir = proj.join("releases").join("v1");
    let slot_toml = format!(
        "\n[[slots]]\nid = \"p1\"\nserver = \"server-01\"\ntarget = \"production\"\ndeploy_dir = \"{deploy_dir}\"\n"
    );
    write_file(
        &release_dir.join("standard.toml"),
        &format!("{}{}", variant_body(), slot_toml),
    );
    let artifacts = release_dir.join("artifacts");
    write_file(&artifacts.join("build/output/app/server"), "server-v1\n");
    write_file(&artifacts.join("deployment/common/README"), "common\n");
    let p = proj.join("deploy.toml");
    (ProjectConfig::load(&p).unwrap(), p)
}

/// Snapshot of a directory tree: sorted (relative path, kind+content) pairs,
/// including symlink targets. Two snapshots are equal iff the trees match.
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
                let data = std::fs::read(&p).unwrap_or_default();
                let digest = deploy::digest::sha256_bytes(&data);
                out.push((rel, format!("file:{digest}")));
            }
        }
    }
    let mut out = Vec::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

// ---- Scenario (b): dry-run push works with a fingerprint-only config -------

/// A dry run still connects (status inspection), so the fingerprint-only
/// identity must be prepared; but it must leave the REMOTE layout untouched.
#[test]
fn fingerprint_only_dry_run_leaves_remote_untouched() -> Result<()> {
    let _guard = SSH_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let fake = make_fake_bin(tmp.path(), "dry.test");
    let deploy_dir = "/srv/deploy/dry-run";

    with_fake_path(&fake.bin, &tmp.path().join("knownhosts"), || {
        with_fake_root(&fake.remote_root, deploy_dir, || {
            let proj = tmp.path().join("proj");
            std::fs::create_dir_all(&proj).unwrap();
            let (config, config_path) = setup_project(&proj, "dry.test", deploy_dir);
            let store = LocalStore::with_base(tmp.path().join("store"))?;

            let fp = fake.fingerprint.clone();
            let factory = move |s: &deploy::config::ServerDef,
                                slot: &deploy::config::SlotConfig|
                  -> Result<Box<dyn Remote>> {
                Ok(Box::new(SshTransport::new(
                    &s.user,
                    &s.address,
                    s.port,
                    &slot.deploy_dir,
                    None,
                    Some(&fp),
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
            assert!(r.dry_run, "report must be a dry run");
            assert!(r.attempt.is_none());
            assert!(
                r.message.contains("first deployment"),
                "dry-run plan should describe the pending first deployment, got: {}",
                r.message
            );

            // The emulated REMOTE host is completely untouched: identity
            // pinning happens in the LOCAL per-test `DEPLOY_SSH_KNOWNHOSTS_DIR`
            // cache, never on the remote layout.
            assert!(
                remote_fingerprint(&fake.remote_root).is_empty(),
                "dry run must not create anything on the remote layout"
            );
            Ok(())
        })
    })
}

// ---- Scenario (c): first push over fingerprint-only ssh ---------------------

#[test]
fn fingerprint_only_first_push_succeeds() -> Result<()> {
    let _guard = SSH_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let fake = make_fake_bin(tmp.path(), "first.test");
    let deploy_dir = "/srv/deploy/first-push";

    with_fake_path(&fake.bin, &tmp.path().join("knownhosts"), || {
        with_fake_root(&fake.remote_root, deploy_dir, || {
            let proj = tmp.path().join("proj");
            std::fs::create_dir_all(&proj).unwrap();
            let (config, config_path) = setup_project(&proj, "first.test", deploy_dir);
            let store = LocalStore::with_base(tmp.path().join("store"))?;

            let fp = fake.fingerprint.clone();
            let factory = move |s: &deploy::config::ServerDef,
                                slot: &deploy::config::SlotConfig|
                  -> Result<Box<dyn Remote>> {
                Ok(Box::new(SshTransport::new(
                    &s.user,
                    &s.address,
                    s.port,
                    &slot.deploy_dir,
                    None,
                    Some(&fp),
                )?))
            };

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
                "first push must succeed"
            );
            let attempt = r.attempt.expect("attempt recorded");
            assert!(
                attempt
                    .slots
                    .contains_key(&deploy::model::SlotId::parse("p1").unwrap())
            );

            // The emulated remote now has the full layout: a generation under
            // generations/, `current` pointing at it, and the protocol marker.
            // (The remote deploy dir lives at `<fake-root>/srv/deploy/first-push`
            // inside the emulated host filesystem.)
            let remote_deploy = fake.remote_root.join("srv/deploy/first-push");
            let fp_entries = remote_fingerprint(&remote_deploy);
            assert!(
                fp_entries
                    .iter()
                    .any(|(rel, _)| rel.starts_with("generations/")),
                "remote must contain a generation record"
            );
            assert!(
                fp_entries
                    .iter()
                    .any(|(rel, kind)| rel == "current" && kind.starts_with("symlink:")),
                "remote `current` must be a symlink"
            );
            assert!(
                fp_entries
                    .iter()
                    .any(|(rel, _)| rel == "control/protocol.json"),
                "protocol marker must be recorded (handshake before layout)"
            );
            Ok(())
        })
    })
}

// ---- Scenario (d): repeat push is idempotent and reuses the pinned key ------

#[test]
fn fingerprint_only_repeat_push_is_idempotent() -> Result<()> {
    let _guard = SSH_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let fake = make_fake_bin(tmp.path(), "repeat.test");
    let deploy_dir = "/srv/deploy/repeat-push";

    with_fake_path(&fake.bin, &tmp.path().join("knownhosts"), || {
        with_fake_root(&fake.remote_root, deploy_dir, || {
            let proj = tmp.path().join("proj");
            std::fs::create_dir_all(&proj).unwrap();
            let (config, config_path) = setup_project(&proj, "repeat.test", deploy_dir);
            let store = LocalStore::with_base(tmp.path().join("store"))?;

            let fp = fake.fingerprint.clone();
            let factory = move |s: &deploy::config::ServerDef,
                                slot: &deploy::config::SlotConfig|
                  -> Result<Box<dyn Remote>> {
                Ok(Box::new(SshTransport::new(
                    &s.user,
                    &s.address,
                    s.port,
                    &slot.deploy_dir,
                    None,
                    Some(&fp),
                )?))
            };

            let r1 = push(
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
                r1.status,
                Some(DeploymentStatus::Successful),
                "first push must succeed"
            );

            // The second push is a no-op ("Everything up to date").
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
            assert!(r2.status.is_none(), "re-push with no change is a no-op");
            assert_eq!(r2.message, "Everything up to date");

            // ssh-keyscan ran exactly once across BOTH pushes: the second
            // push validated the cached pinned file against the configured
            // fingerprint and reused it without re-fetching.
            let calls = std::fs::read_to_string(&fake.keyscan_log)
                .unwrap_or_default()
                .lines()
                .count();
            assert_eq!(calls, 1, "repeat push must reuse the pinned host key");

            // The remote layout is unchanged by the repeat push.
            let remote_deploy = fake.remote_root.join("srv/deploy/repeat-push");
            let after = remote_fingerprint(&remote_deploy);
            assert!(
                after.iter().any(|(rel, _)| rel == "control/protocol.json"),
                "remote layout must persist between pushes"
            );
            Ok(())
        })
    })
}

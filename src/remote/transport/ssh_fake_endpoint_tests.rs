//! `deploy`-DOMAIN SSH endpoint tests: the assertions that belong to
//! `deploy`'s own modules (`RemoteHelper`, retention) rather than to the
//! transport, driven over the emulated remote through the SUBSTRATE
//! `SshTransport` deploy now re-exports.
//!
//! The transport-level half of this harness's coverage (the framed `lstat`
//! protocol, the descriptor-bound verify-open swap proptest, the
//! fingerprint pin/reuse policy, the create-new verdict matrix, and the
//! byte-exact round trip) moved INTO the crate as in-crate tests, because the
//! crate owns those seams. What remains here is what only `deploy` can
//! assert: that a failed far-side `lstat` cannot drive `swap_current`, that an
//! EACCES on the generations root aborts retention with zero deletions, and
//! that a fingerprint-only deploy_dir can serve a `RemoteHelper::status`.

use super::*;
use crate::remote::helper::{ExpectedCurrent, RemoteHelper};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

// HERMETIC SNAPSHOT: every fake-ssh test builds ONE `SysEnv::from_map`
// carrying the fake bin dir first in `PATH` plus the fake-ssh variables
// (`FAKE_SSH_ROOT` / `FAKE_SSH_REMOTE_PREFIX`) and the per-test pin
// cache (`DEPLOY_SSH_KNOWNHOSTS_DIR`). The transport spawns its children
// (ssh / ssh-keyscan / ssh-keygen / stat) with that snapshot's variables
// (`SysEnv::apply_to_command`: env_clear + the snapshot's vars), so the
// fake binaries resolve and their
// inputs ride the same child env — the process-global environment is
// NEVER touched (no lock, no set_var, no cross-test interference).

struct FakeSsh {
    bin: PathBuf,
    remote_root: PathBuf,
    fingerprint: String,
    deploy_dir: PathBuf,
    address: String,
}

impl FakeSsh {
    /// Generate a REAL ed25519 host key (never a hardcoded fake), compute
    /// its SHA256 fingerprint, and write fake `ssh`/`ssh-keyscan`/`stat`
    /// executables into `bin` that emulate a remote host rooted at
    /// `remote_root`.
    fn new(bin: PathBuf, remote_root: PathBuf, address: &str, deploy_dir: &Path) -> FakeSsh {
        std::fs::create_dir_all(&bin).unwrap();
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

        // Fake `ssh`: parse `-o`/`-p`/`--` like OpenSSH, remap every
        // occurrence of the configured remote deploy dir to the local
        // emulation root, and run the single (fully shell-quoted) remote
        // command with `sh -c`. The piped payload flows through this shim
        // untouched into the remote `cat > "$tmp"` (the shell execs the
        // command with stdin intact).
        std::fs::write(
            bin.join("ssh"),
            r##"#!/bin/sh
# Fake `ssh` for tests: emulates a remote host whose filesystem is a local
# directory. `FAKE_SSH_ROOT` is the local dir; `FAKE_SSH_REMOTE_PREFIX` is the
# configured remote deploy dir (e.g. /srv/deploy/app). Every occurrence of the
# remote prefix in the (fully shell-quoted) remote command is remapped to
# $FAKE_SSH_ROOT$FAKE_SSH_REMOTE_PREFIX, then the command runs with `sh -c`.
# The piped stdin payload is inherited untouched (no -n, no stdin reads here).
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
remapped=$(printf '%s' "$cmd" | awk -v old="$REMOTE_PREFIX" -v new="$FAKE_ROOT$REMOTE_PREFIX" '{ gsub(old, new); printf "%s", $0 }')
exec sh -c "$remapped"
"##,
        )
        .unwrap();

        // Fake ssh-keyscan: answer with the generated host key.
        std::fs::write(
            bin.join("ssh-keyscan"),
            format!(
                r#"#!/bin/sh
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
                address = address,
                pubkey = pubkey,
            ),
        )
        .unwrap();

        // Fake `stat` emulating GNU coreutils `-c` (macOS stat lacks it):
        // the transport's list script uses `stat -c '%f'` (raw mode in
        // hex). The metadata path no longer calls `stat` at all — it runs
        // the framed perl `lstat` helper directly — so the shim's `%s %f`
        // branch implements the SAME framed protocol (P/A/E frames from a
        // REAL lstat errno; a missing path reports `A\t2`), keeping the
        // fixture faithful for any caller that still formats through
        // `stat`. `/usr/bin/perl` (absolute) is used so an injected fake
        // `perl` in the test bin dir never shadows the shim's interpreter.
        std::fs::write(
            bin.join("stat"),
            r#"#!/bin/sh
fmt=""
while [ $# -gt 0 ]; do
  case "$1" in
-c) fmt="$2"; shift 2 ;;
-L) shift ;;
-*) shift ;;
*) break ;;
  esac
done
case "$fmt" in
  "%f")
/usr/bin/perl -e 'my @s = lstat($ARGV[0]); printf "%x\n", $s[2] & 0xffff;' "$1"
;;
  "%s %f")
/usr/bin/perl -e 'my @s = lstat($ARGV[0]); if (@s) { printf "P\t%s\t%x\n", $s[7], $s[2] & 0xffff; exit 0; } my $e = $! + 0; print(($e == 2 || $e == 20) ? "A\t$e\n" : "E\t$e\n");' "$1"
;;
  *)
exec /usr/bin/stat "$@"
;;
esac
"#,
        )
        .unwrap();

        // Fake `mv` emulating GNU coreutils `mv -T` (no-target-directory):
        // macOS BSD mv lacks `-T` and, like GNU mv without `-T`, treats a
        // destination that is a symlink to a directory as the directory
        // itself and moves the source INTO it. The deploy tool's `current`
        // swap depends on GNU `-T` semantics, so strip the flag and remove
        // any existing destination first.
        std::fs::write(
            bin.join("mv"),
            r#"#!/bin/sh
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
            deploy_dir: deploy_dir.to_path_buf(),
            address: address.to_string(),
        }
    }

    /// A fingerprint-only `SshTransport` (no `known_hosts`) rooted at
    /// `self.deploy_dir`, pinning into the per-test `cache` dir with the
    /// hermetic snapshot `env` (the fake ssh binaries resolve from its
    /// `PATH`).
    fn transport(&self, cache: &Path, env: &SysEnv) -> SshTransport {
        SshTransport::new(
            "deploy",
            &self.address,
            2222,
            &self.deploy_dir,
            crate::remote::layout::substrate_layout(),
            None,
            Some(self.fingerprint.as_str()),
            cache,
            env,
            false,
        )
        .unwrap()
    }
}

/// Build the hermetic fake-ssh snapshot: `bin` prepended to the ambient
/// `PATH`, the per-test pin `cache`, and the fake-ssh variables. The
/// transport's children receive exactly these variables — the process
/// env is never mutated, so no two tests (in any binary) can interfere.
fn fake_env(bin: &Path, cache: &Path, root: &Path, prefix: &str) -> SysEnv {
    fake_env_with(bin, cache, root, prefix, &[])
}

/// [`fake_env`] with EXTRA snapshot variables (e.g. arbitrary ambient
/// variables for production invariance testing).
fn fake_env_with(
    bin: &Path,
    cache: &Path,
    root: &Path,
    prefix: &str,
    extra: &[(&str, &str)],
) -> SysEnv {
    let base = crate::testutil::fixture_env();
    let mut vars: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        base.child_env().into_iter().collect();
    let mut paths: Vec<_> = base
        .path()
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    paths.insert(0, bin.to_path_buf());
    let joined = std::env::join_paths(paths).unwrap();
    vars.insert(OsString::from("PATH"), joined);
    vars.extend(std::collections::BTreeMap::from([
        (
            OsString::from("DEPLOY_SSH_KNOWNHOSTS_DIR"),
            cache.as_os_str().to_owned(),
        ),
        (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
        (
            OsString::from("FAKE_SSH_REMOTE_PREFIX"),
            OsString::from(prefix),
        ),
    ]));
    for (k, v) in extra {
        vars.insert(OsString::from(k), OsString::from(*v));
    }
    SysEnv::from_map(vars)
}

/// Overwrite a protocol-faithful fake binary (written by [`FakeSsh::new`])
/// with a custom script for a single focused test — the transport resolves
/// every binary (`ssh`, `perl`, `stat`, ...) from the fake bin dir's
/// `PATH`, so the override is picked up by every remote command. Kept
/// executable like the originals.
fn write_fake_bin(bin: &Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = bin.join(name);
    std::fs::write(&p, body).unwrap();
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
}

/// Overwrite the fake `perl` so the transport's framed `lstat` helper
/// resolves to a script that emits `stdout` verbatim (or performs the
/// injected process-level behavior). The fake shim runs the helper as
/// `perl -e '…' -- <path>`, so a `perl` in the fake bin shadows the real
/// interpreter for metadata reads while every other binary is untouched.
fn write_fake_lstat(bin: &Path, stdout: &str) {
    write_fake_bin(bin, "perl", &format!("#!/bin/sh\nprintf '{stdout}\n'\n"));
}

/// Byte-identical snapshot of a directory tree (sorted relative paths +
/// kind/content digests), so a test can assert ZERO deletions.
fn snapshot_tree(root: &Path) -> Vec<(String, String)> {
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
                out.push((
                    rel,
                    format!(
                        "symlink:{}",
                        std::fs::read_link(&p).unwrap().to_string_lossy()
                    ),
                ));
            } else if ft.is_dir() {
                out.push((rel, "dir".to_string()));
                walk(root, &p, out);
            } else {
                let data = std::fs::read(&p).unwrap_or_default();
                out.push((rel, format!("file:{}", crate::digest::sha256_bytes(&data))));
            }
        }
    }
    let mut out = Vec::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

/// The lstat outcomes the fake remote can be told to emit. The property
/// dimension: ONLY the absence errnos (ENOENT/ENOTDIR) may produce
/// `Ok(None)`; every other outcome — EACCES, EIO, malformed frames,
/// signal-killed commands, transport failures — is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LstatOutcome {
    Present,
    AbsentEnoent,
    AbsentEnotdir,
    ErrorEacces,
    ErrorEio,
    MalformedGarbage,
    MalformedWrongPrefix,
    MalformedTruncated,
    MalformedMissingErrno,
    MalformedExtraField,
    MalformedTwoLines,
    SignalKilled,
    TransportSpawnFailure,
}

impl LstatOutcome {
    /// The frame the fake `perl` must emit for this outcome; `None` when
    /// the outcome is injected at the process level (signal-killed
    /// command, spawn failure).
    fn frame(self) -> Option<&'static str> {
        match self {
            LstatOutcome::Present => Some("P\t5\t81a4"),
            LstatOutcome::AbsentEnoent => Some("A\t2"),
            LstatOutcome::AbsentEnotdir => Some("A\t20"),
            LstatOutcome::ErrorEacces => Some("E\t13"),
            LstatOutcome::ErrorEio => Some("E\t5"),
            LstatOutcome::MalformedGarbage => Some("garbage"),
            LstatOutcome::MalformedWrongPrefix => Some("X\t2"),
            LstatOutcome::MalformedTruncated => Some("P\t5"),
            LstatOutcome::MalformedMissingErrno => Some("A"),
            LstatOutcome::MalformedExtraField => Some("P\t5\t81a4\textra"),
            LstatOutcome::MalformedTwoLines => Some("P\t5\t81a4\nE\t13"),
            LstatOutcome::SignalKilled | LstatOutcome::TransportSpawnFailure => None,
        }
    }

    /// Only the absence errnos (ENOENT/ENOTDIR) are confirmed absence.
    fn is_absence(self) -> bool {
        matches!(
            self,
            LstatOutcome::AbsentEnoent | LstatOutcome::AbsentEnotdir
        )
    }

    /// Every non-absence outcome must be an error.
    fn is_error(self) -> bool {
        !matches!(
            self,
            LstatOutcome::Present | LstatOutcome::AbsentEnoent | LstatOutcome::AbsentEnotdir
        )
    }
}

fn all_lstat_outcomes() -> Vec<LstatOutcome> {
    vec![
        LstatOutcome::Present,
        LstatOutcome::AbsentEnoent,
        LstatOutcome::AbsentEnotdir,
        LstatOutcome::ErrorEacces,
        LstatOutcome::ErrorEio,
        LstatOutcome::MalformedGarbage,
        LstatOutcome::MalformedWrongPrefix,
        LstatOutcome::MalformedTruncated,
        LstatOutcome::MalformedMissingErrno,
        LstatOutcome::MalformedExtraField,
        LstatOutcome::MalformedTwoLines,
        LstatOutcome::SignalKilled,
        LstatOutcome::TransportSpawnFailure,
    ]
}

proptest! {
    // FIXED-SEED property (0x5EED_5EED, per house style), bounded cases:
    // the lstat OUTCOME is injected through a fake `perl` (frames) or a
    // fake `ssh` (signal-killed command / spawn failure) and driven
    // through the REAL transport + parser. ONLY the absence errnos
    // (ENOENT/ENOTDIR) return `Ok(None)`; every other outcome returns
    // `Err`, and for the error cases the caller-level gate
    // (`swap_current`) also errors and leaves the `current` link
    // byte-identical — a failed lstat is never absence, so it can never
    // drive a swap/removal (the same fail-closed rule retention relies
    // on: zero deletions on a failed read).
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(16),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn lstat_outcome_injection(outcome in prop::sample::select(all_lstat_outcomes())) {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "lstat-prop.test",
            Path::new("/srv/deploy/lstat-prop"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(
            &fake.bin,
            &cache,
            &fake.remote_root,
            "/srv/deploy/lstat-prop",
        );
        let t = fake.transport(&cache, &env);
        t.prepare_identity().unwrap();
        let remote_deploy = fake.remote_root.join("srv/deploy/lstat-prop");
        std::fs::create_dir_all(&remote_deploy).unwrap();

        // Inject the outcome BEFORE the first remote metadata read.
        match outcome {
            LstatOutcome::SignalKilled => {
                // The remote command is killed by a signal: the runner's
                // direct child dies by SIGTERM, so its exit status carries
                // no code (never a success).
                write_fake_bin(&fake.bin, "ssh", "#!/bin/sh\nkill -TERM $$\n");
            }
            LstatOutcome::TransportSpawnFailure => {
                // The transport cannot even spawn the remote command (a
                // real dead/broken ssh surfaces the same class of failure
                // as a `run_remote` error).
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    fake.bin.join("ssh"),
                    std::fs::Permissions::from_mode(0o000),
                )
                .unwrap();
            }
            _ => {
                write_fake_lstat(&fake.bin, outcome.frame().unwrap());
            }
        }

        // FRAME-LEVEL: the real transport parses the injected outcome.
        let result = t.metadata_opt(&RootedRelativePath::parse(Path::new("probe")).unwrap());
        match result {
            Ok(Some(meta)) => {
                // ONLY the Present outcome may be `Some`.
                assert_eq!(
                    outcome,
                    LstatOutcome::Present,
                    "{outcome:?} must not be Some"
                );
                assert!(meta.is_file && !meta.is_dir && !meta.is_symlink);
                assert_eq!(meta.size, 5);
                assert_eq!(meta.mode, 0o644);
            }
            Ok(None) => {
                // ONLY the absence errnos (ENOENT/ENOTDIR) may be `None`.
                assert!(outcome.is_absence(), "{outcome:?} must not be None");
            }
            Err(e) => {
                assert!(
                    outcome.is_error(),
                    "{outcome:?} must not error, got: {e}"
                );
                let msg = e.to_string();
                match outcome {
                    LstatOutcome::ErrorEacces => {
                        assert!(msg.contains("errno 13"), "{outcome:?}: {msg}")
                    }
                    LstatOutcome::ErrorEio => {
                        assert!(msg.contains("errno 5"), "{outcome:?}: {msg}")
                    }
                    LstatOutcome::MalformedGarbage
                    | LstatOutcome::MalformedWrongPrefix
                    | LstatOutcome::MalformedTruncated
                    | LstatOutcome::MalformedMissingErrno
                    | LstatOutcome::MalformedExtraField
                    | LstatOutcome::MalformedTwoLines => {
                        assert!(msg.contains("malformed"), "{outcome:?}: {msg}")
                    }
                    LstatOutcome::SignalKilled => {
                        assert!(msg.contains("ssh lstat failed"), "{outcome:?}: {msg}")
                    }
                    LstatOutcome::TransportSpawnFailure => {
                        assert!(msg.contains("ssh"), "{outcome:?}: {msg}")
                    }
                    _ => unreachable!()}
            }
        }

        // CALLER-LEVEL (error outcomes only): the current gate reads the
        // `current` link through `metadata_opt`; a FAILED lstat must
        // propagate (never be read as absence), so `swap_current` errors
        // and leaves the link byte-identical — a failed read can never
        // drive a swap/removal (the same fail-closed rule retention
        // relies on: zero deletions on a failed read).
        if outcome.is_error() {
            use std::os::unix::fs::PermissionsExt;
            let link = remote_deploy.join("current");
            std::os::unix::fs::symlink("generations/gen-gate/root", &link).unwrap();
            let before = (
                std::fs::symlink_metadata(&link).unwrap().permissions().mode(),
                std::fs::read_link(&link).unwrap(),
            );
            let helper = RemoteHelper::new(&t);
            let guard = crate::remote::helper::SlotRemote::new(&helper, crate::remote::helper::test_owner("test-app", "s1")).acquire_lock_guard(&crate::identity::OperationId::new("op".to_string()));
            let err = match guard {
                Ok(g) => g.swap_current( &ExpectedCurrent::Absent, &crate::identity::test_generation_id("gen-gate"), "op")
                    .unwrap_err(),
                Err(e) => e};
            assert!(
                err.to_string().contains("ssh"),
                "{outcome:?}: a failed lstat must propagate, got: {err}"
            );
            let after = (
                std::fs::symlink_metadata(&link).unwrap().permissions().mode(),
                std::fs::read_link(&link).unwrap(),
            );
            assert_eq!(
                after, before,
                "{outcome:?}: a failed lstat must leave the current link byte-identical"
            );
        }
    }
}

// Scenario (a): a fingerprint-only configuration can make a STATUS request
// once the identity has been prepared — the exact regression this feature
// fixes. The transport-internal halves of the old assertion (that
// `ssh_args` refuses before `prepare_identity`, and that the pinned file is
// materialized on the local host) now live in the crate's own
// `fingerprint_ssh_tests`; what stays here is the `deploy`-domain half:
// `RemoteHelper::status` against the emulated remote.
#[test]
fn status_succeeds_with_fingerprint_only_config() {
    let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let fake = FakeSsh::new(
        tmp.path().join("bin"),
        tmp.path().join("remote"),
        "status-unit.test",
        Path::new("/srv/deploy/status-unit"),
    );
    let cache = tmp.path().join("knownhosts");
    let env = fake_env(
        &fake.bin,
        &cache,
        &fake.remote_root,
        "/srv/deploy/status-unit",
    );
    let t = fake.transport(&cache, &env);
    t.prepare_identity().unwrap();

    // A status request now succeeds (the fake remote is empty).
    let helper = RemoteHelper::new(&t);
    let status = helper
        .status(&crate::remote::helper::test_owner("test-app", "s1"))
        .unwrap();
    assert!(status.current_generation().is_none());
    assert!(status.inventory.is_empty());
    assert!(status.lock.is_none());
}

/// The retention fail-closed property, end to end over ssh: a remote
/// whose `lstat` fails with EACCES (permission denied) on the
/// generations root must ABORT `compute_retained` with an error — EACCES
/// is never absence — leaving the remote state byte-identical with ZERO
/// retention deletions. The old shell-boolean guard mapped this very
/// failure to absence, so retention saw an empty history and swept
/// everything.
#[test]
fn lstat_eacces_aborts_retention_with_zero_deletions() {
    use crate::config::{DeploymentRetention, PerServerRetention, RetentionConfig};
    use crate::identity::{
        ArtifactRef, VariantName, test_deployment_id, test_generation_id, test_keep_days,
        test_release_id, test_tree_digest,
    };
    use crate::remote::helper::GenerationAssignment;
    use crate::retention::policy::compute_retained;
    use crate::store::local::LocalStore;

    let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let fake = FakeSsh::new(
        tmp.path().join("bin"),
        tmp.path().join("remote"),
        "ret-eacces.test",
        Path::new("/srv/deploy/ret-eacces"),
    );
    let cache = tmp.path().join("knownhosts");
    let env = fake_env(
        &fake.bin,
        &cache,
        &fake.remote_root,
        "/srv/deploy/ret-eacces",
    );
    let t = fake.transport(&cache, &env);
    t.prepare_identity().unwrap();
    let helper = RemoteHelper::new(&t);
    let remote_deploy = fake.remote_root.join("srv/deploy/ret-eacces");

    // Two generations + a garbage tree, written through the REAL transport
    // (the fake ssh shim runs the real perl lstat helper for reads).
    let created = jiff::Timestamp::now();
    let g1 = test_generation_id("g1");
    let g2 = test_generation_id("g2");
    let mk = |gid: &crate::identity::GenerationId, tree: &str| GenerationAssignment {
        deployment_id: test_deployment_id("d1"),
        generation_id: gid.clone(),
        artifact: ArtifactRef {
            release: test_release_id("rel-sha256-x"),
            variant: VariantName::new("standard"),
            tree: test_tree_digest(tree),
        },
        behavior_sha256: crate::identity::test_behavior_digest("b"),
        prior_generation: None,
        created_at: crate::identity::Timestamp::parse(&created.to_string()).unwrap(),
        application: crate::identity::ApplicationStoreKey::parse("test-app").unwrap(),
        slot: crate::identity::SlotId::parse("s1").unwrap(),
        target: Some(crate::identity::TargetName::new("t1")),
    };
    crate::remote::helper::SlotRemote::new(
        &helper,
        crate::remote::helper::test_owner("test-app", "s1"),
    )
    .acquire_lock_guard(&crate::identity::OperationId::new("op".to_string()))
    .unwrap()
    .create_generation(&mk(&g1, "t1").spec().unwrap())
    .unwrap();
    crate::remote::helper::SlotRemote::new(
        &helper,
        crate::remote::helper::test_owner("test-app", "s1"),
    )
    .acquire_lock_guard(&crate::identity::OperationId::new("op".to_string()))
    .unwrap()
    .create_generation(&mk(&g2, "t2").spec().unwrap())
    .unwrap();
    for tree in ["t1", "t2"] {
        let d = test_tree_digest(tree);
        helper
            .remote()
            .create_dir_all(&crate::remote::layout::tree_root(&d))
            .unwrap();
    }
    crate::remote::helper::SlotRemote::new(
        &helper,
        crate::remote::helper::test_owner("test-app", "s1"),
    )
    .acquire_lock_guard(&crate::identity::OperationId::new("op".to_string()))
    .unwrap()
    .swap_current(&ExpectedCurrent::Absent, &g2, "op")
    .unwrap();
    let garbage = test_tree_digest("garbage");
    helper
        .remote()
        .create_dir_all(&crate::remote::layout::tree_root(&garbage))
        .unwrap();

    // Inject EACCES ONLY on the generations-root lstat; every other
    // metadata read (the `current` gate, status validation) delegates to
    // the real perl helper, so the fault fires exactly where retention
    // loads its inventory.
    write_fake_bin(
        &fake.bin,
        "perl",
        "#!/bin/sh\nfor last; do :; done\ncase \"$last\" in\n  */generations) printf 'E\\t13\\n'; exit 0 ;;\nesac\nexec /usr/bin/perl \"$@\"\n",
    );

    let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
    let policy = RetentionConfig {
        per_server: PerServerRetention {
            keep_distinct_artifacts: 5,
            keep_days: test_keep_days(14),
            protect_previous: true,
        },
        deployment: DeploymentRetention {
            protect_deployments: 2,
        },
    };
    let before = snapshot_tree(&remote_deploy);
    let err = compute_retained(
        &helper,
        &[],
        &store,
        &policy,
        &crate::remote::helper::test_owner("test-app", "s1"),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("errno 13"),
        "EACCES on the generations root must abort retention naming the errno, got: {err}"
    );

    // ZERO DELETIONS: the remote state is byte-identical and every tree —
    // both history trees AND the garbage — survives.
    assert_eq!(
        snapshot_tree(&remote_deploy),
        before,
        "the failed retention must leave the remote state byte-identical"
    );
    for tree in ["t1", "t2"] {
        let d = test_tree_digest(tree);
        assert!(
            helper
                .remote()
                .exists(&crate::remote::layout::tree_root(&d)),
            "history tree {d} must survive the failed retention"
        );
    }
    assert!(
        helper
            .remote()
            .exists(&crate::remote::layout::tree_root(&garbage)),
        "the garbage tree must survive the failed retention"
    );
}

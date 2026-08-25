//! Command-line interface.
//!
//! The CLI is the primary documentation surface for agents: every subcommand
//! carries a `long_about` that teaches the forced project structure, the
//! configuration, the rollout/rollback semantics, and copy-paste-runnable
//! examples. Run `deploy --help`, `deploy help <cmd>`, or `deploy <cmd> --help`
//! to see it.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::init::{InitOptions, init_project};
use crate::push::engine::{PushOptions, PushReport, push};
use crate::records::{DeploymentAttempt, DeploymentStatus, ObservedTarget};
use crate::remote::create_remote;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "deploy",
    version,
    about = "Deploy your local files to a named target (Git-push style)",
    long_about = "Deploy your local files to every server in a named target with one command.\n\
\n\
PROJECT STRUCTURE (forced):\n\
  deploy.toml                    names the active release, servers, targets (rollout + rotation)\n\
  releases/<name>/              the release directory named by `release:` in deploy.toml\n\
  releases/<name>/<variant>.toml   every *.toml file here is a variant (file stem = name);\n\
                                  each variant declares its own [[slots]] (server, deploy_dir, target)\n\
  releases/<name>/artifacts/    artifact sources referenced by variant mappings\n\
\n\
The quickest start is `deploy init` — it scaffolds a working project with a\n\
LOCAL deployment endpoint (local://...), so `deploy push production` works\n\
end-to-end with nothing but this binary. See `deploy help init`.\n\
\n\
Every push is transactional per server: immutable release + artifact objects,\n\
atomic `current` swap, then verification; batches follow rollout policy and\n\
failed attempts never advance the rollback ref. Run `deploy push <target>
--dry-run` first."
)]
struct Cli {
    /// Path to deploy.toml (defaults to ./deploy.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scaffold a fresh deploy project in [PATH] (default: current directory).
    #[command(
        long_about = "Scaffold a fresh, immediately-pushable deploy project.\n\
\n\
Creates (never clobbers; the target must not already contain deploy.toml or a\n\
releases/ tree):\n\
  deploy.toml                        schema v1 config: one server, target `production` (rollout+rotation)\n\
  releases/v1/standard.toml          the `standard` variant (mappings + its slot + policies)\n\
  releases/v1/systemd.toml           example `systemd` activation variant with a real unit\n\
  releases/v1/artifacts/build/output/app/hello   placeholder artifact source\n\
  releases/v1/artifacts/systemd/example.service  the unit shipped by the systemd variant\n\
  .deploy-remote/                    LOCAL deployment endpoint (see below)\n\
  .gitignore                         ignores the local endpoint in a repo\n\
\n\
Slots are declared INSIDE the variant files: releases/v1/standard.toml\n\
carries the project's one slot (app-1 -> server-01, bound to target\n\
`production` by its `targets` list — targets derive their members from the\n\
slots, they do not list them).\n\
\n\
The generated files are typed TOML serialized from the same config structs\n\
`Config::load` parses into — not formatted strings. Init validates the flags\n\
BEFORE creating anything, re-loads the written project through the strict\n\
loader, and removes the scaffold if that load fails: success always means\n\
the generated project is valid.\n\
\n\
LOCAL-FIRST DEFAULT: the server address is `local://<project>/.deploy-remote`,\n\
a local-filesystem endpoint, so `deploy push production` runs end-to-end with\n\
zero SSH or server infrastructure. For a real server, pass --address, --user,\n\
and EXACTLY ONE of --known-hosts or --host-key-fingerprint (SSH\n\
trust-on-first-use is refused, and the two flags are mutually exclusive: a\n\
`known_hosts` must be an absolute path and a fingerprint a SHA256:... value).\n\
\n\
Where the project is created: <path> if given, else the directory of --config,\n\
else the current directory. The application name defaults to that directory's\n\
name; override with --name.",
        after_help = "Examples:\n\
  deploy init                        # scaffold into the current directory\n\
  deploy init my-app                 # scaffold into ./my-app (created)\n\
  deploy init my-app --name backend  # choose the application name\n\
  deploy init --address app.example.com --user deploy \\\n\
                --host-key-fingerprint SHA256:abc... # real SSH server\n\
\n\
Then, from inside the project:\n\
  deploy push production --dry-run   # preview what would change (touches nothing)\n\
  deploy push production             # deploy\n\
  deploy status production           # what is actually running per server\n\
  deploy log production              # deployment history"
    )]
    Init {
        /// Directory to scaffold the project into (created if missing).
        ///
        /// Defaults to the directory that will hold deploy.toml: the parent of
        /// `--config`, or the current directory.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        /// Application name written into deploy.toml (default: the target
        /// directory's name).
        #[arg(long)]
        name: Option<String>,
        /// Server address. Default: local://<project>/.deploy-remote (a local
        /// filesystem endpoint, zero SSH). Use a hostname for SSH.
        #[arg(long)]
        address: Option<String>,
        /// SSH user (default: "deploy").
        #[arg(long, default_value = "deploy")]
        user: String,
        /// SSH port (default 22; the typed serialization always writes the
        /// resolved port into deploy.toml).
        #[arg(long)]
        port: Option<u16>,
        /// Absolute path to a known_hosts file (strict host-key checking).
        /// Mutually exclusive with `--host-key-fingerprint`: exactly one
        /// host-identity source must be configured for an SSH address.
        #[arg(long, value_name = "FILE", conflicts_with = "host_key_fingerprint")]
        known_hosts: Option<PathBuf>,
        /// Pre-verified host key fingerprint, e.g. SHA256:... . Mutually
        /// exclusive with `--known-hosts`: exactly one host-identity source
        /// must be configured for an SSH address.
        #[arg(long, value_name = "SHA256:...", conflicts_with = "known_hosts")]
        host_key_fingerprint: Option<String>,
    },
    /// Deploy the current local inputs (or a reference) to a named target.
    #[command(
        long_about = "Deploy to a target: push the local files mapped by the target's\n\
variants (or restore a historical deployment) to every server in the target,\n\
in rollout batches.\n\
\n\
REFERENCE (optional second argument, jj-style — the target is NEVER repeated\n\
in the reference; every relative form resolves against the target argument):\n\n\
  (none), HEAD, @      the current local files (default)\n\
  @-                   the snapshot BEFORE the latest successful deployment\n\
  @--                  two steps back (the grandparent)\n\
  parent(@, N)         N steps back from the latest (e.g. parent(@, 2))\n\
  release:<id>         deploy the named release DIRECTLY to the current\n\
                       target's slots, from the release's own stored slot\n\
                       snapshot — no snapshot history needed (cross-target)\n\
  sN                   the exact Nth successful snapshot (e.g. s3); failed\n\
                       attempts never count and never produce a snapshot\n\
  sN- / sN--            N steps back from snapshot sN\n\
  parent(sN, M)         M steps back from snapshot sN\n\
  <id>-- / parent(<id>, N)   N steps back from the most recent snapshot that\n\
                       deployed deployment <id> or referenced release <id>\n\
\n\
NOTE: every parent(...) form contains a comma, so the shell splits the\n\
reference at the space after the comma. shell-quote parent(...) forms —\n\
e.g. deploy push production 'parent(@, 3)' — in interactive shells.\n\
\n\
--dry-run prints the plan and touches nothing (no store writes, no remote\n\
state, no locks). Pushing identical content prints 'Everything up to date'.\n\
Rollout batches per rollout.batch_size; on a failed server, earlier batches\n\
roll back by default (failure_policy: rollback_changed). The final status is\n\
reported explicitly, including partial states like `degraded`.",
        after_help = "Examples:\n\
  deploy push production               # deploy local files\n\
  deploy push production --dry-run     # preview the plan, touch nothing\n\
  deploy push production @-            # roll back to the previous deployment\n\
  deploy push production 'parent(@, 3)'  # roll back 3 deployments\n\
  deploy push production s3--          # 2 deployments before snapshot s3\n\
  deploy push production release:rel-sha256-2fda63a950  # DIRECT release deploy to this target (cross-target; no history needed)"
    )]
    Push {
        target: String,
        /// Optional jj-style source reference: blank/HEAD/@ (default),
        /// @- / @-- / parent(@, N), release:<id> (direct release deploy),
        /// or a refid relative (sN, <refid>--, parent(<refid>, N)) — never
        /// repeats the target.
        reference: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the target's deployment history (successful and failed).
    #[command(
        long_about = "Show every recorded deployment attempt for the target, newest last:\n\
deployment ID, status, and timestamp. Failed and degraded attempts remain\n\
visible here but are NOT valid rollback refs — only successful deployments\n\
produce snapshots (see `deploy help push` for the reference syntax)."
    )]
    Log { target: String },
    /// Show what is actually running on every server.
    #[command(
        long_about = "Inspect the real generation on every server of the target: generation\n\
id, release id, variant, and tree digest, as observed on the servers themselves\n\
(right now — not from local history)."
    )]
    Status { target: String },
}

/// CLI entry point.
pub fn run() -> Result<()> {
    run_with(std::env::args())
}

/// Parse `args` (argv, including the program name) and run the command.
pub fn run_with<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    // Absolutize the config path so `Config::load` can canonicalize the
    // project root: with a bare `./deploy.toml` the parent would be empty.
    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("deploy.toml"));
    let config_path = if config_path.is_absolute() {
        config_path
    } else {
        std::path::absolute(&config_path).unwrap_or(config_path)
    };

    // `init` needs no config and must run before any config loading.
    let is_init = matches!(&cli.command, Command::Init { .. });
    if is_init {
        let Command::Init {
            path,
            name,
            address,
            user,
            port,
            known_hosts,
            host_key_fingerprint,
        } = cli.command
        else {
            unreachable!("guarded by is_init")
        };
        let target = match path {
            Some(p) => p,
            None => config_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from(".")),
        };
        let report = init_project(
            &target,
            &InitOptions {
                name,
                address,
                user,
                port,
                known_hosts,
                host_key_fingerprint,
            },
        )?;
        print_init_report(&report);
        return Ok(());
    }

    if !config_path.exists() {
        return Err(Error::config(format!(
            "config '{}' not found — run `deploy init` to scaffold a project",
            config_path.display()
        )));
    }
    let config = Config::load(&config_path)?;
    let store = LocalStore::new(&config.application)?;
    let remotes_base = store.base().join("remotes");
    std::fs::create_dir_all(&remotes_base).ok();

    let factory = move |s: &crate::config::ServerDef,
                        slot: &crate::config::SlotDef|
          -> Result<Box<dyn Remote>> { create_remote(s, &slot.deploy_dir) };

    match cli.command {
        Command::Push {
            target,
            reference,
            dry_run,
        } => {
            let report = push(
                &config_path,
                &store,
                &factory,
                &target,
                &config,
                &PushOptions {
                    dry_run,
                    ref_token: reference,
                },
            )?;
            print_report(&report);
        }
        Command::Log { target } => {
            let attempts = store.read_attempts(&target)?;
            if attempts.is_empty() {
                println!("no deployments for target '{target}'");
            }
            for a in &attempts {
                let (status, reason) = effective_status(&store, a)?;
                match reason {
                    Some(r) => println!(
                        "{}  {:?}  {}  ({r})",
                        a.deployment_id, status, a.attempted_at
                    ),
                    None => println!("{}  {:?}  {}", a.deployment_id, status, a.attempted_at),
                }
            }
        }
        Command::Status { target } => {
            let observed = store.read_observed(&target)?;
            for line in render_status(&observed) {
                println!("{line}");
            }
        }
        Command::Init { .. } => unreachable!("handled above"),
    }
    Ok(())
}

/// Render `deploy status <target>` output: one line per observed slot with
/// the generation, release, variant, and tree AS OBSERVED ON THE SERVER right
/// now (never from local history). A slot with no known assignment renders
/// `None` on every column; a known generation with an unreadable assignment
/// renders the generation while the artifact columns stay `None`. The CLI
/// prints exactly these lines; the unit test asserts on them directly because
/// lib unit tests cannot capture the harness-owned stdout sink.
fn render_status(observed: &ObservedTarget) -> Vec<String> {
    observed
        .slots
        .iter()
        .map(|(slot_id, srv)| {
            let artifact = srv.artifact.as_ref();
            format!(
                "{}  generation={:?} release={:?} variant={:?} tree={:?}",
                slot_id,
                srv.generation,
                artifact.map(|a| &a.release),
                artifact.map(|a| &a.variant),
                artifact.map(|a| &a.tree),
            )
        })
        .collect()
}

/// Effective status of an attempt for `deploy log`: the append-only
/// attempts.jsonl record is immutable, but the attempt's status lives in its
/// per-deployment TRANSITION STREAM (`deployments/<id>/transitions.jsonl`),
/// so the effective status is the LATEST transition (plus its reason, if
/// any). When no transition has been recorded yet, the attempt is treated as
/// still pending.
fn effective_status(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
) -> Result<(DeploymentStatus, Option<String>)> {
    match store.latest_transition(attempt.deployment_id.as_str())? {
        Some(t) => Ok((t.status, t.reason)),
        None => Ok((DeploymentStatus::PendingCommit, None)),
    }
}
fn print_init_report(report: &crate::init::InitReport) {
    println!("created deploy project at {}", report.target.display());
    for f in &report.files {
        println!("  {}", f.display());
    }
    for d in &report.dirs {
        println!("  {}/  (local deployment endpoint)", d.display());
    }
    println!();
    println!("next steps (from inside the project):");
    for s in &report.next_steps {
        println!("  {s}");
    }
}
fn print_report(report: &PushReport) {
    if let Some(status) = &report.status {
        println!("status: {status:?}");
    }
    println!("{}", report.message);
    if let Some(warning) = &report.warning {
        println!("warning: {warning}");
    }
    if let Some(attempt) = &report.attempt {
        for (slot_id, s) in &attempt.slots {
            println!(
                "  {slot_id}  variant={} tree={} generation={:?}",
                s.artifact.variant, s.artifact.tree, s.generation
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DeploymentId, GenerationId, PlacementSlotId, ReleaseId, SCHEMA_VERSION, TargetName,
        TreeDigest, VariantName,
    };
    use crate::records::{ObservedServer, ObservedTarget};
    use std::collections::BTreeMap;

    fn pending_attempt(id: &str) -> DeploymentAttempt {
        DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new("production".to_string()),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    #[test]
    fn log_status_overlays_latest_transition() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let a = pending_attempt("deploy-overlay");

        // No transition recorded yet: the attempt is treated as still pending.
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            (DeploymentStatus::PendingCommit, None)
        );

        // An initial transition records `InProgress`.
        store
            .append_transition(
                a.deployment_id.as_str(),
                &DeploymentStatus::InProgress,
                Some("attempt started"),
            )
            .unwrap();
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            (
                DeploymentStatus::InProgress,
                Some("attempt started".to_string())
            )
        );

        // Reconciliation finalizes with a Successful transition: the log
        // overlays Successful over the earlier InProgress transition.
        store
            .append_transition(
                a.deployment_id.as_str(),
                &DeploymentStatus::Successful,
                Some("recovery finalization"),
            )
            .unwrap();
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            (
                DeploymentStatus::Successful,
                Some("recovery finalization".to_string())
            )
        );

        // Degraded likewise overlays; the latest transition wins.
        store
            .append_transition(a.deployment_id.as_str(), &DeploymentStatus::Degraded, None)
            .unwrap();
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            (DeploymentStatus::Degraded, None)
        );
    }

    /// `deploy status <target>` renders each slot's OBSERVED state as it is
    /// right now on the server: generation, release, variant, and tree. A slot
    /// with an unknown assignment renders `None` on every column (the observed
    /// artifact is optional), and a slot with a known generation but no known
    /// artifact renders the generation while the artifact columns stay `None`.
    /// The CLI prints exactly what [`render_status`] returns, so the test
    /// drives the real `run_with` path (parse, config load, store resolution,
    /// print loop) and asserts the rendered lines through the helper — lib
    /// unit tests cannot capture the harness-owned stdout sink.
    #[test]
    fn status_renders_observed_assignments() {
        // The store lives under `XDG_DATA_HOME` and `run_with` reads the real
        // process env, so the env-lock invariant applies.
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // A minimal but VALID project: `Config::load` requires the release
        // directory to exist with at least one variant file.
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"[[slots]]
id = "p1"
server = "s1"
targets = ["production"]
deploy_dir = "/srv/status"

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
"#,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            r#"schema_version = 1
application = "status-cli"
release = "v1"

[targets.production.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.production.rotation.deployment]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");

        // Point the store at a hermetic `XDG_DATA_HOME` and seed observed.json
        // with three slots: p1 has a full assignment, p2 has NO known
        // assignment (never observed / rotated away), and p3 has a known
        // generation but no known artifact (the assignment could not be read).
        let data_home = dir.path().join("data");
        unsafe { std::env::set_var("XDG_DATA_HOME", &data_home) };
        let store = LocalStore::with_base(data_home.join("simple-deploy")).unwrap();
        store
            .write_observed(
                "production",
                &ObservedTarget {
                    target: TargetName::new("production".to_string()),
                    slots: BTreeMap::from([
                        (
                            PlacementSlotId::new("p1".to_string()),
                            ObservedServer {
                                generation: Some(GenerationId::new("gen-41da".to_string())),
                                artifact: Some(crate::model::ArtifactRef {
                                    release: ReleaseId::new("rel-sha256-status".to_string()),
                                    variant: VariantName::new("standard".to_string()),
                                    tree: TreeDigest::new("tree-2c4f".to_string()),
                                }),
                                last_deployment: Some(DeploymentId::new(
                                    "deploy-status-1".to_string(),
                                )),
                            },
                        ),
                        (
                            PlacementSlotId::new("p2".to_string()),
                            ObservedServer {
                                generation: None,
                                artifact: None,
                                last_deployment: None,
                            },
                        ),
                        (
                            PlacementSlotId::new("p3".to_string()),
                            ObservedServer {
                                generation: Some(GenerationId::new("gen-9f00".to_string())),
                                artifact: None,
                                last_deployment: None,
                            },
                        ),
                    ]),
                },
            )
            .unwrap();

        // Drive the real CLI path end-to-end: argument parsing, config load,
        // store resolution, and the print loop must all succeed against the
        // seeded store.
        run_with([
            "deploy",
            "--config",
            cfg_path.to_str().unwrap(),
            "status",
            "production",
        ])
        .expect("deploy status must succeed");

        // Restore the environment and release the env lock BEFORE any
        // assertion: a failing assertion must never poison the shared
        // `ENV_LOCK`.
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        drop(_lock);

        // The rendered lines are exactly what the CLI printed, one per slot
        // (BTreeMap order: p1, p2, p3).
        let lines = render_status(&store.read_observed("production").unwrap());
        assert_eq!(lines.len(), 3, "one line per observed slot: {lines:?}");
        let p1 = &lines[0];
        assert!(p1.contains("p1  generation="), "p1 line: {p1}");
        assert!(p1.contains("gen-41da"), "generation id rendered: {p1}");
        assert!(
            p1.contains("rel-sha256-status"),
            "release id rendered: {p1}"
        );
        assert!(p1.contains("standard"), "variant rendered: {p1}");
        assert!(p1.contains("tree-2c4f"), "tree digest rendered: {p1}");
        // p2: an entirely unknown assignment renders as None on every column.
        assert_eq!(
            lines[1],
            "p2  generation=None release=None variant=None tree=None"
        );
        // p3: a known generation with an unknown artifact renders the
        // generation but None on the artifact columns.
        assert!(lines[2].contains("gen-9f00"), "p3 line: {}", lines[2]);
        assert!(
            lines[2].contains("release=None variant=None tree=None"),
            "generation-only slot must keep the artifact columns None: {}",
            lines[2]
        );
    }

    use clap::{CommandFactory, Parser};
    use std::path::Path;

    #[test]
    fn init_parses_with_flags() {
        let cli = Cli::try_parse_from([
            "deploy",
            "init",
            "my-app",
            "--name",
            "backend",
            "--address",
            "app.example.com",
            "--user",
            "ops",
            "--port",
            "2222",
            "--host-key-fingerprint",
            "SHA256:abc",
        ])
        .unwrap();
        let Command::Init {
            path,
            name,
            address,
            user,
            port,
            known_hosts,
            host_key_fingerprint,
        } = cli.command
        else {
            panic!("expected Init command");
        };
        assert_eq!(path.as_deref(), Some(Path::new("my-app")));
        assert_eq!(name.as_deref(), Some("backend"));
        assert_eq!(address.as_deref(), Some("app.example.com"));
        assert_eq!(user, "ops");
        assert_eq!(port, Some(2222));
        assert_eq!(known_hosts, None);
        assert_eq!(host_key_fingerprint.as_deref(), Some("SHA256:abc"));
    }

    #[test]
    fn init_defaults_to_current_directory() {
        let cli = Cli::try_parse_from(["deploy", "init"]).unwrap();
        assert!(matches!(cli.command, Command::Init { .. }));
    }

    // Host identity is exactly one source: `--known-hosts` and
    // `--host-key-fingerprint` conflict at parse time.
    #[test]
    fn init_rejects_both_identity_flags() {
        let err = Cli::try_parse_from([
            "deploy",
            "init",
            "--address",
            "app.example.com",
            "--known-hosts",
            "/etc/ssh/known_hosts",
            "--host-key-fingerprint",
            "SHA256:abc",
        ])
        .err()
        .expect("both identity flags must conflict at parse time");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be used with") || msg.contains("conflicts"),
            "clap must report the conflict, got: {msg}"
        );
        assert!(
            msg.contains("--known-hosts") && msg.contains("--host-key-fingerprint"),
            "error must name both flags, got: {msg}"
        );
    }

    // The conflict also fires without --address (local:// default) — the
    // identity flags are only meaningful for SSH, so both together is always
    // a parse error.
    #[test]
    fn init_rejects_both_identity_flags_without_address() {
        assert!(
            Cli::try_parse_from([
                "deploy",
                "init",
                "--known-hosts",
                "/etc/ssh/known_hosts",
                "--host-key-fingerprint",
                "SHA256:abc",
            ])
            .is_err()
        );
    }

    #[test]
    fn help_is_self_documenting() {
        // The full help text is a first-class documentation surface: the
        // forced project layout, local:// vs SSH, and the next commands must
        // all be present.
        let help = Cli::command().render_long_help().to_string();
        for needle in [
            "releases/<name>",
            "releases/<name>/<variant>.toml",
            "local://",
            "deploy init",
        ] {
            assert!(help.contains(needle), "top-level help missing {needle:?}");
        }
        let mut cmd = Cli::command();
        let init_help = cmd
            .find_subcommand_mut("init")
            .unwrap()
            .render_long_help()
            .to_string();
        for needle in [
            ".deploy-remote",
            "local://",
            "--host-key-fingerprint",
            "--known-hosts",
            "deploy push production",
        ] {
            assert!(init_help.contains(needle), "init help missing {needle:?}");
        }
        let mut push_cmd = Cli::command();
        let push_help = push_cmd
            .find_subcommand_mut("push")
            .unwrap()
            .render_long_help()
            .to_string();
        for needle in [
            "shell-quote parent(...) forms",
            "deploy push production 'parent(@, 3)'",
            "deploy push production @-",
        ] {
            assert!(push_help.contains(needle), "push help missing {needle:?}");
        }
    }
}

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
use crate::records::{AttemptRecord, DeploymentStatus};
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
  deploy.toml                    names the active release, servers, slots, targets\n\
  releases/<name>/              the release directory named by `release:` in deploy.toml\n\
  releases/<name>/<variant>.toml   every *.toml file here is a variant (file stem = name)\n\
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
  deploy.toml                        schema v1 config: one server, one slot, target `production`\n\
  releases/v1/standard.toml          the `standard` variant (mappings + policies)\n\
  releases/v1/artifacts/build/output/app/hello   placeholder artifact source\n\
  .deploy-remote/                    LOCAL deployment endpoint (see below)\n\
\n\
LOCAL-FIRST DEFAULT: the server address is `local://<project>/.deploy-remote`,\n\
a local-filesystem endpoint, so `deploy push production` runs end-to-end with\n\
zero SSH or server infrastructure. For a real server, pass --address, --user,\n\
and either --known-hosts or --host-key-fingerprint (SSH trust-on-first-use is\n\
refused; both must be absolute paths / a SHA256:... value).\n\
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
        /// SSH port (default 22; written into deploy.toml only when set).
        #[arg(long)]
        port: Option<u16>,
        /// Absolute path to a known_hosts file (strict host-key checking).
        #[arg(long, value_name = "FILE")]
        known_hosts: Option<PathBuf>,
        /// Pre-verified host key fingerprint, e.g. SHA256:... .
        #[arg(long, value_name = "SHA256:...")]
        host_key_fingerprint: Option<String>,
    },
    /// Deploy the current local inputs (or a reference) to a named target.
    #[command(
        long_about = "Deploy to a target: push the local files mapped by the target's\n\
variants (or restore a historical deployment) to every server in the target,\n\
in rollout batches.\n\
\n\
REFERENCE (optional second argument):\n\
  HEAD                          the current local files (default)\n\
  <target>@fN                   roll back to the Nth successful fleet deployment\n\
                                (e.g. production@f1); failed attempts never count\n\
  release/<id>:current          deploy a retained release, keeping each server's\n\
                                configured variant (omit :current to restore the\n\
                                release's original variant per server)\n\
\n\
--dry-run prints the plan and touches nothing (no store writes, no remote\n\
state, no locks). Pushing identical content prints 'Everything up to date'.\n\
Rollout batches per rollout.batch_size; on a failed server, earlier batches\n\
roll back by default (failure_policy: rollback_changed). The final status is\n\
reported explicitly, including partial states like `degraded`.",
        after_help = "Examples:\n\
  deploy push production               # deploy local files\n\
  deploy push production --dry-run     # preview the plan, touch nothing\n\
  deploy push production production@f1 # roll back to the 2nd successful deployment\n\
  deploy push production release/rel-41da2f63   # deploy a specific release"
    )]
    Push {
        target: String,
        /// Optional source reference: HEAD (default), <target>@fN, or
        /// release/<id>:current.
        reference: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the target's deployment history (successful and failed).
    #[command(
        long_about = "Show every recorded deployment attempt for the target, newest last:\n\
deployment ID, status, and timestamp. Failed and degraded attempts remain\n\
visible here but are NOT valid rollback refs — only successful fleet\n\
snapshots advance <target>@fN (see `deploy help push`)."
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
                let status = effective_status(&store, a)?;
                println!("{}  {:?}  {}", a.deployment_id, status, a.attempted_at);
            }
        }
        Command::Status { target } => {
            let observed = store.read_observed(&target)?;
            for (sid, srv) in &observed.servers {
                println!(
                    "{}  generation={:?} release={:?} variant={:?} tree={:?}",
                    sid, srv.generation, srv.release, srv.variant, srv.tree
                );
            }
        }
        Command::Init { .. } => unreachable!("handled above"),
    }
    Ok(())
}

/// Effective status of an attempt for `deploy log`: the append-only
/// attempts.jsonl record is immutable, but reconciliation finalizes the
/// MUTABLE status file (`deployments/<id>/status`), so the recorded status is
/// overlaid with it. When the status file is absent or holds an unrecognized
/// value, fall back to the recorded status.
fn effective_status(store: &LocalStore, attempt: &AttemptRecord) -> Result<DeploymentStatus> {
    match store.read_status(attempt.deployment_id.as_str())? {
        Some(s) => Ok(parse_status(&s).unwrap_or_else(|| attempt.status.clone())),
        None => Ok(attempt.status.clone()),
    }
}

/// Parse the Debug-string form persisted by `write_status` (e.g.
/// "Successful", "Degraded") back into a [`DeploymentStatus`].
fn parse_status(s: &str) -> Option<DeploymentStatus> {
    match s {
        "Successful" => Some(DeploymentStatus::Successful),
        "PendingCommit" => Some(DeploymentStatus::PendingCommit),
        "FailedPreflight" => Some(DeploymentStatus::FailedPreflight),
        "FailedRolledBack" => Some(DeploymentStatus::FailedRolledBack),
        "Degraded" => Some(DeploymentStatus::Degraded),
        _ => None,
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
    if let Some(attempt) = &report.attempt {
        for (sid, s) in &attempt.servers {
            println!(
                "  {sid}  variant={} tree={} generation={:?}",
                s.variant, s.tree, s.generation
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeploymentId, ServerId, TargetName};
    use std::collections::BTreeMap;

    fn pending_attempt(id: &str) -> AttemptRecord {
        AttemptRecord {
            deployment_schema_version: 1,
            deployment_id: DeploymentId::new(id.to_string()),
            status: DeploymentStatus::PendingCommit,
            target: TargetName::new("production".to_string()),
            server_ids: vec![ServerId::new("server-01".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            servers: BTreeMap::new(),
        }
    }

    #[test]
    fn log_status_overlays_mutable_status_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let a = pending_attempt("deploy-overlay");

        // No status file yet: fall back to the recorded (attempts.jsonl) status.
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            DeploymentStatus::PendingCommit
        );

        // Reconciliation finalizes the mutable status file: the log overlays
        // Successful over the still-PendingCommit attempts.jsonl record.
        store
            .write_status(a.deployment_id.as_str(), "Successful")
            .unwrap();
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            DeploymentStatus::Successful
        );

        // Degraded likewise overlays the recorded status.
        store
            .write_status(a.deployment_id.as_str(), "Degraded")
            .unwrap();
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            DeploymentStatus::Degraded
        );

        // An unparseable status file degrades gracefully to the recorded value.
        store
            .write_status(a.deployment_id.as_str(), "NotAStatus")
            .unwrap();
        assert_eq!(
            effective_status(&store, &a).unwrap(),
            DeploymentStatus::PendingCommit
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
    }
}

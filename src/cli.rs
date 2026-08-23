//! Command-line interface.

use crate::config::Config;
use crate::error::{Error, Result};
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
    about = "Simple deployment system with a Git-push-style interface"
)]
struct Cli {
    /// Path to deploy.toml (defaults to ./deploy.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Deploy the current local inputs (or a reference) to a named target.
    Push {
        target: String,
        /// Optional source reference: HEAD (default), <target>@fN, or
        /// release/<id>:current.
        reference: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect the target's deployment history.
    Log { target: String },
    /// Inspect the actual generation on every server.
    Status { target: String },
}

/// CLI entry point.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("deploy.toml"));
    if !config_path.exists() {
        return Err(Error::config(format!(
            "config '{}' not found",
            config_path.display()
        )));
    }
    let config = Config::load(&config_path)?;
    let store = LocalStore::new(&config.application)?;
    let remotes_base = store.base().join("remotes");
    std::fs::create_dir_all(&remotes_base).ok();

    let factory = move |s: &crate::config::ServerDef,
                        pod: &crate::config::PodDef|
          -> Result<Box<dyn Remote>> { create_remote(s, &pod.deploy_dir) };

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
}

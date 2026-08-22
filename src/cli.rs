//! Command-line interface.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::push::engine::{PushOptions, PushReport, push};
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

    let config_for_factory = config.clone();
    let factory = move |s: &crate::config::ServerDef| -> Result<Box<dyn Remote>> {
        create_remote(s, &config_for_factory)
    };

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
                println!("{}  {:?}  {}", a.deployment_id, a.status, a.attempted_at);
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

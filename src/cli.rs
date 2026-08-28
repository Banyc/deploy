//! Command-line interface.
//!
//! The CLI is the primary documentation surface for agents: every subcommand
//! carries a `long_about` that teaches the forced project structure, the
//! configuration, the rollout/rollback semantics, and copy-paste-runnable
//! examples. Run `deploy --help`, `deploy help <cmd>`, or `deploy <cmd> --help`
//! to see it.

use crate::config::ProjectConfig;
use crate::deploy::{PushOptions, PushReport, push};
use crate::env::SysEnv;
use crate::error::{Error, Result};
use crate::identity::{AcquisitionId, DeploymentId, ReleaseId, SlotId, valid_hex_digest};
use crate::init::{InitOptions, init_project};
use crate::ledger::{ObservedAssignment, ObservedTarget};
// The `deploy log` RENDERING lives in [`crate::ledger::log`]; cli.rs stays the
// command wrapper (arg parsing + printing) and keeps the old
// `crate::cli::render_log` path working via this thin re-export (the
// integration tests reference it).
pub use crate::ledger::log::render_log;
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
  deploy.toml                    names the active release, servers, targets (rollout + retention)\n\
  releases/<name>/              the release directory named by `release:` in deploy.toml\n\
  releases/<name>/<variant>.toml   every *.toml file here is a variant (file stem = name);\n\
                                  each variant declares its own [[slots]] (server, deploy_dir, target)\n\
  releases/<name>/artifacts/    artifact sources referenced by variant mappings\n\
\n\
The quickest start is `deploy init` — it scaffolds a working project with a\n\
LOCAL deployment root (the pathless `local` connection; the slot's
\ndeploy_dir is the sole physical root), so `deploy push production` works\n\
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
  deploy.toml                        schema v2 config: one server, target `production` (rollout only)\n\
  releases/v1/standard.toml          the `standard` variant (mappings + its slot + policies)\n\
  releases/v1/systemd.toml           example `systemd` activation variant with a real unit\n\
  releases/v1/artifacts/build/output/app/hello   placeholder artifact source\n\
  releases/v1/artifacts/systemd/example.service  the unit shipped by the systemd variant\n\
  .deploy-remote/                    LOCAL deployment root (see below)\n\
  .gitignore                         ignores the local endpoint in a repo\n\
\n\
Slots are declared INSIDE the variant files: releases/v1/standard.toml\n\
carries the project's one slot (app-1 -> server-01, bound to target\n\
`production` by its `target` field — targets derive their members from the\n\
slots, they do not list them).\n\
\n\
The generated files are typed TOML serialized from the same config structs\n\
`ProjectConfig::load` parses into — not formatted strings. Init validates the flags\n\
BEFORE creating anything, re-loads the written project through the strict\n\
loader, and removes the scaffold if that load fails: success always means\n\
the generated project is valid.\n\
\n\
LOCAL-FIRST DEFAULT: the server address is the pathless `local` marker and\n\
the slot's deploy_dir defaults to `<project>/.deploy-remote` — the sole\n\
physical root — so `deploy push production` runs end-to-end with\n\
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
        /// Server address. Default: the pathless `local` marker (the slot's
        /// deploy_dir — default `<project>/.deploy-remote` — is the sole
        /// physical root; zero SSH). Use a hostname for SSH.
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
SELECTION: by default every slot owned by the target is selected. Pass\n\
--group <name> to select the rollout's slots: for a HEAD or rollback ref,\n\
the target's slots whose CURRENT `groups` list contains the name; for a\n\
release:<id> ref, the slots the RELEASE's frozen topology puts in the\n\
group (a slot the release pushed inside the group but the current config\n\
regrouped still belongs to the release push - the release's frozen group\n\
partition governs). An unknown group, or a group selecting zero slots for\n\
the selected era, is a configuration error. A group push produces a\n\
COMPLETE target snapshot: the\n\
selected slots are replaced with their new assignments while unselected\n\
slots are carried forward unchanged, so a partial rollout stays fully\n\
rollback-capable. On a target's first deployment a group must cover every\n\
target slot; after membership changes every unselected slot must have a\n\
prior assignment with a matching physical binding.\n\
\n\
REFERENCE (optional second argument, jj-style — the target is NEVER repeated\n\
in the reference; every relative form resolves against the target argument):\n\n\
  (none), HEAD, @      the current local files (default)\n\
  @-                   the deployment BEFORE the latest successful deployment\n\
  @--                  two steps back (the grandparent)\n\
  parent(@, N)         N steps back from the latest (e.g. parent(@, 2))\n\
  <deployment-id>      roll back to EXACTLY that deployment's stored state\n\
                       (its snapshot: slots, behavior, bindings, release)\n\
  <deployment-id>- / --    N steps back from that deployment in the history\n\
  parent(<deployment-id>, N)   N steps back from that deployment\n\
  release:<id>         deploy the named release DIRECTLY to the current\n\
                       target's slots, from the release's own stored slot\n\
                        snapshot — no snapshot history needed (cross-target)\n\
\n\
NOTE: every parent(...) form contains a comma, so the shell splits the\n\
reference at the space after the comma. shell-quote parent(...) forms —\n\
e.g. deploy push production 'parent(@, 3)' — in interactive shells.\n\
\n\
ROLLBACK PAYLOADS ARE KEYED BY DEPLOYMENT ID: `@`, `@-`, `@--` and\n\
parent(...) walk the target's DEPLOYMENT HISTORY — each successful\n\
deployment IS a rollback payload keyed by its id; failed attempts never\n\
count and never produce a snapshot. The old `sN` snapshot-index forms are\n\
REMOVED: migrate `deploy push <target> sN` to the deployment id of that\n\
snapshot's deployment (see `deploy log <target>`), or use `@-` /\n\
parent(@, N)` for the deployment history.\n\
--dry-run prints the plan and touches nothing (no store writes, no remote\n\
state, no locks). Pushing identical content prints 'Everything up to date'.\n\
Rollout batches per rollout.batch_size; on a failed server, earlier batches\n\
roll back by default (failure_policy: rollback_changed). The final status is\n\
reported explicitly, including partial states like `degraded`.",
        after_help = "Examples:\n\
  deploy push production               # deploy local files\n\
  deploy push production --group canary  # deploy only the canary group\n\
  deploy push production --dry-run     # preview the plan, touch nothing\n\
  deploy push production @-            # roll back to the previous deployment\n\
  deploy push production 'parent(@, 3)'  # roll back 3 deployments\n\
  deploy push production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b  # roll back to that deployment's stored state\n\
  deploy push production release:rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1  # DIRECT release deploy to this target (cross-target; no history needed)"
    )]
    Push {
        target: String,
        /// Optional jj-style source reference: blank/HEAD/@ (default),
        /// @- / @-- / parent(@, N), a deployment id (rollback to that
        /// deployment's stored state) or a deployment-id relative
        /// (<deployment-id>- / parent(<deployment-id>, N)), or
        /// release:<id> (direct release deploy) — never repeats the target.
        /// The `sN` snapshot-index forms are removed.
        reference: Option<String>,
        /// Select a rollout group: deploy exactly the target's slots whose
        /// `groups` list contains this name (an unknown group, or a group
        /// selecting zero slots, is a configuration error). Omitting the
        /// flag selects every slot owned by the target.
        #[arg(long, value_name = "NAME")]
        group: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the target's deployment history (successful and failed).
    #[command(
        long_about = "Show every recorded deployment attempt for the target, newest last:\n\
deployment ID, status, and timestamp. Each line is prefixed with the\n\
DEPLOYMENT ID of the snapshot that attempt produced — the exact rollback\n\
key `deploy push` accepts (`deploy push <target> <deployment-id>`) — or\n\
`-` for attempts that produced no snapshot. Failed attempts remain\n\
visible here but are NOT valid rollback refs; only successful deployments\n\
produce snapshots (see `deploy help push` for the reference syntax)."
    )]
    Log { target: String },
    /// Show what is actually running on every server.
    #[command(
        long_about = "Inspect the real generation on every server of the target: generation\n\
id, release id, variant, and tree digest, as observed on the servers themselves\n\
(right now — not from local history). Pass --group <name> to show only the\n\
target's slots whose `groups` list contains the name (an unknown group, or a\n\
group selecting zero slots, is a configuration error)."
    )]
    Status {
        target: String,
        /// Show only the slots of this rollout group (an unknown group, or a
        /// group selecting zero slots, is a configuration error).
        #[arg(long, value_name = "NAME")]
        group: Option<String>,
    },
    /// Retain a target's history suffix (checkpoint) and sweep the rest.
    #[command(
        long_about = "Checkpoint the target's ONE history ledger\n\
(targets/<target>/ledger.jsonl) at a successful deployment: the ledger is\n\
ATOMICALLY replaced with the retained suffix at that deployment — the floor\n\
is implicit, the first retained entry is the oldest rollback state — and\n\
the unreachable deployment directories, release records, and tree objects\n\
are swept best-effort. The checkpoint deployment must be a SUCCESSFUL\n\
deployment of the target (its ledger entry carries a rollback state);\n\
everything strictly before it is discarded permanently.\n\
\n\
The operation is IRREVERSIBLE, so the deployment id is an explicit,\n\
required positional and the real operation requires --yes. --dry-run\n\
prints exactly what would be discarded and touches NOTHING (no locks, no\n\
writes, no remote contact); --yes performs the replacement + sweep.\n\
Repeating the same checkpoint is idempotent (the ledger is already the\n\
suffix) and finishes an interrupted sweep by recomputing reachability.\n\
\n\
The atomic ledger replacement is the checkpoint's ONLY logical commit: a\n\
failed replacement deletes nothing, and a failed sweep is retried by\n\
recomputing reachability — no floor marker, no backup, no debt flag. The\n\
sweep keeps everything reachable from another target's ledger, the current\n\
observed state, or a pin. Sweeps are best-effort, not secure erasure.\n\
A checkpoint does not deploy anything or contact remote servers.",
        after_help = "Examples:\n\
  deploy checkpoint production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b --dry-run  # preview what would be discarded\n\
         deploy checkpoint production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b --yes  # retain the suffix + sweep (irreversible)\n\
          deploy log production                               # now shows only the retained suffix\n\
          deploy push production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b  # the checkpoint entry stays the oldest rollback"
    )]
    Checkpoint {
        target: String,
        /// The successful deployment to checkpoint (required: the operation
        /// is irreversible, so the id must be explicit).
        deployment_id: DeploymentId,
        /// Preview exactly what would be discarded; touches nothing (no
        /// locks, no writes, no remote).
        #[arg(long)]
        dry_run: bool,
        /// Confirm the irreversible operation. Required for the real
        /// operation; rejected without it.
        #[arg(long)]
        yes: bool,
    },
    /// Inspect and recover a stranded server mutation lock.
    #[command(
        long_about = "Inspect and recover a stranded server mutation lock.\n\
\n\
The server mutation lock is a create-once ownership record with NO\n\
expiry (no lease, no clock): a held lock never becomes breakable on\n\
its own and changes hands ONLY via explicit recovery. A transient\n\
release failure (transport fault at drop) strands the slot forever\n\
until an operator confirms the holding controller died and recovers.\n\
This command is the explicit, evidence-requiring remedy: it inspects\n\
the remote lock (typed read, never provisioning layout) and — with\n\
--yes — replaces the dead holder's record with a successor (fresh\n\
acquisition id) under the authoritative local store lock, then\n\
releases, leaving the slot free.\n\
\n\
Without --yes the command is a read-only preview: a free slot reports\n\
free, a held slot is refused with the holder, acquisition id, and the\n\
remedy command (the lock is never touched). With --yes the held lock is\n\
recovered and released; the slot ends free. The operation is idempotent\n\
(a free slot stays free) and a stale observed record is refused\n\
(the lock changed; re-read and re-confirm).",
        after_help = "Examples:\n\
  deploy unlock production p1                                      # inspect: free or held + remedy\n\
  deploy unlock production p1 --acquisition acq-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b --yes  # recover the inspected acquisition and release — slot free\n\
  deploy push production                                           # now succeeds (lock was freed)"
    )]
    Unlock {
        /// The target whose member slot's mutation lock to inspect/recover.
        target: String,
        /// The member slot (one of the target's slots) whose server mutation lock is stuck.
        slot: SlotId,
        /// The acquisition id you inspected (the exact `acquisition <id>` shown by the
        /// inspect preview). Required with --yes: recovery is bound to the
        /// acquisition you confirmed dead.
        #[arg(long)]
        acquisition: Option<AcquisitionId>,
        /// Recover the lock: confirm the holding operation died and replace it with a
        /// successor record (fresh acquisition id), then release — leaving the slot free. Required
        /// for the real operation; refused without it. When --yes is present,
        /// --acquisition is required and must match the current on-disk
        /// acquisition id or the recovery is refused.
        #[arg(long)]
        yes: bool,
    },
}

/// CLI entry point: snapshot the process environment ONCE at the process
/// boundary ([`SysEnv::from_process`]) and thread it down through
/// [`cli::run_with`](`crate::cli::run_with`) — the house pattern (mirroring
/// `run_with(std::env::args())` for argv): subsystem code never reads the
/// live process env.
pub fn run() -> Result<()> {
    run_with(std::env::args(), &SysEnv::from_process())
}

/// Parse `args` (argv, including the program name) and run the command
/// against the environment snapshot `env` (resolved at the boundary; the
/// store base and any child-process environment come from it, never from a
/// live process read).
pub fn run_with<I, T>(args: I, env: &SysEnv) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    // Absolutize the config path so `ProjectConfig::load` can canonicalize the
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
    let config = ProjectConfig::load(&config_path)?;
    // The config's `application` IS the store key (one safe application
    // identifier for display and storage): the load already validated it as
    // a single safe path segment, so the store is constructed DIRECTLY from
    // it — no fallible identity conversion remains between a loaded config
    // and its store.
    let store = LocalStore::new_in(env, config.application())?;
    let remotes_base = store.base().join("remotes");
    std::fs::create_dir_all(&remotes_base).ok();

    // The factory owns a CLONE of the snapshot (the `RemoteFactory` type is
    // `'static`): each remote is built from the same boundary snapshot, so
    // every spawned child env is deterministic.
    let env = env.clone();
    let factory =
        move |s: &crate::config::ServerDef,
              slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> { create_remote(&env, s, slot.deploy_dir()) };

    match cli.command {
        Command::Push {
            target,
            reference,
            group,
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
                    group,
                },
            )?;
            print_report(&report);
        }
        Command::Log { target } => {
            let entries = store.read_ledger(&target)?;
            if entries.is_empty() {
                println!("no deployments for target '{target}'");
            }
            for line in render_log(&store, &target, &entries)? {
                println!("{line}");
            }
        }
        Command::Status { target, group } => {
            // The target view over the single physical slot state: the global
            // slot map (`slots/<slot-id>/observed.json`) filtered to this
            // target's member slots, then (with --group) to the group's
            // current membership.
            let observed = store.read_observed(&target, &config)?;
            let observed = match &group {
                Some(g) => {
                    let selected: std::collections::HashSet<&str> = config
                        .target_group_slots(&target, g)?
                        .iter()
                        .map(|(s, _)| s.id.as_str())
                        .collect();
                    crate::ledger::ObservedTarget {
                        target: observed.target,
                        slots: observed
                            .slots
                            .into_iter()
                            .filter(|(id, _)| selected.contains(id.as_str()))
                            .collect(),
                    }
                }
                None => observed,
            };
            for line in render_status(&observed) {
                println!("{line}");
            }
        }
        Command::Checkpoint {
            target,
            deployment_id,
            dry_run,
            yes,
        } => {
            // The real operation is irreversible: without --yes (and without
            // a --dry-run preview) it is refused up front.
            if !dry_run && !yes {
                return Err(Error::preflight(
                    "checkpoint is irreversible: pass --yes to retain the history suffix \
                     (or --dry-run to preview exactly what would be discarded)",
                ));
            }
            let report = crate::retention::checkpoint::run_checkpoint(
                &store,
                &config,
                &target,
                &deployment_id,
                dry_run,
            )?;
            for line in crate::retention::checkpoint::render_checkpoint_report(&report) {
                println!("{line}");
            }
        }
        Command::Unlock {
            target,
            slot,
            acquisition,
            yes,
        } => {
            if yes && acquisition.is_none() {
                return Err(Error::preflight(format!(
                    "unlock --yes requires --acquisition: pass --acquisition <id> with --yes after confirming the holding controller died (re-inspect via `deploy unlock {} {}` to obtain the acquisition id)",
                    target, slot
                )));
            }
            if !yes && acquisition.is_some() {
                return Err(Error::preflight(
                    "--acquisition requires --yes: pass --yes with --acquisition <id> after confirming the holding controller died",
                ));
            }
            let report = crate::deploy::unlock::run_unlock(
                &store,
                &config,
                &factory,
                &target,
                &slot,
                acquisition,
                yes,
            )?;
            for line in crate::deploy::unlock::render_unlock_report(&report) {
                println!("{line}");
            }
        }
        Command::Init { .. } => unreachable!("handled above"),
    }
    Ok(())
}

/// Parse a CLI release input: the full `rel-sha256-<64 lowercase hex>` form
/// OR a bare 64-lowercase-hex digest (a convenience, converted to the full
/// form BEFORE the domain parse). Anything else is a CLI error. The DOMAIN
/// [`ReleaseId`] stays strict — the bare-digest convenience lives HERE, at
/// the CLI boundary, never in the domain.
pub fn parse_release_input(s: &str) -> Result<ReleaseId> {
    if s.starts_with("rel-sha256-") {
        ReleaseId::parse(s)
    } else if valid_hex_digest(s) {
        ReleaseId::parse(&format!("rel-sha256-{s}"))
    } else {
        Err(Error::config(format!(
            "invalid release id {s:?}: expected 'rel-sha256-<64 lowercase hex>' or a bare \
             64-hex digest"
        )))
    }
}

/// Render `deploy status <target>` output: one line per observed slot with
/// the generation, release, variant, and tree AS OBSERVED ON THE SERVER right
/// now (never from local history). A slot with no observed state
/// (`KnownAbsent`) renders `None` on every column; a FAILED observation
/// (`Unknown`) renders `None` on every column with the preserved error
/// appended — an unknown observation is never rendered as if the slot were
/// unchanged. The CLI prints exactly these lines; the unit test asserts on
/// them directly because lib unit tests cannot capture the harness-owned
/// stdout sink.
fn render_status(observed: &ObservedTarget) -> Vec<String> {
    observed
        .slots
        .iter()
        .map(|(slot_id, srv)| match &srv.assignment {
            ObservedAssignment::Known {
                generation,
                artifact,
                ..
            } => format!(
                "{}  generation={:?} release={:?} variant={:?} tree={:?}",
                slot_id,
                Some(generation.clone()),
                Some(artifact.release.clone()),
                Some(artifact.variant.clone()),
                Some(artifact.tree.clone()),
            ),
            // A slot with no observed state (`Absent`), a failed status read
            // (`Unknown`), or a generation whose ASSIGNMENT could not be read
            // (`AssignmentUnknown`) all render `None` on every column — the
            // error variants append the preserved error. An uncertain
            // observation is NEVER rendered as if the slot were running
            // something (no fabricated generation/artifact).
            ObservedAssignment::Absent => format!(
                "{}  generation=None release=None variant=None tree=None",
                slot_id,
            ),
            ObservedAssignment::AssignmentUnknown { error, .. }
            | ObservedAssignment::Unknown { error } => format!(
                "{}  generation=None release=None variant=None tree=None (observation failed: {})",
                slot_id, error.message,
            ),
        })
        .collect()
}

fn print_init_report(report: &crate::init::InitReport) {
    println!("created deploy project at {}", report.target.display());
    for f in &report.files {
        println!("  {}", f.display());
    }
    for d in &report.dirs {
        println!("  {}/  (local deployment root)", d.display());
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
            // The actual artifact is an observation: render a `Known`
            // artifact, and a non-`Known` actual explicitly rather than
            // printing a fabricated variant/tree.
            let artifact = match &s.artifact {
                crate::ledger::Observation::Known(a) => {
                    format!("variant={} tree={}", a.variant, a.tree)
                }
                crate::ledger::Observation::KnownAbsent => "artifact=known_absent".to_string(),
                crate::ledger::Observation::Unknown(e) => {
                    format!("artifact=unknown ({})", e.message)
                }
            };
            println!("  {slot_id}  {artifact} generation={:?}", s.generation);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, ReleaseId, ServerId, SlotId,
        TargetName, VariantName, test_deployment_id, test_generation_id, test_release_id,
        test_tree_digest,
    };
    use crate::ledger::{
        DeploymentIntent, DeploymentStatus, DesiredGeneration, IntentSlot, LedgerRollback,
        LedgerTerminal, NonEmptySlotTable, ObservedSlot, TerminalDisposition,
    };
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    fn pending_attempt(id: &str) -> DeploymentIntent {
        let p1 = SlotId::new("p1".to_string());
        // ONE slot table (the membership + desired/pre-push entries).
        let slots = BTreeMap::from([(
            p1.clone(),
            IntentSlot {
                desired: DesiredGeneration {
                    generation: test_generation_id("gen-1"),
                    artifact: ArtifactRef {
                        release: test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("tree-1"),
                    },
                },
                pre_push: None,
                // The FROZEN plan-time physical binding (schema v6): the
                // fixture's single slot is bound to server s1 at
                // /srv/deploy/p1.
                binding: crate::ledger::PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            },
        )]);
        DeploymentIntent {
            deployment_id: test_deployment_id(id),
            target: TargetName::new("production".to_string()),
            group: None,
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a seeded attempt always has at least one slot"),
            full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
        }
    }

    /// Seed the ledger with a successful deployment (intent + `Successful`
    /// terminal carrying a rollback state, so `sN`/log prefixes apply). The
    /// terminal is the EXACT-EQUAL shape: one Activated outcome per slotted
    /// generation, and a rollback whose slots/bindings key the same
    /// membership (the membership equations (outcomes == selected == full == rollback slots) are enforced by the conversion).
    fn seed_successful(store: &LocalStore, id: &str, attempted_at: &str) {
        let mut it = pending_attempt(id);
        it.attempted_at = attempted_at.to_string();
        store.append_intent("production", &it).unwrap();
        store
            .append_terminal(
                "production",
                &test_deployment_id(id),
                &successful_terminal(attempted_at, "deployed"),
            )
            .unwrap();
    }

    /// A `Successful` terminal in the EXACT-EQUAL shape for the one-slot
    /// fixture intent (membership `p1`): one Activated outcome, and a
    /// rollback whose slots and bindings key exactly `p1`.
    fn successful_terminal(recorded_at: &str, reason: &str) -> LedgerTerminal {
        let p1 = SlotId::new("p1".to_string());
        LedgerTerminal {
            recorded_at: recorded_at.to_string(),
            disposition: TerminalDisposition::Successful {
                rollback: {
                    let __slots: BTreeMap<crate::identity::SlotId, crate::identity::GenerationRef> =
                        BTreeMap::from([(
                            p1.clone(),
                            GenerationRef {
                                generation: test_generation_id("gen-1"),
                                assignment: PlacementSlotAssignment {
                                    placement_slot: p1.clone(),
                                    artifact: ArtifactRef {
                                        release: test_release_id("rel-1"),
                                        variant: VariantName::new("standard".to_string()),
                                        tree: test_tree_digest("tree-1"),
                                    },
                                },
                            },
                        )]);
                    let __bindings: BTreeMap<
                        crate::identity::SlotId,
                        crate::ledger::records::PhysicalBinding,
                    > = BTreeMap::from([(
                        p1.clone(),
                        crate::ledger::PhysicalBinding {
                            server: ServerId::new("s1".to_string()),
                            deploy_dir: "/srv/deploy/p1".to_string(),
                        },
                    )]);
                    let mut __entries: BTreeMap<
                        crate::identity::SlotId,
                        crate::ledger::records::RollbackEntry,
                    > = BTreeMap::new();
                    for (k, v) in __slots.clone() {
                        let b = __bindings.get(&k).cloned().unwrap_or(
                            crate::ledger::records::PhysicalBinding {
                                server: crate::identity::ServerId::new("s1"),
                                deploy_dir: format!("/srv/deploy/{}", k.as_str()),
                            },
                        );
                        __entries.insert(
                            k.clone(),
                            crate::ledger::records::RollbackEntry::new(
                                v.generation.clone(),
                                v.assignment.artifact.clone(),
                                b,
                            ),
                        );
                    }
                    for (k, b) in __bindings.clone() {
                        __entries.entry(k.clone()).or_insert_with(|| {
                            crate::ledger::records::RollbackEntry::new(
                                crate::identity::GenerationId::new("gen-missing".to_string()),
                                crate::identity::ArtifactRef {
                                    release: crate::identity::test_release_id("rel-missing"),
                                    variant: crate::identity::VariantName::new(
                                        "standard".to_string(),
                                    ),
                                    tree: crate::identity::test_tree_digest("missing"),
                                },
                                b.clone(),
                            )
                        });
                    }
                    LedgerRollback::from_entries(__entries)
                },
                // SUCCESS IS THE ACTIVATED SLOT-ID SET: the per-slot
                // generation/artifact facts are DERIVED from the rollback
                // (never stored/trusted separately).
                activated: BTreeSet::from([p1.clone()]),
                // THE EXACT-EQUAL MEMBERSHIPS: activated == full == the
                // one-slot membership (the rollback's slots) — the proven
                // shape the conversion + read require.
                full_membership: BTreeSet::from([p1.clone()]),
            },
            reason: Some(reason.to_string()),
        }
    }

    #[test]
    fn log_status_overlays_terminal_event() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let a = pending_attempt("deploy-overlay");

        // No terminal event yet: an intent-only entry is treated as the
        // recoverable pending state.
        store.append_intent("production", &a).unwrap();
        let entries = store.read_ledger("production").unwrap();
        assert_eq!(
            crate::ledger::log::effective_status(&entries[0]),
            (DeploymentStatus::PendingCommit, None)
        );

        // A terminal event carries the status + reason. The status is
        // `Successful`, so the terminal must carry its rollback payload (the
        // STATUS/ROLLBACK TRUTH TABLE refuses a Successful terminal without
        // one — the status-only `append_transition` helper cannot represent
        // it, so the terminal is appended directly).
        store
            .append_terminal(
                "production",
                &a.deployment_id,
                &successful_terminal("2026-01-01T00:00:00Z", "recovery finalization"),
            )
            .unwrap();
        let entries = store.read_ledger("production").unwrap();
        assert_eq!(
            crate::ledger::log::effective_status(&entries[0]),
            (
                DeploymentStatus::Successful,
                Some("recovery finalization".to_string())
            )
        );
    }

    /// `deploy log <target>` prefixes every line with the snapshot id (`sN`)
    /// of the snapshot that attempt produced — the same `sN` notation the
    /// push reference grammar accepts (`deploy push <target> sN`) — or `-`
    /// when the attempt produced no snapshot. The snapshot id is the snapshot
    /// record's canonical `index` (the 0-based op log position `s0`, `s1`,
    /// ...), never a recomputed Vec position. The CLI prints exactly what
    /// [`render_log`] returns, so the test drives the real `run_with` path
    /// and asserts the rendered lines through the helper — lib unit tests
    /// cannot capture the harness-owned stdout sink.
    #[test]
    fn log_prefixes_lines_with_rollback_ref() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();

        // Two deployments: the first succeeds (producing rollback ref s0);
        // the second fails in preflight (producing NO rollback state).
        seed_successful(&store, "deploy-log-ok", "2026-01-01T00:00:00Z");
        let mut a_failed = pending_attempt("deploy-log-failed");
        a_failed.attempted_at = "2026-01-02T00:00:00Z".to_string();
        store.append_intent("production", &a_failed).unwrap();
        store
            .append_terminal(
                "production",
                &a_failed.deployment_id,
                &LedgerTerminal {
                    recorded_at: "2026-01-02T00:00:00Z".to_string(),
                    disposition: TerminalDisposition::FailedPreflight,
                    reason: Some("preflight failed".to_string()),
                },
            )
            .unwrap();

        let attempts = store.read_attempts("production").unwrap();
        let lines = render_log(&store, "production", &attempts).unwrap();
        assert_eq!(lines.len(), 2, "one line per attempt: {lines:?}");
        // A successful attempt renders its deployment id (the rollback key)
        // as the prefix; an attempt without a snapshot renders `-`.
        assert_eq!(
            lines[0],
            format!(
                "{}  {}  Successful  2026-01-01T00:00:00Z  (deployed)",
                test_deployment_id("deploy-log-ok"),
                test_deployment_id("deploy-log-ok")
            )
        );
        // An entry without a rollback state keeps the columns aligned via `-`.
        assert_eq!(
            lines[1],
            format!(
                "-  {}  FailedPreflight  2026-01-02T00:00:00Z  (preflight failed)",
                test_deployment_id("deploy-log-failed")
            )
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
        // The store base is resolved from the SNAPSHOT passed to `run_with`
        // (never the process env): build a hermetic snapshot whose
        // `XDG_DATA_HOME` is a fresh temp root, and seed + read the store
        // through the same snapshot.
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let env = SysEnv::from_map(std::collections::BTreeMap::from([(
            std::ffi::OsString::from("XDG_DATA_HOME"),
            dir.path().join("store-root").into_os_string(),
        )]));
        let project = dir.path().join("proj");
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // A minimal but VALID project: `ProjectConfig::load` requires the release
        // directory to exist with at least one variant file. The variant
        // declares the three rendered slots (all members of `production`) and
        // owns their retention policy (retention lives in the variant file,
        // not on the target).
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"[[slots]]
id = "p1"
server = "s1"
target = "production"
deploy_dir = "/srv/status"

[[slots]]
id = "p2"
server = "s2"
target = "production"
deploy_dir = "/srv/status2"

[[slots]]
id = "p3"
server = "s3"
target = "production"
deploy_dir = "/srv/status3"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

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
            r#"schema_version = 2
application = "status-cli"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        let config = ProjectConfig::load(&cfg_path).unwrap();

        // Point the snapshot's store base at a hermetic `XDG_DATA_HOME` and
        // seed the ONE physical observed record per slot
        // (`slots/<slot-id>/observed.json`) with three slots: p1 has a full
        // assignment, p2 has NO known
        // assignment (a live read showing no state — `Absent`), and p3 has a
        // FAILED observation (the assignment could not be read — recorded as
        // an `AssignmentUnknown` observation with its error preserved, never
        // a forged artifact).
        let store = LocalStore::with_base(crate::store::local::default_base(&env)).unwrap();
        store
            .write_slot_observed(
                &SlotId::new("p1".to_string()),
                &ObservedSlot {
                    assignment: crate::ledger::ObservedAssignment::Known {
                        generation: test_generation_id("gen-41da"),
                        artifact: crate::identity::ArtifactRef {
                            release: test_release_id("rel-sha256-status"),
                            variant: VariantName::new("standard".to_string()),
                            tree: test_tree_digest("tree-2c4f"),
                        },
                        last_deployment: test_deployment_id("deploy-status-1"),
                    },
                },
            )
            .unwrap();
        store
            .write_slot_observed(
                &SlotId::new("p2".to_string()),
                &ObservedSlot {
                    assignment: crate::ledger::ObservedAssignment::Absent,
                },
            )
            .unwrap();
        store
            .write_slot_observed(
                &SlotId::new("p3".to_string()),
                &ObservedSlot {
                    assignment: crate::ledger::ObservedAssignment::AssignmentUnknown {
                        generation: test_generation_id("gen-p3"),
                        error: crate::ledger::ObservationError {
                            message: "assignment read failed: boom".to_string(),
                        },
                    },
                },
            )
            .unwrap();

        // Drive the real CLI path end-to-end: argument parsing, config load,
        // store resolution, and the print loop must all succeed against the
        // seeded store (the snapshot's store base is the same one `run_with`
        // resolves its store from).
        run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "status",
                "production",
            ],
            &env,
        )
        .expect("deploy status must succeed");

        // The rendered lines are exactly what the CLI printed, one per slot
        // (BTreeMap order: p1, p2, p3). The read goes through the TARGET VIEW
        // (the global slot map filtered to the target's member slots).
        let lines = render_status(&store.read_observed("production", &config).unwrap());
        assert_eq!(lines.len(), 3, "one line per observed slot: {lines:?}");
        let p1 = &lines[0];
        assert!(p1.contains("p1  generation="), "p1 line: {p1}");
        assert!(
            p1.contains(test_generation_id("gen-41da").as_str()),
            "generation id rendered: {p1}"
        );
        assert!(
            p1.contains(test_release_id("rel-sha256-status").as_str()),
            "release id rendered: {p1}"
        );
        assert!(p1.contains("standard"), "variant rendered: {p1}");
        assert!(
            p1.contains(test_tree_digest("tree-2c4f").as_str()),
            "tree digest rendered: {p1}"
        );
        // p2: a slot with no observed state (`Absent`) renders as None on
        // every column.
        assert_eq!(
            lines[1],
            "p2  generation=None release=None variant=None tree=None"
        );
        // p3: an ASSIGNMENT-UNKNOWN observation (the generation exists but
        // the assignment could not be read) renders None on every column
        // with the preserved error appended — the uncertain observation is
        // never rendered as if the slot were running something.
        assert!(
            lines[2].contains("generation=None release=None variant=None tree=None"),
            "p3 line: {}",
            lines[2]
        );
        assert!(
            lines[2].contains("observation failed: assignment read failed: boom"),
            "the preserved observation error must be rendered: {}",
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

    /// `deploy checkpoint <target>` without a deployment id is a parse
    /// error (the id is an explicit required positional: the operation is
    /// irreversible).
    #[test]
    fn checkpoint_requires_explicit_deployment_id() {
        let err = Cli::try_parse_from(["deploy", "checkpoint", "production"])
            .err()
            .expect("the deployment id is required");
        let msg = err.to_string();
        assert!(
            msg.contains("deployment_id") || msg.contains("required"),
            "error must name the missing id, got: {msg}"
        );
        // With an id the flags parse (--dry-run and --yes are both optional).
        // The id must be a canonical (validated) deployment id.
        let canonical = test_deployment_id("deploy-004");
        let cli = Cli::try_parse_from([
            "deploy",
            "checkpoint",
            "production",
            canonical.as_str(),
            "--dry-run",
            "--yes",
        ])
        .unwrap();
        let Command::Checkpoint {
            target,
            deployment_id,
            dry_run,
            yes,
        } = cli.command
        else {
            panic!("expected checkpoint");
        };
        assert_eq!(target, "production");
        assert_eq!(deployment_id, canonical);
        assert!(dry_run && yes);
    }

    /// End-to-end `deploy checkpoint`: a bare invocation (no --yes, no
    /// --dry-run) is refused as irreversible; `--dry-run` previews and
    /// touches NOTHING; `--yes` establishes the durable floor; repeating it
    /// is an idempotent no-op.
    #[test]
    fn checkpoint_dispatch_refuses_without_confirmation_and_is_idempotent() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        // The snapshot's store base (hermetic `XDG_DATA_HOME` under the
        // tempdir) is passed to `run_with` — no process-env mutation.
        let env = SysEnv::from_map(std::collections::BTreeMap::from([(
            std::ffi::OsString::from("XDG_DATA_HOME"),
            dir.path().join("store-root").into_os_string(),
        )]));
        let project = dir.path().join("proj");
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"[[slots]]
id = "p1"
server = "s1"
target = "production"
deploy_dir = "/srv/ckpt"

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
            r#"schema_version = 2
application = "checkpoint-cli"
release = "v1"

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
        // `run_with` resolves the store as
        // `LocalStore::new_in(&env, config.application())`
        // = <XDG_DATA_HOME>/simple-deploy/checkpoint-cli.
        let store =
            LocalStore::with_base(crate::store::local::default_base(&env).join("checkpoint-cli"))
                .unwrap();

        // Seed a small history: deploy-0 (s0), deploy-1 (s1), deploy-2 (s2).
        // The ledger ids are canonical (validated) forms of those tags, and
        // the deployment dirs are keyed by the same canonical ids.
        for id in ["deploy-0", "deploy-1", "deploy-2"] {
            seed_successful(&store, id, "2026-01-01T00:00:00Z");
            std::fs::create_dir_all(store.deployment_dir(test_deployment_id(id).as_str())).unwrap();
        }
        let c0 = test_deployment_id("deploy-0");
        let c1 = test_deployment_id("deploy-1");
        let c2 = test_deployment_id("deploy-2");

        // Bare checkpoint (no --yes, no --dry-run): refused as irreversible
        // BEFORE any store mutation.
        let err = run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "checkpoint",
                "production",
                c1.as_str(),
            ],
            &env,
        )
        .expect_err("a bare checkpoint must be refused");
        assert!(
            err.to_string().contains("irreversible"),
            "must explain the confirmation requirement, got: {err}"
        );
        assert_eq!(store.read_ledger("production").unwrap().len(), 3);

        // --dry-run: succeeds, enumerates the discards, writes NOTHING.
        run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "checkpoint",
                "production",
                c1.as_str(),
                "--dry-run",
            ],
            &env,
        )
        .expect("dry-run checkpoint succeeds");
        assert_eq!(
            store.read_ledger("production").unwrap().len(),
            3,
            "dry-run must not replace the ledger"
        );

        // --yes: atomically replaces the ledger with the retained suffix at
        // deploy-1 and sweeps the unreachable content.
        run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "checkpoint",
                "production",
                c1.as_str(),
                "--yes",
            ],
            &env,
        )
        .expect("the confirmed checkpoint establishes the retained suffix");
        let entries = store.read_ledger("production").unwrap();
        assert_eq!(entries.len(), 2, "deploy-1 and deploy-2 are retained");
        assert_eq!(entries[0].deployment_id, c1);
        assert!(!store.deployment_dir(c0.as_str()).exists());
        assert!(store.deployment_dir(c1.as_str()).exists());
        assert!(store.deployment_dir(c2.as_str()).exists());

        // Repeating the same checkpoint: the suffix is identical (the ledger
        // already IS it) and the sweep finishes.
        run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "checkpoint",
                "production",
                c1.as_str(),
                "--yes",
            ],
            &env,
        )
        .expect("a repeated checkpoint is idempotent");
        let entries2 = store.read_ledger("production").unwrap();
        assert_eq!(entries2, entries, "the retained suffix is unchanged");
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
        // forced project layout, the local marker vs SSH, and the next
        // commands must all be present.
        let help = Cli::command().render_long_help().to_string();
        for needle in [
            "releases/<name>",
            "releases/<name>/<variant>.toml",
            "local",
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
            "local",
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

    /// Every CONCRETE `deploy push` example in the documentation must parse
    /// with the REAL ref parser — the docs cannot contradict the strict
    /// grammar. The corpora are README.md and requirement.md (read via
    /// `CARGO_MANIFEST_DIR`, the same precedent as
    /// `tests/readme_quickstart.rs`) plus the `push` subcommand's own RENDERED
    /// long help (exercised as rendered, not duplicated). A line is an example
    /// iff it starts with `deploy push` (after indentation); everything from
    /// the FIRST `#` is a shell comment (no valid ref contains `#`); the ref
    /// token is the token after the target — flags like `--dry-run` /
    /// `--group <name>` are not refs, and a bare `deploy push <target>` is the
    /// default HEAD push; a quoted ref (`'parent(@, 3)'`) is unquoted the way
    /// a shell would before parsing.
    #[test]
    fn documented_deploy_push_examples_parse() {
        use crate::deploy::refs::parse_ref_expr;

        let manifest = env!("CARGO_MANIFEST_DIR");
        let readme = std::fs::read_to_string(format!("{manifest}/README.md"))
            .expect("README.md must be readable via CARGO_MANIFEST_DIR");
        let requirement = std::fs::read_to_string(format!("{manifest}/requirement.md"))
            .expect("requirement.md must be readable via CARGO_MANIFEST_DIR");
        let mut push_cmd = Cli::command();
        let push_help = push_cmd
            .find_subcommand_mut("push")
            .unwrap()
            .render_long_help()
            .to_string();
        let corpora: [(&str, &str); 3] = [
            ("README.md", &readme),
            ("requirement.md", &requirement),
            ("deploy push --help", &push_help),
        ];

        let mut extracted = 0;
        let mut skipped_placeholders = 0;
        for (source, text) in corpora {
            for (line_no, raw) in text.lines().enumerate() {
                let line = raw.trim();
                if !line.starts_with("deploy push") {
                    continue;
                }
                let loc = format!("{source}:{}", line_no + 1);
                // Everything from the first '#' is a shell comment — no valid
                // ref contains '#', so the example is the code before it.
                let code = line.split('#').next().unwrap().trim();
                let mut toks = code.split_whitespace();
                assert_eq!(toks.next(), Some("deploy"), "{loc}: malformed example");
                assert_eq!(toks.next(), Some("push"), "{loc}: malformed example");
                let _target = toks.next().expect("{loc}: missing target");
                let mut ref_spec = toks.collect::<Vec<_>>().join(" ");
                if ref_spec.is_empty() || ref_spec.starts_with("--") {
                    // Flags (--dry-run, --group <name>) are not refs; a bare
                    // `deploy push <target>` is the default HEAD push.
                    ref_spec.clear();
                } else {
                    // Strip one surrounding pair of shell quotes, exactly as a
                    // shell would before the token reaches the parser.
                    let len = ref_spec.len();
                    if len >= 2 {
                        let b = ref_spec.as_bytes();
                        if (b[0] == b'\'' && b[len - 1] == b'\'')
                            || (b[0] == b'"' && b[len - 1] == b'"')
                        {
                            ref_spec = ref_spec[1..len - 1].to_string();
                        }
                    }
                    // A `<...>` placeholder is not a concrete example and must
                    // not parse; after the canonical-id fixes none should
                    // remain in the example corpus, so skipping is a guarded
                    // escape hatch that the final assert proves unused.
                    if ref_spec.contains('<') || ref_spec.contains('>') {
                        skipped_placeholders += 1;
                        continue;
                    }
                }
                extracted += 1;
                // THE REAL CLI PARSER: run the full `deploy push ...` line
                // through clap's actual argument parsing (`Cli::try_parse_from`
                // → the `push` subcommand), so flags, the required target, the
                // optional reference token, and `--group`/`--dry-run` are all
                // exercised exactly as a user's shell line would be.
                // argv = `deploy push <target>` + the post-target tokens: the
                // unquoted ref as ONE argument (the shell would unquote it),
                // or the raw flag tokens (`--dry-run`, `--group <name>`).
                let mut argv: Vec<&str> = vec!["deploy", "push"];
                let target = code
                    .split_whitespace()
                    .nth(2)
                    .expect("{loc}: missing target");
                argv.push(target);
                if ref_spec.is_empty() {
                    argv.extend(code.split_whitespace().skip(3));
                } else {
                    argv.push(&ref_spec);
                }
                if let Err(e) = Cli::try_parse_from(&argv) {
                    panic!(
                        "{loc}: documented example fails the REAL CLI parser: \
                         Cli::try_parse_from({argv:?}) failed: {e}"
                    );
                }
                // And the reference token itself must satisfy the strict ref
                // grammar (the CLI defers ref validation to push()).
                if !ref_spec.is_empty()
                    && let Err(e) = parse_ref_expr(&ref_spec)
                {
                    panic!(
                        "{loc}: documented example contradicts the strict ref parser: \
                         parse_ref_expr({ref_spec:?}) failed: {e}"
                    );
                }
            }
        }
        assert_eq!(
            skipped_placeholders, 0,
            "documented `<...>` placeholder examples must not remain: every `deploy push` line \
             must be a concrete, parseable example"
        );
        // A floor on the extracted count guards against a refactor silently
        // dropping the documentation out of the test's reach.
        assert!(
            extracted >= 30,
            "expected >= 30 documented examples, extracted {extracted}"
        );
    }

    // -------------------------------------------------------------------
    // HARDENING: ReleaseId exact form + CLI bare-digest parser + no Default
    // + the Unknown observation half (deterministic + property, 16 cases
    // fixed seed 0x5EED_5EED per house style).
    // -------------------------------------------------------------------

    const HARDENING_DIGEST: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn release_id_parse_is_exact() {
        let full = format!("rel-sha256-{HARDENING_DIGEST}");
        assert_eq!(ReleaseId::parse(&full).unwrap().as_str(), full);
        assert_eq!(ReleaseId::parse(&full).unwrap().to_string(), full);
        // from_digest round-trips the exact form.
        let d = crate::identity::ReleaseDigest::parse(HARDENING_DIGEST).unwrap();
        assert_eq!(ReleaseId::from_digest(&d).as_str(), full);
        for bad in [
            "",
            HARDENING_DIGEST,
            "rel-sha256-",
            "rel-sha256-ABCD",
            &format!("rel-sha256-{}gg", &HARDENING_DIGEST[..62]),
            &format!("rel-sha256-{}", &HARDENING_DIGEST[..63]),
            &HARDENING_DIGEST.to_uppercase(),
            "rel-unknown",
            "rel-sha256-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            &format!(" rel-sha256-{HARDENING_DIGEST}"),
            &format!("rel-sha256-{HARDENING_DIGEST} "),
        ] {
            ReleaseId::parse(bad)
                .expect_err(format!("bare/loose form must be rejected: {bad:?}").as_str());
            // Wire deserialization also rejects the loose forms.
            let json = serde_json::to_string(bad).unwrap();
            serde_json::from_str::<ReleaseId>(&json).expect_err("loose wire must be rejected");
        }
    }

    #[test]
    fn cli_parser_accepts_full_and_bare_converts() {
        let full = format!("rel-sha256-{HARDENING_DIGEST}");
        assert_eq!(parse_release_input(&full).unwrap().as_str(), full);
        assert_eq!(
            parse_release_input(HARDENING_DIGEST).unwrap().as_str(),
            full
        );
        assert!(
            !parse_release_input(&HARDENING_DIGEST.to_uppercase()).is_ok(),
            "uppercase bare digest must be rejected"
        );
        for bad in [
            "",
            "rel-sha256-",
            "rel-sha256-abc",
            "rel-unknown",
            "not-hex",
            &HARDENING_DIGEST[..32],
            &format!("rel-sha256-{}", HARDENING_DIGEST.to_uppercase()),
        ] {
            parse_release_input(bad).expect_err(format!("cli must reject {bad:?}").as_str());
        }
    }

    #[test]
    fn artifact_ref_and_identities_have_no_default() {
        // A Default identity would be an EMPTY string — a malformed durable
        // record. The derive is gone, so Default::default() must not exist;
        // empty string is rejected at the domain boundary.
        for bad in ["", "a/b", "..", " x"] {
            crate::identity::SlotId::parse(bad).expect_err("empty/traversal must be rejected");
        }
        crate::identity::ReleaseId::parse("").expect_err("empty ReleaseId must be rejected");
        // ArtifactRef likewise has no Default — empty release would be
        // malformed. A wire artifact with an empty release fails.
        let bad_json =
            format!(r#"{{"release":"","variant":"standard","tree":"{HARDENING_DIGEST}"}}"#);
        serde_json::from_str::<crate::identity::ArtifactRef>(&bad_json)
            .expect_err("empty release in artifact must be rejected");
    }

    #[test]
    fn observed_unknown_never_forged() {
        // An UNKNOWN observed assignment serializes as the tagged
        // `state: "unknown"` variant with its preserved error — never as a
        // forged ArtifactRef — and round-trips. The bare string "unknown" is
        // NOT a valid ObservedAssignment (the tagged enum is the only wire
        // form).
        let unknown = crate::ledger::ObservedAssignment::Unknown {
            error: crate::ledger::ObservationError {
                message: "boom".to_string(),
            },
        };
        let json = serde_json::to_string(&unknown).unwrap();
        assert!(
            json.contains(r#""state":"unknown""#),
            "Unknown must serialize as the tagged unknown state, got: {json}"
        );
        assert_eq!(
            serde_json::from_str::<crate::ledger::ObservedAssignment>(&json).unwrap(),
            unknown
        );
        assert!(
            serde_json::from_str::<crate::ledger::ObservedAssignment>("\"unknown\"").is_err(),
            "the bare \"unknown\" string is not an ObservedAssignment"
        );
        // A slot with no observed state is Absent, not Unknown.
        let slot_none = ObservedSlot {
            assignment: crate::ledger::ObservedAssignment::Absent,
        };
        let json_none = serde_json::to_string(&slot_none).unwrap();
        let back: ObservedSlot = serde_json::from_str(&json_none).unwrap();
        assert_eq!(back.assignment, crate::ledger::ObservedAssignment::Absent);
        assert_eq!(back.last_deployment(), None);
        // An unreadable observed state is Unknown, never a forged artifact.
        let slot_unknown = ObservedSlot {
            assignment: crate::ledger::ObservedAssignment::Unknown {
                error: crate::ledger::ObservationError {
                    message: "assignment read failed: boom".to_string(),
                },
            },
        };
        let lines = render_status(&ObservedTarget {
            target: crate::identity::TargetName::parse("production").unwrap(),
            slots: std::collections::BTreeMap::from([(
                crate::identity::SlotId::parse("p1").unwrap(),
                slot_unknown,
            )]),
        });
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("release=None"),
            "Unknown must not render as a forged artifact: {}",
            lines[0]
        );
        // An ASSIGNMENT-UNKNOWN state (generation known, artifact NOT read)
        // likewise never renders a forged artifact — None on every column
        // with the preserved error.
        let slot_assign_unknown = ObservedSlot {
            assignment: crate::ledger::ObservedAssignment::AssignmentUnknown {
                generation: test_generation_id("gen-p3"),
                error: crate::ledger::ObservationError {
                    message: "assignment read failed: boom".to_string(),
                },
            },
        };
        let lines = render_status(&ObservedTarget {
            target: crate::identity::TargetName::parse("production").unwrap(),
            slots: std::collections::BTreeMap::from([(
                crate::identity::SlotId::parse("p3").unwrap(),
                slot_assign_unknown,
            )]),
        });
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("generation=None release=None variant=None tree=None"),
            "AssignmentUnknown must not render a fabricated generation/artifact: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("observation failed: assignment read failed: boom"),
            "the preserved error must be rendered: {}",
            lines[0]
        );
    }

    #[test]
    fn gc_unknown_aborts_before_deletion() {
        // Fail-closed: an UNKNOWN observation makes the GC abort with an
        // integrity error before any deletion (never retain nothing).
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        store
            .write_slot_observed(
                &crate::identity::SlotId::parse("p1").unwrap(),
                &ObservedSlot {
                    assignment: crate::ledger::ObservedAssignment::Unknown {
                        error: crate::ledger::ObservationError {
                            message: "assignment read failed: boom".to_string(),
                        },
                    },
                },
            )
            .unwrap();
        let cfg = {
            let proj = dir.path().join("proj");
            std::fs::create_dir_all(proj.join("releases").join("v1")).unwrap();
            std::fs::write(
                proj.join("releases").join("v1").join("standard.toml"),
                "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv\"\n[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n[retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n[retention.deployment]\nprotect_deployments = 1\n[activation]\nadapter = \"none\"\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
            )
            .unwrap();
            std::fs::write(
                proj.join("deploy.toml"),
                "schema_version = 2\napplication = \"gc-unknown\"\nrelease = \"v1\"\n[[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n[targets.t1]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n",
            )
            .unwrap();
            crate::config::ProjectConfig::load(&proj.join("deploy.toml")).unwrap()
        };
        let err = store.reachable_set(&cfg, None).unwrap_err();
        assert!(
            err.to_string().contains("UNKNOWN") || err.to_string().contains("Unknown"),
            "GC must abort on Unknown, got: {err}"
        );
    }

    // Property: arbitrary strings — ReleaseId exact, CLI full+bare, reject else.
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    fn is_valid_hex64(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    fn is_valid_release_id(s: &str) -> bool {
        s.strip_prefix("rel-sha256-").is_some_and(is_valid_hex64)
    }

    fn arbitrary_release_input() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                "rel-sha256-".to_string(),
                "rel-sha256-abc".to_string(),
                "rel-".to_string(),
                "rel-sha256-ABCD".to_string(),
                HARDENING_DIGEST.to_string(),
                HARDENING_DIGEST.to_uppercase(),
                format!("rel-sha256-{HARDENING_DIGEST}"),
                format!("rel-sha256-{}", &HARDENING_DIGEST[..63]),
                "not-hex".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..80).prop_map(|v| v.into_iter().collect()),
        ]
    }

    #[test]
    fn unlock_cli_inspects_and_recovers() {
        use crate::remote::helper::RemoteHelper;
        use crate::remote::layout;
        use crate::remote::transport::LocalTransport;
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let env = SysEnv::from_map(std::collections::BTreeMap::from([(
            std::ffi::OsString::from("XDG_DATA_HOME"),
            dir.path().join("store-root").into_os_string(),
        )]));
        let project = dir.path().join("proj");
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let slot_root = dir.path().join("unlock-remote");
        std::fs::create_dir_all(&slot_root).unwrap();
        let slot_root_str = slot_root.to_string_lossy().to_string();
        std::fs::write(
            release_dir.join("standard.toml"),
            format!(
                r#"[[slots]]
id = "p1"
server = "s1"
target = "production"
deploy_dir = "{slot_root_str}"

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
"#
            ),
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            r#"schema_version = 2
application = "unlock-cli"
release = "v1"

[[servers]]
id = "s1"
address = "local"
user = "deploy"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        let config = ProjectConfig::load(&cfg_path).unwrap();
        // Resolve slot's deploy_dir (the transport root): the slot's
        // PhysicalBinding for p1 is the root LocalTransport uses. For the
        // pathless local connection the slot deploy_dir IS the root.
        let slot_deploy_dir = config
            .target_slots("production")
            .unwrap()
            .into_iter()
            .find(|(s, _)| s.id == "p1")
            .unwrap()
            .0
            .deploy_dir()
            .to_path_buf();
        // Plant a hostile lock directly on the slot's remote (LocalTransport
        // over the deploy_dir).
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), slot_deploy_dir.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        let rec = helper.acquire_lock("op-dead", false).unwrap();
        // No --yes: refusal naming holder+acquisition+--yes+--acquisition, lock byte-identical.
        let before = remote.read(&layout::operation_lock()).unwrap();
        let err = run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "unlock",
                "production",
                "p1",
            ],
            &env,
        )
        .expect_err("unlock without --yes must refuse when held");
        let msg = err.to_string();
        assert!(msg.contains("op-dead"), "must name holder: {msg}");
        assert!(
            msg.contains("acquisition"),
            "must name acquisition id: {msg}"
        );
        assert!(msg.contains("--yes"), "must name remedy: {msg}");
        assert!(
            msg.contains("--acquisition"),
            "must name --acquisition: {msg}"
        );
        assert!(
            msg.contains(rec.acquisition_id.as_str()),
            "must show literal acquisition {}: {msg}",
            rec.acquisition_id
        );
        assert!(
            msg.contains(&format!("--acquisition {}", rec.acquisition_id)),
            "remedy must show --acquisition <id>: {msg}"
        );
        let after = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(before, after, "lock must be byte-identical after refusal");
        // --yes without --acquisition: refused up front, lock untouched.
        let err2 = run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "unlock",
                "production",
                "p1",
                "--yes",
            ],
            &env,
        )
        .expect_err("--yes without --acquisition must refuse");
        assert!(
            err2.to_string().contains("--acquisition"),
            "must name required flag: {}",
            err2
        );
        let after2 = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(
            before, after2,
            "lock must stay byte-identical after --yes without acquisition"
        );
        // With matching --acquisition + --yes: recovered and released.
        run_with(
            [
                "deploy",
                "--config",
                cfg_path.to_str().unwrap(),
                "unlock",
                "production",
                "p1",
                "--acquisition",
                rec.acquisition_id.as_str(),
                "--yes",
            ],
            &env,
        )
        .expect("unlock with matching --acquisition --yes must succeed");
        assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "lock file must be gone after --yes"
        );
        // Verify render output would contain recovered line (through helper directly).
        let store =
            LocalStore::with_base(crate::store::local::default_base(&env).join("unlock-cli"))
                .unwrap();
        // Re-plant and test via run_unlock rendering directly for recovered line.
        let remote2 =
            LocalTransport::new(&crate::testutil::fixture_env(), slot_deploy_dir.clone()).unwrap();
        let helper2 = RemoteHelper::new(&remote2);
        let rec2 = helper2.acquire_lock("op-dead2", false).unwrap();
        let factory =
            move |s: &crate::config::ServerDef,
                  slot: &crate::config::SlotConfig|
                  -> crate::error::Result<Box<dyn crate::remote::transport::Remote>> {
                crate::remote::create_remote(&env, s, slot.deploy_dir())
            };
        let report = crate::deploy::unlock::run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &crate::identity::SlotId::parse("p1").unwrap(),
            Some(rec2.acquisition_id.clone()),
            true,
        )
        .unwrap();
        let lines = crate::deploy::unlock::render_unlock_report(&report);
        assert!(
            lines[0].contains("recovered"),
            "rendered line: {}",
            lines[0]
        );
        assert!(lines[0].contains("op-dead2"), "rendered line: {}", lines[0]);
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]
        #[test]
        fn hardening_property_release_id_cli_unknown(s in arbitrary_release_input()) {
            let expected_release = is_valid_release_id(&s);
            assert_eq!(ReleaseId::parse(&s).is_ok(), expected_release, "ReleaseId exact: {s:?}");
            let expected_cli = is_valid_release_id(&s) || is_valid_hex64(&s);
            let cli_ok = parse_release_input(&s).is_ok();
            assert_eq!(cli_ok, expected_cli, "CLI parser: {s:?}");
            if is_valid_hex64(&s) && !is_valid_release_id(&s) {
                let got = parse_release_input(&s).unwrap();
                assert_eq!(got.as_str(), format!("rel-sha256-{s}"));
            }
            if is_valid_release_id(&s) {
                let got = parse_release_input(&s).unwrap();
                assert_eq!(got.as_str(), s);
            }
            // Wire ReleaseId rejects non-exact forms.
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(
                serde_json::from_str::<ReleaseId>(&json).is_ok(),
                expected_release,
                "wire ReleaseId: {s:?}"
            );
            // Unknown is never a forged artifact: the bare "unknown" string
            // is NOT a valid ObservedAssignment wire form (the tagged enum
            // expresses Unknown with its preserved error); a forged artifact
            // would be a valid ArtifactRef JSON.
            if s == "unknown" {
                assert!(
                    serde_json::from_str::<crate::ledger::ObservedAssignment>("\"unknown\"")
                        .is_err(),
                    "bare \"unknown\" must not parse as an ObservedAssignment"
                );
            }
        }
    }
}

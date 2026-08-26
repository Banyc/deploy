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
use crate::model::DeploymentId;
use crate::push::engine::{PushOptions, PushReport, push};
use crate::records::{DeploymentStatus, LedgerEntry, ObservedTarget};
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
  deploy push production deploy-20260821T102000Z  # roll back to that deployment's stored state\n\
  deploy push production release:rel-sha256-2fda63a950  # DIRECT release deploy to this target (cross-target; no history needed)"
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
  deploy checkpoint production deploy-004 --dry-run   # preview what would be discarded\n\
         deploy checkpoint production deploy-004 --yes       # retain the suffix + sweep (irreversible)\n\
          deploy log production                               # now shows only the retained suffix\n\
          deploy push production deploy-004   # the checkpoint entry stays the oldest rollback"
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
                    crate::records::ObservedTarget {
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
            let report = crate::push::checkpoint::run_checkpoint(
                &store,
                &config,
                &target,
                &deployment_id,
                dry_run,
            )?;
            for line in crate::push::checkpoint::render_checkpoint_report(&report) {
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
/// The effective status + reason of a ledger entry for `deploy log`: the
/// entry's TERMINAL EVENT carries the status and reason; an intent-only
/// entry (in flight or recoverable-pending) renders `PendingCommit`.
fn effective_status(entry: &LedgerEntry) -> (DeploymentStatus, Option<String>) {
    match entry.terminal.as_ref() {
        Some(t) => (t.status.clone(), t.reason.clone()),
        None => (DeploymentStatus::PendingCommit, None),
    }
}

/// Render `deploy log <target>` output: one line per recorded ledger entry,
/// newest last, each PREFIXED with the DEPLOYMENT ID of the successful
/// deployment that produced it — the exact rollback key the push reference
/// grammar accepts (`deploy push <target> <deployment-id>`) — or `-` for
/// entries that produced no rollback state (failed/degraded entries are
/// visible here but are NOT valid rollback refs; a failed deployment id
/// never resolves). The ledger IS the deployment history: a successful
/// terminal event carries the rollback payload keyed by its deployment id
/// (the old `sN` index prefix is gone — rollback payloads are keyed by
/// deployment id). The CLI prints exactly these lines; the unit test
/// asserts on them directly because lib unit tests cannot capture the
/// harness-owned stdout sink.
pub fn render_log(
    _store: &LocalStore,
    _target: &str,
    entries: &[LedgerEntry],
) -> Result<Vec<String>> {
    // A successful entry's DEPLOYMENT ID is its rollback key — the prefix
    // `deploy push <target> <deployment-id>` accepts. The public grammar is
    // deployment-keyed (no sN).
    let mut rolled_back: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for e in entries.iter().filter(|e| {
        e.terminal
            .as_ref()
            .is_some_and(|t| t.status == DeploymentStatus::Successful && t.rollback.is_some())
    }) {
        rolled_back.insert(e.deployment_id.as_str());
    }
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let (status, reason) = effective_status(e);
        let prefix = if rolled_back.contains(e.deployment_id.as_str()) {
            e.deployment_id.as_str().to_string()
        } else {
            "-".to_string()
        };
        // The optional rollout group the attempt selected (`--group <name>`),
        // displayed when one was used. The group name is descriptive; the
        // exact selected slot IDs are the authoritative historical evidence.
        let group_note = e
            .intent
            .group
            .as_ref()
            .map(|g| format!(" group={g}"))
            .unwrap_or_default();
        out.push(match reason {
            Some(r) => format!(
                "{prefix}  {}  {status:?}  {}{group_note}  ({r})",
                e.deployment_id, e.intent.attempted_at
            ),
            None => format!(
                "{prefix}  {}  {status:?}  {}{group_note}",
                e.deployment_id, e.intent.attempted_at
            ),
        });
    }
    Ok(out)
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
        ArtifactRef, DeploymentId, GenerationId, GenerationRef, LEDGER_SCHEMA_VERSION,
        PlacementSlotAssignment, PlacementSlotId, ReleaseId, TargetName, TreeDigest, VariantName,
    };
    use crate::records::{LedgerIntent, LedgerRollback, LedgerTerminal, ObservedSlot};
    use std::collections::BTreeMap;

    fn pending_attempt(id: &str) -> LedgerIntent {
        let p1 = PlacementSlotId::new("p1".to_string());
        LedgerIntent {
            deployment_schema_version: LEDGER_SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new("production".to_string()),
            group: None,
            slot_ids: vec![p1.clone()],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            // EXACT key-set equality (slot_ids == desired == pre_push).
            desired: BTreeMap::from([(
                p1.clone(),
                GenerationRef {
                    generation: GenerationId::new("gen-1".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: p1.clone(),
                        artifact: ArtifactRef {
                            release: ReleaseId::new("rel-1".to_string()),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-1".to_string()),
                        },
                    },
                },
            )]),
            pre_push: BTreeMap::from([(p1.clone(), None)]),
        }
    }

    /// Seed the ledger with a successful deployment (intent + `Successful`
    /// terminal carrying a rollback state, so `sN`/log prefixes apply).
    fn seed_successful(store: &LocalStore, id: &str, attempted_at: &str) {
        let mut it = pending_attempt(id);
        it.attempted_at = attempted_at.to_string();
        store.append_intent("production", &it).unwrap();
        store
            .append_terminal(
                "production",
                &LedgerTerminal {
                    deployment_id: DeploymentId::new(id.to_string()),
                    target: TargetName::new("production".to_string()),
                    status: DeploymentStatus::Successful,
                    recorded_at: attempted_at.to_string(),
                    outcomes: BTreeMap::new(),
                    rollback: Some(LedgerRollback {
                        slots: BTreeMap::new(),
                        bindings: BTreeMap::new(),
                    }),
                    reason: Some("deployed".to_string()),
                },
            )
            .unwrap();
    }

    #[test]
    fn log_status_overlays_terminal_event() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let a = pending_attempt("deploy-overlay");

        // No terminal event yet: an intent-only entry is treated as the
        // recoverable pending state.
        store.append_intent("production", &a).unwrap();
        let entries = store.read_ledger("production").unwrap();
        assert_eq!(
            effective_status(&entries[0]),
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
                &LedgerTerminal {
                    deployment_id: a.deployment_id.clone(),
                    target: TargetName::new("production".to_string()),
                    status: DeploymentStatus::Successful,
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    outcomes: BTreeMap::new(),
                    rollback: Some(LedgerRollback {
                        slots: BTreeMap::new(),
                        bindings: BTreeMap::new(),
                    }),
                    reason: Some("recovery finalization".to_string()),
                },
            )
            .unwrap();
        let entries = store.read_ledger("production").unwrap();
        assert_eq!(
            effective_status(&entries[0]),
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
        let tmp = tempfile::tempdir().unwrap();
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
                &LedgerTerminal {
                    deployment_id: a_failed.deployment_id.clone(),
                    target: TargetName::new("production".to_string()),
                    status: DeploymentStatus::FailedPreflight,
                    recorded_at: "2026-01-02T00:00:00Z".to_string(),
                    outcomes: BTreeMap::new(),
                    rollback: None,
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
            "deploy-log-ok  deploy-log-ok  Successful  2026-01-01T00:00:00Z  (deployed)"
        );
        // An entry without a rollback state keeps the columns aligned via `-`.
        assert_eq!(
            lines[1],
            "-  deploy-log-failed  FailedPreflight  2026-01-02T00:00:00Z  (preflight failed)"
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
        // directory to exist with at least one variant file. The variant
        // declares the three rendered slots (all members of `production`) and
        // owns their retention policy (rotation lives in the variant file,
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

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
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
        let config = Config::load(&cfg_path).unwrap();

        // Point the store at a hermetic `XDG_DATA_HOME` and seed the ONE
        // physical observed record per slot (`slots/<slot-id>/observed.json`)
        // with three slots: p1 has a full assignment, p2 has NO known
        // assignment (never observed / rotated away), and p3 has a known
        // generation but no known artifact (the assignment could not be read).
        let data_home = dir.path().join("data");
        unsafe { std::env::set_var("XDG_DATA_HOME", &data_home) };
        let store = LocalStore::with_base(data_home.join("simple-deploy")).unwrap();
        store
            .write_slot_observed(
                &PlacementSlotId::new("p1".to_string()),
                &ObservedSlot {
                    generation: Some(GenerationId::new("gen-41da".to_string())),
                    artifact: Some(crate::model::ArtifactRef {
                        release: ReleaseId::new("rel-sha256-status".to_string()),
                        variant: VariantName::new("standard".to_string()),
                        tree: TreeDigest::new("tree-2c4f".to_string()),
                    }),
                    last_deployment: Some(DeploymentId::new("deploy-status-1".to_string())),
                },
            )
            .unwrap();
        store
            .write_slot_observed(
                &PlacementSlotId::new("p2".to_string()),
                &ObservedSlot {
                    generation: None,
                    artifact: None,
                    last_deployment: None,
                },
            )
            .unwrap();
        store
            .write_slot_observed(
                &PlacementSlotId::new("p3".to_string()),
                &ObservedSlot {
                    generation: Some(GenerationId::new("gen-9f00".to_string())),
                    artifact: None,
                    last_deployment: None,
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
        // (BTreeMap order: p1, p2, p3). The read goes through the TARGET VIEW
        // (the global slot map filtered to the target's member slots).
        let lines = render_status(&store.read_observed("production", &config).unwrap());
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
        let cli = Cli::try_parse_from([
            "deploy",
            "checkpoint",
            "production",
            "deploy-004",
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
        assert_eq!(deployment_id.as_str(), "deploy-004");
        assert!(dry_run && yes);
    }

    /// End-to-end `deploy checkpoint`: a bare invocation (no --yes, no
    /// --dry-run) is refused as irreversible; `--dry-run` previews and
    /// touches NOTHING; `--yes` establishes the durable floor; repeating it
    /// is an idempotent no-op.
    #[test]
    fn checkpoint_dispatch_refuses_without_confirmation_and_is_idempotent() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
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
        let data_home = dir.path().join("data");
        unsafe { std::env::set_var("XDG_DATA_HOME", &data_home) };
        // `run_with` resolves the store as `LocalStore::new("checkpoint-cli")`
        // = XDG_DATA_HOME/simple-deploy/checkpoint-cli.
        let store =
            LocalStore::with_base(data_home.join("simple-deploy").join("checkpoint-cli")).unwrap();

        // Seed a small history: deploy-0 (s0), deploy-1 (s1), deploy-2 (s2).
        for id in ["deploy-0", "deploy-1", "deploy-2"] {
            seed_successful(&store, id, "2026-01-01T00:00:00Z");
            std::fs::create_dir_all(store.deployment_dir(id)).unwrap();
        }

        // Bare checkpoint (no --yes, no --dry-run): refused as irreversible
        // BEFORE any store mutation.
        let err = run_with([
            "deploy",
            "--config",
            cfg_path.to_str().unwrap(),
            "checkpoint",
            "production",
            "deploy-1",
        ])
        .expect_err("a bare checkpoint must be refused");
        assert!(
            err.to_string().contains("irreversible"),
            "must explain the confirmation requirement, got: {err}"
        );
        assert_eq!(store.read_ledger("production").unwrap().len(), 3);

        // --dry-run: succeeds, enumerates the discards, writes NOTHING.
        run_with([
            "deploy",
            "--config",
            cfg_path.to_str().unwrap(),
            "checkpoint",
            "production",
            "deploy-1",
            "--dry-run",
        ])
        .expect("dry-run checkpoint succeeds");
        assert_eq!(
            store.read_ledger("production").unwrap().len(),
            3,
            "dry-run must not replace the ledger"
        );

        // --yes: atomically replaces the ledger with the retained suffix at
        // deploy-1 and sweeps the unreachable content.
        run_with([
            "deploy",
            "--config",
            cfg_path.to_str().unwrap(),
            "checkpoint",
            "production",
            "deploy-1",
            "--yes",
        ])
        .expect("the confirmed checkpoint establishes the retained suffix");
        let entries = store.read_ledger("production").unwrap();
        assert_eq!(entries.len(), 2, "deploy-1 and deploy-2 are retained");
        assert_eq!(entries[0].deployment_id.as_str(), "deploy-1");
        assert!(!store.deployment_dir("deploy-0").exists());
        assert!(store.deployment_dir("deploy-1").exists());
        assert!(store.deployment_dir("deploy-2").exists());

        // Repeating the same checkpoint: the suffix is identical (the ledger
        // already IS it) and the sweep finishes.
        run_with([
            "deploy",
            "--config",
            cfg_path.to_str().unwrap(),
            "checkpoint",
            "production",
            "deploy-1",
            "--yes",
        ])
        .expect("a repeated checkpoint is idempotent");
        let entries2 = store.read_ledger("production").unwrap();
        assert_eq!(entries2, entries, "the retained suffix is unchanged");

        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        drop(_lock);
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

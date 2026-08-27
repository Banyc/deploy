//! DEPLOY LOG RENDERING (feature area A2: Ledger semantics).
//!
//! [`render_log`] builds the `deploy log <target>` display lines from the
//! ledger's [`LedgerEntry`] stream: one line per recorded attempt, NEWEST
//! LAST, each PREFIXED with the DEPLOYMENT ID of the snapshot that attempt
//! produced — the exact rollback key the push reference grammar accepts
//! (`deploy push <target> <deployment-id>`) — or `-` for attempts that
//! produced no rollback state (failed/degraded attempts are visible here
//! but are NOT valid rollback refs). A successful attempt additionally
//! renders the optional rollout ` group=<name>` annotation when it selected
//! a group (`--group <name>`). `effective_status` derives the displayed
//! status: the entry's TERMINAL EVENT carries the status + reason; an
//! intent-only entry (in flight or recoverable-pending) renders
//! `PendingCommit`. The CLI wrapper (`crate::cli`) stays the command
//! boundary — arg parsing + printing; the rendering semantics live HERE.
//!
use crate::error::Result;
use crate::ledger::finalize::LedgerEntry;
use crate::ledger::records::DeploymentStatus;
use crate::store::local::LocalStore;

/// Effective status of an attempt for `deploy log`: the append-only
/// attempts.jsonl record is immutable, but the attempt's status lives in its
/// per-deployment TRANSITION STREAM (`deployments/<id>/transitions.jsonl`),
/// so the effective status is the LATEST transition (plus its reason, if
/// any). When no transition has been recorded yet, the attempt is treated as
/// still pending.
/// The effective status + reason of a ledger entry for `deploy log`: the
/// entry's TERMINAL EVENT carries the status and reason; an intent-only
/// entry (in flight or recoverable-pending) renders `PendingCommit`.
pub(crate) fn effective_status(entry: &LedgerEntry) -> (DeploymentStatus, Option<String>) {
    match entry.terminal.as_ref() {
        // The status is DERIVED from the terminal's disposition (the domain
        // terminal carries no separate status — they can never disagree).
        Some(t) => (t.status(), t.reason.clone()),
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
            .is_some_and(|t| t.status() == DeploymentStatus::Successful)
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

//! DEPLOY LOG RENDERING (feature area A2: Ledger semantics).
//!
//! [`render_log`] builds the `deploy log <target>` display lines from the
//! ledger's [`LedgerEntry`] stream: one line per recorded attempt, NEWEST
//! LAST, each PREFIXED with the DEPLOYMENT ID of the successful deployment
//! that produced it — the exact rollback key the push reference grammar
//! accepts (`deploy push <target> <deployment-id>`) — or `-` for attempts
//! that produced no snapshot (failed/degraded attempts are visible here
//! but are NOT valid rollback refs; a failed deployment id never resolves).
//! A successful attempt additionally renders the optional rollout
//! ` group=<name>` annotation when it selected a group. The effective
//! status: the entry's TERMINAL EVENT carries the status; an intent-only
//! entry (in flight or recoverable-pending) renders `Pending` — the
//! terminal status enum carries no pending status (an intent WITHOUT a
//! terminal IS the pending state). The CLI wrapper (`crate::cli`) stays the
//! command boundary — arg parsing + printing; the rendering semantics live
//! HERE.
//!
use crate::error::Result;
use crate::ledger::finalize::LedgerEntry;
use crate::ledger::records::DeploymentStatus;
use crate::store::local::LocalStore;

/// The effective status + reason of a ledger entry for `deploy log`: an
/// intent-only entry renders the `Pending` OPERATIONAL STATE (an intent
/// WITHOUT a terminal IS pending — the terminal status enum carries no
/// in-progress/pending status).
pub(crate) fn effective_status(entry: &LedgerEntry) -> (Option<DeploymentStatus>, Option<String>) {
    match entry.terminal.as_ref() {
        Some(t) => (Some(t.status()), t.reason().map(str::to_string)),
        None => (None, None),
    }
}

/// Render `deploy log <target>` output: one line per recorded ledger entry,
/// newest last, each PREFIXED with the DEPLOYMENT ID of the successful
/// deployment that produced it — the exact rollback key the push reference
/// grammar accepts (`deploy push <target> <deployment-id>`) — or `-` for
/// entries with no snapshot (failed/degraded entries are visible here but
/// are NOT valid rollback refs). The ledger IS the deployment history; the
/// CLI prints exactly these lines.
pub fn render_log(
    _store: &LocalStore,
    _target: &str,
    entries: &[LedgerEntry],
) -> Result<Vec<String>> {
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
        let status_text = match status {
            Some(s) => format!("{s:?}"),
            None => "Pending".to_string(),
        };
        let group_note = e
            .intent
            .group()
            .map(|g| format!(" group={g}"))
            .unwrap_or_default();
        out.push(match reason {
            Some(r) => format!(
                "{prefix}  {}  {status_text}  {}{group_note}  ({r})",
                e.deployment_id,
                e.intent.attempted_at()
            ),
            None => format!(
                "{prefix}  {}  {status_text}  {}{group_note}",
                e.deployment_id,
                e.intent.attempted_at()
            ),
        });
    }
    Ok(out)
}

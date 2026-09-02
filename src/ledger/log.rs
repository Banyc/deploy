//! DEPLOY LOG RENDERING (feature area A2: Ledger semantics).
//!
//! [`render_log`] builds the `deploy log <target>` display lines from the
//! ledger's [`LedgerEntry`] stream: one line per recorded attempt, NEWEST
//! LAST, each carrying the DEPLOYMENT ID — the exact rollback key the push
//! reference grammar accepts (`deploy push <target> <deployment-id>`) for a
//! SUCCESSFUL deployment — the effective status, the attempted-at
//! timestamp, the optional rollout ` group=<name>` annotation, and the
//! terminal reason. A failed/degraded/pending attempt is visible here but
//! is NOT a valid rollback ref (its status makes that clear; a failed
//! deployment id never resolves). The effective status: the entry's
//! TERMINAL EVENT carries the status; an intent-only entry (in flight or
//! recoverable-pending) renders `Pending` — the terminal status enum
//! carries no pending status (an intent WITHOUT a terminal IS the pending
//! state). The CLI wrapper (`crate::cli`) stays the command boundary — arg
//! parsing + printing; the rendering semantics live HERE.
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
/// newest last, each carrying the DEPLOYMENT ID (the rollback key for a
/// successful deployment), the effective status, the attempted-at
/// timestamp, the optional group annotation, and the terminal reason. The
/// ledger IS the deployment history; the CLI prints exactly these lines.
pub fn render_log(
    _store: &LocalStore,
    _target: &str,
    entries: &[LedgerEntry],
) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let (status, reason) = effective_status(e);
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
                "{}  {status_text}  {}{group_note}  ({r})",
                e.deployment_id,
                e.intent.attempted_at()
            ),
            None => format!(
                "{}  {status_text}  {}{group_note}",
                e.deployment_id,
                e.intent.attempted_at()
            ),
        });
    }
    Ok(out)
}

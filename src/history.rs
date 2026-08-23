//! Fleet history, rollback snapshots, and rollback reference handling.
//!
//! Only fully successful deployments produce a fleet snapshot
//! (`refs/snapshots.jsonl`), exposed as `<target>@f0`, `<target>@f1`, and so
//! on. Failed and degraded attempts remain visible through `deploy log` and
//! `attempts.jsonl` but are not valid rollback sources.

use crate::error::{Error, Result};
use crate::model::{
    GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, TargetName,
};
use crate::records::{DeploymentAttempt, DeploymentSnapshot, DeploymentStatus};
use crate::store::local::LocalStore;
use std::collections::BTreeMap;

/// A parsed push source reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRef {
    /// Materialize the currently mapped local files; assign configured variants.
    Head,
    /// Restore a historical successful fleet snapshot by index.
    Fleet {
        target: TargetName,
        index: u64,
        current_variant: bool,
    },
    /// Assign each current server its configured variant from a named release.
    Release {
        release: ReleaseId,
        current_variant: bool,
    },
}

/// Parse a push source reference token (the part after the target name).
pub fn parse_push_ref(token: &str) -> Result<PushRef> {
    let t = token.trim();
    let current_variant = t.ends_with(":current");
    let base = if current_variant {
        &t[..t.len() - ":current".len()]
    } else {
        t
    };

    if base == "HEAD" || base.is_empty() {
        return Ok(PushRef::Head);
    }
    if let Some(idx) = base.find("@f") {
        let target = &base[..idx];
        let num = &base[idx + 2..];
        let n: u64 = num
            .parse()
            .map_err(|_| Error::r#ref(format!("invalid fleet index in '{token}'")))?;
        // An empty target (e.g. ref token `@f0`) is filled in by the caller
        // from the separate target argument.
        let target = TargetName::new(target.to_string());
        return Ok(PushRef::Fleet {
            target: TargetName::new(target.to_string()),
            index: n,
            current_variant,
        });
    }
    if base.starts_with("release/") {
        let id = base.strip_prefix("release/").unwrap().to_string();
        return Ok(PushRef::Release {
            release: ReleaseId::parse(&id),
            current_variant,
        });
    }
    if base.starts_with("rel-sha256-") || base.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(PushRef::Release {
            release: ReleaseId::parse(base),
            current_variant,
        });
    }
    Err(Error::r#ref(format!("unrecognized reference '{token}'")))
}

/// Human-readable ref name for a fleet index, e.g. `production@f1`.
pub fn ref_name(target: &TargetName, index: u64) -> String {
    format!("{}@f{index}", target.as_str())
}

/// Ensure the snapshot log contains exactly one successful fleet snapshot for
/// the attempt's deployment ID, and that `refs/last-successful` points at it.
/// Returns the snapshot's index.
///
/// This is the single idempotent insert used by BOTH the main success path
/// and pending-commit recovery finalization, and it is replay-safe:
///
/// * If a snapshot with `deployment_id == attempt.deployment_id` already
///   exists (a previous finalization crashed after appending the snapshot but
///   before finishing), no second snapshot is appended: the existing
///   snapshot's index is returned. The log never contains two snapshots for
///   the same deployment ID.
/// * `refs/last-successful` is (re)written to the attempt's deployment ID in
///   both cases — idempotent, the same value on every replay — which also
///   repairs the stale ref left by a crash between the snapshot append and
///   the ref update.
pub fn ensure_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
) -> Result<u64> {
    let target = target.as_str();
    let entries = store.read_snapshots(target)?;
    if let Some(existing) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
    {
        store.write_last_successful(target, attempt.deployment_id.as_str())?;
        return Ok(existing.index);
    }
    let next = entries.len() as u64;
    let entry = build_snapshot(next, attempt);
    store.append_snapshot(target, &entry)?;
    store.write_last_successful(target, attempt.deployment_id.as_str())?;
    Ok(next)
}

/// Append a successful fleet snapshot to the snapshot log and return its
/// index.
///
/// Idempotent by deployment ID: delegates to
/// [`ensure_snapshot`], so re-running finalization for the same
/// attempt never duplicates the snapshot and always repairs
/// `refs/last-successful`. Kept as the historical name; the main success
/// path now finalizes through the shared
/// [`finalize_successful_attempt`], which calls this.
pub fn append_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
) -> Result<u64> {
    ensure_snapshot(store, target, attempt)
}

/// Finalize a successful fleet attempt replay-safely: the single shared
/// terminal path used by BOTH the normal push success path and pending-commit
/// recovery ([`crate::push::engine::reconcile_pending_commits`]).
///
/// Persistence order:
/// 1. RECOVERABLE MARKER: ensure the attempt's LATEST transition is
///    `PendingCommit`, appending a `PendingCommit` transition (reason
///    "finalization started") only when the latest is not already
///    `PendingCommit`. The latest transition is reconciliation's eligibility
///    gate, so a crash at any later point leaves the attempt re-eligible and
///    the next push replays exactly the remaining steps. On the main path the
///    attempt's latest is `InProgress` here (this appends `PendingCommit`);
///    in recovery it is already `PendingCommit` (a no-op).
/// 2. SNAPSHOT + REF: [`ensure_snapshot`] — idempotent by deployment ID (a
///    replay never appends a second entry) and (re)writes
///    `refs/last-successful`, repairing a stale ref left by a crash between
///    the snapshot append and the ref update.
/// 3. STATUS LAST: append the terminal `Successful` transition with `reason`
///    only after every durable step, so the attempt is never recorded
///    `Successful` while its fleet snapshot is missing.
///
/// Replay idempotency: step 1 is skipped when the latest transition is
/// already `PendingCommit`; step 2 is a no-op (or ref repair) when the
/// snapshot entry already exists; step 3 appends exactly once — a crash
/// before it leaves the attempt eligible, and a crash after it means every
/// earlier step is already durable (and the eligibility gate skips the
/// attempt forever once the latest transition says `Successful`).
///
/// Returns the attempt's snapshot index.
pub fn finalize_successful_attempt(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
    reason: &str,
) -> Result<u64> {
    let id = attempt.deployment_id.as_str();
    // Already fully finalized (the eligibility gate normally prevents this):
    // every earlier step is durable by construction; only repair a stale
    // `refs/last-successful` and stop without appending anything.
    if store.latest_status(id)? == Some(DeploymentStatus::Successful) {
        return ensure_snapshot(store, &attempt.target, attempt);
    }
    // 1. Recoverable marker: the attempt must be re-eligible if we crash
    //    before the snapshot lands.
    if store.latest_status(id)? != Some(DeploymentStatus::PendingCommit) {
        store.append_transition(
            id,
            &DeploymentStatus::PendingCommit,
            Some("finalization started"),
        )?;
    }
    // 2. Snapshot entry + `refs/last-successful` (idempotent).
    let idx = ensure_snapshot(store, &attempt.target, attempt)?;
    // 3. Terminal status LAST.
    store.append_transition(id, &DeploymentStatus::Successful, Some(reason))?;
    Ok(idx)
}

/// Build a snapshot entry from a successful attempt. A successful fleet snapshot
/// carries one complete [`GenerationRef`] per slot; slots without a recorded
/// generation are not part of a coherent successful snapshot and are dropped.
pub fn build_snapshot(index: u64, attempt: &DeploymentAttempt) -> DeploymentSnapshot {
    DeploymentSnapshot {
        index,
        deployment_id: attempt.deployment_id.clone(),
        target: attempt.target.clone(),
        behavior_sha256: attempt.behavior_sha256.clone(),
        slots: attempt
            .slots
            .iter()
            .filter_map(|(slot, s)| {
                s.generation.clone().map(|generation| {
                    (
                        slot.clone(),
                        GenerationRef {
                            generation,
                            assignment: PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: s.artifact.clone(),
                            },
                        },
                    )
                })
            })
            .collect(),
    }
}

/// Resolve a fleet snapshot index to its entry.
pub fn resolve_snapshot(
    store: &LocalStore,
    target: &TargetName,
    index: u64,
) -> Result<DeploymentSnapshot> {
    let target = target.as_str();
    let entries = store.read_snapshots(target)?;
    entries
        .into_iter()
        .find(|e| e.index == index)
        .ok_or_else(|| Error::r#ref(format!("no fleet ref @f{index} for target '{target}'")))
}

/// Reconstruct the set of successful fleet deployments for a target from the
/// snapshot log (used to rebuild history from servers when the local ref is
/// stale).
pub fn successful_fleet_snapshots(
    store: &LocalStore,
    target: &TargetName,
) -> Result<Vec<DeploymentSnapshot>> {
    store.read_snapshots(target.as_str())
}

/// Collect the distinct placement slot IDs referenced across a set of attempts.
pub fn attempt_slot_ids(attempt: &DeploymentAttempt) -> Vec<PlacementSlotId> {
    attempt.slot_ids.clone()
}

/// Build a map of `<target>@fN` -> snapshot for display.
pub fn snapshot_index(
    store: &LocalStore,
    target: &TargetName,
) -> Result<BTreeMap<String, DeploymentSnapshot>> {
    let mut out = BTreeMap::new();
    for e in store.read_snapshots(target.as_str())? {
        out.insert(ref_name(target, e.index), e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeploymentId, PlacementSlotId, ReleaseId};
    use std::collections::BTreeMap;

    #[test]
    fn parse_ref_forms() {
        assert_eq!(parse_push_ref("HEAD").unwrap(), PushRef::Head);
        assert_eq!(
            parse_push_ref("production@f0").unwrap(),
            PushRef::Fleet {
                target: TargetName::new("production".to_string()),
                index: 0,
                current_variant: false
            }
        );
        assert_eq!(
            parse_push_ref("@f0").unwrap(),
            PushRef::Fleet {
                target: TargetName::new("".to_string()),
                index: 0,
                current_variant: false
            }
        );
        assert_eq!(
            parse_push_ref("rel-sha256-deadbeef").unwrap(),
            PushRef::Release {
                release: ReleaseId::parse("rel-sha256-deadbeef"),
                current_variant: false
            }
        );
    }

    #[test]
    fn ref_name_index() {
        assert_eq!(
            ref_name(&TargetName::new("production".to_string()), 3),
            "production@f3"
        );
    }

    #[test]
    fn append_snapshot_is_idempotent_by_deployment_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::new("production".to_string());
        let attempt = DeploymentAttempt {
            deployment_schema_version: 2,
            deployment_id: DeploymentId::new("deploy-idempotent".to_string()),
            target: target.clone(),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // First call appends the snapshot and advances the ref.
        let first = append_snapshot(&store, &target, &attempt).unwrap();
        assert_eq!(first, 0);
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, attempt.deployment_id);
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );

        // Second call with the same deployment ID is a no-op: same index, no
        // duplicate entry, and `refs/last-successful` is untouched.
        let second = append_snapshot(&store, &target, &attempt).unwrap();
        assert_eq!(second, first, "repeated append must return the same index");
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1, "no duplicate snapshot entry");
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );
    }
}

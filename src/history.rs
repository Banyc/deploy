//! Fleet history, rollback snapshots, and rollback reference handling.
//!
//! Only fully successful deployments produce a fleet snapshot
//! (`refs/snapshots.jsonl`), exposed as `<target>@f0`, `<target>@f1`, and so
//! on. Failed and degraded attempts remain visible through `deploy log` and
//! `attempts.jsonl` but are not valid rollback sources.

use crate::error::{Error, Result};
use crate::model::{
    GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, ServerId, TargetName,
};
use crate::records::{AttemptServer, DeploymentAttempt, DeploymentSnapshot, DeploymentStatus};
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
/// and recovery finalization, and it is replay-safe:
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
///
/// The snapshot is built from the attempt's OUTCOMES (`outcomes`: the
/// per-slot actual state the engine observed — results.json on the main path,
/// or the verified desired state during recovery), NOT from the attempt
/// record itself: the persisted attempt is the immutable intent and its
/// `slots` map is empty.
pub fn ensure_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    servers: &BTreeMap<PlacementSlotId, ServerId>,
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
    let entry = build_snapshot(next, attempt, outcomes, servers);
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
/// [`finalize_successful_attempt`], which calls this. The snapshot is built
/// from the attempt's OUTCOMES map, not the attempt record (see
/// [`ensure_snapshot`]).
pub fn append_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    servers: &BTreeMap<PlacementSlotId, ServerId>,
) -> Result<u64> {
    ensure_snapshot(store, target, attempt, outcomes, servers)
}

/// Finalize a successful fleet attempt replay-safely: the single shared
/// terminal path used by BOTH the normal push success path and recovery
/// ([`crate::push::engine::reconcile_pending_commits`]).
///
/// The snapshot is built from the attempt's OUTCOMES (`outcomes`: per-slot
/// actual state observed by the engine — live actuals on the main path,
/// results.json or the verified desired state during recovery), never from
/// the attempt record itself (the persisted attempt is the immutable intent;
/// its `slots` map is empty).
///
/// Persistence order:
/// 1. RECOVERABLE MARKER: ensure the attempt's LATEST transition is
///    `PendingCommit`, appending a `PendingCommit` transition (reason
///    "finalization started") only when the latest is not already
///    `PendingCommit`. The latest transition is recovery's eligibility
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
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    reason: &str,
    servers: &BTreeMap<PlacementSlotId, ServerId>,
) -> Result<u64> {
    let id = attempt.deployment_id.as_str();
    // Already fully finalized (the eligibility gate normally prevents this):
    // every earlier step is durable by construction; only repair a stale
    // `refs/last-successful` and stop without appending anything.
    if store.latest_status(id)? == Some(DeploymentStatus::Successful) {
        return ensure_snapshot(store, &attempt.target, attempt, outcomes, servers);
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
    let idx = ensure_snapshot(store, &attempt.target, attempt, outcomes, servers)?;
    // 3. Terminal status LAST.
    store.append_transition(id, &DeploymentStatus::Successful, Some(reason))?;
    Ok(idx)
}

/// Resolve the per-slot outcomes used to build a successful fleet snapshot
/// when the engine no longer has the live outcomes at hand (recovery): the
/// persisted results (`deployments/<id>/results.json`) when present — a
/// crash after the mutation loop but before/within finalization — otherwise
/// the attempt's verified desired state (a crash before outcomes were
/// persisted, e.g. a faulted `write_results`).
///
/// The per-slot ARTIFACT always resolves from the attempt's desired
/// assignment: results.json records outcomes (generation, status) but not
/// artifacts, and recovery already verified each slot's current generation
/// equals the desired generation. Slots without a recorded generation are
/// not part of a coherent successful snapshot and are dropped by
/// [`build_snapshot`].
pub fn resolve_attempt_outcomes(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
) -> Result<BTreeMap<PlacementSlotId, AttemptServer>> {
    // `read_results` fails when `results.json` is absent (crash before the
    // outcomes were persisted); treat that as "verified desired state only".
    let results = store.read_results(attempt.deployment_id.as_str()).ok();
    let mut outcomes = BTreeMap::new();
    for sid in &attempt.slot_ids {
        let Some(desired) = attempt.desired.get(sid) else {
            continue;
        };
        let generation = results
            .as_ref()
            .and_then(|r| r.slots.get(sid).and_then(|sr| sr.generation.clone()))
            .or_else(|| Some(desired.generation.clone()));
        outcomes.insert(
            sid.clone(),
            AttemptServer {
                artifact: desired.assignment.artifact.clone(),
                generation,
            },
        );
    }
    Ok(outcomes)
}

/// Build a snapshot entry from the attempt's OUTCOMES (per-slot actual
/// state), not from the attempt record: the persisted attempt is the
/// immutable intent (its `slots` map is empty), so the snapshot must be
/// built from the outcomes the engine observed — live per-slot actuals on
/// the main path, or results.json / the verified desired state during
/// recovery ([`resolve_attempt_outcomes`]). A successful fleet snapshot
/// carries one complete [`GenerationRef`] per slot; slots without a
/// recorded generation are not part of a coherent successful snapshot and
/// are dropped.
///
/// `servers` records the physical [`ServerId`] each slot was bound to at
/// the time the deployment ran (the engine passes the target's current
/// slot→server binding from `deploy.toml`). It is stored as a separate map
/// so the `slots` map and its [`GenerationRef`]s stay intact; a legacy
/// entry with no `servers` map deserializes to an empty one (unverifiable,
/// so rollback refuses rather than guessing the host).
pub fn build_snapshot(
    index: u64,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    servers: &BTreeMap<PlacementSlotId, ServerId>,
) -> DeploymentSnapshot {
    DeploymentSnapshot {
        index,
        deployment_id: attempt.deployment_id.clone(),
        target: attempt.target.clone(),
        behavior_sha256: attempt.behavior_sha256.clone(),
        slots: outcomes
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
        servers: servers.clone(),
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
    use crate::model::{ArtifactRef, DeploymentId, GenerationId, PlacementSlotId, ReleaseId};
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
        let servers: BTreeMap<PlacementSlotId, ServerId> =
            BTreeMap::from([(PlacementSlotId::new("p1"), ServerId::new("server-01"))]);
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

        // First call appends the snapshot and advances the ref. The snapshot
        // is built from the attempt's OUTCOMES map (the attempt record
        // itself carries only intent; its `slots` map is empty), and records
        // the slot→server binding from `servers`.
        let first = append_snapshot(&store, &target, &attempt, &attempt.slots, &servers).unwrap();
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
        let second = append_snapshot(&store, &target, &attempt, &attempt.slots, &servers).unwrap();
        assert_eq!(second, first, "repeated append must return the same index");
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1, "no duplicate snapshot entry");
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );
    }

    #[test]
    fn build_snapshot_records_each_slots_physical_server() {
        let slot = PlacementSlotId::new("p1".to_string());
        let attempt = DeploymentAttempt {
            deployment_schema_version: 2,
            deployment_id: DeploymentId::new("deploy-server-map".to_string()),
            target: TargetName::new("production".to_string()),
            slot_ids: vec![slot.clone()],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::from([(
                slot.clone(),
                crate::records::AttemptServer {
                    artifact: ArtifactRef::default(),
                    generation: Some(GenerationId::new("gen-x".to_string())),
                },
            )]),
        };
        let servers: BTreeMap<PlacementSlotId, ServerId> =
            BTreeMap::from([(slot.clone(), ServerId::new("server-01"))]);

        let snapshot = build_snapshot(3, &attempt, &attempt.slots, &servers);
        assert_eq!(
            snapshot.servers.get(&slot),
            Some(&ServerId::new("server-01")),
            "the snapshot must record the physical server the slot was bound to"
        );
        assert_eq!(snapshot.slots.len(), 1, "generation refs preserved intact");
        assert_eq!(snapshot.servers.len(), 1);
    }

    /// A legacy pre-feature snapshot line (no `servers` key) must still
    /// deserialize; its `servers` map defaults to empty, which rollback treats
    /// as unverifiable rather than guessing.
    #[test]
    fn legacy_snapshot_without_servers_deserializes_with_empty_map() {
        let line = r#"{"index":0,"deployment_id":"deploy-old","target":"production","behavior_sha256":"sha256-aa","slots":{}}"#;
        let snapshot: DeploymentSnapshot = serde_json::from_str(line).unwrap();
        assert!(
            snapshot.servers.is_empty(),
            "legacy line yields an empty map"
        );
    }
}

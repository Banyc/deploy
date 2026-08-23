//! Fleet history, reflog, and rollback reference handling.
//!
//! The target reflog contains only fully successful fleet snapshots and exposes
//! them as `<target>@f0`, `<target>@f1`, and so on. Failed and degraded attempts
//! remain visible through `deploy log` and `attempts.jsonl` but are not valid
//! rollback sources.

use crate::error::{Error, Result};
use crate::model::{
    GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, TargetName,
};
use crate::records::{AttemptRecord, ReflogEntry};
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

/// Ensure the reflog contains exactly one successful fleet snapshot for the
/// attempt's deployment ID, and that `refs/last-successful` points at it.
/// Returns the entry's reflog index.
///
/// This is the single idempotent insert used by BOTH the main success path
/// and pending-commit recovery finalization, and it is replay-safe:
///
/// * If an entry with `deployment_id == attempt.deployment_id` already exists
///   (a previous finalization crashed after appending the reflog entry but
///   before finishing), no second entry is appended: the existing entry's
///   index is returned. The reflog never contains two entries for the same
///   deployment ID.
/// * `refs/last-successful` is (re)written to the attempt's deployment ID in
///   both cases — idempotent, the same value on every replay — which also
///   repairs the stale ref left by a crash between the reflog append and the
///   ref update.
pub fn ensure_successful_reflog_entry(
    store: &LocalStore,
    target: &TargetName,
    attempt: &AttemptRecord,
) -> Result<u64> {
    let target = target.as_str();
    let entries = store.read_reflog(target)?;
    if let Some(existing) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
    {
        store.write_last_successful(target, attempt.deployment_id.as_str())?;
        return Ok(existing.index);
    }
    let next = entries.len() as u64;
    let entry = build_reflog_entry(next, attempt);
    store.append_reflog(target, &entry)?;
    store.write_last_successful(target, attempt.deployment_id.as_str())?;
    Ok(next)
}

/// Append a successful fleet snapshot to the reflog and return its index.
///
/// Idempotent by deployment ID: delegates to
/// [`ensure_successful_reflog_entry`], so re-running finalization for the same
/// attempt never duplicates the reflog entry and always repairs
/// `refs/last-successful`. Kept as the historical name so existing call sites
/// (and the main success path) read naturally.
pub fn append_successful_reflog(
    store: &LocalStore,
    target: &TargetName,
    attempt: &AttemptRecord,
) -> Result<u64> {
    ensure_successful_reflog_entry(store, target, attempt)
}

/// Build a reflog entry from a successful attempt. A successful fleet snapshot
/// carries one complete [`GenerationRef`] per slot; slots without a recorded
/// generation are not part of a coherent successful snapshot and are dropped.
pub fn build_reflog_entry(index: u64, attempt: &AttemptRecord) -> ReflogEntry {
    ReflogEntry {
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

/// Resolve a fleet reflog index to its entry.
pub fn resolve_fleet_ref(
    store: &LocalStore,
    target: &TargetName,
    index: u64,
) -> Result<ReflogEntry> {
    let target = target.as_str();
    let entries = store.read_reflog(target)?;
    entries
        .into_iter()
        .find(|e| e.index == index)
        .ok_or_else(|| Error::r#ref(format!("no fleet ref @f{index} for target '{target}'")))
}

/// Reconstruct the set of successful fleet deployments for a target from the
/// reflog (used to rebuild history from servers when the local ref is stale).
pub fn successful_fleet_history(
    store: &LocalStore,
    target: &TargetName,
) -> Result<Vec<ReflogEntry>> {
    store.read_reflog(target.as_str())
}

/// Collect the distinct placement slot IDs referenced across a set of attempts.
pub fn attempt_slot_ids(attempt: &AttemptRecord) -> Vec<PlacementSlotId> {
    attempt.slot_ids.clone()
}

/// Build a map of `<target>@fN` -> entry for display.
pub fn reflog_index(
    store: &LocalStore,
    target: &TargetName,
) -> Result<BTreeMap<String, ReflogEntry>> {
    let mut out = BTreeMap::new();
    for e in store.read_reflog(target.as_str())? {
        out.insert(ref_name(target, e.index), e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeploymentId, PlacementSlotId, ReleaseId};
    use crate::records::DeploymentStatus;
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
    fn append_successful_reflog_is_idempotent_by_deployment_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::new("production".to_string());
        let attempt = AttemptRecord {
            deployment_schema_version: 2,
            deployment_id: DeploymentId::new("deploy-idempotent".to_string()),
            status: DeploymentStatus::Successful,
            target: target.clone(),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // First call appends the entry and advances the ref.
        let first = append_successful_reflog(&store, &target, &attempt).unwrap();
        assert_eq!(first, 0);
        let reflog = store.read_reflog(target.as_str()).unwrap();
        assert_eq!(reflog.len(), 1);
        assert_eq!(reflog[0].deployment_id, attempt.deployment_id);
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );

        // Second call with the same deployment ID is a no-op: same index, no
        // duplicate entry, and `refs/last-successful` is untouched.
        let second = append_successful_reflog(&store, &target, &attempt).unwrap();
        assert_eq!(second, first, "repeated append must return the same index");
        let reflog = store.read_reflog(target.as_str()).unwrap();
        assert_eq!(reflog.len(), 1, "no duplicate reflog entry");
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );
    }
}

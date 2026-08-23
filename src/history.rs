//! Fleet history, reflog, and rollback reference handling.
//!
//! The target reflog contains only fully successful fleet snapshots and exposes
//! them as `<target>@f0`, `<target>@f1`, and so on. Failed and degraded attempts
//! remain visible through `deploy log` and `attempts.jsonl` but are not valid
//! rollback sources.

use crate::error::{Error, Result};
use crate::model::{ReleaseId, ServerId, TargetName};
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

/// Append a successful fleet snapshot to the reflog and return its index.
pub fn append_successful_reflog(
    store: &LocalStore,
    target: &TargetName,
    attempt: &AttemptRecord,
) -> Result<u64> {
    let target = target.as_str();
    let entries = store.read_reflog(target)?;
    let next = entries.len() as u64;
    let entry = build_reflog_entry(next, attempt);
    store.append_reflog(target, &entry)?;
    store.write_last_successful(target, attempt.deployment_id.as_str())?;
    Ok(next)
}

/// Build a reflog entry from a successful attempt.
pub fn build_reflog_entry(index: u64, attempt: &AttemptRecord) -> ReflogEntry {
    ReflogEntry {
        index,
        deployment_id: attempt.deployment_id.clone(),
        target: attempt.target.clone(),
        behavior_sha256: attempt.behavior_sha256.clone(),
        servers: attempt.servers.clone(),
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

/// Collect the distinct server IDs referenced across a set of attempts.
pub fn attempt_server_ids(attempt: &AttemptRecord) -> Vec<ServerId> {
    attempt.server_ids.clone()
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
    use crate::model::ReleaseId;

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
}

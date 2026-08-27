//! The behavior-coverage gate (A5 verification semantics): EVERY planned
//! assignment's (release, variant) must have a frozen behavior contract
//! BEFORE any remote state is touched (handshake, incoming cleanup, staging,
//! publication) — each slot's behavior resolves from ITS OWN artifact
//! binding, never a snapshot-wide single release. A historical behavior
//! snapshot can be incomplete (a corrupted or truncated `behavior.json`
//! parses fine but lacks a variant); without the gate the missing entry
//! would panic mid-rollout, after remote trees had already been staged.
//!
//! [`validate_behavior_coverage`] fails closed in preflight, naming the
//! missing (release, variant) pairs and the affected servers. It runs on the
//! push spine ([`crate::deploy::push`]) after planning and before the
//! mutating remote phase.

use crate::deploy::plan::PlannedAssignment;
use crate::error::{Error, Result};
use crate::identity::ReleaseId;
use crate::ledger::BehaviorIndex;
use std::collections::BTreeMap;

/// Fail closed in preflight if any planned assignment's (release, variant)
/// lacks a frozen behavior contract. EACH SLOT's behavior resolves from ITS
/// OWN artifact binding (`slot.assignment.artifact = {release, variant,
/// tree}`) — the per-release, per-variant index — never a snapshot-wide
/// single release. Historical behavior snapshots can be incomplete (a
/// corrupted or truncated `behavior.json` parses successfully but covers only
/// some variants); reaching rollout with a missing entry previously panicked
/// after trees were already staged onto servers. This gate runs before any
/// remote mutation and names the missing (release, variant) pairs and the
/// affected servers.
pub(crate) fn validate_behavior_coverage(
    index: &BehaviorIndex,
    assignments: &[PlannedAssignment],
) -> Result<()> {
    let mut missing: BTreeMap<(ReleaseId, String), Vec<&str>> = BTreeMap::new();
    for a in assignments {
        let covered = index
            .get(&a.artifact.release)
            .is_some_and(|m| m.contains_key(a.artifact.variant.as_str()));
        if !covered {
            missing
                .entry((
                    a.artifact.release.clone(),
                    a.artifact.variant.as_str().to_string(),
                ))
                .or_default()
                .push(a.placement_slot.as_str());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let detail = missing
        .iter()
        .map(|((release, variant), slots)| {
            format!(
                "release {release} variant '{variant}' (slots: {})",
                slots.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(Error::preflight(format!(
        "behavior snapshot incomplete: missing {detail}; \
         refusing to start before any remote state is changed"
    )))
}

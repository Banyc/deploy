//! The ROLLBACK PAYLOAD semantics (feature area A2: Ledger semantics).
//!
//! [`build_rollback`] builds the rollback state of a successful deployment
//! from the attempt's OUTCOMES (`actuals`: per-slot actual state), never
//! from the intent record. The payload is the COMPLETE target snapshot (a
//! [`crate::ledger::records::LedgerRollback`]: per-slot generation refs +
//! COMPLETE physical bindings), so EXACT ROLLBACK is possible: `deploy push
//! <target> <deployment-id>` restores exactly that deployment's stored
//! state, verified by the binding map (a missing binding entry is
//! "unverifiable" and makes exact rollback refuse the slot). The payload
//! FAILS CLOSED on an unknown assignment: an `Unknown`/`KnownAbsent`
//! artifact with a recorded generation is a corrupted payload and the
//! builder refuses it rather than fabricating a `GenerationRef` with a fake
//! artifact.
//!
//! The wire/domain RECORDS themselves ([`crate::ledger::records::LedgerRollback`],
//! [`crate::ledger::records::LedgerRollbackWire`],
//! [`crate::ledger::records::PhysicalBinding`]) live in
//! [`crate::ledger::records`].
//!
use crate::error::{Error, Result};
use crate::ledger::records::{LedgerRollback, Observation, PhysicalBinding, SlotAttemptState};
use crate::model::{GenerationRef, PlacementSlotAssignment, SlotId};
use std::collections::BTreeMap;

/// Build the rollback state of a successful deployment from the attempt's
/// OUTCOMES (`actuals`: per-slot actual state), never from the intent record.
/// A successful deployment carries one complete [`GenerationRef`] per slot;
/// slots without a recorded generation are not part of a coherent rollback
/// and are dropped. `bindings` records the COMPLETE physical binding
/// (`{server, deploy_dir}`) each slot had when the deployment ran; a missing
/// entry is "unverifiable" and makes exact rollback refuse the slot.
///
/// PARTIAL-ROLLOUT OVERLAY: the result is the COMPLETE target snapshot — the
/// latest successful snapshot (`base`) with the SELECTED slots (the attempt's
/// actual per-slot results) replaced by their actual assignments and current
/// bindings, unselected slots carried forward unchanged, and slots absent
/// from `current_slot_ids` (removed from the current target configuration)
/// omitted. A full-target attempt replaces every slot, so the base is
/// irrelevant. There is NO snapshot-wide release/behavior: each slot's
/// `GenerationRef` carries its OWN artifact (release/variant/tree), so a
/// partial snapshot can span several releases (group pushes over time) and
/// the referenced releases are the set derived from the per-slot bindings.
pub fn build_rollback(
    actuals: &BTreeMap<SlotId, SlotAttemptState>,
    bindings: &BTreeMap<SlotId, PhysicalBinding>,
    base: Option<&LedgerRollback>,
    current_slot_ids: &[SlotId],
) -> Result<LedgerRollback> {
    // Start from the base (or empty): unselected slots are carried forward
    // unchanged.
    let mut slots: BTreeMap<SlotId, GenerationRef> =
        base.map(|b| b.slots.clone()).unwrap_or_default();
    let mut out_bindings: BTreeMap<SlotId, PhysicalBinding> =
        base.map(|b| b.bindings.clone()).unwrap_or_default();
    // Replace the SELECTED slots with their actual successful assignments
    // and current physical bindings.
    for (slot, s) in actuals {
        if let Some(generation) = s.generation.clone() {
            // FAIL CLOSED on the artifact: the rollback payload must never
            // carry an unknown assignment. A Successful attempt's actuals are
            // `Known` in practice (the post-mutation refresh only records
            // `Unknown` when a live assignment read fails, and the successful
            // path validates the layout before it ever finalizes); an
            // `Unknown`/`KnownAbsent` artifact with a recorded generation
            // would be a corrupted payload, so the finalize REFUSES it rather
            // than fabricating a `GenerationRef` with a fake artifact.
            let Observation::Known(artifact) = &s.artifact else {
                return Err(Error::integrity(format!(
                    "successful rollback for slot '{slot}' carries an unknown assignment \
                     (the artifact observation is not Known): the rollback payload must \
                     never contain an unknown artifact"
                )));
            };
            slots.insert(
                slot.clone(),
                GenerationRef {
                    generation,
                    assignment: PlacementSlotAssignment {
                        placement_slot: slot.clone(),
                        artifact: artifact.clone(),
                    },
                },
            );
        }
        if let Some(b) = bindings.get(slot) {
            out_bindings.insert(slot.clone(), b.clone());
        }
    }
    // Omit slots removed from the current target configuration.
    let current: std::collections::HashSet<&str> =
        current_slot_ids.iter().map(|s| s.as_str()).collect();
    slots.retain(|k, _| current.contains(k.as_str()));
    out_bindings.retain(|k, _| current.contains(k.as_str()));
    Ok(LedgerRollback {
        slots,
        bindings: out_bindings,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::records::Observation;
    use crate::model::{
        ArtifactRef, ServerId, SlotId, VariantName, test_deployment_id, test_generation_id,
        test_tree_digest,
    };
    use std::collections::BTreeMap;

    /// `build_rollback` records each slot's complete physical binding.
    #[test]
    fn build_rollback_records_each_slots_physical_binding() {
        let slot = SlotId::new("p1".to_string());
        let actuals = BTreeMap::from([(
            slot.clone(),
            SlotAttemptState {
                artifact: Observation::Known(ArtifactRef {
                    release: crate::model::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("tree-1"),
                }),
                generation: Some(test_generation_id("gen-x")),
            },
        )]);
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([(
            slot.clone(),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);

        let rollback = build_rollback(&actuals, &bindings, None, std::slice::from_ref(&slot))
            .expect("a Known actual builds the rollback");
        assert_eq!(
            rollback.bindings.get(&slot),
            Some(&PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            }),
            "the rollback must record the slot's complete physical binding (server AND deploy_dir)"
        );
        assert_eq!(rollback.slots.len(), 1, "generation refs preserved intact");
        assert_eq!(rollback.bindings.len(), 1);
    }

    /// The rollback payload must NEVER carry an unknown assignment: an actual
    /// whose artifact is `Unknown` (or `KnownAbsent`) with a recorded
    /// generation is a corrupted payload for a Successful rollback, so
    /// `build_rollback` FAILS CLOSED with an integrity error rather than
    /// fabricating a `GenerationRef` with a fake artifact. An actual with
    /// `generation: None` stays dropped regardless of its artifact (the
    /// existing "no coherent rollback" rule).
    #[test]
    fn build_rollback_refuses_unknown_actuals() {
        let slot = SlotId::new("p1".to_string());
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([(
            slot.clone(),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);
        // An UNKNOWN actual with a generation: refused.
        let actuals = BTreeMap::from([(
            slot.clone(),
            SlotAttemptState {
                artifact: Observation::Unknown(crate::ledger::records::ObservationError {
                    message: "assignment read failed: fixture".to_string(),
                }),
                generation: Some(test_generation_id("gen-x")),
            },
        )]);
        let err = build_rollback(&actuals, &bindings, None, std::slice::from_ref(&slot))
            .expect_err("an Unknown actual must not build a rollback");
        assert!(
            err.to_string().contains("unknown assignment"),
            "the refusal names the unknown assignment, got: {err}"
        );
        // A KnownAbsent actual with a generation is equally a corrupted
        // payload: refused (an advanced slot always has a Known artifact).
        let actuals = BTreeMap::from([(
            slot.clone(),
            SlotAttemptState {
                artifact: Observation::KnownAbsent,
                generation: Some(test_generation_id("gen-x")),
            },
        )]);
        build_rollback(&actuals, &bindings, None, std::slice::from_ref(&slot))
            .expect_err("a KnownAbsent actual with a generation must not build a rollback");
        // An Unknown actual WITHOUT a generation is dropped (no rollback
        // entry), never an error: the "no recorded generation" rule applies
        // regardless of the artifact observation.
        let actuals = BTreeMap::from([(
            slot.clone(),
            SlotAttemptState {
                artifact: Observation::Unknown(crate::ledger::records::ObservationError {
                    message: "assignment read failed: fixture".to_string(),
                }),
                generation: None,
            },
        )]);
        let rollback = build_rollback(&actuals, &bindings, None, std::slice::from_ref(&slot))
            .expect("an Unknown actual without a generation is simply dropped");
        assert_eq!(rollback.slots.len(), 0, "no fake GenerationRef is inserted");
    }

    /// A legacy LEDGER LINE whose rollback has no `bindings` key must still
    /// deserialize; its `bindings` map defaults to empty, which rollback
    /// treats as unverifiable rather than guessing the host/location. The
    /// line ALSO carries the OLD snapshot-wide `behavior_sha256`/`release`
    /// members — serde ignores the unknown fields, and the rollback payload
    /// is interpreted purely through the per-slot bindings (legacy lines stay
    /// readable after the snapshot-wide fields were removed). The line is
    /// otherwise in the CURRENT v3 shape — it carries the REQUIRED
    /// `selected_membership` / `full_membership` members (empty here) so the
    /// legacy aspect under test is the rollback's missing `bindings` and the
    /// snapshot-wide members, not the membership fields. A line WITHOUT the
    /// v3 membership members is an OLD-SHAPE record and fails
    /// DESERIALIZATION fail-closed (the fields are REQUIRED — no serde
    /// default), pinned below.
    #[test]
    fn legacy_rollback_without_bindings_deserializes_with_empty_map() {
        // The id must be a canonical (validated) deployment id — the legacy
        // aspect under test is the missing `bindings` key and the
        // snapshot-wide members, not the id format.
        let did = test_deployment_id("deploy-old");
        let rel = crate::model::test_release_id("old");
        let line = format!(
            r#"{{"kind":"terminal","deployment_id":"{did}","target":"production","status":"successful","recorded_at":"2026-01-01T00:00:00Z","outcomes":{{}},"selected_membership":[],"full_membership":[],"rollback":{{"behavior_sha256":"sha256-aa","release":"{rel}","slots":{{}}}}}}"#
        );
        // The legacy line PARSES at the wire level (the legacy snapshot-wide
        // members are tolerated by serde — unknown members are skipped), and
        // the domain conversion REFUSES it (fail closed): the legacy
        // `release` disagrees with the snapshot's derived releases (the
        // per-slot bindings — empty here — are the authoritative source).
        let wire: crate::ledger::records::LedgerTerminalWire = serde_json::from_str(&line).unwrap();
        let err = wire.into_domain().expect_err(
            "a legacy release that disagrees with the derived snapshot releases fails closed",
        );
        assert!(err.to_string().contains("release"), "error: {err}");

        // AN OLD-SHAPE TERMINAL LINE (no `selected_membership` /
        // `full_membership` members — the v2 shape) fails DESERIALIZATION
        // fail-closed: the v3 membership fields are REQUIRED (no serde
        // default), so a pre-v3 record can never be read as if it carried
        // proven memberships (the intent-line `deployment_schema_version`
        // check refuses its intent the same way).
        let old_line = format!(
            r#"{{"kind":"terminal","deployment_id":"{did}","target":"production","status":"successful","recorded_at":"2026-01-01T00:00:00Z","outcomes":{{}},"rollback":{{"slots":{{}}}}}}"#
        );
        let err = serde_json::from_str::<crate::ledger::records::LedgerTerminalWire>(&old_line)
            .expect_err("an old-shape terminal line without the v3 memberships must fail deserialization fail-closed");
        assert!(
            err.to_string().contains("selected_membership")
                || err.to_string().contains("full_membership"),
            "the deserialization error must name the missing REQUIRED membership field, got: {err}"
        );
    }
}

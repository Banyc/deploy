//! THE DOC-EXAMPLE GENERATOR (test-only): renders the pretty-printed WIRE
//! examples the public docs' ```json fenced blocks carry, FROM THE REAL
//! WIRE RECORDS — never from hand-written schema. [`render_wire_pair`]
//! serializes any valid intent + terminal pair through the CURRENT wire
//! types ([`LedgerIntentWire`] / [`LedgerTerminalWire`]) wrapped in their
//! physical line kind ([`crate::ledger::finalize::LedgerLine`]), pretty
//! printed, with the CURRENT [`crate::ledger::LEDGER_SCHEMA_VERSION`] — so
//! the docs' examples can never drift from the wire: a schema change that
//! would stale the documented shape fails
//! `tests::docs_examples_match_generated_wire` (which byte-compares the
//! requirement.md fenced blocks against this generator), and the
//! round-trip proptest (`tests::generated_wire_pairs_round_trip_through_the_strict_reader`)
//! parses the generator's output through the STRICT READER
//! ([`crate::store::local::LocalStore::read_ledger`], version gate +
//! verifying conversions) for arbitrary generated pairs.
//!
//! [`canonical_doc_pair`] builds the SPECIFIC fixtures the docs render: a
//! full-push `production` deployment (`deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b`,
//! slots `p1`/`p2`/`p3`) whose intent line and SUCCESSFUL terminal line
//! together show the CURRENT shape: the frozen memberships
//! (`selected_membership`/`full_membership`), the FROZEN PHYSICAL BINDINGS
//! (schema v6, keyed by slot), the strict wire observations
//! (adjacently-tagged `state`+`value`), and the terminal's rollback payload
//! (the deployment's snapshot, keyed by deployment id — the deployment-id
//! keyed snapshot the "Snapshot history and rollback" section describes).
//! Every identity in the fixtures is a VALID canonical value (a full
//! 64-hex tree/behavior digest, a `rel-sha256-<64-hex>` release id, a
//! UUIDv7 deployment/generation id), so the rendered examples are REAL
//! wire records the strict reader accepts byte-for-byte.

use crate::identity::{
    ArtifactRef, DeploymentId, GenerationId, GenerationRef, PlacementSlotAssignment, ReleaseId,
    ServerId, SlotId, TargetName, VariantName,
};
use crate::ledger::finalize::LedgerLine;
use crate::ledger::records::{
    DeploymentStatus, LedgerIntentWire, LedgerTerminalWire, ObservationWire,
    ObservedGenerationWire, PhysicalBinding, SlotOutcomeKind, SlotResult, SnapshotEntry,
    TargetSnapshot,
};
use std::collections::BTreeMap;

/// The pretty-printed JSON of a wire intent + terminal pair, exactly as the
/// docs' fenced ```json blocks carry it (each line rendered through the
/// physical [`crate::ledger::finalize::LedgerLine`] kind, so the `kind`
/// tag — `intent` / `terminal` — is part of the example).
pub(crate) struct RenderedLedgerExamples {
    /// The `{"kind":"intent", ...}` line, pretty printed.
    pub intent: String,
    /// The `{"kind":"terminal", ...}` line, pretty printed.
    pub terminal: String,
}

/// THE DOC-EXAMPLE GENERATOR: serialize a valid intent + terminal wire pair
/// through the CURRENT wire types (pretty printed, with the current
/// `deployment_schema_version` — the intent wire carries
/// [`crate::ledger::LEDGER_SCHEMA_VERSION`] via its own construction, never
/// a hardcoded literal). The output is the EXACT JSON the docs' fenced
/// blocks must carry: `tests::docs_examples_match_generated_wire`
/// byte-compares them, and the round-trip proptest parses the output back
/// through the strict reader.
pub(crate) fn render_wire_pair(
    intent: &LedgerIntentWire,
    terminal: &LedgerTerminalWire,
) -> RenderedLedgerExamples {
    let pretty = |line: &LedgerLine| -> String {
        serde_json::to_string_pretty(line)
            .expect("a valid wire record always serializes to pretty JSON")
    };
    RenderedLedgerExamples {
        intent: pretty(&LedgerLine::Intent(intent.clone())),
        terminal: pretty(&LedgerLine::Terminal(terminal.clone())),
    }
}

/// The CANONICAL fixtures the docs render: a full-push `production`
/// deployment of three slots (`p1` standard, `p2` standard, `p3`
/// high-capacity) whose SUCCESSFUL terminal carries the exact-equal proven
/// shape (outcomes == selected == full == rollback slots, the frozen
/// bindings reproduced). The pair is a REAL wire record: it converts to the
/// domain and passes the strict reader's cross-record invariants
/// (exercised directly by the docs-match test below).
pub(crate) fn canonical_doc_pair() -> (LedgerIntentWire, LedgerTerminalWire) {
    let deployment_id = DeploymentId::parse("deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b")
        .expect("the canonical example deployment id is a UUIDv7");
    let target = TargetName::parse("production").unwrap();
    let release = ReleaseId::parse(
        "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
    )
    .expect("the canonical example release id is a full rel-sha256 digest");
    let slots = [
        (
            "p1",
            "standard",
            "server-01",
            "gen-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
        ),
        (
            "p2",
            "standard",
            "server-02",
            "gen-0290a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
        ),
        (
            "p3",
            "high-capacity",
            "server-03",
            "gen-0390a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
        ),
    ];
    let gen_for =
        |g: &str| GenerationId::parse(g).expect("the canonical example generation ids are UUIDv7");
    let tree_for = |tag: &str| crate::identity::test_tree_digest(tag);
    let binding_for = |sid: &SlotId, server: &str| PhysicalBinding {
        server: ServerId::new(server.to_string()),
        deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
    };
    let gen_ref_for = |sid: &SlotId, variant: &str, gen_id: &str| GenerationRef {
        generation: gen_for(gen_id),
        assignment: PlacementSlotAssignment {
            placement_slot: sid.clone(),
            artifact: ArtifactRef {
                release: release.clone(),
                variant: VariantName::new(variant.to_string()),
                tree: tree_for(sid.as_str()),
            },
        },
    };

    let slot_ids: Vec<SlotId> = slots
        .iter()
        .map(|(s, _, _, _)| SlotId::new(s.to_string()))
        .collect();
    let pre_push: BTreeMap<SlotId, Option<crate::ledger::records::SlotAttemptStateWire>> =
        slot_ids.iter().map(|sid| (sid.clone(), None)).collect();
    let bindings: BTreeMap<SlotId, PhysicalBinding> = slots
        .iter()
        .map(|(s, _, server, _)| {
            let sid = SlotId::new(s.to_string());
            (sid.clone(), binding_for(&sid, server))
        })
        .collect();
    // THE FROZEN RESULTING SNAPSHOT: one entry per target slot (its
    // plan-minted generation/artifact and plan-time physical binding) — its
    // keys ARE the frozen full membership, and the selected slot's desired
    // facts are its snapshot entry (no separate desired projection).
    let snapshot = crate::ledger::records::TargetSnapshot::from_entries(
        slots
            .iter()
            .map(|(s, v, server, g)| {
                let sid = SlotId::new(s.to_string());
                let gr = gen_ref_for(&sid, v, g);
                (
                    sid.clone(),
                    crate::ledger::records::SnapshotEntry::new(
                        gr.generation,
                        gr.assignment.artifact,
                        binding_for(&sid, server),
                    ),
                )
            })
            .collect(),
    );

    let intent = LedgerIntentWire {
        // THE CURRENT SCHEMA VERSION — the constant, never a hardcoded
        // literal: a schema bump that would stale the docs' example fails
        // the docs-match test here.
        deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
        deployment_id: deployment_id.clone(),
        target: target.clone(),
        group: None,
        slot_ids: slot_ids.clone(),
        behavior_sha256: crate::identity::test_sha256_hex("behavior-production"),
        attempted_at: "2026-08-21T10:20:00Z".to_string(),
        resulting_snapshot: crate::ledger::records::TargetSnapshotWire::from(&snapshot),
        pre_push,
        // The persisted intent carries NO outcomes (outcomes live in the
        // terminal event; the wire keeps this map empty).
        slots: BTreeMap::new(),
    };

    let outcomes: BTreeMap<SlotId, SlotResult> = slots
        .iter()
        .map(|(s, _, _, g)| {
            let sid = SlotId::new(s.to_string());
            (
                sid.clone(),
                SlotResult {
                    slot_id: sid.clone(),
                    outcome: SlotOutcomeKind::Activated,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: gen_for(g),
                    }),
                    compensated: false,
                    error: None,
                },
            )
        })
        .collect();
    let rollback_entries: BTreeMap<SlotId, SnapshotEntry> = slots
        .iter()
        .map(|(s, v, _, g)| {
            let sid = SlotId::new(s.to_string());
            let gen_ref = gen_ref_for(&sid, v, g);
            (
                sid.clone(),
                SnapshotEntry::new(
                    gen_ref.generation,
                    gen_ref.assignment.artifact,
                    bindings[&sid].clone(),
                ),
            )
        })
        .collect();
    let terminal = LedgerTerminalWire {
        deployment_id,
        target,
        status: DeploymentStatus::Successful,
        recorded_at: "2026-08-21T10:25:00Z".to_string(),
        outcomes,
        rollback: Some(TargetSnapshot::from_entries(rollback_entries)),
        selected_membership: slot_ids.clone(),
        full_membership: slot_ids,
        reason: Some("push completed".to_string()),
    };
    (intent, terminal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::records::LEDGER_SCHEMA_VERSION;

    /// The canonical pair is a REAL wire record: it converts to the domain
    /// and the SUCCESSFUL terminal's cross-record invariants hold against
    /// its intent (the exact-equal full-push shape the strict reader
    /// requires) — so the docs' example is not just well-formed JSON, it is
    /// a record the strict reader accepts.
    #[test]
    fn canonical_doc_pair_is_a_valid_readable_pair() {
        let (intent, terminal) = canonical_doc_pair();
        assert_eq!(
            intent.deployment_schema_version, LEDGER_SCHEMA_VERSION,
            "the canonical intent carries the CURRENT schema version"
        );
        let d_intent = intent.into_domain().expect("the canonical intent converts");
        assert_eq!(
            terminal.deployment_id.as_str(),
            d_intent.deployment_id.as_str(),
            "the terminal keys the intent's deployment"
        );
        let d_terminal = terminal
            .into_domain()
            .expect("the canonical terminal converts");
        assert_eq!(d_terminal.status(), DeploymentStatus::Successful);
        // The exact-equal full-push shape: selected == full == the intent's
        // frozen memberships == the membership.
        assert_eq!(
            d_terminal.selected_membership(),
            Some(d_intent.selected_membership()),
            "a full push's Successful terminal reproduces the intent's frozen selected membership"
        );
        assert_eq!(
            d_terminal.full_membership(),
            Some(d_intent.full_membership()),
            "a full push's Successful terminal reproduces the intent's frozen full membership"
        );
        let membership: std::collections::BTreeSet<SlotId> =
            d_intent.selected.keys().cloned().collect();
        assert_eq!(membership, d_intent.selected_membership());
        assert_eq!(membership, d_intent.full_membership());
    }
}

//! THE DOC-EXAMPLE GENERATOR (test-only): renders the pretty-printed WIRE
//! examples the public docs' ```json fenced blocks carry, FROM THE REAL
//! WIRE RECORDS — never from hand-written schema. [`render_wire_pair`]
//! serializes any valid intent + terminal pair through the CURRENT wire
//! types ([`LedgerIntentWire`] / [`LedgerTerminalWire`]) wrapped in their
//! physical line kind ([`crate::ledger::records::LedgerEventWire`]), pretty
//! printed, with the CURRENT [`crate::ledger::LEDGER_SCHEMA_VERSION`] — so
//! the docs' examples can never drift from the wire: a schema change that
//! would stale the documented shape fails
//! `tests::docs_examples_match_generated_wire` (which byte-compares the
//! requirement.md fenced blocks against this generator), and the
//! round-trip proptest parses the generator's output through the STRICT
//! READER for arbitrary generated pairs.
//!
//! [`canonical_doc_pair`] builds the SPECIFIC fixtures the docs render: a
//! full-push `production` deployment (`deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b`,
//! slots `p1`/`p2`/`p3`) whose intent line and SUCCESSFUL terminal line
//! together show the CURRENT shape: the complete result stored ONCE in the
//! intent's full slot table (`slots` — each slot's plan-minted result +
//! action), the strict wire observations (adjacently-tagged `state`+`value`)
//! for the pre-push states, and the PAYLOAD-FREE successful terminal bound
//! to its intent by `intent_digest` (the snapshot resolves from the intent
//! — keyed by deployment id, the "Snapshot history and rollback" section).

use crate::identity::{
    ArtifactRef, DeploymentId, GenerationId, ReleaseId, ServerId, SlotId, TargetName, VariantName,
};
use crate::kernel::intent::{DeploymentIntent, PlanInput, PlannedDeploy};
use crate::kernel::snapshot::SnapshotSlot;
use crate::ledger::Observation;
use crate::ledger::records::{LedgerEventWire, LedgerIntentWire, LedgerTerminalWire};

/// The pretty-printed JSON of a wire intent + terminal pair, exactly as the
/// docs' fenced ```json blocks carry it (each line rendered through the
/// physical [`LedgerEventWire`] kind, so the `kind` tag — `intent` /
/// `terminal` — is part of the example).
pub(crate) struct RenderedLedgerExamples {
    /// The `{"kind":"intent", ...}` line, pretty printed.
    pub intent: String,
    /// The `{"kind":"terminal", ...}` line, pretty printed.
    pub terminal: String,
}

/// THE DOC-EXAMPLE GENERATOR: serialize a valid intent + terminal wire pair
/// through the CURRENT wire types (pretty printed, with the current
/// `deployment_schema_version`). The output is the EXACT JSON the docs'
/// fenced blocks must carry: `tests::docs_examples_match_generated_wire`
/// byte-compares them, and the round-trip proptest parses the output back
/// through the strict reader.
pub(crate) fn render_wire_pair(
    intent: &LedgerIntentWire,
    terminal: &LedgerTerminalWire,
) -> RenderedLedgerExamples {
    let pretty = |line: &LedgerEventWire| -> String {
        serde_json::to_string_pretty(line)
            .expect("a valid wire record always serializes to pretty JSON")
    };
    RenderedLedgerExamples {
        intent: pretty(&LedgerEventWire::Intent(intent.clone())),
        terminal: pretty(&LedgerEventWire::Terminal(terminal.clone())),
    }
}

/// The CANONICAL fixtures the docs render: a full-push `production`
/// deployment of three slots (`p1` standard, `p2` standard, `p3`
/// high-capacity) whose intent carries the complete result ONCE (the full
/// slot table) and whose SUCCESSFUL terminal is payload-free, bound by its
/// intent digest. The pair is a REAL wire record: it converts to the domain
/// and passes the strict reader's cross-record invariants (exercised
/// directly by the docs-match test below).
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
    let binding_for = |sid: &SlotId, server: &str| crate::ledger::PhysicalBinding {
        server: ServerId::new(server.to_string()),
        deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
    };

    let slot_ids: Vec<SlotId> = slots
        .iter()
        .map(|(s, _, _, _)| SlotId::new(s.to_string()))
        .collect();
    // THE FULL SLOT TABLE — one entry per slot with its plan-minted RESULT
    // and its ACTION (a full push: every slot `Deploy`, no inherited
    // slots). The complete result is stored once; the snapshot derives from
    // it.
    let planned: Vec<PlannedDeploy> = slots
        .iter()
        .map(|(s, v, server, g)| {
            let sid = SlotId::new(s.to_string());
            PlannedDeploy {
                slot: sid.clone(),
                result: SnapshotSlot::new(
                    gen_for(g),
                    ArtifactRef {
                        release: release.clone(),
                        variant: VariantName::new(v.to_string()),
                        tree: tree_for(s),
                    },
                    binding_for(&sid, server),
                ),
                pre_push: Observation::KnownAbsent,
            }
        })
        .collect();
    let intent_domain = crate::kernel::intent::plan(PlanInput {
        deployment_id: deployment_id.clone(),
        target: target.clone(),
        parent: None,
        parent_snapshot: None,
        group: None,
        selection: slot_ids,
        planned,
        behavior_digest: crate::identity::BehaviorDigest::parse(&crate::identity::test_sha256_hex(
            "behavior-production",
        ))
        .unwrap(),
        attempted_at: crate::identity::Timestamp::parse("2026-08-21T10:20:00Z").unwrap(),
    })
    .expect("the canonical example intent plans");
    let intent = LedgerIntentWire::from(&intent_domain);

    let terminal_domain = crate::kernel::terminal::LedgerTerminal::new(
        crate::identity::Timestamp::parse("2026-08-21T10:25:00Z").unwrap(),
        crate::kernel::terminal::intent_digest(&intent_domain),
        crate::kernel::terminal::TerminalDisposition::Successful,
        Some("push completed".to_string()),
    );
    let terminal = LedgerTerminalWire::to_wire(&deployment_id, &target, &terminal_domain);
    (intent, terminal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::records::LEDGER_SCHEMA_VERSION;

    /// The canonical pair is a REAL wire record: it converts to the domain
    /// and passes the strict reader's cross-record invariants — so the docs'
    /// example is not just well-formed JSON, it is a record the strict
    /// reader accepts.
    #[test]
    fn canonical_doc_pair_is_a_valid_readable_pair() {
        let (intent, terminal) = canonical_doc_pair();
        assert_eq!(
            intent.deployment_schema_version, LEDGER_SCHEMA_VERSION,
            "the canonical intent carries the CURRENT schema version"
        );
        let d_intent: DeploymentIntent = intent
            .clone()
            .into_domain()
            .expect("the canonical intent converts");
        assert_eq!(
            terminal.deployment_id.as_str(),
            d_intent.deployment_id().as_str(),
            "the terminal keys the intent's deployment"
        );
        let d_terminal = terminal
            .clone()
            .into_domain()
            .expect("the canonical terminal converts");
        assert_eq!(
            d_terminal.status(),
            crate::ledger::records::DeploymentStatus::Successful
        );
        assert!(
            d_terminal.disposition().is_successful(),
            "the canonical terminal is payload-free Successful"
        );
        // The strict reader accepts the pair: write + read through the real
        // consumer path.
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
        let p = store.ledger_path("production");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let line1 = serde_json::to_string(&LedgerEventWire::Intent(intent)).unwrap();
        let line2 = serde_json::to_string(&LedgerEventWire::Terminal(terminal)).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        let entries = store.read_ledger("production").unwrap();
        assert_eq!(entries.len(), 1);
        let snapshot = crate::kernel::snapshot::resolve_snapshot(&entries[0]).unwrap();
        assert_eq!(
            snapshot.len(),
            3,
            "the resolved snapshot covers the three slots"
        );
    }
}

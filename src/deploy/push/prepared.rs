//! THE SEALED PREPARED DEPLOYMENT — the ONE value the push execution
//! consumes. The engine persists a [`DeploymentIntent`] (the durable record
//! of what a push intends to do) and then derives EVERY execution input
//! from that value — never from the preflight outcome or a re-parse of the
//! intent. [`PreparedDeployment`] owns EXACTLY ONE [`DeploymentIntent`]
//! (private fields, no public unchecked constructor — the only construction
//! paths validate) and exposes the execution inputs as PROJECTIONS of it:
//!
//! * **execution requirements** — [`PreparedDeployment::execution_requests`]:
//!   the per-slot execution request (artifact, minted generation, expected
//!   pre-push generation, the frozen behavior contract + its digest) the
//!   mutation loop drives [`crate::deploy::rollout::process_server`] with;
//! * **plan rendering** — [`PreparedDeployment::plan_rendering`]: the
//!   dry-run current → desired lines, rendered from the intent's
//!   assignments + generations projections;
//! * **assignments** — [`PreparedDeployment::assignments`]: the per-slot
//!   `placement_slot → artifact` assignments, derived from the selected
//!   slots' plan-minted results;
//! * **generations** — [`PreparedDeployment::generations`]: the freshly
//!   minted desired generation per selected slot, derived from the results;
//! * **expected states** — [`PreparedDeployment::expected_states`]: the
//!   per-slot [`SlotPlan`] (artifact + the compare-and-swap expected
//!   generation), derived from the results and the intent's OWN pre-push
//!   observations.
//!
//! The behavior index ([`PreparedDeployment::behaviors`]) is the ONE
//! execution input the intent cannot carry inline (the intent freezes only
//! its canonical digest, [`DeploymentIntent::behavior_digest`]); the sealed
//! constructor VALIDATES that the carried index's digest equals the
//! intent's digest AND that the index covers every selected slot's
//! (release, variant) — so the execution can never run against a different
//! index than the intent froze, and a prepared deployment whose index lacks
//! a planned slot's contract is unrepresentable.
//!
//! PERSIST → RELOAD/RETAIN → EXECUTE PROJECTIONS: the intent is persisted
//! (the ledger's [`LedgerIntentWire`]); the prepared deployment is either
//! RETAINED in memory (the main push path) or RELOADED from the wire
//! ([`PreparedDeployment::from_wire`] — the recovery path). Both produce
//! the SAME execution requests: the round-trip property
//! ([`prepared_tests::execution_requests_identical_after_persistence_round_trip`])
//! serializes any prepared deployment, reloads it, and asserts every
//! generated execution request is IDENTICAL before and after persistence.

use crate::deploy::plan::PlannedAssignment;
use crate::error::{Error, Result};
use crate::identity::{ArtifactRef, BehaviorContract, GenerationId, SlotId};
use crate::kernel::intent::{DeploymentIntent, SlotAction};
#[cfg(test)]
use crate::ledger::LedgerIntentWire;
use crate::ledger::{BehaviorIndex, Observation, SlotPlan};
use crate::remote::helper::RemoteStatus;
use crate::store::local::LocalStore;
#[cfg(test)]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// THE ONE PER-SLOT EXECUTION REQUEST of a prepared deployment: everything
/// the mutation loop needs to drive one slot's publication — the artifact,
/// the freshly minted generation, the compare-and-swap expected pre-push
/// generation, and the slot's OWN frozen behavior contract (resolved from
/// the intent's behavior index by the slot's (release, variant) binding)
/// plus its canonical digest. DERIVED from the intent's slot table + the
/// validated behavior index; the round-trip property asserts these are
/// byte-identical before and after persistence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExecutionRequest {
    pub slot: SlotId,
    pub artifact: ArtifactRef,
    pub generation: GenerationId,
    pub expected_generation: Option<GenerationId>,
    pub behavior: BehaviorContract,
    pub behavior_sha256: String,
}

/// THE SEALED PREPARED DEPLOYMENT: owns EXACTLY ONE [`DeploymentIntent`]
/// (the durable record) plus the validated behavior index the intent's
/// digest commits to. The fields are PRIVATE and the construction paths
/// ([`PreparedDeployment::new`], [`PreparedDeployment::from_wire`]) are the
/// ONLY ways to build one — every one validates the intent↔index agreement,
/// so a prepared deployment whose execution inputs could disagree with the
/// persisted intent is unrepresentable. All execution inputs are PROJECTIONS
/// of the intent (see the module docs); nothing is re-derived from the
/// preflight outcome or re-parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedDeployment {
    intent: DeploymentIntent,
    behaviors: BehaviorIndex,
}

impl PreparedDeployment {
    /// THE ONLY CONSTRUCTION PATH (validated): wraps the intent with the
    /// behavior index the execution resolves per-slot contracts from. The
    /// intent FREEZES the index's canonical digest
    /// ([`DeploymentIntent::behavior_digest`]); a carried index whose
    /// digest disagrees is REFUSED (the execution can never run against a
    /// different index than the intent froze), and an index that lacks a
    /// selected slot's (release, variant) contract is REFUSED (the
    /// execution resolves every slot's contract from it — a prepared
    /// deployment whose index cannot serve a planned slot is
    /// unrepresentable). The intent itself is already validated by the
    /// kernel's constructor ([`crate::kernel::intent::plan`]) or the
    /// verifying wire conversion ([`LedgerIntentWire::into_domain`]); the
    /// non-empty-selection re-check keeps the sealed wrapper uncorruptible
    /// by construction.
    pub(crate) fn new(intent: DeploymentIntent, behaviors: BehaviorIndex) -> Result<Self> {
        let digest = crate::verify::release::behavior_index_digest(&behaviors);
        if digest != intent.behavior_digest().as_str() {
            return Err(Error::integrity(format!(
                "prepared deployment {}: the behavior index digest {digest} disagrees with the intent's behavior_sha256 {}",
                intent.deployment_id(),
                intent.behavior_digest()
            )));
        }
        if intent.selected_membership().is_empty() {
            return Err(Error::integrity(format!(
                "prepared deployment {}: the intent selects no slot",
                intent.deployment_id()
            )));
        }
        for (slot, p) in intent.selected() {
            let artifact = p.result().artifact();
            let covered = behaviors
                .get(&artifact.release)
                .is_some_and(|m| m.contains_key(artifact.variant.as_str()));
            if !covered {
                return Err(Error::integrity(format!(
                    "prepared deployment {}: the behavior index lacks a contract for slot '{}' variant '{}' of release {} — every selected slot's (release, variant) must be covered",
                    intent.deployment_id(),
                    slot,
                    artifact.variant,
                    artifact.release
                )));
            }
        }
        Ok(PreparedDeployment { intent, behaviors })
    }

    /// RELOAD from the wire (the persisted intent + the persisted behavior
    /// index): the verifying wire → domain conversion
    /// ([`LedgerIntentWire::into_domain`]) scalar-gates every intent field,
    /// then the sealed constructor re-validates the intent↔index agreement.
    /// The recovery path rebuilds the prepared deployment from the durable
    /// record this way; the round-trip property proves the reloaded value
    /// generates the IDENTICAL execution requests. TEST-EXERCISED today
    /// (the main push path retains the value in memory) — see
    /// [`PreparedDeploymentWire`].
    #[cfg(test)]
    pub(crate) fn from_wire(wire: PreparedDeploymentWire) -> Result<Self> {
        let intent = wire.intent.into_domain()?;
        Self::new(intent, wire.behaviors)
    }

    /// The ONE durable intent this prepared deployment owns.
    pub(crate) fn intent(&self) -> &DeploymentIntent {
        &self.intent
    }

    /// The validated behavior index the intent's digest commits to — the
    /// execution requirements' contract source. TEST-EXERCISED today (the
    /// wire form's `From` projection reads it; the production projections
    /// read the field directly).
    #[cfg(test)]
    pub(crate) fn behaviors(&self) -> &BehaviorIndex {
        &self.behaviors
    }

    /// THE ASSIGNMENTS PROJECTION: the per-slot `placement_slot → artifact`
    /// assignments, DERIVED from the selected slots' plan-minted results
    /// (in deployment order — the intent's slot-table insertion order).
    pub(crate) fn assignments(&self) -> Vec<PlannedAssignment> {
        self.intent
            .selected()
            .map(|(slot, p)| PlannedAssignment {
                placement_slot: slot,
                artifact: p.result().artifact().clone(),
            })
            .collect()
    }

    /// THE GENERATIONS PROJECTION: the freshly minted desired generation
    /// per selected slot, DERIVED from the selected slots' plan-minted
    /// results.
    pub(crate) fn generations(&self) -> HashMap<SlotId, GenerationId> {
        self.intent
            .selected()
            .map(|(slot, p)| (slot, p.result().generation().clone()))
            .collect()
    }

    /// THE EXPECTED-STATES PROJECTION: the per-slot [`SlotPlan`] (the
    /// artifact + the compare-and-swap expected pre-push generation),
    /// DERIVED from the selected slots' results and the intent's OWN
    /// pre-push observations — a `Known` pre-push generation is the
    /// expected generation; `KnownAbsent`/`Unknown` (and an inherited slot)
    /// carry `None` (the CAS precondition is absent).
    pub(crate) fn expected_states(&self) -> BTreeMap<SlotId, SlotPlan> {
        self.intent
            .selected()
            .map(|(slot, p)| {
                let expected_generation = match p.action() {
                    SlotAction::Deploy { pre_push } => match pre_push {
                        Observation::Known(prev) => Some(prev.generation.clone()),
                        _ => None,
                    },
                    SlotAction::Inherit => None,
                };
                (
                    slot.clone(),
                    SlotPlan {
                        slot_id: slot,
                        artifact: p.result().artifact().clone(),
                        expected_generation,
                    },
                )
            })
            .collect()
    }

    /// THE DEPLOYMENT-ORDER PROJECTION: the selected slots in the intent's
    /// slot-table insertion order (the deployment order the batch loop
    /// follows) — DERIVED from the assignments projection.
    pub(crate) fn servers_order(&self) -> Vec<SlotId> {
        self.assignments()
            .into_iter()
            .map(|a| a.placement_slot)
            .collect()
    }

    /// THE PLAN-RENDERING PROJECTION: the dry-run current → desired lines
    /// (plus the would-recover notes and the first-deployment lines),
    /// rendered from the intent's assignments + generations projections and
    /// the observed pre-push statuses — the same pure rendering the
    /// dry-run path reports, sourced from the intent rather than the
    /// preflight outcome.
    pub(crate) fn plan_rendering(
        &self,
        store: &LocalStore,
        statuses: &HashMap<SlotId, RemoteStatus>,
    ) -> String {
        crate::deploy::push::render_dry_run_plan(
            store,
            &self.assignments(),
            statuses,
            &self.generations(),
        )
    }

    /// THE EXECUTION-REQUIREMENTS PROJECTION: every per-slot execution
    /// request the mutation loop drives — the artifact, the minted
    /// generation, the expected pre-push generation, and the slot's OWN
    /// frozen behavior contract + digest. The sealed constructor validated
    /// the index covers every selected slot's (release, variant), so the
    /// per-slot contract lookup cannot miss in practice; the `Result`
    /// keeps the failure graceful (an integrity error naming the slot)
    /// rather than a panic.
    pub(crate) fn execution_requests(&self) -> Result<Vec<ExecutionRequest>> {
        let assignments = self.assignments();
        let generations = self.generations();
        let expected = self.expected_states();
        let mut out = Vec::with_capacity(assignments.len());
        for a in &assignments {
            let behavior = self
                .behaviors
                .get(&a.artifact.release)
                .and_then(|m| m.get(a.artifact.variant.as_str()))
                .ok_or_else(|| {
                    Error::integrity(format!(
                        "prepared deployment {}: no behavior contract for slot '{}' variant '{}' of release {} — the sealed constructor requires the index to cover every selected slot",
                        self.intent.deployment_id(),
                        a.placement_slot,
                        a.artifact.variant,
                        a.artifact.release
                    ))
                })?;
            out.push(ExecutionRequest {
                slot: a.placement_slot.clone(),
                artifact: a.artifact.clone(),
                generation: generations[&a.placement_slot].clone(),
                expected_generation: expected[&a.placement_slot].expected_generation.clone(),
                behavior: behavior.clone(),
                behavior_sha256: crate::verify::release::behavior_contract_digest(behavior),
            });
        }
        Ok(out)
    }
}

/// THE WIRE FORM of a prepared deployment: the persisted intent
/// ([`LedgerIntentWire`] — the ledger's durable line, schema-compatible)
/// plus the persisted behavior index (the plan's `behaviors` collection the
/// intent's digest commits to). The round-trip property serializes this
/// shape and reloads it through [`PreparedDeployment::from_wire`].
///
/// TEST-EXERCISED RELOAD PATH: the main push path RETAINS the prepared
/// deployment in memory (the intent is persisted, the value is kept); the
/// reload path ([`PreparedDeployment::from_wire`]) is the recovery-style
/// reconstruction the round-trip property proves generates the IDENTICAL
/// execution requests. Both are `#[cfg(test)]` today because no production
/// path executes a reloaded intent (recovery finalizes without executing);
/// a future execution-from-recovery feature lifts the cfg.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedDeploymentWire {
    pub intent: LedgerIntentWire,
    pub behaviors: BehaviorIndex,
}

#[cfg(test)]
impl From<&PreparedDeployment> for PreparedDeploymentWire {
    fn from(p: &PreparedDeployment) -> Self {
        PreparedDeploymentWire {
            intent: LedgerIntentWire::from(p.intent()),
            behaviors: p.behaviors().clone(),
        }
    }
}

#[cfg(test)]
pub(crate) mod prepared_tests {
    //! THE PERSISTENCE-ROUND-TRIP PROPERTY: serialize any prepared
    //! deployment, reload it, and assert that EVERY generated execution
    //! request is IDENTICAL before and after persistence.

    use super::*;
    use crate::config::{Activation, ValidatedCommand, Verification};
    use crate::identity::{
        BehaviorDigest, TargetName, Timestamp, VariantName, test_deployment_id, test_generation_id,
        test_release_id, test_tree_digest,
    };
    use crate::kernel::intent::{PlanInput, PlannedDeploy};
    use crate::kernel::snapshot::{PreviousGeneration, SnapshotSlot};
    use crate::testutil::fixtures::binding;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// An arbitrary behavior index: 1-3 releases, each with 1-2 variants,
    /// each with a deterministic contract (per release/variant index).
    fn arbitrary_index() -> impl Strategy<Value = BehaviorIndex> {
        prop::collection::vec((0u32..3, 0u32..2), 1..=3).prop_map(|pairs| {
            let mut index = BehaviorIndex::new();
            for (ri, vi) in pairs {
                let release = test_release_id(&format!("rel-{ri}"));
                let variant = format!("variant-{vi}");
                let contract = BehaviorContract::new(
                    Activation::None,
                    Verification::Command(
                        ValidatedCommand::new(vec![format!("true-{ri}-{vi}")], 5, 1, 0)
                            .expect("validated command"),
                    ),
                );
                index.entry(release).or_default().insert(variant, contract);
            }
            index
        })
    }

    /// An arbitrary pre-push observation for a planned slot: `KnownAbsent`
    /// (never deployed) or a `Known` prior generation/artifact.
    fn arbitrary_pre_push() -> impl Strategy<Value = Observation<PreviousGeneration>> {
        prop_oneof![
            Just(Observation::KnownAbsent),
            (0u32..4).prop_map(|i| Observation::Known(PreviousGeneration {
                generation: test_generation_id(&format!("prior-{i}")),
                artifact: ArtifactRef {
                    release: test_release_id(&format!("prior-rel-{i}")),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest(&format!("prior-tree-{i}")),
                },
            })),
        ]
    }

    /// An arbitrary PREPARED DEPLOYMENT: a behavior index, then an intent
    /// whose behavior digest is the index's canonical digest and whose
    /// selected slots reference (release, variant) pairs covered by the
    /// index (the sealed constructor's coverage rule). The intent is built
    /// through the kernel's validated constructor — the domain types cannot
    /// be struct-literal-constructed.
    fn arbitrary_prepared() -> impl Strategy<Value = PreparedDeployment> {
        arbitrary_index().prop_flat_map(|index| {
            let pairs: Vec<(crate::identity::ReleaseId, VariantName)> = index
                .iter()
                .flat_map(|(r, m)| {
                    m.keys()
                        .map(move |v| (r.clone(), VariantName::parse(v).unwrap()))
                })
                .collect();
            let digest = crate::verify::release::behavior_index_digest(&index);
            prop::collection::vec(0..pairs.len() as u32, 1..=4).prop_flat_map(move |choices| {
                let n = choices.len();
                // The `Fn` closure may run more than once, so each
                // captured value is cloned per invocation before the
                // inner `prop_map` closure moves it.
                let pairs = pairs.clone();
                let digest = digest.clone();
                let index = index.clone();
                prop::collection::vec(arbitrary_pre_push(), n).prop_map(move |pre_push| {
                    let slots: Vec<SlotId> = (0..n).map(|i| SlotId::new(format!("p{i}"))).collect();
                    let planned: Vec<PlannedDeploy> = choices
                        .iter()
                        .enumerate()
                        .map(|(i, &ci)| {
                            let (release, variant) = &pairs[ci as usize];
                            PlannedDeploy {
                                slot: slots[i].clone(),
                                result: SnapshotSlot::new(
                                    test_generation_id(&format!("gen-{i}")),
                                    ArtifactRef {
                                        release: release.clone(),
                                        variant: variant.clone(),
                                        tree: test_tree_digest(&format!("tree-{i}")),
                                    },
                                    binding(&slots[i]),
                                ),
                                pre_push: pre_push[i].clone(),
                            }
                        })
                        .collect();
                    let intent = crate::kernel::intent::plan(PlanInput {
                        deployment_id: test_deployment_id("prepared-prop"),
                        target: TargetName::parse("t1").unwrap(),
                        parent: None,
                        parent_snapshot: None,
                        group: None,
                        selection: slots.clone(),
                        planned,
                        behavior_digest: BehaviorDigest::parse(&digest).unwrap(),
                        attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
                    })
                    .expect("a valid prepared-deployment intent plans");
                    PreparedDeployment::new(intent, index.clone())
                        .expect("the prepared deployment validates")
                })
            })
        })
    }

    proptest! {
        // THE PERSISTENCE-ROUND-TRIP PROPERTY: serialize any prepared
        // deployment (its intent + behavior index), reload it through the
        // verifying wire conversion, and assert that EVERY generated
        // execution request is IDENTICAL before and after persistence.
        // Bounded `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`,
        // fast default), fixed seed 0x5EED_5EED (house style), no
        // persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn execution_requests_identical_after_persistence_round_trip(
            prepared in arbitrary_prepared(),
        ) {
            let before = prepared
                .execution_requests()
                .expect("the sealed constructor guarantees the requests generate");
            let wire = PreparedDeploymentWire::from(&prepared);
            let bytes = serde_json::to_vec(&wire).expect("a prepared deployment always serializes");
            let reloaded_wire: PreparedDeploymentWire =
                serde_json::from_slice(&bytes).expect("a serialized prepared deployment reloads");
            let reloaded = PreparedDeployment::from_wire(reloaded_wire)
                .expect("the reloaded prepared deployment validates");
            let after = reloaded
                .execution_requests()
                .expect("the sealed constructor guarantees the requests generate");
            assert_eq!(
                before, after,
                "every generated execution request must be IDENTICAL before and after persistence"
            );
        }
    }
}

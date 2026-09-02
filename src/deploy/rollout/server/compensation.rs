//! Per-slot prior-generation restore: [`compensate_server`] re-installs the
//! previous generation on a slot whose swap/activate failed.

use crate::config::Activation;
use crate::error::Error;
use crate::error::Result;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::remote::helper::HeldSlotLock;
use crate::remote::layout;
use crate::verify::adapters::transaction::VerifiedAdapterRestoration;
use crate::verify::command::run_verification;

// PER-SLOT COMPENSATION (A1 step 11): restore the prior generation after a
// failed activation/verification (or remove `current` on a first deploy),
// re-running the PRIOR generation's stored behavior contract with the PRIOR
// assignment's identity, and only while `current` still names the generation
// the failed push advanced (compare-and-swap). Consumed by the per-server
// process ([`process_server`]) and by the
// failure-policy pass (failure section).
//
// THE ADAPTER-RESTORATION EVIDENCE (the review's P1 fix): the compensation
// is complete ONLY when the mutating adapter's side effects are VERIFIED
// restored — the installed units are READ BACK against the prior contract's
// rendered content (and any advanced-only unit is proven absent) via
// [`verify_adapter_restored`](crate::verify::systemd::verify_adapter_restored),
// producing the sealed
// [`VerifiedAdapterRestoration`](crate::verify::adapters::transaction::VerifiedAdapterRestoration)
// proof the [`CompensationOutcome::Restored`] carries. A slot whose adapter
// restoration is NOT verified is `Refused` (the slot stays on the advanced
// generation → `FailedAfterAdvance` → Degraded), never a rolled-back
// candidate.

/// Pure input data for compensation. The helper, transport and remote root
/// are derived from the held guard — never passed independently.
#[derive(Clone, Debug)]
pub(crate) struct CompensationRequest {
    pub op_id: OperationId,
    pub prior_gen: Option<GenerationId>,
    pub advanced_gen: GenerationId,
    pub template_vars: crate::remote::canonical::TemplateVars,
    /// The expected OWNER of this slot's remote generations: compensation
    /// reads the prior generation's assignment and must verify its owner
    /// marker (fail closed on transplanted state).
    pub owner: crate::remote::helper::GenerationOwner,
}

/// THE COMPENSATION OUTCOME: either the slot was FULLY restored — the
/// GENERATION (CAS back to the prior generation / removed on a first
/// deploy) AND the adapter's side effects, with the VERIFIED-adapter-
/// restoration proof ([`VerifiedAdapterRestoration`]) — or the compensation
/// REFUSED (current no longer names the advanced generation, the prior
/// contract is unavailable, or any restore step failed / was NOT verified:
/// the slot stays on the advanced generation). The OLD `bool` is GONE: a
/// "restored" compensation must PROVE the adapter restoration, not just
/// claim it.
pub(crate) enum CompensationOutcome {
    /// The slot was fully restored; `adapter_restored` is the sealed proof
    /// (produced by a successful READ-BACK verification of the adapter's
    /// restored side effects) and `restoration` is the [`RestorationProof`]
    /// evidence of the generation restoration (the restored generation, or
    /// `None` for a first-deploy removal of `current`).
    Restored {
        adapter_restored: VerifiedAdapterRestoration,
        restoration: crate::remote::helper::RestorationProof,
    },
    /// The compensation refused (CAS failure / unverified restoration): the
    /// slot stays on the advanced generation.
    Refused,
}

/// Load the behavior contract of a generation's stored assignment (its
/// release + variant) — used to learn the ADVANCED contract's declared units
/// (the side effects a compensation back to the PRIOR state must remove and
/// verify absent).
fn load_generation_behavior(
    helper: &crate::remote::helper::RemoteHelper,
    gid: &crate::identity::GenerationId,
    owner: &crate::remote::helper::GenerationOwner,
) -> Result<crate::identity::BehaviorContract> {
    let assignment = helper.read_assignment(gid, owner).map_err(|e| {
        Error::remote(format!(
            "compensation: read assignment of '{gid}' failed: {e}"
        ))
    })?;
    helper
        .read_behavior(&assignment.artifact.release, &assignment.artifact.variant)
        .map_err(|e| {
            Error::remote(format!(
                "compensation: behavior of '{gid}' unavailable: {e}"
            ))
        })
}

/// Restore the prior generation (or remove `current` on first deploy). Uses the
/// prior generation's stored behavior contract rather than the caller's current
/// configuration. `advanced_gen` is the generation this slot was just advanced
/// to; it is used as the compare-and-swap precondition so a concurrent
/// controller cannot have its `current` clobbered. `template_vars` supplies the
/// slot context (deploy_dir, application, ...); the VARIANT is overridden with
/// the prior assignment's variant, because compensation re-runs the PRIOR
/// generation's contract. Returns the compensation outcome: a FULL restoration
/// (generation + ADAPTER side effects, the latter VERIFIED by a read-back)
/// or a refusal — never a bare "true".
pub(crate) fn compensate_server_locked(
    held: &HeldSlotLock<'_>,
    request: &CompensationRequest,
) -> Result<CompensationOutcome> {
    let helper = held.helper();
    let remote = helper.remote();
    match &request.prior_gen {
        Some(prior) => {
            // Load the prior generation's behavior contract from the remote.
            // The read VERIFIES the generation's OWNER MARKER against the
            // expected owner: a prior generation transplanted from another
            // application/slot is refused (never compensated onto).
            let prior_assignment = match helper.read_assignment(prior, &request.owner) {
                Ok(a) => a,
                Err(_) => return Ok(CompensationOutcome::Refused),
            };
            // Load the prior generation's behavior contract from the remote. If it
            // is unavailable we cannot verify what we are restoring, so we must
            // not pretend restoration succeeded by substituting a default
            // contract: report the failure so the attempt is marked Degraded.
            let prior_behavior = helper
                .read_behavior(
                    &prior_assignment.artifact.release,
                    &prior_assignment.artifact.variant,
                )
                .map_err(|e| {
                    Error::remote(format!("compensation: prior behavior unavailable: {e}"))
                })?;
            // Compare-and-swap: only roll back if `current` still points at the
            // generation we just activated. Otherwise another controller changed
            // it and we must not clobber their state.
            if held
                .swap_current(
                    &crate::remote::helper::ExpectedCurrent::Generation(
                        request.advanced_gen.clone(),
                    ),
                    prior,
                    request.op_id.as_str(),
                )
                .is_err()
            {
                return Ok(CompensationOutcome::Refused);
            }
            let root = remote.root().join(layout::generation(prior)).join("root");
            // Re-run prior activation contract + verification. A failure means the
            // service was not actually restored to prior behavior, so propagate
            // it as a compensation failure (the attempt is marked Degraded).
            // The prior contract is rendered with the PRIOR assignment: its own
            // release (the immutable ReleaseId), variant, tree, AND the prior
            // deployment identity (`deployment_id`/`generation`) move together
            // via `with_assignment`, so a restored slot never renders a torn
            // combination (e.g. the prior variant with the desired release, or
            // the prior artifact with the failed generation's deployment id).
            let prior_vars = request.template_vars.with_assignment(&prior_assignment);
            // THE ADAPTER-RESTORATION EVIDENCE (the review's P1 fix): the
            // advanced contract's units that the prior contract does not
            // declare must be REMOVED (the prior state has them ABSENT) and
            // the prior units VERIFIED back at their rendered content — the
            // sealed proof a `Restored` execution must carry. The unit-file
            // restore runs BEFORE the prior verification health check.
            let advanced_behavior =
                load_generation_behavior(helper, &request.advanced_gen, &request.owner)?;
            let advanced_units =
                crate::verify::systemd::declared_user_units(advanced_behavior.activation());
            let prior_units =
                crate::verify::systemd::declared_user_units(prior_behavior.activation());
            let advanced_only_units: Vec<String> = advanced_units
                .iter()
                .filter(|n| !prior_units.iter().any(|p| p == *n))
                .cloned()
                .collect();
            crate::verify::systemd::restore_adapter_to(
                remote,
                &root,
                prior_behavior.activation(),
                &prior_vars,
                &advanced_only_units,
            )
            .map_err(|e| Error::remote(format!("compensation adapter restore failed: {e}")))?;
            let adapter_restored = crate::verify::systemd::verify_adapter_restored(
                remote,
                &root,
                prior_behavior.activation(),
                &prior_vars,
                &advanced_only_units,
            )
            .map_err(|e| {
                Error::remote(format!("compensation adapter restore NOT verified: {e}"))
            })?;
            run_verification(remote, prior_behavior.verification(), &prior_vars)
                .map_err(|e| Error::remote(format!("compensation verification failed: {e}")))?;
            Ok(CompensationOutcome::Restored {
                adapter_restored,
                restoration: crate::remote::helper::RestorationProof::restored(Some(prior.clone())),
            })
        }
        None => {
            // First deploy: remove `current` only if it still points at the
            // generation we advanced (compare-and-swap style).
            if !held
                .remove_current_if(&crate::remote::helper::ExpectedCurrent::Generation(
                    request.advanced_gen.clone(),
                ))
                .unwrap_or(false)
            {
                return Ok(CompensationOutcome::Refused);
            }
            // THE ADAPTER-RESTORATION EVIDENCE: the prior adapter state of a
            // first deploy is ABSENT — the advanced contract's installed units
            // are removed and their absence VERIFIED by reading the remote.
            let advanced_behavior =
                load_generation_behavior(helper, &request.advanced_gen, &request.owner)?;
            let advanced_units =
                crate::verify::systemd::declared_user_units(advanced_behavior.activation());
            crate::verify::systemd::restore_adapter_to(
                remote,
                remote.root(),
                &Activation::None,
                &request.template_vars,
                &advanced_units,
            )
            .map_err(|e| Error::remote(format!("compensation adapter restore failed: {e}")))?;
            let adapter_restored = crate::verify::systemd::verify_adapter_restored(
                remote,
                remote.root(),
                &Activation::None,
                &request.template_vars,
                &advanced_units,
            )
            .map_err(|e| {
                Error::remote(format!("compensation adapter restore NOT verified: {e}"))
            })?;
            Ok(CompensationOutcome::Restored {
                adapter_restored,
                restoration: crate::remote::helper::RestorationProof::restored(None),
            })
        }
    }
}

/// External wrapper: acquires the slot mutation lock ONCE, calls
/// `compensate_server_locked`, and drops the guard at the end. An acquire
/// failure is swallowed as `Refused` (slot stays advanced → attempt Degraded).
pub(crate) fn compensate_server(
    helper: &crate::remote::helper::RemoteHelper,
    request: &CompensationRequest,
) -> Result<CompensationOutcome> {
    // The mutation capability is the SLOT-BOUND [`SlotRemote`]: acquisition
    // returns a guard carrying the slot's owner (the same owner the request
    // carries for its reads).
    let slot_remote = crate::remote::helper::SlotRemote::new(helper, request.owner.clone());
    let guard = match slot_remote.acquire_lock_guard(&request.op_id) {
        Ok(g) => g,
        Err(_) => return Ok(CompensationOutcome::Refused),
    };
    compensate_server_locked(&guard, request)
}

#[cfg(test)]
mod compensation_tests {
    use super::*;
    use crate::deploy::rollout::server::server_tests::{
        Harness, NONE_TOML, NONE_VARIANT, SYSTEMD_TOML, SYSTEMD_VARIANT,
    };
    use crate::deploy::rollout::*;
    use crate::identity::{ArtifactRef, DeploymentId, TreeDigest, VariantName, test_deployment_id};
    use std::os::unix::fs::PermissionsExt;

    /// Compensation re-runs the PRIOR generation's activation contract with the
    /// PRIOR assignment's identity: the unit it installs renders the PRIOR
    /// immutable release id (`{{ release }}`), variant, tree, AND the prior
    /// deployment identity (`{{ deployment_id }}`/`{{ generation }}`) — never a
    /// torn mix of the desired release with the prior variant, and never the
    /// failed generation's deployment id. This pins the
    /// `TemplateVars::with_assignment` path through the real systemd adapter.
    #[test]
    fn compensation_renders_prior_artifact_release_id() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fake_linger = bindir.join("loginctl");
        std::fs::write(&fake_linger, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake_linger, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        // Hermetic env: fake systemctl on PATH, temp config home — children
        // receive this snapshot; the parent process env is never touched.
        let base = crate::testutil::fixture_env();
        let mut vars: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
            base.child_env().into_iter().collect();
        vars.insert(
            "PATH".into(),
            format!(
                "{}:{}",
                bindir.display(),
                base.path()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default()
            )
            .into(),
        );
        vars.insert("XDG_CONFIG_HOME".into(), config_home.as_os_str().to_owned());
        let env = crate::env::SysEnv::from_map(vars);

        let outcome = (|| {
            let h = Harness::new(
                &env,
                SYSTEMD_TOML,
                SYSTEMD_VARIANT,
                &[
                    ("build/output/app/server", "v1"),
                    ("deployment/common/README", "common"),
                    (
                        "units/example.service",
                        "[Service]\nExecStart=/srv/eng/bin/server --release={{ release }} --variant={{ variant }} --tree={{ tree }} --deployment={{ deployment_id }} --generation={{ generation }}\n",
                    ),
                ],
            );
            // First deploy: establishes the PRIOR generation whose assignment
            // carries the immutable release id of the PRIOR assignment and the PRIOR
            // deployment identity (deployment_id + generation_id).
            let first = h.run(None);
            assert!(
                matches!(first.state, SlotExecution::Advanced { .. }),
                "first deploy must activate: {:?}",
                first.state
            );
            let first_gen = first
                .state
                .observed_generation()
                .expect("an advanced first deploy records its generation")
                .clone();
            // The prior generation's assignment is the source of truth for the
            // five values compensation must render: read it back from the
            // remote record (generations/<gen>/assignment.json).
            let prior_assignment = h
                .helper()
                .read_assignment(&first_gen, &crate::remote::helper::test_owner("eng", "p1"))
                .unwrap();

            // A subsequent (desired) push fails activation and the engine
            // compensates back to the prior generation. Drive the same
            // compensation directly: the desired artifact's vars carry a
            // DIFFERENT release/tree AND a DIFFERENT (failed) deployment
            // identity than the prior assignment.
            let op_id = OperationId::generate();
            let failed_deployment_id = DeploymentId::generate();
            let failed_generation = GenerationId::generate();
            let members = h.config.target_slots("t1").unwrap();
            let (slot, server) = members[0];
            let desired = ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-desired"),
                variant: VariantName::new("standard"),
                tree: TreeDigest::new("desired-tree"),
            };
            let desired_vars = crate::remote::canonical::TemplateVars::slot(
                slot.deploy_dir(),
                desired.variant.as_str(),
                h.config.application().as_str(),
                desired.release.as_str(),
                "t1",
                server.id.as_str(),
            )
            .with_server(server.user(), server.address(), server.port())
            .with_slot_id(&slot.id)
            .with_deployment(
                Some(&failed_deployment_id),
                Some(&failed_generation),
                Some(&desired.tree),
            );
            let helper = h.helper();
            // The prior generation's behavior must be readable from the remote
            // (in a real push, push_inner publishes it; the harness bypasses
            // push_inner, so publish it the same way — as ONE aggregate
            // bundle).
            h.publish_harness_release();
            let request = CompensationRequest {
                op_id: op_id.clone(),
                prior_gen: Some(first_gen.clone()),
                advanced_gen: first_gen.clone(),
                template_vars: desired_vars,
                owner: crate::remote::helper::test_owner("eng", "p1"),
            };
            let outcome = compensate_server(&helper, &request).map_err(|e| e.to_string())?;
            let CompensationOutcome::Restored { .. } = outcome else {
                return Err("compensation must restore the prior generation (verified)".into());
            };

            // The installed unit was re-rendered with the PRIOR assignment:
            // its own immutable release id, variant, tree, AND the prior
            // deployment identity (`deployment_id`/`generation`) — never the
            // desired release/tree or the failed generation's identities the
            // failed push would have rendered.
            let installed =
                std::fs::read_to_string(config_home.join("systemd/user/example.service")).unwrap();
            assert!(
                installed.contains(&format!(
                    "--release={}",
                    prior_assignment.artifact.release.as_str()
                )),
                "compensated unit must render the PRIOR release id, got: {installed}"
            );
            assert!(
                !installed.contains("rel-sha256-desired"),
                "compensated unit must not render the desired release, got: {installed}"
            );
            assert!(
                installed.contains(&format!(
                    "--variant={}",
                    prior_assignment.artifact.variant.as_str()
                )) && installed.contains(&format!(
                    "--tree={}",
                    prior_assignment.artifact.tree.as_str()
                )),
                "compensated unit must render the prior variant/tree, got: {installed}"
            );
            assert!(
                installed.contains(&format!(
                    "--deployment={}",
                    prior_assignment.deployment_id.as_str()
                )),
                "compensated unit must render the PRIOR deployment id, got: {installed}"
            );
            assert!(
                installed.contains(&format!(
                    "--generation={}",
                    prior_assignment.generation_id.as_str()
                )),
                "compensated unit must render the PRIOR generation id, got: {installed}"
            );
            assert!(
                !installed.contains(&format!("--deployment={}", failed_deployment_id.as_str()))
                    && !installed.contains(&format!("--generation={}", failed_generation.as_str())),
                "compensated unit must not render the failed generation's identities, got: {installed}"
            );
            Ok::<(), String>(())
        })();

        outcome.unwrap();
    }

    /// Compensation is a compare-and-swap: it restores the prior generation
    /// only while `current` still names the generation the failed push
    /// advanced. If a concurrent controller has since moved `current`
    /// elsewhere, compensation REFUSES (returns `false`) and leaves the
    /// foreign `current` untouched.
    #[test]
    fn compensation_refuses_when_current_moved() {
        let h = Harness::new(
            &crate::testutil::fixture_env(),
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        // First deploy: the PRIOR generation g1 is live.
        let first = h.run(None);
        assert!(
            matches!(first.state, SlotExecution::Advanced { .. }),
            "first deploy must activate"
        );
        let first_gen = first
            .state
            .observed_generation()
            .expect("an advanced first deploy records its generation")
            .clone();
        let helper = h.helper();

        // The failed push advanced to g2 (its generation record exists, and
        // `current` moved to g2)...
        let g2 = GenerationId::generate();
        crate::remote::helper::SlotRemote::new(
            &helper,
            crate::remote::helper::test_owner("eng", "p1"),
        )
        .acquire_lock_guard(&crate::identity::OperationId::new("op2".to_string()))
        .unwrap()
        .create_generation(&crate::remote::helper::GenerationSpec {
            deployment_id: test_deployment_id("d2"),
            generation_id: g2.clone(),
            artifact: ArtifactRef {
                release: h.harness_release_id(),
                variant: crate::identity::VariantName::new("standard"),
                tree: h.tree.clone(),
            },
            behavior_sha256: crate::identity::test_behavior_digest("b"),
            prior_generation: Some(first_gen.clone()),
            created_at: crate::remote::helper::now_rfc3339_ts(),
            target: crate::identity::TargetName::new("t1"),
        })
        .unwrap();
        crate::remote::helper::SlotRemote::new(
            &helper,
            crate::remote::helper::test_owner("eng", "p1"),
        )
        .acquire_lock_guard(&crate::identity::OperationId::new("op2".to_string()))
        .unwrap()
        .swap_current(
            &crate::remote::helper::ExpectedCurrent::Generation(first_gen.clone()),
            &g2,
            "op2",
        )
        .unwrap();
        // ...but a concurrent controller moved `current` to g3 BEFORE this
        // op's compensation ran: the CAS precondition (current == g2) fails.
        let g3 = GenerationId::generate();
        crate::remote::helper::SlotRemote::new(
            &helper,
            crate::remote::helper::test_owner("eng", "p1"),
        )
        .acquire_lock_guard(&crate::identity::OperationId::new("op3".to_string()))
        .unwrap()
        .create_generation(&crate::remote::helper::GenerationSpec {
            deployment_id: test_deployment_id("d3"),
            generation_id: g3.clone(),
            artifact: ArtifactRef {
                release: h.harness_release_id(),
                variant: crate::identity::VariantName::new("standard"),
                tree: h.tree.clone(),
            },
            behavior_sha256: crate::identity::test_behavior_digest("b"),
            prior_generation: Some(g2.clone()),
            created_at: crate::remote::helper::now_rfc3339_ts(),
            target: crate::identity::TargetName::new("t1"),
        })
        .unwrap();
        crate::remote::helper::SlotRemote::new(
            &helper,
            crate::remote::helper::test_owner("eng", "p1"),
        )
        .acquire_lock_guard(&crate::identity::OperationId::new("op3".to_string()))
        .unwrap()
        .swap_current(
            &crate::remote::helper::ExpectedCurrent::Generation(g2.clone()),
            &g3,
            "op3",
        )
        .unwrap();

        // The prior generation's behavior must be readable for compensation to
        // attempt restoration (it still refuses on the CAS before using it).
        h.publish_harness_release();

        let members = h.config.target_slots("t1").unwrap();
        let (slot, server) = members[0];
        let vars = crate::remote::canonical::TemplateVars::slot(
            slot.deploy_dir(),
            "standard",
            h.config.application().as_str(),
            "rel-sha256-desired",
            "t1",
            server.id.as_str(),
        )
        .with_server(server.user(), server.address(), server.port())
        .with_slot_id(&slot.id)
        .with_deployment(
            Some(&DeploymentId::generate()),
            Some(&GenerationId::generate()),
            Some(&h.tree),
        );
        let request = CompensationRequest {
            op_id: OperationId::generate(),
            prior_gen: Some(first_gen.clone()),
            advanced_gen: g2.clone(),
            template_vars: vars,
            owner: crate::remote::helper::test_owner("eng", "p1"),
        };
        let outcome = compensate_server(&helper, &request).unwrap();
        assert!(
            matches!(outcome, CompensationOutcome::Refused),
            "compensation must refuse when current no longer names the advanced generation"
        );
        // The foreign current (g3) survives untouched.
        let st = h
            .helper()
            .status(&crate::remote::helper::test_owner("eng", "p1"))
            .unwrap();
        let current = st.current_generation().unwrap();
        assert_eq!(
            current.as_str(),
            g3.as_str(),
            "the concurrent controller's current must survive a refused compensation"
        );
    }
}

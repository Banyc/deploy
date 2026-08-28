//! Per-slot prior-generation restore: [`compensate_server`] re-installs the
//! previous generation on a slot whose swap/activate failed.

use crate::config::ProjectConfig;
use crate::error::Error;
use crate::error::Result;
use crate::identity::DeploymentId;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::remote::helper::HeldSlotLock;
use crate::remote::helper::RemoteHelper;
use crate::remote::layout;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use crate::verify::command::run_verification;
use crate::verify::systemd::run_activation;

// PER-SLOT COMPENSATION (A1 step 11): restore the prior generation after a
// failed activation/verification (or remove `current` on a first deploy),
// re-running the PRIOR generation's stored behavior contract with the PRIOR
// assignment's identity, and only while `current` still names the generation
// the failed push advanced (compare-and-swap). Consumed by the per-server
// process ([`process_server`]) and by the
// failure-policy pass (failure section).

/// Restore the prior generation (or remove `current` on first deploy). Uses the
/// prior generation's stored behavior contract rather than the caller's current
/// configuration. `advanced_gen` is the generation this slot was just advanced
/// to; it is used as the compare-and-swap precondition so a concurrent
/// controller cannot have its `current` clobbered. `template_vars` supplies the
/// slot context (deploy_dir, application, ...); the VARIANT is overridden with
/// the prior assignment's variant, because compensation re-runs the PRIOR
/// generation's contract. Returns true if compensation restored prior state.
// 11 parameters mirror `process_server` (same rationale: a settings-struct
// consolidation of the trailing config/vars args is a dedicated refactor;
// the allow documents the deliberate choice).
#[allow(clippy::too_many_arguments)]
pub(crate) fn compensate_server_locked(
    held: &HeldSlotLock<'_>,
    _store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    _deployment_id: &DeploymentId,
    prior_gen: Option<&GenerationId>,
    advanced_gen: &GenerationId,
    _config: &ProjectConfig,
    template_vars: &crate::remote::canonical::TemplateVars,
) -> Result<bool> {
    match prior_gen {
        Some(prior) => {
            // Load the prior generation's behavior contract from the remote.
            let prior_assignment = match helper.read_assignment(prior.as_str()) {
                Ok(a) => a,
                Err(_) => return Ok(false),
            };
            // Load the prior generation's behavior contract from the remote. If it
            // is unavailable we cannot verify what we are restoring, so we must
            // not pretend restoration succeeded by substituting a default
            // contract: report the failure so the attempt is marked Degraded.
            let prior_behavior = helper
                .read_behavior(
                    &prior_assignment.artifact.release,
                    prior_assignment.artifact.variant.as_str(),
                )
                .map_err(|e| {
                    Error::remote(format!("compensation: prior behavior unavailable: {e}"))
                })?;
            // Compare-and-swap: only roll back if `current` still points at the
            // generation we just activated. Otherwise another controller changed
            // it and we must not clobber their state.
            if helper
                .swap_current(
                    held,
                    &crate::remote::helper::ExpectedCurrent::Generation(advanced_gen.clone()),
                    prior.as_str(),
                    op_id.as_str(),
                )
                .is_err()
            {
                return Ok(false);
            }
            let root = remote
                .root()
                .join(layout::generation(prior.as_str()))
                .join("root");
            // Re-run prior activation contract + verification. A failure means the
            // service was not actually restored to prior behavior, so propagate
            // it as a compensation failure (the attempt is marked Degraded).
            // The prior contract is rendered with the PRIOR assignment: its own
            // release (the immutable ReleaseId), variant, tree, AND the prior
            // deployment identity (`deployment_id`/`generation`) move together
            // via `with_assignment`, so a restored slot never renders a torn
            // combination (e.g. the prior variant with the desired release, or
            // the prior artifact with the failed generation's deployment id).
            let prior_vars = template_vars.with_assignment(&prior_assignment);
            run_activation(remote, &root, &prior_behavior.activation, &prior_vars)
                .map_err(|e| Error::remote(format!("compensation activation failed: {e}")))?;
            run_verification(remote, &prior_behavior.verification, &prior_vars)
                .map_err(|e| Error::remote(format!("compensation verification failed: {e}")))?;
            Ok(true)
        }
        None => {
            // First deploy: remove `current` only if it still points at the
            // generation we advanced (compare-and-swap style).
            Ok(helper
                .remove_current_if(
                    held,
                    &crate::remote::helper::ExpectedCurrent::Generation(advanced_gen.clone()),
                )
                .unwrap_or(false))
        }
    }
}

/// External wrapper: acquires the slot mutation lock ONCE, calls
/// `compensate_server_locked`, and drops the guard at the end. An acquire
/// failure is swallowed as `Ok(false)` (slot stays advanced → attempt Degraded).
#[allow(clippy::too_many_arguments)]
pub(crate) fn compensate_server(
    store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    prior_gen: Option<&GenerationId>,
    advanced_gen: &GenerationId,
    config: &ProjectConfig,
    template_vars: &crate::remote::canonical::TemplateVars,
) -> Result<bool> {
    let guard = match helper.acquire_lock_guard(op_id.as_str()) {
        Ok(g) => g,
        Err(_) => return Ok(false),
    };
    compensate_server_locked(
        &guard,
        store,
        remote,
        helper,
        op_id,
        deployment_id,
        prior_gen,
        advanced_gen,
        config,
        template_vars,
    )
}

#[cfg(test)]
mod compensation_tests {
    use super::*;
    use crate::deploy::rollout::server::server_tests::{
        Harness, NONE_TOML, NONE_VARIANT, SYSTEMD_TOML, SYSTEMD_VARIANT,
    };
    use crate::deploy::rollout::*;
    use crate::identity::{ArtifactRef, TreeDigest, VariantName, test_deployment_id};
    use crate::ledger::SlotOutcomeKind;
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
            assert_eq!(
                first.kind,
                SlotOutcomeKind::Activated,
                "first deploy must activate: {:?}",
                first.error
            );
            // The prior generation's assignment is the source of truth for the
            // five values compensation must render: read it back from the
            // remote record (generations/<gen>/assignment.json).
            let prior_assignment = h
                .helper()
                .read_assignment(first.generation.as_str())
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
            // push_inner, so publish it the same way).
            let behaviors =
                std::collections::BTreeMap::from([("standard".to_string(), h.behave())]);
            helper
                .publish_release(
                    h.harness_release_id().as_str(),
                    &h.harness_release_json(),
                    &serde_json::to_string(&behaviors).unwrap(),
                )
                .unwrap();
            let ok = compensate_server(
                &h.store,
                &h.remote,
                &helper,
                &op_id,
                &failed_deployment_id,
                Some(&first.generation),
                &first.generation, // current still points at the first generation
                &h.config,
                &desired_vars,
            )
            .map_err(|e| e.to_string())?;
            assert!(ok, "compensation must restore the prior generation");

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
        assert_eq!(first.kind, SlotOutcomeKind::Activated);
        let helper = h.helper();

        // The failed push advanced to g2 (its generation record exists, and
        // `current` moved to g2)...
        let g2 = GenerationId::generate();
        helper
            .create_generation(
                &helper.acquire_lock_guard("op2").unwrap(),
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: test_deployment_id("d2"),
                    generation_id: g2.clone(),
                    artifact: ArtifactRef {
                        release: h.harness_release_id(),
                        variant: crate::identity::VariantName::new("standard"),
                        tree: h.tree.clone(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some(first.generation.clone()),
                    created_at: crate::remote::helper::now_rfc3339(),
                    target: Some(crate::identity::TargetName::new("t1")),
                },
            )
            .unwrap();
        helper
            .swap_current(
                &helper.acquire_lock_guard("op2").unwrap(),
                &crate::remote::helper::ExpectedCurrent::Generation(first.generation.clone()),
                g2.as_str(),
                "op2",
            )
            .unwrap();
        // ...but a concurrent controller moved `current` to g3 BEFORE this
        // op's compensation ran: the CAS precondition (current == g2) fails.
        let g3 = GenerationId::generate();
        helper
            .create_generation(
                &helper.acquire_lock_guard("op3").unwrap(),
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: test_deployment_id("d3"),
                    generation_id: g3.clone(),
                    artifact: ArtifactRef {
                        release: h.harness_release_id(),
                        variant: crate::identity::VariantName::new("standard"),
                        tree: h.tree.clone(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some(g2.clone()),
                    created_at: crate::remote::helper::now_rfc3339(),
                    target: Some(crate::identity::TargetName::new("t1")),
                },
            )
            .unwrap();
        helper
            .swap_current(
                &helper.acquire_lock_guard("op3").unwrap(),
                &crate::remote::helper::ExpectedCurrent::Generation(g2.clone()),
                g3.as_str(),
                "op3",
            )
            .unwrap();

        // The prior generation's behavior must be readable for compensation to
        // attempt restoration (it still refuses on the CAS before using it).
        let behaviors = std::collections::BTreeMap::from([("standard".to_string(), h.behave())]);
        helper
            .publish_release(
                h.harness_release_id().as_str(),
                &h.harness_release_json(),
                &serde_json::to_string(&behaviors).unwrap(),
            )
            .unwrap();

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
        let ok = compensate_server(
            &h.store,
            &h.remote,
            &helper,
            &OperationId::generate(),
            &DeploymentId::generate(),
            Some(&first.generation),
            &g2,
            &h.config,
            &vars,
        )
        .unwrap();
        assert!(
            !ok,
            "compensation must refuse when current no longer names the advanced generation"
        );
        // The foreign current (g3) survives untouched.
        let current = h.helper().status().unwrap().current_generation.unwrap();
        assert_eq!(
            current.as_str(),
            g3.as_str(),
            "the concurrent controller's current must survive a refused compensation"
        );
    }
}

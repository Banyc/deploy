//! Per-server mutation pipeline.
//!
//! `process_server` (publish, integrity re-verify, artifact-path validation,
//! generation creation, atomic `current` swap, activation + verification with
//! compensation) and `compensate_server` (restore the prior generation),
//! plus the tree-download helper and the per-process release-JSON publication
//! cache shared with `push::engine`. Extracted from `push::engine`.

use crate::adapter::systemd::{run_activation, validate_artifact_paths};
use crate::adapter::verify::run_verification;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::layout;
use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, OperationId, ReleaseId, TargetName,
};
use crate::records::ServerOutcomeKind;
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use crate::tree;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(crate) struct ServerProc {
    pub(crate) kind: ServerOutcomeKind,
    pub(crate) generation: GenerationId,
    /// True when this slot's `current` was advanced (the per-slot commit point
    /// was moved to the new generation) at some point during the attempt —
    /// either it still points there, or compensation moved it back. This is
    /// the failure-policy/status signal for "a server this deployment
    /// advanced", distinct from `did_compensate`: a pre-swap failure never
    /// advanced the slot (nothing to roll back, `FailedRolledBack` is
    /// vacuously accurate), while a post-swap failure whose compensation
    /// failed IS still changed from prior state and the attempt must be
    /// `Degraded`, never a falsely clean `FailedRolledBack`.
    pub(crate) did_advance: bool,
    pub(crate) did_compensate: bool,
    pub(crate) error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_server(
    store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    target_name: &str,
    artifact: &ArtifactRef,
    new_gen: &GenerationId,
    expected_gen: Option<&GenerationId>,
    behavior: &BehaviorContract,
    behavior_sha256: &str,
    template_vars: &crate::template::TemplateVars,
    config: &Config,
) -> Result<ServerProc> {
    // Acquire the slot's mutation lock via an RAII guard so every return path
    // (including errors) releases it.
    let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
        Ok(g) => g,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("lock acquire failed: {e}")),
            });
        }
    };

    // Compare-and-swap precondition on current generation.
    let status = match helper.status() {
        Ok(s) => s,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("status failed: {e}")),
            });
        }
    };
    if let Some(exp) = expected_gen
        && status.current_generation.as_deref() != Some(exp.as_str())
    {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Skipped,
            generation: exp.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!(
                "compare-and-swap precondition failed: current {:?} expected {exp}",
                status.current_generation
            )),
        });
    }

    // 1. Publish the staged tree (from incoming), reusing an existing object.
    if let Err(e) = helper.publish_from_incoming(deployment_id.as_str(), artifact.tree.as_str()) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("publish failed: {e}")),
        });
    }

    // 2. Canonically hash the remote tree and compare with the requested digest.
    //    Existing remote objects are re-verified here rather than trusted.
    let verify_tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("tempdir: {e}")),
            });
        }
    };
    let object_rel = layout::tree_root(artifact.tree.as_str());
    if let Err(e) = download_tree_to_host(remote, &object_rel, verify_tmp.path()) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("download for verify failed: {e}")),
        });
    }
    let meta = match tree::canonicalize_tree(verify_tmp.path()) {
        Ok(m) => m,
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("canonicalize remote tree failed: {e}")),
            });
        }
    };
    if meta.tree_sha256 != artifact.tree.as_str() {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!(
                "integrity: remote tree digest {} does not match requested {}",
                meta.tree_sha256, artifact.tree
            )),
        });
    }

    // 3. Validate all declared artifact paths and types before changing current.
    if let Err(e) = validate_artifact_paths(remote, &object_rel, &behavior.activation) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("artifact validation: {e}")),
        });
    }

    // 4. Publish the release record (idempotent) and create the generation.
    if let Some((release_json, behavior_json)) =
        REMOTE_RELEASE_JSON.with(|c| c.borrow().get(&artifact.release).cloned())
        && let Err(e) =
            helper.publish_release(artifact.release.as_str(), &release_json, &behavior_json)
    {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("publish release failed: {e}")),
        });
    }
    let assignment = crate::remote::helper::GenerationAssignment {
        deployment_id: deployment_id.clone(),
        generation_id: new_gen.clone(),
        artifact: artifact.clone(),
        behavior_sha256: behavior_sha256.to_string(),
        prior_generation: expected_gen.cloned(),
        created_at: crate::remote::helper::now_rfc3339(),
        target: Some(TargetName::new(target_name.to_string())),
    };
    if let Err(e) = helper.create_generation(op_id.as_str(), &assignment) {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("create generation failed: {e}")),
        });
    }
    if let Err(e) = helper.transaction_record(op_id.as_str(), "prepared") {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("transaction record failed: {e}")),
        });
    }

    // Atomically move `current` (the per-slot commit point).
    let swap = helper.swap_current(
        expected_gen.map(|g| g.as_str()),
        new_gen.as_str(),
        op_id.as_str(),
    );
    match swap {
        Ok(()) => {}
        Err(e) => {
            return Ok(ServerProc {
                kind: ServerOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("swap failed: {e}")),
            });
        }
    };
    // The generation's tree content root: `generations/<gen>/root` is a
    // symlink to `objects/sha256/<tree>/root`, the same directory `current`
    // points at (it is the tree content root, not a nested `root/root`).
    let generation_root = remote
        .root()
        .join(layout::generation(new_gen.as_str()))
        .join("root");

    // Activation adapter. On failure, compensate (current was advanced).
    if let Err(e) = run_activation(
        remote,
        &generation_root,
        &behavior.activation,
        template_vars,
    ) {
        let comp = compensate_server(
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            expected_gen,
            new_gen,
            config,
            template_vars,
        );
        let _ = helper.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        let generation = if did_comp {
            expected_gen.cloned().unwrap_or_else(|| new_gen.clone())
        } else {
            new_gen.clone()
        };
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation,
            // The desired swap already moved `current` to the new generation:
            // this slot WAS advanced by the attempt, even if compensation
            // (partially) moved it back. A failed compensation must not be
            // mistaken for a never-advanced slot (the status logic treats
            // empty `advanced` as "nothing to roll back").
            did_advance: true,
            did_compensate: did_comp,
            error: Some(format!("activation failed: {e}")),
        });
    }

    // Verification adapter. On failure, compensate.
    if let Err(e) = run_verification(remote, &behavior.verification, template_vars) {
        let comp = compensate_server(
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            expected_gen,
            new_gen,
            config,
            template_vars,
        );
        let _ = helper.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        let generation = if did_comp {
            expected_gen.cloned().unwrap_or_else(|| new_gen.clone())
        } else {
            new_gen.clone()
        };
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Failed,
            generation,
            did_advance: true,
            did_compensate: did_comp,
            error: Some(format!("verification failed: {e}")),
        });
    }

    // The swap, activation, and verification all succeeded, so the new generation
    // is live (current points at it and the service is healthy). A failure to
    // write the bookkeeping record is a *recoverable metadata* failure: the
    // service is active but the attempt cannot be durably marked committed. We
    // still report the server as Activated, but carry the error so the attempt
    // status is demoted to `PendingCommit` rather than erroneously `Successful`.
    // A later push's `reconcile_pending_commits` completes the marker set
    // without touching the healthy server when its generation still matches.
    if helper
        .transaction_record(op_id.as_str(), "committed")
        .is_err()
    {
        return Ok(ServerProc {
            kind: ServerOutcomeKind::Activated,
            generation: new_gen.clone(),
            did_advance: true,
            did_compensate: false,
            error: Some(
                "committed transaction record write failed; server active but bookkeeping incomplete"
                    .to_string(),
            ),
        });
    }
    Ok(ServerProc {
        kind: ServerOutcomeKind::Activated,
        generation: new_gen.clone(),
        did_advance: true,
        did_compensate: false,
        error: None,
    })
}

/// Restore the prior generation (or remove `current` on first deploy). Uses the
/// prior generation's stored behavior contract rather than the caller's current
/// configuration. `advanced_gen` is the generation this slot was just advanced
/// to; it is used as the compare-and-swap precondition so a concurrent
/// controller cannot have its `current` clobbered. `template_vars` supplies the
/// slot context (deploy_dir, application, ...); the VARIANT is overridden with
/// the prior assignment's variant, because compensation re-runs the PRIOR
/// generation's contract. Returns true if compensation restored prior state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compensate_server(
    _store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    _deployment_id: &DeploymentId,
    prior_gen: Option<&GenerationId>,
    advanced_gen: &GenerationId,
    _config: &Config,
    template_vars: &crate::template::TemplateVars,
) -> Result<bool> {
    // Hold the slot's mutation lock for the duration of compensation. Re-acquiring
    // is idempotent when the same op_id already holds it (process_server holds it
    // via a guard that is still alive on the in-process failure paths).
    let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
        Ok(g) => g,
        Err(_) => return Ok(false),
    };
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
                .swap_current(Some(advanced_gen.as_str()), prior.as_str(), op_id.as_str())
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
                .remove_current_if(advanced_gen.as_str())
                .unwrap_or(false))
        }
    }
}

pub(crate) fn download_tree_to_host(
    remote: &dyn Remote,
    rel: &Path,
    host_dest: &Path,
) -> Result<()> {
    std::fs::create_dir_all(host_dest)
        .map_err(|e| Error::transport(format!("mkdir {}: {e}", host_dest.display())))?;
    for entry in remote.list(rel)? {
        let child_rel = rel.join(&entry.name);
        let dest = host_dest.join(&entry.name);
        if entry.is_symlink {
            // Reconstruct the exact symlink target; remove any stale entry first.
            // Best-effort prep: in the only caller (`recover_if_missing`) the
            // destination tree is freshly downloaded, so `dest` does not exist
            // and remove_file returns NotFound. If a stale entry did linger, the
            // subsequent symlink fails loudly with EEXIST rather than silently
            // producing a wrong tree.
            let target = remote.read_link(&child_rel)?;
            let _ = std::fs::remove_file(&dest);
            std::os::unix::fs::symlink(&target, &dest)
                .map_err(|e| Error::transport(format!("symlink {}: {e}", dest.display())))?;
        } else if entry.is_dir {
            download_tree_to_host(remote, &child_rel, &dest)?;
            set_mode(&dest, entry.mode)?;
        } else {
            let data = remote.read(&child_rel)?;
            std::fs::write(&dest, data)
                .map_err(|e| Error::transport(format!("write {}: {e}", dest.display())))?;
            set_mode(&dest, entry.mode)?;
        }
    }
    Ok(())
}

/// Apply a mode to a local file/directory, preserving only the permission bits.
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| Error::transport(format!("chmod {}: {e}", path.display())))
}

// Per-process cache of release JSON for remote publication (avoids re-reading
// the local store inside the nested helper calls).
thread_local! {
    pub(crate) static REMOTE_RELEASE_JSON: std::cell::RefCell<
        HashMap<ReleaseId, (String, String)>
    > = std::cell::RefCell::new(HashMap::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RELEASE_RECORD_SCHEMA_VERSION, TreeDigest, VariantName};
    use crate::remote::transport::LocalTransport;
    use std::path::PathBuf;

    const NONE_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
targets = ["t1"]
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    const NONE_TOML: &str = r#"
schema_version = 1
application = "eng"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    const SYSTEMD_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
targets = ["t1"]
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/units/"
to = "integration/systemd/"
recursive = true

[activation]
adapter = "systemd"
scope = "user"

[[activation.units]]
name = "example.service"
artifact_path = "integration/systemd/example.service"
enable = true
restart = true

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    const SYSTEMD_TOML: &str = r#"
schema_version = 1
application = "eng"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    /// Build the minimal release record for the harness's synthetic release: a
    /// CURRENT-format record carrying its OWN canonical slot snapshot (slot
    /// p1 -> variant `standard`, matching the harness config's NONE_VARIANT
    /// declaration) with the identity RECOMPUTED from the stored content, so
    /// the publish path's recompute-and-verify accepts it. `harness_release_id`
    /// exposes the resulting identity-derived id (the `rel-sha256-<digest>`
    /// that tests thread through artifact refs and the publish path); the
    /// empty-snapshot legacy shape is rejected by verification. The provenance
    /// `behavior_sha256` must be the canonical digest of the behavior payload
    /// published alongside the record (computed from the harness's own
    /// configured contract), or the publish path refuses the pair.
    fn harness_release_record(behavior_sha: &str) -> crate::model::ReleaseRecord {
        let mut rec = crate::model::ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: crate::model::Provenance {
                git_revision: None,
                mapping_sha256: "m".to_string(),
                behavior_sha256: behavior_sha.to_string(),
            },
            variants: std::collections::BTreeMap::from([(
                "standard".to_string(),
                "tree".to_string(),
            )]),
            slots: std::collections::BTreeMap::from([(
                "standard".to_string(),
                crate::model::CanonicalSlots {
                    slots: vec![crate::model::CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/eng".to_string(),
                        targets: vec!["t1".to_string()],
                    }],
                },
            )]),
        };
        let digest = crate::release::recompute_release_digest(&rec)
            .expect("harness release must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::model::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        rec
    }

    fn harness_release_json(behavior_sha: &str) -> String {
        serde_json::to_string(&harness_release_record(behavior_sha)).unwrap()
    }

    fn harness_release_id(behavior_sha: &str) -> crate::model::ReleaseId {
        crate::model::ReleaseId::new(harness_release_record(behavior_sha).release_id)
    }

    struct Harness {
        _dir: tempfile::TempDir,
        config: Config,
        store: LocalStore,
        _project: PathBuf,
        tree: TreeDigest,
        remote: LocalTransport,
    }

    impl Harness {
        fn new(deploy_toml: &str, variant_toml: &str, files: &[(&str, &str)]) -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let release_dir = project.join("releases").join("v1");
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
            let cfg_path = project.join("deploy.toml");
            std::fs::write(&cfg_path, deploy_toml).unwrap();
            // Artifact sources live beneath the release directory (release_root /
            // `artifacts`), so a `from` never reaches into the project root.
            let artifacts_dir = release_dir.join("artifacts");
            for (p, c) in files {
                let fp = artifacts_dir.join(p);
                std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
                std::fs::write(&fp, c).unwrap();
            }
            let config = Config::load(&cfg_path).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();

            // Materialize from the release directory, not the project root.
            let release_root = config.release_root(&cfg_path);
            let vcfg = config.variant("standard").unwrap();
            let staging = store.staging_dir().join("standard");
            crate::mapper::materialize_variant(
                &release_root,
                &vcfg.artifact.mappings,
                &crate::template::TemplateVars::mapping(
                    &config.application,
                    config.release.as_str(),
                    "standard",
                ),
                &staging,
            )
            .unwrap();
            let meta = tree::canonicalize_tree(&staging).unwrap();
            let tree = TreeDigest::new(meta.tree_sha256.clone());
            store
                .store_object(&meta.tree_sha256.into(), &staging)
                .unwrap();

            let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
            Harness {
                _dir: dir,
                config,
                store,
                _project: project,
                tree,
                remote,
            }
        }

        fn behave(&self) -> BehaviorContract {
            let v = self.config.variant("standard").unwrap();
            BehaviorContract {
                activation: v.activation.clone(),
                verification: v.verification.clone(),
            }
        }

        /// The canonical digest of THIS harness's `standard` variant behavior
        /// contract — the provenance `behavior_sha256` the harness release
        /// record must carry so the behavior JSON published alongside it
        /// verifies on the publish path.
        fn behavior_sha256(&self) -> String {
            let behaviors =
                std::collections::BTreeMap::from([("standard".to_string(), self.behave())]);
            crate::release::variant_behaviors_digest(&behaviors)
        }

        /// The synthetic release record bound to THIS harness's configured
        /// behavior (so the published behavior JSON matches its provenance).
        fn harness_release(&self) -> crate::model::ReleaseRecord {
            harness_release_record(&self.behavior_sha256())
        }

        fn harness_release_id(&self) -> crate::model::ReleaseId {
            crate::model::ReleaseId::new(self.harness_release().release_id)
        }

        fn harness_release_json(&self) -> String {
            serde_json::to_string(&self.harness_release()).unwrap()
        }

        fn run(&self, expected_gen: Option<GenerationId>) -> ServerProc {
            let deployment_id = DeploymentId::generate();
            let op_id = OperationId::generate();
            self.helper()
                .stage_incoming(
                    deployment_id.as_str(),
                    self.tree.as_str(),
                    &self.store.object_root(&self.tree),
                )
                .unwrap();
            let behavior = self.behave();
            let sha = crate::release::behavior_contract_digest(&behavior);
            let new_gen = GenerationId::generate();
            let helper = self.helper();
            // Slot context from the harness config (one slot p1 on server s1,
            // target t1, deploy_dir /srv/eng), built from the artifact being
            // processed like the engine's `slot_vars`: release/variant/tree
            // come from the ArtifactRef, never the config release name.
            let artifact = ArtifactRef {
                release: self.harness_release_id(),
                variant: VariantName::new("standard"),
                tree: self.tree.clone(),
            };
            let members = self.config.target_slots("t1").unwrap();
            let (slot, server) = members[0];
            let vars = crate::template::TemplateVars::slot(
                &slot.deploy_dir,
                artifact.variant.as_str(),
                &self.config.application,
                artifact.release.as_str(),
                "t1",
                &server.id,
            )
            .with_server(&server.user, &server.address, server.port)
            .with_slot_id(&slot.id)
            .with_deployment(
                Some(&deployment_id),
                Some(&new_gen),
                Some(&artifact.tree),
            );
            process_server(
                &self.store,
                &self.remote,
                &helper,
                &op_id,
                &deployment_id,
                "t1",
                &artifact,
                &new_gen,
                expected_gen.as_ref(),
                &behavior,
                &sha,
                &vars,
                &self.config,
            )
            .unwrap()
        }

        fn helper(&self) -> RemoteHelper<'_> {
            RemoteHelper::new(&self.remote)
        }
    }

    #[test]
    fn clean_publish_activates() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Activated);
        assert!(!proc.did_compensate);
        assert!(h.remote.exists(layout::current()));
    }

    #[test]
    fn corrupted_existing_remote_object_fails_integrity() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let first = h.run(None);
        assert_eq!(first.kind, ServerOutcomeKind::Activated);

        // Corrupt the already-published remote object's content.
        let obj_file = h
            .remote
            .root()
            .join(crate::layout::objects())
            .join(h.tree.as_str())
            .join("root")
            .join("app")
            .join("README");
        assert!(obj_file.exists(), "expected object file to exist");
        std::fs::write(&obj_file, "TAMPERED").unwrap();

        // A second generation reuses the corrupted object and must detect the
        // digest mismatch before advancing `current`.
        let second = h.run(Some(first.generation.clone()));
        assert_eq!(second.kind, ServerOutcomeKind::Failed);
        assert!(second.error.unwrap().contains("integrity"));
    }

    #[test]
    fn corrupted_upload_fails_integrity() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        // Corrupt the local object store so the staged upload carries bad bytes.
        let local_file = h.store.object_root(&h.tree).join("app").join("README");
        std::fs::write(&local_file, "CORRUPT-LOCAL").unwrap();

        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Failed);
        assert!(proc.error.unwrap().contains("integrity"));
    }

    #[test]
    fn missing_systemd_unit_fails() {
        // The unit file is NOT present in the tree.
        let h = Harness::new(
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/other.txt", "x"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Failed);
        assert!(proc.error.unwrap().contains("missing"));
        assert!(!h.remote.exists(layout::current()));
    }

    #[test]
    fn wrong_artifact_type_fails() {
        // The artifact path exists but is a DIRECTORY, not a regular file.
        let h = Harness::new(
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/example.service/placeholder", "x"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, ServerOutcomeKind::Failed);
        assert!(proc.error.unwrap().to_lowercase().contains("type"));
    }

    /// Regression: the engine must hand the activation adapter
    /// `<remote>/generations/<gid>/root` (the `root` symlink to the tree
    /// content root) as the generation root — never a nested `root/root`. A
    /// full push with the systemd adapter exercises the real path
    /// construction at both `run_activation` call sites; staging reads the
    /// unit from `generations/<gid>/root/<artifact>`, so a `root/root`
    /// double-join would ENOENT and the push would never reach Activated.
    /// Fake `systemctl` in PATH and a temp `XDG_CONFIG_HOME` keep the
    /// activation hermetic (same pattern as the adapter end-to-end test; the
    /// shared `ENV_LOCK` serializes env-mutating tests).
    #[test]
    fn systemd_push_activation_uses_generation_root_not_nested() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        // Fake systemctl (daemon-reload/enable/restart all succeed) and a temp
        // config home so the installed unit lands somewhere hermetic.
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        let old_path = std::env::var_os("PATH");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bindir.display(),
                    old_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
            );
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }

        let outcome = (|| {
            let h = Harness::new(
                SYSTEMD_TOML,
                SYSTEMD_VARIANT,
                &[
                    ("build/output/app/server", "v1"),
                    ("deployment/common/README", "common"),
                    (
                        "units/example.service",
                        "[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
                    ),
                ],
            );
            let proc = h.run(None);
            // The activation read the unit from `generations/<gid>/root`
            // (through the `root` symlink into the tree content root). A
            // `root/root` double-join would fail that read and never reach
            // Activated.
            assert_eq!(
                proc.kind,
                ServerOutcomeKind::Activated,
                "activation failed (root/root double-join?): {:?}",
                proc.error
            );
            assert!(!proc.did_compensate);
            let gen_root = h
                .remote
                .root()
                .join(crate::layout::generation(proc.generation.as_str()))
                .join("root");
            assert!(
                gen_root.ends_with(
                    Path::new("generations")
                        .join(proc.generation.as_str())
                        .join("root")
                ),
                "activation generation root must be <root>/generations/<gid>/root, got {}",
                gen_root.display()
            );
            assert!(
                !gen_root.to_string_lossy().contains("root/root"),
                "activation generation root must not be a nested root/root"
            );
            // The double-joined path resolves to nothing on the published
            // layout: the tree content root has no nested `root` directory.
            assert!(
                !h.remote
                    .root()
                    .join(crate::layout::generation(proc.generation.as_str()))
                    .join("root/root")
                    .exists(),
                "published tree must have no nested root dir (root/root double-join would ENOENT)"
            );
            // The installed unit's content proves staging read the artifact
            // through `generations/<gid>/root` and rendered it with the slot
            // context (deploy_dir /srv/eng from the variant).
            let installed = config_home.join("systemd/user/example.service");
            assert_eq!(
                std::fs::read_to_string(&installed).unwrap(),
                "[Service]\nExecStart=/srv/eng/current/app/server\n"
            );
            Ok::<(), String>(())
        })();
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        match old_xdg {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
        outcome.unwrap();
    }

    /// Compensation re-runs the PRIOR generation's activation contract with the
    /// PRIOR assignment's identity: the unit it installs renders the PRIOR
    /// immutable release id (`{{ release }}`), variant, tree, AND the prior
    /// deployment identity (`{{ deployment_id }}`/`{{ generation }}`) — never a
    /// torn mix of the desired release with the prior variant, and never the
    /// failed generation's deployment id. This pins the
    /// `TemplateVars::with_assignment` path through the real systemd adapter.
    #[test]
    fn compensation_renders_prior_artifact_release_id() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        let old_path = std::env::var_os("PATH");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bindir.display(),
                    old_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
            );
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }

        let outcome = (|| {
            let h = Harness::new(
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
                ServerOutcomeKind::Activated,
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
                release: ReleaseId::new("rel-sha256-desired"),
                variant: VariantName::new("standard"),
                tree: TreeDigest::new("desired-tree"),
            };
            let desired_vars = crate::template::TemplateVars::slot(
                &slot.deploy_dir,
                desired.variant.as_str(),
                &h.config.application,
                desired.release.as_str(),
                "t1",
                &server.id,
            )
            .with_server(&server.user, &server.address, server.port)
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
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        match old_xdg {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
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
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        // First deploy: the PRIOR generation g1 is live.
        let first = h.run(None);
        assert_eq!(first.kind, ServerOutcomeKind::Activated);
        let helper = h.helper();

        // The failed push advanced to g2 (its generation record exists, and
        // `current` moved to g2)...
        let g2 = GenerationId::generate();
        helper
            .create_generation(
                "op2",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: "d2".to_string().into(),
                    generation_id: g2.clone(),
                    artifact: ArtifactRef {
                        release: h.harness_release_id(),
                        variant: crate::model::VariantName::new("standard"),
                        tree: h.tree.clone(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some(first.generation.clone()),
                    created_at: crate::remote::helper::now_rfc3339(),
                    target: Some(crate::model::TargetName::new("t1")),
                },
            )
            .unwrap();
        helper
            .swap_current(Some(first.generation.as_str()), g2.as_str(), "op2")
            .unwrap();
        // ...but a concurrent controller moved `current` to g3 BEFORE this
        // op's compensation ran: the CAS precondition (current == g2) fails.
        let g3 = GenerationId::generate();
        helper
            .create_generation(
                "op3",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: "d3".to_string().into(),
                    generation_id: g3.clone(),
                    artifact: ArtifactRef {
                        release: h.harness_release_id(),
                        variant: crate::model::VariantName::new("standard"),
                        tree: h.tree.clone(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some(g2.clone()),
                    created_at: crate::remote::helper::now_rfc3339(),
                    target: Some(crate::model::TargetName::new("t1")),
                },
            )
            .unwrap();
        helper
            .swap_current(Some(g2.as_str()), g3.as_str(), "op3")
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
        let vars = crate::template::TemplateVars::slot(
            &slot.deploy_dir,
            "standard",
            &h.config.application,
            "rel-sha256-desired",
            "t1",
            &server.id,
        )
        .with_server(&server.user, &server.address, server.port)
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

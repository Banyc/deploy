//! The per-server mutation pipeline (publish/swap/activate/verify/commit
//! per slot): [`process_server`], the [`ServerProc`] outcome, the tree
//! download helper, and the per-slot prior-generation restore
//! ([`compensation`]).

mod compensation;

pub(crate) use compensation::*;

// The per-server mutation pipeline: [`process_server`] (publish, integrity
// re-verify, artifact-path validation, activation, commit marker), the
// [`ServerProc`] outcome, the tree download helper.

use crate::config::ProjectConfig;
use crate::deploy::rollout::SlotExecution;
use crate::error::Error;
use crate::error::Result;
use crate::identity::ArtifactRef;
use crate::identity::BehaviorContract;
use crate::identity::DeploymentId;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::identity::ReleaseId;
use crate::identity::TargetName;
use crate::ledger::Observation;
use crate::ledger::ObservedGeneration;
use crate::remote::canonical as tree;
use crate::remote::helper::RemoteHelper;
use crate::remote::layout;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use crate::verify::command::run_verification;
use crate::verify::systemd::run_activation;
use crate::verify::systemd::validate_artifact_paths;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// Per-server mutation pipeline.
//
// `process_server` (publish, integrity re-verify, artifact-path validation,
// generation creation, atomic `current` swap, activation + verification with
// compensation — the compensation step itself lives in
// [`compensate_server`]), plus the
// tree-download helper and the per-process release-JSON publication cache
// shared with `push::engine`. Extracted from `push::engine`.

/// The per-server mutation OUTCOME: the slot's ONE recorded execution state
/// ([`SlotExecution`]) — the mutually exclusive state the attempt's ordered
/// execution table stores (the pre-swap / post-advance / restored /
/// activated classification, with the recorded generation observation on
/// the states whose evidence is the swap result). The old
/// `kind`/`did_advance`/`did_compensate` report is GONE: the state IS the
/// fact — an in-process-compensated post-swap failure is a `Restored`
/// state, an uncompensated post-swap failure is `FailedAfterAdvance` (the
/// attempt advanced it and did NOT restore it), never a flat `Failed` that
/// loses whether the swap happened.
pub(crate) struct ServerProc {
    pub(crate) state: SlotExecution,
}

impl ServerProc {
    /// A pre-swap failure: the attempt never mutated the slot (the
    /// recorded state carries the operation error; the observed post-state
    /// is attached later from the live read — the never-advanced rule).
    fn failed_before(error: String) -> Self {
        ServerProc {
            state: SlotExecution::FailedBeforeAdvance { error: Some(error) },
        }
    }

    /// An INDETERMINATE outcome: the swap/activation I/O failed with a
    /// transport error, so the attempt cannot know whether `current` moved
    /// (the slot may or may not have advanced — never classified as a
    /// deterministic no-advance).
    fn indeterminate(error: String) -> Self {
        ServerProc {
            state: SlotExecution::Indeterminate { error: Some(error) },
        }
    }

    /// A successfully advanced slot (the observation is the deployment's
    /// own generation — the swap + activation + verification succeeded).
    fn advanced(new_gen: &GenerationId, bookkeeping_error: Option<String>) -> Self {
        ServerProc {
            state: SlotExecution::Advanced {
                observation: Observation::Known(ObservedGeneration {
                    generation: new_gen.clone(),
                }),
                bookkeeping_error,
            },
        }
    }

    /// An in-process-compensated slot: the post-swap failure was restored
    /// by the per-server pipeline (back to the prior generation, or removed
    /// on a first deploy) — the `Restored` state with the restored
    /// generation as its observation.
    fn restored(expected_gen: Option<&GenerationId>) -> Self {
        ServerProc {
            state: SlotExecution::Restored {
                observation: match expected_gen {
                    Some(g) => Observation::Known(ObservedGeneration {
                        generation: g.clone(),
                    }),
                    None => Observation::KnownAbsent,
                },
            },
        }
    }
}

// 13 parameters: the per-server deployment is the full publication context
// (data: store, remote, helper, op_id, deployment_id, target_name, artifact,
// new_gen, expected_gen; policy: behavior, behavior_sha256, template_vars,
// config). Bundling the policy half into one settings struct is a dedicated
// refactor (deferred: `process_server` is the single hottest function in the
// push path and every caller would change with no behavioral gain); the allow
// documents the deliberate choice.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_server(
    _store: &LocalStore,
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
    template_vars: &crate::remote::canonical::TemplateVars,
    _config: &ProjectConfig,
) -> Result<ServerProc> {
    // Acquire the slot's mutation lock via an RAII guard so every return path
    // (including errors) releases it. Held in a named binding so in-process
    // compensation can borrow it without re-acquiring.
    let held = match helper.acquire_lock_guard(op_id) {
        Ok(g) => g,
        Err(e) => {
            return Ok(ServerProc::failed_before(format!(
                "lock acquire failed: {e}"
            )));
        }
    };

    // Compare-and-swap precondition on current generation.
    let status = match helper.status() {
        Ok(s) => s,
        Err(e) => {
            return Ok(ServerProc::failed_before(format!("status failed: {e}")));
        }
    };
    if let Some(exp) = expected_gen
        && status.current_generation.as_ref().map(|g| g.as_str()) != Some(exp.as_str())
    {
        // A compare-and-swap skip: the attempt never started this slot (its
        // post-mutation observation is the live state, attached later).
        return Ok(ServerProc {
            state: SlotExecution::NotStarted,
        });
    }

    // 1. Publish the staged tree (from incoming), reusing an existing object.
    if let Err(e) = held.publish_from_incoming(deployment_id.as_str(), artifact.tree.as_str()) {
        return Ok(ServerProc::failed_before(format!("publish failed: {e}")));
    }

    // 2. Canonically hash the remote tree and compare with the requested digest.
    //    Existing remote objects are re-verified here rather than trusted.
    let verify_tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return Ok(ServerProc::failed_before(format!("tempdir: {e}")));
        }
    };
    let object_rel = layout::tree_root(artifact.tree.as_str());
    if let Err(e) = download_tree_to_host(remote, &object_rel, verify_tmp.path()) {
        return Ok(ServerProc::failed_before(format!(
            "download for verify failed: {e}"
        )));
    }
    let meta = match tree::canonicalize_tree(verify_tmp.path()) {
        Ok(m) => m,
        Err(e) => {
            return Ok(ServerProc::failed_before(format!(
                "canonicalize remote tree failed: {e}"
            )));
        }
    };
    if meta.tree_sha256 != artifact.tree.as_str() {
        return Ok(ServerProc::failed_before(format!(
            "integrity: remote tree digest {} does not match requested {}",
            meta.tree_sha256, artifact.tree
        )));
    }

    // 3. Validate all declared artifact paths and types before changing current.
    if let Err(e) = validate_artifact_paths(remote, &object_rel, &behavior.activation) {
        return Ok(ServerProc::failed_before(format!(
            "artifact validation: {e}"
        )));
    }

    // 4. Publish the release record (idempotent) and create the generation.
    if let Some((release_json, behavior_json)) =
        REMOTE_RELEASE_JSON.with(|c| c.borrow().get(&artifact.release).cloned())
        && let Err(e) =
            helper.publish_release(artifact.release.as_str(), &release_json, &behavior_json)
    {
        return Ok(ServerProc::failed_before(format!(
            "publish release failed: {e}"
        )));
    }
    let assignment = crate::remote::helper::GenerationAssignment {
        deployment_id: deployment_id.clone(),
        generation_id: new_gen.clone(),
        artifact: artifact.clone(),
        behavior_sha256: behavior_sha256.to_string(),
        prior_generation: expected_gen.cloned(),
        created_at: crate::remote::helper::now_rfc3339(),
        target: Some(TargetName::parse(target_name).expect("target name is a safe segment")),
    };
    if let Err(e) = held.create_generation(&assignment) {
        return Ok(ServerProc::failed_before(format!(
            "create generation failed: {e}"
        )));
    }
    if let Err(e) = held.transaction_record(op_id.as_str(), "prepared") {
        return Ok(ServerProc::failed_before(format!(
            "transaction record failed: {e}"
        )));
    }

    // Atomically move `current` (the per-slot commit point).
    let swap = held.swap_current(
        &match expected_gen {
            Some(g) => crate::remote::helper::ExpectedCurrent::Generation(g.clone()),
            None => crate::remote::helper::ExpectedCurrent::Absent,
        },
        new_gen.as_str(),
        op_id.as_str(),
    );
    if let Err(e) = swap {
        // A TRANSPORT/IO failure mid-swap is INDETERMINATE — the swap may or
        // may not have moved `current`, so the outcome is unknown (never
        // classified as a deterministic no-advance). A CAS-refusal or
        // validation error is a DETERMINISTIC no-advance (the swap provably
        // did not happen) — `FailedBeforeAdvance`.
        if matches!(e, crate::error::Error::Transport(_)) {
            return Ok(ServerProc::indeterminate(format!("swap failed: {e}")));
        }
        return Ok(ServerProc::failed_before(format!("swap failed: {e}")));
    }
    // The generation's tree content root: `generations/<gen>/root` is a
    // symlink to `objects/sha256/<tree>/root`, the same directory `current`
    // points at (it is the tree content root, not a nested `root/root`).
    let generation_root = remote
        .root()
        .join(layout::generation(new_gen.as_str()))
        .join("root");

    // Activation adapter. On failure, compensate (current was advanced).
    // Compensation borrows the held lock — no second acquisition in-process.
    if let Err(e) = run_activation(
        remote,
        &generation_root,
        &behavior.activation,
        template_vars,
    ) {
        let request = CompensationRequest {
            op_id: op_id.clone(),
            deployment_id: deployment_id.clone(),
            prior_gen: expected_gen.cloned(),
            advanced_gen: new_gen.clone(),
            template_vars: template_vars.clone(),
        };
        let comp = compensate_server_locked(&held, &request);
        let _ = held.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        return Ok(if did_comp {
            // In-process compensation succeeded: the slot is back at its
            // pre-push state — a `Restored` execution.
            ServerProc::restored(expected_gen)
        } else {
            // The desired swap already moved `current` to the new
            // generation and the compensation FAILED: the slot is STILL ON
            // the advanced generation — `FailedAfterAdvance`, NEVER a
            // never-advanced slot (the old flat `Failed` lost exactly this:
            // an uncompensated post-advance failure must classify degraded,
            // never rolled-back). The observation is the generation the
            // attempt advanced it to.
            ServerProc {
                state: SlotExecution::FailedAfterAdvance {
                    observation: Observation::Known(ObservedGeneration {
                        generation: new_gen.clone(),
                    }),
                    error: Some(format!("activation failed: {e}")),
                },
            }
        });
    }

    // Verification adapter. On failure, compensate (borrow held lock).
    if let Err(e) = run_verification(remote, &behavior.verification, template_vars) {
        let request = CompensationRequest {
            op_id: op_id.clone(),
            deployment_id: deployment_id.clone(),
            prior_gen: expected_gen.cloned(),
            advanced_gen: new_gen.clone(),
            template_vars: template_vars.clone(),
        };
        let comp = compensate_server_locked(&held, &request);
        let _ = held.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        return Ok(if did_comp {
            // In-process compensation succeeded: the slot is back at its
            // pre-push state — a `Restored` execution.
            ServerProc::restored(expected_gen)
        } else {
            ServerProc {
                state: SlotExecution::FailedAfterAdvance {
                    observation: Observation::Known(ObservedGeneration {
                        generation: new_gen.clone(),
                    }),
                    error: Some(format!("verification failed: {e}")),
                },
            }
        });
    }

    // The swap, activation, and verification all succeeded, so the new generation
    // is live (current points at it and the service is healthy). A failure to
    // write the bookkeeping record is a *recoverable metadata* failure: the
    // service is active but the attempt cannot be durably marked committed. We
    // still report the server as Advanced, but carry the bookkeeping error so
    // the attempt status is demoted (stays intent-only) rather than erroneously
    // `Successful`.
    if held
        .transaction_record(op_id.as_str(), "committed")
        .is_err()
    {
        return Ok(ServerProc::advanced(
            new_gen,
            Some(
                "committed transaction record write failed; server active but bookkeeping incomplete"
                    .to_string(),
            ),
        ));
    }
    Ok(ServerProc::advanced(new_gen, None))
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
pub(crate) mod server_tests {
    use super::*;
    use crate::deploy::rollout::*;
    use crate::identity::{TreeDigest, VariantName};
    use crate::remote::transport::LocalTransport;
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    use std::path::PathBuf;

    pub(crate) const NONE_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    pub(crate) const NONE_TOML: &str = r#"
schema_version = 2
application = "eng"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    pub(crate) const SYSTEMD_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[[artifact.mappings]]
from = "artifacts/units/"
to = "integration/systemd/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

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

    pub(crate) const SYSTEMD_TOML: &str = r#"
schema_version = 2
application = "eng"
release = "v1"

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
    /// the publish path's recompute-and-verify accepts it. The provenance
    /// `behavior_sha256` must be the canonical digest of the behavior payload
    /// published alongside the record (computed from the harness's own
    /// configured contract), or the publish path refuses the pair.
    fn harness_release_record(behavior_sha: &str) -> crate::identity::ReleaseRecord {
        let mut rec = crate::identity::ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: crate::identity::Provenance {
                mapping_sha256: "m".to_string(),
                behavior_sha256: behavior_sha.to_string(),
            },
            variants: std::collections::BTreeMap::from([(
                "standard".to_string(),
                "tree".to_string(),
            )]),
            slots: std::collections::BTreeMap::from([(
                "standard".to_string(),
                crate::identity::CanonicalSlots {
                    slots: vec![crate::identity::CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/eng".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    }],
                },
            )]),
        };
        let digest = crate::verify::release::recompute_release_digest(&rec)
            .expect("harness release must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::identity::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        rec
    }

    pub(crate) struct Harness {
        pub(crate) _dir: tempfile::TempDir,
        pub(crate) config: ProjectConfig,
        pub(crate) store: LocalStore,
        pub(crate) _project: PathBuf,
        pub(crate) tree: TreeDigest,
        pub(crate) remote: LocalTransport,
    }

    impl Harness {
        pub(crate) fn new(
            env: &crate::env::SysEnv,
            deploy_toml: &str,
            variant_toml: &str,
            files: &[(&str, &str)],
        ) -> Harness {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
            let config = ProjectConfig::load(&cfg_path).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();

            // Materialize from the release directory, not the project root.
            let release_root = config.release_root(&cfg_path);
            let vcfg = config.variant("standard").unwrap();
            let staging = store.staging_dir().join("standard");
            crate::remote::canonical::materialize_variant(
                &release_root,
                &vcfg.artifact.mappings,
                &crate::remote::canonical::TemplateVars::mapping(
                    config.application().as_str(),
                    config.release().as_str(),
                    "standard",
                ),
                &staging,
            )
            .unwrap();
            let meta = tree::canonicalize_tree(&staging).unwrap();
            let tree = TreeDigest::parse(&meta.tree_sha256)
                .expect("canonicalized tree sha256 is a valid digest");
            store
                .store_object(
                    &TreeDigest::parse(&meta.tree_sha256)
                        .expect("canonicalized tree sha256 is a valid digest"),
                    &staging,
                )
                .unwrap();

            let remote = LocalTransport::new(env, dir.path().join("remote")).unwrap();
            Harness {
                _dir: dir,
                config,
                store,
                _project: project,
                tree,
                remote,
            }
        }

        pub(crate) fn behave(&self) -> BehaviorContract {
            let v = self.config.variant("standard").unwrap();
            BehaviorContract {
                activation: crate::config::ActivationConfig::from(v.activation.clone()),
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
            crate::verify::release::variant_behaviors_digest(&behaviors)
        }

        /// The synthetic release record bound to THIS harness's configured
        /// behavior (so the published behavior JSON matches its provenance).
        fn harness_release(&self) -> crate::identity::ReleaseRecord {
            harness_release_record(&self.behavior_sha256())
        }

        pub(crate) fn harness_release_id(&self) -> crate::identity::ReleaseId {
            crate::identity::ReleaseId::new(self.harness_release().release_id)
        }

        pub(crate) fn harness_release_json(&self) -> String {
            serde_json::to_string(&self.harness_release()).unwrap()
        }

        pub(crate) fn run(&self, expected_gen: Option<GenerationId>) -> ServerProc {
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
            let sha = crate::verify::release::behavior_contract_digest(&behavior);
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
            let vars = crate::remote::canonical::TemplateVars::slot(
                slot.deploy_dir(),
                artifact.variant.as_str(),
                self.config.application().as_str(),
                artifact.release.as_str(),
                "t1",
                server.id.as_str(),
            )
            .with_server(server.user(), server.address(), server.port())
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

        pub(crate) fn helper(&self) -> RemoteHelper<'_> {
            RemoteHelper::new(&self.remote)
        }
    }

    #[test]
    fn clean_publish_activates() {
        let h = Harness::new(
            &crate::testutil::fixture_env(),
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let proc = h.run(None);
        assert!(
            matches!(proc.state, SlotExecution::Advanced { .. }),
            "clean publish must advance the slot, got {:?}",
            proc.state
        );
        assert!(h.remote.exists(layout::current()));
    }

    #[test]
    fn corrupted_existing_remote_object_fails_integrity() {
        let h = Harness::new(
            &crate::testutil::fixture_env(),
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let first = h.run(None);
        assert!(
            matches!(first.state, SlotExecution::Advanced { .. }),
            "first deploy must advance"
        );
        let first_gen = first
            .state
            .observed_generation()
            .expect("an advanced first deploy records its generation")
            .clone();

        // Corrupt the already-published remote object's content.
        let obj_file = h
            .remote
            .root()
            .join(crate::remote::layout::objects())
            .join(h.tree.as_str())
            .join("root")
            .join("app-common")
            .join("README");
        assert!(obj_file.exists(), "expected object file to exist");
        std::fs::write(&obj_file, "TAMPERED").unwrap();

        // A second generation reuses the corrupted object and must detect the
        // digest mismatch before advancing `current`.
        let second = h.run(Some(first_gen.clone()));
        assert!(
            matches!(second.state, SlotExecution::FailedBeforeAdvance { .. }),
            "the digest mismatch must fail before the swap"
        );
        assert!(
            second
                .state
                .failed_error()
                .expect("a pre-swap failure carries its error")
                .contains("integrity")
        );
    }

    #[test]
    fn corrupted_upload_fails_integrity() {
        let h = Harness::new(
            &crate::testutil::fixture_env(),
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
        assert!(
            matches!(proc.state, SlotExecution::FailedBeforeAdvance { .. }),
            "the integrity failure must be pre-swap"
        );
        assert!(
            proc.state
                .failed_error()
                .expect("a pre-swap failure carries its error")
                .contains("integrity")
        );
    }

    #[test]
    fn missing_systemd_unit_fails() {
        // The unit file is NOT present in the tree.
        let h = Harness::new(
            &crate::testutil::fixture_env(),
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/other.txt", "x"),
            ],
        );
        let proc = h.run(None);
        assert!(
            matches!(proc.state, SlotExecution::FailedBeforeAdvance { .. }),
            "the missing-unit failure must be pre-swap"
        );
        assert!(
            proc.state
                .failed_error()
                .expect("a pre-swap failure carries its error")
                .contains("missing")
        );
        assert!(!h.remote.exists(layout::current()));
    }

    #[test]
    fn wrong_artifact_type_fails() {
        // The artifact path exists but is a DIRECTORY, not a regular file.
        let h = Harness::new(
            &crate::testutil::fixture_env(),
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/example.service/placeholder", "x"),
            ],
        );
        let proc = h.run(None);
        assert!(
            matches!(proc.state, SlotExecution::FailedBeforeAdvance { .. }),
            "the wrong-artifact-type failure must be pre-swap"
        );
        assert!(
            proc.state
                .failed_error()
                .expect("a pre-swap failure carries its error")
                .to_lowercase()
                .contains("type")
        );
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
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        // Fake systemctl (daemon-reload/enable/restart all succeed) and a temp
        // config home so the installed unit lands somewhere hermetic.
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        // Hermetic env: fake systemctl first on PATH, temp config home. The
        // child processes (activation shell, transport commands) receive this
        // snapshot; the parent process env is never touched.
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

        let outcome = {
            let h = Harness::new(
                &env,
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
            assert!(
                matches!(proc.state, SlotExecution::Advanced { .. }),
                "activation failed (root/root double-join?): {:?}",
                proc.state
            );
            let deployed_gen = proc
                .state
                .observed_generation()
                .expect("an activated slot records its generation");
            let gen_root = h
                .remote
                .root()
                .join(crate::remote::layout::generation(deployed_gen.as_str()))
                .join("root");
            assert!(
                gen_root.ends_with(
                    Path::new("generations")
                        .join(deployed_gen.as_str())
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
                    .join(crate::remote::layout::generation(deployed_gen.as_str()))
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
        };
        outcome.unwrap();
    }
}

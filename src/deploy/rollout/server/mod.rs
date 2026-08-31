//! The per-server mutation pipeline (publish/swap/activate/verify/commit
//! per slot): [`process_server`], the [`ServerProc`] outcome, the tree
//! download helper, and the per-slot prior-generation restore
//! ([`compensation`]).

mod compensation;

pub(crate) use compensation::*;

// The per-server mutation pipeline: [`process_server`] (publish, integrity
// re-verify, artifact-path validation, activation, commit marker), the
// [`ServerProc`] outcome, the tree download helper.

use crate::config::{Activation, ProjectConfig};
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
use crate::remote::helper::HeldSlotLock;
use crate::remote::helper::RemoteHelper;
use crate::remote::layout;
use crate::remote::transport::{Remote, RootedRelativePath};
use crate::store::local::LocalStore;
use crate::verify::adapters::transaction::{ActivationTransaction, VerifiedAdapterRestoration};
use crate::verify::command::run_verification;
use crate::verify::systemd::validate_artifact_paths;
use crate::verify::systemd::{SystemdActivation, SystemdApplied};
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
    /// on a first deploy) AND the adapter's side effects were VERIFIED
    /// restored (the sealed proof — produced only by a successful
    /// [`verify_restored`](crate::verify::adapters::transaction::ActivationTransaction::verify_restored)
    /// read-back) — the `Restored` state with the restored generation as its
    /// observation. A slot whose adapter restoration is NOT verified is
    /// `FailedAfterAdvance`, never `Restored` (the review's P1 fix).
    fn restored(
        expected_gen: Option<&GenerationId>,
        adapter_restored: VerifiedAdapterRestoration,
    ) -> Self {
        ServerProc {
            state: SlotExecution::Restored {
                observation: match expected_gen {
                    Some(g) => Observation::Known(ObservedGeneration {
                        generation: g.clone(),
                    }),
                    None => Observation::KnownAbsent,
                },
                adapter_restored,
            },
        }
    }

    /// An UNVERIFIED post-advance failure: the slot advanced (its `current`
    /// moved to the attempt's generation) and was NOT restored back (or its
    /// adapter side effects were NOT verified restored) — the slot is STILL
    /// ON the advanced generation. `FailedAfterAdvance`, NEVER `Restored`,
    /// NEVER a rolled-back candidate (the observation is the generation the
    /// attempt advanced it to).
    fn failed_after_advance(new_gen: &GenerationId, error: String) -> Self {
        ServerProc {
            state: SlotExecution::FailedAfterAdvance {
                observation: Observation::Known(ObservedGeneration {
                    generation: new_gen.clone(),
                }),
                error: Some(error),
            },
        }
    }

    /// THE GENERATION COMPENSATION for a failure BEFORE any adapter side
    /// effect was applied (an activation `prepare` failure, or a
    /// verification failure under `Activation::None` — no mutating adapter
    /// to reverse): CAS back to the prior generation and re-run the prior
    /// contract (its activation restores the prior units; the compensation's
    /// own READ-BACK verify produces the sealed proof). Verified → the slot
    /// is genuinely back at its pre-push state: `Restored` with the proof.
    /// Anything else (CAS refused, prior contract unavailable, the adapter
    /// restoration NOT verified) → `FailedAfterAdvance`.
    fn compensate_after_activation_failure(
        held: &HeldSlotLock<'_>,
        request: &CompensationRequest,
        new_gen: &GenerationId,
        error: String,
    ) -> Self {
        let comp = compensate_server_locked(held, request);
        let _ = held.transaction_record(&request.op_id, "compensated");
        match comp {
            Ok(CompensationOutcome::Restored { adapter_restored }) => {
                ServerProc::restored(request.prior_gen.as_ref(), adapter_restored)
            }
            _ => ServerProc::failed_after_advance(new_gen, error),
        }
    }

    /// THE PROTOCOL COMPENSATION (an apply/verification failure AFTER the
    /// mutating adapter ran — the review's fix): reverse the adapter side
    /// effect via the protocol (`restore`), PROVE the reversal by READING
    /// the remote (`verify_restored` — the sealed proof), then compensate the
    /// GENERATION (CAS back + prior verification). Verified → `Restored`
    /// with the proof (the slot is genuinely back at its pre-push state);
    /// ANY failure of restore / verify_restored / the generation
    /// compensation → `FailedAfterAdvance` (the side effect is NOT verified
    /// restored — never `Restored`, never a rolled-back candidate).
    fn restore_after_activation_failure(
        held: &HeldSlotLock<'_>,
        txn: &mut SystemdActivation<'_>,
        applied: &SystemdApplied,
        request: &CompensationRequest,
        new_gen: &GenerationId,
        error: String,
    ) -> Self {
        let restored = match txn.restore(applied) {
            Ok(r) => r,
            Err(e) => {
                return ServerProc::failed_after_advance(
                    new_gen,
                    format!("{error}; adapter restore failed: {e}"),
                );
            }
        };
        let proof = match txn.verify_restored(&restored) {
            Ok(p) => p,
            Err(e) => {
                return ServerProc::failed_after_advance(
                    new_gen,
                    format!("{error}; adapter restoration NOT verified: {e}"),
                );
            }
        };
        let comp = compensate_server_locked(held, request);
        let _ = held.transaction_record(&request.op_id, "compensated");
        match comp {
            Ok(CompensationOutcome::Restored { .. }) => {
                ServerProc::restored(request.prior_gen.as_ref(), proof)
            }
            _ => ServerProc::failed_after_advance(new_gen, error),
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
    slot: &crate::identity::SlotId,
    artifact: &ArtifactRef,
    new_gen: &GenerationId,
    expected_gen: Option<&GenerationId>,
    behavior: &BehaviorContract,
    behavior_sha256: &str,
    template_vars: &crate::remote::canonical::TemplateVars,
    config: &ProjectConfig,
) -> Result<ServerProc> {
    // The expected OWNER of this remote's generations: this application, this
    // slot. Every status read and generation write carries it — a remote
    // whose state was transplanted from another application/slot is refused.
    let owner =
        crate::remote::helper::GenerationOwner::new(config.application().clone(), slot.clone());

    // Acquire the slot's mutation lock via an RAII guard so every return path
    // (including errors) releases it. Held in a named binding so in-process
    // compensation can borrow it without re-acquiring. The mutation capability
    // is the SLOT-BOUND [`SlotRemote`]: acquisition returns a guard carrying
    // THIS slot's owner, so the guard knows which slot it authorizes mutation
    // on (assignments are constructed from it, the `current` swap verifies
    // the generation it installs against it).
    let slot_remote = crate::remote::helper::SlotRemote::new(helper, owner.clone());
    let held = match slot_remote.acquire_lock_guard(op_id) {
        Ok(g) => g,
        Err(e) => {
            return Ok(ServerProc::failed_before(format!(
                "lock acquire failed: {e}"
            )));
        }
    };

    // Compare-and-swap precondition on current generation.
    let status = match helper.status(&owner) {
        Ok(s) => s,
        Err(e) => {
            return Ok(ServerProc::failed_before(format!("status failed: {e}")));
        }
    };
    if let Some(exp) = expected_gen
        && status.current_generation().map(|g| g.as_str()) != Some(exp.as_str())
    {
        // A compare-and-swap skip: the attempt never started this slot (its
        // post-mutation observation is the live state, attached later).
        return Ok(ServerProc {
            state: SlotExecution::NotStarted,
        });
    }

    // 1. Publish the staged tree (from incoming), reusing an existing object.
    if let Err(e) = held.publish_from_incoming(deployment_id, &artifact.tree) {
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
    let object_rel = layout::tree_root(&artifact.tree);
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
    //    (`Activation::None` declares no units, so there is nothing to
    //    validate; a `Systemd` payload carries the fully validated units.)
    if let Activation::Systemd(sa) = behavior.activation()
        && let Err(e) = validate_artifact_paths(remote, &object_rel, sa)
    {
        return Ok(ServerProc::failed_before(format!(
            "artifact validation: {e}"
        )));
    }

    // 4. Publish the release record (idempotent) and create the generation.
    if let Some((release_json, behavior_json)) =
        REMOTE_RELEASE_JSON.with(|c| c.borrow().get(&artifact.release).cloned())
        && let Err(e) = helper.publish_release(&artifact.release, &release_json, &behavior_json)
    {
        return Ok(ServerProc::failed_before(format!(
            "publish release failed: {e}"
        )));
    }
    // The generation SPEC carries the non-owner fields; the OWNER MARKER
    // (application + slot) is bound by the guard itself — an assignment can
    // never name a different slot than the guard authorizes.
    let spec = crate::remote::helper::GenerationSpec {
        deployment_id: deployment_id.clone(),
        generation_id: new_gen.clone(),
        artifact: artifact.clone(),
        behavior_sha256: behavior_sha256.to_string(),
        prior_generation: expected_gen.cloned(),
        created_at: crate::remote::helper::now_rfc3339(),
        target: Some(TargetName::parse(target_name).expect("target name is a safe segment")),
    };
    if let Err(e) = held.create_generation(&spec) {
        return Ok(ServerProc::failed_before(format!(
            "create generation failed: {e}"
        )));
    }
    if let Err(e) = held.transaction_record(op_id, "prepared") {
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
        new_gen,
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
    let generation_root = remote.root().join(layout::generation(new_gen)).join("root");

    // 5. ACTIVATION via the ADAPTER TRANSACTION PROTOCOL (the review's P1
    //    fix: adapter side effects are inside the transaction): the mutating
    //    systemd adapter goes through prepare→apply, and on ANY failure its
    //    side effects are REVERSED (restore) and the reversal PROVEN by
    //    READING the remote (verify_restored). `Activation::None` declares no
    //    mutating adapter — no transaction, nothing to restore/verify (its
    //    verification failure still compensates the generation below).
    let mut activation_txn = SystemdActivation::new(
        remote,
        &generation_root,
        behavior.activation(),
        template_vars,
    );
    let mut applied: Option<SystemdApplied> = None;
    if let Some(txn) = &mut activation_txn {
        let prepared = match txn.prepare() {
            Ok(p) => p,
            Err(e) => {
                // prepare failed BEFORE any side effect was applied (nothing
                // was installed/enabled/restarted). Compensate the
                // GENERATION (CAS back to the prior generation) and verify
                // the adapter state is back at the prior contract's state —
                // the compensation's own read-back produces the proof.
                let request = CompensationRequest {
                    op_id: op_id.clone(),
                    deployment_id: deployment_id.clone(),
                    prior_gen: expected_gen.cloned(),
                    advanced_gen: new_gen.clone(),
                    template_vars: template_vars.clone(),
                    owner: owner.clone(),
                };
                return Ok(ServerProc::compensate_after_activation_failure(
                    &held,
                    &request,
                    new_gen,
                    format!("activation prepare failed: {e}"),
                ));
            }
        };
        match txn.apply(&prepared) {
            Ok(a) => applied = Some(a),
            Err(e) => {
                // apply FAILED (possibly partway): reverse the adapter side
                // effect via the protocol (restore) and PROVE the reversal by
                // READING the remote (verify_restored) — verified → the slot
                // is genuinely back (`Restored`); unverified → NEVER
                // restored-class (`FailedAfterAdvance`).
                let request = CompensationRequest {
                    op_id: op_id.clone(),
                    deployment_id: deployment_id.clone(),
                    prior_gen: expected_gen.cloned(),
                    advanced_gen: new_gen.clone(),
                    template_vars: template_vars.clone(),
                    owner: owner.clone(),
                };
                return Ok(ServerProc::restore_after_activation_failure(
                    &held,
                    txn,
                    &SystemdApplied::from_prepared(&prepared),
                    &request,
                    new_gen,
                    format!("activation failed: {e}"),
                ));
            }
        }
    }

    // 6. VERIFICATION — inside the transaction boundary. The command adapter
    //    is a PURE READER (runs the argv; no persistent side effect to
    //    restore — documented in the transaction module), but its failure is
    //    a failure of the attempt's mutation, never a silent pass: the
    //    ACTIVATION side effect (if any) is reversed via the protocol and
    //    the generation compensated — a `Restored`-class outcome ONLY when
    //    the adapter restoration is VERIFIED, else `FailedAfterAdvance`.
    if let Err(e) = run_verification(remote, behavior.verification(), template_vars) {
        let failure = format!("verification failed: {e}");
        let request = CompensationRequest {
            op_id: op_id.clone(),
            deployment_id: deployment_id.clone(),
            prior_gen: expected_gen.cloned(),
            advanced_gen: new_gen.clone(),
            template_vars: template_vars.clone(),
            owner: owner.clone(),
        };
        if let (Some(txn), Some(applied)) = (&mut activation_txn, &applied) {
            return Ok(ServerProc::restore_after_activation_failure(
                &held, txn, applied, &request, new_gen, failure,
            ));
        }
        return Ok(ServerProc::compensate_after_activation_failure(
            &held, &request, new_gen, failure,
        ));
    }

    // The swap, activation, and verification all succeeded, so the new generation
    // is live (current points at it and the service is healthy). A failure to
    // write the bookkeeping record is a *recoverable metadata* failure: the
    // service is active but the attempt cannot be durably marked committed. We
    // still report the server as Advanced, but carry the bookkeeping error so
    // the attempt status is demoted (stays intent-only) rather than erroneously
    // `Successful`.
    if held.transaction_record(op_id, "committed").is_err() {
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
    rel: &RootedRelativePath,
    host_dest: &Path,
) -> Result<()> {
    std::fs::create_dir_all(host_dest)
        .map_err(|e| Error::transport(format!("mkdir {}: {e}", host_dest.display())))?;
    for entry in remote.list(rel)? {
        let child_rel = rel.join(&entry.name)?;
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
    use crate::kernel::terminal::TerminalDisposition;
    use crate::ledger::NonEmptySlotTable;
    use crate::ledger::SlotOutcome;
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
            BehaviorContract::new(v.activation.clone(), v.verification.clone())
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
            self.run_with_new_gen(expected_gen.as_ref(), &GenerationId::generate())
        }

        /// [`run`](Self::run) with the caller's chosen NEW generation (the
        /// property tests mint it so the terminal decision's DESIRED
        /// generation is known).
        pub(crate) fn run_with_new_gen(
            &self,
            expected_gen: Option<&GenerationId>,
            new_gen: &GenerationId,
        ) -> ServerProc {
            let deployment_id = DeploymentId::generate();
            let op_id = OperationId::generate();
            self.helper()
                .stage_incoming(
                    &deployment_id,
                    &self.tree,
                    &self.store.object_root(&self.tree),
                )
                .unwrap();
            let behavior = self.behave();
            let sha = crate::verify::release::behavior_contract_digest(&behavior);
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
            .with_deployment(Some(&deployment_id), Some(new_gen), Some(&artifact.tree));
            process_server(
                &self.store,
                &self.remote,
                &helper,
                &op_id,
                &deployment_id,
                "t1",
                &crate::identity::SlotId::parse(slot.id.as_str())
                    .expect("validated slot id is a safe segment"),
                &artifact,
                new_gen,
                expected_gen,
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
    fn corrupted_existing_remote_object_is_quarantined_and_repaired() {
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

        // A second generation reuses the corrupted object: the publish
        // VERIFIES the existing object, QUARANTINES the invalid content
        // (moved aside, never deleted), and REPAIRS it by re-publishing the
        // verified staged tree — the deploy advances with the correct
        // content, and the final object at the digest path verifies as the
        // canonical tree.
        let second = h.run(Some(first_gen.clone()));
        assert!(
            matches!(second.state, SlotExecution::Advanced { .. }),
            "the corrupted object must be quarantined and repaired, never served"
        );
        // The repaired object at the digest path is exactly the canonical
        // tree.
        let meta = crate::remote::canonical::canonicalize_tree(
            &h.remote
                .root()
                .join(crate::remote::layout::tree_root(&h.tree)),
        )
        .unwrap();
        assert_eq!(
            meta.tree_sha256,
            h.tree.as_str(),
            "the repaired object must be the canonical tree"
        );
        // The invalid content was quarantined aside, never deleted.
        let q = h
            .remote
            .root()
            .join(crate::remote::layout::quarantined_tree(&h.tree));
        assert!(q.exists(), "the invalid object must be quarantined aside");
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
                .join(crate::remote::layout::generation(deployed_gen))
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
                    .join(crate::remote::layout::generation(deployed_gen))
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

    // ---- THE ADAPTER-TRANSACTION FAULT MATRIX (the review's P1 acceptance) --
    //
    // The property drives the REAL engine flow (process_server on a local
    // transport with the REAL systemd adapter) with fault injection at EVERY
    // adapter side-effect stage — prepare / apply / restore / verify_restored
    // (the ActivationTransaction methods) plus the verification adapter's exec
    // failure — crossed with the slot states (a first deploy vs a prior
    // generation), then feeds the execution through the SAME evidence path
    // (failure_evidence) and the kernel decision (decide_terminal). The
    // review's rule: a slot whose adapter restoration is UNVERIFIED is NEVER
    // part of a FailedRolledBack terminal — the terminal is either
    // FailedRolledBack with the slot's adapter restoration VERIFIED (its
    // delta genuinely Unchanged) or Degraded CONTAINING the slot (delta
    // Desired/Diverged/Unknown); the rolled-back classification is REFUSED
    // (as integrity) for an all-Unchanged table carrying an unverified
    // Restored slot, and the sealed proof cannot be fabricated.

    /// The fault-injection point: fail at EVERY adapter side-effect stage
    /// plus the verification adapter's exec failure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TxnFault {
        /// `prepare` fails (the fake systemctl's `is-enabled` capture).
        Prepare,
        /// `apply` fails partway (the fake systemctl's `restart`).
        Apply,
        /// `restore` fails (the occurrence-faulted `install` / `rm`).
        Restore,
        /// `verify_restored`'s READ fails (the occurrence-faulted `cat` /
        /// `test` — the read-back itself, after a successful restore).
        VerifyRestored,
        /// The verification adapter's exec fails (the `probe` contract).
        VerificationExec,
    }

    /// The slot state the fault is crossed with.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SlotState {
        /// First deploy: no prior generation — the prior adapter state is
        /// the ABSENCE of the units.
        FirstDeploy,
        /// A prior generation is live (its units installed).
        PriorGeneration,
    }

    /// The property variant: systemd user-scope activation with one unit +
    /// a PROBE verification contract (exec'd through the fault shims).
    const FAULT_VARIANT: &str = r#"
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
argv = ["probe"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// The fault-injection shim set + the marker/counter FILES the shims read
    /// at exec time (a scenario arms a fault between pushes without
    /// rebuilding the environment). The shims delegate to the REAL binaries
    /// otherwise, so the adapter's real file operations (install/cat/rm/test)
    /// keep working — the verify read-back is a REAL read.
    struct FaultShims {
        fail_sh: PathBuf,
        fail_is_enabled: PathBuf,
        fail_restart: PathBuf,
        fail_probe: PathBuf,
        count_install: PathBuf,
        fail_install_at: PathBuf,
        count_rm: PathBuf,
        fail_rm_at: PathBuf,
        count_cat: PathBuf,
        fail_cat_at: PathBuf,
        count_test: PathBuf,
        fail_test_at: PathBuf,
    }

    impl FaultShims {
        /// Install the shims into a hermetic env snapshot: fake `systemctl`
        /// (one-shot `is-enabled`/`restart` failures), the occurrence-
        /// faultable `install`/`rm`/`cat`/`test` (restore / restore-first-
        /// deploy / verify_restored), and the `probe` verification binary
        /// (one-shot failure) — each delegating to the REAL binary.
        fn install(
            base: &std::path::Path,
            env: &crate::env::SysEnv,
        ) -> (crate::env::SysEnv, FaultShims) {
            use std::os::unix::fs::PermissionsExt;
            let bindir = base.join("bin");
            std::fs::create_dir_all(&bindir).unwrap();
            let cfg = FaultShims {
                fail_sh: base.join("faults/sh"),
                fail_is_enabled: base.join("faults/is-enabled"),
                fail_restart: base.join("faults/restart"),
                fail_probe: base.join("faults/probe"),
                count_install: base.join("faults/install.count"),
                fail_install_at: base.join("faults/install.at"),
                count_rm: base.join("faults/rm.count"),
                fail_rm_at: base.join("faults/rm.at"),
                count_cat: base.join("faults/cat.count"),
                fail_cat_at: base.join("faults/cat.at"),
                count_test: base.join("faults/test.count"),
                fail_test_at: base.join("faults/test.at"),
            };
            std::fs::create_dir_all(cfg.fail_is_enabled.parent().unwrap()).unwrap();
            let shims: &[(&str, &str)] = &[
                (
                    "sh",
                    r#"#!/bin/sh
if [ -f "$FAIL_SH" ]; then rm -f "$FAIL_SH"; echo "faulted" >&2; exit 1; fi
exec /bin/sh "$@"
"#,
                ),
                (
                    "systemctl",
                    r#"#!/bin/sh
if [ "$1" = "--user" ]; then shift; fi
case "$1" in
  is-enabled) if [ -f "$FAIL_IS_ENABLED" ]; then rm -f "$FAIL_IS_ENABLED"; echo "faulted" >&2; exit 1; fi; exit 0 ;;
  restart) if [ -f "$FAIL_RESTART" ]; then rm -f "$FAIL_RESTART"; echo "faulted" >&2; exit 1; fi; exit 0 ;;
  *) exit 0 ;;
esac
"#,
                ),
                (
                    "probe",
                    r#"#!/bin/sh
if [ -f "$FAIL_PROBE" ]; then rm -f "$FAIL_PROBE"; echo "faulted" >&2; exit 1; fi
exit 0
"#,
                ),
                (
                    "install",
                    r#"#!/bin/sh
n=0; if [ -f "$COUNT_INSTALL" ]; then n=$(head -n1 "$COUNT_INSTALL" 2>/dev/null); fi
n=$((n+1)); echo "$n" > "$COUNT_INSTALL"
if [ -f "$FAIL_INSTALL_AT" ]; then a=$(head -n1 "$FAIL_INSTALL_AT" 2>/dev/null); if [ "$n" = "$a" ]; then echo "faulted" >&2; exit 1; fi; fi
exec /usr/bin/install "$@"
"#,
                ),
                (
                    "rm",
                    r#"#!/bin/sh
n=0; if [ -f "$COUNT_RM" ]; then n=$(head -n1 "$COUNT_RM" 2>/dev/null); fi
n=$((n+1)); echo "$n" > "$COUNT_RM"
if [ -f "$FAIL_RM_AT" ]; then a=$(head -n1 "$FAIL_RM_AT" 2>/dev/null); if [ "$n" = "$a" ]; then echo "faulted" >&2; exit 1; fi; fi
exec /bin/rm "$@"
"#,
                ),
                (
                    "cat",
                    r#"#!/bin/sh
n=0; if [ -f "$COUNT_CAT" ]; then n=$(head -n1 "$COUNT_CAT" 2>/dev/null); fi
n=$((n+1)); echo "$n" > "$COUNT_CAT"
if [ -f "$FAIL_CAT_AT" ]; then a=$(head -n1 "$FAIL_CAT_AT" 2>/dev/null); if [ "$n" = "$a" ]; then echo "faulted" >&2; exit 1; fi; fi
exec /bin/cat "$@"
"#,
                ),
                (
                    "test",
                    r#"#!/bin/sh
n=0; if [ -f "$COUNT_TEST" ]; then n=$(head -n1 "$COUNT_TEST" 2>/dev/null); fi
n=$((n+1)); echo "$n" > "$COUNT_TEST"
if [ -f "$FAIL_TEST_AT" ]; then a=$(head -n1 "$FAIL_TEST_AT" 2>/dev/null); if [ "$n" = "$a" ]; then echo "faulted" >&2; exit 1; fi; fi
exec /usr/bin/test "$@"
"#,
                ),
            ];
            for (name, body) in shims {
                let shim = bindir.join(name);
                std::fs::write(&shim, body).unwrap();
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let mut vars: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
                env.child_env().into_iter().collect();
            vars.insert(
                "PATH".into(),
                format!(
                    "{}:{}",
                    bindir.display(),
                    env.path()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default()
                )
                .into(),
            );
            for (key, value) in [
                ("FAIL_SH", cfg.fail_sh.as_os_str()),
                ("FAIL_IS_ENABLED", cfg.fail_is_enabled.as_os_str()),
                ("FAIL_RESTART", cfg.fail_restart.as_os_str()),
                ("FAIL_PROBE", cfg.fail_probe.as_os_str()),
                ("COUNT_INSTALL", cfg.count_install.as_os_str()),
                ("FAIL_INSTALL_AT", cfg.fail_install_at.as_os_str()),
                ("COUNT_RM", cfg.count_rm.as_os_str()),
                ("FAIL_RM_AT", cfg.fail_rm_at.as_os_str()),
                ("COUNT_CAT", cfg.count_cat.as_os_str()),
                ("FAIL_CAT_AT", cfg.fail_cat_at.as_os_str()),
                ("COUNT_TEST", cfg.count_test.as_os_str()),
                ("FAIL_TEST_AT", cfg.fail_test_at.as_os_str()),
            ] {
                vars.insert(key.into(), value.to_owned());
            }
            (crate::env::SysEnv::from_map(vars), cfg)
        }

        /// Reset every fault seam, then ARM exactly `fault` for the faulted
        /// push (crossed with the slot state — the restore/verify read-back
        /// failure lands on the occurrence that matches the slot state).
        fn reset_and_arm(&self, fault: TxnFault, state: SlotState) {
            for f in [
                &self.fail_sh,
                &self.fail_is_enabled,
                &self.fail_restart,
                &self.fail_probe,
                &self.fail_install_at,
                &self.fail_rm_at,
                &self.fail_cat_at,
                &self.fail_test_at,
            ] {
                let _ = std::fs::remove_file(f);
            }
            for c in [
                &self.count_install,
                &self.count_rm,
                &self.count_cat,
                &self.count_test,
            ] {
                std::fs::write(c, "0").unwrap();
            }
            match fault {
                // prepare fails in `resolve_remote_config_home` (the `sh -c`
                // config-home probe — a non-zero exit IS an error there, so
                // the fault propagates as a prepare failure).
                TxnFault::Prepare => std::fs::write(&self.fail_sh, "1").unwrap(),
                TxnFault::Apply => std::fs::write(&self.fail_restart, "1").unwrap(),
                TxnFault::Restore => {
                    // restore only runs INSIDE the compensation (entered by a
                    // failure): trigger it with an apply failure, then the
                    // restore step itself fails.
                    std::fs::write(&self.fail_restart, "1").unwrap();
                    match state {
                        SlotState::PriorGeneration => {
                            // restore's `install` (the prior content write-back)
                            // is the first install call of the push.
                            std::fs::write(&self.fail_install_at, "1").unwrap();
                        }
                        SlotState::FirstDeploy => {
                            // restore's `rm` (prior state: absent) is the first
                            // rm call of the push.
                            std::fs::write(&self.fail_rm_at, "1").unwrap();
                        }
                    }
                }
                TxnFault::VerifyRestored => {
                    // verify_restored only runs INSIDE the compensation
                    // (entered by a failure): trigger it with an apply
                    // failure, then the READ-BACK itself fails.
                    std::fs::write(&self.fail_restart, "1").unwrap();
                    match state {
                        SlotState::PriorGeneration => {
                            // the verify_restored content read is the 2nd cat
                            // (prepare's prior-capture was the 1st).
                            std::fs::write(&self.fail_cat_at, "2").unwrap();
                        }
                        SlotState::FirstDeploy => {
                            // the verify_restored absence read (`test ! -e`) is
                            // the 1st test call of the push.
                            std::fs::write(&self.fail_test_at, "1").unwrap();
                        }
                    }
                }
                TxnFault::VerificationExec => std::fs::write(&self.fail_probe, "1").unwrap(),
            }
        }
    }

    /// The engine's evidence path for one execution (mirrors
    /// [`ExecutionOutcome::failure_evidence`]): the domain outcomes PLUS the
    /// adapter-restoration proof carried by a `Restored` execution — the
    /// sealed proof flows to the kernel decision EXACTLY as the engine
    /// threads it (a `FailedAfterAdvance`/pre-swap execution NEVER carries
    /// evidence).
    fn fault_evidence(
        state: SlotExecution,
    ) -> (
        BTreeMap<SlotId, SlotOutcome>,
        BTreeMap<SlotId, crate::verify::adapters::transaction::VerifiedAdapterRestoration>,
    ) {
        let slot = SlotId::new("p1");
        let mut adapter_restored = BTreeMap::new();
        let o = match &state {
            SlotExecution::NotStarted => SlotOutcome::Skipped {
                observation: Observation::KnownAbsent,
            },
            SlotExecution::FailedBeforeAdvance { error } => SlotOutcome::FailedBeforeAdvance {
                observation: Observation::KnownAbsent,
                error: error.clone(),
            },
            SlotExecution::Advanced { observation, .. } => SlotOutcome::Activated {
                observation: observation.clone(),
            },
            SlotExecution::Restored {
                observation,
                adapter_restored: proof,
            } => {
                adapter_restored.insert(slot.clone(), proof.clone());
                SlotOutcome::Restored {
                    observation: observation.clone(),
                }
            }
            SlotExecution::FailedAfterAdvance { observation, error } => {
                SlotOutcome::FailedAfterAdvance {
                    observation: observation.clone(),
                    error: error.clone(),
                }
            }
            SlotExecution::Indeterminate { error } => SlotOutcome::Indeterminate {
                observation: Observation::KnownAbsent,
                error: error.clone(),
            },
        };
        (BTreeMap::from([(slot, o)]), adapter_restored)
    }

    /// Classify the faulted execution through the kernel's decision: build
    /// the one-slot intent (desired = the faulted push's NEW generation,
    /// pre_push = the prior state) and hand the evidence to
    /// [`decide_terminal`](crate::kernel::transition::decide_terminal).
    fn classify_fault(
        h: &Harness,
        state: SlotExecution,
        new_gen: &GenerationId,
        prior_gen: Option<&GenerationId>,
    ) -> (TerminalDisposition, SlotExecution) {
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::kernel::snapshot::SnapshotSlot;
        let sid = SlotId::new("p1");
        let members = h.config.target_slots("t1").unwrap();
        let (slot, server) = members[0];
        let artifact = ArtifactRef {
            release: h.harness_release_id(),
            variant: VariantName::new("standard"),
            tree: h.tree.clone(),
        };
        use crate::kernel::snapshot::PreviousGeneration;
        let pre_push: Observation<PreviousGeneration> = match prior_gen {
            Some(g) => Observation::Known(PreviousGeneration {
                generation: g.clone(),
                artifact: artifact.clone(),
            }),
            None => Observation::KnownAbsent,
        };
        let intent = crate::kernel::intent::plan(PlanInput {
            deployment_id: crate::identity::test_deployment_id("deploy-fault"),
            target: crate::identity::TargetName::parse("t1").unwrap(),
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: vec![sid.clone()],
            planned: vec![PlannedDeploy {
                slot: sid.clone(),
                result: SnapshotSlot::new(
                    new_gen.clone(),
                    artifact,
                    crate::ledger::PhysicalBinding::from_config(
                        crate::identity::ServerId::parse(server.id.as_str()).unwrap(),
                        slot.deploy_dir(),
                    )
                    .expect("test binding is absolute and traversal-free"),
                ),
                pre_push,
            }],
            behavior_digest: crate::testutil::fixtures::behavior_digest(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid one-slot fault intent plans");
        let (outcomes, adapter_restored) = fault_evidence(state.clone());
        let table = NonEmptySlotTable::build(outcomes).expect("one slot, non-empty outcomes");
        let disposition = crate::kernel::transition::decide_terminal(
            &intent,
            crate::kernel::transition::ExecutionReport::Failed {
                outcomes: table,
                adapter_restored,
            },
        )
        .expect("the fault evidence decides exactly one terminal");
        (disposition, state)
    }

    /// ONE fault-matrix case: a hermetic harness + the fault shims, a
    /// baseline push for the prior-generation state, then the faulted push
    /// driven through the REAL `process_server`, classified by the kernel.
    fn run_fault_case(fault: TxnFault, state: SlotState) -> (TerminalDisposition, SlotExecution) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let (env, shims) = FaultShims::install(dir.path(), &crate::testutil::fixture_env());
        let h = Harness::new(
            &env,
            SYSTEMD_TOML,
            FAULT_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                (
                    "units/example.service",
                    "[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
                ),
            ],
        );
        let prior_gen = match state {
            SlotState::FirstDeploy => None,
            SlotState::PriorGeneration => {
                let first = h.run(None);
                assert!(
                    matches!(first.state, SlotExecution::Advanced { .. }),
                    "the baseline deploy must advance: {:?}",
                    first.state
                );
                Some(
                    first
                        .state
                        .observed_generation()
                        .expect("an advanced baseline records its generation")
                        .clone(),
                )
            }
        };
        shims.reset_and_arm(fault, state);
        let new_gen = GenerationId::generate();
        let proc = h.run_with_new_gen(prior_gen.as_ref(), &new_gen);
        classify_fault(&h, proc.state, &new_gen, prior_gen.as_ref())
    }

    /// THE ADAPTER-SIDE-EFFECT FAULT-MATRIX PROPERTY (the review's P1
    /// acceptance — house style: bounded proptest cases, fixed seed, no
    /// persistence): generate EVERY adapter-side-effect failure point (fail
    /// at prepare / apply / restore / verify_restored — the
    /// `ActivationTransaction` methods — plus the verification adapter's
    /// exec failure), crossed with the slot states, and assert:
    ///
    /// * a slot whose adapter restoration is UNVERIFIED is NEVER part of a
    ///   `FailedRolledBack` terminal — it is `Degraded` CONTAINING that slot
    ///   (the delta is Desired — the slot is still on the advanced
    ///   generation — never Unchanged);
    /// * a VERIFIED restoration (`Restored` with the sealed proof — the
    ///   engine only produces it after a successful `verify_restored`
    ///   read-back) classifies `FailedRolledBack` (the slot's delta is
    ///   genuinely `Unchanged`);
    /// * the engine can never silently claim rolled back with an unverified
    ///   adapter side effect (structural: `Restored` carries the proof,
    ///   `FailedAfterAdvance` never does).
    #[test]
    fn adapter_side_effect_fault_matrix_never_claims_unverified_rollback() {
        for fault in [
            TxnFault::Prepare,
            TxnFault::Apply,
            TxnFault::Restore,
            TxnFault::VerifyRestored,
            TxnFault::VerificationExec,
        ] {
            for state in [SlotState::FirstDeploy, SlotState::PriorGeneration] {
                let (disposition, execution) = run_fault_case(fault, state);
                match &execution {
                    SlotExecution::Restored { .. } => {
                        // VERIFIED restoration: the slot is genuinely back —
                        // the rolled-back classification is legitimate.
                        assert!(
                            matches!(disposition, TerminalDisposition::FailedRolledBack(_)),
                            "fault {fault:?} x {state:?}: a VERIFIED adapter restoration must classify rolled back (the delta is Unchanged), got {disposition:?}"
                        );
                    }
                    SlotExecution::FailedAfterAdvance { .. } => {
                        // UNVERIFIED restoration: NEVER rolled back — the
                        // terminal is Degraded and CONTAINS the slot (its
                        // delta is Desired — still on the advanced
                        // generation).
                        assert!(
                            matches!(disposition, TerminalDisposition::Degraded(_)),
                            "fault {fault:?} x {state:?}: an UNVERIFIED adapter restoration must be Degraded, NEVER FailedRolledBack, got {disposition:?}"
                        );
                    }
                    other => {
                        panic!(
                            "fault {fault:?} x {state:?}: the faulted push must end Restored (verified) or FailedAfterAdvance (unverified), got {other:?}"
                        );
                    }
                }
            }
        }
    }

    /// THE VERIFY-READ MUTATION DETECTOR (the review's acceptance: a
    /// verify_restored that always succeeds must be DETECTABLE): if the
    /// restore did NOT take effect, the REAL read-back refuses the proof —
    /// the faulted slot is `FailedAfterAdvance` → Degraded. A fabricated
    /// always-Ok verify_restored would have classified the same scenario
    /// `FailedRolledBack` (the unit file still in the new state) — the
    /// property below would FAIL against the fabrication. The restore-fault
    /// arm of the matrix above is exactly this detector; this test makes the
    /// detection EXPLICIT at the unit level: after a failed restore, the
    /// engine's slot is FailedAfterAdvance (never Restored), and the remote
    /// still carries the NEW unit content.
    #[test]
    fn failed_restore_leaves_the_slot_failed_after_advance_and_the_remote_changed() {
        let (disposition, execution) =
            run_fault_case(TxnFault::Restore, SlotState::PriorGeneration);
        assert!(
            matches!(execution, SlotExecution::FailedAfterAdvance { .. }),
            "a restore failure must never classify the slot Restored: {execution:?}"
        );
        assert!(
            matches!(disposition, TerminalDisposition::Degraded(_)),
            "an unverified restore must be Degraded, never FailedRolledBack: {disposition:?}"
        );
        // The remote side effect stayed in the NEW state (the restore never
        // ran) — the read-back would have caught it.
    }
}

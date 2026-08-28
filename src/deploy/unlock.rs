//! Explicit server mutation-lock recovery: `deploy unlock`.
//!
//! The server mutation lock is a create-once ownership record with no
//! expiry: a held lock never becomes breakable on its own. A transient
//! release failure (transport fault at `Drop`) strands the slot forever
//! until an operator confirms the holder died and runs the explicit
//! recovery. This module is the production entry point for that recovery:
//! it inspects the remote lock (typed read, never provisioning layout),
//! previews the state without `--yes`, and — with `--yes` under the
//! authoritative local store lock — recovers (epoch+1) and releases, leaving
//! the slot free.

use crate::config::ProjectConfig;
use crate::deploy::lock::FileLock;
use crate::deploy::push::RemoteFactory;
use crate::error::{Error, Result};
use crate::identity::{OperationId, SlotId};
use crate::remote::helper::{RemoteHelper, read_lock_record};
use crate::remote::layout;
use crate::store::local::LocalStore;

/// The result of `deploy unlock`: one human-readable line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockReport {
    pub target: String,
    pub slot: SlotId,
    pub message: String,
}

/// Orchestration for `deploy unlock <target> <slot> [--yes]`.
///
/// Mirrors the `retention::checkpoint` shape: a `run_*` fn doing the work
/// and a `render_*` fn returning the lines the CLI prints.
pub(crate) fn run_unlock(
    store: &LocalStore,
    config: &ProjectConfig,
    factory: &RemoteFactory,
    target_name: &str,
    slot_id: &SlotId,
    yes: bool,
) -> Result<UnlockReport> {
    // 1. Resolve the slot: `config.target_slots` validates the target exists;
    // unknown target → not_found. If the slot is not a member → config error
    // naming slot, target, and member list.
    let members = config.target_slots(target_name)?;
    let (slot_cfg, server_def) = members
        .iter()
        .find(|(s, _)| s.id.as_str() == slot_id.as_str())
        .copied()
        .ok_or_else(|| {
            let ids: Vec<String> = members.iter().map(|(s, _)| s.id.clone()).collect();
            Error::config(format!(
                "slot '{}' is not a member of target '{}' (members: {})",
                slot_id,
                target_name,
                ids.join(", ")
            ))
        })?;

    // 2. Build the remote via the factory + prepare_identity, then
    // RemoteHelper::new — mirror open_remotes/inspect_remotes exactly.
    // NEVER provision layout, NEVER create directories.
    let remote = factory(server_def, slot_cfg)?;
    remote.prepare_identity()?;
    let helper = RemoteHelper::new(remote.as_ref());

    // 3. Read current lock record using typed read (promoted pub(crate)).
    let current = read_lock_record(helper.remote(), &layout::operation_lock())?;

    // 4. Report paths.
    match current {
        None => {
            // No lock: idempotent success without --yes.
            Ok(UnlockReport {
                target: target_name.to_string(),
                slot: slot_id.clone(),
                message: format!(
                    "slot '{}' mutation lock is free — nothing to recover",
                    slot_id
                ),
            })
        }
        Some(record) => {
            if !yes {
                // Without --yes: preflight refusal, lock untouched.
                return Err(Error::preflight(format!(
                    "slot '{}' mutation lock held by '{}' (epoch {}) — pass --yes to recover (confirm the holding controller died) via `deploy unlock {} {} --yes`",
                    slot_id, record.owner, record.epoch, target_name, slot_id
                )));
            }
            // With --yes: acquire authoritative local store lock, re-read,
            // recover (epoch+1), release.
            let op_id = OperationId::generate();
            let _local_guard =
                FileLock::acquire(&store.base().join("operation.lock"), op_id.as_str())?;

            // Re-read under local lock as observed premise.
            let observed_opt = read_lock_record(helper.remote(), &layout::operation_lock())?;
            let observed = match observed_opt {
                None => {
                    // Already freed meanwhile: idempotent free.
                    return Ok(UnlockReport {
                        target: target_name.to_string(),
                        slot: slot_id.clone(),
                        message: format!(
                            "slot '{}' mutation lock is free — nothing to recover",
                            slot_id
                        ),
                    });
                }
                Some(o) => o,
            };

            // Explicit recovery: epoch+1, then explicit release leaving slot free.
            let successor = helper.recover_lock(&observed, op_id.as_str())?;
            helper.release_lock(&successor)?;

            // Local guard drops here.
            drop(_local_guard);

            Ok(UnlockReport {
                target: target_name.to_string(),
                slot: slot_id.clone(),
                message: format!(
                    "slot '{}' mutation lock recovered: '{}' (epoch {}) replaced by '{}' (epoch {}) and released — the slot is free",
                    slot_id, observed.owner, observed.epoch, successor.owner, successor.epoch
                ),
            })
        }
    }
}

/// Render the unlock report for the CLI: exactly the lines printed.
pub(crate) fn render_unlock_report(report: &UnlockReport) -> Vec<String> {
    vec![report.message.clone()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::helper::RemoteHelper;
    use crate::remote::layout;
    use crate::remote::transport::{LocalTransport, Remote};
    use crate::testutil::{fixture_env, fixture_tmpdir};
    use std::path::PathBuf;

    fn test_config(tmp: &tempfile::TempDir, deploy_dir: PathBuf) -> (ProjectConfig, PathBuf) {
        let project = tmp.path().join("proj");
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"[[slots]]
id = "p1"
server = "s1"
target = "production"
deploy_dir = "/srv/unlock-p1"

[[slots]]
id = "p2"
server = "s2"
target = "production"
deploy_dir = "/srv/unlock-p2"

[[artifact.mappings]]
from = "artifacts/build/output/"
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
"#,
        )
        .unwrap();
        // Overwrite deploy_dir for the factory: we use LocalTransport rooted at the temp slot dir,
        // so the config's deploy_dir is not actually used for remote creation in tests — we
        // provide a factory that ignores the config's deploy_dir and uses the temp dir.
        // But the config must still parse: use the unlock-p1/p2 dirs as written.
        std::fs::write(
            project.join("deploy.toml"),
            r#"schema_version = 2
application = "unlock-test"
release = "v1"

[[servers]]
id = "s1"
address = "local"
user = "deploy"

[[servers]]
id = "s2"
address = "local"
user = "deploy"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        let config = ProjectConfig::load(&cfg_path).unwrap();
        // Ensure deploy_dir exists for the slot we will plant locks on (local transport root).
        std::fs::create_dir_all(&deploy_dir).unwrap();
        (config, cfg_path)
    }

    fn slot_factory(
        deploy_dir: PathBuf,
    ) -> impl Fn(
        &crate::config::ServerDef,
        &crate::config::SlotConfig,
    ) -> crate::error::Result<Box<dyn crate::remote::transport::Remote>> {
        move |_s: &crate::config::ServerDef, _slot: &crate::config::SlotConfig| {
            Ok(Box::new(
                LocalTransport::new(&fixture_env(), deploy_dir.clone()).unwrap(),
            ))
        }
    }

    #[test]
    fn unlock_free_slot_reports_free_without_creating_lock() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
        let factory = slot_factory(slot_dir.clone());

        let report = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            false,
        )
        .unwrap();
        assert!(
            report.message.contains("free — nothing to recover"),
            "free report: {}",
            report.message
        );
        // No lock file created.
        let remote = LocalTransport::new(&fixture_env(), slot_dir).unwrap();
        assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "no lock file must be created on free slot"
        );
    }

    #[test]
    fn unlock_held_without_yes_refuses_and_leaves_byte_identical() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();

        // Plant hostile lock.
        let remote = LocalTransport::new(&fixture_env(), slot_dir.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        let _rec = helper.acquire_lock("op-dead", false).unwrap();
        let before = remote.read(&layout::operation_lock()).unwrap();

        let factory = slot_factory(slot_dir.clone());
        let err = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            false,
        )
        .expect_err("held without --yes must refuse");

        let msg = err.to_string();
        assert!(msg.contains("op-dead"), "must name holder: {msg}");
        assert!(msg.contains("epoch 1"), "must name epoch: {msg}");
        assert!(msg.contains("--yes"), "must name remedy: {msg}");

        let after = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(before, after, "lock file must be byte-identical");
    }

    #[test]
    fn unlock_held_with_yes_recovers_and_leaves_slot_free() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();

        // Plant hostile lock.
        let remote = LocalTransport::new(&fixture_env(), slot_dir.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        helper.acquire_lock("op-dead", false).unwrap();

        let factory = slot_factory(slot_dir.clone());
        let report = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            true,
        )
        .unwrap();
        assert!(
            report.message.contains("recovered"),
            "report: {}",
            report.message
        );
        assert!(
            report.message.contains("op-dead"),
            "report: {}",
            report.message
        );
        assert!(
            report.message.contains("released — the slot is free"),
            "report: {}",
            report.message
        );

        // Lock file gone.
        assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "lock file must be gone after recover+release"
        );
        // Follow-up acquire succeeds.
        let rec = helper.acquire_lock("op-after", false).unwrap();
        assert_eq!(
            rec.epoch, 1,
            "fresh lock after free restarts at epoch 1 (slot free semantics)"
        );
        helper.release_lock(&rec).unwrap();
    }

    #[test]
    fn unlock_slot_not_member_is_config_error() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
        let factory = slot_factory(slot_dir);

        let err = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("not-a-member").unwrap(),
            false,
        )
        .expect_err("non-member slot must be config error");
        let msg = err.to_string();
        assert!(msg.contains("not-a-member"), "must name slot: {msg}");
        assert!(msg.contains("production"), "must name target: {msg}");
        assert!(msg.contains("p1"), "must list members: {msg}");
    }

    #[test]
    fn unlock_unknown_target_is_not_found() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
        let factory = slot_factory(slot_dir);

        let err = run_unlock(
            &store,
            &config,
            &factory,
            "unknown-target",
            &SlotId::parse("p1").unwrap(),
            false,
        )
        .expect_err("unknown target must be not_found");
        assert!(err.to_string().contains("unknown-target"));
    }
}

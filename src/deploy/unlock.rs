//! Explicit server mutation-lock recovery: `deploy unlock`.
//!
//! The server mutation lock is a create-once ownership record with no
//! expiry: a held lock never becomes breakable on its own. A transient
//! release failure (transport fault at `Drop`) strands the slot forever
//! until an operator confirms the holder died and runs the explicit
//! recovery. This module is the production entry point for that recovery:
//! it inspects the remote lock (typed read, never provisioning layout),
//! previews the state without `--yes`, and — with `--yes` under the
//! authoritative local store lock — recovers (fresh acquisition id) and releases, leaving
//! the slot free.

use crate::config::ProjectConfig;
use crate::deploy::lock::FileLock;
use crate::deploy::push::RemoteFactory;
use crate::error::{Error, Result};
use crate::identity::{AcquisitionId, OperationId, SlotId};
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
    acquisition: Option<AcquisitionId>,
    yes: bool,
) -> Result<UnlockReport> {
    // CLI binding rule: --yes requires --acquisition; --acquisition requires --yes.
    if yes && acquisition.is_none() {
        return Err(Error::preflight(format!(
            "unlock --yes requires --acquisition: pass --acquisition <id> with --yes after confirming the holding controller died (re-inspect via `deploy unlock {} {}` to obtain the acquisition id)",
            target_name, slot_id
        )));
    }
    if !yes && acquisition.is_some() {
        return Err(Error::preflight(
            "--acquisition requires --yes: pass --yes with --acquisition <id> after confirming the holding controller died",
        ));
    }
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
                // Without --yes: preflight refusal, lock untouched. The remedy line
                // must SHOW the literal `--acquisition <id>` to copy.
                return Err(Error::preflight(format!(
                    "slot '{}' mutation lock held by '{}' (acquisition {}) — pass --yes with --acquisition {} after confirming the holding controller died via `deploy unlock {} {} --acquisition {} --yes`",
                    slot_id,
                    record.operation_id,
                    record.acquisition_id,
                    record.acquisition_id,
                    target_name,
                    slot_id,
                    record.acquisition_id
                )));
            }
            // With --yes: the supplied acquisition is the operator's inspected
            // premise. Re-read under the authoritative local store lock and
            // REFUSE if the on-disk acquisition differs — NEVER reinterpret a
            // newer record as the confirmed premise.
            let supplied = acquisition.expect("--yes requires --acquisition (validated above)");
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

            if observed.acquisition_id != supplied {
                return Err(Error::preflight(format!(
                    "recovery refused: the lock now carries acquisition {}, not the {} you inspected; re-inspect and re-confirm",
                    observed.acquisition_id, supplied
                )));
            }

            // Explicit recovery: fresh acquisition id, then explicit release leaving slot free.
            let successor = helper.recover_lock(&observed, &op_id)?;
            helper.release_lock(&successor)?;

            // Local guard drops here.
            drop(_local_guard);

            Ok(UnlockReport {
                target: target_name.to_string(),
                slot: slot_id.clone(),
                message: format!(
                    "slot '{}' mutation lock recovered: '{}' (acquisition {}) replaced by '{}' (acquisition {}) and released — the slot is free",
                    slot_id,
                    observed.operation_id,
                    observed.acquisition_id,
                    successor.operation_id,
                    successor.acquisition_id
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

    fn acquire_via_guard(helper: &RemoteHelper, op_str: &str) -> crate::remote::helper::LockRecord {
        let op = crate::identity::OperationId::new(op_str.to_string());
        let guard = helper
            .acquire_lock_guard(&crate::identity::OperationId::new(op.to_string()))
            .unwrap();
        let bytes = helper
            .remote()
            .read(&crate::remote::layout::operation_lock())
            .unwrap();
        let rec: crate::remote::helper::LockRecord = serde_json::from_slice(&bytes).unwrap();
        std::mem::forget(guard);
        rec
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
            None,
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
        let _rec = acquire_via_guard(&helper, "op-dead");
        let before = remote.read(&layout::operation_lock()).unwrap();

        let factory = slot_factory(slot_dir.clone());
        let err = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            None,
            false,
        )
        .expect_err("held without --yes must refuse");

        let msg = err.to_string();
        assert!(msg.contains("op-dead"), "must name holder: {msg}");
        assert!(
            msg.contains("acquisition"),
            "must name acquisition id: {msg}"
        );
        assert!(msg.contains("--yes"), "must name remedy: {msg}");
        assert!(
            msg.contains("--acquisition"),
            "remedy must show --acquisition flag: {msg}"
        );
        // The exact acquisition id must appear as a literal to copy.
        let rec: crate::remote::helper::LockRecord = serde_json::from_slice(&before).unwrap();
        assert!(
            msg.contains(rec.acquisition_id.as_str()),
            "remedy must show literal acquisition id {}: {msg}",
            rec.acquisition_id
        );
        assert!(
            msg.contains(&format!("--acquisition {}", rec.acquisition_id)),
            "remedy must show `--acquisition <id>`: {msg}"
        );

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
        let rec = acquire_via_guard(&helper, "op-dead");

        let factory = slot_factory(slot_dir.clone());
        let report = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            Some(rec.acquisition_id.clone()),
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
        // Follow-up acquire succeeds with a fresh unique acquisition id.
        let rec = acquire_via_guard(&helper, "op-after");
        assert!(
            !rec.acquisition_id.as_str().is_empty(),
            "fresh lock after free carries an acquisition id"
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
            None,
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
            None,
            false,
        )
        .expect_err("unknown target must be not_found");
        assert!(err.to_string().contains("unknown-target"));
    }

    #[test]
    fn unlock_yes_without_acquisition_refuses_and_leaves_byte_identical() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
        let remote = LocalTransport::new(&fixture_env(), slot_dir.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        acquire_via_guard(&helper, "op-dead");
        let before = remote.read(&layout::operation_lock()).unwrap();
        let factory = slot_factory(slot_dir.clone());
        let err = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            None,
            true,
        )
        .expect_err("--yes without --acquisition must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("--acquisition"),
            "must name required flag: {msg}"
        );
        let after = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(before, after, "lock must be byte-identical after refusal");
    }

    #[test]
    fn unlock_acquisition_without_yes_refuses() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
        let remote = LocalTransport::new(&fixture_env(), slot_dir.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        let rec = acquire_via_guard(&helper, "op-dead");
        let before = remote.read(&layout::operation_lock()).unwrap();
        let factory = slot_factory(slot_dir.clone());
        let err = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            Some(rec.acquisition_id.clone()),
            false,
        )
        .expect_err("--acquisition without --yes must refuse");
        let msg = err.to_string();
        assert!(msg.contains("--acquisition"), "must name flag: {msg}");
        let after = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(before, after, "lock must be byte-identical");
    }

    #[test]
    fn unlock_mismatch_refuses_and_leaves_newer_byte_identical() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let slot_dir = dir.path().join("remote-p1");
        let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
        let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
        let remote = LocalTransport::new(&fixture_env(), slot_dir.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        // Inspect-A: plant A and record its acquisition.
        let rec_a = acquire_via_guard(&helper, "op-A");
        let acq_a = rec_a.acquisition_id.clone();
        // Release A -> acquire B (newer record installed after inspection).
        helper.release_lock(&rec_a).unwrap();
        let rec_b = acquire_via_guard(&helper, "op-B");
        assert_ne!(
            rec_b.acquisition_id, acq_a,
            "B must carry fresh acquisition"
        );
        let before_b = remote.read(&layout::operation_lock()).unwrap();
        let factory = slot_factory(slot_dir.clone());
        // Confirm with stale A — must refuse.
        let err = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            Some(acq_a.clone()),
            true,
        )
        .expect_err("mismatch must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains(rec_b.acquisition_id.as_str()),
            "must name on-disk acquisition {}: {msg}",
            rec_b.acquisition_id
        );
        assert!(
            msg.contains(acq_a.as_str()),
            "must name supplied acquisition {}: {msg}",
            acq_a
        );
        assert!(msg.contains("re-inspect"), "must ask to re-inspect: {msg}");
        let after = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(before_b, after, "newer record must remain byte-identical");
        // Matching acquisition succeeds.
        let report = run_unlock(
            &store,
            &config,
            &factory,
            "production",
            &SlotId::parse("p1").unwrap(),
            Some(rec_b.acquisition_id.clone()),
            true,
        )
        .unwrap();
        assert!(
            report.message.contains("recovered"),
            "report: {}",
            report.message
        );
        assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "slot free after matching recovery"
        );
    }

    // Proptest: inspect-A → release A → acquire B → confirm A (--acquisition <A> --yes)
    // must refuse and leave B byte-identical. Fixed seed, proptest_cases(64),
    // failure_persistence: None per house style.
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: crate::testutil::proptest_cases(64),
            max_shrink_iters: 10000,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]
        #[test]
        fn unlock_proptest_stale_acquisition_refused(
            tag_a in prop::sample::select(vec!["proptest-A1", "proptest-A2", "proptest-A3"]),
            tag_b in prop::sample::select(vec!["proptest-B1", "proptest-B2", "proptest-B3"]),
        ) {
            let dir = fixture_tmpdir(&fixture_env()).unwrap();
            let slot_dir = dir.path().join("remote-p1");
            let (config, _cfg_path) = test_config(&dir, slot_dir.clone());
            let store = crate::store::local::LocalStore::with_base(dir.path().join("store")).unwrap();
            let remote = LocalTransport::new(&fixture_env(), slot_dir.clone()).unwrap();
            let helper = RemoteHelper::new(&remote);
            let rec_a = acquire_via_guard(&helper, &format!("op-{tag_a}"));
            let acq_a = rec_a.acquisition_id.clone();
            helper.release_lock(&rec_a).unwrap();
            let rec_b = acquire_via_guard(&helper, &format!("op-{tag_b}"));
            prop_assert_ne!(rec_b.acquisition_id.clone(), acq_a.clone());
            let before_b = remote.read(&layout::operation_lock()).unwrap();
            let factory = slot_factory(slot_dir.clone());
            let acq_b = rec_b.acquisition_id.clone();
            let err = run_unlock(
                &store,
                &config,
                &factory,
                "production",
                &SlotId::parse("p1").unwrap(),
                Some(acq_a.clone()),
                true,
            ).expect_err("stale acquisition must be refused");
            let msg = err.to_string();
            prop_assert!(msg.contains(acq_b.as_str()), "must name on-disk: {msg}");
            prop_assert!(msg.contains(acq_a.as_str()), "must name supplied: {msg}");
            let after = remote.read(&layout::operation_lock()).unwrap();
            prop_assert_eq!(before_b, after, "B must remain byte-identical");
        }
    }
}

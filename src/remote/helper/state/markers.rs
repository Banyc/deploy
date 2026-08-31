//! Write-once commit markers ([`RemoteHelper::write_commit_marker`]): the
//! immutable per-deployment commit record under `state/commits/`.

use crate::error::{Error, Result};
use crate::identity::DeploymentId;
use crate::remote::layout;
use crate::remote::transport::{CreateNewVerdict, VerifiedExisting};

use super::super::HeldSlotLock;
#[allow(unused_imports)]
use super::super::RemoteHelper;

impl<'a> HeldSlotLock<'a> {
    /// Write a commit marker for a deployment under this server. Requires the
    /// slot-mutation capability — the receiver is the guard; the helper is the
    /// guard's own. The marker records the generation
    /// this slot committed, the full set of placement slot IDs that
    /// participate in the commit (so a partial marker can never masquerade as
    /// a complete commit), and the originating target of the push. `target`
    /// is optional for legacy markers written before originating-target
    /// attribution existed; new commits always record it.
    ///
    /// Markers are immutable and write-once: the file is created exclusively,
    /// and an existing record must match byte-for-byte (deterministic payload
    /// for the same deployment) or the rewrite fails integrity. A concurrent or
    /// retried commit therefore never corrupts a recorded fact.
    pub fn write_commit_marker(
        &self,
        deployment_id: &DeploymentId,
        generation: &str,
        slot_ids: &[String],
        target: Option<&str>,
    ) -> Result<()> {
        let p = layout::commit_marker(deployment_id);
        let mut payload = serde_json::json!({
            "deployment_id": deployment_id,
            "committed": true,
            "generation": generation,
            "slots": slot_ids});
        if let Some(t) = target {
            payload["target"] = serde_json::json!(t);
        }
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| Error::remote(format!("serialize commit: {e}")))?;
        // The TYPED verdict: `Created` installed the marker, `AlreadyPresent`
        // means the winner was VERIFIED as a regular file with the exact mode
        // and byte-identical content (the identical retry converges — treat
        // like success with "already there" semantics). A `Conflict` carries
        // the TYPED reason: a CONTENT mismatch means the winner's bytes
        // differ (the transport already performed the byte comparison — a
        // read-back would only re-derive the same verdict), and a METADATA
        // conflict — a directory/symlink where the marker should be, a mode
        // mismatch, an unreadable entry — is a real marker-integrity
        // conflict, never silently accepted as "already present, fine".
        match self.helper.remote.try_write_new(&p, &bytes)? {
            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => Ok(()),
            CreateNewVerdict::Conflict(reason) => Err(Error::integrity(match reason {
                VerifiedExisting::ContentMismatch => format!(
                    "commit marker for {deployment_id} already exists with different content"
                ),
                VerifiedExisting::ModeMismatch { actual, required } => format!(
                    "commit marker for {deployment_id} exists with mode {actual:o} (required {required:o})"
                ),
                VerifiedExisting::NotRegularFile { kind } => format!(
                    "commit marker for {deployment_id} exists as a {kind:?} entry, not a regular file"
                ),
                VerifiedExisting::Unreadable(e) => format!(
                    "commit marker for {deployment_id} exists but could not be verified: {e}"
                ),
                VerifiedExisting::NotFound => {
                    format!("commit marker for {deployment_id} vanished during verification")
                }
                VerifiedExisting::Ok { .. } => {
                    unreachable!("a verified-ok entry is AlreadyPresent, never Conflict")
                }
            })),
        }
    }
}

#[cfg(test)]
mod tests_markers {
    use super::*;
    use crate::identity::test_deployment_id;
    use crate::remote::transport::LocalTransport;
    use crate::remote::transport::Remote;
    use std::path::PathBuf;

    fn setup() -> (tempfile::TempDir, LocalTransport, PathBuf) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let root = remote.root().to_path_buf();
        (dir, remote, root)
    }

    /// Same recovery rule for commit markers: an interrupted write never
    /// surfaces as a partial marker, and a later commit succeeds cleanly.
    #[test]
    fn interrupted_commit_marker_write_is_recovered() {
        let (_dir, remote, root) = setup();

        std::fs::create_dir_all(root.join(layout::commits_dir())).unwrap();
        let marker = layout::commit_marker(&test_deployment_id("deploy-0"));
        let tmp = marker
            .with_file_name(format!(
                ".{}.tmp.99999.7",
                marker.file_name().unwrap().to_string_lossy()
            ))
            .unwrap();
        std::fs::write(
            root.join(&tmp),
            b"{ \"deployment_id\": \"deploy-0\", \"commi",
        )
        .unwrap();

        let helper = RemoteHelper::new(&remote);
        let _guard = helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-marker".to_string()))
            .unwrap();
        _guard
            .write_commit_marker(
                &test_deployment_id("deploy-0"),
                "gen-0",
                &["p1".to_string()],
                Some("t1"),
            )
            .expect("commit marker install must succeed past stale temp");

        let marker: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(layout::commit_marker(&test_deployment_id("deploy-0"))))
                .unwrap(),
        )
        .expect("installed commit marker must be valid JSON");
        assert_eq!(marker["committed"], serde_json::json!(true));
        assert_eq!(marker["generation"], serde_json::json!("gen-0"));
    }

    /// A SYMLINK where a commit marker should be — even one pointing at a
    /// byte-identical regular file — is a marker-integrity CONFLICT, never
    /// silently accepted as "already present, fine". The lstat guarantee:
    /// the symlink is never followed, so a symlink that would verify as a
    /// perfect retry if followed is still rejected as
    /// `NotRegularFile { Symlink }`.
    #[test]
    fn commit_marker_symlink_is_a_conflict_never_followed() {
        let (_dir, remote, root) = setup();
        let marker = layout::commit_marker(&test_deployment_id("deploy-0"));
        std::fs::create_dir_all(root.join(marker.parent().unwrap())).unwrap();

        // The marker the writer would install: deterministic bytes for this
        // (deployment, generation, slots, target). The symlink points AT a
        // regular file carrying EXACTLY these bytes and the canonical mode —
        // a stat (which follows symlinks) would accept it as an identical
        // retry; the lstat must not.
        let payload = serde_json::json!({
            "deployment_id": "deploy-0",
            "committed": true,
            "generation": "gen-0",
            "slots": ["p1"],
            "target": "t1"});
        let bytes = serde_json::to_vec_pretty(&payload).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let target = root.join("target.json");
        std::fs::write(&target, &bytes).unwrap();
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(crate::remote::transport::IMMUTABLE_RECORD_MODE),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, root.join(&marker)).unwrap();

        let helper = RemoteHelper::new(&remote);
        let _guard = helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-symlink".to_string()))
            .unwrap();
        let err = _guard
            .write_commit_marker(
                &test_deployment_id("deploy-0"),
                "gen-0",
                &["p1".to_string()],
                Some("t1"),
            )
            .expect_err("a symlink where the marker should be is a real conflict");
        let msg = err.to_string();
        assert!(
            msg.contains("Symlink"),
            "error must name the NotRegularFile(Symlink) reason, got: {msg}"
        );
        // The symlink (and its target) stay untouched.
        assert!(
            std::fs::symlink_metadata(root.join(&marker))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    }

    /// Concurrent readers listing and parsing commit markers while they are
    /// being installed must only ever observe complete records.
    #[test]
    fn commit_markers_are_never_partially_visible_to_concurrent_readers() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("remote");
        let commits_dir = root.join(layout::commits_dir());
        let done = Arc::new(AtomicBool::new(false));

        // Set even if the writer panics (Drop runs during unwind), so the
        // readers always terminate instead of hanging the test binary.
        struct DoneGuard(Arc<AtomicBool>);
        impl Drop for DoneGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        std::thread::scope(|s| {
            let base = root.clone();
            let done_w = done.clone();
            let writer_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let writer_error_writer = writer_error.clone();
            s.spawn(move || {
                let _done = DoneGuard(done_w);
                let Ok(remote) = LocalTransport::new(&crate::testutil::fixture_env(), base) else {
                    *writer_error_writer.lock().unwrap() =
                        Some("transport setup failed".to_string());
                    return;
                };
                let h = RemoteHelper::new(&remote);
                // Acquire a single guard covering the burst of marker writes
                // (the capability is per-slot, reused across writes in this
                // test harness).
                let _guard = h
                    .acquire_lock_guard(&crate::identity::OperationId::new("op-burst".to_string()))
                    .unwrap();
                for i in 0..80 {
                    if let Err(e) = _guard.write_commit_marker(
                        &test_deployment_id(&format!("deploy-{i}")),
                        &format!("gen-{i}"),
                        &["p1".to_string()],
                        Some("t1"),
                    ) {
                        *writer_error_writer.lock().unwrap() = Some(e.to_string());
                        return;
                    }
                }
            });
            for _ in 0..2 {
                let done = done.clone();
                let commits_dir = commits_dir.clone();
                s.spawn(move || {
                    loop {
                        if done.load(Ordering::SeqCst) {
                            break;
                        }
                        if let Ok(entries) = std::fs::read_dir(&commits_dir) {
                            for e in entries.flatten() {
                                // Temporaries are dot-prefixed so listing-based
                                // observers can skip them.
                                if e.file_name().to_string_lossy().starts_with('.') {
                                    continue;
                                }
                                let data = std::fs::read(e.path()).unwrap_or_default();
                                if data.is_empty() {
                                    panic!("concurrent reader observed an empty marker");
                                }
                                let v: serde_json::Value = serde_json::from_slice(&data)
                                    .expect("marker must always be complete valid JSON");
                                assert_eq!(v["committed"], serde_json::json!(true));
                            }
                        }
                    }
                });
            }

            // The writer must have completed every install successfully.
            assert_eq!(
                writer_error.lock().unwrap().as_deref(),
                None,
                "writer failed to install all commit markers"
            );
        });

        for i in 0..80 {
            // The marker is written under the CANONICAL deployment id (the
            // typed identity the layout builder names), so the read-back uses
            // the same canonical id — never a raw fixture string.
            // The marker is written under the CANONICAL deployment id (the
            // typed identity the layout builder names), so the read-back uses
            // the same canonical id — never a raw fixture string. The marker
            // path is relative to the REMOTE ROOT, so it is joined onto the
            // root (not onto the commits dir, which would double the prefix).
            let p = root.join(layout::commit_marker(&test_deployment_id(&format!(
                "deploy-{i}"
            ))));
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            assert_eq!(v["committed"], serde_json::json!(true));
        }
    }
}

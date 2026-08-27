//! Write-once commit markers ([`RemoteHelper::write_commit_marker`]): the
//! immutable per-deployment commit record under `state/commits/`.

use crate::error::{Error, Result};
use crate::remote::layout;

use super::super::RemoteHelper;

impl<'a> RemoteHelper<'a> {
    /// Write a commit marker for a deployment under this server. The marker
    /// records the generation this slot committed, the full set of placement
    /// slot IDs that participate in the commit (so a partial marker can
    /// never masquerade as a complete commit), and the originating target of
    /// the push. `target` is optional for legacy markers written before
    /// originating-target attribution existed; new commits always record it.
    ///
    /// Markers are immutable and write-once: the file is created exclusively,
    /// and an existing record must match byte-for-byte (deterministic payload
    /// for the same deployment) or the rewrite fails integrity. A concurrent or
    /// retried commit therefore never corrupts a recorded fact.
    pub fn write_commit_marker(
        &self,
        deployment_id: &str,
        generation: &str,
        slot_ids: &[String],
        target: Option<&str>,
    ) -> Result<()> {
        let p = layout::commit_marker(deployment_id);
        let mut payload = serde_json::json!({
            "deployment_id": deployment_id,
            "committed": true,
            "generation": generation,
            "slots": slot_ids,
        });
        if let Some(t) = target {
            payload["target"] = serde_json::json!(t);
        }
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| Error::remote(format!("serialize commit: {e}")))?;
        if self.remote.try_write_new(&p, &bytes)? {
            return Ok(());
        }
        let existing = self.remote.read(&p)?;
        if existing != bytes {
            return Err(Error::integrity(format!(
                "commit marker for {deployment_id} already exists with different content"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests_markers {
    use super::*;
    use crate::remote::transport::LocalTransport;
    use crate::remote::transport::Remote;
    use std::path::PathBuf;

    fn setup() -> (tempfile::TempDir, LocalTransport, PathBuf) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote = LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote")).unwrap();
        let root = remote.root().to_path_buf();
        (dir, remote, root)
    }

    /// Same recovery rule for commit markers: an interrupted write never
    /// surfaces as a partial marker, and a later commit succeeds cleanly.
    #[test]
    fn interrupted_commit_marker_write_is_recovered() {
        let (_dir, remote, root) = setup();

        std::fs::create_dir_all(root.join(layout::commits_dir())).unwrap();
        let marker = layout::commit_marker("deploy-0");
        let tmp = marker.with_file_name(format!(
            ".{}.tmp.99999.7",
            marker.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(
            root.join(&tmp),
            b"{ \"deployment_id\": \"deploy-0\", \"commi",
        )
        .unwrap();

        let helper = RemoteHelper::new(&remote);
        helper
            .write_commit_marker("deploy-0", "gen-0", &["p1".to_string()], Some("t1"))
            .expect("commit marker install must succeed past stale temp");

        let marker: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(layout::commit_marker("deploy-0"))).unwrap(),
        )
        .expect("installed commit marker must be valid JSON");
        assert_eq!(marker["committed"], serde_json::json!(true));
        assert_eq!(marker["generation"], serde_json::json!("gen-0"));
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
                for i in 0..80 {
                    if let Err(e) = h.write_commit_marker(
                        &format!("deploy-{i}"),
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
            let p = commits_dir.join(format!("deploy-{i}.json"));
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            assert_eq!(v["committed"], serde_json::json!(true));
        }
    }
}

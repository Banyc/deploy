//! The protocol handshake ([`RemoteHelper::handshake`]): first-contact
//! `control/protocol.json` marker and version refusal on mismatch.

use crate::error::{Error, Result};
use crate::remote::layout;
use crate::remote::transport::{CreateNewVerdict, VerifiedExisting};

use super::RemoteHelper;

impl<'a> RemoteHelper<'a> {
    /// Protocol handshake. Records the protocol version marker.
    /// Negotiate the remote-state protocol version.
    ///
    /// First contact records this client's `PROTOCOL_VERSION` under
    /// `control/protocol.json` via exclusive create; every later contact reads
    /// it back and refuses on any mismatch, so an old client can never drive a
    /// state directory written by a newer one (and vice versa). Returns the
    /// agreed version.
    pub fn handshake(&self) -> Result<u32> {
        let marker =
            serde_json::json!({ "protocol_version": crate::remote::transport::PROTOCOL_VERSION });
        let bytes = serde_json::to_vec_pretty(&marker)
            .map_err(|e| Error::remote(format!("serialize marker: {e}")))?;
        let marker_path = layout::protocol_marker();
        // The TYPED verdict: `Created` wrote the marker, `AlreadyPresent`
        // means it was VERIFIED as a regular file with the exact mode and
        // byte-identical content (the identical retry — the parse below
        // would only re-derive the same version). A `Conflict` carries the
        // TYPED reason: only a CONTENT mismatch (the marker exists with
        // different bytes — a different version, or a different
        // serialization) keeps the read-back parse; a METADATA conflict — a
        // directory/symlink where the marker should be, a mode mismatch, an
        // unreadable entry — refuses the negotiation outright, never
        // accepted as "already present, fine".
        match self.remote.try_write_new(&marker_path, &bytes)? {
            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => {
                Ok(crate::remote::transport::PROTOCOL_VERSION)
            }
            CreateNewVerdict::Conflict(reason) => match reason {
                VerifiedExisting::ContentMismatch => {
                    #[derive(serde::Deserialize)]
                    struct ProtocolMarker {
                        protocol_version: u32,
                    }
                    let existing = self.remote.read(&marker_path)?;
                    let recorded: ProtocolMarker =
                        serde_json::from_slice(&existing).map_err(|e| {
                            Error::remote(format!(
                                "corrupt control/protocol.json: {e}; refusing to negotiate"
                            ))
                        })?;
                    if recorded.protocol_version != crate::remote::transport::PROTOCOL_VERSION {
                        return Err(Error::remote(format!(
                            "protocol mismatch: remote state was written with protocol {}, but this client speaks {}",
                            recorded.protocol_version,
                            crate::remote::transport::PROTOCOL_VERSION
                        )));
                    }
                    Ok(recorded.protocol_version)
                }
                reason => Err(Error::remote(format!(
                    "corrupt control/protocol.json: refusing to negotiate (conflict: {reason:?})"
                ))),
            },
        }
    }
}

#[cfg(test)]
mod tests_protocol {
    use super::*;
    use crate::remote::transport::LocalTransport;
    use crate::remote::transport::PROTOCOL_VERSION;
    use crate::remote::transport::Remote;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn setup() -> (tempfile::TempDir, LocalTransport, PathBuf) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let root = remote.root().to_path_buf();
        (dir, remote, root)
    }

    /// A crash during a protocol-marker install leaves only an orphaned temp
    /// file: the final marker is absent, and a later handshake installs the
    /// complete record without being confused by the stale temporary.
    #[test]
    fn interrupted_protocol_marker_write_is_recovered() {
        let (_dir, remote, root) = setup();

        // Simulate a writer that died after creating its unique temp and
        // writing only a prefix of the payload.
        let marker = layout::protocol_marker();
        let tmp = marker
            .with_file_name(format!(
                ".{}.tmp.99999.7",
                marker.file_name().unwrap().to_string_lossy()
            ))
            .unwrap();
        std::fs::create_dir_all(root.join(marker.parent().unwrap())).unwrap();
        std::fs::write(root.join(&tmp), b"{ \"protocol_ver").unwrap();
        assert!(!root.join(&marker).exists());

        let helper = RemoteHelper::new(&remote);
        let agreed = helper.handshake().expect("handshake must recover");
        assert_eq!(agreed, PROTOCOL_VERSION);

        // The installed marker is complete and correct.
        let recorded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(layout::protocol_marker())).unwrap())
                .expect("installed protocol marker must be valid JSON");
        assert_eq!(
            recorded["protocol_version"],
            serde_json::json!(PROTOCOL_VERSION)
        );
    }

    /// The handshake REFUSES a state directory written by a DIFFERENT
    /// protocol version: a marker carrying a version other than the client's
    /// must make `handshake()` fail on read-back (an old client can never
    /// drive a state directory written by a newer one, and vice versa). This
    /// is the documented cross-version corruption invariant; the recovery test
    /// above covers only the interrupted-write half of the marker lifecycle.
    #[test]
    fn protocol_version_mismatch_refuses_handshake() {
        let (_dir, remote, root) = setup();
        let marker = layout::protocol_marker();
        std::fs::create_dir_all(root.join(marker.parent().unwrap())).unwrap();
        std::fs::write(
            root.join(&marker),
            format!("{{\"protocol_version\": {}}}", PROTOCOL_VERSION + 1),
        )
        .unwrap();
        // Pin the marker mode to the handshake's required 0o644: `std::fs::write`
        // creates with `0o666 & ~umask` (0o644 under macOS's 0o022, 0o664 under
        // Linux's 0o002) — an unpinned mode would fail the handshake with a
        // ModeMismatch BEFORE the version check, masking the case under test.
        std::fs::set_permissions(root.join(&marker), std::fs::Permissions::from_mode(0o644))
            .unwrap();

        let err = RemoteHelper::new(&remote)
            .handshake()
            .expect_err("a mismatched protocol marker must refuse the handshake");
        let msg = err.to_string();
        assert!(
            msg.contains("protocol mismatch"),
            "error must report the protocol mismatch, got: {msg}"
        );
        assert!(
            msg.contains(PROTOCOL_VERSION.to_string().as_str())
                && msg.contains((PROTOCOL_VERSION + 1).to_string().as_str()),
            "error must name both recorded and client protocol versions, got: {msg}"
        );
    }
}

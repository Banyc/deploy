//! Adoption of `deploy`'s LEGACY receiver marker into the crate-format one.
//!
//! Every provisioned deploy_dir carries its PHYSICAL identity as
//! `recv-<uuid-v7>` at [`crate::remote::layout::receiver_uuid`]
//! (`receiver-uuid`). `storekit` does not understand that format: it reads
//! and validates an opaque receiver id — EXACTLY 40 lowercase hex characters,
//! stored as `<id>\n` at the path its caller supplies as
//! `storekit::transport::Layout::receiver_marker` — and FAILS CLOSED on
//! anything else, with no adoption path of its own, because silently adopting
//! a foreign format would misidentify a deploy_dir.
//!
//! This module is `deploy`'s adoption path, run from
//! [`crate::remote::transport::read_receiver_uuid_opt`] when a deploy_dir is
//! read and still carries ONLY the legacy marker. It DERIVES a crate-format
//! receiver id from the legacy UUID (see [`derive_receiver_id`]), writes it
//! at [`crate::remote::layout::receiver_id`] (`receiver-id`, a sibling of the
//! legacy file), and leaves the legacy file UNTOUCHED.
//!
//! # Why the legacy file is kept, and what would make it removable
//!
//! The legacy `receiver-uuid` marker is the deploy_dir's identity for every
//! `deploy` release that predates `storekit`, and it is what the ledger, the
//! recovery guards, and duplicate-location detection compare. Deleting or
//! rewriting it during the migration would destroy the only identity those
//! readers understand and would make the adoption irreversible. Keeping it
//! makes the migration a pure ADDITION: the derived id is recoverable at any
//! time by re-running the derivation, and rolling `storekit` back to the
//! legacy substrate needs no undo.
//!
//! `receiver-uuid` becomes removable only after BOTH hold: (1) no deployed
//! `deploy` release still reads it as the physical identity (the substrate
//! swap lands, and the ledger carries the crate-format id), and (2) every
//! provisioned deploy_dir has a validated `receiver-id` marker. Until then
//! the adoption deliberately leaves the legacy file in place.

use super::{CreateNewVerdict, Remote};
use crate::identity::ReceiverUuid;
use crate::remote::layout;
use storekit::error::{Error, Result};

/// The exact number of lowercase hex characters in a crate-format receiver
/// id. MUST match `storekit::transport::RECEIVER_ID_LEN` (40): it is not
/// re-exported, so the two crates agree on the wire form and this constant
/// pins it here.
pub(crate) const RECEIVER_ID_LEN: usize = 40;

/// Domain separation for the derivation: the derived id is a digest of a
/// string that can never be confused with a digest of the legacy UUID alone,
/// so the same legacy string hashed for any OTHER purpose can never equal a
/// derived receiver id. `\0` terminates the domain so the domain and the
/// legacy string cannot run together (`"a" + "bc"` vs `"ab" + "c"`).
const DERIVATION_DOMAIN: &[u8] = b"deploy/receiver-id/v1\0";

/// A VALIDATED crate-format receiver id: exactly [`RECEIVER_ID_LEN`]
/// lowercase hex characters. Byte-for-byte the shape
/// `storekit::transport::ReceiverId::parse` accepts, so anything this type
/// holds is a value the crate will read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiverId(String);

impl ReceiverId {
    /// Validate `raw` as a crate-format receiver id: EXACTLY 40 lowercase
    /// hex characters. Anything else (empty, wrong length, uppercase,
    /// non-hex) is rejected. Mirrors `storekit::transport::ReceiverId::parse`
    /// so the two crates agree on the wire form byte for byte.
    pub(crate) fn parse(raw: &str) -> Result<ReceiverId> {
        let valid = raw.len() == RECEIVER_ID_LEN
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if valid {
            Ok(ReceiverId(raw.to_string()))
        } else {
            Err(Error::transport(format!(
                "invalid receiver id {raw:?}: expected {RECEIVER_ID_LEN} lowercase hex characters"
            )))
        }
    }

    /// The id as a string slice (40 lowercase hex characters).
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// The wire form the crate stores and reads: the id followed by a
    /// newline. Byte-for-byte `storekit::transport::ReceiverId::wire_bytes`.
    pub(crate) fn wire_bytes(&self) -> Vec<u8> {
        let mut out = self.as_str().as_bytes().to_vec();
        out.push(b'\n');
        out
    }
}

/// Derive the crate-format receiver id from a legacy receiver UUID,
/// DETERMINISTICALLY: `sha256(domain || legacy.as_str())[..20]` as lowercase
/// hex. The input is the CANONICAL legacy string ([`ReceiverUuid::as_str`] —
/// the trimmed, validated `recv-<uuid-v7>`), never the raw file bytes, so a
/// whitespace-only difference in the marker file cannot change the id.
///
/// Stability and collision:
///
/// * STABLE FOREVER: SHA-256 is deterministic and the input is the canonical
///   legacy identity, so the same legacy marker always derives the same
///   40-hex id — re-running the derivation, on any host, at any time, agrees.
/// * NO COLLISION WITH ANOTHER DIRECTORY: distinct legacy UUIDs give distinct
///   inputs (the domain is a fixed prefix, so `legacy_a != legacy_b` implies
///   `domain || legacy_a != domain || legacy_b`), and distinct inputs collide
///   on the 160-bit truncation only with birthday probability ~2^-80 — below
///   the crate's own 160-bit ids' collision budget. Two deploy_dirs therefore
///   can never share a derived id unless they share a physical identity.
/// * DOMAIN-SEPARATED: the fixed prefix keeps the digest from coinciding with
///   any other SHA-256 use of the same legacy string.
pub(crate) fn derive_receiver_id(legacy: &ReceiverUuid) -> ReceiverId {
    let mut input = Vec::with_capacity(DERIVATION_DOMAIN.len() + legacy.as_str().len());
    input.extend_from_slice(DERIVATION_DOMAIN);
    input.extend_from_slice(legacy.as_str().as_bytes());
    let digest = crate::digest::sha256_bytes(&input);
    ReceiverId(digest[..RECEIVER_ID_LEN].to_string())
}

/// Read and validate the crate-format receiver-id marker. `Ok(None)` ONLY
/// for a CONFIRMED ABSENT marker; a present marker that is not valid UTF-8
/// or not a well-formed crate id is an `Err` (fail closed — a marker that
/// exists but cannot be parsed is never silently treated as absent, the same
/// stance `storekit`'s `read_receiver_id_opt` takes).
pub(crate) fn read_receiver_id_opt<R: Remote + ?Sized>(remote: &R) -> Result<Option<ReceiverId>> {
    let marker = layout::receiver_id();
    if remote.metadata_opt(&marker)?.is_none() {
        return Ok(None);
    }
    let data = remote.read(&marker)?;
    let text = std::str::from_utf8(&data).map_err(|e| {
        Error::transport(format!(
            "deploy_dir {}: the crate-format receiver-id marker at {marker} is not valid UTF-8: {e}",
            remote.root().display()
        ))
    })?;
    ReceiverId::parse(text.trim()).map(Some).map_err(|e| {
        Error::transport(format!(
            "deploy_dir {}: refusing the crate-format receiver-id marker at {marker}: {e}. This \
             is a FAIL-CLOSED refusal — a marker that is neither the legacy `recv-<uuid-v7>` form \
             nor a {RECEIVER_ID_LEN}-character lowercase-hex receiver id is never adopted, because \
             silently adopting a corrupt or foreign format would misidentify the deploy_dir.",
            remote.root().display()
        ))
    })
}

/// Ensure the crate-format receiver-id marker exists for `legacy`, adopting
/// it ONCE. Idempotent: when a well-formed marker is already present the call
/// only READS it and returns (no write, no replace). The derivation is the
/// only writer, and it never overwrites a marker it has already written
/// because the presence check short-circuits first.
///
/// A present-but-malformed marker is REFUSED ([`read_receiver_id_opt`]) — the
/// adoption never repairs or replaces it. The install itself goes through
/// [`Remote::try_write_new`] (durable create-new, never replace), so a
/// concurrent adopter converges: whichever writes first is the marker.
pub(crate) fn adopt_receiver_marker<R: Remote + ?Sized>(
    remote: &R,
    legacy: &ReceiverUuid,
) -> Result<()> {
    // Fast path AND validation: an existing marker must be well-formed, and
    // an existing well-formed marker is already the adopted one.
    if read_receiver_id_opt(remote)?.is_some() {
        return Ok(());
    }
    let marker = layout::receiver_id();
    let id = derive_receiver_id(legacy);
    match remote.try_write_new(&marker, &id.wire_bytes())? {
        CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => Ok(()),
        CreateNewVerdict::Conflict(reason) => Err(Error::transport(format!(
            "deploy_dir {}: could not adopt the crate-format receiver-id marker at {marker}: the \
             path exists but is not an identical regular file ({reason:?}); refusing to replace it",
            remote.root().display()
        ))),
    }
}

/// Read the deploy_dir's IMMUTABLE receiver-UUID marker
/// ([`crate::remote::layout::receiver_uuid`]) and parse it. Fails closed on
/// a MISSING marker (the deploy_dir was never provisioned, or was
/// provisioned before the receiver-UUID feature) and on a MALFORMED marker
/// (a tampered/foreign marker is never accepted as a physical identity).
pub(crate) fn read_receiver_uuid<R: Remote + ?Sized>(remote: &R) -> Result<ReceiverUuid> {
    read_receiver_uuid_opt(remote)?.ok_or_else(|| {
        Error::transport(format!(
            "deploy_dir {}: no receiver-UUID marker (the deploy_dir was never provisioned, or was provisioned before the receiver-UUID feature)",
            remote.root().display()
        ))
    })
}

/// READ-ONLY twin of [`read_receiver_uuid_opt`]: read and validate the
/// deploy_dir's receiver identity WITHOUT adopting a legacy marker. Returns
/// `Ok(None)` ONLY for a CONFIRMED absent marker; a read failure or a marker
/// (legacy OR crate-format) that cannot be parsed is an `Err` (fail closed).
///
/// This is the read a DRY RUN uses: a dry run touches nothing, so it must not
/// write the crate-format marker either.
pub(crate) fn peek_receiver_uuid_opt<R: Remote + ?Sized>(
    remote: &R,
) -> Result<Option<ReceiverUuid>> {
    let marker = layout::receiver_uuid();
    if remote.metadata_opt(&marker)?.is_none() {
        // No legacy identity in `deploy`'s terms (the deploy_dir was never
        // provisioned). A crate-format marker that IS present must still
        // VALIDATE: a corrupt one is refused here, never ignored, and an
        // absent one is a confirmed absence.
        read_receiver_id_opt(remote)?;
        return Ok(None);
    }
    let data = remote.read(&marker)?;
    let s = std::str::from_utf8(&data).map_err(|e| {
        Error::transport(format!(
            "deploy_dir {}: the receiver-UUID marker is not valid UTF-8: {e}",
            remote.root().display()
        ))
    })?;
    let uuid = ReceiverUuid::parse(s.trim()).map_err(|e| {
        Error::transport(format!(
            "deploy_dir {}: the receiver-UUID marker is malformed: {e}",
            remote.root().display()
        ))
    })?;
    // A crate-format marker that is present must be well-formed even on the
    // read-only path — a corrupt one is refused, never ignored.
    read_receiver_id_opt(remote)?;
    Ok(Some(uuid))
}

/// Read the deploy_dir's receiver-UUID marker, returning `Ok(None)` ONLY for
/// a CONFIRMED absent marker (a not-yet-provisioned deploy_dir — the marker
/// is created by [`provision_receiver_uuid`] during provisioning). A read
/// failure or a malformed marker is an `Err` (fail closed — a marker that
/// exists but cannot be parsed is never silently treated as absent).
///
/// ADOPT-ON-READ: when the deploy_dir carries the LEGACY `recv-<uuid-v7>`
/// marker but no crate-format marker BESIDE it, this read also writes the
/// crate-format receiver id derived from that legacy identity (see
/// [`adopt_receiver_marker`]), so an already-provisioned deploy_dir becomes
/// acceptable to the store substrate the next time it is read. The write is
/// idempotent and NEVER touches the legacy marker. A crate-format marker that
/// is present but malformed is refused, exactly as the crate refuses it.
/// Because this WRITES, a dry run uses [`peek_receiver_uuid_opt`] instead.
pub(crate) fn read_receiver_uuid_opt<R: Remote + ?Sized>(
    remote: &R,
) -> Result<Option<ReceiverUuid>> {
    let uuid = peek_receiver_uuid_opt(remote)?;
    if let Some(uuid) = &uuid {
        adopt_receiver_marker(remote, uuid)?;
    }
    Ok(uuid)
}

/// Provision the deploy_dir's IMMUTABLE receiver-UUID marker: create it ONCE
/// (a fresh [`ReceiverUuid`]) and return the deploy_dir's physical identity.
/// The marker is never replaced: a re-provisioning or a concurrent
/// provisioner adopts the EXISTING marker (the first writer wins — the
/// deploy_dir's physical identity is whatever was created first), and a
/// marker with different content is adopted too (fail closed on a malformed
/// marker, never on a differing-but-valid one: the physical identity is
/// immutable, so the existing marker is the truth).
pub(crate) fn provision_receiver_uuid<R: Remote + ?Sized>(remote: &R) -> Result<ReceiverUuid> {
    let marker = layout::receiver_uuid();
    // Fast path: the deploy_dir already carries its immutable identity.
    if remote.metadata_opt(&marker)?.is_some() {
        return read_receiver_uuid(remote);
    }
    let uuid = ReceiverUuid::generate();
    match remote.try_write_new(&marker, uuid.as_str().as_bytes())? {
        CreateNewVerdict::Created => {
            // A FRESHLY provisioned deploy_dir also gains the crate-format
            // marker derived from the identity just created, so it is
            // acceptable to the store substrate without a second read.
            adopt_receiver_marker(remote, &uuid)?;
            Ok(uuid)
        }
        // A concurrent provisioner won the create-new race (or the marker
        // exists with different content): the deploy_dir's identity is
        // whatever was created FIRST — adopt it, never replace it.
        CreateNewVerdict::AlreadyPresent | CreateNewVerdict::Conflict(_) => {
            read_receiver_uuid(remote)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::SysEnv;
    use crate::remote::transport::LocalTransport;
    use std::os::unix::fs::MetadataExt;

    fn fixture() -> (tempfile::TempDir, LocalTransport) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("deploy-dir");
        let t = LocalTransport::new(&SysEnv::from_process(), root).unwrap();
        (dir, t)
    }

    /// Provision a deploy_dir the way `deploy` did BEFORE this change: a
    /// legacy `recv-<uuid-v7>` marker and NO crate-format marker. Returns the
    /// legacy UUID and the deploy_dir root.
    fn provision_legacy_only(t: &LocalTransport, root: &std::path::Path) -> ReceiverUuid {
        let uuid = ReceiverUuid::generate();
        t.write(&layout::receiver_uuid(), uuid.as_str().as_bytes(), 0o644)
            .unwrap();
        assert!(
            !root.join("receiver-id").exists(),
            "the pre-change fixture carries only the legacy marker"
        );
        uuid
    }

    /// The adoption derives a STABLE 40-lowercase-hex id: the same legacy UUID
    /// always derives the same id, a different one derives a different id,
    /// and every derived id is exactly the crate's wire shape.
    #[test]
    fn derivation_is_stable_distinct_and_crate_shaped() {
        let a = crate::identity::test_receiver_uuid("adopt-a");
        let b = crate::identity::test_receiver_uuid("adopt-b");
        let id_a = derive_receiver_id(&a);
        let id_b = derive_receiver_id(&b);
        assert_eq!(id_a, derive_receiver_id(&a), "stable for the same input");
        assert_ne!(id_a, id_b, "distinct identities derive distinct ids");
        for id in [&id_a, &id_b] {
            assert_eq!(id.as_str().len(), RECEIVER_ID_LEN);
            assert!(
                id.as_str()
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "derived id is lowercase hex, got {:?}",
                id.as_str()
            );
        }
        // The parser the crate uses accepts what we derive.
        assert_eq!(ReceiverId::parse(id_a.as_str()).unwrap(), id_a);
    }

    /// A malformed crate-format marker is REFUSED (never repaired), and an
    /// absent one reads as `None` (never an error).
    #[test]
    fn crate_marker_reads_none_when_absent_and_refuses_malformed() {
        let (_dir, t) = fixture();
        assert_eq!(
            read_receiver_id_opt(&t).unwrap(),
            None,
            "an absent marker is a confirmed absence"
        );
        let hex39 = format!("{}\n", "a".repeat(39));
        let hex41 = format!("{}\n", "a".repeat(41));
        let cases: [&[u8]; 5] = [
            b"",                                       // empty file
            b"recv-\n",                                // legacy prefix only
            b"0190f3c2-7a1e-7b3c-8d4f-0123456789ab\n", // truncated/undashed uuid
            hex39.as_bytes(),                          // 39 hex characters
            hex41.as_bytes(),                          // 41 hex characters
        ];
        for raw in cases {
            t.write(&layout::receiver_id(), raw, 0o644).unwrap();
            read_receiver_id_opt(&t).expect_err("a malformed crate-format marker is refused");
        }
    }

    /// A corrupt LEGACY marker (the other half of the fail-closed matrix) is
    /// refused by `deploy`'s read with an actionable error, and adoption
    /// writes nothing.
    #[test]
    fn deploy_read_refuses_corrupt_legacy_markers() {
        let (dir, t) = fixture();
        let root = dir.path().join("deploy-dir");
        let cases: [&[u8]; 5] = [
            b"",                          // empty file
            b"recv-\n",                   // legacy prefix only
            b"recv-0190f3c2-7a1e-7b3c\n", // truncated uuid
            &[b'a'; 39],                  // 39 hex characters
            &[b'a'; 41],                  // 41 hex characters
        ];
        for raw in cases {
            t.write(&layout::receiver_uuid(), raw, 0o644).unwrap();
            let err = crate::remote::transport::read_receiver_uuid_opt(&t)
                .expect_err("a corrupt legacy marker is refused");
            assert!(
                err.to_string()
                    .contains("receiver-UUID marker is malformed"),
                "the refusal names the condition, got: {err}"
            );
            assert!(
                !root.join("receiver-id").exists(),
                "a corrupt legacy marker must not be adopted"
            );
        }
    }

    /// Adopting a legacy-only deploy_dir writes the derived id in the crate's
    /// exact wire form BESIDE the legacy file, leaves the legacy bytes
    /// untouched, and a second adoption is a NO-OP: the marker's inode and
    /// mtime do not change (proof method: inode + mtime_ns via
    /// `std::os::unix::fs::MetadataExt`; `try_write_new` installs by renaming
    /// a fresh temp inode into place, so ANY rewrite changes the inode).
    #[test]
    fn adoption_writes_once_beside_the_legacy_file_and_is_idempotent() {
        let (dir, t) = fixture();
        let root = dir.path().join("deploy-dir");
        let legacy = provision_legacy_only(&t, &root);
        let legacy_bytes_before = std::fs::read(root.join("receiver-uuid")).unwrap();

        assert_eq!(
            read_receiver_id_opt(&t).unwrap(),
            None,
            "pre-adoption: the crate marker is absent (non-vacuous)"
        );

        adopt_receiver_marker(&t, &legacy).unwrap();

        let marker_path = root.join("receiver-id");
        let after_first = std::fs::read(&marker_path).expect("adoption wrote the marker");
        let expected = derive_receiver_id(&legacy);
        assert_eq!(
            after_first,
            expected.wire_bytes(),
            "the marker is the derived id in the crate's exact `<id>\\n` wire form"
        );
        let meta_first = std::fs::metadata(&marker_path).unwrap();

        // The legacy identity survives byte-for-byte, and the legacy file is
        // still right there beside the new marker.
        assert_eq!(
            std::fs::read(root.join("receiver-uuid")).unwrap(),
            legacy_bytes_before,
            "the legacy marker's bytes are unchanged"
        );

        // Idempotence: a second adoption reads and does nothing.
        adopt_receiver_marker(&t, &legacy).unwrap();
        let after_second = std::fs::read(&marker_path).unwrap();
        let meta_second = std::fs::metadata(&marker_path).unwrap();
        assert_eq!(
            after_second, after_first,
            "second adoption leaves the bytes"
        );
        assert_eq!(
            meta_first.ino(),
            meta_second.ino(),
            "second adoption rewrote the marker (inode changed)"
        );
        assert_eq!(
            meta_first.mtime(),
            meta_second.mtime(),
            "second adoption rewrote the marker (mtime changed)"
        );
        assert_eq!(
            meta_first.mtime_nsec(),
            meta_second.mtime_nsec(),
            "second adoption rewrote the marker (mtime_ns changed)"
        );
    }

    /// THE PRE-FIX-FAILING TEST: reading a legacy-only deploy_dir through the
    /// public read path
    /// ([`crate::remote::transport::read_receiver_uuid_opt`]) adopts it — the
    /// crate-format marker appears in the crate's exact wire form beside the
    /// legacy file, the read returns the legacy identity, and the legacy
    /// bytes are untouched. On the tree BEFORE this change the read returns
    /// the legacy UUID but writes no crate-format marker, so this test fails
    /// at the `receiver-id` assertion below.
    ///
    /// SELF-CONTAINED BY DESIGN: this test uses ONLY pre-change symbols
    /// (`read_receiver_uuid_opt`, `LocalTransport`, `ReceiverUuid`, the
    /// layout path), so the exact function can be copied verbatim into the
    /// PRE-change tree's test module and run there — which is how the
    /// pre-change failure was observed.
    #[test]
    fn reading_a_legacy_only_dir_adopts_it_for_the_crate() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("deploy-dir");
        let t = LocalTransport::new(&SysEnv::from_process(), root.clone()).unwrap();
        let legacy = crate::identity::ReceiverUuid::generate();
        t.write(&layout::receiver_uuid(), legacy.as_str().as_bytes(), 0o644)
            .unwrap();
        let legacy_bytes = std::fs::read(root.join("receiver-uuid")).unwrap();
        assert!(
            !root.join("receiver-id").exists(),
            "the pre-change fixture carries only the legacy marker"
        );

        let read = crate::remote::transport::read_receiver_uuid_opt(&t)
            .expect("the legacy identity reads")
            .expect("the deploy_dir is provisioned");
        assert_eq!(read, legacy, "the read still returns the legacy identity");

        // ON THE PRE-CHANGE TREE THIS ASSERTION FAILS: the read returns the
        // legacy identity but writes no crate-format marker.
        let marker_path = root.join("receiver-id");
        let marker = std::fs::read(&marker_path)
            .expect("reading a legacy-only deploy_dir must adopt it for the crate");
        assert_eq!(marker.len(), 41, "`<40 hex>\\n` wire form");
        assert_eq!(marker[40], b'\n', "the wire form ends in \\n");
        assert!(
            marker[..40]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "the id is 40 lowercase hex characters"
        );
        assert_eq!(
            std::fs::read(root.join("receiver-uuid")).unwrap(),
            legacy_bytes,
            "the legacy identity survives the adoption"
        );

        // A second read does nothing (same inode, same bytes).
        let before = std::fs::metadata(&marker_path).unwrap();
        crate::remote::transport::read_receiver_uuid_opt(&t).unwrap();
        let after = std::fs::metadata(&marker_path).unwrap();
        assert_eq!(before.ino(), after.ino(), "second read must not rewrite");
        assert_eq!(std::fs::read(&marker_path).unwrap(), marker);
    }

    /// A DRY RUN's read (`peek_receiver_uuid_opt`) returns the legacy
    /// identity but writes NOTHING, and it still refuses a malformed
    /// crate-format marker (fail closed on the read-only path too).
    #[test]
    fn peek_reads_the_legacy_identity_without_adopting() {
        let (dir, t) = fixture();
        let root = dir.path().join("deploy-dir");
        let legacy = provision_legacy_only(&t, &root);
        let read = crate::remote::transport::peek_receiver_uuid_opt(&t)
            .unwrap()
            .expect("the legacy identity reads");
        assert_eq!(read, legacy);
        assert!(
            !root.join("receiver-id").exists(),
            "peek must not adopt (a dry run touches nothing)"
        );

        t.write(&layout::receiver_id(), b"not-a-receiver-id\n", 0o644)
            .unwrap();
        crate::remote::transport::peek_receiver_uuid_opt(&t)
            .expect_err("peek refuses a malformed crate-format marker");
    }

    /// A well-formed crate-format marker from a DIFFERENT deploy_dir is left
    /// alone (the admission is presence + well-formedness), and a malformed
    /// one is refused rather than replaced.
    #[test]
    fn adoption_never_replaces_a_present_marker() {
        let (dir, t) = fixture();
        let root = dir.path().join("deploy-dir");
        let legacy = provision_legacy_only(&t, &root);
        let foreign = crate::identity::test_receiver_uuid("adopt-foreign");
        let foreign_id = derive_receiver_id(&foreign);
        t.write(&layout::receiver_id(), &foreign_id.wire_bytes(), 0o644)
            .unwrap();
        adopt_receiver_marker(&t, &legacy).unwrap();
        assert_eq!(
            std::fs::read(root.join("receiver-id")).unwrap(),
            foreign_id.wire_bytes(),
            "a present marker is never replaced"
        );

        t.write(&layout::receiver_id(), b"not-a-receiver-id\n", 0o644)
            .unwrap();
        adopt_receiver_marker(&t, &legacy)
            .expect_err("a malformed marker is refused, not repaired");
    }

    /// THE MARKER-ORDERING RESOLUTION, pinned from `deploy`'s side: a
    /// LEGACY-ONLY deploy_dir must keep its DERIVED identity, never the fresh
    /// random id the crate's `provision_receiver_id` generates when it finds
    /// no crate marker. Provisioning such a directory runs `deploy`'s
    /// adopt-on-read FIRST, so `receiver-id` is EXACTLY
    /// `derive_receiver_id(legacy)` — not merely "some 40 hex characters".
    ///
    /// The resolution the eventual `LocalTransport` swap must preserve: pass
    /// `Layout::receiver_marker: None` so the crate leaves the marker alone
    /// and `deploy` owns it (cost: the crate performs no receiver-marker
    /// provisioning for a deploy_dir, so `deploy`'s adoption remains the only
    /// writer — which it already is).
    #[test]
    fn provisioning_a_legacy_only_dir_keeps_the_derived_id_not_a_random_one() {
        let (dir, t) = fixture();
        let root = dir.path().join("deploy-dir");
        let legacy = provision_legacy_only(&t, &root);
        let expected = derive_receiver_id(&legacy);
        assert!(
            !root.join("receiver-id").exists(),
            "the fixture carries only the legacy marker (non-vacuous)"
        );

        // Provisioning through `deploy`'s writer takes the fast path: the
        // existing legacy identity is read (and adopted), never regenerated.
        let recovered = crate::remote::transport::provision_receiver_uuid(&t).unwrap();
        assert_eq!(
            recovered, legacy,
            "the deploy_dir's identity is the legacy UUID it already had"
        );

        let marker = std::fs::read(root.join("receiver-id"))
            .expect("provisioning a legacy-only dir adopts a crate-format marker");
        assert_eq!(
            marker,
            expected.wire_bytes(),
            "the crate marker must be the DERIVED id, never a fresh random one"
        );

        // Idempotent: a second provisioning adopts the same identity and does
        // not rewrite the marker.
        let meta_before = std::fs::metadata(root.join("receiver-id")).unwrap();
        let again = crate::remote::transport::provision_receiver_uuid(&t).unwrap();
        let meta_after = std::fs::metadata(root.join("receiver-id")).unwrap();
        assert_eq!(again, legacy);
        assert_eq!(
            meta_before.ino(),
            meta_after.ino(),
            "a second provisioning must not rewrite the derived marker"
        );
    }

    /// STRUCTURAL CONFIRMATION of the second post-swap non-regression: the
    /// deploy_dir's receiver markers (`receiver-uuid`, `receiver-id`) may be
    /// READ or WRITTEN only through this module.
    ///
    /// The substrate cannot reach them by construction —
    /// [`crate::remote::layout::substrate_layout`] hands the re-exported
    /// `SshTransport` `receiver_marker: None`, so `storekit` never receives a
    /// marker path at all (and its `provision_receiver_id`, which would MINT A
    /// RANDOM id, is unreachable) — but a future edit could still call
    /// `layout::receiver_uuid()` from another module. This source audit fails
    /// if any PRODUCTION (non-`#[cfg(test)]`) code outside this file names
    /// either marker path, so "one authority per resource" is enforced, not
    /// merely documented.
    #[test]
    fn only_this_module_names_the_receiver_marker_paths() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let this = "src/remote/transport/receiver_marker.rs";
        let mut offenders: Vec<String> = Vec::new();
        for dir in ["src", "tests"] {
            for entry in walkdir::WalkDir::new(root.join(dir))
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let rel = p
                    .strip_prefix(root)
                    .expect("a walked path is under the manifest dir")
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel == this || rel.starts_with("tests/ui/") {
                    continue;
                }
                let src = std::fs::read_to_string(p).expect("a source file reads");
                let code = strip_cfg_test_items(&code_only(&src));
                for needle in ["layout::receiver_uuid()", "layout::receiver_id()"] {
                    if code.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                        offenders.push(format!("{rel}: {needle}"));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these files name a receiver-marker path outside the ONE module that owns it \
             ({this}), so the marker would have more than one reader/writer: {offenders:#?}"
        );
    }

    /// Remove comments and string/char literals (byte-level), so the
    /// `#[cfg(test)]` brace tracker is not confused by a brace inside a string
    /// (the crate's own audits strip code first for the same reason).
    fn code_only(src: &str) -> Vec<u8> {
        let b = src.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(b.len());
        let mut i = 0usize;
        while i < b.len() {
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    i += 2;
                    while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                        i += 1;
                    }
                    i = (i + 2).min(b.len());
                }
                b'"' => {
                    i += 1;
                    while i < b.len() {
                        match b[i] {
                            b'\\' => i += 2,
                            b'"' => {
                                i += 1;
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                }
                // A char literal is `'X'` or `'\X'`; a lifetime (`'a`) is not
                // a literal, so only consume the quoted forms.
                b'\'' if b.get(i + 1) == Some(&b'\\') => {
                    i += 2;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                    i = (i + 1).min(b.len());
                }
                b'\'' if b.get(i + 2) == Some(&b'\'') => i += 3,
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            }
        }
        out
    }

    /// Remove every `#[cfg(test)]`-gated item from `src`, so an audit sees
    /// PRODUCTION code only. A byte scanner (the crate's own audits use the
    /// same shape): skip the attribute(s), then the balanced `{…}` item or the
    /// `;`-terminated form.
    fn strip_cfg_test_items(bytes: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"#[cfg(test)]") {
                let mut j = i + b"#[cfg(test)]".len();
                loop {
                    let before = j;
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if bytes.get(j) == Some(&b'#') && bytes.get(j + 1) == Some(&b'[') {
                        let mut depth = 0i32;
                        while j < bytes.len() {
                            match bytes[j] {
                                b'[' => depth += 1,
                                b']' => {
                                    depth -= 1;
                                    j += 1;
                                    if depth == 0 {
                                        break;
                                    }
                                    continue;
                                }
                                _ => {}
                            }
                            j += 1;
                        }
                    } else {
                        j = before;
                        break;
                    }
                }
                let mut depth = 0i32;
                let mut started = false;
                while j < bytes.len() {
                    match bytes[j] {
                        b'{' => {
                            depth += 1;
                            started = true;
                        }
                        b'}' => {
                            depth -= 1;
                            if started && depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        b';' if !started && depth == 0 => {
                            j += 1;
                            break;
                        }
                        b',' if !started && depth == 0 => {
                            j += 1;
                            break;
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        out
    }
}

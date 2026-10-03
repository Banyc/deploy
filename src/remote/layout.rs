//! Canonical on-server layout paths.
//!
//! Every path inside a server's deployment directory is defined exactly once,
//! here. `remote/helper.rs`, `push/engine.rs`, and `retention.rs` must never
//! hand-build these strings: renaming a directory becomes a one-line change in
//! this module instead of a silent three-way breakage. All functions return
//! paths *relative* to the deployment directory root; transports anchor them.
//!
//! Every function that names a SEMANTIC IDENTITY takes the TYPED identity
//! ([`crate::identity::TreeDigest`], [`crate::identity::GenerationId`], ...)
//! — never a raw `&str` — so a caller cannot build a semantic path from an
//! arbitrary string. The returned paths are validated
//! [`RootedRelativePath`]s: relative to the deployment root, never absolute,
//! never traversal-bearing, so a transport's `root.join(rel)` is safe by
//! construction.

use crate::identity::{DeploymentId, GenerationId, OperationId, ReleaseId, TreeDigest};
use crate::remote::transport::RootedRelativePath;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Parse a COMPILE-TIME-CONSTANT layout literal into the crate's validated
/// [`RootedRelativePath`].
///
/// `storekit`'s `RootedRelativePath::from_validated` — the infallible
/// constructor `deploy` used to call here — is `pub(crate)`, so a consumer
/// must construct through the validated [`RootedRelativePath::parse`] (the
/// ONE spelling authority). Every literal in this module is a plain relative
/// name (or a `/`-joined pair of plain names, all defined as constants
/// above), so `parse` cannot fail; the `expect` records that proof once, here,
/// instead of at each builder. A literal that is NOT a safe relative spelling
/// (empty, absolute, `.`/`..`, or a multi-segment literal that introduces one)
/// makes the builder panic at first use — the same fail-closed class the
/// crate's private constructor prevented by construction, now enforced by the
/// crate's validator rather than bypassed.
fn layout_path(literal: &str) -> RootedRelativePath {
    RootedRelativePath::parse(Path::new(literal))
        .unwrap_or_else(|e| panic!("layout literal {literal:?} must be a safe relative path: {e}"))
}

// ---- path components -------------------------------------------------------
// Each component of the on-server layout is named exactly once, here.

/// Name of the content-addressed object-store directory.
pub const OBJECTS: &str = "objects";
/// Name of the hash subdirectory inside the object store.
pub const SHA256: &str = "sha256";
/// Component name of the generations directory inside a `current` target.
pub const GENERATIONS_COMPONENT: &str = "generations";
/// Name of the server-side state directory.
pub const STATE: &str = "state";
/// Name of the control directory (protocol negotiation markers).
pub const CONTROL: &str = "control";
/// Name of the incoming staging directory.
pub const INCOMING: &str = "incoming";
/// Name of the published releases directory.
pub const RELEASES: &str = "releases";

// ---- file names ------------------------------------------------------------

/// Remote mutation lock file (inside `state/`).
pub const OPERATION_LOCK: &str = "operation.lock";
/// Sidecar mutex for serializing `operation.lock` mutations (inside `state/`).
/// Created once durably and never removed/renamed, so every participant flocks the same inode.
pub const OPERATION_LOCK_SIDECAR: &str = "operation.lock.mutex";
/// Remote inventory snapshot file (inside `state/`).
pub const INVENTORY: &str = "inventory.json";
/// Suffix appended to a digest while a tree upload is still in flight.
pub const PARTIAL_SUFFIX: &str = ".partial";
/// Suffix appended to an invalid tree object moved aside (quarantined) before
/// repair: the digest path is absent while the invalid content is preserved
/// for inspection.
pub const QUARANTINE_SUFFIX: &str = ".quarantined";

/// The deployment-directory layout created before the first mutation.
/// `LocalTransport::provision_layout` creates these locally;
/// `SshTransport::provision_layout` mkdir -p's them remotely.
pub fn bootstrap_dirs() -> Vec<RootedRelativePath> {
    vec![
        layout_path(CONTROL),
        layout_path("helpers"),
        objects().clone(),
        layout_path(RELEASES),
        generations().clone(),
        layout_path(INCOMING),
        state_dir(),
        layout_path("adapters"),
        layout_path("transactions"),
    ]
}

/// Root of the content-addressed object store.
pub fn objects() -> &'static RootedRelativePath {
    static OBJECTS_ROOT: LazyLock<RootedRelativePath> = LazyLock::new(|| {
        layout_path(OBJECTS)
            .join(SHA256)
            .expect("a constant object-store component is a safe path segment")
    });
    &OBJECTS_ROOT
}

/// Root directory of one tree object. `digest` is the TYPED tree identity —
/// a caller cannot name a tree object from an arbitrary string.
pub fn tree_root(digest: &TreeDigest) -> RootedRelativePath {
    // A validated digest is a single safe path segment, so the joins are
    // safe by construction.
    objects()
        .join(digest.as_str())
        .and_then(|p| p.join("root"))
        .expect("a validated tree digest is a safe path component")
}

/// Directory holding every generation record.
pub fn generations() -> &'static RootedRelativePath {
    static GENERATIONS_ROOT: LazyLock<RootedRelativePath> =
        LazyLock::new(|| layout_path(GENERATIONS_COMPONENT));
    &GENERATIONS_ROOT
}

/// One generation's record directory. `gen_id` is the TYPED generation
/// identity — a caller cannot name a generation from an arbitrary string.
pub fn generation(gen_id: &GenerationId) -> RootedRelativePath {
    generations()
        .join(gen_id.as_str())
        .expect("a validated generation id is a safe path component")
}

/// A UNIQUE STAGING SIBLING of a generation directory: the assignment record
/// and the `root` symlink are written here, fsynced, and then the WHOLE
/// directory is atomically renamed into the final generation directory
/// ([`generation`]) — the final generation directory is either wholly absent
/// or complete and readable, never partial. The `.partial` suffix marks the
/// staging dir as not-yet-installed; `nonce` makes it unique per install
/// attempt (a crashed earlier attempt's staging dir is removed before
/// re-staging). `gen_id` is the TYPED generation identity and `nonce` a
/// freshly minted unique value — a caller cannot stage an arbitrary name.
pub fn staged_generation(gen_id: &GenerationId, nonce: &str) -> RootedRelativePath {
    generations()
        .join(format!("{}.partial-{}", gen_id.as_str(), nonce))
        .expect("a validated generation id and a nonce are safe path components")
}

/// The atomically swapped per-server commit pointer.
pub fn current() -> &'static RootedRelativePath {
    static CURRENT: LazyLock<RootedRelativePath> = LazyLock::new(|| layout_path("current"));
    &CURRENT
}

/// Incoming staging area for one deployment. `deployment_id` is the TYPED
/// deployment identity — a caller cannot name a staging area from an
/// arbitrary string.
pub fn incoming_dir(deployment_id: &DeploymentId) -> RootedRelativePath {
    layout_path(INCOMING)
        .join(deployment_id.as_str())
        .expect("a validated deployment id is a safe path component")
}

/// A staged (partial) tree upload inside a deployment's incoming area. Both
/// identities are TYPED — a caller cannot stage an arbitrary name.
pub fn staged_tree(deployment_id: &DeploymentId, digest: &TreeDigest) -> RootedRelativePath {
    layout_path(INCOMING)
        .join(deployment_id.as_str())
        .and_then(|p| p.join(format!("{digest}{PARTIAL_SUFFIX}")))
        .expect("a validated deployment id and a validated tree digest are safe path components")
}

/// A deployment-independent staging path for a tree upload in flight (used by
/// [`crate::remote::helper::HeldSlotLock::publish_tree`] when no
/// deployment-scoped incoming area exists). The `.partial` suffix marks the
/// upload as not-yet-published; the digest is the TYPED tree identity — a
/// caller cannot stage an arbitrary name.
pub fn staged_tree_global(digest: &TreeDigest) -> RootedRelativePath {
    layout_path(INCOMING)
        .join(format!("{digest}{PARTIAL_SUFFIX}"))
        .expect("a validated tree digest is a safe path component")
}

/// Quarantine path for an invalid tree object: the invalid `root` is moved
/// aside here (never deleted) before repair, so the digest path is absent
/// while the invalid content is preserved for inspection. `digest` is the
/// TYPED tree identity — a caller cannot name a quarantine from an arbitrary
/// string.
pub fn quarantined_tree(digest: &TreeDigest) -> RootedRelativePath {
    objects()
        .join(digest.as_str())
        .and_then(|p| p.join(format!("root{QUARANTINE_SUFFIX}")))
        .expect("a validated tree digest is a safe path component")
}

/// Parent of all published release-side files.
pub fn remote_releases() -> &'static RootedRelativePath {
    static RELEASES_ROOT: LazyLock<RootedRelativePath> = LazyLock::new(|| layout_path(RELEASES));
    &RELEASES_ROOT
}

/// Release-side files for one release. `release_id` is the TYPED release
/// identity — a caller cannot name a release from an arbitrary string.
pub fn remote_release(release_id: &ReleaseId) -> RootedRelativePath {
    remote_releases()
        .join(release_id.as_str())
        .expect("a validated release id is a safe path component")
}

/// A UNIQUE STAGING SIBLING of the release directory: every member of the
/// release bundle is written here, verified, fsynced, and then the WHOLE
/// directory is atomically renamed into the final release directory
/// ([`remote_release`]) — the final release directory is either wholly
/// absent or complete and readable, never partial. The `.partial` suffix
/// marks the staging dir as not-yet-published; `nonce` makes it unique per
/// publish attempt (a crashed earlier attempt's staging dir is removed
/// before re-staging). `release_id` is the TYPED release identity and
/// `nonce` a freshly minted unique value — a caller cannot stage an
/// arbitrary name.
pub fn staged_release(release_id: &ReleaseId, nonce: &str) -> RootedRelativePath {
    remote_releases()
        .join(format!("{}.partial-{}", release_id.as_str(), nonce))
        .expect("a validated release id and a nonce are safe path components")
}

/// The server-side state directory.
pub fn state_dir() -> RootedRelativePath {
    layout_path(STATE)
}

/// A file inside the `state/` directory. `name` is a CONSTANT file name
/// (never a semantic identity); the join is safe by construction.
fn state_file(name: &str) -> RootedRelativePath {
    state_dir()
        .join(name)
        .expect("a constant state file name is a safe path component")
}

/// Remote mutation lock.
pub fn operation_lock() -> RootedRelativePath {
    state_file(OPERATION_LOCK)
}

/// Sidecar mutex file that serializes every mutation of `operation.lock`.
/// The file is created once durably and never removed/renamed, so every
/// participant flocks the SAME inode via `flock(2)`; the lock is released
/// by the kernel on holder death, so no lease is needed.
pub fn operation_lock_sidecar() -> RootedRelativePath {
    state_file(OPERATION_LOCK_SIDECAR)
}

/// Directory holding commit markers.
pub fn commits_dir() -> RootedRelativePath {
    state_dir()
        .join("commits")
        .expect("a constant directory name is a safe path component")
}

/// Commit markers, one per deployment. `deployment_id` is the TYPED
/// deployment identity — a caller cannot name a commit marker from an
/// arbitrary string.
pub fn commit_marker(deployment_id: &DeploymentId) -> RootedRelativePath {
    commits_dir()
        .join(format!("{deployment_id}.json"))
        .expect("a validated deployment id is a safe path component")
}

/// Protocol negotiation marker (first-contact version record).
pub fn protocol_marker() -> RootedRelativePath {
    layout_path(CONTROL)
        .join("protocol.json")
        .expect("a constant control-file name is a safe path component")
}

/// Parent of all per-deployment staging areas.
pub fn incoming() -> &'static RootedRelativePath {
    static INCOMING_ROOT: LazyLock<RootedRelativePath> = LazyLock::new(|| layout_path(INCOMING));
    &INCOMING_ROOT
}

/// Remote inventory snapshot.
pub fn inventory() -> RootedRelativePath {
    state_file(INVENTORY)
}

/// The IMMUTABLE receiver-UUID marker file at the deploy_dir root: the
/// PHYSICAL identity of one provisioned deploy_dir, created ONCE at
/// provisioning ([`crate::remote::transport::provision_receiver_uuid`]) and
/// never changed. Two ServerIds that name the same physical host+dir share
/// the same receiver; a slot rebound to a different ServerId pointing at the
/// same physical location keeps it. Read during preflight and recorded in
/// the ledger's [`crate::ledger::PhysicalBinding`]; exact rollback and
/// duplicate-location detection compare it.
pub fn receiver_uuid() -> RootedRelativePath {
    layout_path("receiver-uuid")
}

/// The CRATE-FORMAT receiver-id marker file at the deploy_dir root, BESIDE
/// the legacy [`receiver_uuid`] marker: exactly 40 lowercase hex characters
/// followed by a newline — the form `storekit`'s `Layout::receiver_marker`
/// reads and validates. It is written ONCE by the legacy-marker ADOPTION
/// ([`crate::remote::transport::receiver_marker::adopt_receiver_marker`]), which derives it
/// from the legacy receiver UUID; the legacy file is never modified, so the
/// deploy_dir's old identity survives and the adoption is reversible.
///
/// The eventual crate migration points `Layout::receiver_marker` at THIS
/// path; nothing else in `deploy` reads it yet.
pub fn receiver_id() -> RootedRelativePath {
    layout_path("receiver-id")
}

/// Relative link target (from inside a generation directory) to that
/// generation's tree object. `tree` is the TYPED tree identity. The target
/// is relative to the LINK's directory (it legitimately traverses up to the
/// object store), so it is a plain `PathBuf`, never a
/// [`RootedRelativePath`].
pub fn generation_root_link(tree: &TreeDigest) -> PathBuf {
    Path::new("../../")
        .join(OBJECTS)
        .join(SHA256)
        .join(tree.as_str())
        .join("root")
}

/// Per-operation transaction record. `operation_id` is the TYPED operation
/// identity — a caller cannot name a transaction record from an arbitrary
/// string.
pub fn transaction_record(operation_id: &OperationId) -> RootedRelativePath {
    layout_path("transactions")
        .join(format!("{operation_id}.json"))
        .expect("a validated operation id is a safe path component")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        test_deployment_id, test_generation_id, test_operation_id, test_release_id,
        test_tree_digest,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn every_layout_path_stays_under_its_root(tag in "[a-z0-9]{1,16}") {
            let root = std::path::Path::new("/srv/deploy");
            let digest = test_tree_digest(&tag);
            let gid = test_generation_id(&tag);
            let rel = test_release_id(&tag);
            let dep = test_deployment_id(&tag);
            let op = test_operation_id(&tag);

            let mut paths: Vec<RootedRelativePath> = vec![
                tree_root(&digest),
                generation(&gid),
                incoming_dir(&dep),
                staged_tree(&dep, &digest),
                staged_tree_global(&digest),
                quarantined_tree(&digest),
                remote_release(&rel),
                staged_release(&rel, "nonce-1"),
                state_dir(),
                operation_lock(),
                operation_lock_sidecar(),
                commits_dir(),
                commit_marker(&dep),
                protocol_marker(),
                inventory(),
                transaction_record(&op),
            ];
            paths.extend(bootstrap_dirs());
            paths.push(objects().clone());
            paths.push(generations().clone());
            paths.push(current().clone());
            paths.push(remote_releases().clone());
            paths.push(incoming().clone());

            for p in paths {
                let joined = root.join(p.as_path());
                prop_assert!(
                    joined.starts_with(root),
                    "path {} escapes root {}: joined {}",
                    p.display(),
                    root.display(),
                    joined.display()
                );
                // The relative part stays relative and traversal-free: every
                // component is a NORMAL component.
                let rel_part = joined.strip_prefix(root).unwrap();
                for c in rel_part.components() {
                    prop_assert!(
                        matches!(c, std::path::Component::Normal(_)),
                        "path {} has an unsafe component {:?}",
                        p.display(),
                        c
                    );
                }
            }
        }
    }
}

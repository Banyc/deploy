//! Canonical on-server layout paths.
//!
//! Every path inside a server's deployment directory is defined exactly once,
//! here. `remote/helper.rs`, `push/engine.rs`, and `retention.rs` must never
//! hand-build these strings: renaming a directory becomes a one-line change in
//! this module instead of a silent three-way breakage. All functions return
//! paths *relative* to the deployment directory root; transports anchor them.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

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
/// Remote inventory snapshot file (inside `state/`).
pub const INVENTORY: &str = "inventory.json";
/// Suffix appended to a digest while a tree upload is still in flight.
pub const PARTIAL_SUFFIX: &str = ".partial";

/// The deployment-directory layout created before the first mutation.
/// `LocalTransport::provision_layout` creates these locally;
/// `SshTransport::provision_layout` mkdir -p's them remotely.
pub fn bootstrap_dirs() -> Vec<PathBuf> {
    vec![
        Path::new(CONTROL).to_path_buf(),
        Path::new("helpers").to_path_buf(),
        objects().to_path_buf(),
        Path::new(RELEASES).to_path_buf(),
        generations().to_path_buf(),
        Path::new(INCOMING).to_path_buf(),
        state_dir(),
        Path::new("adapters").to_path_buf(),
        Path::new("transactions").to_path_buf(),
    ]
}

/// Root of the content-addressed object store.
pub fn objects() -> &'static Path {
    static OBJECTS_ROOT: LazyLock<PathBuf> = LazyLock::new(|| Path::new(OBJECTS).join(SHA256));
    &OBJECTS_ROOT
}

/// Root directory of one tree object.
pub fn tree_root(digest: &str) -> PathBuf {
    objects().join(digest).join("root")
}

/// Directory holding every generation record.
pub fn generations() -> &'static Path {
    Path::new(GENERATIONS_COMPONENT)
}

/// One generation's record directory.
pub fn generation(gen_id: &str) -> PathBuf {
    generations().join(gen_id)
}

/// The atomically swapped per-server commit pointer.
pub fn current() -> &'static Path {
    Path::new("current")
}

/// Incoming staging area for one deployment.
pub fn incoming_dir(deployment_id: &str) -> PathBuf {
    Path::new(INCOMING).join(deployment_id)
}

/// A staged (partial) tree upload inside a deployment's incoming area.
pub fn staged_tree(deployment_id: &str, digest: &str) -> PathBuf {
    incoming_dir(deployment_id).join(format!("{digest}{PARTIAL_SUFFIX}"))
}

/// Parent of all published release-side files.
pub fn remote_releases() -> &'static Path {
    Path::new(RELEASES)
}

/// Release-side files for one release.
pub fn remote_release(release_id: &str) -> PathBuf {
    remote_releases().join(release_id)
}

/// The server-side state directory.
pub fn state_dir() -> PathBuf {
    Path::new(STATE).to_path_buf()
}

/// A file inside the `state/` directory.
fn state_file(name: &str) -> PathBuf {
    state_dir().join(name)
}

/// Remote mutation lock.
pub fn operation_lock() -> PathBuf {
    state_file(OPERATION_LOCK)
}

/// Directory holding commit markers.
pub fn commits_dir() -> PathBuf {
    state_dir().join("commits")
}

/// Commit markers, one per deployment.
pub fn commit_marker(deployment_id: &str) -> PathBuf {
    commits_dir().join(format!("{deployment_id}.json"))
}

/// Protocol negotiation marker (first-contact version record).
pub fn protocol_marker() -> PathBuf {
    Path::new(CONTROL).join("protocol.json")
}

/// Parent of all per-deployment staging areas.
pub fn incoming() -> &'static Path {
    Path::new(INCOMING)
}

/// Remote inventory snapshot.
pub fn inventory() -> PathBuf {
    state_file(INVENTORY)
}

/// Relative link target (from inside a generation directory) to that
/// generation's tree object.
pub fn generation_root_link(tree: &str) -> PathBuf {
    Path::new("../../")
        .join(OBJECTS)
        .join(SHA256)
        .join(tree)
        .join("root")
}

/// Per-operation transaction record.
pub fn transaction_record(operation_id: &str) -> PathBuf {
    Path::new("transactions").join(format!("{operation_id}.json"))
}

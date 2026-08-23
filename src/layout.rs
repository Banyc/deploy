//! Canonical on-server layout paths.
//!
//! Every path inside a server's deployment directory is defined exactly once,
//! here. `remote/helper.rs`, `push/engine.rs`, and `rotation.rs` must never
//! hand-build these strings: renaming a directory becomes a one-line change in
//! this module instead of a silent three-way breakage. All functions return
//! paths *relative* to the deployment directory root; transports anchor them.

use std::path::{Path, PathBuf};

/// Component name of the generations directory inside a `current` target.
pub const GENERATIONS_COMPONENT: &str = "generations";

/// Root of the content-addressed object store.
pub fn objects() -> &'static Path {
    Path::new("objects/sha256")
}

/// Root directory of one tree object.
pub fn tree_root(digest: &str) -> PathBuf {
    objects().join(digest).join("root")
}

/// Directory holding every generation record.
pub fn generations() -> &'static Path {
    Path::new("generations")
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
    Path::new("incoming").join(deployment_id)
}

/// A staged (partial) tree upload inside a deployment's incoming area.
pub fn staged_tree(deployment_id: &str, digest: &str) -> PathBuf {
    incoming_dir(deployment_id).join(format!("{digest}.partial"))
}

/// Parent of all published release-side files.
pub fn remote_releases() -> &'static Path {
    Path::new("releases")
}

/// Release-side files for one release.
pub fn remote_release(release_id: &str) -> PathBuf {
    remote_releases().join(release_id)
}

/// Remote mutation lock.
pub fn operation_lock() -> PathBuf {
    state_file("operation.lock")
}

/// Fleet-commit markers, one per deployment.
pub fn commit_marker(deployment_id: &str) -> PathBuf {
    Path::new("state/commits").join(format!("{deployment_id}.json"))
}

/// Protocol negotiation marker (first-contact version record).
pub fn protocol_marker() -> PathBuf {
    Path::new("control").join("protocol.json")
}

/// Parent of all per-deployment staging areas.
pub fn incoming() -> &'static Path {
    Path::new("incoming")
}

/// Remote inventory snapshot.
pub fn inventory() -> PathBuf {
    state_file("inventory.json")
}

/// A file inside the `state/` directory.
fn state_file(name: &str) -> PathBuf {
    Path::new("state").join(name)
}

/// Relative link target (from inside a generation directory) to that
/// generation's tree object.
pub fn generation_root_link(tree: &str) -> PathBuf {
    Path::new("../../objects/sha256").join(tree).join("root")
}

/// Per-operation transaction record.
pub fn transaction_record(operation_id: &str) -> PathBuf {
    Path::new("transactions").join(format!("{operation_id}.json"))
}

//! TEST-SUPPORT FIXTURE HELPERS (the `test-support` cargo feature): the
//! crate's EXTERNAL tests (`tests/*.rs`) build remote fixtures through these
//! PUBLIC helpers — the ONLY public mutation surface besides
//! [`crate::deploy::rollout::commit`] — so no external test calls a
//! crate-private mutation primitive. The module is gated behind the
//! `test-support` feature (enabled only for the crate's own test builds via
//! the self dev-dependency in `Cargo.toml`), so a production library caller
//! never sees it: the ONLY public mutation path in a production build is
//! [`crate::deploy::rollout::commit`] with a
//! [`crate::deploy::rollout::PreparedSlotMutation`].

use crate::error::Result;
use crate::identity::{GenerationId, OperationId};
use crate::remote::helper::{
    ExpectedCurrent, GenerationOwner, GenerationSpec, RemoteHelper, SlotRemote,
};
use crate::remote::layout;

/// Mint a REAL foreign generation on a remote and point `current` at it —
/// the fixture a test uses to simulate "another controller advanced the
/// server" (a generation the pending attempt did not mint). The tree object
/// directory is created, the generation record is installed through the
/// guard (the owner marker is bound by the guard itself), and `current` is
/// swapped to it under the `Absent` compare-and-swap precondition. Returns
/// the minted generation id.
///
/// The helper is the PUBLIC test-support seam: it internally uses the
/// crate-private guard primitives, so an external test never names them.
pub fn install_foreign_generation(
    helper: &RemoteHelper,
    owner: &GenerationOwner,
    spec: GenerationSpec,
) -> Result<GenerationId> {
    let gen_id = spec.generation_id.clone();
    helper
        .remote()
        .create_dir_all(&layout::tree_root(&spec.artifact.tree))?;
    let slot = SlotRemote::new(helper, owner.clone());
    let guard = slot.acquire_lock_guard(&OperationId::generate())?;
    guard.create_generation(&spec)?;
    guard.swap_current(&ExpectedCurrent::Absent, &gen_id, "op-foreign")?;
    Ok(gen_id)
}

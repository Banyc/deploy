//! # The remote-fixture API (the `test-support` cargo feature)
//!
//! The SANCTIONED public seam for building remote state in test fixtures:
//! [`install_foreign_generation`] mints a genuine FOREIGN generation on a
//! remote and points `current` at it — the fixture a test uses to simulate
//! "another controller advanced the server" (a generation the pending
//! attempt did not mint).
//!
//! ## What this module is
//!
//! A first-class, documented part of the crate's public API: the DELIBERATE
//! exception to the production mutation rule. The crate's mutation
//! primitives (`create_generation`, `swap_current`, `rotate`,
//! `publish_release`, `publish_tree`, `transaction_record`, ...) are
//! CRATE-PRIVATE — a library caller can never name them. This module is the
//! ONLY public seam that performs a slot mutation, and it exists for ONE
//! purpose: building remote fixtures (external test suites, integration
//! harnesses, repair tooling that must reconstruct a remote's state).
//!
//! ## When to use it
//!
//! Use this module when your code needs to BUILD remote state that the
//! production API does not expose — most commonly a test fixture that must
//! mint a generation the pending attempt did not create (a foreign
//! generation) and point `current` at it. The production mutation path
//! ([`crate::deploy::rollout::commit`] with a
//! [`crate::deploy::rollout::PreparedSlotMutation`]) cannot express this:
//! it commits a slot's OWN next generation, never a foreign one.
//!
//! ## The production relationship (we choose not to use it)
//!
//! The crate's PRODUCTION code deliberately does not use this module: the
//! production build (default features) does not even compile it, so the
//! ONLY public mutation path in a production build is
//! [`crate::deploy::rollout::commit`] with a
//! [`crate::deploy::rollout::PreparedSlotMutation`] (plus the capability
//! acquisition [`crate::remote::helper::SlotRemote::acquire_lock_guard`]).
//! The fixture API is OPT-IN: an external consumer enables the
//! `test-support` cargo feature to access it. The crate's own integration
//! tests enable it through the self dev-dependency in `Cargo.toml`.
//!
//! ## Example
//!
//! ```ignore
//! // Requires the `test-support` cargo feature (see the module docs).
//! use deploy::remote::helper::test_support::install_foreign_generation;
//! use deploy::remote::helper::{GenerationOwner, GenerationSpec, RemoteHelper};
//! use deploy::remote::transport::LocalTransport;
//! use std::path::PathBuf;
//!
//! let remote = LocalTransport::new(
//!     &deploy::env::SysEnv::from_process(),
//!     PathBuf::from("/srv/deploy/remote"),
//! )?;
//! let helper = RemoteHelper::new(&remote);
//! let owner = GenerationOwner::new(
//!     deploy::identity::ApplicationStoreKey::parse("example")?,
//!     deploy::identity::SlotId::parse("p1")?,
//! );
//! let spec = GenerationSpec {
//!     deployment_id: deploy::identity::DeploymentId::generate(),
//!     generation_id: deploy::identity::GenerationId::generate(),
//!     artifact: deploy::identity::ArtifactRef {
//!         release: deploy::identity::ReleaseId::parse(
//!             "rel-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
//!         )?,
//!         variant: deploy::identity::VariantName::parse("standard")?,
//!         tree: deploy::identity::TreeDigest::parse(
//!             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
//!         )?,
//!     },
//!     behavior_sha256: deploy::identity::BehaviorDigest::parse(
//!         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
//!     )?,
//!     prior_generation: None,
//!     created_at: deploy::identity::Timestamp::parse("2020-01-01T00:00:00Z")?,
//!     target: deploy::identity::TargetName::parse("t1")?,
//! };
//! let gen_id = install_foreign_generation(&helper, &owner, spec)?;
//! ```

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
/// This is the module's ONE public entry point — the sanctioned fixture
/// operation. It internally uses the crate-private guard primitives
/// (`create_generation` + `swap_current`), so an external consumer never
/// names them: the fixture API is the ONLY public seam that performs a slot
/// mutation, and it is deliberate and documented (see the module docs for
/// when to use it and how it relates to the production mutation path
/// [`crate::deploy::rollout::commit`]).
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

//! The frozen behavior-contract and release-identity semantics that pin a
//! release's activation/verification behavior (moved from `crate::release`).
//!
//! * [`behavior`] — the frozen behavior-contract semantics (canonical
//!   `behavior_sha256` derivation, `verify_behavior_json`).
//! * [`release`] — release identity/verification semantics (`build_release`,
//!   `verify_release_identity`, the canonical payload recompute), plus the
//!   behavior-contract re-exports that keep the legacy
//!   `deploy::release::*` surface (e.g. `behavior_digest`).

pub mod behavior;
pub mod release;

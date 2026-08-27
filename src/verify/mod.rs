//! Verification/activation semantics (area A5).
//!
//! The adapters that translate the canonical behavior contract into concrete
//! host operations, plus the frozen behavior-contract and release-identity
//! semantics that pin a release's activation/verification behavior:
//!
//! * [`command`] — the `command` verification adapter: the configured argv is
//!   executed directly (never through a shell) with the configured timeout,
//!   attempt count, and interval; every argv element is rendered through the
//!   template module with the slot context BEFORE exec, and an unknown or
//!   malformed variable fails loudly before anything is executed.
//! * [`systemd`] — the `systemd` activation adapter: user-scope staging of
//!   slot-rendered units plus `systemctl --user` enable/restart, system-scope
//!   wrapper-only restart, `reconcile_managed_units` recording, unit-name
//!   safety, and artifact-path validation.
//! * [`behavior`] — the frozen behavior-contract semantics (canonical
//!   `behavior_sha256` derivation, `verify_behavior_json`), moved from
//!   `crate::release`.
//! * [`release`] — release identity/verification semantics (`build_release`,
//!   `verify_release_identity`, the canonical payload recompute), moved from
//!   `crate::release`, plus the behavior-contract re-exports that keep the
//!   legacy `deploy::release::*` surface (e.g. `behavior_digest`).
//!
//! Host identity, key-pin caching, protocol handshake, and ssh timeouts live
//! in [`crate::remote`] (`hostkey`, `helper`, `runner`) — an earlier pass
//! owns them.

pub mod behavior;
pub mod command;
pub mod release;
pub mod systemd;

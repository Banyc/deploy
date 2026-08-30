//! The activation/verification adapters: the concrete host operations that
//! translate the canonical behavior contract into reality.
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
//! * [`transaction`] — the ADAPTER TRANSACTION PROTOCOL (the review's P1
//!   fix): the prepare→apply→restore→verify_restored discipline every
//!   MUTATING adapter must expose, plus the sealed
//!   [`VerifiedAdapterRestoration`](transaction::VerifiedAdapterRestoration)
//!   proof a rolled-back terminal requires.

pub mod command;
pub mod systemd;
pub mod transaction;

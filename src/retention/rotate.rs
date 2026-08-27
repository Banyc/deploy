//! Receiver-side rotation semantics (feature area A4).
//!
//! The Constitution's "No disk usage leak" rule is served by TWO sweep
//! mechanisms, one per side of the push. This module owns the RECEIVER side:
//!
//! * RECEIVER side (every server's deployment root): swept by ROTATION. The
//!   slot's single owning-variant retention policy computes the retained
//!   digest set ([`super::policy::compute_retained`]); the mark-and-sweep
//!   pass ([`crate::remote::helper::RemoteHelper::rotate`]) deletes every
//!   tree object NOT in the retained set and every abandoned incoming
//!   directory. Generation/release/commit metadata is small and kept by
//!   design; the disk usage — the tree content — is reclaimed.
//!
//! The rotation I/O itself lives in [`crate::remote::helper`]
//! ([`RemoteHelper::rotate`]) and the receiver-side post-commit orchestration
//! (the retention-debt retry that fires the rotation on the next push) lives
//! in [`crate::deploy`] — both owned by other passes; this module holds
//! the retention-side contract the rotation honors. The pusher side of the
//! two-sided sweep (checkpoint) lives in [`super::checkpoint`], and the
//! two-sided no-leak contract tests live in [`super::sweep_tests`].

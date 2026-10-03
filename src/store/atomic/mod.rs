//! Durable atomic filesystem I/O for the store — now the `storekit::atomic`
//! substrate.
//!
//! This module was `deploy`'s own atomic-I/O implementation (1766 lines across
//! `mod.rs`/`unix.rs`/`windows.rs`, the source `storekit` was extracted from).
//! It is now a `pub(crate) use` of [`storekit::atomic`], so the implementation
//! lives in exactly one place and every `crate::store::atomic::…` call site
//! keeps resolving. The `pub(crate)` (never `pub`) form is deliberate: every
//! item this module exposed in `deploy` was `pub(crate)`, while the crate
//! exports them as `pub` for its own consumers, so a `pub use` would WIDEN
//! `deploy`'s surface. This mirrors the `digest`/`platform`/`trace` re-exports.
//!
//! # What moved to the crate unchanged
//!
//! The durability protocol, the descriptor-relative owned-root confinement
//! (`openat`/`renameat`/`linkat`/`unlinkat`/`mkdirat` with `O_NOFOLLOW`), the
//! path-based unconfined replace ([`write_atomic_replace`], public in the crate
//! for exactly this consumer), `path_state`, `temp_name_for`,
//! `copy_dir_recursive`, and the platform split behind ONE `cfg` boundary.
//!
//! # What the crate is STRICTER about (the licensed differences)
//!
//! * **Every root-relative mutation takes `(&RootDir, &RootedRelativePath)`.**
//!   The crate deleted the public path-based helpers `ensure_private_dir`,
//!   `ensure_private_dir_durable`, `sync_parent_dir`, `remove_dir_all_path`,
//!   and `set_private`; a caller adapts by resolving a root and parsing the
//!   validated type ONCE at the boundary ([`crate::store::local`]'s `rel`), so
//!   a `..`/`.`/absolute/empty spelling is refused where `deploy` previously
//!   accepted it.
//! * **ONE reserved-spelling gate** (`storekit::reserved` + the crate's private
//!   `guard`): no mutating primitive may break the lock record or a strand
//!   (`.sync-aside.…`), on ANY component, and the rename worker demands an
//!   unforgeable `GuardedRel` capability. `deploy` did not have this class of
//!   guard; a `deploy` path that happened to name `operation.lock` now fails
//!   closed.
//! * **The FIFO/`O_NONBLOCK` guard:** the read-side opens (`read_fd`,
//!   `path_state_fd`, the tree copy) open with `O_NONBLOCK` and classify the
//!   OPENED inode, so a FIFO/socket/device is REFUSED promptly instead of
//!   blocking forever on a read. `deploy`'s read path had no such guard.
//! * **Identity-based ownership** (`OwnedLockRecord`): the shipped
//!   `remove_owned_lock_record_fd` / `rename_residue_paths` seam the transport
//!   needs is a capability, not a path.
//! * **The explicit durability outcome types** (`ReplaceOutcome`,
//!   `PathKind`, `CompareReplace`) are public and typed.
//!
//! The `storekit::Error` a primitive returns crosses into this crate through
//! the `From<storekit::Error> for crate::error::Error` bridge, which maps the
//! shared classes onto the SAME variants and the crate-only conditions
//! (`Reserved`, `LockContended`) onto typed variants — the `Display` text is
//! byte-identical on both sides.

pub(crate) use storekit::atomic::*;

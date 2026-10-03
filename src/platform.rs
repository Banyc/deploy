//! Platform helpers: the small Unix/Windows divergences (file mode bits,
//! symlinks) consolidated behind ONE cfg switch at this module boundary.
//!
//! * [`chmod`] — set a file's mode bits; a no-op on Windows (no Unix mode
//!   bits; file ACLs are the privacy mechanism).
//! * [`file_mode`] — read a file's mode bits; a fixed conventional mode on
//!   Windows.
//! * [`symlink`] — create a symlink; on Windows, best-effort via the
//!   platform symlink API (which requires admin/developer mode — a failure
//!   propagates, documented).
//!
//! The rest of the crate calls these helpers and never sees the switch.
//!
//! The implementation lives in `storekit::platform` (its prior home was this
//! file, verbatim); this module re-exports it so every `crate::platform::…`
//! call site keeps compiling unchanged. The crate exports these functions as
//! `pub` (a library must); deploy's module-wide `pub(crate)` visibility is
//! preserved here by the `pub(crate) use`, so deploy's surface does not widen.

pub(crate) use storekit::platform::*;

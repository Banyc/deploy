//! Per-server capacity headroom ([`CapacityConfig`]): the validated
//! [`crate::identity::CapacityPercent`] domain form.

use crate::identity::CapacityPercent;

/// A server's capacity headroom policy, declared once per `[[servers]]` entry
/// and shared by every deployment slot on that server. It is LIVE
/// configuration resolved from the caller's current `deploy.toml` at preflight
/// time — servers have no per-release history — and it is NOT part of the
/// release identity: changing a server's capacity never produces a new release
/// and never touches any stored snapshot.
///
/// The DOMAIN form: `reserve_percent` is a validated [`CapacityPercent`]
/// (0..=100). Built ONLY by the raw -> domain conversion; the raw
/// serialization shape is `raw::RawCapacityConfig` (bare integer percent).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CapacityConfig {
    /// Keep at least this many bytes free on the server after an upload.
    pub reserve_bytes: u64,
    /// Keep at least this percentage of the destination filesystem's TOTAL
    /// size free after an upload (0..=100). A VALIDATED [`CapacityPercent`]:
    /// the raw `reserve_percent` integer is parsed by the raw -> domain
    /// conversion, which rejects any value outside 0..=100, so a domain
    /// capacity percent is in range by construction.
    pub reserve_percent: CapacityPercent,
}

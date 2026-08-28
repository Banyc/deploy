//! The remote helper: server-side operations over a [`Remote`]
//! transport. The [`RemoteHelper`] struct, its constructor, and the shared
//! read/status plumbing everything uses (status/record types, behavior-contract
//! reads, the server mutation lock and its RAII guard, inventory writes) lead
//! this module; the per-operation groups live in submodules under section
//! banners. Every mutating operation is keyed by an operation ID and is
//! idempotent.
//!
//! # Submodules
//!
//! * `state` — the generation-state facets: `current` status/chain +
//!   swap/CAS (`current`), commit (`markers`),
//!   and the generation (`assignment`) records.
//! * `mutation` — the mutation facets: object-store (`publish`)
//!   (publication/staging), receiver (`rotate`), and per-operation
//!   (`transactions`) records.
//! * `protocol` — the protocol handshake.
//! * `observed` — the observed-state re-exports.

mod mutation;
mod observed;
mod protocol;
mod state;

pub use mutation::copy_host_tree_to_remote;
pub use observed::{
    Observation, ObservationError, ObservedAssignment, ObservedGeneration, ObservedSlot,
    ObservedTarget,
};
pub use state::GenerationAssignment;
pub use state::current::{CurrentState, ExpectedCurrent};

use crate::error::{Error, Result};
use crate::identity::{BehaviorContract, GenerationId, ReleaseId, ReleaseRecord};
use crate::remote::layout;
use crate::remote::transport::{CreateNewVerdict, Remote, RemoveIfVerdict, VerifiedExisting};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct RemoteStatus {
    /// The validated identity of the generation the `current` symlink names.
    /// `None` ONLY when there is no `current` link at all (genuine absence).
    /// Any PRESENT `current` must name the EXACT canonical
    /// `generations/<gen-id>/root` target and the whole chain behind it must
    /// validate; every deviation (non-canonical target, missing/corrupt
    /// assignment, mismatched generation id, missing/wrong generation `root`
    /// link, missing tree object) fails `status()` with an integrity error —
    /// never a fabricated `None` and never a panic.
    pub current_generation: Option<GenerationId>,
    pub current_tree: Option<String>,
    pub inventory: Vec<String>,
    pub lock: Option<String>,
    pub pending_incoming: Vec<String>,
}

pub struct RemoteHelper<'a> {
    pub(crate) remote: &'a dyn Remote,
    /// The lease clock: the injectable time source behind every lease
    /// expiry. Production uses the real wall clock ([`RealClock`], the
    /// codebase's jiff time source); the lock proptest drives a shared
    /// deterministic fake so the expiry is testable.
    clock: Arc<dyn LeaseClock>,
}

impl<'a> RemoteHelper<'a> {
    pub fn new(remote: &'a dyn Remote) -> Self {
        RemoteHelper {
            remote,
            clock: Arc::new(RealClock),
        }
    }

    /// Test seam: build a helper whose lease clock is the supplied shared
    /// clock (the two-controller lock proptest advances ONE fake clock for
    /// both controllers). Production code goes through [`Self::new`] and the
    /// real wall clock.
    #[cfg(test)]
    pub(crate) fn with_clock(remote: &'a dyn Remote, clock: Arc<dyn LeaseClock>) -> Self {
        RemoteHelper { remote, clock }
    }

    pub fn remote(&self) -> &dyn Remote {
        self.remote
    }

    /// Read the behavior contract for a specific variant of a release. The
    /// release's `behavior.json` stores one contract per declared variant; the
    /// assigned variant is selected explicitly rather than falling back to the
    /// caller's current configuration.
    ///
    /// The published release record is read and identity-verified FIRST (its
    /// canonical digest is recomputed from its own content); its provenance
    /// `behavior_sha256` is then the digest the remote `behavior.json` must
    /// match. A tampered behavior document fails closed with an integrity
    /// error — the historical contract is never returned unverified.
    pub fn read_behavior(&self, release_id: &ReleaseId, variant: &str) -> Result<BehaviorContract> {
        let p = layout::remote_release(release_id.as_str()).join("behavior.json");
        let data = self.remote.read(&p)?;
        // Verify the published release record (its own identity is recomputed
        // from its content) and bind it to the requested release path; its
        // provenance `behavior_sha256` is the canonical digest the behavior
        // snapshot must match.
        let rec: ReleaseRecord = serde_json::from_slice(
            &self
                .remote
                .read(&layout::remote_release(release_id.as_str()).join("release.json"))?,
        )
        .map_err(|e| Error::integrity(format!("malformed release record for {release_id}: {e}")))?;
        crate::verify::release::verify_release_identity(&rec)?;
        if rec.release_id != release_id.as_str() {
            return Err(Error::integrity(format!(
                "release record identity {} does not match the read path {release_id}",
                rec.release_id
            )));
        }
        let behaviors = crate::verify::release::verify_behavior_json(
            &data,
            &rec.release_id,
            &rec.provenance.behavior_sha256,
        )?;
        behaviors.get(variant).cloned().ok_or_else(|| {
            Error::remote(format!(
                "release {release_id} has no behavior for variant '{variant}'"
            ))
        })
    }

    /// Acquire the server mutation lock as a LEASE-CARRYING record (see
    /// [`LockRecord`] and the module contract on this file). `force`
    /// overrides a held lock (used only during recovery) — but the override
    /// is a compare-and-delete BREAK, never a blind overwrite: the lock is
    /// removed only if it still carries the EXACT record that was read, so a
    /// valid successor's lock that changed between the read and the delete
    /// is never removed. Returns the authoritative record now held — a
    /// caller MUST present the SAME record to [`Self::release_lock`], so a
    /// stale release can never delete a successor's lock.
    pub fn acquire_lock(&self, op_id: &str, force: bool) -> Result<LockRecord> {
        let p = &layout::operation_lock();
        // The FENCING TOKEN of a fresh lock is 1 (the first generation of
        // the slot); every break/replacement writes the broken record's
        // token + 1, so tokens are monotonically increasing per slot and a
        // generation is never re-used.
        let mut token = 1u64;
        for _ in 0..ACQUIRE_BREAK_ATTEMPTS {
            let record = LockRecord {
                owner: op_id.to_string(),
                token,
                expires_at_ms: self.clock.now_ms() + LEASE_DURATION_MS,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| Error::remote(format!("serialize lock record: {e}")))?;
            // Atomic create-if-absent: only one caller wins the race for a
            // free lock. The TYPED verdict maps to the lock semantics
            // directly: `Created` (I won the race) and `AlreadyPresent` with
            // IDENTICAL bytes (the identical retry — my own record is
            // already installed) both mean the lock now carries my record;
            // `Conflict` carries the TYPED reason — only a CONTENT conflict
            // (a DIFFERENT holder's lock bytes, type+mode verified regular)
            // is the read-the-winner path below, while a METADATA conflict
            // (a directory or symlink where the lock file should be, a mode
            // mismatch, an unreadable entry) is a REAL conflict: the lock is
            // never silently accepted and the entry is never treated as a
            // lease record.
            match self.remote.try_write_new(p, &bytes)? {
                CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => return Ok(record),
                CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch) => {}
                CreateNewVerdict::Conflict(VerifiedExisting::ModeMismatch { actual, required }) => {
                    return Err(Error::remote(format!(
                        "remote mutation lock exists with mode {actual:o} (required {required:o}); refusing to treat it as a lock"
                    )));
                }
                CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile { kind }) => {
                    return Err(Error::remote(format!(
                        "remote mutation lock path is a {kind:?} entry, not a regular lock file; refusing to treat it as a lock"
                    )));
                }
                CreateNewVerdict::Conflict(VerifiedExisting::Unreadable(e)) => {
                    return Err(Error::remote(format!(
                        "remote mutation lock exists but is unreadable: {e}"
                    )));
                }
                CreateNewVerdict::Conflict(VerifiedExisting::NotFound) => {
                    return Err(Error::remote(
                        "remote mutation lock vanished during verification",
                    ));
                }
                CreateNewVerdict::Conflict(VerifiedExisting::Ok { .. }) => {
                    return Err(Error::remote(
                        "remote mutation lock verification unexpectedly succeeded as Ok",
                    ));
                }
            }
            // Already held by a different record: read the winner and decide
            // — a same-owner retry (the file's record is authoritative),
            // a VALID foreign lease (fail, the current behavior), or an
            // EXPIRED lease (break it via compare-and-delete, then retry).
            let held = self.remote.read(p)?;
            let held_rec: LockRecord = serde_json::from_slice(&held).map_err(|e| {
                Error::integrity(format!(
                    "mutation lock {} is not a lease record: {e}",
                    p.display()
                ))
            })?;
            if held_rec.owner == op_id {
                return Ok(held_rec);
            }
            let expired = held_rec.expires_at_ms <= self.clock.now_ms();
            if !expired && !force {
                return Err(Error::remote(format!(
                    "remote mutation lock held by '{}' (token {}, lease valid until {}), not '{op_id}'",
                    held_rec.owner, held_rec.token, held_rec.expires_at_ms
                )));
            }
            // BREAK: atomic compare-and-delete of the EXACT record that was
            // read. A lock that changed between the read and the delete (a
            // successor's newer generation) is NEVER removed — the break
            // fails and the loop re-reads. Only a `Removed` verdict frees
            // the slot and advances our fencing token.
            match self.remote.remove_file_if(p, &held)? {
                RemoveIfVerdict::Removed => {
                    token = held_rec.token + 1;
                }
                RemoveIfVerdict::Mismatch | RemoveIfVerdict::Absent => {}
            }
        }
        Err(Error::remote(format!(
            "remote mutation lock contended beyond {ACQUIRE_BREAK_ATTEMPTS} attempts (slot {})",
            p.display()
        )))
    }

    /// Release the mutation lock: atomic compare-and-delete with the record
    /// returned by [`Self::acquire_lock`]. The file is removed ONLY if it
    /// still carries EXACTLY this record — a STALE release (the lock now
    /// belongs to a successor generation, e.g. our lease expired and a
    /// contender broke and re-acquired it) FAILS explicitly and NEVER
    /// deletes the successor's lock. An already-absent lock is an idempotent
    /// success (it was already released, or expired and broken). A release
    /// failure is an EXPLICIT error — callers never swallow it silently, and
    /// the LEASE is the backstop: a failed release expires and a contender
    /// breaks it, so a slot can never block forever.
    pub fn release_lock(&self, record: &LockRecord) -> Result<()> {
        let p = &layout::operation_lock();
        let bytes = serde_json::to_vec(record)
            .map_err(|e| Error::remote(format!("serialize lock record: {e}")))?;
        match self.remote.remove_file_if(p, &bytes)? {
            RemoveIfVerdict::Removed | RemoveIfVerdict::Absent => Ok(()),
            RemoveIfVerdict::Mismatch => Err(Error::remote(format!(
                "stale mutation-lock release: the lock no longer carries {}'s record (token {}) — a successor holds it; refusing to delete the successor's lock",
                record.owner, record.token
            ))),
        }
    }

    /// Acquire the server mutation lock and return a guard that releases it
    /// on drop, so every return path (including early errors) releases the
    /// lock. Returns an error only if the lock is held by a different
    /// operation. An explicit [`LockGuard::release`] surfaces the release
    /// outcome; the drop path is best-effort with the lease as the backstop
    /// (see [`LockGuard`]).
    pub fn acquire_lock_guard(&self, op_id: &str) -> Result<LockGuard<'_>> {
        let record = self.acquire_lock(op_id, false)?;
        Ok(LockGuard {
            helper: self,
            record,
            active: true,
        })
    }

    /// Recompute and write `state/inventory.json`.
    pub fn write_inventory(&self) -> Result<()> {
        let mut inv = Vec::new();
        let obj_root = layout::objects();
        if self.remote.metadata_opt(obj_root)?.is_some() {
            for e in self.remote.list(obj_root)? {
                if e.is_dir {
                    inv.push(e.name);
                }
            }
        }
        inv.sort();
        let json = serde_json::to_vec_pretty(&inv)
            .map_err(|e| Error::remote(format!("serialize inventory: {e}")))?;
        self.remote.write(&layout::inventory(), &json, 0o644)?;
        Ok(())
    }
}

/// RAII guard for the server mutation lock: releases it on drop (every
/// return path, including early errors). The release is a compare-and-delete
/// against the record acquired ([`LockGuard::release`] surfaces the outcome
/// as a `Result`); the drop path cannot return errors, so a drop-time release
/// failure is never destructive and never permanent — the record's LEASE
/// expires and a contender's break removes it (the lease is the backstop),
/// so a failed release can never permanently block the slot. Callers that
/// need the release outcome call [`LockGuard::release`] explicitly.
pub struct LockGuard<'a> {
    helper: &'a RemoteHelper<'a>,
    /// The authoritative lock record (owner + fencing token + lease expiry)
    /// this guard holds; release compares the on-disk lock against EXACTLY
    /// this record, so a stale release can never delete a successor's lock.
    record: LockRecord,
    active: bool,
}

impl<'a> LockGuard<'a> {
    /// Release the lock now, surfacing the outcome: `Ok` when the lock was
    /// removed (or was already gone — idempotent), `Err` when the release
    /// FAILED — a stale release whose record no longer matches the on-disk
    /// lock (a successor holds it; it is NEVER deleted) or a transport
    /// fault. Idempotent: releasing twice is a no-op success.
    pub fn release(mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        self.helper.release_lock(&self.record)
    }
}

impl<'a> Drop for LockGuard<'a> {
    fn drop(&mut self) {
        if self.active {
            // Best-effort compare-and-delete; a failure is NOT propagated
            // (drop cannot return errors) but is also never destructive and
            // never permanent: the lease expires and a contender breaks it,
            // so the slot is never blocked forever. Callers that need the
            // release outcome use the explicit [`LockGuard::release`].
            let _ = self.helper.release_lock(&self.record);
        }
    }
}

pub fn now_rfc3339() -> String {
    jiff::Timestamp::now().to_string()
}

/// The lease duration of the per-slot mutation lock: 24 hours. Every
/// operation the lock guards (finalization, retention, publish) completes in
/// minutes at most, so a generous lease exceeds any operation by orders of
/// magnitude and NO heartbeat is needed — the lease exists so a CRASHED
/// owner's lock eventually becomes breakable (a contender breaks the expired
/// record via compare-and-delete). A future long-running operation would
/// renew by re-acquiring; the codebase has none.
pub(crate) const LEASE_DURATION_MS: i64 = 24 * 60 * 60 * 1000;

/// The bounded retry budget of the acquire break loop. Each iteration either
/// installs our record, converges (identical retry), fails on a VALID
/// holder, or breaks EXACTLY ONE expired lock it verified (compare-and-delete
/// never removes a successor's lock), so progress is guaranteed and the cap
/// only bounds adversarially-repeated foreign breaks.
const ACQUIRE_BREAK_ATTEMPTS: usize = 8;

/// The on-server mutation-lock record: owner identity, a per-slot FENCING
/// TOKEN, and the LEASE EXPIRY. The record IS the lock's content — the
/// compare-and-delete primitive ([`Remote::remove_file_if`]) removes the
/// file only when its bytes still match, so a stale release can never delete
/// a successor's lock and an expired-lease break can never remove a newer
/// generation.
///
/// * `owner` — the operation id holding the lock.
/// * `token` — the fencing token: a per-slot MONOTONICALLY INCREASING value
///   identifying the lock's generation (a fresh lock is 1; every
///   break/replacement writes the broken record's token + 1), so a
///   generation is never re-used and two different generations always carry
///   different records.
/// * `expires_at_ms` — the LEASE EXPIRY in epoch milliseconds (the
///   [`LeaseClock`]'s units): the lock is VALID until this instant and
///   BREAKABLE after it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    pub owner: String,
    pub token: u64,
    pub expires_at_ms: i64,
}

/// The lock's time source: an injectable clock so lease expiry is testable.
/// Production uses the real wall clock ([`RealClock`], the codebase's jiff
/// time source); the two-controller lock proptest drives one shared
/// deterministic fake for both controllers.
pub(crate) trait LeaseClock: Send + Sync {
    /// Current time in epoch milliseconds.
    fn now_ms(&self) -> i64;
}

/// The production clock: jiff's wall clock, the codebase's time source.
pub(crate) struct RealClock;

impl LeaseClock for RealClock {
    fn now_ms(&self) -> i64 {
        jiff::Timestamp::now().as_millisecond()
    }
}

/// A deterministic clock whose time a test can advance (the lease expiry
/// seam of the lock proptest). Starts at a fixed epoch; advances only via
/// [`Self::advance`]/[`Self::set`]; shared by both controllers so they
/// observe ONE timeline.
#[cfg(test)]
pub(crate) struct FakeClock {
    now_ms: std::sync::atomic::AtomicI64,
}

#[cfg(test)]
impl FakeClock {
    pub(crate) fn new(start_ms: i64) -> Self {
        Self {
            now_ms: std::sync::atomic::AtomicI64::new(start_ms),
        }
    }

    /// Advance the clock by `ms` (a lease expires once `now` passes it).
    pub(crate) fn advance(&self, ms: i64) {
        self.now_ms
            .fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// Read the current fake time (epoch milliseconds).
    pub(crate) fn read(&self) -> i64 {
        self.now_ms.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
impl LeaseClock for FakeClock {
    fn now_ms(&self) -> i64 {
        self.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::transport::LocalTransport;

    /// The RAII lock guard releases the server mutation lock on drop, even
    /// when the guarded block exits through an error path (no explicit
    /// release): after the guard drops, a fresh operation can acquire the
    /// lock again and the lock file is gone. This is the property the two
    /// retention paths rely on — a manual acquire/release pair would leak the
    /// lock on a `?` error and strand every later operation on the slot.
    #[test]
    fn lock_guard_releases_on_drop_after_error() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);

        {
            let _guard = helper.acquire_lock_guard("op-1").expect("lock acquired");
            // While the guard is alive the lock is held: a second operation
            // cannot acquire it.
            assert!(
                helper.acquire_lock("op-2", false).is_err(),
                "a second operation must not acquire a held lock"
            );
            // Simulate an error path: the guard drops here (scope exit)
            // without any explicit release.
        }

        // After the guard dropped, the lock file is gone and another
        // operation can acquire the lock.
        assert!(
            !remote.exists(&layout::operation_lock()),
            "the lock file must be removed on drop"
        );
        assert!(
            helper.acquire_lock("op-2", false).is_ok(),
            "the lock must be released when the guard drops"
        );
    }

    /// The lease protocol's healthy round trip: a fresh acquire installs a
    /// record carrying the owner's identity, fencing token 1, and a lease
    /// expiry in the future; a VALID lease blocks a contender; a release
    /// with the SAME record removes it (atomic compare-and-delete); and the
    /// next generation restarts the fencing token.
    #[test]
    fn lease_acquire_release_round_trip() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::with_clock(&remote, clock.clone());

        let record = helper.acquire_lock("op-1", false).unwrap();
        assert_eq!(record.owner, "op-1");
        assert_eq!(record.token, 1, "a fresh lock's fencing token starts at 1");
        assert!(
            record.expires_at_ms > clock.read(),
            "the lease must expire in the future"
        );
        // A VALID lease blocks a different operation (the current behavior).
        assert!(
            helper.acquire_lock("op-2", false).is_err(),
            "a valid foreign lease must block a contender"
        );
        // Release with the same record: compare-and-delete removes the lock.
        helper.release_lock(&record).unwrap();
        assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "the lock must be removed by the release"
        );
        // The slot is free again; the next generation restarts the token.
        let r2 = helper.acquire_lock("op-2", false).unwrap();
        assert_eq!(r2.token, 1);
        helper.release_lock(&r2).unwrap();
    }

    /// THE core lease/fencing property: A acquires (token 1), its lease
    /// expires; B BREAKS it (token 2 — the successor fencing token) and
    /// holds; A's DELAYED release then FAILS (compare-and-delete mismatch —
    /// an explicit stale-release error) and B's lock survives byte-for-byte;
    /// the slot is never blocked forever.
    #[test]
    fn expired_lease_break_and_stale_release_preserves_successor() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper_a = RemoteHelper::with_clock(&remote, clock.clone());
        let helper_b = RemoteHelper::with_clock(&remote, clock.clone());

        let a = helper_a.acquire_lock("A", false).unwrap();
        assert_eq!(a.token, 1);
        // B cannot take the lock while A's lease is valid.
        assert!(helper_b.acquire_lock("B", false).is_err());
        // A's lease expires...
        clock.advance(LEASE_DURATION_MS + 1);
        // ...and B BREAKS the expired record (compare-and-delete), writing
        // the successor fencing token.
        let b = helper_b.acquire_lock("B", false).unwrap();
        assert_eq!(
            b.token,
            a.token + 1,
            "a break must write the successor fencing token"
        );
        // A's DELAYED release: the lock no longer carries A's record — the
        // compare-and-delete mismatches, the release FAILS explicitly, and
        // B's lock is NEVER deleted.
        let err = helper_a
            .release_lock(&a)
            .expect_err("a stale release must fail explicitly");
        assert!(
            err.to_string().contains("stale"),
            "the failure must name the stale release, got: {err}"
        );
        let held = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(
            serde_json::from_slice::<LockRecord>(&held).unwrap(),
            b,
            "the successor's lock must survive the stale release byte-for-byte"
        );
        // B releases normally and the slot is free.
        helper_b.release_lock(&b).unwrap();
        assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "the slot must be free after B's release"
        );
    }

    /// The compare-and-delete release is record-exact: releasing with a
    /// DIFFERENT record (a foreign token or owner) is a Mismatch — an
    /// explicit error that never touches the current lock.
    #[test]
    fn release_with_foreign_record_fails_without_touching_lock() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::with_clock(&remote, clock.clone());

        let held = helper.acquire_lock("op-1", false).unwrap();
        // A fabricated record with the same owner but a WRONG token (and an
        // already-expired lease): the release must fail as stale and the
        // real lock must survive.
        let forged = LockRecord {
            owner: "op-1".to_string(),
            token: held.token + 42,
            expires_at_ms: 0,
        };
        let err = helper
            .release_lock(&forged)
            .expect_err("a record-exact release must reject a forged record");
        assert!(err.to_string().contains("stale"));
        let on_disk =
            serde_json::from_slice::<LockRecord>(&remote.read(&layout::operation_lock()).unwrap())
                .unwrap();
        assert_eq!(
            on_disk, held,
            "the real lock must survive the forged release"
        );
        // The genuine release still works.
        helper.release_lock(&held).unwrap();
    }
}

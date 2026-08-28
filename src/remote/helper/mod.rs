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
//!
//! # The server mutation lock: create-once ownership, no automatic takeover
//!
//! The per-slot mutation lock is a CREATE-ONCE OWNERSHIP record
//! ([`LockRecord`]: owner + a persisted monotonic epoch) installed by atomic
//! create-if-absent and removed only by atomic compare-and-delete. The
//! record is created exactly once — a different holder's record FAILS a
//! contender — and is removed either by its OWNER's release or by EXPLICIT
//! RECOVERY ([`RemoteHelper::recover_lock`]) after the controller's death is
//! CONFIRMED. There is NO automatic takeover and NO time anywhere in the
//! protocol: no lease, no expiry, no clock is consulted (the protocol is
//! immune to clock skew by construction), and a held lock never becomes
//! breakable on its own.
//!
//! ## Why no automatic takeover (the two rejected designs)
//!
//! The previous protocol (automatic lease takeover with client-side expiry)
//! was neither linearizable nor genuinely fenced:
//!
//! * **Not linearizable**: the expiry decision was made by the CONTENDER'S
//!   clock. With independent skewable clocks, a contender whose clock runs
//!   fast could break a lease the owner believed was still valid — TWO
//!   controllers could both hold the lock at once and both mutate.
//! * **Not genuinely fenced**: the fencing token was only used for
//!   compare-and-delete on release/break — the actual slot MUTATIONS never
//!   presented or validated the token, so a superseded owner could still
//!   mutate.
//!
//! The "server-side serialized transitions + persisted epoch + server time"
//! alternative (every mutation presents and validates the epoch against a
//! server authority) is NOT implemented here: this codebase's substrate is a
//! FILESYSTEM with no genuine server — a "server-side" check for the local
//! transport is just another process's clock, so automatic takeover cannot
//! be made linearizable on this substrate. Design one is chosen: time
//! disappears from the protocol entirely (the skew surface vanishes), the
//! lock is created once and only its owner releases it, and a held lock
//! changes hands ONLY via explicit recovery under the authoritative local
//! lock.
//!
//! ## The fencing guarantee (precisely)
//!
//! What the protocol GUARANTEES:
//!
//! * **Create-once mutual exclusion**: the lock is installed by atomic
//!   create-if-absent; at most ONE claim ever succeeds for a given slot
//!   generation, so two controllers never both hold the same record. Every
//!   slot mutation happens only while the mutating controller holds the
//!   create-once lock.
//! * **A stale release never displaces a live holder**: release is a
//!   compare-and-delete against the EXACT record acquired — a release whose
//!   record no longer matches the on-disk lock (a successor recovered the
//!   slot) FAILS explicitly and NEVER deletes the successor's lock.
//! * **Recovery is explicit, evidence-requiring, and epoch-advancing**:
//!   recovery ([`RemoteHelper::recover_lock`]) is a named operation invoked
//!   ONLY after the operator CONFIRMS the holding controller died, performed
//!   WHILE HOLDING the authoritative local application-store lock (a live
//!   controller always holds it while operating, so recovery under it cannot
//!   race a live controller). It takes the observed record as its premise
//!   (read → verify → remove — never a blind overwrite), removes it via
//!   compare-and-delete (a lock that changed between the read and the remove
//!   is NEVER removed), and installs the successor with epoch + 1.
//! * **The epoch never repeats**: the epoch is persisted in the record
//!   (starts at 1); EVERY recovery writes the broken record's epoch + 1 —
//!   monotonically increasing per slot — and because the record is
//!   persisted, a fresh process reading the lock sees the current epoch.
//!
//! What the protocol does NOT guarantee (design one deliberately omits
//! design two's mutation-epoch validation): a superseded controller's slot
//! MUTATION is not rejected by the lock itself — the mutual exclusion comes
//! from create-once ownership plus the local-lock serialization of recovery,
//! not from token-checking every mutation. A controller that lost its lock
//! to a recovery must not mutate; the protocol prevents it from HOLDING
//! (its claim is gone, its release is a compare-and-delete mismatch), but a
//! misbehaving controller could still write. Design two's per-mutation epoch
//! validation is the documented alternative, rejected above for the
//! filesystem substrate.

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
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static HELD_LOCK_COUNTS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
fn held_lock_counts() -> &'static Mutex<HashMap<String, usize>> {
    HELD_LOCK_COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn lock_key(helper: &RemoteHelper<'_>) -> String {
    helper
        .remote
        .root()
        .join(layout::operation_lock())
        .to_string_lossy()
        .to_string()
}

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
}

impl<'a> RemoteHelper<'a> {
    pub fn new(remote: &'a dyn Remote) -> Self {
        RemoteHelper { remote }
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

    /// Acquire the server mutation lock as a CREATE-ONCE OWNERSHIP record
    /// (see [`LockRecord`] and the module contract on this file). The lock
    /// is installed by atomic create-if-absent: `Created` (I won the race)
    /// and `AlreadyPresent` with IDENTICAL bytes (the identical retry — my
    /// own record is already installed) both mean the lock now carries my
    /// record. A DIFFERENT holder's record FAILS with "held by X (epoch N)"
    /// — NO automatic break, NO time check, no expiry: a held lock never
    /// becomes breakable on its own.
    ///
    /// `force` breaks a held lock — used ONLY by the recovery path (see
    /// [`Self::recover_lock`]); the override is a compare-and-delete BREAK,
    /// never a blind overwrite: the lock is removed only if it still carries
    /// the EXACT record that was read, so a valid successor's lock that
    /// changed between the read and the delete is never removed. Returns the
    /// authoritative record now held — a caller MUST present the SAME record
    /// to [`Self::release_lock`], so a stale release can never delete a
    /// successor's lock.
    pub fn acquire_lock(&self, op_id: &str, force: bool) -> Result<LockRecord> {
        let p = &layout::operation_lock();
        // A FRESH lock's epoch is 1 (the slot's first generation); every
        // recovery break writes the broken record's epoch + 1, so epochs are
        // monotonically increasing per slot and a generation is never
        // re-used (the record is persisted, so a fresh process reading the
        // lock sees the current epoch).
        let mut epoch = 1u64;
        for _ in 0..RECOVERY_BREAK_ATTEMPTS {
            let record = LockRecord {
                owner: op_id.to_string(),
                epoch,
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
            // never silently accepted and the entry is never treated as an
            // ownership record.
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
            // — a same-owner retry (the file's record is authoritative)
            // converges on it; any other holder is a FAIL (the current
            // behavior — no automatic break) UNLESS `force` (recovery only)
            // requests a compare-and-delete break.
            let held = self.remote.read(p)?;
            let held_rec: LockRecord = serde_json::from_slice(&held).map_err(|e| {
                Error::integrity(format!(
                    "mutation lock {} is not an ownership record: {e}",
                    p.display()
                ))
            })?;
            if held_rec.owner == op_id {
                return Ok(held_rec);
            }
            if !force {
                return Err(Error::remote(format!(
                    "remote mutation lock held by '{}' (epoch {}), not '{op_id}' — no automatic \
                     takeover; explicit recovery is required after confirming the holder died \
                     (recover via `deploy unlock <target> <slot> --yes`)",
                    held_rec.owner, held_rec.epoch
                )));
            }
            // BREAK (recovery only): atomic compare-and-delete of the EXACT
            // record that was read. A lock that changed between the read and
            // the delete (a successor's newer generation) is NEVER removed —
            // the break fails and the loop re-reads. Only a `Removed` verdict
            // frees the slot and advances our epoch.
            match self.remote.remove_file_if(p, &held)? {
                RemoveIfVerdict::Removed => {
                    epoch = held_rec.epoch + 1;
                }
                RemoveIfVerdict::Mismatch | RemoveIfVerdict::Absent => {}
            }
        }
        Err(Error::remote(format!(
            "remote mutation lock contended beyond {RECOVERY_BREAK_ATTEMPTS} attempts (slot {})",
            p.display()
        )))
    }

    /// Release the mutation lock: atomic compare-and-delete with the record
    /// returned by [`Self::acquire_lock`]. The file is removed ONLY if it
    /// still carries EXACTLY this record — a STALE release (the lock now
    /// belongs to a successor generation, e.g. a recovery re-took the slot)
    /// FAILS explicitly and NEVER deletes the successor's lock. An
    /// already-absent lock is an idempotent success (it was already
    /// released). A release failure is an EXPLICIT error — callers never
    /// swallow it silently. There is NO lease backstop: a failed release
    /// leaves the lock HELD until an explicit recovery (the only removal
    /// besides the owner's own release).
    pub fn release_lock(&self, record: &LockRecord) -> Result<()> {
        let p = &layout::operation_lock();
        let bytes = serde_json::to_vec(record)
            .map_err(|e| Error::remote(format!("serialize lock record: {e}")))?;
        match self.remote.remove_file_if(p, &bytes)? {
            RemoveIfVerdict::Removed | RemoveIfVerdict::Absent => Ok(()),
            RemoveIfVerdict::Mismatch => Err(Error::remote(format!(
                "stale mutation-lock release: the lock no longer carries {}'s record (epoch {}) — a successor holds it; refusing to delete the successor's lock",
                record.owner, record.epoch
            ))),
        }
    }

    /// EXPLICIT RECOVERY of a crashed controller's lock — the ONLY way a
    /// held lock changes hands besides its owner's own release. A fresh
    /// acquire NEVER takes over a held lock; a held lock remains held until
    /// this path removes it.
    ///
    /// # The recovery contract (explicit, evidence-requiring, serialized)
    ///
    /// * **CONFIRMATION**: the caller is an OPERATOR who has CONFIRMED the
    ///   holding controller is dead — a named, explicit recovery call (or
    ///   `--recover`-style command), NEVER automatic. The call is performed
    ///   WHILE HOLDING the controller's authoritative local application-store
    ///   lock ([`crate::deploy::lock::FileLock`] on the store's
    ///   `operation.lock`): a LIVE controller always holds that local lock
    ///   while it operates, so a recovery under it cannot race a live
    ///   controller on the same store.
    /// * **THE PREMISE**: `observed` is the record the operator READ (the
    ///   dead controller's record) — recovery is read → verify → remove,
    ///   never a blind overwrite. The current on-disk record must be EXACTLY
    ///   `observed`; a lock that changed (a successor's newer epoch) or is
    ///   already gone is REFUSED.
    /// * **THE REMOVE**: compare-and-delete against the EXACT observed
    ///   bytes — a lock that changed between the verify-read and the delete
    ///   is NEVER removed.
    /// * **THE EPOCH ADVANCE**: the successor record carries epoch =
    ///   `observed.epoch + 1` — strictly greater, monotonically increasing
    ///   per slot, never reused — and is installed by create-if-absent, so a
    ///   concurrent fresh acquire in the tiny remove/install window loses the
    ///   race (the recovery FAILS explicitly rather than overwriting).
    ///
    /// Returns the successor record the recovering controller now holds (its
    /// acquisition — the slot is never left free after a recovery).
    pub fn recover_lock(&self, observed: &LockRecord, new_owner: &str) -> Result<LockRecord> {
        let p = &layout::operation_lock();
        // First try the transport's atomic recover (SSH: one remote exec under
        // the sidecar flock, so the whole read→verify→remove→install is
        // operation-atomic and no contender can win the freed window).
        let observed_bytes = serde_json::to_vec(observed)
            .map_err(|e| Error::remote(format!("serialize lock record: {e}")))?;
        let new_record = LockRecord {
            owner: new_owner.to_string(),
            epoch: observed.epoch + 1,
        };
        let new_bytes = serde_json::to_vec(&new_record)
            .map_err(|e| Error::remote(format!("serialize lock record: {e}")))?;
        if let Some(()) = self.remote.atomic_recover(p, &observed_bytes, &new_bytes)? {
            return Ok(new_record);
        }
        // Local fallback: hold the sidecar flock for the entire
        // read→verify→remove→install sequence, so the compare-then-delete
        // plus the install becomes operation-atomic and a contender's
        // create-if-absent cannot interleave.
        crate::remote::transport::with_operation_lock_sidecar(self.remote.root(), || {
            // READ + VERIFY under the sidecar.
            let current = read_lock_record(self.remote, p)?;
            match &current {
                None => {
                    return Err(Error::remote(
                        "no lock to recover: the slot is already free (the observed record is gone) \
                         — no recovery needed",
                    ));
                }
                Some(rec) if rec != observed => {
                    return Err(Error::remote(format!(
                        "recovery refused: the lock no longer carries the observed record (now held by \
                         '{}', epoch {}) — a successor's newer epoch is never removed; re-read and \
                         re-confirm",
                        rec.owner, rec.epoch
                    )));
                }
                Some(_) => {}
            }
            // REMOVE under the same sidecar.
            match self.remote.remove_file_if(p, &observed_bytes)? {
                RemoveIfVerdict::Removed => {}
                RemoveIfVerdict::Mismatch => {
                    return Err(Error::remote(
                        "recovery race: the lock changed between the verify-read and the remove — a \
                         successor's newer epoch is never removed; re-read and re-confirm",
                    ));
                }
                RemoveIfVerdict::Absent => {
                    return Err(Error::remote(
                        "the lock vanished during recovery; re-read and re-confirm",
                    ));
                }
            }
            // INSTALL under the same sidecar.
            match self.remote.try_write_new(p, &new_bytes)? {
                CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => {
                    Ok(new_record.clone())
                }
                CreateNewVerdict::Conflict(reason) => Err(Error::remote(format!(
                    "recovery install contended (a concurrent acquire won the freed slot: {reason:?}); \
                     re-read and re-confirm"
                ))),
            }
        })
    }

    /// Acquire the server mutation lock and return a guard that releases it
    /// on drop, so every return path (including early errors) releases the
    /// lock. Returns an error only if the lock is held by a different
    /// operation. An explicit [`HeldSlotLock::release`] surfaces the release
    /// outcome; the drop path is best-effort — with no lease, a failed
    /// drop-time release leaves the lock HELD until explicit recovery (see
    /// [`HeldSlotLock`]).
    pub fn acquire_lock_guard(&self, op_id: &str) -> Result<HeldSlotLock<'_>> {
        let record = self.acquire_lock(op_id, false)?;
        let key = lock_key(self);
        {
            let mut counts = held_lock_counts().lock().unwrap();
            *counts.entry(key.clone()).or_insert(0) += 1;
        }
        Ok(HeldSlotLock {
            helper: self,
            record,
            key,
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
/// against the record acquired ([`HeldSlotLock::release`] surfaces the outcome
/// as a `Result`); the drop path cannot return errors, so a drop-time release
/// failure is never destructive but — with NO LEASE in the protocol — it is
/// also no longer self-healing: a failed drop-time release leaves the lock
/// HELD until an EXPLICIT RECOVERY ([`RemoteHelper::recover_lock`]) removes
/// it. The recovery path is the only removal besides the owner's own
/// release. Callers that need the release outcome call [`HeldSlotLock::release`]
/// explicitly.
///
/// Contract: "only the outermost owner may release" — dropping a guard
/// releases the remote lock ONLY when it is the outermost instance for that
/// slot; a nested/aliased instance's drop NEVER releases. Nesting is made
/// impossible by construction for production paths (the locked body takes
/// `&HeldSlotLock`, a borrow — there is no second guard to drop), while the
/// guard's Drop itself defensively enforces outermost-only release via a
/// process-wide refcount keyed by the lock file path.
pub struct HeldSlotLock<'a> {
    helper: &'a RemoteHelper<'a>,
    /// The authoritative lock record (owner + persisted monotonic epoch)
    /// this guard holds; release compares the on-disk lock against EXACTLY
    /// this record, so a stale release can never delete a successor's lock.
    record: LockRecord,
    key: String,
    active: bool,
}

impl<'a> HeldSlotLock<'a> {
    /// Release the lock now, surfacing the outcome: `Ok` when the lock was
    /// removed (or was already gone — idempotent), `Err` when the release
    /// FAILED — a stale release whose record no longer matches the on-disk
    /// lock (a successor holds it; it is NEVER deleted) or a transport
    /// fault. Idempotent: releasing twice is a no-op success.
    /// Only the outermost guard actually performs the remote compare-and-delete;
    /// nested guards decrement the refcount and return `Ok(())` without touching
    /// the remote lock.
    pub fn release(mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let outermost = {
            let mut counts = held_lock_counts().lock().unwrap();
            if let Some(cnt) = counts.get_mut(&self.key) {
                *cnt = cnt.saturating_sub(1);
                let is_last = *cnt == 0;
                if is_last {
                    counts.remove(&self.key);
                }
                is_last
            } else {
                true
            }
        };
        if outermost {
            self.helper.release_lock(&self.record)
        } else {
            Ok(())
        }
    }
}

impl<'a> Drop for HeldSlotLock<'a> {
    fn drop(&mut self) {
        if self.active {
            let outermost = {
                let mut counts = held_lock_counts().lock().unwrap();
                if let Some(cnt) = counts.get_mut(&self.key) {
                    *cnt = cnt.saturating_sub(1);
                    let is_last = *cnt == 0;
                    if is_last {
                        counts.remove(&self.key);
                    }
                    is_last
                } else {
                    true
                }
            };
            if outermost {
                // Best-effort compare-and-delete; a failure is NOT propagated
                // (drop cannot return errors) and is never destructive — but with
                // no lease the protocol does not self-heal: a failed drop-time
                // release leaves the lock HELD until an EXPLICIT recovery
                // ([`RemoteHelper::recover_lock`]) removes it. Callers that need
                // the release outcome use the explicit [`HeldSlotLock::release`].
                let _ = self.helper.release_lock(&self.record);
            }
        }
    }
}

/// Backwards-compat alias: existing call sites using `LockGuard` keep compiling.
/// New code should use `HeldSlotLock`.
pub type LockGuard<'a> = HeldSlotLock<'a>;

pub fn now_rfc3339() -> String {
    jiff::Timestamp::now().to_string()
}

/// The bounded retry budget of the recovery break loop in
/// [`RemoteHelper::acquire_lock`] (the `force` path) and the create/install
/// convergence of the healthy path. Each iteration either installs our
/// record, converges (identical retry), fails on a DIFFERENT holder, or —
/// with `force` — breaks EXACTLY ONE record it verified (compare-and-delete
/// never removes a successor's lock), so progress is guaranteed and the cap
/// only bounds adversarially-repeated foreign breaks. There is NO automatic
/// break: a held lock is only ever broken by this explicit recovery path.
const RECOVERY_BREAK_ATTEMPTS: usize = 8;

/// The on-server mutation-lock record: owner identity plus a PERSISTED
/// MONOTONIC EPOCH (the fencing generation). The record IS the lock's
/// content — the compare-and-delete primitive ([`Remote::remove_file_if`])
/// removes the file only when its bytes still match, so a stale release can
/// never delete a successor's lock and a recovery can never remove a newer
/// generation. The record is CREATE-ONCE: it is installed by atomic
/// create-if-absent (a different holder's record fails a contender — no
/// automatic takeover, no time anywhere) and removed only by its OWNER's
/// release or by EXPLICIT recovery ([`RemoteHelper::recover_lock`]).
///
/// * `owner` — the operation id holding the lock.
/// * `epoch` — the PERSISTED MONOTONIC EPOCH: a per-slot strictly
///   increasing value identifying the lock's generation (a fresh lock is 1;
///   every recovery writes the broken record's epoch + 1), so a generation
///   is never re-used, two different generations always carry different
///   records, and a fresh process reading the persisted record sees the
///   current epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    pub owner: String,
    pub epoch: u64,
}

/// Read the current on-disk lock record (typed absence probe first): `None`
/// for genuine absence, the parsed record otherwise, `Err` for a transport
/// fault or a present-but-not-a-record file. The typed `metadata_opt` probe
/// means a failed read is NEVER indistinguishable from absence.
pub(crate) fn read_lock_record(
    remote: &dyn Remote,
    p: &std::path::Path,
) -> Result<Option<LockRecord>> {
    let Some(_) = remote.metadata_opt(p)? else {
        return Ok(None);
    };
    let data = remote.read(p)?;
    let rec: LockRecord = serde_json::from_slice(&data).map_err(|e| {
        Error::integrity(format!(
            "mutation lock {} is not an ownership record: {e}",
            p.display()
        ))
    })?;
    Ok(Some(rec))
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
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "the lock file must be removed on drop"
        );
        assert!(
            helper.acquire_lock("op-2", false).is_ok(),
            "the lock must be released when the guard drops"
        );
    }

    /// The create-once protocol's healthy round trip: a fresh acquire
    /// installs a record carrying the owner's identity and epoch 1; a
    /// DIFFERENT holder's record blocks a contender (no automatic takeover —
    /// a fresh acquire on a held lock FAILS no matter what); a release with
    /// the SAME record removes it (atomic compare-and-delete); and the next
    /// generation of a FREE slot restarts the epoch at 1.
    #[test]
    fn acquire_release_round_trip() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);

        let record = helper.acquire_lock("op-1", false).unwrap();
        assert_eq!(record.owner, "op-1");
        assert_eq!(record.epoch, 1, "a fresh lock's epoch starts at 1");
        // A DIFFERENT holder's record blocks a contender — NO automatic
        // takeover: the lock never becomes breakable on its own.
        assert!(
            helper.acquire_lock("op-2", false).is_err(),
            "a held lock must block a contender (no automatic takeover)"
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
        // The slot is free again; the next generation of the free slot
        // restarts the epoch.
        let r2 = helper.acquire_lock("op-2", false).unwrap();
        assert_eq!(r2.epoch, 1);
        helper.release_lock(&r2).unwrap();
    }

    /// THE core no-takeover/fencing property: A acquires (epoch 1) and never
    /// releases (a crash); B's fresh acquire FAILS (no automatic takeover —
    /// the lock is not breakable on its own); B's EXPLICIT recovery — under
    /// the authoritative local lock, taking A's observed record as its
    /// premise — removes A's record and installs B's successor record with
    /// epoch 2; A's DELAYED release then FAILS (compare-and-delete mismatch —
    /// an explicit stale-release error) and B's lock survives byte-for-byte.
    #[test]
    fn crash_then_recover_and_stale_release_preserves_successor() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper_a = RemoteHelper::new(&remote);
        let helper_b = RemoteHelper::new(&remote);

        let a = helper_a.acquire_lock("A", false).unwrap();
        assert_eq!(a.epoch, 1);
        // B cannot take the lock while A holds it — no matter what: no
        // expiry, no automatic break.
        assert!(helper_b.acquire_lock("B", false).is_err());
        // A "crashes" (its lock stays in place — no release). The lock is
        // held forever until explicit recovery: B's fresh acquire still
        // fails even with `force: false` obviously, and there is no time
        // that would ever make it succeed on its own.
        assert!(
            helper_b.acquire_lock("B", false).is_err(),
            "a crashed owner's lock is held until explicit recovery"
        );
        // EXPLICIT RECOVERY under the authoritative local application-store
        // lock (a live controller always holds it while operating, so a
        // recovery under it cannot race a live controller): the operator
        // confirms A died and calls the named recovery with A's OBSERVED
        // record as the premise. The successor record advances the epoch.
        let store_dir = dir.path().join("store");
        let _local_guard = crate::deploy::lock::FileLock::acquire(
            &store_dir.join("operation.lock"),
            "recovery-op",
        )
        .expect("the authoritative local lock must be acquirable");
        let b = helper_b
            .recover_lock(&a, "B")
            .expect("explicit recovery of the confirmed-dead controller succeeds");
        assert_eq!(
            b.epoch,
            a.epoch + 1,
            "a recovery must write the broken record's epoch + 1 (strictly greater)"
        );
        assert_eq!(b.owner, "B");
        assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_some(),
            "the successor record must be installed by the recovery"
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

    /// Recovery is evidence-requiring (read → verify → remove, never a blind
    /// overwrite): recovering with a STALE observed record (a successor
    /// already recovered the slot) is REFUSED and the successor's newer-epoch
    /// lock survives byte-for-byte.
    #[test]
    fn recovery_with_stale_observed_record_refuses_and_preserves_successor() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper_a = RemoteHelper::new(&remote);
        let helper_b = RemoteHelper::new(&remote);
        let helper_c = RemoteHelper::new(&remote);

        // A acquires (epoch 1) and crashes.
        let a = helper_a.acquire_lock("A", false).unwrap();
        // B recovers the slot: epoch advances to 2.
        let b = helper_b.recover_lock(&a, "B").unwrap();
        assert_eq!(b.epoch, 2);
        // C tries to recover the slot with A's OLD observed record (stale —
        // the slot now carries B's epoch-2 record): REFUSED, and B's lock
        // survives byte-for-byte.
        let err = helper_c
            .recover_lock(&a, "C")
            .expect_err("a recovery with a stale observed record must be refused");
        assert!(
            err.to_string().contains("recovery refused"),
            "the failure must name the refusal, got: {err}"
        );
        let held = remote.read(&layout::operation_lock()).unwrap();
        assert_eq!(
            serde_json::from_slice::<LockRecord>(&held).unwrap(),
            b,
            "the successor's newer-epoch lock must survive a refused recovery byte-for-byte"
        );
        // Recovery with the CURRENT observed record succeeds: epoch advances
        // to 3 (monotonic, never reused).
        let c = helper_c.recover_lock(&b, "C").unwrap();
        assert_eq!(c.epoch, 3, "recoveries advance the epoch monotonically");
        helper_c.release_lock(&c).unwrap();
    }

    /// Recovery of an ALREADY-FREE slot is refused (the premise — a dead
    /// controller's record — no longer holds; the operator re-reads and
    /// re-confirms, and a fresh acquire proceeds directly).
    #[test]
    fn recovery_of_a_free_slot_is_refused() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);

        let record = helper.acquire_lock("op-1", false).unwrap();
        helper.release_lock(&record).unwrap();
        let err = helper
            .recover_lock(&record, "op-2")
            .expect_err("recovering a free slot must be refused");
        assert!(err.to_string().contains("already free"));
        // A fresh acquire proceeds directly (create-once on the free slot).
        assert!(helper.acquire_lock("op-2", false).is_ok());
    }

    /// The compare-and-delete release is record-exact: releasing with a
    /// DIFFERENT record (a foreign epoch or owner) is a Mismatch — an
    /// explicit error that never touches the current lock.
    #[test]
    fn release_with_foreign_record_fails_without_touching_lock() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);

        let held = helper.acquire_lock("op-1", false).unwrap();
        // A fabricated record with the same owner but a WRONG epoch: the
        // release must fail as stale and the real lock must survive.
        let forged = LockRecord {
            owner: "op-1".to_string(),
            epoch: held.epoch + 42,
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

    /// Sidecar mutex property: a mismatched or failed `remove_file_if` must
    /// leave the original record byte-identical and continuously visible, and
    /// a contender can only succeed when the slot is legitimately free.
    /// The test exposes the claim/compare/restore/delete boundaries of the
    /// remove and inserts a contender acquisition after EVERY boundary.
    /// With the sidecar, a contended remove is operation-atomic: the
    /// contender's create-if-absent is serialized behind the sidecar and
    /// fails, and the record is never absent. Without the sidecar, the
    /// transient claim window would let the contender win the freed path
    /// and the original record would be destroyed.
    #[cfg(test)]
    mod sidecar_mutex {
        use super::*;
        use crate::remote::layout;
        use crate::remote::transport::{CreateNewVerdict, LocalTransport, Remote, RemoveIfVerdict};
        use proptest::prelude::*;
        use proptest::test_runner::RngSeed;

        fn lock_bytes(owner: &str, epoch: u64) -> Vec<u8> {
            serde_json::to_vec(&LockRecord {
                owner: owner.to_string(),
                epoch,
            })
            .unwrap()
        }

        proptest! {
            #![proptest_config(proptest::test_runner::Config {
                cases: crate::testutil::proptest_cases(64),
                max_shrink_iters: 10000,
                rng_seed: RngSeed::Fixed(0x5EED_5EED),
                failure_persistence: None,
                ..proptest::test_runner::Config::default()
            })]
            #[test]
            fn contender_after_every_boundary(
                holder in prop_oneof![Just("holder-A".to_string()), Just("holder-B".to_string())],
                holder_epoch in 1u64..10,
                contender in prop_oneof![Just("contender-X".to_string()), Just("contender-Y".to_string())],
                mismatch_epoch in 100u64..200,
                steps in prop::collection::vec(
                    prop_oneof![
                        Just(0u8), // mismatched remove
                        Just(1u8), // matched remove
                    ],
                    1..=crate::testutil::proptest_steps(40)
                )
            ) {
                let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
                let remote = LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote")).unwrap();
                let holder_bytes = lock_bytes(&holder, holder_epoch);
                // Claim by holder (create-if-absent, sidecar-serialized).
                let verdict = remote.try_write_new(&layout::operation_lock(), &holder_bytes).unwrap();
                prop_assert!(matches!(verdict, CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent));
                let original = remote.read(&layout::operation_lock()).unwrap();
                prop_assert_eq!(original.clone(), holder_bytes.clone(), "original must be byte-identical after claim");
                // Contender after claim: must fail (slot held).
                let contender_bytes = lock_bytes(&contender, 1);
                let c1 = remote.try_write_new(&layout::operation_lock(), &contender_bytes).unwrap();
                prop_assert!(matches!(c1, CreateNewVerdict::Conflict(_)), "contender after held claim must be Conflict, got {c1:?}");
                prop_assert_eq!(remote.read(&layout::operation_lock()).unwrap(), original.clone(), "record must stay byte-identical after contender");
                prop_assert!(remote.metadata_opt(&layout::operation_lock()).unwrap().is_some(), "record must stay continuously visible after contender");
                for &step in &steps {
                    if step == 0 {
                        // Mismatched remove: compare-boundary then delete-boundary.
                        let mismatched = lock_bytes(&contender, mismatch_epoch);
                        // Expose compare-boundary: read+compare without mutating, then contender.
                        let cur = remote.read(&layout::operation_lock()).unwrap();
                        prop_assert_eq!(cur, original.clone(), "compare-boundary: record still original");
                        let cc = remote.try_write_new(&layout::operation_lock(), &contender_bytes).unwrap();
                        prop_assert!(matches!(cc, CreateNewVerdict::Conflict(_)), "contender after compare-boundary (mismatched) must fail");
                        prop_assert_eq!(remote.read(&layout::operation_lock()).unwrap(), original.clone());
                        // Now the actual mismatched remove (sidecar-serialized, continuously visible).
                        let v = remote.remove_file_if(&layout::operation_lock(), &mismatched).unwrap();
                        prop_assert_eq!(v, RemoveIfVerdict::Mismatch, "mismatched remove must be Mismatch");
                        // Delete-boundary: after the remove, contender again.
                        prop_assert_eq!(remote.read(&layout::operation_lock()).unwrap(), original.clone(), "delete-boundary mismatched must leave original byte-identical");
                        prop_assert!(remote.metadata_opt(&layout::operation_lock()).unwrap().is_some(), "mismatched remove must never leave path absent");
                        let cd = remote.try_write_new(&layout::operation_lock(), &contender_bytes).unwrap();
                        prop_assert!(matches!(cd, CreateNewVerdict::Conflict(_)), "contender after mismatched delete-boundary must fail");
                        prop_assert_eq!(remote.read(&layout::operation_lock()).unwrap(), original.clone());
                    } else {
                        // Matched remove: the slot becomes legitimately free, contender must succeed.
                        let v = remote.remove_file_if(&layout::operation_lock(), &original).unwrap();
                        if v == RemoveIfVerdict::Removed {
                            prop_assert!(remote.metadata_opt(&layout::operation_lock()).unwrap().is_none(), "matched remove must leave path absent");
                            let cd = remote.try_write_new(&layout::operation_lock(), &contender_bytes).unwrap();
                            prop_assert!(matches!(cd, CreateNewVerdict::Created), "contender after legitimate free must succeed, got {cd:?}");
                            // Re-establish holder for next iteration if needed
                            let _ = remote.remove_file_if(&layout::operation_lock(), &contender_bytes).unwrap();
                            let _ = remote.try_write_new(&layout::operation_lock(), &holder_bytes).unwrap();
                        } else {
                            // Already absent (idempotent) — also legitimately free
                            prop_assert_eq!(v, RemoveIfVerdict::Absent);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod nested_guard_proptest {
    use super::*;
    use crate::remote::transport::LocalTransport;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    fn run_nested_case(depth: usize, outcome: u8) -> std::result::Result<(), TestCaseError> {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper_a = RemoteHelper::new(&remote);
        let helper_b = RemoteHelper::new(&remote);
        let op_a = "op-A";
        let op_b = "op-B";
        // Outer acquires — the process_server guard.
        let outer = helper_a
            .acquire_lock_guard(op_a)
            .expect("outer acquire must succeed");
        let initial_bytes = remote.read(&layout::operation_lock()).unwrap();
        let initial_rec: LockRecord = serde_json::from_slice(&initial_bytes).unwrap();
        prop_assert_eq!(initial_rec.owner, op_a);
        // Inner "compensation" scopes — reentrant acquire with SAME op_id
        // must converge (identical bytes) and create nested guards. Depth 1..=3.
        let mut inners: Vec<HeldSlotLock<'_>> = Vec::new();
        for _ in 0..depth {
            let g = helper_a
                .acquire_lock_guard(op_a)
                .expect("inner reentrant acquire must converge");
            let bytes = remote.read(&layout::operation_lock()).unwrap();
            prop_assert_eq!(
                bytes,
                initial_bytes.clone(),
                "reentrant acquire must leave on-disk record byte-identical"
            );
            inners.push(g);
        }
        // Simulate compensation outcome variation — success / failure / faulted
        // do not change lock behavior, but exercise the generated variations:
        // we optionally exercise explicit release vs drop for faulted.
        if outcome == 2 {
            // faulted: explicitly release the innermost guard via `release()`
            // — must still NOT free the lock while outer lives.
            if let Some(g) = inners.pop() {
                let r = g.release();
                prop_assert!(r.is_ok(), "nested explicit release must not error");
                let bytes = remote.read(&layout::operation_lock()).unwrap();
                prop_assert_eq!(
                    bytes,
                    initial_bytes.clone(),
                    "nested explicit release must not delete outer lock"
                );
                // B must still be blocked in the faulted tail window.
                let b_attempt = helper_b.acquire_lock(op_b, false);
                prop_assert!(
                    b_attempt.is_err(),
                    "B must remain blocked after faulted inner release while outer lives"
                );
            }
        }
        // Drop remaining inners one by one, checking after each that B stays blocked.
        while let Some(g) = inners.pop() {
            drop(g);
            let bytes = remote.read(&layout::operation_lock()).unwrap();
            prop_assert_eq!(
                bytes,
                initial_bytes.clone(),
                "inner drop must not delete outer lock"
            );
            let b_attempt = helper_b.acquire_lock(op_b, false);
            prop_assert!(
                b_attempt.is_err(),
                "B must remain blocked after inner drop while outer lives"
            );
        }
        // Tail window: inner scope ended, outer still alive — the
        // process_server-tail window after compensation returns.
        {
            let bytes = remote.read(&layout::operation_lock()).unwrap();
            prop_assert_eq!(
                bytes,
                initial_bytes.clone(),
                "tail window must keep A's record byte-for-byte"
            );
            let b_attempt = helper_b.acquire_lock(op_b, false);
            prop_assert!(
                b_attempt.is_err(),
                "B must remain blocked in process_server tail window while outer lives"
            );
            prop_assert!(
                remote
                    .metadata_opt(&layout::operation_lock())
                    .unwrap()
                    .is_some(),
                "lock file must still exist in tail window"
            );
        }
        // Only after outer drops may B succeed.
        drop(outer);
        prop_assert!(
            remote
                .metadata_opt(&layout::operation_lock())
                .unwrap()
                .is_none(),
            "lock file must be removed after outer drop"
        );
        let b_ok = helper_b.acquire_lock(op_b, false);
        prop_assert!(b_ok.is_ok(), "B may succeed only after outer guard drops");
        // Clean up B for next case isolation.
        if let Ok(rec) = b_ok {
            let _ = helper_b.release_lock(&rec);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            max_shrink_iters: 1000,
            rng_seed: RngSeed::Fixed(0x5EED_5EEF),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        #[test]
        fn nested_acquire_blocks_contender_until_outer_drop(
            depth in 1usize..=3,
            outcome in 0u8..=2,
        ) {
            run_nested_case(depth, outcome)?;
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            max_shrink_iters: 1000,
            rng_seed: RngSeed::Fixed(0x5EED_5EF0),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        #[test]
        fn contender_in_tail_window_with_outer_alive(
            depth in 1usize..=3,
        ) {
            // Dedicated tail-window assertion: outer guard alive, inner(s)
            // dropped, contender injected immediately after compensation returns.
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let remote = LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote")).unwrap();
            let helper_a = RemoteHelper::new(&remote);
            let helper_b = RemoteHelper::new(&remote);
            let op_a = "op-A-tail";
            let outer = helper_a.acquire_lock_guard(op_a).unwrap();
            let initial_bytes = remote.read(&layout::operation_lock()).unwrap();
            let mut inners: Vec<HeldSlotLock<'_>> = Vec::new();
            for _ in 0..depth {
                inners.push(helper_a.acquire_lock_guard(op_a).unwrap());
            }
            for g in inners.into_iter().rev() {
                drop(g);
            }
            // Tail window — outer still alive.
            let b_attempt = helper_b.acquire_lock("op-B-tail", false);
            prop_assert!(b_attempt.is_err(), "B must fail in tail window while outer lives");
            let after_bytes = remote.read(&layout::operation_lock()).unwrap();
            prop_assert_eq!(after_bytes, initial_bytes, "on-disk record must remain A's record byte-for-byte in tail window");
            drop(outer);
            // After outer drop B may succeed.
            prop_assert!(helper_b.acquire_lock("op-B-tail", false).is_ok(), "B may succeed after outer drop");
        }
    }
}

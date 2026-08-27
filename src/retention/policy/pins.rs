//! Pin honoring, fail closed on BOTH sweep sides (feature area A4).
//!
//! The config/store pin types live in `crate::config::pins` and the store;
//! the HONORING logic lives here:
//!
//! * `LocalStore::honor_release_pin` — the pusher-side GC anchor semantics
//!   (moved from `crate::retention::history_floor`): a pin that names a release
//!   with NO record on disk, or whose record cannot be read or
//!   identity-verified, is an [`Error::integrity`] error — the retained set
//!   would be incomplete, so the sweep must abort before any deletion.
//! * `LocalStore::expand_retention_pins` — the receiver-side mirror (the
//!   retention policy's durable pins): a pin protects the whole release, and
//!   an un-honorable pin aborts retention with an integrity error before any
//!   tree deletion, never treating the pin as absent.

use crate::config::Pin;
use crate::error::{Error, Result};
use crate::identity::ReleaseId;
use crate::retention::history_floor::ReachableSet;
use crate::store::atomic::path_state;
use crate::store::local::LocalStore;
use std::collections::HashSet;

impl LocalStore {
    /// Honor ONE release pin: verify the named release's record exists and
    /// reads clean (identity-verified via [`LocalStore::read_release`]), then
    /// retain the record; when `expand_variants` (a WHOLE-RELEASE pin) also
    /// retain every variant's tree from the record's `variants` map. An
    /// EXACT-BINDING pin (`expand_variants = false`) keeps its own
    /// (release, tree) at the call site.
    ///
    /// FAIL CLOSED — a pin-abort, before any deletion: a pin that names a
    /// release with NO record on disk, or whose record cannot be read or
    /// identity-verified, is an [`Error::integrity`] error. An un-honorable
    /// pin means the reachability computation cannot expand the content the
    /// pin protects, so the retained set is incomplete — the sweep must
    /// abort rather than delete against it. (A missing record is tri-state
    /// DETECTED here: a genuine NotFound on the record file is not "absent
    /// pin" — it is a pin naming nothing on disk, an integrity violation.)
    pub(crate) fn honor_release_pin(
        &self,
        out: &mut ReachableSet,
        rid: &ReleaseId,
        expand_release_variants: bool,
    ) -> Result<()> {
        let rec_path = self.release_dir(rid).join("release.json");
        if !path_state(&rec_path)? {
            return Err(Error::integrity(format!(
                "pin names release {rid} which has no release record on disk: the pin cannot be honored, so reachability is incomplete — aborting the artifact sweep before any deletion"
            )));
        }
        // Read + identity-verify the record; ANY failure (an unreadable
        // file, malformed content, an identity mismatch) is an un-honorable
        // pin and is normalized to [`Error::integrity`] (the underlying
        // cause stays embedded in the message) — requirement: a pin that
        // cannot be honored aborts the sweep with an integrity error
        // whether the record is missing, unreadable, or unverifiable.
        let rec = self.read_release(rid).map_err(|e| {
            Error::integrity(format!(
                "pin names release {rid} whose record cannot be read or verified ({e}): the pin cannot be honored, so reachability is incomplete — aborting the artifact GC before any deletion"
            ))
        })?;
        out.releases.insert(rec.release_id.clone());
        if expand_release_variants {
            for tree in rec.variants.values() {
                out.trees.insert(tree.clone());
            }
        }
        Ok(())
    }

    /// Expand the RECEIVER-side retention pins into the retained set: a pin
    /// protects the whole release — every variant's tree recorded in the
    /// release record is retained, so the pinned release stays fully
    /// rollback-able no matter how old it is or how far outside the
    /// count/age windows it falls.
    ///
    /// FAIL CLOSED — the receiver-side mirror of the pusher-side GC anchor
    /// semantics ([`LocalStore::honor_release_pin`]): a pin that names a
    /// release with NO record on disk, or whose record cannot be read or
    /// identity-verified, is an INTEGRITY error (see [`LocalStore::read_release`],
    /// which recomputes-and-verifies the record's identity from its own content
    /// and binds it to the requested release id). An un-honorable pin means the
    /// retained set cannot expand the content the pin protects, so it is
    /// INCOMPLETE — retention must ABORT BEFORE ANY DELETION, never treat the
    /// pin as absent and sweep the trees it protects. The retention caller
    /// converts the abort into the retention-debt machinery (a durable marker +
    /// warning, post-commit maintenance): the next push retries retention once
    /// the pinned release is repaired.
    pub(crate) fn expand_retention_pins(
        &self,
        retained: &mut HashSet<String>,
        pins: &[Pin],
    ) -> Result<()> {
        for pin in pins {
            // The pin's release is the TYPED [`crate::identity::ReleaseId`]: it was
            // validated when the config was loaded, so this can never be a late
            // release-id syntax error.
            let rid = pin.release.clone();
            let rec = self.read_release(&rid).map_err(|e| {
                Error::integrity(format!(
                    "pin names release {rid} whose record cannot be read or verified ({e}): \
                     the pin cannot be honored, so the retained set is incomplete — aborting \
                     retention before any tree deletion"
                ))
            })?;
            for tree in rec.variants.values() {
                retained.insert(tree.clone());
            }
        }
        Ok(())
    }
}

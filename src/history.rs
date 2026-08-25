//! Deployment snapshot history, rollback snapshots, and rollback reference
//! handling.
//!
//! Only fully successful deployments produce a snapshot
//! (`refs/snapshots.jsonl`), exposed as the indices `s0`, `s1`, and so on
//! (`ref_name` renders them `snapshot s0 of target production` for display). Failed and degraded
//! attempts remain visible through `deploy log` and `attempts.jsonl` but are
//! not valid rollback sources.
//!
//! # Reference syntax (jj-style)
//!
//! The push reference is jj-style: the TARGET IS NEVER REPEATED in the
//! reference, and the `@`-relative forms resolve against the separately-given
//! target argument. Resolution is a TWO-PHASE process:
//!
//! * [`parse_ref_expr`] turns the token into a structured [`RefExpr`] with NO
//!   store access — pure syntax. The engine parses the token BEFORE it
//!   acquires locks or persists anything, so a malformed token fails before
//!   any side effect and the deployment id/plan are never serialized against
//!   a half-parsed reference.
//! * [`resolve_ref_expr`] turns the parsed expression into a concrete
//!   [`PushRef`] against the target's snapshot chain in the store. The engine
//!   calls it AFTER reconciliation
//!   ([`crate::push::reconcile::reconcile_pending_commits`]) has appended any
//!   recovered snapshots, so a relative ref is computed against the
//!   POST-reconciliation chain: `@-` means one before the latest INCLUDING
//!   this push's reconciled append, never a stale pre-recovery snapshot.
//!
//! The accepted forms are:
//!
//! * `` (empty), `HEAD`, `@` — the current local files (the default).
//! * `@-`, `@--` — the snapshot BEFORE the latest, the grandparent.
//! * `parent(@, N)` — the Nth ancestor of the latest snapshot.
//! * `release:<id>` — the DIRECT release form: deploy the named release to
//!   the CURRENT target's slots as they are, from the release's OWN stored
//!   slot-variant snapshot. No snapshot-chain stepping and no
//!   deployment-snapshot membership/binding checks: cross-target capable —
//!   the release may have been built/pushed anywhere, and the destination
//!   needs NO snapshot history at all. The id is a full `rel-sha256-...` id
//!   or a hex digest.
//! * `<refid>-`, `<refid>--` — N ancestors of the refid (1 or 2 dashes).
//! * `parent(<refid>, N)` — N ancestors of the refid (N = 0 is the refid
//!   itself).
//! * the bare refid itself — `s3` (snapshot index 3), `deploy-...` (the
//!   most recent snapshot of that deployment).
//!
//! `<refid>` is a snapshot index (`s3`), a deployment id (`deploy-...`), or a
//! release id (`rel-sha256-...` or a bare digest). A snapshot index resolves
//! to the snapshot with that index; a deployment or release id resolves to
//! the MOST RECENT snapshot that deployed that deployment / references that
//! release — SNAPSHOT ANCESTRY, distinct from the direct `release:<id>` form
//! above. The ancestor steps then walk `s(index - N)`; stepping past the
//! start of the chain, an unresolvable refid, or an empty chain fail closed
//! with a ref error — never underflow, never guess.

use crate::error::{Error, Result};
use crate::model::{
    GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, TargetName,
};
use crate::records::{
    AttemptServer, DeploymentAttempt, DeploymentSnapshot, DeploymentStatus, PhysicalBinding,
};
use crate::store::local::LocalStore;
use std::collections::BTreeMap;

/// A concrete push source reference (store + target already resolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRef {
    /// Materialize the currently mapped local files; assign configured variants.
    Head,
    /// Restore a historical successful snapshot by index.
    Snapshot { target: TargetName, index: u64 },
    /// Assign each current server its configured variant from a named release.
    Release { release: ReleaseId },
}

/// A parsed push reference BEFORE store/target resolution.
///
/// The relative forms cannot be turned into a concrete [`PushRef`] without the
/// target's snapshot chain, so [`parse_ref_expr`] stops at this parsed form
/// and [`resolve_ref_expr`] finishes the job against the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefExpr {
    /// `""`, `HEAD`, `@`: materialize the currently mapped local files.
    Head,
    /// `release:<id>`: deploy the named release DIRECTLY to the current
    /// target's slots — no snapshot-chain stepping, no deployment-snapshot
    /// membership/binding checks. Resolves to [`PushRef::Release`] without
    /// touching the store.
    Release(ReleaseId),
    /// A jj-style relative reference needing the store + target.
    Relative(RelativeRef),
}

impl RefExpr {
    /// Whether this ref materializes the CURRENT local files (a HEAD push):
    /// the `HEAD`/`@` form directly, or `parent(@, 0)` — the base itself,
    /// which [`resolve_ref_expr`] folds to `PushRef::Head` the same way.
    ///
    /// The engine needs this BEFORE resolution (materialization only runs for
    /// HEAD pushes, and it happens before the post-reconciliation resolution
    /// point), so the `parent(@, 0)` special case is mirrored here; the two
    /// sites MUST stay in agreement.
    pub fn is_head_push(&self) -> bool {
        matches!(self, RefExpr::Head)
            || matches!(self, RefExpr::Relative(rel) if rel.base == RelBase::At && rel.steps == 0)
    }
}

/// A jj-style relative push reference: `@-`, `@--`, `parent(@, N)`,
/// `<refid>-`, `<refid>--`, `parent(<refid>, N)`, or the bare refid itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelativeRef {
    /// The chain position the ancestor steps walk back from.
    pub base: RelBase,
    /// How many ancestors to walk (1 for `@-`, 2 for `@--`; 0 = the base
    /// itself, e.g. the bare `s3` refid form).
    pub steps: u64,
}

/// The chain position a relative reference walks back from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelBase {
    /// `@`: the target's LATEST successful snapshot.
    At,
    /// `<refid>`: an explicit snapshot index, deployment id, or release id.
    Refid(RefId),
}

/// A refid primitive: a snapshot index, a deployment id, or a release id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefId {
    /// `s<K>`: a snapshot index.
    SnapshotIndex(u64),
    /// A deployment id (`deploy-...`): the most recent snapshot that deployed it.
    Deployment(String),
    /// A release id (`rel-sha256-...` or a bare digest): the most recent
    /// snapshot that references it.
    Release(String),
}

impl std::fmt::Display for RefId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefId::SnapshotIndex(k) => write!(f, "s{k}"),
            RefId::Deployment(s) | RefId::Release(s) => write!(f, "{s}"),
        }
    }
}

impl std::fmt::Display for RelativeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match &self.base {
            RelBase::At => "@".to_string(),
            RelBase::Refid(rid) => rid.to_string(),
        };
        match self.steps {
            0 => write!(f, "{id}"),
            1 => write!(f, "{id}-"),
            2 => write!(f, "{id}--"),
            n => write!(f, "parent({id}, {n})"),
        }
    }
}

impl std::fmt::Display for RefExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefExpr::Head => write!(f, "@"),
            RefExpr::Relative(rel) => write!(f, "{rel}"),
            RefExpr::Release(rid) => write!(f, "release:{rid}"),
        }
    }
}

/// Parse a push source reference token (the part after the target name),
/// WITHOUT touching the store: pure syntax, no `LocalStore` in scope.
///
/// The target is never part of the token: every relative form resolves
/// against the separately-given target argument at [`resolve_push_ref`] time.
/// The legacy combined forms — the target repeated inline before an `sN`
/// index, `release/<id>`, bare release-id, and the old `fN` index prefix —
/// are NOT accepted (they predate the jj-style grammar); they fail with an
/// explicit migration hint.
pub fn parse_ref_expr(token: &str) -> Result<RefExpr> {
    let t = token.trim();
    // HEAD / the default / `@` all mean the current state.
    if t.is_empty() || t == "HEAD" || t == "@" {
        return Ok(RefExpr::Head);
    }

    // `@-` / `@--`: the latest snapshot's parent / grandparent.
    if let Some(rest) = t.strip_prefix('@') {
        let steps = match rest {
            "-" => 1,
            "--" => 2,
            _ => {
                return Err(Error::r#ref(format!(
                    "unrecognized reference '{token}' (the only '@' forms are '@', '@-' and '@--')"
                )));
            }
        };
        return Ok(RefExpr::Relative(RelativeRef {
            base: RelBase::At,
            steps,
        }));
    }

    // `parent(<base>, <N>)`.
    if let Some(inner) = t.strip_prefix("parent(").and_then(|s| s.strip_suffix(')')) {
        let (base, n) = inner.split_once(',').ok_or_else(|| {
            Error::r#ref(format!(
                "malformed parent() reference '{token}' (expected 'parent(<ref>, N)')"
            ))
        })?;
        let steps: u64 = n
            .trim()
            .parse()
            .map_err(|_| Error::r#ref(format!("invalid ancestor step count in '{token}'")))?;
        let base_tok = base.trim();
        let base = if base_tok == "@" {
            RelBase::At
        } else if let Some(digits) = f_index_digits(base_tok) {
            return Err(Error::r#ref(format!(
                "legacy 'f{digits}' snapshot-index form is no longer accepted; use 's{digits}'"
            )));
        } else {
            RelBase::Refid(parse_ref_id(base_tok)?.ok_or_else(|| {
                Error::r#ref(format!(
                    "unrecognized reference id '{base_tok}' in '{token}'"
                ))
            })?)
        };
        return Ok(RefExpr::Relative(RelativeRef { base, steps }));
    }

    // `release:<id>` — the DIRECT release form (shell-safe: the token starts
    // with the literal `release:` prefix, no slash): deploy the named release
    // to the CURRENT target's slots from the release's OWN stored slot-variant
    // snapshot. The id may be a full `rel-sha256-...` id or a hex digest; it
    // needs no store lookup beyond shape validation (existence is verified at
    // plan time). This is distinct from the refid forms: `parent(<id>, N)` /
    // `<id>--` keep their SNAPSHOT-ANCESTRY semantics.
    if let Some(id) = t.strip_prefix("release:") {
        let valid = if let Some(rest) = id.strip_prefix("rel-sha256-") {
            !rest.is_empty()
        } else {
            !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit())
        };
        if !valid {
            return Err(Error::r#ref(format!(
                "unrecognized release id '{id}' in '{token}' \
                (expected 'release:<rel-sha256-...>' or 'release:<hex digest>')"
            )));
        }
        return Ok(RefExpr::Release(ReleaseId::parse(id)));
    }

    // The legacy combined form (the target repeated inline before an `sN`
    if t.contains('@') {
        return Err(Error::r#ref(format!(
            "unrecognized reference '{token}' (the target is passed once, on the command line: \
            the '@' forms are '@', '@-', '@--', and 'parent(@, N)')"
        )));
    }
    // The legacy `release/<id>` form is not accepted either.
    if let Some(_id) = t.strip_prefix("release/") {
        return Err(Error::r#ref(format!(
            "legacy 'release/<id>' reference '{token}' is no longer accepted; \
            use 'release:<id>' for the DIRECT release form, or reference the \
            release by its id as a refid ('parent(<id>, N)' / '<id>--') for \
            snapshot ancestry"
        )));
    }
    // The legacy `fN` snapshot-index form is not accepted (snapshot indices
    // are `sN` now).
    if let Some(digits) = f_index_digits(t) {
        return Err(Error::r#ref(format!(
            "legacy 'f{digits}' snapshot-index form is no longer accepted; use 's{digits}'"
        )));
    }

    // A `<refid>` with an optional trailing `-` / `--` ancestor suffix (1 or
    // 2 dashes), or the bare refid itself (0 steps, only meaningful for a
    // snapshot index or a deployment id — a bare release id is a legacy form).
    let dashes = t.len() - t.trim_end_matches('-').len();
    if dashes > 2 {
        return Err(Error::r#ref(format!(
            "unrecognized reference '{token}' (only '-' and '--' ancestor steps are accepted)"
        )));
    }
    let id = &t[..t.len() - dashes];
    if id.is_empty() {
        return Err(Error::r#ref(format!("unrecognized reference '{token}'")));
    }
    // The refid itself may be an `f<digits>` (legacy prefix) even when the
    // steps made the whole token something else (e.g. `f3--`).
    if let Some(digits) = f_index_digits(id) {
        return Err(Error::r#ref(format!(
            "legacy 'f{digits}' snapshot-index form is no longer accepted; use 's{digits}'"
        )));
    }
    if let Some(rid) = parse_ref_id(id)? {
        if dashes > 0 || matches!(rid, RefId::SnapshotIndex(_) | RefId::Deployment(_)) {
            return Ok(RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(rid),
                steps: dashes as u64,
            }));
        }
        return Err(Error::r#ref(format!(
            "legacy bare release id '{token}' is no longer accepted; \
            reference the release as 'parent(<id>, N)' or '<id>--'"
        )));
    }
    if t.starts_with("rel-sha256-") || (!t.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit())) {
        return Err(Error::r#ref(format!(
            "legacy bare release id '{token}' is no longer accepted; \
            reference the release as 'parent(<id>, N)' or '<id>--'"
        )));
    }
    Err(Error::r#ref(format!("unrecognized reference '{token}'")))
}

/// The `f<digits>` legacy snapshot-index prefix, if the string has it.
fn f_index_digits(s: &str) -> Option<&str> {
    let rest = s.strip_prefix('f')?;
    (!rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())).then_some(rest)
}

/// Parse a refid primitive. Ordering is by shape: a `s<digits>` token is a
/// snapshot index; a `deploy-...` token a deployment id; a `rel-sha256-...`
/// token or a bare hex digest a release id. The `f<digits>` legacy
/// snapshot-index prefix is REJECTED (never misread as a bare-hex release
/// digest — `f3` is hex); callers surface the specific "use sN" hint before
/// reaching here.
///
/// Returns `Ok(Some(rid))` for a recognized refid, `Ok(None)` for a shape
/// that is not a refid at all, and `Err` when an `s<digits>` index does not
/// fit a `u64` (e.g. `s999...` at magnitude 10^100). Overflow is a parse
/// error (`Error::r#ref`), NEVER a panic: the numeric conversion is mapped
/// to the error rather than unwrapped.
fn parse_ref_id(s: &str) -> Result<Option<RefId>> {
    // Legacy `f<digits>` snapshot-index prefix: never a release digest.
    if f_index_digits(s).is_some() {
        return Ok(None);
    }
    if let Some(digits) = s.strip_prefix('s')
        && !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_digit())
    {
        let index = digits
            .parse::<u64>()
            .map_err(|_| Error::r#ref(format!("snapshot index 's{digits}' out of range")))?;
        return Ok(Some(RefId::SnapshotIndex(index)));
    }
    if let Some(rest) = s.strip_prefix("deploy-")
        && !rest.is_empty()
    {
        return Ok(Some(RefId::Deployment(s.to_string())));
    }
    if let Some(rest) = s.strip_prefix("rel-sha256-")
        && !rest.is_empty()
    {
        return Ok(Some(RefId::Release(s.to_string())));
    }
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Some(RefId::Release(s.to_string())));
    }
    Ok(None)
}

/// Resolve a parsed [`RefExpr`] to a concrete [`PushRef`] against the
/// separately-given `target` and the target's snapshot chain in `store`.
///
/// Store-DEPENDENT (unlike [`parse_ref_expr`]): reads the target's snapshot
/// chain, so the caller must invoke it AFTER reconciliation has appended any
/// recovered snapshots — the engine parses the token up front but resolves
/// only once the chain is stable, so relative refs see the reconciled append.
/// The target is passed ONCE (the push argument); the relative forms never
/// repeat it. Failures are ref errors: an empty chain, an unresolvable
/// refid, and walking past the start of the chain all fail closed rather
/// than guessing.
pub fn resolve_ref_expr(expr: &RefExpr, target: &str, store: &LocalStore) -> Result<PushRef> {
    match expr {
        // `@` / `HEAD` / the default push: the current local files.
        RefExpr::Head => Ok(PushRef::Head),
        // The DIRECT release form: `release:<id>` maps straight to a
        // `PushRef::Release` — no snapshot-chain stepping, no target history
        // required (cross-target capable by design; the release's own stored
        // slot snapshot and the CURRENT target's slots are what the plan
        // resolves against).
        RefExpr::Release(release) => Ok(PushRef::Release {
            release: release.clone(),
        }),
        RefExpr::Relative(rel) => {
            // `parent(@, 0)` is the same as `@` itself: the current state.
            if rel.base == RelBase::At && rel.steps == 0 {
                return Ok(PushRef::Head);
            }
            let entries = store.read_snapshots(target)?;
            let base_index = resolve_base_index(&rel.base, target, &entries, expr)?;
            let index = base_index.checked_sub(rel.steps).ok_or_else(|| {
                Error::r#ref(format!(
                    "'{expr}' walks {} step(s) back from snapshot s{base_index} on target '{target}', \
                    before the start of the snapshot chain",
                    rel.steps
                ))
            })?;
            Ok(PushRef::Snapshot {
                target: TargetName::new(target.to_string()),
                index,
            })
        }
    }
}

/// Resolve a relative reference's base to a snapshot index in the chain.
/// `expr` renders the reference for error messages (the parsed form has no
/// raw token anymore).
fn resolve_base_index(
    base: &RelBase,
    target: &str,
    entries: &[DeploymentSnapshot],
    expr: &RefExpr,
) -> Result<u64> {
    let latest = entries.iter().map(|e| e.index).max();
    match base {
        RelBase::At => latest.ok_or_else(|| {
            Error::r#ref(format!(
                "no successful snapshots for target '{target}'; cannot resolve '{expr}'"
            ))
        }),
        RelBase::Refid(RefId::SnapshotIndex(k)) => {
            if entries.iter().any(|e| e.index == *k) {
                Ok(*k)
            } else {
                Err(Error::r#ref(format!(
                    "no snapshot s{k} for target '{target}'"
                )))
            }
        }
        RelBase::Refid(RefId::Deployment(id)) => entries
            .iter()
            .filter(|e| e.deployment_id.as_str() == id)
            .map(|e| e.index)
            .max()
            .ok_or_else(|| {
                Error::r#ref(format!(
                    "no successful snapshot for deployment '{id}' on target '{target}'"
                ))
            }),
        RelBase::Refid(RefId::Release(rid)) => {
            let want = ReleaseId::parse(rid);
            entries
                .iter()
                .filter(|e| snapshot_release(e) == want)
                .map(|e| e.index)
                .max()
                .ok_or_else(|| {
                    Error::r#ref(format!(
                        "no successful snapshot references release '{rid}' on target '{target}'"
                    ))
                })
        }
    }
}

/// The release a snapshot's generations came from (a coherent snapshot
/// carries one release across its slots).
fn snapshot_release(e: &DeploymentSnapshot) -> ReleaseId {
    e.slots
        .values()
        .next()
        .map(|g| g.assignment.artifact.release.clone())
        .unwrap_or_default()
}

/// Human-readable display name for a snapshot index, e.g.
/// `snapshot s1 of target production`.
pub fn ref_name(target: &TargetName, index: u64) -> String {
    format!("snapshot s{index} of target {}", target.as_str())
}

/// Ensure the snapshot log contains exactly one successful snapshot for
/// the attempt's deployment ID, and that `refs/last-successful` points at it.
/// Returns the snapshot's index.
///
/// This is the single idempotent insert used by BOTH the main success path
/// and recovery finalization, and it is replay-safe:
///
/// * If a snapshot with `deployment_id == attempt.deployment_id` already
///   exists (a previous finalization crashed after appending the snapshot but
///   before finishing), no second snapshot is appended: the existing
///   snapshot's index is returned. The log never contains two snapshots for
///   the same deployment ID.
/// * `refs/last-successful` is (re)written to the attempt's deployment ID in
///   both cases — idempotent, the same value on every replay — which also
///   repairs the stale ref left by a crash between the snapshot append and
///   the ref update.
///
/// The snapshot is built from the attempt's OUTCOMES (`outcomes`: the
/// per-slot actual state the engine observed — results.json on the main path,
/// or the verified desired state during recovery), NOT from the attempt
/// record itself: the persisted attempt is the immutable intent and its
/// `slots` map is empty.
pub fn ensure_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<u64> {
    let target = target.as_str();
    let entries = store.read_snapshots(target)?;
    if let Some(existing) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
    {
        store.write_last_successful(target, attempt.deployment_id.as_str())?;
        return Ok(existing.index);
    }
    let next = entries.len() as u64;
    let entry = build_snapshot(next, attempt, outcomes, bindings);
    store.append_snapshot(target, &entry)?;
    store.write_last_successful(target, attempt.deployment_id.as_str())?;
    Ok(next)
}

/// Append a successful snapshot to the snapshot log and return its
/// index.
///
/// Idempotent by deployment ID: delegates to
/// [`ensure_snapshot`], so re-running finalization for the same
/// attempt never duplicates the snapshot and always repairs
/// `refs/last-successful`. Kept as the historical name; the main success
/// path now finalizes through the shared
/// [`finalize_successful_attempt`], which calls this. The snapshot is built
/// from the attempt's OUTCOMES map, not the attempt record (see
/// [`ensure_snapshot`]).
pub fn append_snapshot(
    store: &LocalStore,
    target: &TargetName,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<u64> {
    ensure_snapshot(store, target, attempt, outcomes, bindings)
}

/// Finalize a successful deployment attempt replay-safely: the single shared
/// terminal path used by BOTH the normal push success path and recovery
/// ([`crate::push::reconcile::reconcile_pending_commits`]).
///
/// The snapshot is built from the attempt's OUTCOMES (`outcomes`: per-slot
/// actual state observed by the engine — live actuals on the main path,
/// results.json or the verified desired state during recovery), never from
/// the attempt record itself (the persisted attempt is the immutable intent;
/// its `slots` map is empty).
///
/// Persistence order:
/// 1. RECOVERABLE MARKER: ensure the attempt's LATEST transition is
///    `PendingCommit`, appending a `PendingCommit` transition (reason
///    "finalization started") only when the latest is not already
///    `PendingCommit`. The latest transition is recovery's eligibility
///    gate, so a crash at any later point leaves the attempt re-eligible and
///    the next push replays exactly the remaining steps. On the main path the
///    attempt's latest is `InProgress` here (this appends `PendingCommit`);
///    in recovery it is already `PendingCommit` (a no-op).
/// 2. SNAPSHOT + REF: [`ensure_snapshot`] — idempotent by deployment ID (a
///    replay never appends a second entry) and (re)writes
///    `refs/last-successful`, repairing a stale ref left by a crash between
///    the snapshot append and the ref update.
/// 3. STATUS LAST: append the terminal `Successful` transition with `reason`
///    only after every durable step, so the attempt is never recorded
///    `Successful` while its snapshot is missing.
///
/// Replay idempotency: step 1 is skipped when the latest transition is
/// already `PendingCommit`; step 2 is a no-op (or ref repair) when the
/// snapshot entry already exists; step 3 appends exactly once — a crash
/// before it leaves the attempt eligible, and a crash after it means every
/// earlier step is already durable (and the eligibility gate skips the
/// attempt forever once the latest transition says `Successful`).
///
/// Returns the attempt's snapshot index.
pub fn finalize_successful_attempt(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    reason: &str,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> Result<u64> {
    let id = attempt.deployment_id.as_str();
    // Already fully finalized (the eligibility gate normally prevents this):
    // every earlier step is durable by construction; only repair a stale
    // `refs/last-successful` and stop without appending anything.
    if store.latest_status(id)? == Some(DeploymentStatus::Successful) {
        return ensure_snapshot(store, &attempt.target, attempt, outcomes, bindings);
    }
    // 1. Recoverable marker: the attempt must be re-eligible if we crash
    //    before the snapshot lands.
    if store.latest_status(id)? != Some(DeploymentStatus::PendingCommit) {
        store.append_transition(
            id,
            &DeploymentStatus::PendingCommit,
            Some("finalization started"),
        )?;
    }
    // 2. Snapshot entry + `refs/last-successful` (idempotent).
    let idx = ensure_snapshot(store, &attempt.target, attempt, outcomes, bindings)?;
    // 3. Terminal status LAST.
    store.append_transition(id, &DeploymentStatus::Successful, Some(reason))?;
    Ok(idx)
}

/// Resolve the per-slot outcomes used to build a successful snapshot
/// when the engine no longer has the live outcomes at hand (recovery): the
/// persisted results (`deployments/<id>/results.json`) when present — a
/// crash after the mutation loop but before/within finalization — otherwise
/// the attempt's verified desired state (a crash before outcomes were
/// persisted, e.g. a faulted `write_results`).
///
/// The per-slot ARTIFACT always resolves from the attempt's desired
/// assignment: results.json records outcomes (generation, status) but not
/// artifacts, and recovery already verified each slot's current generation
/// equals the desired generation. Slots without a recorded generation are
/// not part of a coherent successful snapshot and are dropped by
/// [`build_snapshot`].
pub fn resolve_attempt_outcomes(
    store: &LocalStore,
    attempt: &DeploymentAttempt,
) -> Result<BTreeMap<PlacementSlotId, AttemptServer>> {
    // `read_results` fails when `results.json` is absent (crash before the
    // outcomes were persisted); treat that as "verified desired state only".
    let results = store.read_results(attempt.deployment_id.as_str()).ok();
    let mut outcomes = BTreeMap::new();
    for sid in &attempt.slot_ids {
        let Some(desired) = attempt.desired.get(sid) else {
            continue;
        };
        let generation = results
            .as_ref()
            .and_then(|r| r.slots.get(sid).and_then(|sr| sr.generation.clone()))
            .or_else(|| Some(desired.generation.clone()));
        outcomes.insert(
            sid.clone(),
            AttemptServer {
                artifact: desired.assignment.artifact.clone(),
                generation,
            },
        );
    }
    Ok(outcomes)
}

/// Build a snapshot entry from the attempt's OUTCOMES (per-slot actual
/// state), not from the attempt record: the persisted attempt is the
/// immutable intent (its `slots` map is empty), so the snapshot must be
/// built from the outcomes the engine observed — live per-slot actuals on
/// the main path, or results.json / the verified desired state during
/// recovery ([`resolve_attempt_outcomes`]). A successful snapshot
/// carries one complete [`GenerationRef`] per slot; slots without a
/// recorded generation are not part of a coherent successful snapshot and
/// are dropped.
///
/// `bindings` records the COMPLETE physical binding (`{server, deploy_dir}`)
/// each slot had when the deployment ran (the engine passes the target's
/// current slot→binding map from `deploy.toml`). It is stored as a separate
/// map so the `slots` map and its [`GenerationRef`]s stay intact; a legacy
/// entry with no bindings map deserializes to an empty one (unverifiable,
/// so rollback refuses rather than guessing the host/location).
pub fn build_snapshot(
    index: u64,
    attempt: &DeploymentAttempt,
    outcomes: &BTreeMap<PlacementSlotId, AttemptServer>,
    bindings: &BTreeMap<PlacementSlotId, PhysicalBinding>,
) -> DeploymentSnapshot {
    DeploymentSnapshot {
        index,
        deployment_id: attempt.deployment_id.clone(),
        target: attempt.target.clone(),
        behavior_sha256: attempt.behavior_sha256.clone(),
        slots: outcomes
            .iter()
            .filter_map(|(slot, s)| {
                s.generation.clone().map(|generation| {
                    (
                        slot.clone(),
                        GenerationRef {
                            generation,
                            assignment: PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: s.artifact.clone(),
                            },
                        },
                    )
                })
            })
            .collect(),
        bindings: bindings.clone(),
    }
}

/// Resolve a snapshot index to its entry.
pub fn resolve_snapshot(
    store: &LocalStore,
    target: &TargetName,
    index: u64,
) -> Result<DeploymentSnapshot> {
    let target = target.as_str();
    let entries = store.read_snapshots(target)?;
    entries
        .into_iter()
        .find(|e| e.index == index)
        .ok_or_else(|| Error::r#ref(format!("no snapshot s{index} for target '{target}'")))
}

/// Reconstruct the set of successful deployments for a target from the
/// snapshot log (used to rebuild history from servers when the local ref is
/// stale).
pub fn successful_snapshots(
    store: &LocalStore,
    target: &TargetName,
) -> Result<Vec<DeploymentSnapshot>> {
    store.read_snapshots(target.as_str())
}

/// Collect the distinct placement slot IDs referenced across a set of attempts.
pub fn attempt_slot_ids(attempt: &DeploymentAttempt) -> Vec<PlacementSlotId> {
    attempt.slot_ids.clone()
}

/// Build a map of snapshot display names (`snapshot sN of target <target>`)
/// -> snapshot.
pub fn snapshot_index(
    store: &LocalStore,
    target: &TargetName,
) -> Result<BTreeMap<String, DeploymentSnapshot>> {
    let mut out = BTreeMap::new();
    for e in store.read_snapshots(target.as_str())? {
        out.insert(ref_name(target, e.index), e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactRef, DeploymentId, GenerationId, PlacementSlotId, ReleaseId, SCHEMA_VERSION,
        ServerId, TreeDigest, VariantName,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;

    #[test]
    fn parse_ref_head_forms() {
        // The empty form, `HEAD`, and `@` all mean the current local files
        // (the default push). Parsing is STORE-FREE: no `LocalStore` exists
        // in this test, so a parse cannot touch the store by construction.
        for token in ["", "HEAD", "@"] {
            assert_eq!(
                parse_ref_expr(token).unwrap(),
                RefExpr::Head,
                "{token:?} must parse to Head"
            );
        }
    }

    /// Every jj-style relative form parses WITHOUT touching the store:
    /// `@-` / `@--` / `parent(@, N)` walk back from the latest snapshot;
    /// `<refid>-`, `<refid>--`, `parent(<refid>, N)`, and the bare refid
    /// itself walk back from a snapshot index, deployment id, or release id.
    #[test]
    fn parse_ref_relative_forms() {
        let rel = |token: &str| parse_ref_expr(token).unwrap();
        assert_eq!(
            rel("@-"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::At,
                steps: 1
            })
        );
        assert_eq!(
            rel("@--"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::At,
                steps: 2
            })
        );
        assert_eq!(
            rel("parent(@, 3)"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::At,
                steps: 3
            })
        );
        assert_eq!(
            rel("s3--"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(RefId::SnapshotIndex(3)),
                steps: 2
            })
        );
        assert_eq!(
            rel("parent(s5, 2)"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(RefId::SnapshotIndex(5)),
                steps: 2
            })
        );
        assert_eq!(
            rel("s1"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(RefId::SnapshotIndex(1)),
                steps: 0
            })
        );
        assert_eq!(
            rel("deploy-abc123--"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(RefId::Deployment("deploy-abc123".to_string())),
                steps: 2
            })
        );
        assert_eq!(
            rel("parent(rel-sha256-deadbeef, 1)"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(RefId::Release("rel-sha256-deadbeef".to_string())),
                steps: 1
            })
        );
        // An abbreviated digest is a release refid too.
        assert_eq!(
            rel("parent(deadbeef, 2)"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(RefId::Release("deadbeef".to_string())),
                steps: 2
            })
        );
        // N = 0 means the base itself.
        assert_eq!(
            rel("parent(@, 0)"),
            RefExpr::Relative(RelativeRef {
                base: RelBase::At,
                steps: 0
            })
        );
    }

    /// `release:<id>` parses to a DIRECT release form — a full
    /// `rel-sha256-...` id or a bare hex digest — WITHOUT touching the store,
    /// and is distinct from the refid forms (`parent(<id>, N)`, `<id>--`)
    /// which keep snapshot-ancestry semantics.
    #[test]
    fn parse_ref_direct_release_form() {
        assert_eq!(
            parse_ref_expr("release:rel-sha256-deadbeef").unwrap(),
            RefExpr::Release(ReleaseId::new("rel-sha256-deadbeef".to_string()))
        );
        // A bare digest is normalized to the full `rel-sha256-` id.
        assert_eq!(
            parse_ref_expr("release:deadbeef").unwrap(),
            RefExpr::Release(ReleaseId::new("rel-sha256-deadbeef".to_string()))
        );
        // The refid forms STILL parse as snapshot ancestry.
        assert!(matches!(
            parse_ref_expr("rel-sha256-deadbeef--").unwrap(),
            RefExpr::Relative(_)
        ));
        assert!(matches!(
            parse_ref_expr("parent(rel-sha256-deadbeef, 1)").unwrap(),
            RefExpr::Relative(_)
        ));
    }

    /// The legacy grammar is REJECTED with a ref error, never silently
    /// re-mapped: the target repeated inline before an `sN` index,
    /// `release/<id>`, bare release ids, the old `fN` snapshot-index prefix,
    /// `:current`, and malformed relatives.
    #[test]
    fn parse_ref_rejects_legacy_forms() {
        for token in [
            "production@s0",
            "@s0",
            "release/rel-sha256-x",
            "rel-sha256-x",
            "deadbeef",
            "release:",
            "release:rel-sha256-",
            "release:not-hex",
            "release:has/dash",
            "f3",
            "f3--",
            "parent(f5, 2)",
            "HEAD:current",
            "@-:current",
            "@@",
            "@---",
            "parent(@, x)",
            "parent(@, -1)",
            "parent(@",
            "s3---",
            "--",
        ] {
            let err = parse_ref_expr(token).expect_err(&format!("{token:?} must be rejected"));
            assert!(
                err.to_string().contains("reference"),
                "error for {token:?} must be a ref error, got: {err}"
            );
        }
    }

    /// Build a store whose target `production` has the chain s0..s5
    /// (deployments deploy-a..deploy-f; the s2 and s3 snapshots BOTH carry
    /// release rel-sha256-cccc, so the "most recent" release resolution is
    /// exercised).
    fn chain() -> (tempfile::TempDir, LocalStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        for (i, (dep, rel)) in [
            ("deploy-a", "aaaa"),
            ("deploy-b", "bbbb"),
            ("deploy-c", "cccc"),
            ("deploy-d", "cccc"),
            ("deploy-e", "eeee"),
            ("deploy-f", "ffff"),
        ]
        .iter()
        .enumerate()
        {
            store
                .append_snapshot("production", &snapshot_entry(i as u64, dep, rel))
                .unwrap();
        }
        (tmp, store)
    }

    fn snapshot_entry(index: u64, deployment: &str, release: &str) -> DeploymentSnapshot {
        DeploymentSnapshot {
            index,
            deployment_id: DeploymentId::new(deployment.to_string()),
            target: TargetName::new("production".to_string()),
            behavior_sha256: "sha256-aa".to_string(),
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new(format!("gen-{index}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new(format!("rel-sha256-{release}")),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new(format!("tree-{index}")),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::new(),
        }
    }

    fn snap(target: &TargetName, index: u64) -> PushRef {
        PushRef::Snapshot {
            target: target.clone(),
            index,
        }
    }

    /// Parse-then-resolve a token against the store, mirroring the engine's
    /// two-phase flow (parse first, resolve later).
    fn resolve(token: &str, store: &LocalStore) -> Result<PushRef> {
        resolve_ref_expr(&parse_ref_expr(token)?, "production", store)
    }

    /// `@` / `HEAD` / `` / `parent(@, 0)` resolve to the default HEAD push.
    #[test]
    fn resolve_ref_head_forms() {
        let (_tmp, store) = chain();
        for token in ["", "HEAD", "@", "parent(@, 0)"] {
            assert_eq!(
                resolve(token, &store).unwrap(),
                PushRef::Head,
                "{token:?} must resolve to Head"
            );
        }
    }

    /// The ancestor steps on the s0..s5 chain (latest = s5): `@-` = s4,
    /// `@--` = s3, `parent(@, 3)` = s2, `s3--` = s1, `parent(s5, 2)` = s3,
    /// `s1-` = s0, and the bare `s1` / `parent(s1, 0)` forms name s1 itself.
    #[test]
    fn resolve_ref_ancestor_steps() {
        let (_tmp, store) = chain();
        let target = TargetName::new("production".to_string());
        for (token, want) in [
            ("@-", 4u64),
            ("@--", 3),
            ("parent(@, 3)", 2),
            ("parent(@, 2)", 3),
            ("s3--", 1),
            ("parent(s5, 2)", 3),
            ("s1-", 0),
            ("s1", 1),
            ("parent(s1, 0)", 1),
            ("parent(s2, 1)", 1),
        ] {
            assert_eq!(
                resolve(token, &store).unwrap(),
                snap(&target, want),
                "{token} must resolve to index {want}"
            );
        }
    }

    /// A deployment refid resolves to the snapshot that deployed it (most
    /// recent); a release refid to the most recent snapshot referencing the
    /// release — then the ancestor steps walk from there.
    #[test]
    fn resolve_ref_deployment_and_release_refids() {
        let (_tmp, store) = chain();
        let target = TargetName::new("production".to_string());
        // deploy-b deployed s1.
        assert_eq!(resolve("deploy-b-", &store).unwrap(), snap(&target, 0));
        assert_eq!(
            resolve("parent(deploy-b, 1)", &store).unwrap(),
            snap(&target, 0)
        );
        assert_eq!(
            resolve("parent(deploy-c, 0)", &store).unwrap(),
            snap(&target, 2)
        );
        // rel-sha256-cccc is referenced by BOTH s2 and s3; the most recent
        // (s3) wins, then the ancestor steps apply.
        assert_eq!(
            resolve("parent(rel-sha256-cccc, 0)", &store).unwrap(),
            snap(&target, 3)
        );
        assert_eq!(
            resolve("rel-sha256-cccc-", &store).unwrap(),
            snap(&target, 2)
        );
        assert_eq!(
            resolve("parent(rel-sha256-cccc, 2)", &store).unwrap(),
            snap(&target, 1)
        );
        // Abbreviated digest form resolves the same release.
        assert_eq!(
            resolve("parent(cccc, 0)", &store).unwrap(),
            snap(&target, 3)
        );
    }

    /// `release:<id>` resolves DIRECTLY to a `PushRef::Release` — with NO
    /// store lookup and NO target snapshot history: the bare release id never
    /// steps the deployment-snapshot chain, so a cross-target / fresh-target
    /// direct deployment is expressible even when the destination has zero
    /// snapshots. This is the grammar's escape hatch for
    /// direct/cross-target release deployment.
    #[test]
    fn resolve_ref_direct_release_form_ignores_chain_and_store() {
        let (_tmp, store) = chain();
        // Even though `rel-sha256-cccc` IS referenced by snapshots in this
        // chain, `release:` yields the bare release ref, not a snapshot.
        assert_eq!(
            resolve_push_ref("release:rel-sha256-cccc", "production", &store).unwrap(),
            PushRef::Release {
                release: ReleaseId::new("rel-sha256-cccc".to_string())
            }
        );
        assert_eq!(
            resolve_push_ref("release:cccc", "production", &store).unwrap(),
            PushRef::Release {
                release: ReleaseId::new("rel-sha256-cccc".to_string())
            }
        );
        // A release that is NOT referenced by any snapshot — and a target
        // with an EMPTY chain — resolve the same way: resolution never reads
        // the store.
        let tmp = tempfile::tempdir().unwrap();
        let empty = LocalStore::with_base(tmp.path().join("store")).unwrap();
        assert_eq!(
            resolve_push_ref("release:rel-sha256-zzzz", "brand-new-target", &empty).unwrap(),
            PushRef::Release {
                release: ReleaseId::new("rel-sha256-zzzz".to_string())
            }
        );
        // The refid form on the same empty chain still fails closed (it
        // needs a snapshot that references the release).
        resolve_push_ref("parent(rel-sha256-zzzz, 0)", "brand-new-target", &empty)
            .expect_err("the refid form needs snapshot ancestry and must fail on an empty chain");
    }

    /// Out-of-range and unresolvable references fail closed with a ref
    /// error: stepping before the chain start, a missing snapshot index, an
    /// unknown deployment/release, and an EMPTY chain. Never underflow,
    /// never guess.
    #[test]
    fn resolve_ref_failures_fail_closed() {
        let (_tmp, store) = chain();
        for token in [
            "parent(@, 6)", // s5 - 6 underflows
            "s0-",
            "s0--",
            "parent(s1, 2)",
            "s9",
            "parent(s9, 0)",
            "deploy-missing-",
            "parent(deploy-missing, 1)",
            "parent(rel-sha256-zzzz, 0)",
        ] {
            let err = resolve(token, &store).expect_err(&format!("{token} must fail closed"));
            assert!(
                err.to_string().contains("reference") || err.to_string().contains("step(s) back"),
                "{token} error must be a ref error, got: {err}"
            );
        }

        // An EMPTY target chain: `@` is still fine (HEAD), every relative
        // form fails.
        let tmp = tempfile::tempdir().unwrap();
        let empty = LocalStore::with_base(tmp.path().join("store")).unwrap();
        assert_eq!(resolve("@", &empty).unwrap(), PushRef::Head);
        for token in ["@-", "parent(@, 2)", "s0", "deploy-x-"] {
            resolve(token, &empty).expect_err(&format!("{token} on an empty chain must fail"));
        }
    }

    #[test]
    fn ref_name_index() {
        assert_eq!(
            ref_name(&TargetName::new("production".to_string()), 3),
            "snapshot s3 of target production"
        );
    }

    #[test]
    fn append_snapshot_is_idempotent_by_deployment_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::new("production".to_string());
        let bindings: BTreeMap<PlacementSlotId, PhysicalBinding> = BTreeMap::from([(
            PlacementSlotId::new("p1"),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);
        let attempt = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-idempotent".to_string()),
            target: target.clone(),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // First call appends the snapshot and advances the ref. The snapshot
        // is built from the attempt's OUTCOMES map (the attempt record
        // itself carries only intent; its `slots` map is empty), and records
        // the slot→{server, deploy_dir} binding from `bindings`.
        let first = append_snapshot(&store, &target, &attempt, &attempt.slots, &bindings).unwrap();
        assert_eq!(first, 0);
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, attempt.deployment_id);
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );

        // Second call with the same deployment ID is a no-op: same index, no
        // duplicate entry, and `refs/last-successful` is untouched.
        let second = append_snapshot(&store, &target, &attempt, &attempt.slots, &bindings).unwrap();
        assert_eq!(second, first, "repeated append must return the same index");
        let snapshots = store.read_snapshots(target.as_str()).unwrap();
        assert_eq!(snapshots.len(), 1, "no duplicate snapshot entry");
        assert_eq!(
            store.read_last_successful(target.as_str()).as_deref(),
            Some("deploy-idempotent")
        );
    }

    #[test]
    fn build_snapshot_records_each_slots_physical_binding() {
        let slot = PlacementSlotId::new("p1".to_string());
        let attempt = DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-binding-map".to_string()),
            target: TargetName::new("production".to_string()),
            slot_ids: vec![slot.clone()],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::from([(
                slot.clone(),
                crate::records::AttemptServer {
                    artifact: ArtifactRef::default(),
                    generation: Some(GenerationId::new("gen-x".to_string())),
                },
            )]),
        };
        let bindings: BTreeMap<PlacementSlotId, PhysicalBinding> = BTreeMap::from([(
            slot.clone(),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);

        let snapshot = build_snapshot(3, &attempt, &attempt.slots, &bindings);
        assert_eq!(
            snapshot.bindings.get(&slot),
            Some(&PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            }),
            "the snapshot must record the slot's complete physical binding (server AND deploy_dir)"
        );
        assert_eq!(snapshot.slots.len(), 1, "generation refs preserved intact");
        assert_eq!(snapshot.bindings.len(), 1);
    }

    /// A legacy pre-feature snapshot line (no `bindings` key — either the
    /// oldest pre-binding shape or the intermediate shape that only recorded
    /// a `servers` map) must still deserialize; its `bindings` map defaults
    /// to empty, which rollback treats as unverifiable rather than guessing
    /// the host/location.
    #[test]
    fn legacy_snapshot_without_bindings_deserializes_with_empty_map() {
        // Oldest shape: no binding recorded at all.
        let bare = r#"{"index":0,"deployment_id":"deploy-old","target":"production","behavior_sha256":"sha256-aa","slots":{}}"#;
        let snapshot: DeploymentSnapshot = serde_json::from_str(bare).unwrap();
        assert!(
            snapshot.bindings.is_empty(),
            "legacy line without bindings yields an empty map"
        );

        // Intermediate server-only shape: the `servers` key is an unknown
        // field now (the physical binding is richer than a bare ServerId),
        // so it is ignored and `bindings` still defaults to empty →
        // fail-closed refusal.
        let with_servers = r#"{"index":1,"deployment_id":"deploy-old-servers","target":"production","behavior_sha256":"sha256-aa","slots":{},"servers":{"p1":"server-01"}}"#;
        let snapshot: DeploymentSnapshot = serde_json::from_str(with_servers).unwrap();
        assert!(
            snapshot.bindings.is_empty(),
            "old `servers`-keyed line yields an empty bindings map"
        );
    }

    /// Run the parser under `catch_unwind`: a panicking parse turns into a
    /// test failure at the `.expect`, so the property can assert BOTH that
    /// no input ever panics AND that the result has the expected shape.
    /// `parse_ref_expr` is a plain fn with no interior mutability, so the
    /// closure is `UnwindSafe` (it captures only a `&str`).
    fn parse_no_panic(token: &str) -> Result<RefExpr> {
        std::panic::catch_unwind(|| parse_ref_expr(token)).expect("parse_ref_expr must never panic")
    }

    // PROPERTY: no reference token, however huge its snapshot index or
    // ancestor count, may panic the parser, and any index/count that does
    // not fit a `u64` must be a ref error — never a silently valid parse.
    //
    // The generated digits are 100 chars with a nonzero lead (magnitude
    // >= 10^99, far beyond `u64::MAX` ~ 1.8*10^19), covering `sN`, the
    // dash forms `sN-` / `sN--`, and `parent(sN, M)` with a huge `N`, a
    // huge `M`, and both. Boundary cases pin `u64::MAX` exactly (the
    // largest VALID index) against `u64::MAX + 1` (the smallest overflow).
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            rng_seed: RngSeed::Fixed(0x0F10_0F10),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn oversized_snapshot_indices_are_errors_never_panics(huge in "[1-9][0-9]{99}") {
            // `sN`, `sN-`, `sN--`: the index itself overflows. The error must
            // be the snapshot-index out-of-range ref error, not a panic and
            // not a silently valid parse.
            for token in [
                format!("s{huge}"),
                format!("s{huge}-"),
                format!("s{huge}--"),
            ] {
                let err = parse_no_panic(&token)
                    .expect_err(&format!("oversized index '{token}' must be a ref error"));
                assert!(
                    err.to_string().contains("out of range"),
                    "error for '{token}' must report the out-of-range index, got: {err}"
                );
            }

            // `parent(sN, M)` with a huge N (M itself small and valid).
            for m in ["0", "1", "2"] {
                let token = format!("parent(s{huge}, {m})");
                let err = parse_no_panic(&token)
                    .expect_err(&format!("oversized base index '{token}' must be a ref error"));
                assert!(
                    err.to_string().contains("out of range"),
                    "error for '{token}' must report the out-of-range index, got: {err}"
                );
            }

            // `parent(sN, M)` with a huge M (and huge M AND huge N: M is
            // parsed first, so it reports the ancestor-count error).
            for token in [
                format!("parent(s1, {huge})"),
                format!("parent(s{huge}, {huge})"),
            ] {
                let err = parse_no_panic(&token)
                    .expect_err(&format!("oversized ancestor count '{token}' must be a ref error"));
                assert!(
                    err.to_string().contains("invalid ancestor step count"),
                    "error for '{token}' must report the bad ancestor count, got: {err}"
                );
            }

            // Boundary: `u64::MAX` exactly is the largest VALID snapshot
            // index; `u64::MAX + 1` overflows and is a ref error.
            let max = u64::MAX.to_string();
            assert_eq!(
                parse_no_panic(&format!("s{max}")).unwrap(),
                RefExpr::Relative(RelativeRef {
                    base: RelBase::Refid(RefId::SnapshotIndex(u64::MAX)),
                    steps: 0,
                }),
            );
            let over = (u64::MAX as u128 + 1).to_string();
            for token in [format!("s{over}"), format!("parent(s{over}, 1)")] {
                let err = parse_no_panic(&token)
                    .expect_err(&format!("u64::MAX + 1 index '{token}' must be a ref error"));
                assert!(
                    err.to_string().contains("out of range"),
                    "error for '{token}' must report the out-of-range index, got: {err}"
                );
            }
        }
    }
}

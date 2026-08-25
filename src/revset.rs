//! The push reference LANGUAGE: a pure, store-free grammar over reference
//! tokens (`@`, `@-`, `@--`, `parent(...)`, direct ids, ...). The module
//! owns ONLY the syntax — its [`parse_ref_expr`] returns an AST
//! ([`RefExpr`]) with no `LocalStore` in scope and no resolution; the
//! store-dependent resolution that FOLLOWS the AST lives in
//! [`crate::history::resolve_ref_expr`].
//!
//! The push reference is jj-style: the TARGET IS NEVER REPEATED in the
//! reference, and the `@`-relative forms resolve against the separately-given
//! target argument. Resolution is a TWO-PHASE process:
//!
//! * [`parse_ref_expr`] (this module) turns the token into a structured
//!   [`RefExpr`] with NO store access — pure syntax. The engine parses the
//!   token BEFORE it acquires locks or persists anything, so a malformed
//!   token fails before any side effect and the deployment id/plan are never
//!   serialized against a half-parsed reference.
//! * [`crate::history::resolve_ref_expr`] turns the parsed expression into a
//!   concrete [`crate::history::PushRef`] against the target's snapshot
//!   chain in the store.
//!
//! The accepted forms are:
//!
//! * `` (empty), `HEAD`, `@` — the current local files (the default).
//! * `@-`, `@--` — the snapshot BEFORE the latest, the grandparent.
//! * `parent(@, N)` — the Nth ancestor of the latest snapshot.
//! * `release:<id>` — the DIRECT release form: deploy the named release to
//!   the CURRENT target's slots as they are, from the release's OWN stored
//!   slot-variant snapshot — but ONLY when the target's CURRENT slot-id
//!   membership EXACTLY equals the slot set the release record froze for
//!   that target (membership drift is refused at plan time, before any
//!   remote access; physical bindings are intentionally not compared).
//!   No snapshot-chain stepping: cross-target capable —
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
//!
//! The legacy combined forms — the target repeated inline before an `sN`
//! index, `release/<id>`, bare release-id, and the old `fN` index prefix —
//! are NOT accepted (they predate the jj-style grammar); they fail with an
//! explicit migration hint.

use crate::error::{Error, Result};
use crate::model::ReleaseId;
/// A parsed push reference BEFORE store/target resolution.
///
/// The relative forms cannot be turned into a concrete [`PushRef`] without the
/// target's snapshot chain, so [`parse_ref_expr`] stops at this parsed form
/// and [`resolve_ref_expr`] finishes the job against the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RefExpr {
    /// `""`, `HEAD`, `@`: materialize the currently mapped local files.
    Head,
    /// `release:<id>`: deploy the named release DIRECTLY to the current
    /// target's slots — no snapshot-chain stepping, no deployment-snapshot
    /// exact-binding checks. The target's CURRENT slot-id membership must
    /// EXACTLY match the slot set the release's OWN stored slot snapshot
    /// froze for it (checked at plan time, before any remote access);
    /// physical bindings are intentionally not compared. Resolves to
    /// [`PushRef::Release`] without touching the store.
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
pub(crate) struct RelativeRef {
    /// The chain position the ancestor steps walk back from.
    pub base: RelBase,
    /// How many ancestors to walk (1 for `@-`, 2 for `@--`; 0 = the base
    /// itself, e.g. the bare `s3` refid form).
    pub steps: u64,
}

/// The chain position a relative reference walks back from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelBase {
    /// `@`: the target's LATEST successful snapshot.
    At,
    /// `<refid>`: an explicit snapshot index, deployment id, or release id.
    Refid(RefId),
}

/// A refid primitive: a snapshot index, a deployment id, or a release id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RefId {
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
            // A bare release id (`rel-sha256-...` or a bare digest) is a
            // LEGACY form the parser REJECTS, so a 0-step release refid must
            // render as `parent(<id>, 0)` — every string `Display` prints
            // must be re-parseable (the canonical round-trip). The `At` base
            // keeps the bare `@` form: the documented fold
            // `parent(@, 0) ≡ @` makes `@` the canonical rendering.
            0 if matches!(self.base, RelBase::Refid(RefId::Release(_))) => {
                write!(f, "parent({id}, 0)")
            }
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
pub(crate) fn parse_ref_expr(token: &str) -> Result<RefExpr> {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

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

    /// Run the parser under `catch_unwind`: a panicking parse turns into a
    /// test failure at the `.expect`, so the property can assert BOTH that
    /// no input ever panics AND that the result has the expected shape.
    /// `parse_ref_expr` is a plain fn with no interior mutability, so the
    /// closure is `UnwindSafe` (it captures only a `&str`).
    // Shared with the history.rs resolve-leg tests (the resolve contract
    // runs the same grammar universe and the same canonical fold against a
    // seeded store), so they are `pub(crate)` inside the test module.
    pub(crate) fn parse_no_panic(token: &str) -> Result<RefExpr> {
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

    // -------------------------------------------------------------------
    // Ref-grammar property suite (parse leg)
    // -------------------------------------------------------------------

    /// One of the ancestor-count / snapshot-index magnitudes the grammar
    /// must accept or reject by fit: the small steps {0,1,2,3}, exactly
    /// `u64::MAX` (the largest VALID count/index), `u64::MAX + 1` (the
    /// smallest overflow — a ref error, never a panic), and a 100-digit
    /// string (magnitude ~10^99, far beyond `u64`).
    fn big_num() -> impl Strategy<Value = String> {
        prop_oneof![
            "0".prop_map(String::from),
            "1".prop_map(String::from),
            "2".prop_map(String::from),
            "3".prop_map(String::from),
            Just(u64::MAX.to_string()),
            Just((u64::MAX as u128 + 1).to_string()),
            "[1-9][0-9]{99}".prop_map(String::from),
        ]
    }

    /// A deployment-id refid (`deploy-<id>`).
    fn dep_id() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{0,7}".prop_map(|s| format!("deploy-{s}"))
    }

    /// A release refid: a full `rel-sha256-<hex>` id or a bare hex digest.
    /// The digest is at least 4 chars so it can never collide with the
    /// legacy `f<digits>` prefix (e.g. `f3a4` has a non-digit tail).
    fn rel_id() -> impl Strategy<Value = String> {
        prop_oneof![
            "[0-9a-f]{4,16}".prop_map(|h| format!("rel-sha256-{h}")),
            "[0-9a-f]{4,16}".prop_map(String::from),
        ]
    }

    /// Junk: arbitrary strings over the grammar's alphabet (alnum; the
    /// punctuation `- @ ( ) , : space { }`; the `s f rel- deploy-` shapes
    /// are covered by the char pool) plus unicode, length 0..30. Any of it
    /// may parse or not; the contract is that it NEVER panics and every
    /// failure is a ref error.
    fn junk_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                prop::sample::select(&[
                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                    'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
                    'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                    'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                ]),
                prop::sample::select(&['-', '@', '(', ')', ',', ':', ' ', '{', '}']),
                prop::sample::select(&['α', 'é', '中', '🚀', '\u{00A0}']),
            ],
            0..30,
        )
        .prop_map(|cs| cs.into_iter().collect())
    }

    /// The ref-token universe: the structured forms the grammar accepts
    /// (including the oversized extremes it must fail closed on) plus junk.
    pub(crate) fn ref_token_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // The HEAD forms.
            Just("".to_string()),
            Just("HEAD".to_string()),
            Just("@".to_string()),
            Just("@-".to_string()),
            Just("@--".to_string()),
            // parent(@, N).
            big_num().prop_map(|n| format!("parent(@, {n})")),
            // sK / sK- / sK--.
            big_num().prop_flat_map(|k| {
                prop_oneof![
                    Just(format!("s{k}")),
                    Just(format!("s{k}-")),
                    Just(format!("s{k}--")),
                ]
            }),
            // parent(sK, M).
            (big_num(), big_num()).prop_map(|(k, m)| format!("parent(s{k}, {m})")),
            // deploy-<id> / deploy-<id>- / parent(deploy-<id>, M).
            dep_id().prop_flat_map(|d| {
                prop_oneof![
                    Just(d.to_string()),
                    Just(format!("{d}-")),
                    big_num().prop_map(move |m| format!("parent({d}, {m})")),
                ]
            }),
            // rel-sha256-<hex>-- / parent(rel-sha256-<hex>, M) and the bare
            // digest equivalents.
            rel_id().prop_flat_map(|r| {
                prop_oneof![
                    Just(format!("{r}--")),
                    big_num().prop_map(move |m| format!("parent({r}, {m})")),
                ]
            }),
            // release:<id> — the DIRECT release form.
            rel_id().prop_map(|r| format!("release:{r}")),
            // Junk.
            junk_strategy(),
        ]
    }

    /// The documented fold: `Relative { base: At, steps: 0 }` is the same
    /// as `Head` (`parent(@, 0) ≡ @`), and the two display identically
    /// (`@`).
    pub(crate) fn fold(expr: RefExpr) -> RefExpr {
        match expr {
            RefExpr::Relative(rel) if rel.base == RelBase::At && rel.steps == 0 => RefExpr::Head,
            other => other,
        }
    }

    /// Assert the CANONICAL ROUND-TRIP for a successfully parsed
    /// expression: its `Display` string must re-parse, to the SAME
    /// expression modulo the documented `Relative{At,0} ≡ Head` fold, and
    /// `Display` must be a fixed point.
    fn assert_canonical_round_trip(expr: &RefExpr, token: &str) {
        let shown = expr.to_string();
        let reparsed = parse_no_panic(&shown).unwrap_or_else(|err| {
            panic!("Display({token:?}) = {shown:?} must re-parse, got: {err}")
        });
        assert_eq!(
            fold(reparsed.clone()),
            fold(expr.clone()),
            "canonical round-trip: Display({token:?}) = {shown:?} re-parses to {reparsed:?}, \
             expected {expr:?} modulo the Relative{{At,0}} ≡ Head fold"
        );
        assert_eq!(
            reparsed.to_string(),
            shown,
            "Display must be a fixed point for {token:?} (rendered {shown:?})"
        );
    }

    proptest! {
        // The PARSE leg — pure syntax, no store: canonical round-trip for
        // everything the parser accepts (modulo the documented fold), plus
        // totality (never panics; every failure is a ref error). Randomized
        // seeds with failure persistence (proptest's defaults): a failing
        // vector writes `proptest-regressions/revset.txt` and is replayed
        // on the next run — commit it. Bounded at 256 cases; the leg is
        // pure, so this stays fast.
        #![proptest_config(ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ref_grammar_parse_contract(token in ref_token_strategy()) {
            match parse_no_panic(&token) {
                Ok(expr) => assert_canonical_round_trip(&expr, &token),
                Err(err) => assert!(
                    matches!(err, Error::Ref(_)),
                    "parse failure for {token:?} must be a ref error, got: {err}"
                ),
            }
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION for the parse leg: the identical generator
        // under the pinned 0x5EED_5EED seed, no persistence, runs the same
        // vectors on every invocation.
        #![proptest_config(ProptestConfig {
            cases: 256,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ref_grammar_parse_contract_fixed_seed(token in ref_token_strategy()) {
            match parse_no_panic(&token) {
                Ok(expr) => assert_canonical_round_trip(&expr, &token),
                Err(err) => assert!(
                    matches!(err, Error::Ref(_)),
                    "parse failure for {token:?} must be a ref error, got: {err}"
                ),
            }
        }
    }
}

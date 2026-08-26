//! The push reference LANGUAGE: a pure, store-free grammar over reference
//! tokens (`@`, `@-`, `@--`, `parent(...)`, deployment ids, ...). The module
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
//!   concrete [`crate::history::PushRef`] against the target's deployment
//!   history in the store.
//!
//! The accepted forms are:
//!
//! * `` (empty), `HEAD`, `@` — the current local files (the default).
//! * `@-`, `@--` — the deployment BEFORE the latest successful deployment,
//!   the grandparent (walking the target's DEPLOYMENT HISTORY — each
//!   successful deployment is a rollback payload keyed by its id).
//! * `parent(@, N)` — the Nth ancestor of the latest successful deployment.
//! * `<deployment-id>` — roll back to THAT deployment's stored state (its
//!   exact snapshot: slots, behavior, bindings, and the release its
//!   generations came from). The id is the full `deploy-...` id.
//! * `<deployment-id>-`, `<deployment-id>--` — N ancestors of the deployment
//!   (1 or 2 dashes; walking the deployment history back from it).
//! * `parent(<deployment-id>, N)` — N ancestors of the deployment (N = 0 is
//!   the deployment itself).
//! * `release:<id>` — the DIRECT release form: deploy the named release to
//!   the CURRENT target's slots as they are, from the release's OWN stored
//!   slot-variant snapshot — but ONLY when the target's CURRENT slot-id
//!   membership EXACTLY equals the slot set the release record froze for
//!   that target (membership drift is refused at plan time, before any
//!   remote access; physical bindings are intentionally not compared).
//!   No deployment-history stepping: cross-target capable — the release may
//!   have been built/pushed anywhere, and the destination needs NO snapshot
//!   history at all. The id is a full `rel-sha256-...` id or a hex digest.
//!
//! REMOVED from the public surface (each fails closed with a migration
//! hint): the `sN` snapshot-index forms (`sN`, `sN-`, `sN--`,
//! `parent(sN, M)`), the `fN` legacy prefix, the release-refid ancestor
//! forms (`rel-...--`, `parent(rel-..., M)`), the legacy combined forms
//! (the target repeated inline, `release/<id>`), and bare release ids.
//! Rollback payloads are keyed by deployment id; the deployment history is
//! walked with `@` / `parent(...)`.
//!
//! Walking steps from a base POSITION in the deployment history (the log
//! order — positions are DERIVED, never stored): `parent(@, N)` = the
//! (len-1-N)-th entry of the floored chain; `parent(<id>, N)` = N positions
//! back from `<id>`'s position. Stepping past the start of the chain, an
//! unresolvable deployment id, or an empty chain fail closed with a ref
//! error — never underflow, never guess.

use crate::error::{Error, Result};
use crate::model::{DeploymentId, ReleaseId};
use winnow::ascii::digit1;
use winnow::combinator::{alt, cut_err, eof, peek, preceded, terminated};
use winnow::error::{ErrMode, ParserError};
use winnow::stream::Stream;
use winnow::token::{literal, rest, take_while};
use winnow::{ModalResult, Parser};
/// A parsed push reference BEFORE store/target resolution.
///
/// The relative forms cannot be turned into a concrete [`PushRef`] without the
/// target's deployment history, so [`parse_ref_expr`] stops at this parsed
/// form and [`resolve_ref_expr`] finishes the job against the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RefExpr {
    /// `""`, `HEAD`, `@`: materialize the currently mapped local files.
    Head,
    /// `release:<id>`: deploy the named release DIRECTLY to the current
    /// target's slots — no deployment-history stepping, no deployment-snapshot
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
/// `<deployment-id>-`, `<deployment-id>--`, `parent(<deployment-id>, N)`, or
/// the bare deployment id itself. The ancestor steps walk the target's
/// DEPLOYMENT HISTORY (the snapshot log in deployment order — each
/// successful deployment is a rollback payload keyed by its id); positions
/// are derived from that log order, never a stored index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelativeRef {
    /// The chain position the ancestor steps walk back from.
    pub base: RelBase,
    /// How many ancestors to walk (1 for `@-`, 2 for `@--`; 0 = the base
    /// itself, e.g. the bare `<deployment-id>` form).
    pub steps: u64,
}

/// The chain position a relative reference walks back from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelBase {
    /// `@`: the target's LATEST successful deployment.
    At,
    /// `<deployment-id>`: an explicit successful deployment id.
    Refid(DeploymentId),
}

impl std::fmt::Display for RelativeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match &self.base {
            RelBase::At => "@".to_string(),
            RelBase::Refid(dep) => dep.as_str().to_string(),
        };
        match self.steps {
            // `@` is the canonical rendering of `parent(@, 0)`: the
            // documented fold `parent(@, 0) ≡ @`. A bare deployment id is
            // the canonical 0-step refid form (`parent(deploy-x, 0)` renders
            // as `deploy-x`, re-parseable).
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
/// against the separately-given target argument at [`resolve_ref_expr`] time.
/// The removed `sN` snapshot-index grammar (and the legacy combined
/// `fN`/`release/<id>`/target-repeated forms) is NOT accepted — it fails
/// with an explicit migration hint (rollback payloads are keyed by
/// deployment id).
pub(crate) fn parse_ref_expr(token: &str) -> Result<RefExpr> {
    let t = token.trim();
    let mut parser = ref_expr(token);
    match parser.parse(t) {
        Ok(expr) => Ok(expr),
        Err(err) => Err(Error::r#ref(err.into_inner().0)),
    }
}

/// A ref-grammar parse failure carrying the exact user-facing message.
///
/// The parser is written with `winnow` combinators over this custom error
/// type so each failing branch can report the SAME message the hand-written
/// parser did (the tests assert message substrings, e.g. "invalid ancestor
/// step count").
#[derive(Debug)]
struct RefErr(String);

impl<I> ParserError<I> for RefErr
where
    I: Stream,
{
    type Inner = Self;

    fn from_input(_input: &I) -> Self {
        RefErr("unrecognized reference".to_string())
    }

    fn into_inner(self) -> std::result::Result<Self::Inner, Self> {
        Ok(self)
    }
}

/// A parser that always fails with the given ref message, as a CUT error:
/// the enclosing `alt` commits to this branch's diagnosis (its shape already
/// matched) instead of trying the next branch.
fn ref_fail<'i, O>(msg: String) -> impl Parser<&'i str, O, ErrMode<RefErr>> {
    move |_input: &mut &'i str| Err(ErrMode::Cut(RefErr(msg.clone())))
}

/// Zero or more whitespace, matching `str::trim`'s unicode whitespace so the
/// `parent(...)` argument tolerance is exactly what the hand-written parser
/// accepted (`parent(@, 3)`, `parent(@,3)`, `parent( @ , 3 )`, ...).
fn ws0<'i>(input: &mut &'i str) -> ModalResult<&'i str, RefErr> {
    take_while(0.., |c: char| c.is_whitespace()).parse_next(input)
}

/// The ref-grammar parser: `@`/`@-`/`@--`, `parent(<base>, N)`,
/// `<deployment-id>[-|--]`, `release:<id>`, and the legacy forms that fail
/// with migration hints. The `alt` order mirrors the documented dispatch;
/// every branch consumes the WHOLE token or fails, and each branch that
/// diagnoses a specific failure commits with a CUT error so its message
/// survives the `alt`.
fn ref_expr<'i>(token: &'i str) -> impl Parser<&'i str, RefExpr, ErrMode<RefErr>> + 'i {
    move |input: &mut &'i str| {
        alt((
            |i: &mut &str| head_form(i),
            |i: &mut &str| at_relative(i, token),
            |i: &mut &str| parent_form(i, token),
            |i: &mut &str| release_form(i, token),
            |i: &mut &str| legacy_forms(i, token),
            |i: &mut &str| deployment_form(i, token),
        ))
        .parse_next(input)
    }
}

/// `""`, `HEAD`, `@` — the current local files (the default push).
fn head_form(input: &mut &str) -> ModalResult<RefExpr, RefErr> {
    alt((
        eof.value(RefExpr::Head),
        terminated(literal("HEAD"), eof).value(RefExpr::Head),
        terminated(literal("@"), eof).value(RefExpr::Head),
    ))
    .parse_next(input)
}

/// `@-` / `@--` — 1 or 2 steps back from the latest successful deployment.
/// Any other `@`-prefixed token is a ref error (the only `@` forms).
fn at_relative(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    preceded(
        literal('@'),
        alt((
            terminated(literal("-"), eof).value(1u64),
            terminated(literal("--"), eof).value(2u64),
            ref_fail(format!(
                "unrecognized reference '{token}' (the only '@' forms are '@', '@-' and '@--'; \
                use 'parent(@, N)' for deeper steps)"
            )),
        )),
    )
    .map(|steps| {
        RefExpr::Relative(RelativeRef {
            base: RelBase::At,
            steps,
        })
    })
    .parse_next(input)
}

/// `parent(<base>, N)` — N ancestors of the base. Commits (CUT) once the
/// `parent(` prefix is seen, so a malformed parent() is diagnosed here
/// rather than falling through to the legacy checks.
fn parent_form(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    preceded(
        literal("parent("),
        cut_err(|i: &mut &str| parent_inner(i, token)),
    )
    .parse_next(input)
}

fn parent_inner(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    let _ = ws0.parse_next(input)?;
    let base = parent_base(input, token)?;
    let _ = (ws0, literal(',')).parse_next(input).map_err(|_| {
        ErrMode::Cut(RefErr(format!(
            "malformed parent() reference '{token}' (expected 'parent(<ref>, N)')"
        )))
    })?;
    let _ = ws0.parse_next(input)?;
    let steps = terminated(
        take_while(1.., |c: char| c.is_ascii_digit()),
        peek((ws0, literal(')'))),
    )
    .parse_next(input)
    .map_err(|_| ErrMode::Cut(RefErr(format!("invalid ancestor step count in '{token}'"))))?;
    let steps = steps
        .parse::<u64>()
        .map_err(|_| ErrMode::Cut(RefErr(format!("invalid ancestor step count in '{token}'"))))?;
    let _ = (ws0, literal(')'), eof).parse_next(input).map_err(|_| {
        ErrMode::Cut(RefErr(format!(
            "malformed parent() reference '{token}' (expected 'parent(<ref>, N)')"
        )))
    })?;
    Ok(RefExpr::Relative(RelativeRef { base, steps }))
}

/// The base of a `parent(<base>, N)`: `@`, a deployment id, or a legacy
/// snapshot-index / release-refid shape (rejected with its migration hint).
fn parent_base(input: &mut &str, token: &str) -> ModalResult<RelBase, RefErr> {
    alt((
        |i: &mut &str| literal("@").value(RelBase::At).parse_next(i),
        |i: &mut &str| legacy_snapshot_base(i, token),
        |i: &mut &str| legacy_release_base(i, token),
        |i: &mut &str| deployment_id_base(i, token),
    ))
    .parse_next(input)
}

/// The legacy `f<digits>` / `s<digits>` snapshot-index base inside
/// `parent(...)` — rejected with the deployment-keyed migration hint.
fn legacy_snapshot_base(input: &mut &str, token: &str) -> ModalResult<RelBase, RefErr> {
    let base = terminated(
        (alt((literal('f'), literal('s'))), digit1).take(),
        peek((ws0, literal(','))),
    )
    .parse_next(input)?;
    Err(ErrMode::Cut(RefErr(format!(
        "legacy snapshot-index base '{base}' in '{token}' is no longer accepted: \
        rollback payloads are keyed by deployment id — use 'parent(<deployment-id>, N)' \
        to walk the deployment history, or the deployment id directly"
    ))))
}

/// The legacy release-refid base inside `parent(...)` (a `rel-sha256-...`
/// id or a bare hex digest) — rejected: use `release:<id>` for the DIRECT
/// release form.
fn legacy_release_base(input: &mut &str, token: &str) -> ModalResult<RelBase, RefErr> {
    let base = alt((
        preceded(literal("rel-sha256-"), take_while(0.., |c: char| c != ',')),
        terminated(
            take_while(1.., |c: char| c.is_ascii_hexdigit()),
            peek((ws0, literal(','))),
        ),
    ))
    .take()
    .parse_next(input)?;
    Err(ErrMode::Cut(RefErr(format!(
        "legacy release-refid base '{base}' in '{token}' is no longer accepted: \
        use 'release:<id>' for the DIRECT release form"
    ))))
}

/// A deployment-id refid primitive (`deploy-...`, non-empty tail) inside
/// `parent(...)`.
fn deployment_id_base(input: &mut &str, token: &str) -> ModalResult<RelBase, RefErr> {
    let base = take_while(0.., |c: char| c != ',').parse_next(input)?;
    let base = base.trim();
    if let Some(rest) = base.strip_prefix("deploy-")
        && !rest.is_empty()
    {
        return DeploymentId::parse(base).map(RelBase::Refid).map_err(|_| {
            ErrMode::Backtrack(RefErr(format!(
                "unrecognized reference id '{base}' in '{token}' (expected a deployment id like \
                    'deploy-...', the '@' forms, or 'release:<id>')"
            )))
        });
    }
    Err(ErrMode::Backtrack(RefErr(format!(
        "unrecognized reference id '{base}' in '{token}' (expected a deployment id like \
        'deploy-...', the '@' forms, or 'release:<id>')"
    ))))
}

/// `release:<id>` — the DIRECT release form: a full `rel-sha256-...` id or
/// a bare hex digest.
fn release_form(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    preceded(
        literal("release:"),
        cut_err(|i: &mut &str| release_id(i, token)),
    )
    .map(RefExpr::Release)
    .parse_next(input)
}

fn release_id(input: &mut &str, token: &str) -> ModalResult<ReleaseId, RefErr> {
    let id = rest.parse_next(input)?;
    let valid = if let Some(r) = id.strip_prefix("rel-sha256-") {
        !r.is_empty()
    } else {
        !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit())
    };
    if !valid {
        return Err(ErrMode::Cut(RefErr(format!(
            "unrecognized release id '{id}' in '{token}' (expected 'release:<rel-sha256-...>' or \
            'release:<hex digest>')"
        ))));
    }
    Ok(ReleaseId::parse(id))
}

/// The removed/legacy grammar, each shape failing with its migration hint.
/// Every branch matches its shape then commits with a CUT error, so the hint
/// survives the enclosing `alt`.
fn legacy_forms(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    alt((
        |i: &mut &str| legacy_target_repeated(i, token),
        |i: &mut &str| legacy_release_slash(i, token),
        |i: &mut &str| legacy_f_index(i),
        |i: &mut &str| legacy_s_index(i),
        |i: &mut &str| legacy_bare_release(i, token),
    ))
    .parse_next(input)
}

/// The target repeated inline (`<target>@<ref>`) — the target is passed
/// once, on the command line.
fn legacy_target_repeated(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    preceded(
        (take_while(0.., |c: char| c != '@'), literal('@')).void(),
        ref_fail(format!(
            "unrecognized reference '{token}' (the target is passed once, on the command line: \
            the '@' forms are '@', '@-', '@--', and 'parent(@, N)')"
        )),
    )
    .parse_next(input)
}

/// The legacy `release/<id>` form.
fn legacy_release_slash(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    preceded(
        literal("release/"),
        ref_fail(format!(
            "legacy 'release/<id>' reference '{token}' is no longer accepted; \
            use 'release:<id>' for the DIRECT release form"
        )),
    )
    .parse_next(input)
}

/// The legacy `f<digits>` snapshot-index prefix.
fn legacy_f_index(input: &mut &str) -> ModalResult<RefExpr, RefErr> {
    let digits = terminated(preceded(literal('f'), digit1), eof).parse_next(input)?;
    Err(ErrMode::Cut(RefErr(format!(
        "legacy 'f{digits}' snapshot-index form is no longer accepted: rollback payloads are \
        keyed by deployment id — use 'deploy push <target> <deployment-id>' or '@- / @-- / \
        parent(@, N)' to walk the deployment history"
    ))))
}

/// The legacy `s<digits>` snapshot-index forms (bare, or with an ancestor
/// suffix — `s3---` reaches here only when the dashes count is > 2; `s3--`
/// and `parent(s3, M)` are caught above).
fn legacy_s_index(input: &mut &str) -> ModalResult<RefExpr, RefErr> {
    let digits = terminated(preceded(literal('s'), digit1), eof).parse_next(input)?;
    Err(ErrMode::Cut(RefErr(format!(
        "legacy 's{digits}' snapshot-index form is no longer accepted: rollback payloads are \
        keyed by deployment id — use 'deploy push <target> <deployment-id>', or '@- / @-- / \
        parent(@, N)' to walk the deployment history"
    ))))
}

/// Bare release ids (full `rel-sha256-...` or a hex digest) — the DIRECT
/// form requires the `release:` prefix.
fn legacy_bare_release(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    preceded(
        alt((
            literal("rel-sha256-"),
            terminated(take_while(1.., |c: char| c.is_ascii_hexdigit()), eof),
        )),
        ref_fail(format!(
            "legacy bare release id '{token}' is no longer accepted; \
            use 'release:<id>' for the DIRECT release form"
        )),
    )
    .parse_next(input)
}

/// `<deployment-id>` with an optional `-` / `--` ancestor suffix, or the
/// bare deployment id itself (0 steps). The id is a `deploy-...` primitive
/// (any non-empty tail, internal dashes allowed); the trailing-dash count is
/// derived from the token exactly as the hand-written parser did.
fn deployment_form(input: &mut &str, token: &str) -> ModalResult<RefExpr, RefErr> {
    let t = rest.parse_next(input)?;
    let dashes = t.len() - t.trim_end_matches('-').len();
    if dashes > 2 {
        return Err(ErrMode::Backtrack(RefErr(format!(
            "unrecognized reference '{token}' (only '-' and '--' ancestor steps are accepted)"
        ))));
    }
    let id = &t[..t.len() - dashes];
    if id.is_empty() {
        return Err(ErrMode::Backtrack(RefErr(format!(
            "unrecognized reference '{token}'"
        ))));
    }
    let dep = match id.strip_prefix("deploy-") {
        Some(tail) if !tail.is_empty() => DeploymentId::parse(id),
        _ => Err(Error::config("unrecognized reference id")),
    }
    .map_err(|_| {
        ErrMode::Backtrack(RefErr(format!(
            "unrecognized reference id '{id}' in '{token}' (expected a deployment id like \
            'deploy-...', the '@' forms, or 'release:<id>')"
        )))
    })?;
    Ok(RefExpr::Relative(RelativeRef {
        base: RelBase::Refid(dep),
        steps: dashes as u64,
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::test_deployment_id;
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
    /// `@-` / `@--` / `parent(@, N)` walk back from the latest successful
    /// deployment; `<deployment-id>-`, `<deployment-id>--`,
    /// `parent(<deployment-id>, N)`, and the bare deployment id itself walk
    /// back from that deployment. The snapshot-index and release-refid forms
    /// are GONE from the public grammar.
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
        let d = test_deployment_id("deploy-abc123");
        assert_eq!(
            rel(&format!("{d}--")),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(d.clone()),
                steps: 2
            })
        );
        assert_eq!(
            rel(&format!("parent({d}, 2)")),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(d.clone()),
                steps: 2
            })
        );
        // The bare deployment id is the 0-step form.
        assert_eq!(
            rel(d.as_str()),
            RefExpr::Relative(RelativeRef {
                base: RelBase::Refid(d.clone()),
                steps: 0
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
    /// and stays the ONLY way to reference a release (the release-refid
    /// ancestor forms are removed).
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
    }

    /// The removed and legacy grammar is REJECTED with a ref error, never
    /// silently re-mapped: the `sN` snapshot-index forms (bare, stepped,
    /// parent base, oversized), the old `fN` prefix, bare release ids and
    /// release-refid ancestors, the target repeated inline, `release/<id>`,
    /// `:current`, and malformed relatives.
    #[test]
    fn parse_ref_rejects_legacy_forms() {
        for token in [
            "s0",
            "s3",
            "s3-",
            "s3--",
            "s3---",
            "parent(s5, 2)",
            "parent(s5, 0)",
            "f3",
            "f3--",
            "parent(f5, 2)",
            "rel-sha256-x",
            "rel-sha256-x--",
            "parent(rel-sha256-x, 1)",
            "deadbeef",
            "parent(deadbeef, 2)",
            "production@s0",
            "@s0",
            "release/rel-sha256-x",
            "release:",
            "release:rel-sha256-",
            "release:not-hex",
            "release:has/dash",
            "HEAD:current",
            "@-:current",
            "@@",
            "@---",
            "parent(@, x)",
            "parent(@, -1)",
            "parent(@",
            "--",
            "-",
            "deploy-",
        ] {
            let err = parse_ref_expr(token).expect_err(&format!("{token:?} must be rejected"));
            assert!(
                err.to_string().contains("reference")
                    || err.to_string().contains("step count")
                    || err.to_string().contains("release"),
                "error for {token:?} must be a ref error, got: {err}"
            );
        }
    }

    /// A `deploy-<id>` deployment-id refid parses to a deployment base.
    #[test]
    fn parse_deployment_id_forms() {
        let d = test_deployment_id("deploy-a");
        for token in [
            d.as_str().to_string(),
            format!("{d}-"),
            format!("{d}--"),
            format!("parent({d}, 5)"),
        ] {
            let parsed = parse_ref_expr(&token).expect("deployment-id forms parse");
            assert!(
                matches!(
                    parsed,
                    RefExpr::Relative(RelativeRef {
                        base: RelBase::Refid(_),
                        ..
                    })
                ),
                "{token} must parse to a deployment-id relative, got: {parsed:?}"
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

    // PROPERTY: no reference token, however huge its ancestor count, may
    // panic the parser, and any count that does not fit a `u64` must be a
    // ref error — never a silently valid parse.
    //
    // The generated digits are 100 chars with a nonzero lead (magnitude
    // >= 10^99, far beyond `u64::MAX` ~ 1.8*10^19), covering `parent(@, M)`
    // and `parent(<deployment-id>, M)` with a huge `M`. Boundary cases pin
    // `u64::MAX` exactly (the largest VALID count) against `u64::MAX + 1`
    // (the smallest overflow).
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            rng_seed: RngSeed::Fixed(0x0F10_0F10),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn oversized_ancestor_counts_are_errors_never_panics(huge in "[1-9][0-9]{99}") {
            // `parent(@, M)` with a huge M.
            let err = parse_no_panic(&format!("parent(@, {huge})"))
                .expect_err("an oversized ancestor count must be a ref error");
            assert!(
                err.to_string().contains("invalid ancestor step count"),
                "error must report the bad ancestor count, got: {err}"
            );

            // `parent(<deployment-id>, M)` with a huge M (and huge M AND a
            // huge count: M is parsed first, so it reports the ancestor-count
            // error).
            let d = test_deployment_id("deploy-a");
            for token in [
                format!("parent({d}, {huge})"),
                format!("parent({d}, {huge})"),
            ] {
                let err = parse_no_panic(&token)
                    .expect_err(&format!("oversized ancestor count '{token}' must be a ref error"));
                assert!(
                    err.to_string().contains("invalid ancestor step count"),
                    "error for '{token}' must report the bad ancestor count, got: {err}"
                );
            }

            // Boundary: `u64::MAX` exactly is the largest VALID ancestor
            // count; `u64::MAX + 1` overflows and is a ref error.
            let max = u64::MAX.to_string();
            assert_eq!(
                parse_no_panic(&format!("parent(@, {max})")).unwrap(),
                RefExpr::Relative(RelativeRef {
                    base: RelBase::At,
                    steps: u64::MAX,
                }),
            );
            let over = (u64::MAX as u128 + 1).to_string();
            for token in [
                format!("parent(@, {over})"),
                format!("parent({d}, {over})"),
            ] {
                let err = parse_no_panic(&token)
                    .expect_err(&format!("u64::MAX + 1 count '{token}' must be a ref error"));
                assert!(
                    err.to_string().contains("invalid ancestor step count"),
                    "error for '{token}' must report the bad ancestor count, got: {err}"
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // Ref-grammar property suite (parse leg)
    // -------------------------------------------------------------------

    /// One of the ancestor-count magnitudes the grammar must accept or
    /// reject by fit: the small steps {0,1,2,3}, exactly `u64::MAX` (the
    /// largest VALID count), `u64::MAX + 1` (the smallest overflow — a ref
    /// error, never a panic), and a 100-digit string (magnitude ~10^99, far
    /// beyond `u64`).
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

    /// A deployment-id refid (`deploy-<id>`). The id must be a CANONICAL
    /// (validated) deployment id — the grammar validates the refid, so the
    /// strategy generates the canonical form of a random tag.
    fn dep_id() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{0,7}".prop_map(|s| test_deployment_id(&s).as_str().to_string())
    }

    /// A release id for the DIRECT `release:<id>` form: a full
    /// `rel-sha256-<hex>` id or a bare hex digest. The digest is at least 4
    /// chars so it can never collide with the legacy `f<digits>` prefix.
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
            // deploy-<id> / deploy-<id>- / deploy-<id>--.
            dep_id().prop_flat_map(|d| {
                prop_oneof![
                    Just(d.to_string()),
                    Just(format!("{d}-")),
                    Just(format!("{d}--")),
                ]
            }),
            // parent(<deployment-id>, M).
            (dep_id(), big_num()).prop_map(|(d, m)| format!("parent({d}, {m})")),
            // release:<id> — the DIRECT release form (unchanged).
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

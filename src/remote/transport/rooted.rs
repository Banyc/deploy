//! `deploy`'s boundary tests for the validated root-relative path.
//!
//! The TYPE moved to [`storekit::relpath::RootedRelativePath`] (re-exported as
//! [`super::RootedRelativePath`](crate::remote::transport::RootedRelativePath));
//! the 200 lines of implementation in the former `deploy` module are gone
//! because the crate's public API is byte-for-byte the same. This module keeps
//! `deploy`'s own boundary tests, now exercised THROUGH `deploy`'s re-export of
//! the crate's type, so the migration neither removes coverage nor leaves the
//! boundary unpinned in `deploy`'s suite. The crate carries the same three
//! tests (and more) in `storekit::relpath`'s own module; the one `deploy`-only
//! fact pinned here is that a rejected spelling surfaces as `deploy`'s
//! [`crate::error::Error::Transport`] through the `From<storekit::Error>`
//! bridge.

use super::RootedRelativePath;
use std::path::Path;

/// The boundary rule: a validated relative path accepts every safe relative
/// form and rejects every unsafe one (empty, absolute, `.`/`..` at any
/// position).
#[test]
fn parse_accepts_safe_rejects_unsafe() {
    for ok in [
        "a",
        "a/b",
        "a/b/c.json",
        "generations/gen-1/assignment.json",
        "objects/sha256/abc/root",
        "a//b",
        "a/",
    ] {
        let p = RootedRelativePath::parse(Path::new(ok))
            .unwrap_or_else(|e| panic!("{ok:?} must parse: {e}"));
        assert_eq!(p.as_path(), Path::new(ok));
    }
    for bad in [
        "",
        "/",
        "//",
        "/abs",
        "/abs/rel",
        ".",
        "..",
        "./a",
        "a/.",
        "a/..",
        "../a",
        "a/../b",
        "a/b/../../c",
        "/a/../b",
    ] {
        assert!(
            RootedRelativePath::parse(Path::new(bad)).is_err(),
            "{bad:?} must be rejected"
        );
    }
}

/// Joining re-validates: a safe component joins, an absolute or traversal
/// component is rejected.
#[test]
fn join_revalidates() {
    let base = RootedRelativePath::parse(Path::new("a/b")).unwrap();
    assert_eq!(
        base.join("c.json").unwrap().as_path(),
        Path::new("a/b/c.json")
    );
    for bad in ["/abs", "..", "../x", ".", "/"] {
        base.join(bad)
            .expect_err(&format!("{bad:?} must be rejected"));
    }
}

/// A refused spelling crosses into `deploy` as a typed transport error (the
/// same variant the crate's `Error::Transport` maps to), so a caller can
/// branch on the class and the message is preserved.
#[test]
fn a_rejected_spelling_surfaces_as_a_deploy_transport_error() {
    let storekit_err = RootedRelativePath::parse(Path::new("../escape"))
        .expect_err("a traversal spelling must be refused");
    assert!(
        matches!(storekit_err, storekit::Error::Transport { .. }),
        "the crate refuses with its transport class: {storekit_err:?}"
    );
    let deploy_err: crate::error::Error = storekit_err.into();
    assert!(
        matches!(deploy_err, crate::error::Error::Transport(_)),
        "the bridge maps it onto deploy's transport class: {deploy_err:?}"
    );
}

/// Arbitrary untyped path text covering every unsafe class: empty,
/// absolute, `.`/`..` at any position, separators, whitespace, unicode,
/// control characters, and clean safe relative values.
fn arbitrary_path_text() -> impl proptest::prelude::Strategy<Value = String> {
    use proptest::prelude::*;
    prop_oneof![
        prop::sample::select(vec![
            String::new(),
            "/".to_string(),
            "//".to_string(),
            "/abs".to_string(),
            "/abs/rel".to_string(),
            ".".to_string(),
            "..".to_string(),
            "./a".to_string(),
            "a/.".to_string(),
            "a/..".to_string(),
            "../a".to_string(),
            "a/../b".to_string(),
            "a/b/../../c".to_string(),
            "/a/../b".to_string(),
            "a".to_string(),
            "a/b".to_string(),
            "a/b/c.json".to_string(),
            "generations/gen-1/assignment.json".to_string(),
            "objects/sha256/abc/root".to_string(),
            "a//b".to_string(),
            "a/".to_string(),
            " x".to_string(),
            "x ".to_string(),
            "a\nb".to_string(),
            "α".to_string(),
            "a\u{0}b".to_string(),
        ]),
        prop::collection::vec(prop::char::any(), 0..48).prop_map(|v| v.into_iter().collect()),
    ]
}

proptest::proptest! {
    // THE BOUNDARY PROPERTY: over ARBITRARY untyped path text, the
    // validated parse accepts EXACTLY the safe relative forms and rejects
    // every unsafe one. Bounded 16 cases, fixed seed 0x5EED_5EED (house
    // style), no failure persistence. The rejection classification uses the
    // PLATFORM separator predicate the crate's `parse` uses (never a
    // hardcoded `/`), so on Windows `..\x` is classified as traversal.
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: crate::testutil::proptest_cases(16),
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..proptest::prelude::ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_untyped_paths_are_rejected_or_safe(s in arbitrary_path_text()) {
        use proptest::prelude::*;
        let p = Path::new(&s);
        match RootedRelativePath::parse(p) {
            Ok(r) => {
                // A path that parses is SAFE: relative, non-empty, and
                // every component is a NORMAL component (no `.`/`..`,
                // no root).
                prop_assert!(!r.as_path().is_absolute(), "{s:?} must not be absolute");
                prop_assert!(!r.as_path().as_os_str().is_empty(), "{s:?} must not be empty");
                for c in r.as_path().components() {
                    prop_assert!(
                        matches!(c, std::path::Component::Normal(_)),
                        "{s:?} has an unsafe component {:?}",
                        c
                    );
                }
            }
            Err(_) => {
                // A path that is rejected is UNSAFE: absolute, empty, a
                // non-Normal component, or a literal `.`/`..` segment on a
                // platform separator (which `Path::components` erases).
                let unsafe_class = p.is_absolute()
                    || p.as_os_str().is_empty()
                    || p.components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                    || s.split(std::path::is_separator)
                        .any(|seg| seg == "." || seg == "..");
                prop_assert!(
                    unsafe_class,
                    "rejected path {s:?} must be absolute, empty, or traversal-bearing"
                );
            }
        }
    }
}

//! The SEALED filesystem-ownership root ([`OwnedRoot`]) — now the
//! `storekit::root` substrate.
//!
//! This module was `deploy`'s own ownership root (439 lines: the sealed type,
//! the process-global per-endpoint registry, and the overlap refusal, the
//! source `storekit` was extracted from). It is now a `pub use` of
//! [`storekit::root::OwnedRoot`], so the implementation lives in exactly one
//! place and every `crate::store::local::OwnedRoot` call site keeps resolving.
//! The re-export is `pub` (not `pub(crate)` like the `lock`/`atomic` swaps):
//! `deploy` itself re-exported `OwnedRoot` publicly from
//! [`crate::store::local`], and the crate exports it publicly too, so the
//! surface is neither narrowed nor widened.
//!
//! # Behaviour (unchanged from `deploy`'s copy)
//!
//! Filesystem ownership is LEXICAL: two stores (or two deployment roots) can
//! be created on the same directory, or on ancestor/descendant directories of
//! each other, and nothing rejects it — two owners over overlapping state.
//! [`OwnedRoot`] closes that class: the only construction path is
//! [`OwnedRoot::parse`], which canonicalizes the path, rejects the filesystem
//! root and a symlink root, and refuses a root that equals — or is an ancestor
//! or descendant of — an already-owned root on the SAME resolved endpoint. The
//! refusal happens against the process-global ownership registry BEFORE any
//! filesystem mutation, and the registration is REFCOUNTED (released when the
//! last clone drops). The crate adds ONE shared authority for the overlap
//! predicate (`root::roots_overlap`), which the sync's source/destination
//! check also uses; `deploy` inlined the same comparison.
//!
//! The store's mutations remain descriptor-relative (`crate::store::atomic`'s
//! `_fd` primitives, now the crate's): every mutation resolves paths
//! component-wise relative to the owned root's open directory descriptor with
//! `openat(O_NOFOLLOW)`, so a symlink injected into a path component can never
//! redirect a mutation outside the owned root.
//!
//! # The `EndpointKey` domain cut
//!
//! [`OwnedRoot::parse`] now takes `storekit::root::EndpointKey` and
//! [`OwnedRoot::local_endpoint`] returns it, while `deploy` keeps its own
//! [`crate::identity::EndpointKey`]. The two are the SAME domain type cut at
//! two levels: the crate's is the minimal non-empty, separator/whitespace/
//! control-free token the ownership registry needs; `deploy`'s is the
//! PHYSICAL deployment-identity component of [`crate::identity::PhysicalSlotKey`]
//! (`{application, slot, endpoint, deploy_dir}`, where the endpoint is the
//! ServerDef's `user@address`), with the `Config`-class error its domain
//! expects. **Decision: keep `deploy`'s type where its domain needs it, and
//! let the crate's type own the root boundary.** The only endpoint `deploy`
//! ever feeds to a root is the constant `local` marker
//! ([`OwnedRoot::local_endpoint`], which now parses the crate's own
//! [`storekit::root::LOCAL_ENDPOINT_MARKER`]); no `deploy` endpoint is mapped
//! into the registry, so there is no conversion to write. Nothing is lost:
//! both validators accept exactly the same token set, and the only
//! observable difference is the error CLASS an INVALID endpoint would take
//! (`Ref` from the crate vs `Config` from `deploy`) — a class `deploy` never
//! routes through the root constructor. A future caller that DOES thread a
//! non-local `deploy` endpoint into an `OwnedRoot` converts with
//! `storekit::root::EndpointKey::parse(endpoint.as_str())` (infallible for an
//! already-validated `deploy` endpoint).

pub use storekit::root::OwnedRoot;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ApplicationStoreKey;
    use crate::store::local::LocalStore;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::path::{Path, PathBuf};
    use storekit::root::EndpointKey;

    /// A unique endpoint per proptest case: derived from the generated tag,
    /// so the process-global registry never accumulates across cases and
    /// never collides with another test's endpoint (the store's `local`
    /// marker, or another case's tag).
    fn case_endpoint(tag: &str) -> EndpointKey {
        EndpointKey::parse(&format!("local-{tag}")).expect("a clean tag is a valid endpoint")
    }

    /// Snapshot the directory tree under `root` (every entry path, sorted)
    /// so a test can assert a refused registration created or deleted
    /// NOTHING. Symlinks are listed as entries, never followed.
    fn tree_snapshot(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let p = entry.path();
                out.push(p.clone());
                if entry.file_type().unwrap().is_dir() {
                    walk(&p, out);
                }
            }
        }
        walk(root, &mut out);
        out.sort();
        out
    }

    // -------------------------------------------------------------------
    // THE OWNERSHIP-REFUSAL PROPERTY (the review's acceptance): generate
    // EQUAL, NESTED (ancestor/descendant), TRAVERSAL (`..`), `/`, and
    // SYMLINK-INJECTED candidate roots against a first owned root; EVERY
    // candidate must be refused at construction, and the refusal must
    // happen BEFORE creating or deleting anything (the directory tree is
    // byte-for-byte unchanged after each failed construction). Bounded
    // `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`, fast
    // default), fixed seed 0x5EED_5EED (house style), no persistence.
    // -------------------------------------------------------------------
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn overlapping_roots_are_refused_before_any_mutation(tag in "[a-z0-9]{1,8}") {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let root = dir.path().join("owned");
            std::fs::create_dir_all(&root).unwrap();
            let endpoint = case_endpoint(&tag);
            // The FIRST root is owned and stays alive for the whole case.
            let first = OwnedRoot::parse(&endpoint, &root).unwrap();
            assert_eq!(
                first.canonical(),
                std::fs::canonicalize(&root).unwrap(),
                "the owned root is the canonical directory"
            );

            // The candidate roots: equal, nested (child), nested (parent),
            // traversal (`..` — canonicalizes to the owned root), the
            // filesystem root, and symlink-injected (a final-component
            // symlink, and an intermediate-component symlink resolving to a
            // descendant of the owned root).
            let child = root.join("child");
            std::fs::create_dir_all(&child).unwrap();
            let parent = root.parent().unwrap().to_path_buf();
            let traversal = root.join("..").join(root.file_name().unwrap());
            let symlink_final = dir.path().join("link-final");
            std::os::unix::fs::symlink(&root, &symlink_final).unwrap();
            let symlink_mid = dir.path().join("link-mid");
            std::os::unix::fs::symlink(&root, &symlink_mid).unwrap();
            let symlink_child = symlink_mid.join("child");

            let before = tree_snapshot(dir.path());

            for candidate in [
                root.clone(),          // equal
                child.clone(),         // nested (descendant)
                parent.clone(),        // nested (ancestor)
                traversal,             // traversal -> equal after canonicalize
                PathBuf::from("/"),    // the filesystem root
                symlink_final,         // symlink root (final component)
                symlink_child,         // symlink-injected intermediate -> descendant
            ] {
                let res = OwnedRoot::parse(&endpoint, &candidate);
                assert!(
                    res.is_err(),
                    "candidate {:?} must be refused on endpoint {}",
                    candidate,
                    endpoint.as_str()
                );
            }

            // EVERY refusal happened BEFORE creating or deleting anything:
            // the directory tree is unchanged.
            assert_eq!(
                tree_snapshot(dir.path()),
                before,
                "a refused root must not create or delete anything"
            );
        }
    }

    /// The store-level integration: two stores on the SAME base (via the
    /// production `new_in` path) are refused while the first is alive, and
    /// the refusal happens before any store record is created or deleted.
    #[test]
    fn two_stores_on_the_same_base_are_refused() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let env = crate::env::SysEnv::from_map(std::collections::BTreeMap::from([(
            std::ffi::OsString::from("XDG_DATA_HOME"),
            dir.path().join("store-root").into_os_string(),
        )]));
        let key = ApplicationStoreKey::parse("my-app").unwrap();
        let store = LocalStore::new_in(&env, &key).expect("the first store owns its base");
        let err = match LocalStore::new_in(&env, &key) {
            Ok(_) => panic!("a second store on the same base must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("overlaps"),
            "the refusal must name the overlap, got: {err}"
        );
        // The first store is still fully functional.
        store
            .write_pins(&crate::ledger::Pins::empty())
            .expect("the first store keeps working");
        // Dropping the first store releases the registration: a fresh store
        // on the same base is allowed again.
        drop(store);
        LocalStore::new_in(&env, &key).expect("a released root can be re-owned");
    }

    /// A symlink root is refused at construction (the root must be a real
    /// directory, not a symlink), and the filesystem root is refused.
    #[test]
    fn symlink_and_filesystem_roots_are_refused() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let endpoint = case_endpoint("symlink-root");
        let err = OwnedRoot::parse(&endpoint, &link).expect_err("a symlink root must be refused");
        assert!(
            err.to_string().contains("not a symlink"),
            "the refusal must name the symlink rule, got: {err}"
        );
        let err = OwnedRoot::parse(&endpoint, Path::new("/"))
            .expect_err("the filesystem root must be refused");
        assert!(
            err.to_string().contains("filesystem root"),
            "the refusal must name the non-root rule, got: {err}"
        );
    }

    /// THE DESCRIPTOR-RELATIVE MUTATION CONFINEMENT: a symlink injected
    /// into a path component cannot redirect a store mutation outside the
    /// owned root — the mutation is REFUSED (the component-wise
    /// `openat(O_NOFOLLOW)` open's ELOOP), and the outside target is
    /// untouched.
    #[test]
    fn symlink_injected_path_component_cannot_redirect_a_mutation() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // An outside directory the injected symlink would point at.
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        // Inject a symlink at the TARGET directory component:
        // `targets/<target>` is replaced by a symlink to the outside dir.
        let target = crate::identity::TargetName::parse("t1").unwrap();
        let target_dir = store
            .retention_debt_path(&target)
            .parent()
            .unwrap()
            .to_path_buf();
        std::os::unix::fs::symlink(&outside, &target_dir).unwrap();
        // The mutation must be REFUSED (the O_NOFOLLOW open never follows
        // the symlink), and the outside dir must stay untouched.
        let debt = std::collections::BTreeMap::from([("p1".to_string(), "reason".to_string())]);
        let err = store
            .write_retention_debt(&target, &debt)
            .expect_err("a mutation through a symlink-injected path component must be refused");
        assert!(
            err.to_string().contains("openat"),
            "the refusal must be the O_NOFOLLOW open failure, got: {err}"
        );
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            0,
            "the outside directory must be untouched"
        );
    }

    /// THE DESCRIPTOR-RELATIVE READ CONFINEMENT: a symlink injected into a
    /// path component cannot redirect a store READ outside the owned root —
    /// the read is REFUSED (the component-wise `openat(O_NOFOLLOW)` open's
    /// ELOOP), and the outside target is untouched. The mirror of the
    /// mutation-confinement test above: the enforcement mechanism
    /// (descriptor-relative, symlink-refusing) covers BOTH directions.
    #[test]
    fn symlink_injected_path_component_cannot_redirect_a_read() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // An outside directory the injected symlink would point at.
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        // Inject a symlink at the TARGET directory component:
        // `targets/<target>` is replaced by a symlink to the outside dir.
        let target = crate::identity::TargetName::parse("t1").unwrap();
        let target_dir = store
            .retention_debt_path(&target)
            .parent()
            .unwrap()
            .to_path_buf();
        std::os::unix::fs::symlink(&outside, &target_dir).unwrap();
        // The READ must be REFUSED (the O_NOFOLLOW open never follows the
        // symlink), and the outside dir must stay untouched.
        let err = store
            .read_retention_debt(&target)
            .expect_err("a read through a symlink-injected path component must be refused");
        assert!(
            err.to_string().contains("openat"),
            "the refusal must be the O_NOFOLLOW open failure, got: {err}"
        );
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            0,
            "the outside directory must be untouched"
        );

        // A symlink at the FINAL component is refused too: `pins.json`
        // replaced by a symlink to an outside file — the read must error,
        // never follow the link.
        let outside_file = dir.path().join("outside-pins.json");
        std::fs::write(&outside_file, b"{}").unwrap();
        let pins_path = store.pins_path();
        std::os::unix::fs::symlink(&outside_file, &pins_path).unwrap();
        let err = store
            .read_pins()
            .expect_err("a read of a symlink final component must be refused");
        assert!(
            err.to_string().contains("openat"),
            "the refusal must be the O_NOFOLLOW open failure, got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&outside_file).unwrap(),
            "{}",
            "the outside file must be untouched"
        );
    }
}

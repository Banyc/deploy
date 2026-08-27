//! The `current` symlink chain (feature areas A1/A3/A7).
//!
//! Hosts the top-level `current` entry's canonical-target contract and the
//! full-chain integrity validation [`RemoteHelper::status`] runs on every
//! read: `current` -> `generations/<gen>/root` -> the canonical generation
//! `root` symlink -> the matching `assignment.json` -> the tree object.
//! Malformed `current` is an integrity error, never absence (A7: a malformed
//! link is not "nothing deployed"). [`RemoteHelper::swap_current`] advances
//! `current` only on the CAS precondition (A1), and
//! [`RemoteHelper::remove_current_if`] is the first-deployment compensation's
//! CAS removal.

use crate::error::{Error, Result};
use crate::identity::GenerationId;
use crate::remote::helper::{RemoteHelper, RemoteStatus};
use crate::remote::layout;
use std::path::Path;

impl<'a> RemoteHelper<'a> {
    /// Inspect the actual remote generation, object inventory, lock, and
    /// pending incoming directories.
    ///
    /// Absence is reported ONLY when the top-level `current` symlink itself
    /// is absent. Any PRESENT `current` must name the EXACT canonical
    /// `generations/<gen>/root` target (a parseable `gen-<uuid-v7>` id,
    /// exactly three components — no `generations`-component lookup at an
    /// arbitrary position, no missing `root` suffix, no extra components, no
    /// empty/absolute/`..` targets); every deviation from the canonical target
    /// is an integrity error, never a `None`. When the target IS canonical,
    /// the COMPLETE chain behind it is validated and every deviation fails
    /// closed with an integrity error — never a panic:
    ///
    /// * the generation directory `generations/<gen>/` exists;
    /// * `generations/<gen>/assignment.json` exists, parses, and its
    ///   generation id matches the directory;
    /// * the generation's `root` symlink exists, is a symlink, and its target
    ///   is byte-exactly the canonical `../../objects/sha256/<tree>/root` for
    ///   the assignment's tree (the exact form `create_generation` writes);
    /// * the tree object directory `objects/sha256/<tree>/root` exists.
    ///
    /// On full success `current_generation`/`current_tree` carry the
    /// validated generation id and tree.
    pub fn status(&self) -> Result<RemoteStatus> {
        let mut status = RemoteStatus::default();

        // Current generation via the top-level `current` symlink. The ONLY
        // absence case is "no `current` entry at all": `exists` FOLLOWS the
        // link, so a DANGLING `current` (one whose target does not resolve)
        // reports false, while `metadata` (an lstat) still sees the link
        // itself — both are checked so a dangling link is treated as PRESENT
        // and validated (failing on its missing record) rather than silently
        // treated as absent.
        if let Some(gid) = self.canonical_current_target()? {
            // The link names a generation: validate the COMPLETE chain it
            // points at. A missing generation directory, a missing/corrupt
            // assignment, an assignment whose id does not match its
            // directory, a missing or wrong generation `root` symlink, or a
            // missing tree object is a MALFORMED remote state — fail closed
            // with an integrity error rather than reporting a current
            // generation that cannot be verified.
            let gen_dir = layout::generation(gid.as_str());
            if !self.remote.exists(&gen_dir) {
                return Err(Error::integrity(format!(
                    "current symlink points at missing generation directory {}",
                    gen_dir.display()
                )));
            }
            let a = self.read_assignment(gid.as_str()).map_err(|e| {
                Error::integrity(format!(
                    "current generation {gid} has a malformed assignment: {e}"
                ))
            })?;
            if a.generation_id != gid {
                return Err(Error::integrity(format!(
                    "current generation {gid} assignment names generation {}",
                    a.generation_id
                )));
            }
            // generation/root: `generations/<gen>/root` must exist, be a
            // symlink, and its target must be byte-exactly the CANONICAL
            // relative target for the assignment's tree (the exact form
            // `create_generation` writes).
            let root_link = gen_dir.join("root");
            let root_meta = self.remote.metadata(&root_link);
            let root_present =
                self.remote.exists(&root_link) || matches!(&root_meta, Ok(m) if m.is_symlink);
            if !root_present {
                return Err(Error::integrity(format!(
                    "current generation {gid} has no root symlink at {}",
                    root_link.display()
                )));
            }
            let root_meta = root_meta?;
            if !root_meta.is_symlink {
                return Err(Error::integrity(format!(
                    "generation {gid} root entry at {} is not a symlink",
                    root_link.display()
                )));
            }
            let root_target = self.remote.read_link(&root_link)?;
            let canonical_root = layout::generation_root_link(a.artifact.tree.as_str());
            if root_target != canonical_root {
                return Err(Error::integrity(format!(
                    "generation {gid} root symlink target {root_target:?} is not the canonical {} for tree {}",
                    canonical_root.display(),
                    a.artifact.tree
                )));
            }
            // Object tree: the tree object directory the `root` link names
            // must exist on the remote.
            let tree_root = layout::tree_root(a.artifact.tree.as_str());
            if !self.remote.exists(&tree_root) {
                return Err(Error::integrity(format!(
                    "current generation {gid} tree object {} is missing",
                    tree_root.display()
                )));
            }
            status.current_generation = Some(gid);
            status.current_tree = Some(a.artifact.tree.as_str().to_string());
        }

        // Object inventory.
        let obj_root = layout::objects();
        if self.remote.exists(obj_root) {
            for e in self.remote.list(obj_root)? {
                if e.is_dir {
                    status.inventory.push(e.name);
                }
            }
        }

        // Lock holder.
        if self.remote.exists(&layout::operation_lock()) {
            let data = self.remote.read(&layout::operation_lock())?;
            status.lock = Some(String::from_utf8_lossy(&data).trim().to_string());
        }

        // Pending incoming.
        let inc = layout::incoming();
        if self.remote.exists(inc) {
            for e in self.remote.list(inc)? {
                if e.is_dir {
                    status.pending_incoming.push(e.name);
                }
            }
        }

        Ok(status)
    }

    /// Parse the top-level `current` entry into the generation it names,
    /// enforcing the EXACT canonical target form. `Ok(None)` when `current`
    /// is genuinely ABSENT (no entry at all); `Ok(Some(gid))` when it is a
    /// symlink whose target is exactly `generations/<gen-id>/root` with a
    /// parseable generation id; an integrity error for ANY present-but-
    /// malformed entry (not a symlink, or a target that is not the exact
    /// canonical form — no `generations` component, unparseable id, missing
    /// `root` suffix, extra components, empty/absolute/`..` targets).
    ///
    /// `exists` FOLLOWS the link while `metadata` is an lstat: a DANGLING
    /// `current` (one whose target does not resolve) is still PRESENT here
    /// and validated rather than silently treated as absent. Both `status()`
    /// and `swap_current()` gate on this rule, so the exact-target contract
    /// lives in exactly one place.
    fn canonical_current_target(&self) -> Result<Option<GenerationId>> {
        let meta = self.remote.metadata(layout::current());
        let present =
            self.remote.exists(layout::current()) || matches!(&meta, Ok(m) if m.is_symlink);
        if !present {
            return Ok(None);
        }
        let meta = meta?;
        if !meta.is_symlink {
            // `current` exists but is not a symlink: malformed remote state.
            return Err(Error::integrity("current is not a symlink"));
        }
        let target = self.remote.read_link(layout::current())?;
        let gid = parse_canonical_current_target(&target).ok_or_else(|| {
            Error::integrity(format!(
                "current symlink target {target:?} is not the exact canonical generations/<gen-id>/root form"
            ))
        })?;
        Ok(Some(gid))
    }

    /// Atomically move `current` to the given generation. `expected` is the
    /// compare-and-swap precondition (the planned pre-push generation). When
    /// `expected` is `None` there is no precondition (first deployment).
    ///
    /// A PRESENT-but-malformed `current` link is NEVER overwritten: it is
    /// parsed exactly like [`Self::status`], and any deviation from the exact
    /// canonical `generations/<gen-id>/root` target fails with an integrity
    /// error — even with `expected = None` (the first-deployment path). Only
    /// genuine absence (no `current` entry at all) or an exact canonical
    /// target passes this gate; a canonical target then follows the CAS
    /// precondition below.
    ///
    /// Lock discipline: the CAS precondition alone is necessary but NOT
    /// sufficient — every caller MUST hold this server's mutation lock
    /// ([`Self::acquire_lock_guard`]) for the whole read-decide-swap window.
    /// The same rule governs [`Self::remove_current_if`]. A swap performed
    /// without the flock can race a concurrent activation between its status
    /// read and the rename.
    pub fn swap_current(&self, expected: Option<&str>, gen_id: &str, op_id: &str) -> Result<()> {
        // A present-but-malformed `current` (non-symlink, or a target that is
        // not the exact canonical `generations/<gen>/root` form with a
        // parseable id) fails closed here, so a corrupt link can never be
        // mistaken for absence and silently overwritten by a swap — even on
        // the first-deployment (`expected = None`) path.
        let actual = self.canonical_current_target()?;
        if let Some(actual) = &actual
            && let Some(exp) = expected
            && actual.as_str() != exp
        {
            return Err(Error::remote(format!(
                "compare-and-swap precondition failed: current generation is {:?}, expected {exp}",
                Some(actual.as_str())
            )));
        }
        let new_target = layout::generation(gen_id).join("root");
        let tmp_name = format!(".current.tmp.{op_id}");
        let tmp = Path::new(&tmp_name);
        // Remove any stale temp link.
        self.remote.remove_file(tmp)?;
        self.remote.symlink(new_target.as_path(), tmp)?;
        self.remote.rename(tmp, layout::current())?;
        self.remote.remove_file(tmp).ok();
        Ok(())
    }

    /// Remove the top-level `current` symlink (used for first-deploy
    /// compensation). `expected` makes the removal a compare-and-swap: the link
    /// is removed only if it currently points at `expected`, so a concurrent
    /// activation cannot be clobbered.
    /// Remove `current` only if it currently points at `expected`. Returns true
    /// if it was removed, false if `current` pointed elsewhere (or did not exist).
    pub fn remove_current_if(&self, expected: &str) -> Result<bool> {
        if !self.remote.exists(layout::current()) {
            return Ok(false);
        }
        let target = self.remote.read_link(layout::current())?;
        let comps: Vec<String> = target
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let actual = comps
            .iter()
            .position(|c| c == layout::GENERATIONS_COMPONENT)
            .and_then(|i| comps.get(i + 1).cloned());
        if actual.as_deref() == Some(expected) {
            self.remote.remove_file(layout::current())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Copy a host-local tree into a remote-relative path, reconstructing symlinks
/// and modes.
/// Parse a `current`-style link target as the EXACT canonical
/// `generations/<gen-id>/root` form: exactly three path components, the first
/// `generations`, the last `root`, and a middle component that parses as a
/// [`GenerationId`]. `Some(gid)` only for that exact shape; `None` for every
/// other target (no `generations` component, an unparseable id, a missing
/// `root` suffix, extra components, an empty target, an absolute path, `..`
/// traversal, ...). `Path::components` drops repeated separators and `.`
/// components and surfaces `..`/absolute components, so the exact three-
/// component shape is enforced on the normalized form.
fn parse_canonical_current_target(target: &Path) -> Option<GenerationId> {
    let comps: Vec<&str> = target
        .components()
        .map(|c| c.as_os_str().to_str().unwrap_or(""))
        .collect();
    if comps.len() != 3 || comps[0] != layout::GENERATIONS_COMPONENT || comps[2] != "root" {
        return None;
    }
    GenerationId::parse(comps[1]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ArtifactRef, TargetName};
    use crate::identity::{test_deployment_id, test_generation_id, test_tree_digest};
    use crate::remote::helper::GenerationAssignment;
    use crate::remote::transport::LocalTransport;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    fn assignment(gen_id: &str, tree: &str) -> GenerationAssignment {
        GenerationAssignment {
            deployment_id: test_deployment_id("deploy-1"),
            generation_id: test_generation_id(gen_id),
            artifact: ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-x"),
                variant: crate::identity::VariantName::new("standard".to_string()),
                tree: crate::identity::test_tree_digest(tree),
            },
            behavior_sha256: "b".to_string(),
            prior_generation: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            target: Some(TargetName::new("t1")),
        }
    }

    // ---- status() validates the complete symlink layout -------------------

    /// One piece of a hand-built remote layout. `None` (or a false flag)
    /// leaves that piece ABSENT, so every deviation from the canonical chain
    /// is expressible.
    #[derive(Clone, Debug, Default)]
    struct LayoutSpec {
        /// The top-level `current` entry; `None` installs no entry at all
        /// (genuine absence — the ONLY absence case).
        current: Option<CurrentLink>,
        /// The generation directory to create (by its id string); `None`
        /// leaves it absent.
        gen_id: Option<String>,
        /// `generations/<gen>/assignment.json` contents; `None` leaves the
        /// file absent.
        assignment: Option<Vec<u8>>,
        /// The generation's `root` entry; `None` leaves it absent.
        root: Option<RootLink>,
        /// The tree object directory `objects/sha256/<tree>/root` to create
        /// (keyed by its digest); `None` leaves it absent.
        tree: Option<String>,
    }

    #[derive(Clone, Debug)]
    enum CurrentLink {
        Symlink(String),
        PlainFile,
    }

    #[derive(Clone, Debug)]
    enum RootLink {
        Symlink(String),
        PlainFile,
    }

    impl LayoutSpec {
        /// A fully canonical chain exactly as `create_generation` +
        /// `swap_current` + `publish_tree` would produce it: `current` ->
        /// `generations/<gen>/root`, the canonical assignment, the canonical
        /// `../../objects/sha256/<tree>/root` generation root link, and the
        /// tree object directory.
        fn canonical(tag: &str, tree: &str) -> LayoutSpec {
            let gid = test_generation_id(tag);
            LayoutSpec {
                current: Some(CurrentLink::Symlink(format!(
                    "{}/{}/root",
                    layout::GENERATIONS_COMPONENT,
                    gid.as_str()
                ))),
                gen_id: Some(gid.as_str().to_string()),
                assignment: Some(assignment_json(tag, tree)),
                root: Some(RootLink::Symlink(
                    layout::generation_root_link(test_tree_digest(tree).as_str())
                        .to_string_lossy()
                        .into_owned(),
                )),
                tree: Some(test_tree_digest(tree).as_str().to_string()),
            }
        }

        /// Install the layout under `base`.
        fn install(&self, base: &Path) {
            match &self.current {
                Some(CurrentLink::Symlink(t)) => {
                    std::os::unix::fs::symlink(t, base.join("current")).unwrap();
                }
                Some(CurrentLink::PlainFile) => {
                    std::fs::write(base.join("current"), b"not a symlink").unwrap();
                }
                None => {}
            }
            if let Some(gid) = &self.gen_id {
                let gen_dir = base.join(layout::generation(gid));
                std::fs::create_dir_all(&gen_dir).unwrap();
                if let Some(bytes) = &self.assignment {
                    std::fs::write(gen_dir.join("assignment.json"), bytes).unwrap();
                }
                match &self.root {
                    Some(RootLink::Symlink(t)) => {
                        std::os::unix::fs::symlink(t, gen_dir.join("root")).unwrap();
                    }
                    Some(RootLink::PlainFile) => {
                        std::fs::write(gen_dir.join("root"), b"not a symlink").unwrap();
                    }
                    None => {}
                }
            }
            if let Some(tree) = &self.tree {
                std::fs::create_dir_all(base.join(layout::tree_root(tree))).unwrap();
            }
        }
    }

    /// Install `spec` into a fresh temp remote and run `f` under
    /// `catch_unwind` (a panic becomes a test failure at the `.expect`, so
    /// every layout asserts BOTH the expected outcome AND that the operation
    /// never panics).
    fn run_on_layout<T>(
        spec: &LayoutSpec,
        f: impl FnOnce(&RemoteHelper<'_>) -> Result<T>,
    ) -> Result<T> {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("remote");
        std::fs::create_dir_all(&base).unwrap();
        spec.install(&base);
        let remote = LocalTransport::new(base).unwrap();
        let helper = RemoteHelper::new(&remote);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&helper)))
            .expect("must never panic on a malformed layout")
    }

    /// A structurally valid assignment record for `gen_id` (its generation id
    /// matches the id it is built for).
    fn assignment_json(gen_id: &str, tree: &str) -> Vec<u8> {
        serde_json::to_vec(&assignment(gen_id, tree)).unwrap()
    }

    /// A remote with no `current` link reports NO current generation —
    /// genuine absence is the ONLY absence case.

    #[test]
    fn status_reports_none_when_current_link_absent() {
        let spec = LayoutSpec::default();
        let st = run_on_layout(&spec, |h| h.status()).expect("absence is not an error");
        assert!(st.current_generation.is_none());
        assert!(st.current_tree.is_none());
    }

    /// A `current` entry that is NOT a symlink (a plain file) is a malformed
    /// remote state: an integrity error, never a panic.
    #[test]
    fn status_fails_integrity_when_current_is_not_a_symlink() {
        let spec = LayoutSpec {
            current: Some(CurrentLink::PlainFile),
            ..LayoutSpec::default()
        };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("a plain-file current must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// A `current` link whose target has NO `generations` component is NOT
    /// absence: it is a malformed remote state and must fail closed with an
    /// integrity error — never a silent `None` (the old buggy contract
    /// reported `None`, which let a first-deployment swap overwrite the link).
    #[test]
    fn status_fails_integrity_for_link_without_generations_component() {
        for target in ["objects/sha256/x/root", "foo/bar", "root"] {
            let spec = LayoutSpec {
                current: Some(CurrentLink::Symlink(target.to_string())),
                ..LayoutSpec::default()
            };
            let err = run_on_layout(&spec, |h| h.status())
                .expect_err("a non-canonical current target must fail closed");
            assert!(
                err.to_string().contains("integrity"),
                "target {target:?} must fail with an integrity error, got: {err}"
            );
        }
    }

    /// EVERY malformed `current` target — an unparseable generation id, a
    /// missing `root` suffix, `generations` at a non-canonical position,
    /// extra components, an empty target, absolute/`..` traversal — is an
    /// integrity error, never a `None` and never a panic.
    #[test]
    fn status_fails_integrity_for_malformed_current_targets() {
        let valid_gid = test_generation_id("gen-any");
        let canonical = |gid: &str| format!("{}/{}/root", layout::GENERATIONS_COMPONENT, gid);
        for target in [
            "generations/not-a-gen-id/root".to_string(),
            "generations//root".to_string(),
            "generations/".to_string(),
            "generations".to_string(),
            format!("foo/generations/{}/root", valid_gid.as_str()),
            canonical(valid_gid.as_str()),
            format!("{}/extra", canonical(valid_gid.as_str())),
            format!("../{}", canonical(valid_gid.as_str())),
            format!("/{}", canonical(valid_gid.as_str())),
            format!(
                "{}/{}/ROOT",
                layout::GENERATIONS_COMPONENT,
                valid_gid.as_str()
            ),
            "".to_string(),
            "not a path at all!!".to_string(),
        ] {
            let spec = LayoutSpec {
                current: Some(CurrentLink::Symlink(target.clone())),
                ..LayoutSpec::default()
            };
            let err = run_on_layout(&spec, |h| h.status())
                .expect_err("a malformed current target must fail closed");
            assert!(
                err.to_string().contains("integrity"),
                "target {target:?} must fail with an integrity error, got: {err}"
            );
        }
    }

    /// A `current` link naming a generation whose DIRECTORY does not exist is
    /// a malformed remote state: an integrity error, never a panic.
    #[test]
    fn status_fails_integrity_for_missing_generation_dir() {
        let gid = test_generation_id("gen-missing-dir");
        let spec = LayoutSpec {
            current: Some(CurrentLink::Symlink(format!(
                "{}/{}/root",
                layout::GENERATIONS_COMPONENT,
                gid.as_str()
            ))),
            ..LayoutSpec::default()
        };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("a dangling current link must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// A `current` link naming a generation whose `assignment.json` is
    /// MISSING is a malformed remote state: an integrity error, never a
    /// panic.
    #[test]
    fn status_fails_integrity_for_missing_assignment() {
        let gid = test_generation_id("gen-missing-asn");
        let spec = LayoutSpec {
            current: Some(CurrentLink::Symlink(format!(
                "{}/{}/root",
                layout::GENERATIONS_COMPONENT,
                gid.as_str()
            ))),
            gen_id: Some(gid.as_str().to_string()),
            ..LayoutSpec::default()
        };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("a generation without an assignment must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// A `current` link naming a generation whose `assignment.json` is
    /// CORRUPT (unparseable) is a malformed remote state: an integrity
    /// error, never a panic.
    #[test]
    fn status_fails_integrity_for_corrupt_assignment() {
        let gid = test_generation_id("gen-corrupt-asn");
        let spec = LayoutSpec {
            current: Some(CurrentLink::Symlink(format!(
                "{}/{}/root",
                layout::GENERATIONS_COMPONENT,
                gid.as_str()
            ))),
            gen_id: Some(gid.as_str().to_string()),
            assignment: Some(b"{ corrupt json !".to_vec()),
            ..LayoutSpec::default()
        };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("a corrupt assignment must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// A `current` link naming a generation whose `assignment.json` carries a
    /// DIFFERENT generation id than its directory is a malformed remote
    /// state: an integrity error, never a panic.
    #[test]
    fn status_fails_integrity_for_mismatched_assignment_id() {
        let dir_gid = test_generation_id("gen-dir");
        let spec = LayoutSpec {
            current: Some(CurrentLink::Symlink(format!(
                "{}/{}/root",
                layout::GENERATIONS_COMPONENT,
                dir_gid.as_str()
            ))),
            gen_id: Some(dir_gid.as_str().to_string()),
            assignment: Some(assignment_json("gen-other", "tree-a")),
            ..LayoutSpec::default()
        };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("an assignment naming a different generation must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// The generation's `root` symlink is MISSING: an integrity error, never
    /// a panic.
    #[test]
    fn status_fails_integrity_for_missing_root_link() {
        let spec = LayoutSpec::canonical("gen-no-root", "tree-a");
        let spec = LayoutSpec { root: None, ..spec };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("a generation without its root symlink must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// The generation's `root` symlink points at a DIFFERENT target than the
    /// canonical `../../objects/sha256/<tree>/root` for the assignment's
    /// tree: an integrity error, never a panic.
    #[test]
    fn status_fails_integrity_for_wrong_root_link_target() {
        for wrong in [
            // Missing the leading `..`/`..` traversal.
            format!(
                "objects/sha256/{}/root",
                test_tree_digest("tree-a").as_str()
            ),
            // The canonical target for a DIFFERENT tree.
            layout::generation_root_link(test_tree_digest("tree-b").as_str())
                .to_string_lossy()
                .into_owned(),
            // Garbage.
            "garbage-target".to_string(),
        ] {
            let spec = LayoutSpec::canonical("gen-wrong-root", "tree-a");
            let spec = LayoutSpec {
                root: Some(RootLink::Symlink(wrong.clone())),
                ..spec
            };
            let err = run_on_layout(&spec, |h| h.status())
                .expect_err("a wrong generation root target must fail closed");
            assert!(
                err.to_string().contains("integrity"),
                "root target {wrong:?} must fail with an integrity error, got: {err}"
            );
        }
    }

    /// The generation's `root` entry is NOT a symlink (a plain file): an
    /// integrity error, never a panic.
    #[test]
    fn status_fails_integrity_for_root_link_not_a_symlink() {
        let spec = LayoutSpec::canonical("gen-file-root", "tree-a");
        let spec = LayoutSpec {
            root: Some(RootLink::PlainFile),
            ..spec
        };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("a plain-file generation root must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// The tree object directory `objects/sha256/<tree>/root` is MISSING: an
    /// integrity error, never a panic.
    #[test]
    fn status_fails_integrity_for_missing_tree_object() {
        let spec = LayoutSpec::canonical("gen-no-tree", "tree-a");
        let spec = LayoutSpec { tree: None, ..spec };
        let err = run_on_layout(&spec, |h| h.status())
            .expect_err("a generation without its tree object must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
    }

    /// A fully VALID chain (`current` -> `generations/<gen>/root` -> the
    /// canonical generation `root` symlink -> the matching `assignment.json`,
    /// with the tree object present) reports the VALIDATED generation id and
    /// its tree.
    #[test]
    fn status_reports_validated_generation_and_tree() {
        let gid = test_generation_id("gen-ok");
        let spec = LayoutSpec::canonical("gen-ok", "tree-a");
        let st = run_on_layout(&spec, |h| h.status())
            .expect("a fully consistent chain must report the validated generation");
        assert_eq!(st.current_generation, Some(gid));
        assert_eq!(
            st.current_tree.as_deref(),
            Some(test_tree_digest("tree-a").as_str())
        );
    }

    // ---- swap_current() never overwrites a malformed present link ----------

    /// A PRESENT-but-malformed `current` link makes `swap_current` fail
    /// closed with an integrity error — even with `expected = None` (the
    /// first-deployment path) — and the malformed link is left byte-
    /// identical. This is the reported bug: a malformed link was previously
    /// mistaken for absence, so the first-deployment swap silently
    /// overwrote it.
    #[test]
    fn swap_rejects_malformed_present_current() {
        for target in [
            "objects/sha256/x/root",
            "generations/not-a-gen-id/root",
            "generations/",
            "",
        ] {
            let spec = LayoutSpec {
                current: Some(CurrentLink::Symlink(target.to_string())),
                ..LayoutSpec::default()
            };
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("remote");
            std::fs::create_dir_all(&base).unwrap();
            spec.install(&base);
            let remote = LocalTransport::new(base.clone()).unwrap();
            let helper = RemoteHelper::new(&remote);
            let new_gen = GenerationId::generate();
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                helper.swap_current(None, new_gen.as_str(), "op")
            }))
            .expect("swap must never panic on a malformed current link")
            .expect_err("a malformed present current must never be swapped over");
            assert!(
                err.to_string().contains("integrity"),
                "target {target:?} must fail with an integrity error, got: {err}"
            );
            // The malformed link is untouched (byte-identical target).
            assert_eq!(
                std::fs::read_link(base.join("current")).unwrap(),
                Path::new(target),
                "a failed swap must leave the current link unchanged"
            );
            // The CAS form (with an expected generation) fails the same way.
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                helper.swap_current(Some(new_gen.as_str()), new_gen.as_str(), "op")
            }))
            .expect("swap must never panic on a malformed current link")
            .expect_err("a malformed present current must fail even with an expected generation");
            assert!(
                err.to_string().contains("integrity"),
                "target {target:?} must fail with an integrity error, got: {err}"
            );
            assert_eq!(
                std::fs::read_link(base.join("current")).unwrap(),
                Path::new(target),
                "a failed swap must leave the current link unchanged"
            );
        }
    }

    /// A `current` entry that is a PLAIN FILE (not a symlink) is malformed:
    /// `swap_current` must refuse it with an integrity error and leave the
    /// entry untouched.
    #[test]
    fn swap_fails_integrity_when_current_is_not_a_symlink() {
        let spec = LayoutSpec {
            current: Some(CurrentLink::PlainFile),
            ..LayoutSpec::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("remote");
        std::fs::create_dir_all(&base).unwrap();
        spec.install(&base);
        let remote = LocalTransport::new(base.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        let new_gen = GenerationId::generate();
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            helper.swap_current(None, new_gen.as_str(), "op")
        }))
        .expect("swap must never panic on a plain-file current")
        .expect_err("a plain-file current must never be swapped over");
        assert!(
            err.to_string().contains("integrity"),
            "error must be an integrity error, got: {err}"
        );
        assert_eq!(
            std::fs::read(base.join("current")).unwrap(),
            b"not a symlink".to_vec(),
            "a failed swap must leave the current entry untouched"
        );
    }

    /// GENUINE absence (no `current` entry at all) is the only case where the
    /// first-deployment swap proceeds: `swap_current(None, ...)` succeeds and
    /// installs the canonical target.
    #[test]
    fn swap_succeeds_on_genuine_absence() {
        let spec = LayoutSpec::default();
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("remote");
        std::fs::create_dir_all(&base).unwrap();
        spec.install(&base);
        let remote = LocalTransport::new(base.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        let new_gen = GenerationId::generate();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            helper.swap_current(None, new_gen.as_str(), "op")
        }))
        .expect("swap must never panic on genuine absence")
        .expect("first deployment over genuine absence must succeed");
        let target = std::fs::read_link(base.join("current")).unwrap();
        assert_eq!(
            target,
            layout::generation(new_gen.as_str()).join("root"),
            "the swap must install the canonical current target"
        );
    }

    /// Over a CANONICAL chain the CAS semantics are preserved: matching
    /// expected (or `None`) proceeds, a mismatched expected refuses with the
    /// remote CAS error and leaves the link untouched.
    #[test]
    fn swap_over_canonical_chain_keeps_cas_semantics() {
        let spec = LayoutSpec::canonical("gen-cas", "tree-a");
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("remote");
        std::fs::create_dir_all(&base).unwrap();
        spec.install(&base);
        let remote = LocalTransport::new(base.clone()).unwrap();
        let helper = RemoteHelper::new(&remote);
        let cas_gid = test_generation_id("gen-cas");
        let next_gen = GenerationId::generate();
        let cas_target = format!(
            "{}/{}/root",
            layout::GENERATIONS_COMPONENT,
            cas_gid.as_str()
        );

        // Mismatched expected: refuse (remote CAS error), link untouched.
        let err = helper
            .swap_current(Some(next_gen.as_str()), next_gen.as_str(), "op")
            .expect_err("a mismatched CAS precondition must refuse");
        assert!(
            err.to_string().contains("compare-and-swap"),
            "error must name the CAS precondition, got: {err}"
        );
        assert_eq!(
            std::fs::read_link(base.join("current")).unwrap(),
            Path::new(&cas_target),
            "a refused swap must leave the current link unchanged"
        );

        // Matching expected: proceeds and moves the link.
        helper
            .swap_current(Some(cas_gid.as_str()), next_gen.as_str(), "op")
            .expect("a matching CAS precondition must swap");
        assert_eq!(
            std::fs::read_link(base.join("current")).unwrap(),
            layout::generation(next_gen.as_str()).join("root")
        );
    }

    // ---- PROPERTY: arbitrary layouts never panic status or swap ------------

    /// A generation id: either a VALID `gen-<uuid-v7>` (derived from an
    /// arbitrary tag, so distinct tags yield distinct valid ids) or an
    /// arbitrary malformed string (wrong prefix, empty, garbage).
    fn arbitrary_gen_id() -> impl Strategy<Value = String> {
        prop_oneof![
            // Valid: gen-<uuid-v7> derived from an arbitrary tag.
            "[a-z0-9]{1,16}".prop_map(|tag| format!("gen-{}", crate::identity::test_uuid_v7(&tag))),
            // Malformed: wrong prefix, empty, garbage.
            "[a-zA-Z0-9]{0,40}",
        ]
    }

    /// A VALID canonical generation id (`gen-<uuid-v7>` derived from a tag).
    fn valid_gen_id() -> impl Strategy<Value = String> {
        "[a-z0-9]{1,16}".prop_map(|tag| format!("gen-{}", crate::identity::test_uuid_v7(&tag)))
    }

    /// A tree digest: either a VALID 64-hex digest (derived from a tag) or
    /// arbitrary garbage (so a canonical root-link target / tree directory
    /// derived from it may not be a valid digest at all).
    fn arbitrary_tree() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z0-9]{1,32}".prop_map(|tag| crate::identity::test_sha256_hex(&tag)),
            "[a-zA-Z0-9]{0,70}",
        ]
    }

    /// Arbitrary `current` symlink targets: exact canonical
    /// `generations/<id>/root`, canonical-with-malformed-id, `generations/
    /// <id>` without the `root` suffix, extra components
    /// (`foo/generations/<id>/root`), no-`generations` paths, and arbitrary
    /// garbage (including empty).
    fn arbitrary_current_target() -> impl Strategy<Value = String> {
        prop_oneof![
            // Canonical shape with an ARBITRARY id (valid or malformed).
            (
                Just(layout::GENERATIONS_COMPONENT.to_string()),
                arbitrary_gen_id(),
                Just("root".to_string()),
            )
                .prop_map(|(g, id, r)| format!("{g}/{id}/{r}")),
            // generations/<id> without the root suffix.
            (
                Just(layout::GENERATIONS_COMPONENT.to_string()),
                arbitrary_gen_id(),
            )
                .prop_map(|(g, id)| format!("{g}/{id}")),
            // Extra component: foo/generations/<id>/root.
            (
                Just("foo".to_string()),
                Just(layout::GENERATIONS_COMPONENT.to_string()),
                arbitrary_gen_id(),
                Just("root".to_string()),
            )
                .prop_map(|(f, g, id, r)| format!("{f}/{g}/{id}/{r}")),
            // No generations component: arbitrary path-ish garbage.
            "[a-zA-Z0-9/._-]{1,60}",
            // Arbitrary printable garbage (may or may not contain
            // `generations` as a component; may be empty).
            "[ -~]{0,60}",
        ]
    }

    /// Arbitrary `assignment.json` contents: a structurally VALID record
    /// whose generation id may or may not match the directory it is installed
    /// under and whose tree may be valid or garbage, corrupt JSON, and
    /// arbitrary bytes.
    fn arbitrary_assignment_content() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // A structurally valid record.
            (arbitrary_gen_id(), arbitrary_tree()).prop_map(|(gid, tree)| {
                serde_json::to_vec(&serde_json::json!({
                    "deployment_id": format!("deploy-{}", crate::identity::test_uuid_v7("prop")),
                    "generation_id": gid,
                    "artifact": {
                        "release": format!("rel-sha256-{}", "0".repeat(64)),
                        "variant": "standard",
                        "tree": tree,
                    },
                    "behavior_sha256": "0".repeat(64),
                    "created_at": "2020-01-01T00:00:00Z",
                }))
                .expect("the generated record serializes")
            }),
            // Corrupt JSON.
            Just(b"{ corrupt json !".to_vec()),
            // Arbitrary bytes.
            prop::collection::vec(any::<u8>(), 0..64),
        ]
    }

    /// One piece of a generated remote layout.
    #[derive(Clone, Debug)]
    struct PropLayout {
        /// The top-level `current` entry; `None` = no entry (genuine
        /// absence).
        current: Option<CurrentKind>,
        /// Install the generation directory `generations/<G>/` (G = the
        /// canonical id parsed from `current` when it has one).
        gen_dir: bool,
        /// `generations/<G>/assignment.json` contents; `None` = no file.
        assignment: Option<Vec<u8>>,
        /// The generation `root` entry; `None` = no entry.
        root: Option<RootKind>,
        /// Create the tree object directory `objects/sha256/<T>/root` for the
        /// tree parsed from the assignment (when it parses to a valid digest).
        tree_dir: bool,
    }

    #[derive(Clone, Debug)]
    enum CurrentKind {
        Symlink(String),
        PlainFile,
    }

    #[derive(Clone, Debug)]
    enum RootKind {
        Symlink(String),
        PlainFile,
    }

    /// A fully consistent chain, exactly as the write path would produce it:
    /// `current` -> `generations/<G>/root`, the canonical assignment for G
    /// (tree T), the generation `root` link -> `../../objects/sha256/<T>/root`,
    /// and the tree object directory present.
    fn consistent_layout() -> impl Strategy<Value = PropLayout> {
        ("[a-z0-9]{1,16}", "[a-z0-9]{1,32}").prop_map(|(g_tag, t_tag)| {
            let gid = format!("gen-{}", crate::identity::test_uuid_v7(&g_tag));
            let tree = crate::identity::test_sha256_hex(&t_tag);
            PropLayout {
                current: Some(CurrentKind::Symlink(format!(
                    "{}/{}/root",
                    layout::GENERATIONS_COMPONENT,
                    gid
                ))),
                gen_dir: true,
                assignment: Some(assignment_json(&g_tag, &t_tag)),
                root: Some(RootKind::Symlink(
                    layout::generation_root_link(&tree)
                        .to_string_lossy()
                        .into_owned(),
                )),
                tree_dir: true,
            }
        })
    }

    /// Arbitrary `current` entry kinds: symlink with an arbitrary target, or
    /// a plain file.
    fn arbitrary_current_kind() -> impl Strategy<Value = CurrentKind> {
        prop_oneof![
            arbitrary_current_target().prop_map(CurrentKind::Symlink),
            Just(CurrentKind::PlainFile),
        ]
    }

    /// Arbitrary generation `root` entries: canonical-for-an-arbitrary-tree,
    /// garbage target, or a plain file.
    fn arbitrary_root_kind() -> impl Strategy<Value = RootKind> {
        prop_oneof![
            arbitrary_tree().prop_map(|t| RootKind::Symlink(
                layout::generation_root_link(&t)
                    .to_string_lossy()
                    .into_owned()
            )),
            "[a-zA-Z0-9/._-]{1,60}".prop_map(RootKind::Symlink),
            Just(RootKind::PlainFile),
        ]
    }

    /// An arbitrary layout: every piece generated independently (absent
    /// pieces included).
    fn arbitrary_layout() -> impl Strategy<Value = PropLayout> {
        (
            prop::option::weighted(0.95, arbitrary_current_kind()),
            any::<bool>(),
            prop::option::weighted(0.8, arbitrary_assignment_content()),
            prop::option::weighted(0.8, arbitrary_root_kind()),
            any::<bool>(),
        )
            .prop_map(
                |(current, gen_dir, assignment, root, tree_dir)| PropLayout {
                    current,
                    gen_dir,
                    assignment,
                    root,
                    tree_dir,
                },
            )
    }

    /// One generated layout, biased so fully consistent chains occur
    /// regularly (otherwise the "Ok with a validated generation" arm would
    /// rarely be exercised).
    fn any_layout() -> impl Strategy<Value = PropLayout> {
        prop_oneof![consistent_layout(), arbitrary_layout()]
    }

    /// Install a generated layout: the `current` entry, the generation
    /// directory the canonical target names (with the assignment and `root`
    /// entry), and the tree object directory the assignment names.
    fn install_prop_layout(layout: &PropLayout, base: &Path) {
        match &layout.current {
            Some(CurrentKind::Symlink(t)) => {
                std::os::unix::fs::symlink(t, base.join("current")).unwrap();
            }
            Some(CurrentKind::PlainFile) => {
                std::fs::write(base.join("current"), b"not a symlink").unwrap();
            }
            None => {}
        }
        let current_gid = match &layout.current {
            Some(CurrentKind::Symlink(t)) => {
                parse_canonical_current_target(Path::new(t)).map(|g| g.as_str().to_string())
            }
            _ => None,
        };
        if layout.gen_dir
            && let Some(gid) = &current_gid
        {
            let gen_dir = base.join(layout::generation(gid));
            std::fs::create_dir_all(&gen_dir).unwrap();
            if let Some(bytes) = &layout.assignment {
                std::fs::write(gen_dir.join("assignment.json"), bytes).unwrap();
            }
            match &layout.root {
                Some(RootKind::Symlink(t)) => {
                    std::os::unix::fs::symlink(t, gen_dir.join("root")).unwrap();
                }
                Some(RootKind::PlainFile) => {
                    std::fs::write(gen_dir.join("root"), b"not a symlink").unwrap();
                }
                None => {}
            }
        }
        // The tree object directory, keyed by the tree a parseable
        // assignment names.
        if layout.tree_dir
            && let Some((_, tree)) = layout.assignment.as_deref().and_then(|b| {
                serde_json::from_slice::<GenerationAssignment>(b)
                    .ok()
                    .map(|a| {
                        (
                            a.generation_id.as_str().to_string(),
                            a.artifact.tree.as_str().to_string(),
                        )
                    })
            })
        {
            std::fs::create_dir_all(base.join(layout::tree_root(&tree))).unwrap();
        }
    }

    proptest! {
        // PROPERTY (the directive's point 4): generate ARBITRARY remote
        // layouts — arbitrary `current` targets (canonical,
        // canonical-with-malformed-id, no `root` suffix, extra components, no
        // `generations`, garbage, empty, absent, plain-file), arbitrary
        // generation `root` targets (canonical, wrong tree, garbage, absent,
        // plain-file), arbitrary assignment contents (valid
        // matching/mismatching, corrupt, arbitrary bytes, absent), and
        // arbitrary path existence (generation dir / tree object dir / root
        // link / assignment file). Then:
        //
        // * `status()` NEVER panics; it reports `None` ONLY for genuine
        //   absence of `current`; it reports a generation ONLY when the
        //   ENTIRE chain is consistent (exact canonical current target,
        //   existing generation dir, valid matching assignment, exact
        //   canonical root link, existing tree object); every other layout
        //   fails with an integrity error.
        // * `swap_current(None, ...)` NEVER panics; it succeeds ONLY when
        //   `current` is genuinely absent or its target is the exact
        //   canonical form (the swap-visible consistency contract); any
        //   malformed-present layout fails with an integrity error and the
        //   `current` entry is left byte-identical.
        //
        // Bounded 64 cases, fixed seed 0x5EED_5EED (house style), no
        // persistence. `catch_unwind` turns a panic into a test failure at
        // the `.expect`.
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn status_and_swap_never_panic_and_validate_the_full_chain_on_arbitrary_layouts(
            layout in any_layout(),
            new_gen in valid_gen_id(),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("remote");
            std::fs::create_dir_all(&base).unwrap();
            install_prop_layout(&layout, &base);
            let remote = LocalTransport::new(base.clone()).unwrap();
            let helper = RemoteHelper::new(&remote);

            // The generation named by a canonical `current` target and the
            // tree named by a parseable assignment — the two facts the
            // consistency check needs. Both mirror the code's OWN strict
            // parse (an invalid wire identity fails the assignment parse,
            // exactly like `read_assignment`).
            let current_gid: Option<String> = match &layout.current {
                Some(CurrentKind::Symlink(t)) => {
                    parse_canonical_current_target(Path::new(t)).map(|g| g.as_str().to_string())
                }
                _ => None,
            };
            let assignment_parsed: Option<(String, String)> = layout.assignment.as_deref().and_then(
                |b| {
                    serde_json::from_slice::<GenerationAssignment>(b)
                        .ok()
                        .map(|a| {
                            (
                                a.generation_id.as_str().to_string(),
                                a.artifact.tree.as_str().to_string(),
                            )
                        })
                },
            );
            let consistent = match (
                &layout.current,
                current_gid.as_deref(),
                assignment_parsed.as_ref(),
            ) {
                (Some(CurrentKind::Symlink(_)), Some(g), Some((a_gid, tree))) => {
                    layout.gen_dir
                        && a_gid == g
                        && matches!(&layout.root, Some(RootKind::Symlink(t))
                            if t.as_str() == layout::generation_root_link(tree).to_string_lossy().as_ref())
                        && layout.tree_dir
                }
                _ => false,
            };

            // ---- status() ----
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| helper.status()))
                .expect("status must never panic on arbitrary symlink layouts");
            match result {
                Ok(st) => {
                    if layout.current.is_none() {
                        assert!(
                            st.current_generation.is_none() && st.current_tree.is_none(),
                            "genuine absence must report no current generation, got {st:?}"
                        );
                    } else {
                        assert!(
                            consistent,
                            "status must not succeed on an inconsistent layout, got {st:?}"
                        );
                        assert_eq!(
                            st.current_generation.as_ref().map(|g| g.as_str()),
                            Some(current_gid.as_deref().unwrap()),
                            "the validated generation must be the canonical target's id"
                        );
                        assert_eq!(
                            st.current_tree.as_deref(),
                            Some(assignment_parsed.as_ref().unwrap().1.as_str()),
                            "the validated tree must be the assignment's tree"
                        );
                    }
                }
                Err(e) => {
                    if layout.current.is_none() {
                        panic!("genuine absence must not error, got: {e}");
                    }
                    assert!(
                        !consistent,
                        "a fully consistent chain must not error, got: {e}"
                    );
                    assert!(
                        e.to_string().contains("integrity"),
                        "every inconsistent layout must fail with an integrity error, got: {e}"
                    );
                }
            }

            // ---- swap_current(None, ...): never panic; succeed only on
            // genuine absence or an exact canonical current target;
            // malformed-present must fail and leave the entry unchanged. ----
            let swap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                helper.swap_current(None, new_gen.as_str(), "op")
            }))
            .expect("swap must never panic on arbitrary symlink layouts");
            match swap {
                Ok(()) => {
                    assert!(
                        layout.current.is_none() || current_gid.is_some(),
                        "swap must not succeed over a malformed present current"
                    );
                    // The swap installed the canonical target for the new gen.
                    assert_eq!(
                        std::fs::read_link(base.join("current")).unwrap(),
                        layout::generation(new_gen.as_str()).join("root")
                    );
                }
                Err(e) => {
                    assert!(
                        layout.current.is_some() && current_gid.is_none(),
                        "swap failed for an unexpected reason: {e}"
                    );
                    assert!(
                        e.to_string().contains("integrity"),
                        "a refused swap must be an integrity error, got: {e}"
                    );
                    // The entry is byte-identical after the failed swap.
                    match &layout.current {
                        Some(CurrentKind::Symlink(t)) => assert_eq!(
                            std::fs::read_link(base.join("current")).unwrap(),
                            Path::new(t),
                            "a failed swap must leave the current link unchanged"
                        ),
                        Some(CurrentKind::PlainFile) => assert_eq!(
                            std::fs::read(base.join("current")).unwrap(),
                            b"not a symlink".to_vec(),
                            "a failed swap must leave the current entry unchanged"
                        ),
                        None => {}
                    }
                }
            }
        }
    }
}

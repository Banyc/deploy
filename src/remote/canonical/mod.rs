//! Canonical tree content: canonicalization and materialization.
//!
//! The canonical tree objects ([`canonicalize_tree`], [`compute_tree_digest`],
//! [`entry_paths`]) lead this module; mapping/template materialization
//! ([`materialize_variant`], [`TemplateVars`], [`render_template`],
//! [`render_argv`]) lives in the `materialize` submodule.
//!
//! The canonical format is a cross-module contract: the store verifies
//! objects against it ([`crate::store::local::LocalStore::store_object`]),
//! recovery and pre-activation checks re-hash with it
//! ([`crate::deploy::push::push`]), and the SSH transport must preserve exactly
//! these bytes on upload. Any module that serializes or transfers tree bytes
//! diverging from this format silently breaks digest equality for every other
//! verifier.

mod materialize;

pub use materialize::{
    ELECTED_VARIABLES, TemplateVars, materialize_variant, render_argv, render_template,
    validate_template_variables,
};

use crate::digest::sha256_bytes;
use crate::error::{Error, Result};
use crate::identity::{TreeEntry, TreeMetadata};
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

/// [`canonicalize_tree`] emits exactly this value and
/// [`crate::store::local::LocalStore::read_tree_meta`] refuses any other
/// version (fail closed).
pub(crate) const TREE_SCHEMA_VERSION: u32 = 1;

fn fmt_mode(m: u32) -> String {
    format!("{:04o}", m & 0o7777)
}

/// Lexically normalize a path, collapsing `.` and `..`, returning `None` if it
/// escapes the base directory.
fn normalize_lexical(base: &Path, rel: &Path) -> Option<PathBuf> {
    let mut out = base.to_path_buf();
    for comp in rel.components() {
        use std::path::Component::*;
        match comp {
            Prefix(_) | RootDir => return None,
            CurDir => {}
            ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Normal(c) => out.push(c),
        }
    }
    Some(out)
}

/// Canonicalize a directory into a [`TreeMetadata`] and compute its digest.
///
/// Rejects absolute paths, `..`, NUL bytes, duplicate normalized paths,
/// escaping/absolute symbolic links, devices, sockets, FIFOs, and hard links.
pub fn canonicalize_tree(root: &Path) -> Result<TreeMetadata> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let root_c = root
        .canonicalize()
        .map_err(|e| Error::materialization(format!("canonicalize {}: {e}", root.display())))?;

    for entry in WalkDir::new(root).min_depth(1).into_iter() {
        let entry = entry.map_err(|e| Error::materialization(format!("walk {e}")))?;
        let path = entry.path();
        let rel_os = path
            .strip_prefix(root)
            .map_err(|e| Error::materialization(format!("{e}")))?;

        // Unicode NFC normalization and reject NUL bytes.
        let rel_str = rel_os.to_string_lossy();
        if rel_str.contains('\0') {
            return Err(Error::materialization(format!(
                "path contains NUL bytes: {}",
                path.display()
            )));
        }
        let normalized: String = rel_str.nfc().collect();
        // Reject TRAVERSAL components — an exact `..` (or `.`) path
        // COMPONENT, never a substring: a legitimate filename like `a..b`
        // or `..hidden` contains ".." but is not traversal. The component
        // check splits on '/' and refuses only the exact traversal names.
        if normalized.split('/').any(|c| c == ".." || c == ".") {
            return Err(Error::materialization(format!(
                "path contains traversal components: {normalized}"
            )));
        }
        if normalized.starts_with('/') {
            return Err(Error::materialization(format!(
                "absolute path not allowed: {normalized}"
            )));
        }
        if !seen.insert(normalized.clone()) {
            return Err(Error::materialization(format!(
                "duplicate normalized path: {normalized}"
            )));
        }

        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| Error::materialization(format!("stat {}: {e}", path.display())))?;

        let entry_type;
        let mut mode = fmt_mode(meta.mode());
        let mut content_sha256 = None;
        let mut symlink_target = None;

        if meta.is_dir() {
            entry_type = "dir";
        } else if meta.is_symlink() {
            entry_type = "symlink";
            let target = std::fs::read_link(path)
                .map_err(|e| Error::materialization(format!("readlink {}: {e}", path.display())))?;
            if target.is_absolute() {
                return Err(Error::materialization(format!(
                    "absolute symlink not allowed: {}",
                    path.display()
                )));
            }
            // Ensure target resolves inside the artifact root.
            let resolved = normalize_lexical(&root_c, &target);
            match resolved {
                Some(r) if r.starts_with(&root_c) => {}
                _ => {
                    return Err(Error::materialization(format!(
                        "escaping symlink not allowed: {}",
                        path.display()
                    )));
                }
            }
            let target_bytes = target.into_os_string().into_encoded_bytes();
            content_sha256 = Some(sha256_bytes(&target_bytes));
            symlink_target = Some(String::from_utf8_lossy(&target_bytes).into_owned());
            mode = "0777".to_string();
        } else if meta.is_file() {
            entry_type = "file";
            if meta.nlink() > 1 {
                return Err(Error::materialization(format!(
                    "hard links not allowed: {}",
                    path.display()
                )));
            }
            let data = std::fs::read(path)
                .map_err(|e| Error::materialization(format!("read {}: {e}", path.display())))?;
            content_sha256 = Some(sha256_bytes(&data));
        } else {
            return Err(Error::materialization(format!(
                "unsupported file type at {}",
                path.display()
            )));
        }

        entries.push(TreeEntry {
            path: normalized,
            entry_type: entry_type.to_string(),
            mode,
            content_sha256,
            symlink_target,
        });
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut meta = TreeMetadata {
        tree_schema_version: TREE_SCHEMA_VERSION,
        hash_algorithm: "sha256".to_string(),
        tree_sha256: String::new(),
        entries,
    };
    meta.tree_sha256 = compute_tree_digest(&meta);
    Ok(meta)
}

/// Verify that a stored [`TreeMetadata`] is EXACTLY the canonical metadata of
/// the tree content at `root`: canonicalize the root and compare EVERY field
/// (schema version, hash algorithm, tree digest, and each entry's
/// path/type/mode/content_sha256/symlink_target). Returns the RECOMPUTED
/// canonical metadata on success; any mismatch is an [`Error::integrity`]
/// failure (fail closed — a metadata record whose fields were mutated while
/// the tree content was left unchanged is never returned as if it were the
/// canonical metadata for that content).
pub fn verify_tree_metadata(root: &Path, stored: &TreeMetadata) -> Result<TreeMetadata> {
    let canonical = canonicalize_tree(root).map_err(|e| {
        Error::integrity(format!(
            "tree content at {} cannot be canonicalized: {e}",
            root.display()
        ))
    })?;
    if stored.tree_schema_version != canonical.tree_schema_version {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: tree_schema_version {} != {}",
            root.display(),
            stored.tree_schema_version,
            canonical.tree_schema_version
        )));
    }
    if stored.hash_algorithm != canonical.hash_algorithm {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: hash_algorithm {:?} != {:?}",
            root.display(),
            stored.hash_algorithm,
            canonical.hash_algorithm
        )));
    }
    if stored.tree_sha256 != canonical.tree_sha256 {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: tree_sha256 {} != {}",
            root.display(),
            stored.tree_sha256,
            canonical.tree_sha256
        )));
    }
    if stored.entries.len() != canonical.entries.len() {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: {} entries != {} entries",
            root.display(),
            stored.entries.len(),
            canonical.entries.len()
        )));
    }
    for (i, (se, ce)) in stored
        .entries
        .iter()
        .zip(canonical.entries.iter())
        .enumerate()
    {
        if se.path != ce.path {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} path {:?} != {:?}",
                root.display(),
                se.path,
                ce.path
            )));
        }
        if se.entry_type != ce.entry_type {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) type {:?} != {:?}",
                root.display(),
                se.path,
                se.entry_type,
                ce.entry_type
            )));
        }
        if se.mode != ce.mode {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) mode {:?} != {:?}",
                root.display(),
                se.path,
                se.mode,
                ce.mode
            )));
        }
        if se.content_sha256 != ce.content_sha256 {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) content_sha256 {:?} != {:?}",
                root.display(),
                se.path,
                se.content_sha256,
                ce.content_sha256
            )));
        }
        if se.symlink_target != ce.symlink_target {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) symlink_target {:?} != {:?}",
                root.display(),
                se.path,
                se.symlink_target,
                ce.symlink_target
            )));
        }
    }
    Ok(canonical)
}

/// Compute the canonical tree digest from metadata. Deterministic, independent
/// of filesystem layout or source ordering.
pub fn compute_tree_digest(meta: &TreeMetadata) -> String {
    let bytes = serde_json::to_vec(meta).expect("tree metadata serializes");
    sha256_bytes(&bytes)
}

/// Build the artifact-relative path strings for a tree's entries (used by the
/// mapper and remote transfer).
pub fn entry_paths(meta: &TreeMetadata) -> Vec<&str> {
    meta.entries.iter().map(|e| e.path.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// Build a RICH tree (a file, a nested file, and a symlink) so every
    /// entry-field mutation class has a target entry to mutate. The symlink
    /// target is resolved relative to the tree ROOT (the canonicalizer's
    /// in-root rule), so `sub/link -> file.txt` stays inside the root.
    fn build_tree(root: &Path) {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("file.txt"), b"content").unwrap();
        std::fs::write(root.join("sub").join("nested.txt"), b"nested").unwrap();
        std::os::unix::fs::symlink("file.txt", root.join("sub").join("link")).unwrap();
    }

    /// A legitimate filename containing `..` as a SUBSTRING (e.g. `a..b`,
    /// `..hidden`) is NOT traversal — the component-wise check accepts it.
    /// (An exact `..` path component cannot be created on POSIX — it is the
    /// parent — so the rejection arm is defensive; the acceptance arm is the
    /// regression this test pins: the old substring check falsely rejected
    /// these valid filenames.)
    #[test]
    fn dotdot_substring_is_not_traversal() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a..b"), b"content").unwrap();
        std::fs::write(root.join("..hidden"), b"content").unwrap();
        let meta = canonicalize_tree(&root).unwrap();
        let paths: Vec<&str> = meta.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            paths.contains(&"a..b"),
            "a filename containing '..' as a substring is valid, got {paths:?}"
        );
        assert!(
            paths.contains(&"..hidden"),
            "a filename starting with '..' is valid, got {paths:?}"
        );
    }

    /// One systematically-mutated metadata field the verifier must reject
    /// while the tree root is left unchanged.
    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        TreeSha256,
        HashAlgorithm,
        SchemaVersion,
        EntryPath,
        EntryType,
        EntryMode,
        EntryContentSha256,
        EntrySymlinkTarget,
        RemoveEntry,
        AddEntry,
        ReorderEntries,
    }

    fn mutation() -> impl Strategy<Value = Mutation> {
        prop::sample::select(vec![
            Mutation::TreeSha256,
            Mutation::HashAlgorithm,
            Mutation::SchemaVersion,
            Mutation::EntryPath,
            Mutation::EntryType,
            Mutation::EntryMode,
            Mutation::EntryContentSha256,
            Mutation::EntrySymlinkTarget,
            Mutation::RemoveEntry,
            Mutation::AddEntry,
            Mutation::ReorderEntries,
        ])
    }

    /// Apply exactly ONE mutation to the canonical metadata, leaving the tree
    /// root untouched.
    fn apply_mutation(mut meta: TreeMetadata, m: Mutation) -> TreeMetadata {
        match m {
            Mutation::TreeSha256 => meta.tree_sha256 = "0".repeat(64),
            Mutation::HashAlgorithm => meta.hash_algorithm = "sha512".to_string(),
            Mutation::SchemaVersion => meta.tree_schema_version += 1,
            Mutation::EntryPath => meta.entries[0].path = "mutated.txt".to_string(),
            Mutation::EntryType => meta.entries[0].entry_type = "dir".to_string(),
            Mutation::EntryMode => meta.entries[0].mode = "0000".to_string(),
            Mutation::EntryContentSha256 => {
                meta.entries[0].content_sha256 = Some("0".repeat(64));
            }
            Mutation::EntrySymlinkTarget => {
                if let Some(e) = meta.entries.iter_mut().find(|e| e.symlink_target.is_some()) {
                    e.symlink_target = Some("../other.txt".to_string());
                }
            }
            Mutation::RemoveEntry => {
                meta.entries.pop();
            }
            Mutation::AddEntry => meta.entries.push(TreeEntry {
                path: "bogus.txt".to_string(),
                entry_type: "file".to_string(),
                mode: "0644".to_string(),
                content_sha256: Some("0".repeat(64)),
                symlink_target: None,
            }),
            Mutation::ReorderEntries => {
                meta.entries.swap(0, 1);
            }
        }
        meta
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        // THE CONTENT BINDING: the verifier compares the COMPLETE stored
        // metadata against freshly canonicalized metadata of the actual tree
        // content. Mutating ANY metadata field (tree_sha256, hash_algorithm,
        // schema version, an entry's path/type/mode/content_sha256/
        // symlink_target, entry count, ordering) while leaving the tree root
        // unchanged must be REJECTED; the unmutated metadata verifies and
        // returns the recomputed canonical value.
        #[test]
        fn mutated_metadata_is_rejected(m in mutation()) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let root = dir.path().join("tree");
            build_tree(&root);
            let canonical = canonicalize_tree(&root).unwrap();
            let mutated = apply_mutation(canonical.clone(), m);
            prop_assert!(
                verify_tree_metadata(&root, &mutated).is_err(),
                "mutation {m:?} of the stored metadata must be rejected while the tree root is unchanged"
            );
            // The unmutated metadata verifies and returns the RECOMPUTED
            // canonical value (never the stored bytes).
            let verified = verify_tree_metadata(&root, &canonical).unwrap();
            prop_assert_eq!(verified, canonical);
        }
    }
}

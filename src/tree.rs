//! Canonical tree objects.
//!
//! A tree is immutable filesystem content identified only by its digest. The
//! canonical form records normalized relative paths, entry types, modes, and
//! content digests. It deliberately excludes ownership, timestamps, ACLs, and
//! extended attributes (stripped in schema version 1).
//!
//! This canonical format is a cross-module contract: the mapper materializes
//! into it (`mapper.rs`), the store verifies objects against it
//! (`store/local.rs::store_object`), recovery and pre-activation checks
//! re-hash with it (`push/engine.rs`), and the SSH transport must preserve
//! exactly these bytes on upload — modes as raw octal in `list`, symlinks
//! pinned to a fixed recorded mode. Any module that serializes or transfers
//! tree bytes diverging from this format silently breaks digest equality for
//! every other verifier.

use crate::digest::sha256_bytes;
use crate::error::{Error, Result};
use crate::model::{TreeEntry, TreeMetadata};
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

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
        if normalized.contains("..") {
            return Err(Error::materialization(format!(
                "path contains '..': {normalized}"
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
        tree_schema_version: 1,
        hash_algorithm: "sha256".to_string(),
        tree_sha256: String::new(),
        entries,
    };
    meta.tree_sha256 = compute_tree_digest(&meta);
    Ok(meta)
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

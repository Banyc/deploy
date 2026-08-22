//! Mapping semantics: applies declarative `from -> to` mappings for one
//! variant to assemble a staging tree directory.
//!
//! * `from` is relative to the project root and must stay beneath it.
//! * `{{ variant }}` is the only interpolation variable.
//! * Mappings are applied in declaration order.
//! * Recursive directory mappings merge; their conflict policy applies to
//!   colliding descendant entries rather than deleting unrelated entries.

use crate::config::{ConflictPolicy, Mapping, resolved_mode};
use crate::error::{Error, Result};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

/// Normalize a path string to NFC and forward slashes.
pub fn normalize_rel(path: &Path) -> String {
    let s = path.to_string_lossy();
    s.nfc().collect::<String>().replace('\\', "/")
}

fn ensure_within_root(root: &Path, candidate: &Path) -> Result<PathBuf> {
    let root_c = root
        .canonicalize()
        .map_err(|e| Error::path(format!("canonicalize root {}: {e}", root.display())))?;
    let cand_c = candidate
        .canonicalize()
        .map_err(|e| Error::path(format!("canonicalize {}: {e}", candidate.display())))?;
    if !cand_c.starts_with(&root_c) {
        return Err(Error::path(format!(
            "path {} escapes project root",
            candidate.display()
        )));
    }
    Ok(cand_c)
}

/// Determine the concrete destination path inside `staging` for a source entry.
fn dest_for(staging: &Path, to: &str, src_is_dir: bool, rel: &Path) -> PathBuf {
    let to_p = Path::new(to);
    if src_is_dir {
        // recursive dir merge: each descendant is placed under `to/rel`
        staging.join(to_p).join(rel)
    } else {
        // single file/dir entry
        if to.ends_with('/') || to.is_empty() {
            staging.join(to_p).join(
                rel.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )
        } else {
            staging.join(to_p)
        }
    }
}

fn set_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    let m = mode.unwrap_or(0o755);
    let perms = std::fs::Permissions::from_mode(m);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::materialization(format!("set_permissions {}: {e}", path.display())))?;
    Ok(())
}

/// Copy a single source entry (file or symlink) to a destination, applying the
/// mapping mode override. When the override is `None` the source's own mode is
/// preserved (instead of defaulting to 0755). Directories are created with a
/// canonical 0755 mode.
fn copy_entry(src: &Path, dst: &Path, mode_override: Option<u32>) -> Result<()> {
    let ft = std::fs::symlink_metadata(src)
        .map_err(|e| Error::materialization(format!("stat {}: {e}", src.display())))?;
    if ft.is_dir() {
        std::fs::create_dir_all(dst)
            .map_err(|e| Error::materialization(format!("mkdir {}: {e}", dst.display())))?;
        let final_mode = mode_override.unwrap_or_else(|| ft.mode() & 0o7777);
        set_mode(dst, Some(final_mode))?;
        return Ok(());
    }
    if ft.is_symlink() {
        let target = std::fs::read_link(src)
            .map_err(|e| Error::materialization(format!("readlink {}: {e}", src.display())))?;
        // Reject escaping symlinks relative to the project root at copy time.
        if target.is_absolute() {
            return Err(Error::mapping(format!(
                "absolute symlink {} is not allowed",
                src.display()
            )));
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // remove existing dst if present (replace policy handled by caller)
        let _ = std::fs::remove_file(dst);
        std::os::unix::fs::symlink(&target, dst).map_err(|e| {
            Error::materialization(format!(
                "symlink {} -> {}: {e}",
                dst.display(),
                target.display()
            ))
        })?;
        return Ok(());
    }
    // Regular file: preserve the source mode unless an override is given.
    let source_mode = ft.mode() & 0o7777;
    let final_mode = mode_override.unwrap_or(source_mode);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::materialization(format!("mkdir {}: {e}", parent.display())))?;
    }
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst).map_err(|e| {
        Error::materialization(format!("copy {} -> {}: {e}", src.display(), dst.display()))
    })?;
    set_mode(dst, Some(final_mode))?;
    Ok(())
}

/// Defensively verify that a computed destination stays beneath the staging
/// root, rejecting any path that escapes it.
fn ensure_within_dest(dest_root: &Path, dst: &Path) -> Result<()> {
    dst.strip_prefix(dest_root).map_err(|_| {
        Error::mapping(format!(
            "computed destination '{}' escapes staging root '{}'",
            dst.display(),
            dest_root.display()
        ))
    })?;
    Ok(())
}

/// Apply all mappings for `variant` to assemble a complete staging tree at
/// `dest`. `dest` is created/cleared before mapping.
pub fn materialize_variant(
    root: &Path,
    mappings: &[Mapping],
    variant: &str,
    dest: &Path,
) -> Result<()> {
    if dest.exists() {
        std::fs::remove_dir_all(dest)
            .map_err(|e| Error::materialization(format!("clear {}: {e}", dest.display())))?;
    }
    std::fs::create_dir_all(dest)
        .map_err(|e| Error::materialization(format!("mkdir {}: {e}", dest.display())))?;
    set_mode(dest, Some(0o755))?;

    for (idx, m) in mappings.iter().enumerate() {
        let from = m.from.replace("{{ variant }}", variant);
        let src = root.join(&from);
        let mode_override = resolved_mode(&m.mode)?;
        if !src.exists() {
            if m.optional {
                continue;
            }
            return Err(Error::mapping(format!(
                "mapping[{idx}] source '{}' does not exist",
                m.from
            )));
        }
        ensure_within_root(root, &src)?;
        let src_meta = std::fs::symlink_metadata(&src)
            .map_err(|e| Error::mapping(format!("stat {}: {e}", src.display())))?;

        if src_meta.is_dir() && m.recursive {
            // Merge directory contents into `to`.
            let to_rel = Path::new(&m.to);
            let base = dest.join(to_rel);
            ensure_within_dest(dest, &base)?;
            // Preserve the source directory's mode on the merge base.
            let base_mode = src_meta.mode() & 0o7777;
            for entry in WalkDir::new(&src).min_depth(1).into_iter() {
                let entry = entry.map_err(|e| Error::mapping(format!("walk {e}")))?;
                let rel = entry
                    .path()
                    .strip_prefix(&src)
                    .map_err(|e| Error::mapping(format!("{e}")))?;
                let dst = base.join(rel);
                ensure_within_dest(dest, &dst)?;
                if dst.exists() {
                    match m.conflict {
                        ConflictPolicy::Error => {
                            return Err(Error::conflict(format!(
                                "mapping[{idx}] destination '{}' already exists",
                                normalize_rel(rel)
                            )));
                        }
                        ConflictPolicy::Keep => continue,
                        ConflictPolicy::Replace => {}
                    }
                }
                copy_entry(entry.path(), &dst, mode_override)?;
            }
            set_mode(&base, Some(base_mode)).ok();
        } else {
            // Single file or non-recursive dir.
            let dst = dest_for(
                dest,
                &m.to,
                src_meta.is_dir() && !m.recursive,
                Path::new(&from),
            );
            ensure_within_dest(dest, &dst)?;
            if dst.exists() {
                match m.conflict {
                    ConflictPolicy::Error => {
                        return Err(Error::conflict(format!(
                            "mapping[{idx}] destination '{}' already exists",
                            normalize_rel(dst.strip_prefix(dest).unwrap_or(dst.as_path()))
                        )));
                    }
                    ConflictPolicy::Keep => continue,
                    ConflictPolicy::Replace => {}
                }
            }
            copy_entry(&src, &dst, mode_override)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConflictPolicy, Mapping};

    #[test]
    fn preserves_source_mode_when_no_override() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        let app_dir = root.join("app");
        std::fs::create_dir_all(&app_dir).unwrap();
        // Build source files/dirs with explicit modes.
        for (name, mode) in [("f0640", 0o640), ("f0644", 0o644), ("f0750", 0o750)] {
            let p = app_dir.join(name);
            std::fs::write(&p, b"x").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let sub = app_dir.join("sub0750");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(sub.join("inside"), b"y").unwrap();

        let mappings = vec![Mapping {
            from: "app/".into(),
            to: "out/".into(),
            recursive: true,
            conflict: ConflictPolicy::Replace,
            mode: None,
            optional: false,
        }];
        let dest = dir.path().join("dest");
        materialize_variant(&root, &mappings, "standard", &dest).unwrap();

        let check = |rel: &str, want: u32| {
            let m = std::fs::metadata(dest.join(rel)).unwrap().mode() & 0o7777;
            assert_eq!(m, want, "mode of '{rel}' (got {m:o}) should be {want:o}");
        };
        check("out/f0640", 0o640);
        check("out/f0644", 0o644);
        check("out/f0750", 0o750);
        check("out/sub0750", 0o750);
        check("out/sub0750/inside", 0o644);
    }

    #[test]
    fn interpolation_and_conflict_replace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(root.join("deployment/common")).unwrap();
        std::fs::write(root.join("deployment/common/README"), b"common").unwrap();
        std::fs::create_dir_all(root.join("deployment/variants/standard")).unwrap();
        std::fs::write(root.join("deployment/variants/standard/extra"), b"std").unwrap();
        std::fs::create_dir_all(root.join("build/output")).unwrap();
        std::fs::write(root.join("build/output/server"), b"srv").unwrap();
        let mappings = vec![
            Mapping {
                from: "build/output/".into(),
                to: "app/".into(),
                recursive: true,
                conflict: ConflictPolicy::Keep,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "deployment/common/".into(),
                to: "app/".into(),
                recursive: true,
                conflict: ConflictPolicy::Keep,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "deployment/variants/{{ variant }}/".into(),
                to: "app/".into(),
                recursive: true,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
        ];
        let dest = dir.path().join("dest");
        materialize_variant(&root, &mappings, "standard", &dest).unwrap();
        assert!(dest.join("app/README").exists());
        assert!(dest.join("app/extra").exists());
        assert!(dest.join("app/server").exists());
    }
}

//! Mapping semantics: applies declarative `from -> to` mappings for one
//! variant to assemble a staging tree directory.
//!
//! * `from` is relative to the project root and must stay beneath it.
//! * `from` is rendered through the template module
//!   ([`crate::template`]) with the mapping context, which exposes
//!   `{{ variant }}` only — trees are content-addressed and shared across
//!   slots, so slot-level variables (`deploy_dir`, `server`, `target`) are
//!   never available here and fail loudly if referenced.
//! * Mappings are applied in declaration order.
//! * Recursive directory mappings merge; their conflict policy applies to
//!   colliding descendant entries rather than deleting unrelated entries.
//! * Symlinks are fail-closed. A relative target means what it means where the
//!   link LIVES, so the target is validated from the DESTINATION parent
//!   (`dst.parent().join(target)`) and must resolve beneath the staging root.
//!   And no destination operation may pass through a symlink: every component
//!   of a destination is walked with no-follow `symlink_metadata` semantics
//!   before any write, so a symlink ancestor refuses the whole mapping instead
//!   of redirecting writes to its target.

use crate::config::{ConflictPolicy, Mapping, resolved_mode};
use crate::error::{Error, Result};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
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

/// Create every missing ancestor directory of `dst` (not `dst` itself),
/// applying a canonical, umask-independent mode to each freshly created
/// directory, so the tree digest never depends on the process umask.
///
/// Mode policy: an intermediate that mirrors a source directory — the parent
/// chain of a copied directory, whose destination path duplicates the source
/// path below the mapping's source root — inherits that source directory's
/// mode; every other intermediate is fresh staging scaffolding and gets the
/// deterministic default 0755. `src_root` is the mapping's source root the
/// `from` path is relative to (the merge source directory for recursive
/// walks, the project root for non-recursive directory mappings); pass `None`
/// for single file/symlink mappings, whose destination parents are always
/// scaffolding.
fn create_parent_dirs(src: &Path, dst: &Path, src_root: Option<&Path>) -> Result<()> {
    let mirror_depth = src_root
        .and_then(|r| src.strip_prefix(r).ok())
        .map(|rel| rel.components().count().saturating_sub(1))
        .unwrap_or(0);
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cur = dst;
    while let Some(parent) = cur.parent() {
        if parent.exists() {
            break;
        }
        missing.push(parent.to_path_buf());
        cur = parent;
    }
    // Create top-down so each `create_dir` sees its parent; `idx + 1` is the
    // depth measured from `dst` (1 = its direct parent), which is the depth
    // the source ancestor chain is aligned against.
    for (idx, created) in missing.iter().enumerate().rev() {
        let depth = idx + 1;
        let mode = if depth <= mirror_depth {
            src.ancestors()
                .nth(depth)
                .and_then(|counterpart| std::fs::symlink_metadata(counterpart).ok())
                .filter(|m| m.is_dir())
                .map(|m| m.mode() & 0o7777)
                .unwrap_or(0o755)
        } else {
            0o755
        };
        std::fs::create_dir(created)
            .map_err(|e| Error::materialization(format!("mkdir {}: {e}", created.display())))?;
        set_mode(created, Some(mode))?;
    }
    Ok(())
}

/// Settings for a single [`copy_entry`]: the mapping mode override, the source
/// root whose modes the mirrored intermediate directories inherit, and the
/// destination root the copy must stay inside.
struct CopyEntryOptions<'a> {
    mode_override: Option<u32>,
    src_root: Option<&'a Path>,
    dest_root: &'a Path,
}

/// Copy a single source entry (file or symlink) to a destination, applying the
/// mapping mode override. When the override is `None` the source's own mode is
/// preserved (instead of defaulting to 0755). Intermediate directories created
/// along the way get canonical, umask-independent modes (see
/// [`create_parent_dirs`]); the final entry itself is always set explicitly.
///
/// The destination is fail-closed against symlinks: any symlink component of
/// the destination path refuses the copy before any write (a write would
/// resolve to the link's target instead of the intended staging location), and
/// a relative symlink target must resolve beneath `opts.dest_root` from `dst`'s
/// own parent directory.
fn copy_entry(src: &Path, dst: &Path, opts: &CopyEntryOptions<'_>) -> Result<()> {
    let ft = std::fs::symlink_metadata(src)
        .map_err(|e| Error::materialization(format!("stat {}: {e}", src.display())))?;
    // Refuse BEFORE any write: a symlink component would redirect every
    // subsequent mkdir/remove_file/copy/symlink/set_mode to its target.
    ensure_no_symlink_ancestor(opts.dest_root, dst)?;
    if ft.is_dir() {
        create_parent_dirs(src, dst, opts.src_root)?;
        match std::fs::symlink_metadata(dst) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(Error::materialization(format!(
                    "mkdir {}: destination exists and is not a directory",
                    dst.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(dst)
                    .map_err(|e| Error::materialization(format!("mkdir {}: {e}", dst.display())))?;
            }
            Err(e) => {
                return Err(Error::materialization(format!(
                    "lstat {}: {e}",
                    dst.display()
                )));
            }
        }
        let final_mode = opts.mode_override.unwrap_or_else(|| ft.mode() & 0o7777);
        set_mode(dst, Some(final_mode))?;
        return Ok(());
    }
    if ft.is_symlink() {
        let target = std::fs::read_link(src)
            .map_err(|e| Error::materialization(format!("readlink {}: {e}", src.display())))?;
        if target.is_absolute() {
            return Err(Error::mapping(format!(
                "absolute symlink {} is not allowed",
                src.display()
            )));
        }
        // A relative target resolves against the DESTINATION parent — the
        // relocation into staging changes what it means — so reject any target
        // whose resolved destination location escapes the staging root.
        ensure_symlink_target_within(opts.dest_root, dst, &target)?;
        create_parent_dirs(src, dst, opts.src_root)?;
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
    let final_mode = opts.mode_override.unwrap_or(source_mode);
    create_parent_dirs(src, dst, opts.src_root)?;
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst).map_err(|e| {
        Error::materialization(format!("copy {} -> {}: {e}", src.display(), dst.display()))
    })?;
    set_mode(dst, Some(final_mode))?;
    Ok(())
}

/// Lexically resolve `rel` against `base`, collapsing `.` and `..` without
/// touching the filesystem (no symlink following). Returns `None` when `rel` is
/// absolute or its `..` climbs above `base` entirely.
fn resolve_lexically(base: &Path, rel: &Path) -> Option<PathBuf> {
    let mut out = base.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => return None,
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    Some(out)
}

/// Refuse to touch `dst` when ANY component of it (walked from the destination
/// root with no-follow `symlink_metadata`) is a symlink. A destination whose
/// path passes through a symlink would redirect the write to the link's target
/// instead of the intended staging location, so a symlink component — the
/// final one included, which a replace would otherwise write through — refuses
/// the operation. Real directories are unaffected, so recursive merges keep
/// their semantics.
fn ensure_no_symlink_ancestor(dest_root: &Path, dst: &Path) -> Result<()> {
    let rel = dst.strip_prefix(dest_root).map_err(|_| {
        Error::mapping(format!(
            "destination '{}' escapes staging root '{}'",
            dst.display(),
            dest_root.display()
        ))
    })?;
    let mut cur = dest_root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                return Err(Error::mapping(format!(
                    "destination '{}' is not beneath staging root '{}'",
                    dst.display(),
                    dest_root.display()
                )));
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                cur.pop();
                continue;
            }
            Component::Normal(name) => cur.push(name),
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(Error::mapping(format!(
                    "destination '{}' descends through symlink '{}'",
                    dst.display(),
                    cur.display()
                )));
            }
            Ok(_) => {}
            // A missing component cannot have anything below it, so the rest
            // of the destination is safe by construction.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(Error::materialization(format!(
                    "lstat {}: {e}",
                    cur.display()
                )));
            }
        }
    }
    Ok(())
}

/// Reject a symlink whose relative `target` resolves OUTSIDE the destination
/// root when copied to `dst`: resolve the target against the DESTINATION
/// parent (`dst.parent().join(target)`) — relocation into staging changes what
/// a relative target means, so the source-side absolute check alone does not
/// protect destination operations.
fn ensure_symlink_target_within(dest_root: &Path, dst: &Path, target: &Path) -> Result<()> {
    let base = dst.parent().unwrap_or(dest_root);
    let resolved = resolve_lexically(base, target).ok_or_else(|| {
        Error::mapping(format!(
            "symlink '{}' target '{}' resolves above its destination parent '{}'",
            dst.display(),
            target.display(),
            base.display()
        ))
    })?;
    if !resolved.starts_with(dest_root) {
        return Err(Error::mapping(format!(
            "symlink '{}' target '{}' escapes staging root: {}",
            dst.display(),
            target.display(),
            resolved.display()
        )));
    }
    Ok(())
}

/// Defensively verify that a computed destination stays beneath the staging
/// root. `..` is resolved LEXICALLY (no filesystem access, no canonicalize,
/// which would FOLLOW symlinks), so the destination cannot climb above the
/// staging root; the resolved path is returned for the caller to write into.
fn ensure_within_dest(dest_root: &Path, dst: &Path) -> Result<PathBuf> {
    let rel = dst.strip_prefix(dest_root).map_err(|_| {
        Error::mapping(format!(
            "computed destination '{}' escapes staging root '{}'",
            dst.display(),
            dest_root.display()
        ))
    })?;
    let resolved = resolve_lexically(dest_root, rel).ok_or_else(|| {
        Error::mapping(format!(
            "computed destination '{}' climbs above staging root '{}'",
            dst.display(),
            dest_root.display()
        ))
    })?;
    if !resolved.starts_with(dest_root) {
        return Err(Error::mapping(format!(
            "computed destination '{}' escapes staging root '{}'",
            dst.display(),
            dest_root.display()
        )));
    }
    Ok(resolved)
}

/// Apply all mappings for `variant` to assemble a complete staging tree at
/// `dest`. `dest` is created/cleared before mapping.
///
/// `vars` is the mapping context ([`TemplateVars::mapping`]): only
/// per-variant values (`variant`, `application`, `release`) are available,
/// because the assembled tree is content-addressed and shared across slots —
/// a mapping `from` that references a server/slot variable fails loudly
/// instead of producing a slot-dependent tree.
pub fn materialize_variant(
    root: &Path,
    mappings: &[Mapping],
    vars: &crate::template::TemplateVars,
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
        let from = crate::template::render_template(&m.from, vars)?;
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
            let base = ensure_within_dest(dest, &dest.join(to_rel))?;
            // The merge writes INTO `base`, so its own component chain must be
            // symlink-free; every nested entry re-checks through `copy_entry`.
            ensure_no_symlink_ancestor(dest, &base)?;
            // Preserve the source directory's mode on the merge base.
            let base_mode = src_meta.mode() & 0o7777;
            for entry in WalkDir::new(&src).min_depth(1).into_iter() {
                let entry = entry.map_err(|e| Error::mapping(format!("walk {e}")))?;
                let rel = entry
                    .path()
                    .strip_prefix(&src)
                    .map_err(|e| Error::mapping(format!("{e}")))?;
                let dst = ensure_within_dest(dest, &base.join(rel))?;
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
                copy_entry(
                    entry.path(),
                    &dst,
                    &CopyEntryOptions {
                        mode_override,
                        src_root: Some(&src),
                        dest_root: dest,
                    },
                )?;
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
            let dst = ensure_within_dest(dest, &dst)?;
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
            // A copied directory's intermediate parents inherit the source
            // directories' modes; a single file's parents are fresh staging
            // scaffolding (None). `copy_entry` itself refuses any destination
            // whose path passes through a symlink.
            let src_root = src_meta.is_dir().then_some(root);
            copy_entry(
                &src,
                &dst,
                &CopyEntryOptions {
                    mode_override,
                    src_root,
                    dest_root: dest,
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConflictPolicy, Mapping};
    use crate::model::TreeMetadata;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn preserves_source_mode_when_no_override() {
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
        materialize_variant(
            &root,
            &mappings,
            &crate::template::TemplateVars::mapping("app", "v1", "standard"),
            &dest,
        )
        .unwrap();

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
        materialize_variant(
            &root,
            &mappings,
            &crate::template::TemplateVars::mapping("app", "v1", "standard"),
            &dest,
        )
        .unwrap();
        assert!(dest.join("app/README").exists());
        assert!(dest.join("app/extra").exists());
        assert!(dest.join("app/server").exists());
    }

    #[test]
    fn mapping_referencing_server_variable_fails_loudly() {
        // Trees are content-addressed and shared across slots: a mapping
        // `from` referencing a per-server variable (e.g. `{{ user }}`) must
        // fail loudly — never render an empty path component, never produce a
        // slot-dependent tree.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(root.join("deployment")).unwrap();
        std::fs::write(root.join("deployment/x"), b"x").unwrap();
        let mappings = vec![Mapping {
            from: "deployment/{{ user }}/".into(),
            to: "app/".into(),
            recursive: true,
            conflict: ConflictPolicy::Replace,
            mode: None,
            optional: false,
        }];
        let dest = dir.path().join("dest");
        let err = materialize_variant(
            &root,
            &mappings,
            &crate::template::TemplateVars::mapping("app", "v1", "standard"),
            &dest,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("variable 'user' is not available in this context"),
            "mapping must reject a server-scoped variable: {err}"
        );
        // The staging dir exists (created before mapping) but nothing was
        // materialized into it — no slot-dependent tree content.
        assert!(
            !dest.join("app").exists(),
            "nothing materialized on a template error"
        );
    }

    // -----------------------------------------------------------------------
    // Umask independence: the tree digest is a pure function of source content
    // -----------------------------------------------------------------------

    /// RAII restore for the process-global umask. Used ONLY inside a dedicated
    /// child process (see [`tree_digest_independent_of_umask`]), never in the
    /// shared test process: `libc::umask` is process-global, so mutating it in
    /// a thread of the test binary would leak the mask into every concurrently
    /// running test's `create_dir_all` calls.
    struct UmaskGuard(libc::mode_t);

    impl UmaskGuard {
        fn set(mode: u32) -> UmaskGuard {
            let previous = unsafe { libc::umask(mode as libc::mode_t) };
            UmaskGuard(previous)
        }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    /// The fixed scenario shared by the umask probe and the shape proptest:
    /// assorted dirs/files with EXPLICIT modes (`set_permissions` is umask-
    /// immune), a nested chain, and a relative in-root symlink.
    fn build_source_tree(root: &Path) {
        for (rel, mode) in [
            ("app", 0o755),
            ("app/sub", 0o750),
            ("app/sub/deep", 0o700),
            ("bin", 0o755),
            ("conf", 0o755),
            ("share", 0o755),
        ] {
            let p = root.join(rel);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        for (rel, mode) in [
            ("app.sh", 0o644),
            ("app/run.sh", 0o755),
            ("app/sub/deep.ini", 0o644),
            ("bin/tool", 0o750),
            ("conf/site.conf", 0o644),
            ("share/λ.txt", 0o600),
            ("share/data.bin", 0o600),
        ] {
            let p = root.join(rel);
            std::fs::write(&p, rel.as_bytes()).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        std::os::unix::fs::symlink("app/run.sh", root.join("bin/run")).unwrap();
    }

    /// The mapping list that must be umask-independent: BOTH leak paths — a
    /// single-file `to` with a trailing slash forcing fresh intermediate
    /// directories, and a non-recursive directory mapping — plus
    /// recursive-merge controls that must keep preserving source modes.
    fn umask_probe_mappings() -> Vec<Mapping> {
        vec![
            Mapping {
                from: "conf/site.conf".into(),
                to: "etc/nginx/".into(),
                recursive: false,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "share".into(),
                to: "out/".into(),
                recursive: false,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "app/".into(),
                to: "app/".into(),
                recursive: true,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "bin/tool".into(),
                to: "opt/tools/".into(),
                recursive: false,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "app/sub/".into(),
                to: "mirror/".into(),
                recursive: false,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "bin/".into(),
                to: "bin/".into(),
                recursive: true,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
        ]
    }

    fn materialize_canonicalize(
        root: &Path,
        mappings: &[Mapping],
        dest: &Path,
    ) -> Result<TreeMetadata> {
        materialize_variant(
            root,
            mappings,
            &crate::template::TemplateVars::mapping("app", "v1", "standard"),
            dest,
        )?;
        crate::tree::canonicalize_tree(dest)
    }

    /// Child runner, re-executed once per umask by
    /// [`tree_digest_independent_of_umask`] in a FRESH PROCESS: sets the umask,
    /// materializes the fixed scenario twice into fresh staging roots, asserts
    /// in-process determinism, and writes the canonical metadata to the file
    /// named by `UMASK_RESULT_FILE`. A no-op when run as part of the normal
    /// suite (no env var set).
    #[test]
    fn umask_probe_child() {
        let Ok(mode) = std::env::var("UMASK_PROBE_MODE") else {
            return;
        };
        let umask = u32::from_str_radix(&mode, 8).expect("UMASK_PROBE_MODE is an octal mode");
        let result_file = std::env::var("UMASK_RESULT_FILE").expect("UMASK_RESULT_FILE is set");
        let _umask_guard = UmaskGuard::set(umask);

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        build_source_tree(&root);
        let mappings = umask_probe_mappings();
        let meta_a =
            materialize_canonicalize(&root, &mappings, &dir.path().join("stage-a")).unwrap();
        let meta_b =
            materialize_canonicalize(&root, &mappings, &dir.path().join("stage-b")).unwrap();
        assert_eq!(
            meta_a, meta_b,
            "two materializations under umask {umask:#o} must agree"
        );
        std::fs::write(&result_file, serde_json::to_vec(&meta_a).unwrap()).unwrap();
    }

    /// The tree digest must be a pure function of source content: identical
    /// sources materialized under different process umasks (which mask freshly
    /// created intermediate directories) must canonicalize to byte-identical
    /// metadata with identical digests. The umask is process-global, so each
    /// umask runs in its own re-executed child process (see [`umask_probe_child`])
    /// and the parent compares the four snapshots.
    #[test]
    fn tree_digest_independent_of_umask() {
        let exe = std::env::current_exe().expect("current test binary");
        let dir = tempfile::tempdir().unwrap();
        let mut snapshots: Vec<(u32, TreeMetadata)> = Vec::new();
        for umask in [0o022, 0o002, 0o000, 0o077] {
            let result_file = dir.path().join(format!("umask-{umask:o}.json"));
            let out = std::process::Command::new(&exe)
                .arg("umask_probe_child")
                .env("UMASK_PROBE_MODE", format!("{umask:o}"))
                .env("UMASK_RESULT_FILE", &result_file)
                .output()
                .expect("spawn umask probe child");
            assert!(
                out.status.success(),
                "umask probe child failed under umask {umask:#o}:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let meta: TreeMetadata =
                serde_json::from_slice(&std::fs::read(&result_file).unwrap()).unwrap();
            snapshots.push((umask, meta));
        }
        let (first_umask, first) = &snapshots[0];
        for (umask, meta) in &snapshots[1..] {
            assert_eq!(
                first, meta,
                "canonical tree (entries, modes, content digests, symlink targets) \
                 must not depend on the process umask: {first_umask:#o} vs {umask:#o}"
            );
            assert_eq!(
                first.tree_sha256, meta.tree_sha256,
                "tree digest must not depend on the process umask: \
                 {first_umask:#o} vs {umask:#o}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Property: mapping shapes materialize deterministically (fixed umask)
    // -----------------------------------------------------------------------

    #[derive(Clone, Debug)]
    struct MapperCase {
        mappings: Vec<Mapping>,
    }

    fn existing_from_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            2 => Just("app.sh".to_string()),
            2 => Just("app/run.sh".to_string()),
            2 => Just("conf/site.conf".to_string()),
            1 => Just("app/sub/deep.ini".to_string()),
            1 => Just("share/λ.txt".to_string()),
            1 => Just("bin/tool".to_string()),
            1 => Just("app".to_string()),
            1 => Just("app/sub".to_string()),
            1 => Just("bin".to_string()),
            1 => Just("conf/".to_string()),
            1 => Just("share".to_string()),
        ]
    }

    /// Destination shapes: trailing slash × both, nested dirs, empty `to`, and
    /// a unicode name. Duplicate/nested destinations occur organically, so
    /// every conflict policy is exercised (erroring cases are compared by
    /// error variant in the property).
    fn to_shape_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            2 => Just("out/".to_string()),
            1 => Just("out".to_string()),
            2 => Just("out/nested/".to_string()),
            1 => Just(String::new()),
            1 => Just("λ-目的地/".to_string()),
            1 => Just("deep/er/still/".to_string()),
        ]
    }

    fn conflict_strategy() -> impl Strategy<Value = ConflictPolicy> {
        prop_oneof![
            1 => Just(ConflictPolicy::Error),
            1 => Just(ConflictPolicy::Keep),
            1 => Just(ConflictPolicy::Replace),
        ]
    }

    fn mode_strategy() -> impl Strategy<Value = Option<String>> {
        prop_oneof![
            3 => Just(None),
            1 => Just(Some("0644".to_string())),
            1 => Just(Some("0755".to_string())),
            1 => Just(Some("0700".to_string())),
        ]
    }

    fn mapping_shape_strategy() -> impl Strategy<Value = Mapping> {
        (
            existing_from_strategy(),
            to_shape_strategy(),
            conflict_strategy(),
            mode_strategy(),
            prop::bool::ANY,
            prop_oneof![
                4 => Just(None),
                1 => Just(Some("ghost/missing".to_string())),
            ],
        )
            .prop_map(|(from, to, conflict, mode, recursive, missing)| {
                let optional = missing.is_some();
                Mapping {
                    from: missing.unwrap_or(from),
                    to,
                    recursive,
                    conflict,
                    mode,
                    optional,
                }
            })
    }

    fn mapper_case_strategy() -> impl Strategy<Value = MapperCase> {
        prop::collection::vec(mapping_shape_strategy(), 1..=3)
            .prop_map(|mappings| MapperCase { mappings })
    }

    /// Every source mode must survive a single recursive mapping with no
    /// override: files, dirs, and the merge base all keep their source modes.
    fn assert_recursive_modes_preserved(root: &Path, dest: &Path, m: &Mapping) {
        let from = m.from.trim_end_matches('/');
        let src_dir = root.join(from);
        let base = dest.join(Path::new(&m.to));
        let src_root_mode = std::fs::symlink_metadata(&src_dir).unwrap().mode() & 0o7777;
        let dst_root_mode = std::fs::symlink_metadata(&base).unwrap().mode() & 0o7777;
        assert_eq!(
            src_root_mode, dst_root_mode,
            "merge base must keep the source directory's mode"
        );
        for entry in WalkDir::new(&src_dir).min_depth(1) {
            let entry = entry.unwrap();
            let rel = entry.path().strip_prefix(&src_dir).unwrap();
            let src_mode = std::fs::symlink_metadata(entry.path()).unwrap().mode() & 0o7777;
            let dst_path = base.join(rel);
            let dst_mode = std::fs::symlink_metadata(&dst_path).unwrap().mode() & 0o7777;
            assert_eq!(
                src_mode,
                dst_mode,
                "source mode {src_mode:o} of '{}' must be preserved in the merged tree \
                 (got {dst_mode:o})",
                rel.display()
            );
        }
    }

    fn run_mapper_case_property(case: &MapperCase) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        build_source_tree(&root);
        let vars = crate::template::TemplateVars::mapping("app", "v1", "standard");
        let dest_a = dir.path().join("stage-a");
        let dest_b = dir.path().join("stage-b");
        let res_a = materialize_variant(&root, &case.mappings, &vars, &dest_a)
            .and_then(|()| crate::tree::canonicalize_tree(&dest_a));
        let res_b = materialize_variant(&root, &case.mappings, &vars, &dest_b)
            .and_then(|()| crate::tree::canonicalize_tree(&dest_b));
        match (&res_a, &res_b) {
            (Ok(meta_a), Ok(meta_b)) => {
                assert_eq!(
                    meta_a, meta_b,
                    "two materializations of the same mapping shapes must produce \
                     identical canonical trees (entries, modes, digests)"
                );
            }
            (Err(ea), Err(eb)) => {
                assert_eq!(
                    std::mem::discriminant(ea),
                    std::mem::discriminant(eb),
                    "the two materializations must fail identically: {ea} vs {eb}"
                );
            }
            (a, b) => panic!("materialization must be deterministic: {a:?} vs {b:?}"),
        }
        // Recursive-merge shapes with no override preserve source modes exactly.
        if case.mappings.len() == 1
            && case.mappings[0].recursive
            && case.mappings[0].mode.is_none()
            && res_a.is_ok()
        {
            let from = case.mappings[0].from.trim_end_matches('/');
            if root.join(from).is_dir() {
                assert_recursive_modes_preserved(&root, &dest_a, &case.mappings[0]);
            }
        }
    }

    proptest! {
        // Main property: ORDINARY RANDOMIZED SEEDS with FAILURE PERSISTENCE
        // (proptest's defaults) — a failing vector writes to
        // `proptest-regressions/mapper.txt` and is replayed on the next run
        // (commit it so CI keeps reproducing the regression until fixed). The
        // case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn mapping_shapes_materialize_deterministically(case in mapper_case_strategy()) {
            run_mapper_case_property(&case);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION: the deterministic floor for CI. The same
        // generator under the pinned 0x5EED_5EED seed with no persistence runs
        // the IDENTICAL vectors on every invocation, so the suite stays
        // reproducible even when no failure has ever been persisted by the
        // main test. The case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn mapping_shapes_deterministic_fixed_seed_regression(case in mapper_case_strategy()) {
            run_mapper_case_property(&case);
        }
    }

    // -----------------------------------------------------------------------
    // Property: relocated symlinks never write outside staging (fail-closed)
    // -----------------------------------------------------------------------

    /// A generated symlink-escape scenario: the symlinked tree is copied into
    /// a RELOCATED destination (so its relative targets resolve differently),
    /// and a LATER mapping descends through the relocated symlink. The mapper
    /// must either refuse (destination-parent validation of the target, or the
    /// no-follow ancestor walk) or complete WITHOUT writing through a symlink
    /// — the outside-staging canary is the oracle either way.
    #[derive(Clone, Debug)]
    struct SymlinkEscapeCase {
        /// Nested real-directory depth between the relocated tree's root and
        /// the final symlink `ln`, so its relative target sits at a depth.
        depth: usize,
        /// Destination the symlinked tree is relocated to.
        reloc: String,
        /// Number of `..` hops in an in-staging target (0 = no hops).
        hops: usize,
        /// Whether the target must escape to the canary (outside staging).
        escape: bool,
        /// File name the nested mapping writes through the relocated link.
        nested_name: String,
        nested_policy: ConflictPolicy,
    }

    fn symlink_escape_case_strategy() -> impl Strategy<Value = SymlinkEscapeCase> {
        let depth = 0usize..=2;
        let reloc = prop_oneof![
            2 => Just("reloc/".to_string()),
            1 => Just("deep/nested/".to_string()),
        ];
        let hops = 0usize..=2;
        let escape = prop::bool::ANY;
        let nested_name = prop_oneof![
            1 => Just("can.txt".to_string()),
            1 => Just("esc.txt".to_string()),
            1 => Just("canary.txt".to_string()),
        ];
        let nested_policy = conflict_strategy();
        (depth, reloc, hops, escape, nested_name, nested_policy).prop_map(
            |(depth, reloc, hops, escape, nested_name, nested_policy)| SymlinkEscapeCase {
                depth,
                reloc,
                hops,
                escape,
                nested_name,
                nested_policy,
            },
        )
    }

    /// Build the source tree: under `sym/`, `depth` nested real directories
    /// each carrying a relative symlink `s{i} -> d{i}` (relative targets at
    /// various depths), a final symlink `ln` with the generated target at the
    /// deepest level, plus `payload/p.txt` for the nested mapping to write.
    fn build_symlink_source(root: &Path, depth: usize, target: &str) {
        let mut cur = root.join("sym");
        std::fs::create_dir_all(&cur).unwrap();
        for i in 0..depth {
            std::os::unix::fs::symlink(format!("d{i}"), cur.join(format!("s{i}"))).unwrap();
            cur = cur.join(format!("d{i}"));
            std::fs::create_dir_all(&cur).unwrap();
        }
        std::os::unix::fs::symlink(target, cur.join("ln")).unwrap();
        let payload = root.join("payload");
        std::fs::create_dir_all(&payload).unwrap();
        std::fs::write(payload.join("payload.txt"), b"payload").unwrap();
    }

    fn run_symlink_escape_property(case: &SymlinkEscapeCase) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");

        // The number of components between the staging root and the symlink's
        // destination parent decides how many `..` hops the relative target
        // needs to escape: the very same target resolves DIFFERENTLY per
        // relocation/depth combination.
        let reloc_comps = Path::new(&case.reloc).components().count();
        let below = reloc_comps + case.depth;
        let target = if case.escape {
            // Resolves EXACTLY onto the canary directory (the staging root's
            // parent), so an escaping copy or write-through hits it.
            format!("{}{}", "../".repeat(below + 1), "canary/")
        } else {
            // Stays inside staging: capped hops keep the resolution at or
            // below the staging root for every relocation/depth combination.
            format!("{}{}", "../".repeat(case.hops.min(below)), "payload/")
        };
        build_symlink_source(&root, case.depth, &target);

        // Outside-staging canary, unique per case via the fresh tempdir so
        // parallel cases can never collide.
        let staging = dir.path().join("staging");
        let canary_dir = dir.path().join("canary");
        std::fs::create_dir_all(&canary_dir).unwrap();
        let canary = canary_dir.join("canary.txt");
        std::fs::write(&canary, b"SENTINEL-CANARY").unwrap();

        // The relocated link lives at `reloc/d0/.../d{depth-1}/ln`; the nested
        // mapping descends through it.
        let mut link_rel = PathBuf::new();
        for i in 0..case.depth {
            link_rel.push(format!("d{i}"));
        }
        link_rel.push("ln");
        let nested_to = format!("{}{}/{}", case.reloc, link_rel.display(), case.nested_name);
        let mappings = vec![
            Mapping {
                from: "sym/".into(),
                to: case.reloc.clone(),
                recursive: true,
                conflict: ConflictPolicy::Replace,
                mode: None,
                optional: false,
            },
            Mapping {
                from: "payload/payload.txt".into(),
                to: nested_to,
                recursive: false,
                conflict: case.nested_policy.clone(),
                mode: None,
                optional: false,
            },
        ];
        let res = materialize_variant(
            &root,
            &mappings,
            &crate::template::TemplateVars::mapping("app", "v1", "standard"),
            &staging,
        );

        // Oracle: the canary must be byte-identical after EVERY materialization
        // (a write through the relocated symlink would land here), and nothing
        // else may appear in the canary directory.
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"SENTINEL-CANARY",
            "outside-staging canary was written: depth {} reloc {} target {}",
            case.depth,
            case.reloc,
            target
        );
        let leaked: Vec<String> = std::fs::read_dir(&canary_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "canary.txt")
            .collect();
        assert!(leaked.is_empty(), "canary dir leaked entries: {leaked:?}");

        match res {
            Ok(()) => {
                // Accepted staging must be canonical: no escaping or absolute
                // symlink survives and every entry sits inside the staging root
                // (no writes outside the intended destinations).
                crate::tree::canonicalize_tree(&staging)
                    .expect("an accepted mapping must canonicalize");
                // The nested mapping may not have been resolved through the
                // link: the write would have landed at the target's RESOLVED
                // location instead of the lexical destination.
                let link_dir = staging
                    .join(&case.reloc)
                    .join(link_rel.parent().unwrap_or(Path::new("")));
                let resolved = resolve_lexically(&link_dir, Path::new(&target))
                    .expect("in-staging target resolves");
                if resolved.starts_with(&staging) {
                    let through = resolved.join(&case.nested_name);
                    assert!(
                        !through.exists(),
                        "nested mapping leaked through the relocated symlink to {}",
                        through.display()
                    );
                }
            }
            Err(_) => {
                // Fail-closed refusal is the expected outcome for an escaping
                // target (destination-parent validation) or for a write through
                // the relocated symlink (no-follow ancestor walk).
            }
        }
    }

    proptest! {
        // Property: MAIN RANDOMIZED RUN with FAILURE PERSISTENCE (house
        // style) — a failing vector is written to `proptest-regressions/
        // mapper.txt` and replayed until fixed. Bounded count keeps it fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn symlink_relocation_never_escapes_staging(case in symlink_escape_case_strategy()) {
            run_symlink_escape_property(&case);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION for the symlink property: identical vectors on
        // every run, so CI always exercises the fail-closed symlink paths even
        // with no persisted failure.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn symlink_relocation_fixed_seed_regression(case in symlink_escape_case_strategy()) {
            run_symlink_escape_property(&case);
        }
    }
}

//! Mapping/template materialization: assemble a complete staging tree from a
//! mapping set ([`materialize_variant`]), the elected template variables
//! ([`TemplateVars`]), and template/argv rendering ([`render_template`],
//! [`render_argv`]).

use crate::config::{Mapping, destinations_overlap, resolved_mode};
use crate::error::{Error, Result};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

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
/// for single-file mappings, whose destination parents are always
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

/// Copy a single source entry (regular file or directory) to a destination,
/// applying the mapping mode override to FILES. When the override is `None`
/// the source's own mode is preserved (instead of defaulting to 0755).
/// Directories always keep their source mode (a non-traversable override
/// would break the no-follow destination walk). Intermediate directories
/// created along the way get canonical, umask-independent modes (see
/// [`create_parent_dirs`]); the final entry itself is always set explicitly.
///
/// STRICT SEMANTICS: symbolic links and every other non-regular entry (FIFO,
/// socket, device) are rejected outright — the pre-validation pass already
/// refused them, this re-check is defense-in-depth. The destination is also
/// fail-closed against symlinks: any symlink component of the destination
/// path refuses the copy before any write (a write would resolve to the
/// link's target instead of the intended staging location).
fn copy_entry(src: &Path, dst: &Path, opts: &CopyEntryOptions<'_>) -> Result<()> {
    let ft = std::fs::symlink_metadata(src)
        .map_err(|e| Error::materialization(format!("stat {}: {e}", src.display())))?;
    if !(ft.is_dir() || ft.is_file()) {
        return Err(Error::mapping(format!(
            "source '{}' is not a regular file or directory (type {:?})",
            src.display(),
            ft.file_type()
        )));
    }
    // Refuse BEFORE any write: a symlink component would redirect every
    // subsequent mkdir/remove_file/copy/set_mode to its target.
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
            Err(e) if e.kind() == ErrorKind::NotFound => {
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
        // Directories ALWAYS keep their source mode: the mapping mode
        // override is a FILE-mode policy, and applying a non-traversable
        // override (e.g. 0644) to a directory would break every later
        // no-follow destination walk through it.
        let final_mode = ft.mode() & 0o7777;
        set_mode(dst, Some(final_mode))?;
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
/// their semantics. This is defense-in-depth for hostile destination state:
/// the pre-validation pass already walked every destination.
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
            Err(e) if e.kind() == ErrorKind::NotFound => break,
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

/// Reject a source entry that is not a regular file or directory. Symbolic
/// links — and any other special entry (FIFO, socket, device) — are refused
/// outright: they carry target/relocation semantics that have no place in a
/// canonical content-addressed tree.
fn ensure_regular_source_type(ft: &std::fs::Metadata, idx: usize, what: &str) -> Result<()> {
    if !(ft.is_dir() || ft.is_file()) {
        return Err(Error::mapping(format!(
            "mapping[{idx}] source '{what}' is not a regular file or directory (type {:?})",
            ft.file_type()
        )));
    }
    Ok(())
}

/// Refuse a destination that would receive content from MORE THAN ONE source
/// entry of the same mapping expansion: the second entry is a divergent
/// collision (or a duplicate normalized path `canonicalize_tree` would reject
/// anyway). Identical destinations across mappings are already rejected by the
/// overlap check; this catches within-mapping collisions such as two source
/// names that NFC-normalize to the same destination path.
fn ensure_destination_free(
    dest_root: &Path,
    dst: &Path,
    seen: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let rel = dst.strip_prefix(dest_root).unwrap_or(dst).to_string_lossy();
    let normalized: String = rel.nfc().collect();
    if !seen.insert(normalized.clone()) {
        return Err(Error::conflict(format!(
            "destination '{normalized}' is written by more than one source entry"
        )));
    }
    Ok(())
}

/// PRE-VALIDATION PASS — runs BEFORE any staging write. A fully-valid mapping
/// set + source tree is the only thing that reaches materialization, so an
/// invalid set (overlapping destinations, missing source, symlink or special
/// source entry, escaping source/destination, or a destination written by two
/// source entries) fails without modifying the staging directory.
///
/// Order is deterministic: (1) the pair-wise destination-overlap check on the
/// mapping list, then (2) per mapping, in declaration order, the rendered
/// source's existence/type/escape checks and the destination's escape and
/// no-follow-ancestor checks — recursive directory mappings walk their full
/// source tree so every nested entry is validated and every normalized
/// destination is unique within the expansion.
fn validate_mapping_set(
    root: &Path,
    mappings: &[Mapping],
    vars: &TemplateVars,
    dest: &Path,
) -> Result<()> {
    // (1) Overlapping destinations: identical, or one a component-prefix of
    // the other (a nested `to` descending into another mapping's `to` tree).
    for i in 0..mappings.len() {
        for j in (i + 1)..mappings.len() {
            if destinations_overlap(&mappings[i].to, &mappings[j].to) {
                return Err(Error::mapping(format!(
                    "mapping destinations overlap: mappings[{i}] '{}' and mappings[{j}] '{}'",
                    mappings[i].to, mappings[j].to
                )));
            }
        }
    }
    // (2) Per mapping, declaration order: source + destination validation.
    for (idx, m) in mappings.iter().enumerate() {
        let from = render_template(&m.from, vars)?;
        let src = root.join(&from);
        let src_ft = match std::fs::symlink_metadata(&src) {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(Error::mapping(format!(
                    "mapping[{idx}] source '{from}' does not exist"
                )));
            }
            Err(e) => {
                return Err(Error::mapping(format!("stat {}: {e}", src.display())));
            }
            Ok(ft) => ft,
        };
        ensure_regular_source_type(&src_ft, idx, &from)?;
        ensure_within_root(root, &src)?;
        if src_ft.is_dir() && m.recursive {
            let base = ensure_within_dest(dest, &dest.join(Path::new(&m.to)))?;
            ensure_no_symlink_ancestor(dest, &base)?;
            let mut seen = std::collections::HashSet::new();
            for entry in WalkDir::new(&src).min_depth(1).into_iter() {
                let entry = entry.map_err(|e| Error::mapping(format!("walk {e}")))?;
                let rel = entry
                    .path()
                    .strip_prefix(&src)
                    .map_err(|e| Error::mapping(format!("{e}")))?;
                let dst = ensure_within_dest(dest, &base.join(rel))?;
                ensure_no_symlink_ancestor(dest, &dst)?;
                ensure_destination_free(dest, &dst, &mut seen)?;
                let eft = std::fs::symlink_metadata(entry.path())
                    .map_err(|e| Error::mapping(format!("stat {}: {e}", entry.path().display())))?;
                ensure_regular_source_type(&eft, idx, &from)?;
            }
        } else {
            let dst = dest_for(
                dest,
                &m.to,
                src_ft.is_dir() && !m.recursive,
                Path::new(&from),
            );
            let dst = ensure_within_dest(dest, &dst)?;
            ensure_no_symlink_ancestor(dest, &dst)?;
        }
    }
    Ok(())
}

/// Apply all mappings for `variant` to assemble a complete staging tree at
/// `dest`. `dest` is created/cleared before mapping.
///
/// The FULL mapping set + source tree is pre-validated first
/// (`validate_mapping_set`) and only a fully-valid set reaches
/// materialization: overlapping destinations, missing sources, symlink/special
/// sources, escaping paths, and destination collisions all fail BEFORE the
/// staging directory is touched. The staging tree itself is a disposable
/// cache: it is cleared and rebuilt, so re-running the same push over the same
/// staging is an idempotent no-op (byte-identical output), while a mapping set
/// whose expanded destinations collide (or diverge) is rejected up front.
///
/// `vars` is the mapping context ([`TemplateVars::mapping`]): only
/// per-variant values (`variant`, `application`, `release`) are available,
/// because the assembled tree is content-addressed and shared across slots —
/// a mapping `from` that references a server/slot variable fails loudly
/// instead of producing a slot-dependent tree.
pub fn materialize_variant(
    root: &Path,
    mappings: &[Mapping],
    vars: &TemplateVars,
    dest: &Path,
) -> Result<()> {
    validate_mapping_set(root, mappings, vars, dest)?;

    if dest.exists() {
        std::fs::remove_dir_all(dest)
            .map_err(|e| Error::materialization(format!("clear {}: {e}", dest.display())))?;
    }
    std::fs::create_dir_all(dest)
        .map_err(|e| Error::materialization(format!("mkdir {}: {e}", dest.display())))?;
    set_mode(dest, Some(0o755))?;

    for (idx, m) in mappings.iter().enumerate() {
        let from = render_template(&m.from, vars)?;
        let src = root.join(&from);
        let mode_override = resolved_mode(&m.mode)?;
        let src_meta = std::fs::symlink_metadata(&src)
            .map_err(|e| Error::mapping(format!("stat {}: {e}", src.display())))?;
        ensure_regular_source_type(&src_meta, idx, &from)?;

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
                copy_entry(
                    entry.path(),
                    &dst,
                    &CopyEntryOptions {
                        mode_override,
                        src_root: Some(src.as_path()),
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

/// The full elected variable set, in documentation order.
pub const ELECTED_VARIABLES: [&str; 13] = [
    "deploy_dir",
    "variant",
    "application",
    "release",
    "target",
    "server",
    "user",
    "address",
    "port",
    "slot",
    "deployment_id",
    "generation",
    "tree",
];

/// The context for one `render` call.
///
/// Every field is `Option` because a render site can only fill the variables
/// it actually knows: materialization ([`TemplateVars::mapping`]) knows only
/// `variant`/`application`/`release`, while activation/verification
/// ([`TemplateVars::slot`] plus the `with_*` builders) knows the full slot
/// context. A template that references a `None` field fails loudly instead of
/// silently rendering an empty string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVars {
    deploy_dir: Option<String>,
    variant: Option<String>,
    application: Option<String>,
    release: Option<String>,
    target: Option<String>,
    server: Option<String>,
    user: Option<String>,
    address: Option<String>,
    port: Option<String>,
    slot: Option<String>,
    deployment_id: Option<String>,
    generation: Option<String>,
    tree: Option<String>,
}

impl TemplateVars {
    /// Context for mapping materialization: per-variant values only
    /// (`variant`, `application`, `release`). `release` is the release NAME
    /// from `deploy.toml` — the immutable `ReleaseId` is derived from the
    /// materialized trees, so at materialization time it is not yet knowable
    /// (rendering it into a tree would be a circular dependency). Trees are
    /// content-addressed and shared across slots, so slot/server/deployment
    /// variables (`deploy_dir`, `server`, `target`, `user`, `address`,
    /// `port`, `slot`, `deployment_id`, `generation`, `tree`) must never be
    /// rendered into a tree; a mapping that references them fails loudly.
    pub fn mapping(application: &str, release: &str, variant: &str) -> TemplateVars {
        TemplateVars {
            deploy_dir: None,
            variant: Some(variant.to_string()),
            application: Some(application.to_string()),
            release: Some(release.to_string()),
            target: None,
            server: None,
            user: None,
            address: None,
            port: None,
            slot: None,
            deployment_id: None,
            generation: None,
            tree: None,
        }
    }

    /// Base slot context available at activation/verification time: the
    /// per-slot deployment location plus the artifact's identity — `variant`
    /// and the immutable `release` `ReleaseId` of the artifact actually being
    /// deployed (never the caller's current release name). The server-level
    /// (`user`/`address`/`port`), slot ID, and deployment-scoped variables
    /// start unset — fill them with [`TemplateVars::with_server`],
    /// [`TemplateVars::with_slot_id`], and
    /// [`TemplateVars::with_deployment`] at sites that have them.
    pub fn slot(
        deploy_dir: &Path,
        variant: &str,
        application: &str,
        release: &str,
        target: &str,
        server: &str,
    ) -> TemplateVars {
        TemplateVars {
            deploy_dir: Some(deploy_dir.to_string_lossy().into_owned()),
            variant: Some(variant.to_string()),
            application: Some(application.to_string()),
            release: Some(release.to_string()),
            target: Some(target.to_string()),
            server: Some(server.to_string()),
            user: None,
            address: None,
            port: None,
            slot: None,
            deployment_id: None,
            generation: None,
            tree: None,
        }
    }

    /// Add the server's connection metadata: the deployment account
    /// (`user`, from `[[servers]].user`), the address, and the SSH `port`.
    /// Together with `server` (the ID) these describe the physical host the
    /// slot deploys onto.
    pub fn with_server(mut self, user: &str, address: &str, port: u16) -> TemplateVars {
        self.user = Some(user.to_string());
        self.address = Some(address.to_string());
        self.port = Some(port.to_string());
        self
    }

    /// Add the placement-slot ID (`[[slots]].id`), distinct from `server`
    /// (the physical server the slot deploys onto).
    pub fn with_slot_id(mut self, slot: &str) -> TemplateVars {
        self.slot = Some(slot.to_string());
        self
    }

    /// Add the per-deployment identity, available only in the per-server
    /// activation/verification path: the deployment ID being pushed, the
    /// generation being activated, and the activated tree digest. Pass
    /// `None` at sites that do not know them (e.g. the reconciliation loop);
    /// a template referencing an unfilled deployment variable fails loudly.
    pub fn with_deployment(
        mut self,
        deployment_id: Option<&crate::identity::DeploymentId>,
        generation: Option<&crate::identity::GenerationId>,
        tree: Option<&crate::identity::TreeDigest>,
    ) -> TemplateVars {
        self.deployment_id = deployment_id.map(|d| d.as_str().to_string());
        self.generation = generation.map(|g| g.as_str().to_string());
        self.tree = tree.map(|t| t.as_str().to_string());
        self
    }

    /// Same context with the artifact-scoped variables replaced from ONE
    /// [`crate::identity::ArtifactRef`]: `variant`, the immutable `release`
    /// `ReleaseId`, and `tree` are all taken from the same artifact.
    /// Compensation re-runs the PRIOR generation's contract, whose
    /// release/variant/tree can all differ from the desired artifact; setting
    /// the triple together never leaves a torn combination (e.g. a prior
    /// variant rendered with the desired release). Everything else
    /// (deploy_dir, application, server metadata, deployment identity, ...)
    /// is unchanged.
    pub fn with_artifact(&self, artifact: &crate::identity::ArtifactRef) -> TemplateVars {
        let mut out = self.clone();
        out.variant = Some(artifact.variant.as_str().to_string());
        out.release = Some(artifact.release.as_str().to_string());
        out.tree = Some(artifact.tree.as_str().to_string());
        out
    }

    /// Same context with the FIVE deployment-scoped variables replaced from
    /// ONE [`crate::remote::helper::GenerationAssignment`]: `variant`,
    /// `release`, and `tree` from the assignment's artifact, plus
    /// `deployment_id` and `generation` from the assignment's own identity
    /// fields. The deployment identity must move WITH the artifact: a
    /// compensation-rendered unit/argv describes the PRIOR generation, so it
    /// must carry the prior deployment's `deployment_id`/`generation`, never
    /// the failed (new) generation's. This supersedes
    /// [`TemplateVars::with_artifact`] for compensation, which replaces only
    /// the artifact triple and would leave the deployment identity pointing at
    /// the failed generation. Everything else (deploy_dir, application, server
    /// metadata, ...) is unchanged.
    pub fn with_assignment(
        &self,
        assignment: &crate::remote::helper::GenerationAssignment,
    ) -> TemplateVars {
        let mut out = self.clone();
        out.variant = Some(assignment.artifact.variant.as_str().to_string());
        out.release = Some(assignment.artifact.release.as_str().to_string());
        out.tree = Some(assignment.artifact.tree.as_str().to_string());
        out.deployment_id = Some(assignment.deployment_id.as_str().to_string());
        out.generation = Some(assignment.generation_id.as_str().to_string());
        out
    }

    /// Resolve one variable name. `None` = the name is not elected at all;
    /// `Some(None)` = elected but not available in this context.
    fn lookup(&self, name: &str) -> Option<Option<&str>> {
        let value = match name {
            "deploy_dir" => self.deploy_dir.as_deref(),
            "variant" => self.variant.as_deref(),
            "application" => self.application.as_deref(),
            "release" => self.release.as_deref(),
            "target" => self.target.as_deref(),
            "server" => self.server.as_deref(),
            "user" => self.user.as_deref(),
            "address" => self.address.as_deref(),
            "port" => self.port.as_deref(),
            "slot" => self.slot.as_deref(),
            "deployment_id" => self.deployment_id.as_deref(),
            "generation" => self.generation.as_deref(),
            "tree" => self.tree.as_deref(),
            _ => return None,
        };
        Some(value)
    }
}

/// Render `template`, substituting every `{{ name }}` for an elected variable
/// in `vars`.
///
/// * unknown variable names → `Err` (no silent passthrough);
/// * an elected variable that this context does not provide → `Err`;
/// * unterminated `{{` or an empty `{{ }}` → `Err`;
/// * literal text without templates → returned unchanged.
pub fn render_template(template: &str, vars: &TemplateVars) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(close) = after.find("}}") else {
            return Err(Error::template(format!(
                "malformed template: unterminated '{{{{' in {template:?}"
            )));
        };
        let name = after[..close].trim();
        if name.is_empty() {
            return Err(Error::template(format!(
                "malformed template: empty '{{{{ }}}}' variable in {template:?}"
            )));
        }
        match vars.lookup(name) {
            None => {
                return Err(Error::template(format!(
                    "unknown template variable '{name}' in {template:?} \
                     (supported variables: {})",
                    ELECTED_VARIABLES.join(", ")
                )));
            }
            Some(None) => {
                return Err(Error::template(format!(
                    "template variable '{name}' is not available in this \
                     context (render site) while rendering {template:?}"
                )));
            }
            Some(Some(value)) => out.push_str(value),
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Statically validate every `{{ name }}` variable reference in `template`
/// WITHOUT rendering: the same grammar as [`render_template`] (unterminated
/// `{{`, empty `{{ }}`, and any non-`ELECTED_VARIABLES` name — including
/// every form of filter/property syntax, since only bare names are elected —
/// are refused). Used at the closed-enum boundary so a frozen record or
/// config whose argv/unit templates reference an unknown variable is refused
/// before any deployment work, instead of failing at render time after
/// remote state was touched.
pub fn validate_template_variables(template: &str) -> Result<()> {
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(close) = after.find("}}") else {
            return Err(Error::template(format!(
                "malformed template: unterminated '{{{{' in {template:?}"
            )));
        };
        let name = after[..close].trim();
        if name.is_empty() {
            return Err(Error::template(format!(
                "malformed template: empty '{{{{ }}}}' variable in {template:?}"
            )));
        }
        if !ELECTED_VARIABLES.contains(&name) {
            return Err(Error::template(format!(
                "unknown template variable '{name}' in {template:?} \
                 (supported variables: {})",
                ELECTED_VARIABLES.join(", ")
            )));
        }
        rest = &after[close + 2..];
    }
    Ok(())
}

/// Render every element of a command vector (e.g. verification `argv`).
/// Elements without templates are unchanged; malformed or unknown variables
/// fail loudly before the command is executed.
pub fn render_argv(argv: &[String], vars: &TemplateVars) -> Result<Vec<String>> {
    argv.iter().map(|a| render_template(a, vars)).collect()
}

#[cfg(test)]
mod tests_materialize {
    use super::*;
    use crate::config::{ConflictPolicy, Mapping};
    use crate::identity::{
        ArtifactRef, DeploymentId, GenerationId, ReleaseId, TreeDigest, TreeMetadata, VariantName,
        test_deployment_id, test_generation_id, test_tree_digest,
    };
    use crate::remote::canonical::canonicalize_tree;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::{FileFailurePersistence, RngSeed};
    use std::os::unix::fs::PermissionsExt;

    fn mapping(from: &str, to: &str) -> Mapping {
        Mapping {
            from: from.to_string(),
            to: to.to_string(),
            recursive: true,
            conflict: ConflictPolicy::Error,
            mode: None,
        }
    }

    #[test]
    fn preserves_source_mode_when_no_override() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
        // Pin the source mode explicitly: `std::fs::write` creates with
        // `0o666 & ~umask`, which is 0o644 under macOS's 0o022 but 0o664
        // under Linux's 0o002 — the materializer preserves the SOURCE mode,
        // so the fixture must make it deterministic.
        std::fs::set_permissions(sub.join("inside"), std::fs::Permissions::from_mode(0o644))
            .unwrap();

        let mappings = vec![mapping("app/", "out/")];
        let dest = dir.path().join("dest");
        materialize_variant(
            &root,
            &mappings,
            &TemplateVars::mapping("app", "v1", "standard"),
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
    fn interpolation_and_recursive_mappings() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(root.join("deployment/common")).unwrap();
        std::fs::write(root.join("deployment/common/README"), b"common").unwrap();
        std::fs::create_dir_all(root.join("deployment/variants/standard")).unwrap();
        std::fs::write(root.join("deployment/variants/standard/extra"), b"std").unwrap();
        std::fs::create_dir_all(root.join("build/output")).unwrap();
        std::fs::write(root.join("build/output/server"), b"srv").unwrap();
        // Strict semantics: every destination is disjoint — the merge that the
        // old conflict-policy fixtures produced (three sources into `app/`) is
        // now a rejected overlap, so each recursive mapping owns its own tree.
        let mappings = vec![
            mapping("build/output/", "app/"),
            mapping("deployment/common/", "common/"),
            mapping("deployment/variants/{{ variant }}/", "variant/"),
        ];
        let dest = dir.path().join("dest");
        materialize_variant(
            &root,
            &mappings,
            &TemplateVars::mapping("app", "v1", "standard"),
            &dest,
        )
        .unwrap();
        assert!(dest.join("app/server").exists());
        assert!(dest.join("common/README").exists());
        assert!(dest.join("variant/extra").exists());
    }

    #[test]
    fn mapping_referencing_server_variable_fails_loudly() {
        // Trees are content-addressed and shared across slots: a mapping
        // `from` referencing a per-server variable (e.g. `{{ user }}`) must
        // fail loudly — never render an empty path component, never produce a
        // slot-dependent tree.
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(root.join("deployment")).unwrap();
        std::fs::write(root.join("deployment/x"), b"x").unwrap();
        let mappings = vec![mapping("deployment/{{ user }}/", "app/")];
        let dest = dir.path().join("dest");
        let err = materialize_variant(
            &root,
            &mappings,
            &TemplateVars::mapping("app", "v1", "standard"),
            &dest,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("variable 'user' is not available in this context"),
            "mapping must reject a server-scoped variable: {err}"
        );
        // Pre-validation failed before any write: nothing was materialized.
        assert!(
            !dest.exists(),
            "nothing materialized on a template error (staging untouched)"
        );
    }

    // -----------------------------------------------------------------------
    // Strict semantics: pre-validation rejects before any staging write
    // -----------------------------------------------------------------------

    /// A recursive snapshot of a staging dir: every entry as a sorted
    /// `(rel path, mode, file bytes or None for dirs)`. A missing dir
    /// snapshots to the empty list, so "staging is unmodified" can be
    /// asserted across a failed materialization whether or not the dir
    /// existed before.
    fn snapshot_staging(root: &Path) -> Vec<(String, u32, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(root) else {
            return out;
        };
        for e in rd.flatten() {
            let p = e.path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let mode = m.mode() & 0o7777;
            if m.is_dir() {
                out.push((format!("{rel}/"), mode, None));
                out.extend(snapshot_staging(&p));
            } else if m.is_file() {
                out.push((rel, mode, Some(std::fs::read(&p).unwrap())));
            } else {
                out.push((rel, mode, None));
            }
        }
        out.sort();
        out
    }

    /// Assert a materialization that must FAIL leaves the staging directory
    /// byte-for-byte untouched (existence included).
    fn assert_fails_without_touching_staging(
        root: &Path,
        mappings: &[Mapping],
        dest: &Path,
        needle: &str,
    ) -> Error {
        let before = snapshot_staging(dest);
        let err = materialize_variant(
            root,
            mappings,
            &TemplateVars::mapping("app", "v1", "standard"),
            dest,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "error must mention '{needle}', got: {err}"
        );
        let after = snapshot_staging(dest);
        assert_eq!(
            before,
            after,
            "failed materialization must leave staging unmodified (dest: {})",
            dest.display()
        );
        err
    }

    #[test]
    fn overlapping_destinations_rejected_before_any_write() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::write(root.join("app/run.sh"), b"x").unwrap();
        std::fs::create_dir_all(root.join("conf")).unwrap();
        std::fs::write(root.join("conf/site.conf"), b"y").unwrap();
        let dest = dir.path().join("staging");
        let mappings = vec![mapping("app/", "out/"), mapping("conf/", "out/nested/")];
        let err = assert_fails_without_touching_staging(&root, &mappings, &dest, "overlap");
        assert!(
            err.to_string().contains("out/"),
            "error names the overlapping destinations: {err}"
        );
    }

    #[test]
    fn missing_source_rejected_before_any_write() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(&root).unwrap();
        let dest = dir.path().join("staging");
        let mappings = vec![mapping("ghost/missing", "out/")];
        assert_fails_without_touching_staging(&root, &mappings, &dest, "does not exist");
    }

    #[test]
    fn escaping_destination_rejected_before_any_write() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.sh"), b"x").unwrap();
        let dest = dir.path().join("staging");
        let mappings = vec![Mapping {
            from: "app.sh".into(),
            to: "../escape".into(),
            recursive: false,
            conflict: ConflictPolicy::Error,
            mode: None,
        }];
        assert_fails_without_touching_staging(&root, &mappings, &dest, "escape");
    }

    #[test]
    fn symlink_source_rejected_before_any_write() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/tool"), b"x").unwrap();
        std::os::unix::fs::symlink("tool", root.join("bin/run")).unwrap();
        let dest = dir.path().join("staging");
        // A recursive mapping walks into the symlink.
        let mappings = vec![mapping("bin/", "out/")];
        assert_fails_without_touching_staging(&root, &mappings, &dest, "regular file or directory");
        // A direct mapping of the symlink itself is rejected too.
        let mappings = vec![Mapping {
            from: "bin/run".into(),
            to: "out/run".into(),
            recursive: false,
            conflict: ConflictPolicy::Error,
            mode: None,
        }];
        assert_fails_without_touching_staging(&root, &mappings, &dest, "regular file or directory");
    }

    #[test]
    fn colliding_destinations_error_but_re_materialization_is_a_no_op() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.sh"), b"version-1").unwrap();
        let dest = dir.path().join("staging");
        let vars = TemplateVars::mapping("app", "v1", "standard");
        let mappings = vec![Mapping {
            from: "app.sh".into(),
            to: "bin/tool".into(),
            recursive: false,
            conflict: ConflictPolicy::Error,
            mode: None,
        }];
        materialize_variant(&root, &mappings, &vars, &dest).unwrap();

        // Re-running the same push over the same staging is an idempotent
        // no-op: the disposable staging is rebuilt to byte-identical output.
        let before = snapshot_staging(&dest);
        materialize_variant(&root, &mappings, &vars, &dest).unwrap();
        assert_eq!(
            before,
            snapshot_staging(&dest),
            "re-running the same push over the same staging must be a no-op"
        );

        // A DIVERGENT mapping set (a changed source now colliding with another
        // entry's destination) is rejected BEFORE the staging is touched.
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/tool"), b"other").unwrap();
        let divergent = vec![
            mapping("bin/", "out/"),
            Mapping {
                from: "app.sh".into(),
                to: "out/tool".into(),
                recursive: false,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
        ];
        assert_fails_without_touching_staging(&root, &divergent, &dest, "overlap");
    }

    #[test]
    fn within_mapping_destination_collision_rejected() {
        // Two source entries that NFC-normalize to the SAME destination path
        // (a decomposed vs precomposed unicode name) are a divergent
        // collision: `canonicalize_tree` would reject the duplicate anyway,
        // so the mapper must refuse before writing anything. On a
        // normalization-insensitive filesystem (APFS) such a pair cannot even
        // be constructed, so the uniqueness check is exercised directly here
        // and stays as defense-in-depth for normalization-preserving ones.
        let root = Path::new("/tmp/mapper-collision-test");
        let mut seen = std::collections::HashSet::new();
        ensure_destination_free(root, &root.join("out/caf\u{00e9}.txt"), &mut seen).unwrap();
        let err = ensure_destination_free(root, &root.join("out/cafe\u{0301}.txt"), &mut seen)
            .expect_err("normalized duplicate destination must be refused");
        assert!(
            err.to_string().contains("more than one source"),
            "got: {err}"
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
    /// immune) and a nested chain. No symlinks: strict mapping semantics
    /// reject symlink sources outright, so the scenario stays fully valid.
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
    }

    /// The mapping list that must be umask-independent: BOTH leak paths — a
    /// single-file `to` with a trailing slash forcing fresh intermediate
    /// directories, and a non-recursive directory mapping — plus
    /// recursive-merge controls that must keep preserving source modes.
    /// Every destination is disjoint (strict semantics: no overlaps).
    fn umask_probe_mappings() -> Vec<Mapping> {
        vec![
            Mapping {
                from: "conf/site.conf".into(),
                to: "etc/nginx/".into(),
                recursive: false,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
            Mapping {
                from: "share".into(),
                to: "out/".into(),
                recursive: false,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
            mapping("app/", "app/"),
            Mapping {
                from: "bin/tool".into(),
                to: "opt/tools/".into(),
                recursive: false,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
            Mapping {
                from: "app/sub/".into(),
                to: "mirror/".into(),
                recursive: false,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
            mapping("bin/", "bin/"),
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
            &TemplateVars::mapping("app", "v1", "standard"),
            dest,
        )?;
        canonicalize_tree(dest)
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

        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let env = crate::testutil::fixture_env();
        let mut snapshots: Vec<(u32, TreeMetadata)> = Vec::new();
        for umask in [0o022, 0o002, 0o000, 0o077] {
            let result_file = dir.path().join(format!("umask-{umask:o}.json"));
            // The probe child re-executes this test binary with the snapshot as
            // its ENTIRE environment (hermetic, via apply_to_command), then the
            // two probe vars on top.
            let mut cmd = std::process::Command::new(&exe);
            env.apply_to_command(&mut cmd);
            let out = cmd
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
                "canonical tree (entries, modes, content digests) \
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
    // Property (a): VALID mappings (regular files/dirs only, non-overlapping,
    // all sources present) always materialize deterministically — two
    // materializations produce byte-identical staging and identical canonical
    // tree digests, and re-materializing over the SAME staging is a no-op.
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

    fn mode_strategy() -> impl Strategy<Value = Option<String>> {
        prop_oneof![
            3 => Just(None),
            1 => Just(Some("0644".to_string())),
            1 => Just(Some("0755".to_string())),
            1 => Just(Some("0700".to_string())),
        ]
    }

    /// Destination pool: every member is pairwise NON-OVERLAPPING (flat, so
    /// no destination is nested beneath another), so any subset is a valid
    /// strict-mapping destination set.
    const DEST_POOL: [&str; 8] = [
        "out/", "etc/", "share/", "bin/", "conf/", "mirror/", "opt/", "app/",
    ];

    /// Generated VALID mapping cases: sources all exist in
    /// [`build_source_tree`], destinations are pairwise non-overlapping, and
    /// `conflict` is always `Error` (the only policy).
    fn valid_mapper_case_strategy() -> impl Strategy<Value = MapperCase> {
        (1usize..=3)
            .prop_flat_map(|k| {
                (
                    prop::sample::subsequence(DEST_POOL.to_vec(), k),
                    prop::collection::vec(existing_from_strategy(), k),
                    prop::collection::vec(mode_strategy(), k),
                    prop::collection::vec(prop::bool::ANY, k),
                )
            })
            .prop_map(|(dests, froms, modes, recs)| MapperCase {
                mappings: (0..dests.len())
                    .map(|i| Mapping {
                        from: froms[i].clone(),
                        to: dests[i].to_string(),
                        recursive: recs[i],
                        conflict: ConflictPolicy::Error,
                        mode: modes[i].clone(),
                    })
                    .collect(),
            })
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        build_source_tree(&root);
        let vars = TemplateVars::mapping("app", "v1", "standard");
        let dest_a = dir.path().join("stage-a");
        let dest_b = dir.path().join("stage-b");

        // Every generated case is VALID by construction: it must materialize.
        materialize_variant(&root, &case.mappings, &vars, &dest_a).unwrap();
        // Re-running over the SAME staging is an idempotent no-op.
        materialize_variant(&root, &case.mappings, &vars, &dest_a).unwrap();
        // A second materialization into a FRESH staging is byte-identical.
        materialize_variant(&root, &case.mappings, &vars, &dest_b).unwrap();

        assert_eq!(
            snapshot_staging(&dest_a),
            snapshot_staging(&dest_b),
            "two materializations of the same valid mapping set must produce \
             byte-identical staging: {case:?}"
        );
        let meta_a = canonicalize_tree(&dest_a).unwrap();
        let meta_b = canonicalize_tree(&dest_b).unwrap();
        assert_eq!(
            meta_a, meta_b,
            "two materializations of the same valid mapping set must produce \
             identical canonical trees (entries, modes, digests): {case:?}"
        );
        assert_eq!(
            meta_a.tree_sha256, meta_b.tree_sha256,
            "tree digest must be deterministic: {case:?}"
        );

        // Recursive-merge shapes with no override preserve source modes exactly.
        if case.mappings.len() == 1 && case.mappings[0].recursive && case.mappings[0].mode.is_none()
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
            cases: crate::testutil::proptest_cases(16),
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn valid_mappings_materialize_deterministically(case in valid_mapper_case_strategy()) {
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
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn valid_mappings_deterministic_fixed_seed_regression(case in valid_mapper_case_strategy()) {
            run_mapper_case_property(&case);
        }
    }

    // -----------------------------------------------------------------------
    // Property (b): ANY invalid case — a symlink source, an overlap, an
    // escaping destination path, a missing source — FAILS and the staging
    // directory is UNMODIFIED (byte-identical after the failed call).
    // -----------------------------------------------------------------------

    #[derive(Clone, Debug)]
    enum InvalidKind {
        SymlinkSource,
        Overlap,
        EscapeDestination,
        MissingSource,
    }

    #[derive(Clone, Debug)]
    struct InvalidCase {
        kind: InvalidKind,
        mappings: Vec<Mapping>,
    }

    fn invalid_case_strategy() -> impl Strategy<Value = InvalidCase> {
        prop_oneof![
            1 => Just(InvalidCase {
                kind: InvalidKind::SymlinkSource,
                mappings: vec![
                    Mapping {
                        from: "bin".into(),
                        to: "out/".into(),
                        recursive: true,
                        conflict: ConflictPolicy::Error,
                        mode: None},
                ]}),
            1 => Just(InvalidCase {
                kind: InvalidKind::SymlinkSource,
                mappings: vec![Mapping {
                    from: "bin/run".into(),
                    to: "out/run".into(),
                    recursive: false,
                    conflict: ConflictPolicy::Error,
                    mode: None}]}),
            1 => Just(InvalidCase {
                kind: InvalidKind::Overlap,
                mappings: vec![
                    Mapping {
                        from: "app.sh".into(),
                        to: "out/".into(),
                        recursive: false,
                        conflict: ConflictPolicy::Error,
                        mode: None},
                    Mapping {
                        from: "bin/tool".into(),
                        to: "out/nested/".into(),
                        recursive: false,
                        conflict: ConflictPolicy::Error,
                        mode: None},
                ]}),
            1 => Just(InvalidCase {
                kind: InvalidKind::Overlap,
                mappings: vec![
                    Mapping {
                        from: "app.sh".into(),
                        to: "out".into(),
                        recursive: false,
                        conflict: ConflictPolicy::Error,
                        mode: None},
                    Mapping {
                        from: "bin/tool".into(),
                        to: "out".into(),
                        recursive: false,
                        conflict: ConflictPolicy::Error,
                        mode: None},
                ]}),
            1 => Just(InvalidCase {
                kind: InvalidKind::EscapeDestination,
                mappings: vec![Mapping {
                    from: "app.sh".into(),
                    to: "../escape".into(),
                    recursive: false,
                    conflict: ConflictPolicy::Error,
                    mode: None}]}),
            1 => Just(InvalidCase {
                kind: InvalidKind::MissingSource,
                mappings: vec![Mapping {
                    from: "ghost/missing".into(),
                    to: "out/".into(),
                    recursive: false,
                    conflict: ConflictPolicy::Error,
                    mode: None}]}),
        ]
    }

    fn run_invalid_case_property(case: &InvalidCase) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        build_source_tree(&root);
        // A symlink source for the SymlinkSource cases.
        std::os::unix::fs::symlink("app/run.sh", root.join("bin/run")).unwrap();
        let dest = dir.path().join("staging");

        let before = snapshot_staging(&dest);
        let res = materialize_variant(
            &root,
            &case.mappings,
            &TemplateVars::mapping("app", "v1", "standard"),
            &dest,
        );
        let after = snapshot_staging(&dest);

        let err = res.expect_err("invalid case must fail before staging is modified");
        let needle = match case.kind {
            InvalidKind::SymlinkSource => "regular file or directory",
            InvalidKind::Overlap => "overlap",
            InvalidKind::EscapeDestination => "escape",
            InvalidKind::MissingSource => "does not exist",
        };
        assert!(
            err.to_string().contains(needle),
            "{:?} must be rejected with '{needle}', got: {err}",
            case.kind
        );
        assert_eq!(
            before, after,
            "an invalid case must leave staging byte-for-byte unmodified: {case:?}"
        );
    }

    proptest! {
        // Main property: ORDINARY RANDOMIZED SEEDS with FAILURE PERSISTENCE
        // (house style). Bounded count keeps the suite fast.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn invalid_mappings_fail_before_staging_is_modified(case in invalid_case_strategy()) {
            run_invalid_case_property(&case);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION (0x5EED_5EED, per house style): the identical
        // invalid vectors on every run, so CI always exercises the rejections
        // even with no persisted failure.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn invalid_mappings_fixed_seed_regression(case in invalid_case_strategy()) {
            run_invalid_case_property(&case);
        }
    }

    // -----------------------------------------------------------------------
    // Property: relocated symlink sources are REJECTED without writing
    // -----------------------------------------------------------------------

    /// A generated symlink scenario: a symlinked tree under `sym/` would be
    /// relocated into `reloc/` (its relative targets would resolve
    /// differently), and a nested mapping descends through the relocated
    /// link. STRICT SEMANTICS: the symlink source is refused outright, so the
    /// outside-staging canary trivially survives — no relocation logic ever
    /// runs, and the staging directory is untouched.
    #[derive(Clone, Debug)]
    struct SymlinkRejectionCase {
        /// Nested real-directory depth between the relocated tree's root and
        /// the final symlink `ln`.
        depth: usize,
        /// Destination the symlinked tree would be relocated to.
        reloc: String,
        /// File name a later mapping would write through the link.
        nested_name: String,
    }

    fn symlink_rejection_case_strategy() -> impl Strategy<Value = SymlinkRejectionCase> {
        let depth = 0usize..=2;
        let reloc = prop_oneof![
            2 => Just("reloc/".to_string()),
            1 => Just("deep/nested/".to_string()),
        ];
        let nested_name = prop_oneof![
            1 => Just("can.txt".to_string()),
            1 => Just("esc.txt".to_string()),
            1 => Just("canary.txt".to_string()),
        ];
        (depth, reloc, nested_name).prop_map(|(depth, reloc, nested_name)| SymlinkRejectionCase {
            depth,
            reloc,
            nested_name,
        })
    }

    /// Build the source tree: under `sym/`, `depth` nested real directories
    /// each carrying a relative symlink `s{i} -> d{i}`, a final symlink `ln`
    /// at the deepest level, plus `payload/p.txt` for a later mapping.
    fn build_symlink_source(root: &Path, depth: usize) {
        let mut cur = root.join("sym");
        std::fs::create_dir_all(&cur).unwrap();
        for i in 0..depth {
            std::os::unix::fs::symlink(format!("d{i}"), cur.join(format!("s{i}"))).unwrap();
            cur = cur.join(format!("d{i}"));
            std::fs::create_dir_all(&cur).unwrap();
        }
        std::os::unix::fs::symlink("payload/", cur.join("ln")).unwrap();
        let payload = root.join("payload");
        std::fs::create_dir_all(&payload).unwrap();
        std::fs::write(payload.join("payload.txt"), b"payload").unwrap();
    }

    fn run_symlink_rejection_property(case: &SymlinkRejectionCase) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("src");
        build_symlink_source(&root, case.depth);

        // Outside-staging canary, unique per case via the fresh tempdir so
        // parallel cases can never collide.
        let staging = dir.path().join("staging");
        let canary_dir = dir.path().join("canary");
        std::fs::create_dir_all(&canary_dir).unwrap();
        let canary = canary_dir.join("canary.txt");
        std::fs::write(&canary, b"SENTINEL-CANARY").unwrap();

        // The symlinked tree under `sym/` is mapped into the RELOCATED
        // destination; a LATER mapping descends through the deepest link.
        let mut link_rel = PathBuf::new();
        for i in 0..case.depth {
            link_rel.push(format!("d{i}"));
        }
        link_rel.push("ln");
        let nested_to = format!("{}{}/{}", case.reloc, link_rel.display(), case.nested_name);
        let mappings = vec![
            mapping("sym/", &case.reloc),
            Mapping {
                from: "payload/payload.txt".into(),
                to: nested_to,
                recursive: false,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
        ];

        // STRICT SEMANTICS: the symlink source is refused — before ANY
        // staging write, so the canary trivially survives and the staging
        // directory is untouched.
        let before = snapshot_staging(&staging);
        let res = materialize_variant(
            &root,
            &mappings,
            &TemplateVars::mapping("app", "v1", "standard"),
            &staging,
        );
        assert!(
            res.is_err(),
            "a symlink source must be refused: depth {} reloc {}",
            case.depth,
            case.reloc
        );
        assert_eq!(
            snapshot_staging(&staging),
            before,
            "the refused materialization must leave staging untouched"
        );
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"SENTINEL-CANARY",
            "outside-staging canary must survive (no write ever escaped): \
             depth {} reloc {}",
            case.depth,
            case.reloc
        );
        let leaked: Vec<String> = std::fs::read_dir(&canary_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "canary.txt")
            .collect();
        assert!(leaked.is_empty(), "canary dir leaked entries: {leaked:?}");
    }

    proptest! {
        // Main property: ORDINARY RANDOMIZED SEEDS with FAILURE PERSISTENCE
        // (house style) — a failing vector is written to
        // `proptest-regressions/mapper.txt` and replayed until fixed. Bounded
        // count keeps it fast.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn symlink_sources_are_rejected_before_writing(case in symlink_rejection_case_strategy()) {
            run_symlink_rejection_property(&case);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION for the symlink property: identical vectors on
        // every run, so CI always exercises the fail-closed symlink paths even
        // with no persisted failure.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn symlink_rejection_fixed_seed_regression(case in symlink_rejection_case_strategy()) {
            run_symlink_rejection_property(&case);
        }
    }

    fn slot_vars() -> TemplateVars {
        TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            "standard",
            "example",
            "rel-sha256-7b278acf5041d50a9704392ac9fac4c6c02ca2cf3be9e5aee61668c8070526d2",
            "production",
            "server-01",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&test_deployment_id("deploy-1")),
            Some(&test_generation_id("gen-1")),
            Some(&TreeDigest::new("abc123")),
        )
    }

    #[test]
    fn known_variables_render() {
        let v = slot_vars();
        assert_eq!(
            render_template("{{ deploy_dir }}/current/app/server", &v,).unwrap(),
            "/srv/deploy/example/current/app/server"
        );
        assert_eq!(
            render_template(
                "deployment/variants/{{ variant }}/",
                &TemplateVars::mapping("example", "v1", "standard"),
            )
            .unwrap(),
            "deployment/variants/standard/"
        );
        // No whitespace inside the braces is required.
        assert_eq!(
            render_template("{{variant}} {{ deploy_dir }}", &v).unwrap(),
            "standard /srv/deploy/example"
        );
        // Every elected variable renders from the slot context.
        let all = render_template(
            "{{ deploy_dir }}|{{ variant }}|{{ application }}|{{ release }}|{{ target }}|{{ server }}|{{ user }}|{{ address }}|{{ port }}|{{ slot }}|{{ deployment_id }}|{{ generation }}|{{ tree }}",
            &v,
        )
        .unwrap();
        assert_eq!(
            all,
            format!(
                "/srv/deploy/example|standard|example|rel-sha256-7b278acf5041d50a9704392ac9fac4c6c02ca2cf3be9e5aee61668c8070526d2|production|server-01|deploy|10.0.0.5|22|app-1|{}|{}|abc123",
                test_deployment_id("deploy-1"),
                test_generation_id("gen-1"),
            )
        );
        // `release` renders the immutable ReleaseId of the deployed artifact,
        // not the human release name from deploy.toml.
        assert_ne!(
            render_template("{{ release }}", &v).unwrap(),
            "v1",
            "the ReleaseId must not be confused with the short label"
        );
    }

    #[test]
    fn unknown_variable_fails() {
        let v = slot_vars();
        let err = render_template("a {{ nope }} b", &v).unwrap_err();
        assert!(err.to_string().contains("unknown template variable 'nope'"));
        // Expressions/filters/control flow are not variable names.
        for bad in ["{{ variant|upper }}", "{{ 1 + 1 }}", "{{ 'x' }}"] {
            assert!(
                render_template(bad, &v).is_err(),
                "expression {bad} must be rejected"
            );
        }
    }

    #[test]
    fn unavailable_variable_fails_at_its_render_site() {
        // A mapping context knows only variant/application/release:
        // referencing deploy_dir there must fail loudly rather than render an
        // empty path component.
        let m = TemplateVars::mapping("example", "v1", "standard");
        let err = render_template("artifacts/{{ deploy_dir }}", &m).unwrap_err();
        assert!(
            err.to_string()
                .contains("variable 'deploy_dir' is not available in this context")
        );
    }

    #[test]
    fn mapping_context_rejects_server_and_deployment_variables() {
        // Trees are content-addressed and shared across slots: slot-level,
        // server-level, and deployment-scoped variables must never render
        // into a tree. Every one of them fails loudly in the mapping context.
        let m = TemplateVars::mapping("example", "v1", "standard");
        for name in [
            "deploy_dir",
            "target",
            "server",
            "user",
            "address",
            "port",
            "slot",
            "deployment_id",
            "generation",
            "tree",
        ] {
            let t = format!("artifacts/{{{{ {name} }}}}");
            let err = render_template(&t, &m).unwrap_err();
            assert!(
                err.to_string().contains(&format!(
                    "variable '{name}' is not available in this context"
                )),
                "mapping context must reject '{name}' (got: {err})"
            );
        }
        // The mapping context DOES provide variant/application/release.
        assert_eq!(
            render_template("{{ variant }}/{{ application }}/{{ release }}", &m).unwrap(),
            "standard/example/v1"
        );
    }

    #[test]
    fn malformed_template_fails() {
        let v = slot_vars();
        assert!(render_template("{{ variant", &v).is_err(), "unterminated");
        assert!(render_template("{{ }}", &v).is_err(), "empty variable");
        assert!(render_template("a {{ }} b", &v).is_err(), "empty in text");
        assert!(
            render_template("{{{ variant }}}", &v).is_err(),
            "triple brace"
        );
    }

    #[test]
    fn literal_text_passes_through() {
        let v = slot_vars();
        assert_eq!(
            render_template("no templates here", &v).unwrap(),
            "no templates here"
        );
        assert_eq!(render_template("", &v).unwrap(), "");
        // Stray braces that never open a template are literal text.
        assert_eq!(
            render_template("printf \"%s\" \"$x\"", &v).unwrap(),
            "printf \"%s\" \"$x\""
        );
    }

    #[test]
    fn argv_renders_elementwise() {
        let v = slot_vars();
        let argv = render_argv(
            &[
                "{{ deploy_dir }}/bin/probe".to_string(),
                "{{ variant }}".to_string(),
                "--flag".to_string(),
            ],
            &v,
        )
        .unwrap();
        assert_eq!(
            argv,
            vec![
                "/srv/deploy/example/bin/probe".to_string(),
                "standard".to_string(),
                "--flag".to_string(),
            ]
        );
        // An unknown element fails the whole vector (fail closed).
        assert!(render_argv(&["{{ bogus }}".to_string()], &v).is_err());
    }

    /// Template output is LITERAL text: a `deploy_dir` (or any variable)
    /// containing spaces, `$`, backticks, or braces is passed through verbatim
    /// in argv elements — never shell-escaped, quoted, or split — because the
    /// adapter receives argv element-wise with no shell in between.
    #[test]
    fn special_chars_in_deploy_dir_render_literal() {
        let v = TemplateVars::slot(
            Path::new("/srv/Deploy Dir$/app"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("d1")),
            Some(&GenerationId::new("g1")),
            Some(&test_tree_digest("t1")),
        );
        let argv = render_argv(
            &[
                "{{ deploy_dir }}/bin/probe".to_string(),
                "--root={{ deploy_dir }}".to_string(),
                "{{ variant }}".to_string(),
            ],
            &v,
        )
        .unwrap();
        assert_eq!(
            argv,
            vec![
                "/srv/Deploy Dir$/app/bin/probe".to_string(),
                "--root=/srv/Deploy Dir$/app".to_string(),
                "standard".to_string(),
            ],
            "spaces and $ must pass through as literal text (no escaping, no quoting)"
        );
        // A deploy_dir containing a backtick or brace is equally literal in
        // plain template text.
        let v2 = TemplateVars::slot(
            Path::new("/srv/`tick`/{braced}"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        );
        assert_eq!(
            render_template("{{ deploy_dir }}/current", &v2).unwrap(),
            "/srv/`tick`/{braced}/current"
        );
    }

    #[test]
    fn with_artifact_replaces_artifact_vars_together() {
        let v = TemplateVars::slot(
            Path::new("/srv/a"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("d1")),
            Some(&GenerationId::new("g1")),
            Some(&test_tree_digest("t1")),
        );
        // The prior artifact differs in every artifact-scoped variable: a
        // historical release, a different variant, a different tree.
        let prior = v.with_artifact(&ArtifactRef {
            release: crate::identity::test_release_id("rel-sha256-999"),
            variant: VariantName::new("legacy"),
            tree: test_tree_digest("t9"),
        });
        // release + variant + tree move TOGETHER to the prior artifact: never
        // a torn combination (prior variant with the desired release/tree).
        assert_eq!(
            render_template(
                "{{ variant }}|{{ deploy_dir }}|{{ release }}|{{ user }}|{{ slot }}|{{ generation }}|{{ tree }}",
                &prior
            )
            .unwrap(),
            format!(
                "legacy|/srv/a|{}|deploy|app-1|g1|{}",
                crate::identity::test_release_id("rel-sha256-999"),
                test_tree_digest("t9")
            )
        );
        // The source context is unchanged (with_artifact clones).
        assert_eq!(
            render_template("{{ release }}", &v).unwrap(),
            "rel-sha256-111"
        );
        assert_eq!(render_template("{{ variant }}", &v).unwrap(), "standard");
    }

    #[test]
    fn with_assignment_replaces_all_five_from_one_assignment() {
        let v = TemplateVars::slot(
            Path::new("/srv/a"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("d-failed")),
            Some(&GenerationId::new("g-failed")),
            Some(&test_tree_digest("t-failed")),
        );
        // The prior assignment differs in every one of the five values: a
        // historical release, a different variant/tree, and the PRIOR
        // deployment identity (not the failed generation's).
        let prior = v.with_assignment(&crate::remote::helper::GenerationAssignment {
            deployment_id: DeploymentId::new("d-prior"),
            generation_id: GenerationId::new("g-prior"),
            artifact: ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-999"),
                variant: VariantName::new("legacy"),
                tree: test_tree_digest("t9"),
            },
            behavior_sha256: crate::identity::test_behavior_digest("b"),
            prior_generation: None,
            created_at: crate::identity::Timestamp::parse("2020-01-01T00:00:00Z").unwrap(),
            application: crate::identity::ApplicationStoreKey::parse("app").unwrap(),
            slot: crate::identity::SlotId::parse("s1").unwrap(),
            target: Some(crate::identity::TargetName::new("prod")),
        });
        // All five move TOGETHER from the one assignment: never a torn
        // combination (prior artifact with the failed deployment identity).
        assert_eq!(
            render_template(
                "{{ variant }}|{{ release }}|{{ tree }}|{{ deployment_id }}|{{ generation }}",
                &prior
            )
            .unwrap(),
            format!(
                "legacy|{}|{}|d-prior|g-prior",
                crate::identity::test_release_id("rel-sha256-999"),
                test_tree_digest("t9")
            )
        );
        // The failed generation's identities are gone from the prior context.
        assert!(
            !render_template("{{ deployment_id }}", &prior)
                .unwrap()
                .contains("d-failed")
        );
        assert!(
            !render_template("{{ generation }}", &prior)
                .unwrap()
                .contains("g-failed")
        );
        // The source context is unchanged (with_assignment clones).
        assert_eq!(
            render_template("{{ deployment_id }}", &v).unwrap(),
            "d-failed"
        );
        assert_eq!(
            render_template("{{ release }}", &v).unwrap(),
            "rel-sha256-111"
        );
    }

    #[test]
    fn historical_artifact_renders_its_own_release_id() {
        // A historical/rollback push deploys an artifact whose release is the
        // stored, immutable ReleaseId — the template must render that id, not
        // the caller's current release name (e.g. "v1").
        let artifact = ArtifactRef {
            release: ReleaseId::new(
                "rel-sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            ),
            variant: VariantName::new("standard"),
            tree: TreeDigest::new("abc123"),
        };
        let v = TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            artifact.variant.as_str(),
            "example",
            artifact.release.as_str(),
            "production",
            "server-01",
        )
        .with_deployment(
            Some(&test_deployment_id("deploy-1")),
            Some(&test_generation_id("gen-1")),
            Some(&artifact.tree),
        );
        assert_eq!(
            render_template("{{ release }}", &v).unwrap(),
            artifact.release.as_str()
        );
        assert_eq!(
            render_template("{{ variant }}", &v).unwrap(),
            artifact.variant.as_str()
        );
        assert_eq!(render_template("{{ tree }}", &v).unwrap(), "abc123");
        // The ReleaseId is the immutable id, never the short label.
        assert_ne!(render_template("{{ release }}", &v).unwrap(), "v1");
    }
}

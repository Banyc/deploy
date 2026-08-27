//! `deploy init`: scaffold a fresh, immediately-valid deploy project.
//!
//! The generated project is LOCAL-FIRST: the server address defaults to
//! `local://<project>/.deploy-remote`, a local-filesystem endpoint, so
//! `deploy push production` works end-to-end with nothing but this binary (no
//! SSH, no server, no provisioning). Point `--address` at a real host and add
//! host-key verification to switch to SSH.
//!
//! The scaffold refuses to clobber: `deploy.toml` (or an existing `releases/`
//! tree) at the target is an error, and init never writes outside the target
//! directory.
//!
//! The scaffolded files are TYPED TOML, not formatting strings: every file is
//! built from the same config structs `ProjectConfig::load` parses into
//! (`ServerDef`, `SlotConfig`, `TargetConfig`, `VariantConfig`, ...) and serialized
//! with `toml::to_string_pretty`, so the emitted keys match the parser's
//! expectations exactly (`deny_unknown_fields` and all). Init validates the
//! options and the typed payload BEFORE anything is created, and re-loads the
//! written project through `ProjectConfig::load` BEFORE reporting success — a failed
//! init removes everything it created, so success always means the generated
//! project is valid.

use crate::config::{
    ActivationConfig, ActivationScope, ArtifactConfig, ConflictPolicy, DeploymentRetention,
    FailurePolicy, Mapping, PerServerRetention, RetentionConfig, SlotConfig, UnitDef,
    VerificationConfig,
};
use crate::error::{Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Options controlling the scaffold.
pub struct InitOptions {
    /// Application name. Defaults to the target directory's name.
    pub name: Option<String>,
    /// Server address. Defaults to `local://<target>/.deploy-remote`. Use a
    /// real hostname (plus `user`, and `known_hosts` or
    /// `host_key_fingerprint`) for SSH.
    pub address: Option<String>,
    /// SSH user (default "deploy").
    pub user: String,
    /// SSH port (default 22). Written into `deploy.toml` (the typed
    /// serialization always emits the resolved port).
    pub port: Option<u16>,
    /// Absolute `known_hosts` file for the server.
    pub known_hosts: Option<PathBuf>,
    /// `SHA256:...` host-key fingerprint pinned on first contact.
    pub host_key_fingerprint: Option<String>,
}

impl Default for InitOptions {
    fn default() -> Self {
        InitOptions {
            name: None,
            address: None,
            user: "deploy".to_string(),
            port: None,
            known_hosts: None,
            host_key_fingerprint: None,
        }
    }
}

/// Report of a successful scaffold.
#[derive(Debug)]
pub struct InitReport {
    /// Absolute target directory the project was created in.
    pub target: PathBuf,
    /// Regular files created, relative to `target`, sorted.
    pub files: Vec<PathBuf>,
    /// Directories created, relative to `target`, sorted (the `local://`
    /// endpoint included).
    pub dirs: Vec<PathBuf>,
    /// The commands the user should run next, in order.
    pub next_steps: Vec<String>,
}

/// Scaffold a fresh deploy project into `target`.
///
/// Fails closed, in three stages:
///
/// 1. Option validation runs FIRST, before any directory or file exists:
///    an SSH `--address` must configure EXACTLY ONE host-identity source
///    (`known_hosts` or `host_key_fingerprint`), `known_hosts` must be
///    absolute, a fingerprint must be `SHA256:...`, and a `local://` address
///    must name an absolute path (it doubles as the slot's `deploy_dir`).
/// 2. The typed scaffold is assembled and serialized; the emitted TOML must
///    round-trip through the strict parsers `ProjectConfig::load` uses.
/// 3. After every file is written, the project is RE-LOADED through
///    `ProjectConfig::load` (parse + validate + variant discovery). On failure the
///    just-created tree is removed (best effort) and the load error returned,
///    so a failed init never leaves a half-written project.
///
/// Refusing to clobber: `deploy.toml` or a `releases/` tree at the target is
/// an error, and init never writes outside the target directory.
pub fn init_project(target: &Path, opts: &InitOptions) -> Result<InitReport> {
    // Stage 1: option-level validation, before anything exists on disk.
    validate_init_options(opts)?;

    // Fail closed: never clobber. Both checks run before the first write (the
    // target may not exist yet, in which case the checks trivially pass).
    let deploy_toml_path = target.join("deploy.toml");
    if deploy_toml_path.exists() {
        return Err(Error::config(format!(
            "refusing to clobber existing '{}' — deploy init needs a fresh \
             project directory (or `deploy init <path>` into a new one)",
            deploy_toml_path.display()
        )));
    }
    if target.join("releases").exists() {
        return Err(Error::config(format!(
            "refusing to clobber existing '{}' (a release tree is already \
             present)",
            target.join("releases").display()
        )));
    }

    // Create/canonicalize the target, then derive the scaffold inputs.
    let (target, created_target) = ensure_target_dir(target)?;
    let name = sanitize_name(&match &opts.name {
        Some(n) => n.clone(),
        None => target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "deploy".to_string()),
    });
    let address = match &opts.address {
        Some(a) => a.clone(),
        None => format!("local://{}", target.join(".deploy-remote").display()),
    };
    let deploy_dir = match address.strip_prefix("local://") {
        // The local endpoint doubles as the slot's deploy location. The
        // transport is rooted at the `local://` path; the deploy_dir must stay
        // an absolute path per validation (enforced in stage 1).
        Some(p) => PathBuf::from(p),
        // Real server: a conventional absolute location the deployment account
        // must be able to create (documented in `deploy init --help`).
        None => PathBuf::from(format!("/srv/deploy/{name}")),
    };

    // Stage 2: build the typed scaffold documents and serialize them. The
    // serialized payloads must already round-trip through the strict schemas
    // the loader uses, so a serialization mistake fails here — before writing.
    let mut writes = build_docs(&name, &address, opts, &deploy_dir)?.writes;

    // Keep `.deploy-remote/` out of source control when the project sits in a
    // repo. Only created when the project has no `.gitignore` yet.
    if !target.join(".gitignore").exists() {
        writes.push((PathBuf::from(".gitignore"), ".deploy-remote/\n".to_string()));
    }

    // Stage 3: write everything, then require the written project to load.
    let created = match write_and_verify(&target, &writes, &[".deploy-remote"]) {
        Ok(created) => created,
        Err(e) => {
            if created_target {
                remove_tree_restoring_write(&target);
            }
            return Err(e);
        }
    };

    let mut files = created.files;
    files.sort();
    let mut dirs = vec![PathBuf::from(".deploy-remote")];
    dirs.sort();
    Ok(InitReport {
        target,
        files,
        dirs,
        next_steps: vec![
            "deploy push production --dry-run".to_string(),
            "deploy push production".to_string(),
            "deploy status production".to_string(),
            "deploy log production".to_string(),
        ],
    })
}

/// Reject option combinations the loader would reject, BEFORE any directory
/// or file is created. This mirrors the rules the config conversion
/// (`ProjectConfig::load`) applies to
/// the surfaces the flags expose (SSH identity, `known_hosts`, fingerprint,
/// `local://` endpoint). The fixed template parts (capacity 0/0, rollout,
/// variant sanity) are covered by the typed round-trip in [`build_docs`] and,
/// authoritatively, by the post-write `ProjectConfig::load`.
fn validate_init_options(opts: &InitOptions) -> Result<()> {
    let has_known_hosts = opts.known_hosts.is_some();
    let has_fingerprint = opts.host_key_fingerprint.is_some();
    if let Some(a) = &opts.address {
        if a.starts_with("local://") {
            // The local endpoint doubles as the slot's deploy_dir, which must
            // be an absolute path per validation.
            let p = a.trim_start_matches("local://");
            if !Path::new(p).is_absolute() {
                return Err(Error::config(format!(
                    "local address '{a}': the path after local:// must be absolute \
                     (it becomes the slot's deploy_dir)"
                )));
            }
        } else {
            match (has_known_hosts, has_fingerprint) {
                (false, false) => {
                    return Err(Error::config(format!(
                        "SSH address '{a}': exactly one of --known-hosts or \
                         --host-key-fingerprint must be provided (trust-on-first-use is disabled)"
                    )));
                }
                (true, true) => {
                    return Err(Error::config(format!(
                        "--known-hosts and --host-key-fingerprint are mutually exclusive; \
                         configure exactly one for SSH address '{a}'"
                    )));
                }
                _ => {}
            }
        }
    }
    if let Some(kh) = &opts.known_hosts
        && !kh.is_absolute()
    {
        return Err(Error::config(format!(
            "--known-hosts must be an absolute path, got '{}'",
            kh.display()
        )));
    }
    if let Some(fp) = &opts.host_key_fingerprint
        && !fp.starts_with("SHA256:")
    {
        return Err(Error::config(format!(
            "--host-key-fingerprint must be a SHA256:... value, got '{fp}'"
        )));
    }
    Ok(())
}

/// Every text file the scaffold writes, target-relative.
struct ScaffoldDocs {
    writes: Vec<(PathBuf, String)>,
}

/// The serialized shape of the scaffolded `deploy.toml`. It mirrors the raw
/// serializable surface of `config::raw::RawConfig` (schema_version,
/// application, release, servers, targets; `pins` and the variant map are
/// load-time only) so the emitted TOML round-trips through `ProjectConfig::load` —
/// which is exactly how the written project is re-validated in
/// [`write_and_verify`]. Slots are NOT a top-level surface anymore: they live
/// inside the variant files (see [`standard_variant`]). Building it from the
/// typed raw config structs (never formatting strings) guarantees the emitted
/// keys match the parser's expectations (`deny_unknown_fields` included).
#[derive(Serialize)]
struct ScaffoldManifest {
    schema_version: u32,
    application: String,
    release: String,
    servers: Vec<crate::config::raw::RawServer>,
    targets: BTreeMap<String, crate::config::raw::RawTargetConfig>,
}

/// Build the typed scaffold documents and serialize them with
/// `toml::to_string_pretty`. The serialized payloads are then re-parsed with
/// the exact strict schemas `ProjectConfig::load` uses (`deny_unknown_fields`,
/// snake_case enums, typed ports/rollout/retention) as a round-trip backstop:
/// the emitted TOML must parse back before anything is written.
fn build_docs(
    name: &str,
    address: &str,
    opts: &InitOptions,
    deploy_dir: &Path,
) -> Result<ScaffoldDocs> {
    let manifest = ScaffoldManifest {
        schema_version: crate::config::raw::CONFIG_SCHEMA_VERSION,
        application: name.to_string(),
        release: "v1".to_string(),
        servers: vec![crate::config::raw::RawServer {
            id: "server-01".to_string(),
            address: address.to_string(),
            user: opts.user.clone(),
            port: opts.port.unwrap_or(22),
            known_hosts: opts.known_hosts.clone(),
            host_key_fingerprint: opts.host_key_fingerprint.clone(),
            // Capacity is a per-server policy (shared by every deployment
            // slot on the server), zero by default.
            capacity: crate::config::raw::RawCapacityConfig {
                reserve_bytes: 0,
                reserve_percent: 0,
            },
        }],
        targets: BTreeMap::from([(
            "production".to_string(),
            // Targets own ROLLOUT behavior only; retention is slot-owned
            // (it lives in the slot's OWNING VARIANT file, see
            // [`standard_variant`]).
            crate::config::raw::RawTargetConfig {
                rollout: crate::config::raw::RawRolloutConfig {
                    batch_size: 1,
                    stop_on_failure: true,
                    // The scaffolded project uses the safe fail-closed
                    // default: an unknown policy spelling can never enter a
                    // generated config (the enum is closed; the serialized
                    // `failure_policy = "rollback_changed"` is exactly the
                    // spelling the strict parse accepts).
                    failure_policy: FailurePolicy::RollbackChanged,
                },
            },
        )]),
    };
    let standard = standard_variant(deploy_dir);
    let systemd = systemd_variant();

    let manifest_toml = toml::to_string_pretty(&manifest)
        .map_err(|e| Error::internal(format!("serializing scaffolded deploy.toml: {e}")))?;
    let standard_toml = toml::to_string_pretty(&standard)
        .map_err(|e| Error::internal(format!("serializing scaffolded standard.toml: {e}")))?;
    let systemd_toml = toml::to_string_pretty(&systemd)
        .map_err(|e| Error::internal(format!("serializing scaffolded systemd.toml: {e}")))?;

    // Round-trip backstop: what we are about to write must parse back under
    // the strict schemas the loader uses. Typed serialization cannot emit
    // comments, so the educational doc lines are prepended as TOML comments —
    // legal everywhere, ignored by the parser.
    let manifest_toml = format!("{MANIFEST_DOC}\n{manifest_toml}");
    let standard_toml = format!("{STANDARD_DOC}\n{standard_toml}");
    let systemd_toml = format!("{SYSTEMD_DOC}\n{systemd_toml}");
    toml::from_str::<crate::config::raw::RawConfig>(&manifest_toml).map_err(|e| {
        Error::config(format!(
            "scaffolded deploy.toml failed to round-trip through the strict loader: {e}"
        ))
    })?;
    toml::from_str::<crate::config::raw::RawVariant>(&standard_toml).map_err(|e| {
        Error::config(format!(
            "scaffolded standard.toml failed to round-trip through the strict loader: {e}"
        ))
    })?;
    toml::from_str::<crate::config::raw::RawVariant>(&systemd_toml).map_err(|e| {
        Error::config(format!(
            "scaffolded systemd.toml failed to round-trip through the strict loader: {e}"
        ))
    })?;

    Ok(ScaffoldDocs {
        writes: vec![
            (PathBuf::from("deploy.toml"), manifest_toml),
            (PathBuf::from("releases/v1/standard.toml"), standard_toml),
            (PathBuf::from("releases/v1/systemd.toml"), systemd_toml),
            (
                PathBuf::from("releases/v1/artifacts/build/output/app/hello"),
                PLACEHOLDER.to_string(),
            ),
            (
                PathBuf::from("releases/v1/artifacts/systemd/example.service"),
                systemd_unit_file(),
            ),
        ],
    })
}

/// The `standard` variant: a pure file push (`adapter = "none"`), the
/// zero-infrastructure default. It also declares the project's deployment
/// slot: the `[[slots]]` entry binds `app-1` to server-01 under the
/// scaffold's `deploy_dir` and to its ONE owning target `production` (a
/// target's members are derived from the slots' `target` fields). The unit
/// artifact and systemd activation live in the sibling `systemd` variant.
fn standard_variant(deploy_dir: &Path) -> crate::config::raw::RawVariant {
    crate::config::raw::RawVariant {
        description: Some("Standard deployment".to_string()),
        artifact: ArtifactConfig {
            mappings: vec![mapping("artifacts/build/output/app/", "app/")],
        },
        activation: ActivationConfig {
            adapter: "none".to_string(),
            scope: ActivationScope::User,
            reconcile_managed_units: true,
            units: Vec::new(),
        },
        verification: command_verification(),
        slots: vec![SlotConfig::new(
            "app-1",
            "server-01",
            deploy_dir.to_path_buf(),
            "production",
            Vec::new(),
        )],
        // The slot's ONE retention policy: the standard variant file owns the
        // policy of the slot it declares (app-1). A slot's owning variant is
        // its single retention source — never a per-target policy.
        retention: RetentionConfig {
            per_server: PerServerRetention {
                keep_distinct_artifacts: 5,
                keep_days: 14,
                protect_previous: true,
            },
            deployment: DeploymentRetention {
                protect_deployments: 2,
            },
        },
    }
}

/// The `systemd` example variant: ships the real user unit shipped as an
/// artifact (`releases/v1/artifacts/systemd/example.service`) mapped to
/// `app/`. It declares NO slots: it is an example you bind by adding a
/// `[[slots]]` entry (with a `target` field) to this file.
///
/// STRICT MAPPING SEMANTICS: destinations must not overlap, so this variant
/// maps only its own unit tree — the `standard` variant's `app/` destination
/// is deliberately not repeated here (repeating it would be a rejected
/// overlap).
fn systemd_variant() -> crate::config::raw::RawVariant {
    crate::config::raw::RawVariant {
        description: Some("Systemd-managed deployment".to_string()),
        artifact: ArtifactConfig {
            mappings: vec![mapping("artifacts/systemd/", "app/")],
        },
        activation: ActivationConfig {
            adapter: "systemd".to_string(),
            scope: ActivationScope::User,
            reconcile_managed_units: true,
            units: vec![UnitDef {
                name: "example.service".to_string(),
                artifact_path: "app/example.service".to_string(),
                enable: true,
                restart: true,
            }],
        },
        verification: command_verification(),
        slots: Vec::new(),
        // The systemd example declares no slots, so no slot owns it as a
        // retention source; its (unused) policy is the default.
        retention: RetentionConfig::default(),
    }
}

/// One artifact mapping: `from` resolves inside the release directory,
/// `to` is artifact-relative.
fn mapping(from: &str, to: &str) -> Mapping {
    Mapping {
        from: from.to_string(),
        to: to.to_string(),
        recursive: true,
        conflict: ConflictPolicy::Error,
        mode: None,
    }
}

/// The scaffold's verification: a command health check that always succeeds,
/// run once with a 5s timeout (the user replaces `true` with a real check).
fn command_verification() -> VerificationConfig {
    VerificationConfig {
        adapter: "command".to_string(),
        argv: vec!["true".to_string()],
        timeout_seconds: 5,
        attempts: 1,
        interval_seconds: 0,
    }
}

/// Educational doc header prepended to the serialized `deploy.toml` as TOML
/// comments (comments are legal TOML and ignored by `ProjectConfig::load`; typed
/// serialization itself cannot emit them).
const MANIFEST_DOC: &str = "\
# deploy.toml — generated by `deploy init`. Schema version 1.
# The project structure is forced (see `deploy help`):
#   releases/<release>/            the release directory named by `release:`
#   releases/<release>/*.toml      one file per variant (file stem = variant);
#                                  each variant declares its own [[slots]]
#   releases/<release>/artifacts/  artifact sources mapped by variant files
#
# Servers and targets are declared here; slots are declared inside the
# variant files (releases/v1/standard.toml declares the project's one slot,
# bound to its ONE owning target `production` by its `target` field).
#
# LOCAL-FIRST: `address` is a local:// filesystem endpoint (.deploy-remote/
# in this project) so `deploy push production` runs with zero SSH. To deploy
# to a real server, replace `address` with a hostname, set `user`, and add
# EXACTLY ONE of `known_hosts` (absolute path) or `host_key_fingerprint`
# (SHA256:...) — SSH trust-on-first-use is refused. `deploy init --help`
# documents the full flag set.
";

/// Doc header for `releases/v1/standard.toml`.
const STANDARD_DOC: &str = "\
# The `standard` variant — every *.toml file directly inside the release
# directory is a variant, named by its file stem: add a file to add a variant.
# Each variant declares its own deployment slots: the [[slots]] entry below
# binds slot `app-1` to server-01 (declared in deploy.toml) under this
# project's deploy_dir, and its `target` field binds it to its ONE owning
# target `production` (a target's members are derived from the slots'
# `target` fields; `groups` may add rollout-group membership for
# `deploy push production --group <name>`).
# `adapter = \"none\"` is a pure file push: the mapped artifacts land under
# `current/` and nothing else runs. For per-deployment service management,
# switch the activation adapter to \"systemd\" with [[activation.units]]
# entries — releases/v1/systemd.toml is a working example. scope = \"user\"
# (systemctl --user) is the default; \"system\" needs an admin-installed
# root-owned wrapper unit.
";

/// The doc for `releases/v1/systemd.toml`.
const SYSTEMD_DOC: &str = "\
# The `systemd` example variant — ships the shipped user unit
# (releases/v1/artifacts/systemd/example.service) into the artifact as
# `app/example.service` (strict mapping semantics: one file-tree destination
# per variant, so this variant maps only its own unit tree — the `standard`
# variant's `app/` destination is not repeated). The unit file is rendered
# per slot at activation time with the
# template module: `{{ deploy_dir }}` resolves to the slot's deploy_dir and
# `{{ user }}` to the per-server deployment account (the tree itself stays
# slot-independent), so `ExecStart` points through the
# deployment's `current` symlink and a successful push atomically points the
# running service at the new generation. Artifact-controlled units work by
# default with scope = \"user\" (systemctl --user); scope = \"system\" needs
# an admin-installed root-owned wrapper unit.
";

const PLACEHOLDER: &str = "Hello from deploy!\n\
\n\
This placeholder is mapped into the artifact as `app/hello` by the\n\
`standard` variant (see releases/v1/standard.toml). Add or replace files\n\
under releases/v1/artifacts/ and run `deploy push production` again.\n";

/// The unit file shipped with the scaffold's `systemd` variant. It uses the
/// template module's `{{ deploy_dir }}` and `{{ user }}` variables (see
/// [`crate::remote::materialize`]): the tree is content-addressed and shared across
/// slots, so the unit's `ExecStart` and the deployment-account comment are
/// rendered per slot at activation time — for the default `local://` project
/// the slot's `deploy_dir` is the absolute `.deploy-remote` path.
fn systemd_unit_file() -> String {
    r#"# systemd user unit for the scaffold's `systemd` example variant
# (releases/v1/systemd.toml). `deploy push` renders this file with the slot's
# template context ({{ deploy_dir }} -> the slot's deploy_dir, {{ user }} ->
# the per-server deployment account) and installs the rendered copy into the
# user service manager (`~/.config/systemd/user/`), then enables/restarts it.
# With scope = "user" the unit runs as the deployment account, so {{ user }}
# describes the invoking user. `ExecStart` resolves through the deployment's
# `current` symlink, so a successful push atomically points the running
# service at the new generation.
[Unit]
Description=Example service (managed by deploy)
# deployed by {{ user }}

[Service]
ExecStart={{ deploy_dir }}/current/app/hello
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#
    .to_string()
}

/// Create `target` if missing and canonicalize it to an absolute path. The
/// parent of `target` must already exist (init creates the project directory
/// itself, not an arbitrary path chain). Returns whether `target` was created
/// by this call (used to decide how aggressively a failed init cleans up).
fn ensure_target_dir(target: &Path) -> Result<(PathBuf, bool)> {
    if target.exists() {
        if !target.is_dir() {
            return Err(Error::config(format!(
                "init target '{}' exists and is not a directory",
                target.display()
            )));
        }
        return Ok((target.canonicalize().map_err(Error::Io)?, false));
    }
    std::fs::create_dir_all(target)
        .map_err(|e| Error::config(format!("creating init target '{}': {e}", target.display())))?;
    Ok((target.canonicalize().map_err(Error::Io)?, true))
}

/// Everything this init created inside `target`: target-relative file paths
/// and directories that did not exist before (recorded while writing).
#[derive(Debug, Default)]
struct CreatedTree {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

/// Write every scaffolded file, then require the generated project to load
/// through [`ProjectConfig::load`] (re-parse + re-validate + variant discovery). On a
/// load failure the just-created tree is removed (best effort — restore
/// owner-write, then remove, mirroring the engine's cleanup convention) and
/// the load error is returned: a failed init never leaves a half-written
/// project, and success is only reported once the written project is known
/// valid. `extra_dirs` are directories created up front (the `local://`
/// endpoint).
fn write_and_verify(
    target: &Path,
    writes: &[(PathBuf, String)],
    extra_dirs: &[&str],
) -> Result<CreatedTree> {
    let mut created = CreatedTree::default();
    for d in extra_dirs {
        let rel = PathBuf::from(d);
        let abs = target.join(&rel);
        let existed = abs.exists();
        std::fs::create_dir_all(&abs).map_err(Error::Io)?;
        if !existed {
            created.dirs.push(rel);
        }
    }
    for (rel, content) in writes {
        write_project_file(target, rel, content, &mut created)?;
    }
    if let Err(e) = crate::config::ProjectConfig::load(&target.join("deploy.toml")) {
        cleanup_created(target, &created);
        return Err(e);
    }
    Ok(created)
}

/// Write one file inside `target` (target-relative path), creating parent
/// directories, and record the file plus any directory this call actually
/// created for the report and for post-failure cleanup.
fn write_project_file(
    target: &Path,
    rel: &Path,
    content: &str,
    created: &mut CreatedTree,
) -> Result<()> {
    if let Some(parent) = rel.parent() {
        let mut cur = PathBuf::new();
        for comp in parent.components() {
            cur.push(comp);
            let abs = target.join(&cur);
            if !abs.exists() {
                std::fs::create_dir(&abs).map_err(Error::Io)?;
                created.dirs.push(cur.clone());
            }
        }
    }
    std::fs::write(target.join(rel), content).map_err(Error::Io)?;
    created.files.push(rel.to_path_buf());
    Ok(())
}

/// Best-effort removal of everything this init created under `target`: files
/// first, then directories deepest-first, restoring owner-write permission
/// before removing (POSIX `remove_dir_all` needs write on every directory it
/// enters). Never touches anything outside `target`; a pre-existing `target`
/// is left in place. Errors are ignored — cleanup runs on an already-failing
/// init.
fn cleanup_created(target: &Path, created: &CreatedTree) {
    for f in &created.files {
        let _ = std::fs::remove_file(target.join(f));
    }
    let mut dirs = created.dirs.clone();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for d in dirs {
        remove_tree_restoring_write(&target.join(&d));
    }
}

/// Remove a directory tree, restoring owner-write permission on read-only
/// entries inside it first, so `remove_dir_all` cannot fail with EACCES
/// (mirrors the engine's cleanup convention). Best-effort: a missing tree is a
/// no-op and errors are ignored.
fn remove_tree_restoring_write(root: &Path) {
    fn restore(dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                restore(&path);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = entry.metadata()
                    && md.permissions().mode() & 0o200 == 0
                {
                    let _ = std::fs::set_permissions(
                        &path,
                        std::fs::Permissions::from_mode(md.permissions().mode() | 0o200),
                    );
                }
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(md) = std::fs::metadata(dir)
                && md.permissions().mode() & 0o200 == 0
            {
                let _ = std::fs::set_permissions(
                    dir,
                    std::fs::Permissions::from_mode(md.permissions().mode() | 0o200),
                );
            }
        }
    }
    restore(root);
    let _ = std::fs::remove_dir_all(root);
}

/// Turn a directory name into a safe TOML/application name.
fn sanitize_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.trim().chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "deploy".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> InitOptions {
        InitOptions::default()
    }

    #[test]
    fn init_scaffolds_valid_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("my-app");
        let report = init_project(&proj, &opts()).unwrap();

        assert_eq!(
            report.files,
            vec![
                PathBuf::from(".gitignore"),
                PathBuf::from("deploy.toml"),
                PathBuf::from("releases/v1/artifacts/build/output/app/hello"),
                PathBuf::from("releases/v1/artifacts/systemd/example.service"),
                PathBuf::from("releases/v1/standard.toml"),
                PathBuf::from("releases/v1/systemd.toml"),
            ]
        );
        assert_eq!(report.dirs, vec![PathBuf::from(".deploy-remote")]);
        assert_eq!(report.next_steps.len(), 4);

        // The scaffolded config must pass full validation (strict rules:
        // absolute deploy_dir, unique server ids, known variant, non-empty
        // target, verified variant file).
        let config =
            crate::config::ProjectConfig::load(&report.target.join("deploy.toml")).unwrap();
        assert_eq!(config.application().as_str(), "my-app");
        assert_eq!(config.release().as_str(), "v1");
        assert_eq!(config.target_slot_ids("production").unwrap(), vec!["app-1"]);
        assert_eq!(
            config.variant("standard").unwrap().verification.argv,
            vec!["true"]
        );

        // The scaffold also ships the `systemd` example variant with a real
        // unit artifact; it is not bound to any slot, so pushes stay
        // adapter-agnostic.
        let systemd = config.variant("systemd").unwrap();
        let crate::config::Activation::Systemd(sa) = &systemd.activation else {
            panic!("systemd variant must carry the systemd activation");
        };
        assert_eq!(sa.scope, crate::config::ActivationScope::User);
        assert_eq!(sa.units.len(), 1);
        assert_eq!(sa.units[0].name, "example.service");
        assert_eq!(sa.units[0].artifact_path, "app/example.service");
        assert!(
            report
                .target
                .join("releases/v1/artifacts/systemd/example.service")
                .is_file()
        );

        // The local-first address routes the transport into the project.
        let addr = config.server("server-01").unwrap().address();
        assert!(
            addr.starts_with("local://") && addr.ends_with("/.deploy-remote"),
            "unexpected address {addr}"
        );
        assert!(config.slot_defs()[0].deploy_dir().is_absolute());
    }

    #[test]
    fn init_refuses_to_clobber() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("my-app");
        init_project(&proj, &opts()).unwrap();

        // Second init in the same place must fail closed.
        let err = init_project(&proj, &opts()).unwrap_err();
        assert!(err.to_string().contains("clobber"), "got: {err}");
    }

    // An SSH address (not `local://`) needs EXACTLY ONE host-identity source:
    // the handler rejects neither-set before anything is written, and the
    // both-set case is already a clap parse error (conflicting flags).
    #[test]
    fn init_ssh_address_requires_identity() {
        let tmp = tempfile::tempdir().unwrap();

        // SSH address + neither identity: handler error, nothing scaffolded.
        let proj = tmp.path().join("no-identity");
        let no_id_opts = InitOptions {
            address: Some("app.example.com".to_string()),
            ..Default::default()
        };
        let err = init_project(&proj, &no_id_opts).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exactly one of --known-hosts or --host-key-fingerprint")
                && msg.contains("app.example.com"),
            "got: {msg}"
        );
        assert!(
            !proj.join("deploy.toml").exists(),
            "nothing may be scaffolded on an invalid SSH address"
        );

        // SSH address with a fingerprint: valid.
        let proj = tmp.path().join("fp-only");
        let fp_opts = InitOptions {
            address: Some("app.example.com".to_string()),
            host_key_fingerprint: Some("SHA256:abc".to_string()),
            ..Default::default()
        };
        let report = init_project(&proj, &fp_opts).unwrap();
        let config =
            crate::config::ProjectConfig::load(&report.target.join("deploy.toml")).unwrap();
        assert_eq!(
            match config.server("server-01").unwrap().identity() {
                crate::config::HostIdentity::Fingerprint(f) => Some(f.as_str()),
                _ => None,
            },
            Some("SHA256:abc")
        );
        assert!(!matches!(
            config.server("server-01").unwrap().identity(),
            crate::config::HostIdentity::KnownHosts(_)
        ));

        // local:// address with no identity stays the zero-SSH default.
        let proj = tmp.path().join("local");
        init_project(&proj, &opts()).unwrap();
    }

    #[test]
    fn init_with_ssh_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("real-app");
        let opts = InitOptions {
            name: Some("prod".to_string()),
            address: Some("app.example.com".to_string()),
            user: "ops".to_string(),
            port: Some(2222),
            known_hosts: Some(PathBuf::from("/etc/ssh/known_hosts")),
            host_key_fingerprint: None,
        };
        let report = init_project(&proj, &opts).unwrap();
        let config =
            crate::config::ProjectConfig::load(&report.target.join("deploy.toml")).unwrap();
        assert_eq!(config.application().as_str(), "prod");
        let s = config.server("server-01").unwrap();
        assert_eq!(s.address(), "app.example.com");
        assert_eq!(s.user(), "ops");
        assert_eq!(s.port(), 2222);
        assert_eq!(
            match s.identity() {
                crate::config::HostIdentity::KnownHosts(p) => Some(p.as_path()),
                _ => None,
            },
            Some(Path::new("/etc/ssh/known_hosts"))
        );
        // No local endpoint: the slot targets a conventional server path.
        assert!(config.slot_defs()[0].deploy_dir().is_absolute());
        assert!(
            config.slot_defs()[0]
                .deploy_dir()
                .starts_with("/srv/deploy/")
        );
    }

    // Every option combination that would make the generated config invalid
    // fails BEFORE any file is written: the target directory is not even
    // created for a fresh path.
    #[test]
    fn invalid_options_fail_before_writing_anything() {
        let tmp = tempfile::tempdir().unwrap();

        // SSH address with neither identity source.
        let proj = tmp.path().join("ssh-no-identity");
        let err = init_project(
            &proj,
            &InitOptions {
                address: Some("app.example.com".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
        assert!(!proj.exists(), "target must not even be created");

        // A relative known_hosts is rejected (the config conversion requires
        // absolute).
        let proj = tmp.path().join("relative-known-hosts");
        let err = init_project(
            &proj,
            &InitOptions {
                address: Some("app.example.com".to_string()),
                known_hosts: Some(PathBuf::from("relative/known_hosts")),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("absolute"), "got: {err}");
        assert!(!proj.exists());

        // A fingerprint that is not SHA256:... is rejected.
        let proj = tmp.path().join("bad-fingerprint");
        let err = init_project(
            &proj,
            &InitOptions {
                address: Some("app.example.com".to_string()),
                host_key_fingerprint: Some("md5:deadbeef".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("SHA256:"), "got: {err}");
        assert!(!proj.exists());

        // A local:// address must name an absolute path (it becomes the
        // slot's deploy_dir).
        let proj = tmp.path().join("relative-local");
        let err = init_project(
            &proj,
            &InitOptions {
                address: Some("local://relative/path".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("absolute"), "got: {err}");
        assert!(!proj.exists());
    }

    // The scaffold is TYPED TOML: serializing the loaded config (and each
    // variant) again with toml::to_string_pretty must yield a project that
    // still loads through the strict ProjectConfig::load with identical semantics.
    #[test]
    fn scaffold_is_typed_toml_and_serializes_to_the_same_config() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("typed-app");
        let report = init_project(&proj, &opts()).unwrap();
        let config =
            crate::config::ProjectConfig::load(&report.target.join("deploy.toml")).unwrap();

        // Re-serialize every typed payload into a fresh project and load it.
        // The raw layer is the serializable surface (the domain model is
        // private-construction), so the re-serialization goes through the raw
        // shapes the loader parses.
        let reserialized = tmp.path().join("reserialized-app");
        let release_dir = reserialized.join("releases/v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let manifest: crate::config::raw::RawConfig =
            toml::from_str(&std::fs::read_to_string(report.target.join("deploy.toml")).unwrap())
                .unwrap();
        std::fs::write(
            reserialized.join("deploy.toml"),
            toml::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        for name in ["standard", "systemd"] {
            let variant: crate::config::raw::RawVariant = toml::from_str(
                &std::fs::read_to_string(
                    report
                        .target
                        .join("releases/v1")
                        .join(format!("{name}.toml")),
                )
                .unwrap(),
            )
            .unwrap();
            std::fs::write(
                release_dir.join(format!("{name}.toml")),
                toml::to_string_pretty(&variant).unwrap(),
            )
            .unwrap();
        }
        let reloaded = crate::config::ProjectConfig::load(&reserialized.join("deploy.toml"))
            .expect("re-serialized typed payload must load");

        // The re-serialized project carries the same semantics as the
        // scaffold (same application name and release, same server/slot
        // bindings, same rollout and variants).
        assert_eq!(reloaded.application().as_str(), "typed-app");
        assert_eq!(reloaded.release().as_str(), "v1");
        assert_eq!(
            reloaded.target_slot_ids("production").unwrap(),
            vec!["app-1"]
        );
        assert_eq!(
            reloaded
                .target("production")
                .unwrap()
                .rollout
                .batch_size
                .get(),
            1
        );
        assert_eq!(
            reloaded.server("server-01").unwrap().address(),
            config.server("server-01").unwrap().address()
        );
        assert_eq!(
            reloaded.server("server-01").unwrap().user(),
            config.server("server-01").unwrap().user()
        );
        assert_eq!(
            reloaded.server("server-01").unwrap().capacity,
            config.server("server-01").unwrap().capacity
        );
        assert_eq!(
            reloaded.slot_defs()[0].deploy_dir(),
            config.slot_defs()[0].deploy_dir()
        );
        assert_eq!(
            reloaded.variant("standard").unwrap().activation,
            crate::config::Activation::None
        );
        assert!(matches!(
            reloaded.variant("systemd").unwrap().activation,
            crate::config::Activation::Systemd(_)
        ));
        assert_eq!(
            reloaded.variant("standard").unwrap().artifact.mappings[0].from,
            "artifacts/build/output/app/"
        );
    }

    // A post-write ProjectConfig::load failure removes the just-created tree: the
    // factored write+verify helper gets an injected bad config that parses
    // options but fails the loader, and asserts nothing is left behind.
    #[test]
    fn failed_post_write_load_removes_the_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("bad-load");

        // The writes look scaffold-shaped but the deploy.toml is malformed
        // TOML, so the post-write ProjectConfig::load must fail and the helper must
        // remove every file and directory it created.
        let writes = vec![
            (
                PathBuf::from("deploy.toml"),
                "this is not toml {{{".to_string(),
            ),
            (
                PathBuf::from("releases/v1/standard.toml"),
                "adapter = \"none\"".to_string(),
            ),
        ];
        let err = write_and_verify(&proj, &writes, &[".deploy-remote"]).unwrap_err();
        assert!(
            err.to_string().contains("parsing deploy.toml"),
            "loader error must surface, got: {err}"
        );
        assert!(
            !proj.join("deploy.toml").exists(),
            "failed init must not leave deploy.toml"
        );
        assert!(
            !proj.join("releases").exists(),
            "failed init must not leave the release tree"
        );
        assert!(
            !proj.join(".deploy-remote").exists(),
            "failed init must not leave the local endpoint"
        );
        assert_eq!(
            std::fs::read_dir(&proj).unwrap().count(),
            0,
            "the target must be empty after a failed init"
        );
    }

    #[test]
    fn init_defaults_and_ssh_flags_round_trip_through_loader() {
        let tmp = tempfile::tempdir().unwrap();
        // SSH + known_hosts only: exactly one identity.
        let proj = tmp.path().join("kh-app");
        let opts = InitOptions {
            name: Some("kh-app".to_string()),
            address: Some("app.example.com".to_string()),
            user: "ops".to_string(),
            known_hosts: Some(PathBuf::from("/etc/ssh/known_hosts")),
            ..Default::default()
        };
        let report = init_project(&proj, &opts).unwrap();
        let config =
            crate::config::ProjectConfig::load(&report.target.join("deploy.toml")).unwrap();
        assert_eq!(config.server("server-01").unwrap().user(), "ops");
        assert_eq!(
            match config.server("server-01").unwrap().identity() {
                crate::config::HostIdentity::KnownHosts(p) => Some(p.as_path()),
                _ => None,
            },
            Some(Path::new("/etc/ssh/known_hosts"))
        );
        assert!(!matches!(
            config.server("server-01").unwrap().identity(),
            crate::config::HostIdentity::Fingerprint(_)
        ));
    }
}

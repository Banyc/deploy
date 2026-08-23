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

use crate::error::{Error, Result};
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
    /// SSH port (default 22). Written into `deploy.toml` only when set.
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
/// Fails closed: refuses to write if `deploy.toml` or a `releases/` tree
/// already exists at `target`, never writes outside it, and rejects an SSH
/// `--address` that does not configure EXACTLY ONE host-identity source
/// (`known_hosts` or `host_key_fingerprint`) — SSH trust-on-first-use is
/// disabled, and both sources together are ambiguous.
pub fn init_project(target: &Path, opts: &InitOptions) -> Result<InitReport> {
    let target = ensure_target_dir(target)?;
    let name = sanitize_name(&match &opts.name {
        Some(n) => n.clone(),
        None => target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "deploy".to_string()),
    });

    // An SSH address (anything that is not an explicit `local://` endpoint)
    // needs exactly one host-identity source. `clap` already rejects both
    // flags together; this catches the SSH-address-without-identity case
    // before anything is written.
    let has_known_hosts = opts.known_hosts.is_some();
    let has_fingerprint = opts.host_key_fingerprint.is_some();
    if let Some(a) = &opts.address
        && !a.starts_with("local://")
    {
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

    // Fail closed: never clobber. Both checks run before the first write.
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

    let address = match &opts.address {
        Some(a) => a.clone(),
        None => format!("local://{}", target.join(".deploy-remote").display()),
    };
    let deploy_dir = match address.strip_prefix("local://") {
        // The local endpoint doubles as the slot's deploy location. The
        // transport is rooted at the `local://` path; the deploy_dir must stay
        // an absolute path per validation.
        Some(p) => PathBuf::from(p),
        // Real server: a conventional absolute location the deployment account
        // must be able to create (documented in `deploy init --help`).
        None => PathBuf::from(format!("/srv/deploy/{name}")),
    };

    let mut files = Vec::new();
    let mut dirs = Vec::new();

    write_project_file(
        &target,
        &deploy_toml_path,
        &deploy_toml(&name, &address, opts, &deploy_dir),
        &mut files,
    )?;
    write_project_file(
        &target,
        &target.join("releases/v1/standard.toml"),
        STANDARD_VARIANT,
        &mut files,
    )?;
    write_project_file(
        &target,
        &target.join("releases/v1/systemd.toml"),
        SYSTEMD_VARIANT,
        &mut files,
    )?;
    write_project_file(
        &target,
        &target.join("releases/v1/artifacts/build/output/app/hello"),
        PLACEHOLDER,
        &mut files,
    )?;
    write_project_file(
        &target,
        &target.join("releases/v1/artifacts/systemd/example.service"),
        &systemd_unit_file(&deploy_dir),
        &mut files,
    )?;

    // The `local://` endpoint: created up front so the scaffold is visibly
    // self-contained. A push would provision it anyway.
    let endpoint = target.join(".deploy-remote");
    std::fs::create_dir_all(&endpoint).map_err(Error::Io)?;
    dirs.push(PathBuf::from(".deploy-remote"));

    // Keep `.deploy-remote/` out of source control when the project sits in a
    // repo. Only created when the project has no `.gitignore` yet.
    let gitignore = target.join(".gitignore");
    if !gitignore.exists() {
        write_project_file(&target, &gitignore, ".deploy-remote/\n", &mut files)?;
    }

    files.sort();
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

/// Create `target` if missing and canonicalize it to an absolute path. The
/// parent of `target` must already exist (init creates the project directory
/// itself, not an arbitrary path chain).
fn ensure_target_dir(target: &Path) -> Result<PathBuf> {
    if target.exists() {
        if !target.is_dir() {
            return Err(Error::config(format!(
                "init target '{}' exists and is not a directory",
                target.display()
            )));
        }
        return target.canonicalize().map_err(Error::Io);
    }
    std::fs::create_dir_all(target)
        .map_err(|e| Error::config(format!("creating init target '{}': {e}", target.display())))?;
    target.canonicalize().map_err(Error::Io)
}

/// Write one file inside `target`, creating parent directories, and record its
/// target-relative path in `files` for the report.
fn write_project_file(
    target: &Path,
    path: &Path,
    content: &str,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    std::fs::write(path, content).map_err(Error::Io)?;
    let rel = path.strip_prefix(target).unwrap_or(path).to_path_buf();
    files.push(rel);
    Ok(())
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

const PLACEHOLDER: &str = "Hello from deploy!\n\
\n\
This placeholder is mapped into the artifact as `app/hello` by the\n\
`standard` variant (see releases/v1/standard.toml). Add or replace files\n\
under releases/v1/artifacts/ and run `deploy push production` again.\n";

const SYSTEMD_VARIANT: &str = r#"# The `systemd` variant: same artifact mappings as `standard`, but the
# deployment is activated through a real systemd user unit shipped as an
# artifact (`artifacts/systemd/example.service`). Every *.toml file directly
# inside the release directory is a variant, named by its file stem.
description = "Systemd-managed deployment"

[[artifact.mappings]]
from = "artifacts/build/output/app/"
to = "app/"
recursive = true

# The unit file is an artifact too: it lands at `app/example.service` in the
# release tree, matching `artifact_path` below.
[[artifact.mappings]]
from = "artifacts/systemd/"
to = "app/"
recursive = true

# Activation: what happens after `current` is atomically swapped. This is the
# `standard` variant's commented-out systemd block made live: on push the unit
# is linked into the user service manager, enabled, and restarted.
# Artifact-controlled unit files are supported by default only with
# `scope = "user"` (systemctl --user): they hold no more authority than the
# deployment account, and a host may need one-time admin configuration to keep
# the user manager running. `scope = "system"` instead requires an
# admin-installed root-owned wrapper unit. See releases/v1/standard.toml.
[activation]
adapter = "systemd"
scope = "user"                     # "user" (default) | "system"
reconcile_managed_units = true     # on success, disable and remove
                                   # formerly-managed links absent from the
                                   # new behavior contract
[[activation.units]]               # required: at least one unit
name = "example.service"           # unit name to enable and restart
artifact_path = "app/example.service"  # unit file inside the release tree
enable = true                      # systemctl enable (default)
restart = true                     # systemctl restart (default)

[verification]
adapter = "command"
argv = ["true"]           # replace with a real health-check command
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

/// The unit file shipped with the scaffold's `systemd` variant. The
/// `ExecStart` must point at the artifact's real landing spot under the slot's
/// `deploy_dir` (`current/app/hello`), so it is interpolated from the
/// scaffold's deploy_dir — for the default `local://` project that is the
/// absolute `.deploy-remote` path.
fn systemd_unit_file(deploy_dir: &Path) -> String {
    format!(
        r#"# systemd user unit for the scaffold's `systemd` example variant
# (releases/v1/systemd.toml). `deploy push` links this file into the user
# service manager (`~/.config/systemd/user/`) and enables/restarts it.
# `ExecStart` resolves through the deployment's `current` symlink, so a
# successful push atomically points the running service at the new generation.
[Unit]
Description=Example service (managed by deploy)

[Service]
ExecStart={}/current/app/hello
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#,
        deploy_dir.display()
    )
}

const STANDARD_VARIANT: &str = r#"# The `standard` variant. Every *.toml file directly inside the release
# directory is a variant, named by its file stem: add a file to add a variant.
# `from` paths resolve inside the release directory, so artifact sources live
# under `artifacts/` (the forced project structure — see `deploy help`).
description = "Standard deployment"

[[artifact.mappings]]
from = "artifacts/build/output/app/"
to = "app/"
recursive = true

# Activation: what happens after `current` is atomically swapped.
#
# `adapter = "none"` is a pure file push: the mapped artifacts land under
# `current/` and nothing else runs. Use it when the service is managed
# out-of-band or needs no service manager. To manage a service per
# deployment, switch to the systemd adapter instead (commented out below):
#
#   [activation]
#   adapter = "systemd"
#   scope = "user"                     # "user" (default) | "system"
#   reconcile_managed_units = true     # on success, disable and remove
#                                      # formerly-managed links absent from
#                                      # the new behavior contract; unrelated
#                                      # units are never touched
#   [[activation.units]]               # required: at least one unit
#   name = "my-app.service"            # unit name to enable and restart
#   artifact_path = "app/my-app.service"  # unit file inside the release tree
#   enable = true                      # systemctl enable (default)
#   restart = true                     # systemctl restart (default)
#
# Artifact-controlled unit files are supported by default only with
# `scope = "user"` (systemctl --user): they hold no more authority than the
# deployment account, and a host may need one-time admin configuration to keep
# the user manager running. `scope = "system"` instead requires an
# admin-installed root-owned wrapper unit: push only verifies that wrapper's
# identity and restarts that specific unit with a narrowly scoped permission —
# it never links artifact unit files into /etc/systemd/system.
[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]           # replace with a real health-check command
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

/// The scaffolded `deploy.toml` (schema version 1), annotated to teach the
/// forced project structure. Must pass `Config::load` validation as written.
fn deploy_toml(name: &str, address: &str, opts: &InitOptions, deploy_dir: &Path) -> String {
    let mut servers = String::new();
    if let Some(port) = opts.port {
        servers.push_str(&format!("port = {port}\n"));
    }
    if let Some(kh) = &opts.known_hosts {
        servers.push_str(&format!("known_hosts = \"{}\"\n", kh.display()));
    }
    if let Some(fp) = &opts.host_key_fingerprint {
        servers.push_str(&format!("host_key_fingerprint = \"{fp}\"\n"));
    }
    // Capacity is a per-server policy (shared by every deployment slot on the
    // server), resolved from this file at preflight time — never part of the
    // release identity.
    servers.push_str(
        "capacity = { reserve_bytes = 0, reserve_percent = 0 }  # keep at least this much free\n",
    );

    format!(
        r#"# deploy.toml — generated by `deploy init`. Schema version 1.
# The project structure is forced (see `deploy help`):
#   releases/<release>/            the release directory named by `release:`
#   releases/<release>/*.toml      one file per variant (file stem = variant name)
#   releases/<release>/artifacts/  artifact sources mapped by variants
schema_version = 1
application = "{name}"

# The active release. Cut a new one by copying `releases/v1` to
# `releases/v2`, editing the variant files, and bumping this line.
release = "v1"

# Servers are declared once at the top level; slots bind a server to a variant;
# targets group slots by ID and carry the rollout policy.
#
# LOCAL-FIRST DEFAULT: `local://<abs-path>` makes `deploy push` run against a
# local filesystem endpoint (`.deploy-remote/` in this project) with zero SSH
# or server infrastructure. To deploy to a real server, replace `address` with
# a hostname, set `user`, and add `known_hosts` (or `host_key_fingerprint =
# "SHA256:...") — SSH trust-on-first-use is refused. See `deploy init --help`.
[[servers]]
id = "server-01"          # durable ID; never rename it (history keys on it)
address = "{address}"
user = "{user}"
{servers}
# A slot binds one server to one variant and names the absolute directory on
# the server where deployment state (objects, generations, `current`) lives.
[[slots]]
id = "app-1"
server = "server-01"
variant = "standard"
deploy_dir = "{deploy_dir}"

# Targets group slots by ID, in rollout order.
[targets.production]
slots = ["app-1"]

[targets.production.rollout]
batch_size = 1
stop_on_failure = true
failure_policy = "rollback_changed"

# Retention belongs to the target: how aggressively its servers rotate.
[targets.production.rotation.per_server]
keep_distinct_artifacts = 5   # keep the newest 5 distinct artifacts per server
keep_days = 14                # ...and everything activated in the last 14 days
protect_previous = true       # never delete the artifact `current` rolls back to

[targets.production.rotation.fleet]
protect_deployments = 2       # keep each server's artifacts of the newest 2 successful deployments
"#,
        name = name,
        address = address,
        user = opts.user,
        servers = servers,
        deploy_dir = deploy_dir.display(),
    )
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
        let config = crate::config::Config::load(&report.target.join("deploy.toml")).unwrap();
        assert_eq!(config.application, "my-app");
        assert_eq!(config.release.as_str(), "v1");
        assert_eq!(config.targets["production"].slots, vec!["app-1"]);
        assert_eq!(
            config.variant("standard").unwrap().verification.argv,
            vec!["true"]
        );

        // The scaffold also ships the `systemd` example variant with a real
        // unit artifact; it is not bound to any slot, so pushes stay
        // adapter-agnostic.
        let systemd = config.variant("systemd").unwrap();
        assert_eq!(systemd.activation.adapter, "systemd");
        assert_eq!(
            systemd.activation.scope,
            crate::config::ActivationScope::User
        );
        assert_eq!(systemd.activation.units.len(), 1);
        assert_eq!(systemd.activation.units[0].name, "example.service");
        assert_eq!(
            systemd.activation.units[0].artifact_path,
            "app/example.service"
        );
        assert!(
            report
                .target
                .join("releases/v1/artifacts/systemd/example.service")
                .is_file()
        );

        // The local-first address routes the transport into the project.
        let addr = &config.servers[0].address;
        assert!(
            addr.starts_with("local://") && addr.ends_with("/.deploy-remote"),
            "unexpected address {addr}"
        );
        assert!(config.slots[0].deploy_dir.is_absolute());
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
        let config = crate::config::Config::load(&report.target.join("deploy.toml")).unwrap();
        assert_eq!(
            config.servers[0].host_key_fingerprint.as_deref(),
            Some("SHA256:abc")
        );
        assert!(config.servers[0].known_hosts.is_none());

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
            ..Default::default()
        };
        let report = init_project(&proj, &opts).unwrap();
        let config = crate::config::Config::load(&report.target.join("deploy.toml")).unwrap();
        assert_eq!(config.application, "prod");
        let s = &config.servers[0];
        assert_eq!(s.address, "app.example.com");
        assert_eq!(s.user, "ops");
        assert_eq!(s.port, 2222);
        assert_eq!(
            s.known_hosts.as_deref(),
            Some(Path::new("/etc/ssh/known_hosts"))
        );
        // No local endpoint: the slot targets a conventional server path.
        assert!(config.slots[0].deploy_dir.is_absolute());
        assert!(config.slots[0].deploy_dir.starts_with("/srv/deploy/"));
    }
}

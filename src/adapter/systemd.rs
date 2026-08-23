//! Systemd activation adapter.
//!
//! The mapped unit file remains an ordinary artifact in the tree, but its
//! CONTENT is rendered with the slot's template context (see
//! [`crate::template`]) at activation time: unit files use per-slot values
//! such as `ExecStart={{ deploy_dir }}/current/app/server`, and trees are
//! content-addressed and shared across slots, so the slot context can only be
//! substituted when the unit is installed, never at materialization. The
//! rendered unit is staged under the remote root as a REGULAR FILE (a rendered
//! unit can no longer be a symlink into the generation tree) and copied into
//! the user service manager directory. For `scope: user` it manages
//! `~/.config/systemd/user/<unit>` files and uses `systemctl --user`. For
//! `scope: system` it only verifies a fixed, root-owned wrapper unit and uses
//! a narrowly scoped restart permission; it never installs an
//! artifact-controlled unit into `/etc/systemd/system`.

use crate::config::{ActivationConfig, validate_relative_path};
use crate::error::{Error, Result};
use crate::remote::transport::Remote;
use crate::template::TemplateVars;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Remote-root-relative directory where rendered unit files are staged before
/// being copied into the user service manager directory. The regular file
/// under this directory is what `cp` installs; it sits next to the
/// `adapters/systemd.json` state file (a file and a directory can coexist
/// under `adapters/`).
const RENDERED_UNITS_DIR: &str = "adapters/systemd";

/// Resolve the XDG configuration home base from explicit variables.
///
/// Pure: takes the variable values as arguments so it can be tested without
/// mutating the process-wide environment.
///
/// * `XDG_CONFIG_HOME` wins when set and non-empty.
/// * otherwise `$HOME/.config`.
/// * otherwise `.config`.
pub fn resolve_config_home(xdg_config_home: Option<&str>, home: Option<&str>) -> PathBuf {
    match xdg_config_home.filter(|s| !s.is_empty()) {
        Some(xdg) => PathBuf::from(xdg),
        None => match home.filter(|s| !s.is_empty()) {
            Some(h) => PathBuf::from(h).join(".config"),
            None => PathBuf::from(".config"),
        },
    }
}

/// The configuration base directory for the current process environment.
pub fn config_home() -> PathBuf {
    resolve_config_home(
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Where user-scope unit links live: `<config_home>/systemd/user/<unit>`.
pub fn user_unit_link(_deploy_dir: &Path, unit: &str) -> PathBuf {
    user_unit_link_for(&config_home(), unit)
}

/// Pure variant of [`user_unit_link`] that takes an explicit config base, so it
/// can be tested without depending on the process environment.
pub fn user_unit_link_for(config_base: &Path, unit: &str) -> PathBuf {
    config_base.join("systemd/user").join(unit)
}

/// Resolve the XDG config base on the *remote* host by asking its shell. The
/// systemd user unit directory lives under `${XDG_CONFIG_HOME:-$HOME/.config}`,
/// and that value must come from the host where the unit will be linked and
/// activated, not from the controller's own environment.
pub fn resolve_remote_config_home(remote: &dyn Remote) -> Result<PathBuf> {
    let outcome = remote.exec(
        &[
            "sh".into(),
            "-c".into(),
            r#"printf "%s" "${XDG_CONFIG_HOME:-$HOME/.config}""#.into(),
        ],
        Duration::from_secs(30),
    )?;
    if !outcome.success() {
        return Err(Error::remote(format!(
            "resolve remote config home failed: {}",
            outcome.stderr
        )));
    }
    let home = outcome.stdout.trim().to_string();
    if home.is_empty() {
        return Err(Error::remote("remote config home resolved to empty"));
    }
    Ok(PathBuf::from(home))
}

/// Reject unit names that could escape the systemd/user directory
/// (absolute paths, parent-dir components, or empty names).
fn validate_unit_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::config("systemd unit name must not be empty"));
    }
    if Path::new(name).is_absolute() {
        return Err(Error::config(format!(
            "systemd unit name '{}' must not be an absolute path",
            name
        )));
    }
    let dangerous = name
        .split('/')
        .any(|c| c == ".." || c == "." || c.is_empty());
    if dangerous {
        return Err(Error::config(format!(
            "systemd unit name '{}' must be a single filename",
            name
        )));
    }
    Ok(())
}

/// Build the activation command vectors for the given remote root.
///
/// Ordering follows the required contract:
/// 1. Create the parent directory and (user scope only) install each unit:
///    the unit was staged as a rendered REGULAR FILE under
///    `<remote_root>/adapters/systemd/<unit>` by [`stage_rendered_units`], and
///    `cp` copies it into the user systemd dir (the rendered content is never
///    concatenated into a command; commands only reference file paths).
/// 2. `daemon-reload` (user scope only).
/// 3. `enable` and `restart` each declared unit.
///
/// System scope never installs an artifact-controlled unit; it only performs
/// the narrowly scoped restart of the fixed wrapper unit.
///
/// `remote_root` is the absolute deployment directory on the remote host
/// ([`Remote::root`]); `config_home` is the remote host's resolved config
/// base (see [`resolve_remote_config_home`]); unit files are installed under
/// it so the path is correct on the remote host rather than reflecting the
/// controller's env.
pub fn activation_commands(
    remote_root: &Path,
    config_home: &Path,
    cfg: &ActivationConfig,
) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    let scope_user = matches!(cfg.scope, crate::config::ActivationScope::User);

    // 1. Parent directory + install each unit from its rendered staging file
    //    (user scope only).
    if scope_user {
        for u in &cfg.units {
            let link = user_unit_link_for(config_home, &u.name);
            if let Some(parent) = link.parent() {
                cmds.push(vec![
                    "mkdir".into(),
                    "-p".into(),
                    parent.to_string_lossy().into_owned(),
                ]);
            }
            let staged = remote_root.join(RENDERED_UNITS_DIR).join(&u.name);
            cmds.push(vec![
                "cp".into(),
                staged.to_string_lossy().into_owned(),
                link.to_string_lossy().into_owned(),
            ]);
            cmds.push(vec![
                "chmod".into(),
                "0644".into(),
                link.to_string_lossy().into_owned(),
            ]);
        }
    }

    // 2. daemon-reload (user scope only).
    if scope_user {
        cmds.push(vec![
            "systemctl".into(),
            "--user".into(),
            "daemon-reload".into(),
        ]);
    }

    // 3. enable + restart.
    for u in &cfg.units {
        if u.enable && scope_user {
            cmds.push(vec![
                "systemctl".into(),
                "--user".into(),
                "enable".into(),
                u.name.clone(),
            ]);
        }
        if u.restart {
            if scope_user {
                cmds.push(vec![
                    "systemctl".into(),
                    "--user".into(),
                    "restart".into(),
                    u.name.clone(),
                ]);
            } else {
                // system scope: only a narrowly scoped restart of the wrapper.
                cmds.push(vec!["systemctl".into(), "restart".into(), u.name.clone()]);
            }
        }
    }
    cmds
}

/// Render every declared unit's artifact content with the slot context and
/// stage the rendered REGULAR FILE under the remote root
/// (`adapters/systemd/<unit>`). The subsequent `cp` in
/// [`activation_commands`] installs the rendered copy into the user service
/// manager directory. A template error (unknown variable, malformed syntax)
/// fails loudly here, before any command runs.
pub fn stage_rendered_units(
    remote: &dyn Remote,
    generation_root: &Path,
    cfg: &ActivationConfig,
    vars: &TemplateVars,
) -> Result<()> {
    // `generation_root` is an absolute host path (`remote.root()` joined with
    // the generation layout); the transport's read/write surface is anchored
    // at the remote root, so strip the root prefix back off.
    let gen_rel = generation_root.strip_prefix(remote.root()).map_err(|_| {
        Error::remote(format!(
            "generation root '{}' is not under remote root '{}'",
            generation_root.display(),
            remote.root().display()
        ))
    })?;
    for u in &cfg.units {
        let src = gen_rel.join(&u.artifact_path);
        let raw = remote.read(&src).map_err(|e| {
            Error::remote(format!(
                "read unit artifact '{}' from generation tree: {e}",
                u.artifact_path
            ))
        })?;
        let text = std::str::from_utf8(&raw)
            .map_err(|e| Error::remote(format!("unit '{}' is not UTF-8: {e}", u.name)))?;
        let rendered = crate::template::render_template(text, vars).map_err(|e| {
            Error::remote(format!(
                "render unit '{}' ({}) with slot context: {e}",
                u.name, u.artifact_path
            ))
        })?;
        let dest = Path::new(RENDERED_UNITS_DIR).join(&u.name);
        remote
            .write(&dest, rendered.as_bytes(), 0o644)
            .map_err(|e| Error::remote(format!("stage rendered unit '{}': {e}", u.name)))?;
    }
    Ok(())
}

/// Validate that every declared artifact path exists in the desired generation
/// tree with the correct type before changing `current`.
pub fn validate_artifact_paths(
    remote: &dyn Remote,
    generation_root_rel: &Path,
    cfg: &ActivationConfig,
) -> Result<()> {
    for u in &cfg.units {
        let p = generation_root_rel.join(&u.artifact_path);
        if !remote.exists(&p) {
            return Err(Error::remote(format!(
                "declared artifact path '{}' missing in desired tree",
                u.artifact_path
            )));
        }
        let meta = remote.metadata(&p)?;
        if !meta.is_file {
            return Err(Error::remote(format!(
                "declared artifact path '{}' is not a regular file (type error)",
                u.artifact_path
            )));
        }
    }
    Ok(())
}

/// Run activation: render + stage the units with the slot context, build and
/// execute the systemd commands, then record the managed unit links.
///
/// `generation_root` is the absolute generation tree path on the remote host
/// (the source of each unit's artifact content); `vars` is the slot context
/// ([`TemplateVars::slot`]) whose `deploy_dir`/`variant`/... are substituted
/// into the unit content and any templated argv.
pub fn run_activation(
    remote: &dyn Remote,
    generation_root: &Path,
    cfg: &ActivationConfig,
    vars: &TemplateVars,
) -> Result<()> {
    if cfg.adapter != "systemd" {
        return Ok(());
    }
    // Validate every declared unit name and artifact path before touching any
    // remote state; a path traversal here would escape the generation root.
    for u in &cfg.units {
        validate_unit_name(&u.name)?;
        validate_relative_path(Path::new(&u.artifact_path))
            .map_err(|e| Error::remote(format!("unit '{}' artifact path invalid: {e}", u.name)))?;
    }
    // Render + stage the units BEFORE any command runs: a template error
    // (unknown variable, malformed syntax) must fail activation loudly, never
    // install a half-rendered unit or leave the previous unit in place.
    if matches!(cfg.scope, crate::config::ActivationScope::User) {
        stage_rendered_units(remote, generation_root, cfg, vars)?;
    }
    // Resolve the unit directory base on the *remote* host, not the controller.
    let config_home = resolve_remote_config_home(remote)?;
    let cmds = activation_commands(remote.root(), &config_home, cfg);
    for argv in &cmds {
        let outcome = remote.exec(argv, Duration::from_secs(30))?;
        if !outcome.success() {
            return Err(Error::remote(format!(
                "systemd activation command {:?} failed: {}",
                argv, outcome.stderr
            )));
        }
    }
    let managed: Vec<String> = cfg.units.iter().map(|u| u.name.clone()).collect();
    let payload = serde_json::json!({ "managed_units": managed });
    let bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|e| Error::remote(format!("serialize systemd state: {e}")))?;
    remote.write(Path::new("adapters/systemd.json"), &bytes, 0o644)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{ActivationConfig, ActivationScope, UnitDef};
    use crate::model::{DeploymentId, GenerationId, TreeDigest};
    use crate::remote::transport::LocalTransport;

    /// Serializes every test that mutates the process-wide `PATH` or
    /// `XDG_CONFIG_HOME` (the fake-`systemctl` end-to-end test here and the
    /// engine-level systemd push regression in `push/engine.rs`): all lib
    /// tests share one process, and `run_activation` resolves the unit
    /// directory base from the process environment, so two env-mutating tests
    /// must never overlap.
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn cfg(scope: ActivationScope, units: Vec<&str>) -> ActivationConfig {
        ActivationConfig {
            adapter: "systemd".into(),
            scope,
            reconcile_managed_units: true,
            units: units
                .into_iter()
                .map(|n| UnitDef {
                    name: n.into(),
                    artifact_path: format!("integration/systemd/{n}"),
                    enable: true,
                    restart: true,
                })
                .collect(),
        }
    }

    /// Full slot context including the per-server metadata (user, address,
    /// port), the slot ID, and the per-deployment identity, exactly as the
    /// engine's `slot_vars` fills it for the activation/verification path.
    fn slot_vars() -> TemplateVars {
        TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            "standard",
            "example",
            "v1",
            "production",
            "server-01",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("deploy-1")),
            Some(&GenerationId::new("gen-1")),
            Some(&TreeDigest::new("abc123")),
        )
    }

    #[test]
    fn config_home_resolution() {
        // XDG wins.
        assert_eq!(
            resolve_config_home(Some("/x/.config"), Some("/h")),
            PathBuf::from("/x/.config")
        );
        // HOME falls back to $HOME/.config.
        assert_eq!(
            resolve_config_home(None, Some("/h")),
            PathBuf::from("/h/.config")
        );
        // Neither -> .config
        assert_eq!(resolve_config_home(None, None), PathBuf::from(".config"));
    }

    #[test]
    fn user_link_uses_config_base() {
        // Resolution lives under <config_base>/systemd/user/<unit>.
        let link = user_unit_link_for(Path::new("/home/deploy/.config"), "example.service");
        assert_eq!(
            link,
            PathBuf::from("/home/deploy/.config/systemd/user/example.service")
        );
        // XDG_CONFIG_HOME base is used verbatim (no extra .config appended).
        let link = user_unit_link_for(Path::new("/x/.config"), "example.service");
        assert_eq!(
            link,
            PathBuf::from("/x/.config/systemd/user/example.service")
        );
        // The public helper resolves the environment-derived base.
        let link = user_unit_link(Path::new("/srv/x"), "example.service");
        assert!(link.ends_with("systemd/user/example.service"));
    }

    #[test]
    fn user_commands_install_rendered_unit_before_reload() {
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let cmds =
            activation_commands(Path::new("/srv/eng"), Path::new("/home/deploy/.config"), &c);
        // First commands must mkdir + cp + chmod (install), then
        // daemon-reload after the copy.
        assert_eq!(cmds[0][0], "mkdir");
        assert_eq!(cmds[1][0], "cp");
        assert_eq!(
            cmds[1][1], "/srv/eng/adapters/systemd/example.service",
            "cp source is the staged rendered unit under the remote root"
        );
        assert_eq!(
            cmds[1][2], "/home/deploy/.config/systemd/user/example.service",
            "cp destination is the user systemd dir"
        );
        assert_eq!(cmds[2][0], "chmod");
        assert_eq!(cmds[2][1], "0644");
        let reload_idx = cmds
            .iter()
            .position(|c| {
                c.len() >= 3 && c[0] == "systemctl" && c[1] == "--user" && c[2] == "daemon-reload"
            })
            .unwrap();
        let cp_idx = cmds.iter().position(|c| c[0] == "cp").unwrap();
        assert!(
            cp_idx < reload_idx,
            "installed unit must precede daemon-reload"
        );
        // enable + restart present with --user.
        assert!(cmds.iter().any(|c| c.contains(&"enable".to_string())));
        assert!(cmds.iter().any(|c| c.contains(&"restart".to_string())));
        assert!(
            cmds.iter().all(
                |c| !(c[0] == "systemctl" && c[1] == "--user" && c[2] == "restart") || c.len() == 4
            )
        );
    }

    #[test]
    fn system_scope_does_not_install_user_units() {
        let c = cfg(ActivationScope::System, vec!["wrapper.service"]);
        let cmds = activation_commands(Path::new("/srv/x"), Path::new("/home/deploy/.config"), &c);
        // No mkdir/cp/chmod for artifact units in system scope.
        assert!(!cmds.iter().any(|c| c[0] == "mkdir"));
        assert!(!cmds.iter().any(|c| c[0] == "cp"));
        assert!(!cmds.iter().any(|c| c[0] == "chmod"));
        // Only a narrow restart of the wrapper (no --user).
        assert!(
            cmds.iter()
                .any(|c| c == &vec!["systemctl", "restart", "wrapper.service"])
        );
    }

    /// A unit file containing `{{ deploy_dir }}`, `{{ user }}`, `{{ address }}`,
    /// `{{ port }}`, and `{{ deployment_id }}` (plus other elected variables)
    /// renders with the slot's context when staged, and the staged REGULAR
    /// FILE is what the install commands copy into the user systemd dir. The
    /// per-server `user`/`address`/`port` values come from the matching
    /// `[[servers]]` entry; `deployment_id` from the push being activated.
    #[test]
    fn rendered_unit_uses_slot_deploy_dir_and_server_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("remote");
        let remote = LocalTransport::new(base.clone()).unwrap();
        // Tree content under the object store, like `tree::canonicalize_tree`.
        let tree_rel = crate::layout::tree_root("abc123");
        let unit_rel = tree_rel.join("integration/systemd/example.service");
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(
            base.join(&unit_rel),
            "[Service]\n# deployed by {{ user }} on {{ address }}:{{ port }} (deployment {{ deployment_id }})\nExecStart={{ deploy_dir }}/current/app/server\nArg={{ variant }} {{ application }} {{ target }}/{{ server }}\n",
        )
        .unwrap();
        // `generations/<gid>/root` -> the tree content root (symlink), as the
        // helper creates it.
        let gen_rel = crate::layout::generation("g1");
        let gen_dir = base.join(&gen_rel);
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink(
            crate::layout::generation_root_link("abc123"),
            gen_dir.join("root"),
        )
        .unwrap();

        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let generation_root = base.join(gen_rel).join("root");
        stage_rendered_units(&remote, &generation_root, &c, &slot_vars()).unwrap();

        // The staged copy is a regular file with the rendered content.
        let staged = remote
            .read(Path::new("adapters/systemd/example.service"))
            .unwrap();
        assert_eq!(
            String::from_utf8(staged).unwrap(),
            "[Service]\n# deployed by deploy on 10.0.0.5:22 (deployment deploy-1)\nExecStart=/srv/deploy/example/current/app/server\nArg=standard example production/server-01\n"
        );
        // The install commands install the staged file into the user dir.
        let cmds = activation_commands(&base, Path::new("/home/deploy/.config"), &c);
        let cp = cmds.iter().find(|c| c[0] == "cp").unwrap();
        assert_eq!(
            cp[1],
            base.join("adapters/systemd/example.service")
                .to_string_lossy()
        );
        assert_eq!(cp[2], "/home/deploy/.config/systemd/user/example.service");
    }

    /// Regression: the activation generation root must be
    /// `<remote_root>/generations/<gid>/root` — the `root` symlink to the tree
    /// content root — never `<remote_root>/generations/<gid>/root/root`.
    /// `push/engine.rs` builds this path at both `run_activation` call sites;
    /// staging derives the unit read source from it, so a `root/root`
    /// double-join would try to read through a nonexistent nested `root`
    /// directory inside the tree content root and fail loudly. This test pins
    /// the shape and proves staging reads the unit from the canonical root.
    #[test]
    fn activation_generation_root_is_single_root_not_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("remote");
        let remote = LocalTransport::new(base.clone()).unwrap();
        // Unit artifact under the tree content root.
        let tree_rel = crate::layout::tree_root("abc123");
        let unit_rel = tree_rel.join("integration/systemd/example.service");
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(
            base.join(&unit_rel),
            "[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
        )
        .unwrap();
        // `generations/<gid>/root` -> the tree content root (symlink), exactly
        // as `RemoteHelper::create_generation` installs it.
        let gen_dir = base.join(crate::layout::generation("g1"));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink(
            crate::layout::generation_root_link("abc123"),
            gen_dir.join("root"),
        )
        .unwrap();

        // Build the generation root exactly as the engine does at both
        // `run_activation` call sites: `<root>/generations/<gid>/root`.
        let generation_root = remote
            .root()
            .join(crate::layout::generation("g1"))
            .join("root");
        assert!(
            generation_root.ends_with(Path::new("generations/g1/root")),
            "activation generation root must be <root>/generations/<gid>/root, got {}",
            generation_root.display()
        );
        assert!(
            !generation_root.to_string_lossy().contains("root/root"),
            "activation generation root must never be a nested root/root, got {}",
            generation_root.display()
        );

        // Staging reads the unit from `generations/<gid>/root/<artifact>`:
        // assert the exact relative read source `stage_rendered_units` derives
        // from the generation root.
        let gen_rel = generation_root.strip_prefix(remote.root()).unwrap();
        let read_src = gen_rel.join("integration/systemd/example.service");
        assert_eq!(
            read_src,
            Path::new("generations/g1/root/integration/systemd/example.service")
        );
        assert!(
            !read_src.to_string_lossy().contains("root/root"),
            "unit read source must not be a nested root/root path"
        );
        // The double-joined variant resolves to nothing on this layout (the
        // tree content root has no nested `root` directory), so a `root/root`
        // generation root would fail activation with a read error.
        assert!(
            !base.join("generations/g1/root/root").exists(),
            "tree content root must have no nested root dir (a root/root double-join would ENOENT)"
        );

        // End-to-end: staging must read the content through the canonical
        // `generations/<gid>/root` symlink (only that path reaches the unit).
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        stage_rendered_units(&remote, &generation_root, &c, &slot_vars()).unwrap();
        let staged = remote
            .read(Path::new("adapters/systemd/example.service"))
            .unwrap();
        assert_eq!(
            String::from_utf8(staged).unwrap(),
            "[Service]\nExecStart=/srv/deploy/example/current/app/server\n"
        );
    }

    /// An unknown or malformed variable in a unit file fails activation
    /// loudly: nothing is staged and nothing is installed.
    #[test]
    fn unit_template_error_fails_loudly() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("remote");
        let remote = LocalTransport::new(base.clone()).unwrap();
        let gen_rel = crate::layout::generation("g1");
        let unit_rel = gen_rel.join("root/integration/systemd/example.service");
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(base.join(&unit_rel), "ExecStart={{ bogus }}\n").unwrap();

        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let generation_root = base.join(gen_rel).join("root");
        let err = stage_rendered_units(&remote, &generation_root, &c, &slot_vars()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown template variable 'bogus'")
        );
        assert!(
            !base.join("adapters/systemd/example.service").exists(),
            "nothing staged on a template error"
        );
    }

    /// End-to-end activation on a local transport: the adapter stages the
    /// rendered unit, resolves the config home on the "remote" host (the
    /// local host, via `sh`), and EXECUTES the mkdir/cp/chmod/systemctl
    /// commands. A fake `systemctl` shim in PATH and a temp `XDG_CONFIG_HOME`
    /// keep the test hermetic; the assertion is that the INSTALLED file in the
    /// user systemd dir is a regular file containing the slot-rendered unit.
    #[test]
    fn run_activation_installs_rendered_unit_end_to_end() {
        use std::os::unix::fs::PermissionsExt;
        let _lock = ENV_LOCK.lock().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("remote");
        let remote = LocalTransport::new(base.clone()).unwrap();
        // Unit artifact with a slot-dependent ExecStart and the per-server
        // deployment account, under the tree.
        let tree_rel = crate::layout::tree_root("abc123");
        let unit_rel = tree_rel.join("integration/systemd/example.service");
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(
            base.join(&unit_rel),
            "[Unit]\nDescription=Example service (managed by deploy, run as {{ user }})\n\n[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
        )
        .unwrap();
        let gen_dir = base.join(crate::layout::generation("g1"));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink(
            crate::layout::generation_root_link("abc123"),
            gen_dir.join("root"),
        )
        .unwrap();

        // Fake systemctl (daemon-reload/enable/restart all succeed) and a temp
        // config home so the installed unit lands somewhere hermetic.
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        let old_path = std::env::var_os("PATH");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bindir.display(),
                    old_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
            );
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }

        // Regression pin: the activation generation root must be
        // `<remote>/generations/<gid>/root` (the symlink to the tree content
        // root), never a nested `root/root`. A double-join would make staging
        // read through a nonexistent `root` directory inside the tree content
        // root and fail below.
        let generation_root = base.join(crate::layout::generation("g1")).join("root");
        assert!(
            generation_root.ends_with(Path::new("generations/g1/root")),
            "activation root must be <root>/generations/<gid>/root, got {}",
            generation_root.display()
        );
        assert!(
            !generation_root.to_string_lossy().contains("root/root"),
            "activation root must not be a nested root/root, got {}",
            generation_root.display()
        );
        assert!(
            !base.join("generations/g1/root/root").exists(),
            "tree content root has no nested root dir: a root/root double-join would ENOENT"
        );

        let result = (|| {
            let c = cfg(ActivationScope::User, vec!["example.service"]);
            run_activation(&remote, &generation_root, &c, &slot_vars())
        })();
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        match old_xdg {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
        result.unwrap();

        // The installed unit is a REGULAR FILE with the slot-rendered content
        // (never a symlink into the generation tree).
        let installed = config_home.join("systemd/user/example.service");
        let meta = std::fs::symlink_metadata(&installed).unwrap();
        assert!(meta.is_file(), "installed unit must be a regular file");
        assert_eq!(
            std::fs::read_to_string(&installed).unwrap(),
            "[Unit]\nDescription=Example service (managed by deploy, run as deploy)\n\n[Service]\nExecStart=/srv/deploy/example/current/app/server\n"
        );
        // Adapter state recorded on the remote root.
        assert!(base.join("adapters/systemd.json").is_file());
    }
}

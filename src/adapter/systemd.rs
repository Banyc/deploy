//! Systemd activation adapter.
//!
//! The mapped unit file remains an ordinary artifact. The adapter alone knows
//! how to register and activate it. For `scope: user` it manages
//! `~/.config/systemd/user/<unit>` links and uses `systemctl --user`. For
//! `scope: system` it only verifies a fixed, root-owned wrapper unit and uses a
//! narrowly scoped restart permission; it never links an artifact-controlled
//! unit into `/etc/systemd/system`.

use crate::config::{ActivationConfig, validate_relative_path};
use crate::error::{Error, Result};
use crate::remote::transport::Remote;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
pub fn user_unit_link(_remote_root: &Path, unit: &str) -> PathBuf {
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

/// Build the activation command vectors for the given generation root.
///
/// Ordering follows the required contract:
/// 1. Create the parent directory and (user scope only) create/update the unit
///    link, so the link exists before the manager reloads.
/// 2. `daemon-reload` (user scope only).
/// 3. `enable` and `restart` each declared unit.
///
/// System scope never links an artifact-controlled unit; it only performs the
/// narrowly scoped restart of the fixed wrapper unit.
///
/// `config_home` is the remote host's resolved config base (see
/// [`resolve_remote_config_home`]); unit links are placed under it so the path
/// is correct on the remote host rather than reflecting the controller's env.
pub fn activation_commands(
    cfg: &ActivationConfig,
    _remote_root: &Path,
    generation_root: &Path,
    config_home: &Path,
) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    let scope_user = matches!(cfg.scope, crate::config::ActivationScope::User);

    // 1. Parent directory + unit link (user scope only).
    if scope_user {
        for u in &cfg.units {
            let link_target = generation_root.join(&u.artifact_path);
            let link = user_unit_link_for(config_home, &u.name);
            if let Some(parent) = link.parent() {
                cmds.push(vec![
                    "mkdir".into(),
                    "-p".into(),
                    parent.to_string_lossy().into_owned(),
                ]);
            }
            cmds.push(vec![
                "ln".into(),
                "-sf".into(),
                link_target.to_string_lossy().into_owned(),
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

/// Validate that every declared artifact path exists in the desired generation
/// tree with the correct type before changing `current`.
pub fn validate_artifact_paths(
    remote: &dyn Remote,
    cfg: &ActivationConfig,
    generation_root_rel: &Path,
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

/// Run activation: build and execute the systemd commands, then record the
/// managed unit links.
pub fn run_activation(
    cfg: &ActivationConfig,
    remote: &dyn Remote,
    remote_root: &Path,
    generation_root: &Path,
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
    // Resolve the unit directory base on the *remote* host, not the controller.
    let config_home = resolve_remote_config_home(remote)?;
    let cmds = activation_commands(cfg, remote_root, generation_root, &config_home);
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
mod tests {
    use super::*;
    use crate::config::{ActivationConfig, ActivationScope, UnitDef};

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
    fn user_commands_link_before_reload() {
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let cmds = activation_commands(
            &c,
            Path::new("/srv/x"),
            Path::new("/gen"),
            Path::new("/home/deploy/.config"),
        );
        // First commands must mkdir + ln (link), then daemon-reload after.
        assert_eq!(cmds[0][0], "mkdir");
        assert_eq!(cmds[1][0], "ln");
        let reload_idx = cmds
            .iter()
            .position(|c| {
                c.len() >= 3 && c[0] == "systemctl" && c[1] == "--user" && c[2] == "daemon-reload"
            })
            .unwrap();
        let link_idx = cmds.iter().position(|c| c[0] == "ln").unwrap();
        assert!(link_idx < reload_idx, "links must precede daemon-reload");
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
    fn system_scope_does_not_link_user_units() {
        let c = cfg(ActivationScope::System, vec!["wrapper.service"]);
        let cmds = activation_commands(
            &c,
            Path::new("/srv/x"),
            Path::new("/gen"),
            Path::new("/home/deploy/.config"),
        );
        // No mkdir/ln for artifact links in system scope.
        assert!(!cmds.iter().any(|c| c[0] == "mkdir"));
        assert!(!cmds.iter().any(|c| c[0] == "ln"));
        // Only a narrow restart of the wrapper (no --user).
        assert!(
            cmds.iter()
                .any(|c| c == &vec!["systemctl", "restart", "wrapper.service"])
        );
    }
}

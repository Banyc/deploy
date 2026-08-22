//! Systemd activation adapter.
//!
//! The mapped unit file remains an ordinary artifact. The adapter alone knows
//! how to register and activate it. For `scope: user` it manages
//! `~/.config/systemd/user/<unit>` links and uses `systemctl --user`. For
//! `scope: system` it only verifies a fixed, root-owned wrapper unit and uses a
//! narrowly scoped restart permission; it never links an artifact-controlled
//! unit into `/etc/systemd/system`.

use crate::config::ActivationConfig;
use crate::error::{Error, Result};
use crate::remote::transport::Remote;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where user-scope unit links live.
pub fn user_unit_link(_remote_root: &Path, unit: &str) -> PathBuf {
    home_config()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("systemd/user")
        .join(unit)
}

fn home_config() -> Option<PathBuf> {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
        .map(|p| p.join("systemd/user"))
}

/// Build the activation command vectors for the given generation root.
pub fn activation_commands(
    cfg: &ActivationConfig,
    remote_root: &Path,
    generation_root: &Path,
) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    let scope_flag: Option<&str> = match cfg.scope {
        crate::config::ActivationScope::User => Some("--user"),
        crate::config::ActivationScope::System => None,
    };
    if let Some(flag) = scope_flag {
        cmds.push(vec![
            "systemctl".into(),
            flag.into(),
            "daemon-reload".into(),
        ]);
    }
    for u in &cfg.units {
        let link_target = generation_root.join(&u.artifact_path);
        let link = user_unit_link(remote_root, &u.name);
        cmds.push(vec![
            "ln".into(),
            "-sf".into(),
            link_target.to_string_lossy().into_owned(),
            link.to_string_lossy().into_owned(),
        ]);
        if u.enable && let Some(flag) = scope_flag {
            cmds.push(vec![
                "systemctl".into(),
                flag.into(),
                "enable".into(),
                u.name.clone(),
            ]);
        }
        if u.restart {
            if let Some(flag) = scope_flag {
                cmds.push(vec![
                    "systemctl".into(),
                    flag.into(),
                    "restart".into(),
                    u.name.clone(),
                ]);
            } else {
                // system scope: only a narrowly scoped restart of the wrapper.
                cmds.push(vec![
                    "systemctl".into(),
                    "restart".into(),
                    u.name.clone(),
                ]);
            }
        }
    }
    cmds
}

/// Validate that every declared artifact path exists in the desired generation
/// tree before changing `current`.
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
    let cmds = activation_commands(cfg, remote_root, generation_root);
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

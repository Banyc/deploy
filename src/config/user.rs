//! The per-user server overlay: `servers.toml` under the user-scope config
//! directory.
//!
//! Server connection details are machine- and account-specific — the address,
//! the SSH user, the port, and which host-identity source to use. This module
//! lets those live outside a project's `deploy.toml` in a per-user file:
//!
//! ```toml
//! [[servers]]
//! id = "server-02"
//! address = "104.36.71.200"
//! user = "root"
//! port = 28298
//! host_key_fingerprint = "SHA256:…"
//! ```
//!
//! The path is resolved by [`etcetera`] with the XDG application strategy and
//! the application name `deploy`: `$XDG_CONFIG_HOME/deploy/servers.toml`, or
//! `~/.config/deploy/servers.toml` when `XDG_CONFIG_HOME` is unset. The file is
//! read at the CLI process boundary ([`crate::cli::run`]); the library and its
//! hermetic tests take an explicit path ([`ProjectConfig::load_with_servers`]).
//!
//! # Overlay rules
//!
//! * A user entry whose `id` matches a project `[[servers]]` entry REPLACES
//!   that entry's connection fields (`address`, `user`, `port`, `known_hosts`
//!   and `host_key_fingerprint`) — the two identity fields move together, so a
//!   user entry cannot accidentally end up with both sources set. Its
//!   `capacity` overrides the project's only when the user entry declares one;
//!   otherwise the project's capacity is kept.
//! * A user entry whose `id` is not in the project is APPENDED, with the
//!   capacity it declares (zero when omitted). The project still has to name
//!   the server's `id` where a slot references it; the user file supplies the
//!   connection.
//! * A duplicate `id` inside the user file is refused: the overlay has no
//!   last-one-wins rule.
//! * A missing file is not an error (no overlay). An existing but unreadable
//!   or invalid file fails the load, naming the path.
//!
//! The merged servers pass through the SAME validation as the project's own
//! (exactly one host-identity source, unique ids, well-formed addresses), so
//! the overlay cannot smuggle an invalid connection into the domain.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use etcetera::app_strategy::{AppStrategy, AppStrategyArgs, Xdg};
use serde::Deserialize;

use crate::config::raw::{RawCapacityConfig, RawServer};
use crate::config::servers::default_ssh_port;
use crate::error::{Error, Result};

/// The user-scope file name inside the application's config directory.
const FILE_NAME: &str = "servers.toml";

/// The user-scope server overlay path, or `None` when the platform has no home
/// directory (there is nowhere to look). This is the ONE place the process
/// environment enters the overlay; it is called from [`crate::cli::run`] at
/// the process boundary, never from subsystem code.
pub fn path() -> Option<PathBuf> {
    let strategy = Xdg::new(AppStrategyArgs {
        top_level_domain: String::new(),
        author: String::new(),
        app_name: "deploy".to_string(),
    })
    .ok()?;
    Some(strategy.config_dir().join(FILE_NAME))
}

/// The raw shape of the overlay file: `[[servers]]` entries whose capacity is
/// optional (absent means "keep the project's capacity", unlike a project
/// entry where an absent capacity means zero).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserServersFile {
    servers: Vec<RawUserServer>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUserServer {
    id: String,
    address: String,
    user: String,
    #[serde(default = "default_ssh_port")]
    port: u16,
    #[serde(default)]
    known_hosts: Option<PathBuf>,
    #[serde(default)]
    host_key_fingerprint: Option<String>,
    #[serde(default)]
    capacity: Option<RawCapacityConfig>,
}

/// Apply the overlay at `path` to `project`'s servers, in place.
///
/// The caller runs this BEFORE the raw -> domain conversion, so the merged
/// vector goes through the one validator like any project file.
pub(crate) fn apply(project: &mut Vec<RawServer>, path: &Path) -> Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(Error::config(format!(
                "reading user server config {}: {e}",
                path.display()
            )));
        }
    };
    let file: UserServersFile = toml::from_str(&text).map_err(|e| {
        Error::config(format!(
            "parsing user server config {}: {e}",
            path.display()
        ))
    })?;
    let mut seen = BTreeSet::new();
    for entry in file.servers {
        if !seen.insert(entry.id.clone()) {
            return Err(Error::config(format!(
                "duplicate server id `{}` in user server config {}",
                entry.id,
                path.display()
            )));
        }
        match project.iter_mut().find(|server| server.id == entry.id) {
            Some(existing) => {
                existing.address = entry.address;
                existing.user = entry.user;
                existing.port = entry.port;
                existing.known_hosts = entry.known_hosts;
                existing.host_key_fingerprint = entry.host_key_fingerprint;
                if let Some(capacity) = entry.capacity {
                    existing.capacity = capacity;
                }
            }
            None => project.push(RawServer {
                id: entry.id,
                address: entry.address,
                user: entry.user,
                port: entry.port,
                known_hosts: entry.known_hosts,
                host_key_fingerprint: entry.host_key_fingerprint,
                capacity: entry.capacity.unwrap_or_else(RawCapacityConfig::empty),
            }),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project_server(id: &str, address: &str, fingerprint: &str) -> RawServer {
        RawServer {
            id: id.to_string(),
            address: address.to_string(),
            user: "project".to_string(),
            port: 22,
            known_hosts: None,
            host_key_fingerprint: Some(fingerprint.to_string()),
            capacity: RawCapacityConfig::empty(),
        }
    }

    fn write(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("servers.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn a_user_entry_replaces_the_connection_and_keeps_an_undeclared_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let mut project = vec![project_server("s1", "project-host", "SHA256:project")];
        project[0].capacity.reserve_bytes = 5;
        let path = write(
            dir.path(),
            r#"
[[servers]]
id = "s1"
address = "user-host"
user = "user"
host_key_fingerprint = "SHA256:user"
"#,
        );
        apply(&mut project, &path).unwrap();
        assert_eq!(project.len(), 1);
        assert_eq!(project[0].address, "user-host");
        assert_eq!(project[0].user, "user");
        assert_eq!(
            project[0].host_key_fingerprint.as_deref(),
            Some("SHA256:user")
        );
        assert!(project[0].known_hosts.is_none());
        assert_eq!(project[0].capacity.reserve_bytes, 5);
    }

    #[test]
    fn a_user_only_entry_is_appended_with_its_own_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let mut project = vec![project_server("s1", "a", "SHA256:a")];
        let path = write(
            dir.path(),
            r#"
[[servers]]
id = "s2"
address = "b"
user = "u"
known_hosts = "/etc/ssh/known_hosts"
capacity = { reserve_bytes = 7, reserve_percent = 0 }
"#,
        );
        apply(&mut project, &path).unwrap();
        assert_eq!(project.len(), 2);
        let added = &project[1];
        assert_eq!(added.id, "s2");
        assert_eq!(added.address, "b");
        assert_eq!(added.capacity.reserve_bytes, 7);
        assert!(added.host_key_fingerprint.is_none());
    }

    #[test]
    fn a_missing_file_is_no_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let mut project = vec![project_server("s1", "a", "SHA256:a")];
        apply(&mut project, &dir.path().join("absent.toml")).unwrap();
        assert_eq!(project, vec![project_server("s1", "a", "SHA256:a")]);
    }

    #[test]
    fn a_duplicate_id_in_the_user_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            r#"
[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:a"

[[servers]]
id = "s1"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:b"
"#,
        );
        let mut project = vec![project_server("s1", "a", "SHA256:a")];
        let error = apply(&mut project, &path).unwrap_err();
        assert!(error.to_string().contains("duplicate server id `s1`"));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            r#"
[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:a"
unexpected = 1
"#,
        );
        let mut project = vec![project_server("s1", "a", "SHA256:a")];
        let error = apply(&mut project, &path).unwrap_err();
        assert!(error.to_string().contains("parsing user server config"));
    }
}

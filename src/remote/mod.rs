//! Transport, remote helper, and remote adapter orchestration.

pub mod helper;
pub mod ssh;
pub mod transport;

use crate::config::{Config, ServerDef};
use crate::error::{Error, Result};
use crate::remote::transport::{LocalTransport, Remote};

/// Build the remote handle for one server from the configuration.
///
/// Production pushes use the SSH transport keyed by `ServerDef.address`,
/// `ServerDef.user`, and `Config.remote_root` with strict host-key
/// verification. The local transport is reserved for tests and for servers whose
/// `address` is an explicit `local://` path, which routes the transport to that
/// exact filesystem location (an explicit local endpoint) rather than the
/// application store's `remotes/` directory.
pub fn create_remote(server: &ServerDef, config: &Config) -> Result<Box<dyn Remote>> {
    if let Some(local_path) = server.address.strip_prefix("local://") {
        let p = std::path::PathBuf::from(local_path);
        if p.is_relative() {
            return Err(Error::transport(format!(
                "local:// endpoint must be an absolute path: '{}'",
                local_path
            )));
        }
        return Ok(Box::new(LocalTransport::new(p)?));
    }
    Ok(Box::new(ssh::SshTransport::new(
        &server.user,
        &server.address,
        server.port,
        &config.remote_root,
        server.known_hosts.as_deref(),
        server.host_key_fingerprint.as_deref(),
    )?))
}

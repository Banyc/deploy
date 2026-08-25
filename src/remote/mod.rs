//! Transport, remote helper, and remote adapter orchestration.

pub mod helper;
pub mod hostkey;
pub mod runner;
pub mod ssh;
pub mod transport;

use crate::config::ServerDef;
use crate::error::{Error, Result};
use crate::remote::transport::{LocalTransport, Remote};

/// Build the remote handle for one server from the configuration.
///
/// Production pushes use the SSH transport keyed by `ServerDef.address`,
/// `ServerDef.user`, and the slot's absolute `deploy_dir`, with strict host-key
/// verification. The local transport is reserved for tests and for servers whose
/// `address` is an explicit `local://` path, which routes the transport to that
/// exact filesystem location (an explicit local endpoint) rather than the
/// application store's `remotes/` directory.
pub fn create_remote(server: &ServerDef, deploy_dir: &std::path::Path) -> Result<Box<dyn Remote>> {
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
        deploy_dir,
        server.known_hosts.as_deref(),
        server.host_key_fingerprint.as_deref(),
    )?))
}

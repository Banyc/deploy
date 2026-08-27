//! Transport, remote helper, remote adapter orchestration, and the remote-
//! facing semantics: canonical tree objects, mapping/template materialization,
//! and the canonical on-server layout.
//!
//! # Modules
//!
//! * [`helper`] — [`RemoteHelper`](helper::RemoteHelper): status inspection,
//!   locking, generation switching, commit markers, inventory, rotation, and
//!   transaction records (the object-store-facing helpers — `tree_exists`,
//!   `stage_incoming`, `publish_from_incoming`, `remove_incoming` — stay here:
//!   they are [`RemoteHelper`](helper::RemoteHelper) methods interdependent
//!   with the rest of the struct, and splitting them would loosen the struct's
//!   field encapsulation).
//! * [`canonical`] — canonical tree objects (moved from `crate::tree`).
//! * [`materialize`] — mapping resolution + the template renderer (moved from
//!   `crate::mapper` / `crate::template`).
//! * [`layout`] — canonical on-server layout paths (moved from `crate::layout`).
//! * [`observed`] — the three-state observation types, re-exported from
//!   [`crate::ledger`] (owned by the A2 ledger area).
//! * [`transport`], [`ssh`], [`hostkey`], [`runner`] — transport and
//!   execution layers.

pub mod canonical;
pub mod helper;
pub mod hostkey;
pub mod layout;
pub mod materialize;
pub mod observed;
pub mod runner;
pub mod ssh;
pub mod transport;

use crate::config::{ServerConnection, ServerDef};
use crate::error::{Error, Result};
use crate::remote::transport::{LocalTransport, Remote};

/// Build the remote handle for one server from the configuration.
///
/// Production pushes use the SSH transport keyed by the server's
/// [`ServerConnection::Ssh`] host/user/port and the slot's absolute
/// `deploy_dir`, with strict host-key verification. The local transport is
/// reserved for tests and for servers whose connection is
/// [`ServerConnection::Local`] (an explicit `local://` endpoint), which
/// routes the transport to that exact filesystem location rather than the
/// application store's `remotes/` directory.
pub fn create_remote(server: &ServerDef, deploy_dir: &std::path::Path) -> Result<Box<dyn Remote>> {
    match server.connection() {
        ServerConnection::Local { address, .. } => {
            let Some(local_path) = address.strip_prefix("local://") else {
                return Err(Error::transport(format!(
                    "local connection must carry a local:// address: '{address}'"
                )));
            };
            let p = std::path::PathBuf::from(local_path);
            if p.is_relative() {
                return Err(Error::transport(format!(
                    "local:// endpoint must be an absolute path: '{local_path}'"
                )));
            }
            Ok(Box::new(LocalTransport::new(p)?))
        }
        ServerConnection::Ssh {
            address,
            user,
            port,
            identity,
        } => {
            let (known_hosts, host_key_fingerprint) = match identity {
                crate::config::HostIdentity::KnownHosts(p) => (Some(p.as_path()), None),
                crate::config::HostIdentity::Fingerprint(f) => (None, Some(f.as_str())),
                crate::config::HostIdentity::Local => {
                    return Err(Error::transport(format!(
                        "server '{}': an SSH connection cannot carry a Local identity",
                        server.id
                    )));
                }
            };
            Ok(Box::new(ssh::SshTransport::new(
                user.as_str(),
                address.as_str(),
                port.get(),
                deploy_dir,
                known_hosts,
                host_key_fingerprint,
            )?))
        }
    }
}

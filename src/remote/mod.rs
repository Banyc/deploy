//! Transport, remote helper, and the remote-facing semantics: the remote
//! helper operations (status/chain, CAS swap, commit markers, transactions,
//! publication, rotation, protocol handshake, assignment records, observed
//! state), the transport stack (Remote trait, Local/Ssh transports, host
//! identity pinning, execution runner), canonical tree content
//! (canonicalization + mapping/template materialization), and the canonical
//! on-server layout.
//!
//! # Modules
//!
//! * [`helper`] — THE REMOTE HELPER OPERATIONS: [`RemoteHelper`](helper::RemoteHelper),
//!   the `current`-chain status inspection, the CAS `current` swap, commit
//!   markers, transaction records, object-store publication, receiver
//!   rotation, the protocol handshake, the generation assignment record, and
//!   the observed-state re-exports.
//! * [`transport`] — THE TRANSPORT STACK: the [`Remote`](transport::Remote)
//!   trait, [`LocalTransport`](transport::LocalTransport) and
//!   [`SshTransport`](transport::SshTransport), host-identity verification
//!   and pinning, and the bounded subprocess execution runner.
//! * [`canonical`] — THE TREE CONTENT: canonical tree objects plus
//!   mapping/template materialization.
//! * [`layout`] — canonical on-server layout paths (crate-wide infra).

pub mod canonical;
pub mod helper;
pub mod layout;
pub mod transport;

use crate::config::{ServerConnection, ServerDef};
use crate::env::SysEnv;
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
///
/// `env` is the environment snapshot taken at the process boundary: the
/// transport's children receive its variables ([`SysEnv::child_env`]) and
/// the managed known-hosts pin cache is RESOLVED here (the snapshot's
/// `DEPLOY_SSH_KNOWNHOSTS_DIR`, else `<temp_dir>/deploy-ssh-knownhosts`) —
/// never read from the live process env.
pub fn create_remote(
    env: &SysEnv,
    server: &ServerDef,
    deploy_dir: &std::path::Path,
) -> Result<Box<dyn Remote>> {
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
            Ok(Box::new(LocalTransport::new(env, p)?))
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
            // The managed known-hosts pin cache: resolved ONCE at this
            // boundary from the snapshot (tests point it at a per-test cache
            // via the snapshot's `DEPLOY_SSH_KNOWNHOSTS_DIR`; production uses
            // `<temp_dir>/deploy-ssh-knownhosts`).
            let known_hosts_cache_dir = env
                .get("DEPLOY_SSH_KNOWNHOSTS_DIR")
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| env.temp_dir().join("deploy-ssh-knownhosts"));
            Ok(Box::new(transport::SshTransport::new(
                user.as_str(),
                address.as_str(),
                port.get(),
                deploy_dir,
                known_hosts,
                host_key_fingerprint,
                &known_hosts_cache_dir,
                env,
            )?))
        }
    }
}

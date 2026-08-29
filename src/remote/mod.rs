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
//! * [`transport`] — THE TRANSPORT STACK: the [`Remote`]
//!   trait, [`LocalTransport`] and
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
use crate::identity::AbsoluteDeployDir;
use crate::remote::transport::{LocalTransport, Remote};

/// THE ONE AUTHORITATIVE LOCAL DEPLOYMENT ROOT: the canonical directory a
/// LOCAL slot operates on. It is the slot's validated [`crate::identity::AbsoluteDeployDir`]
/// (absolute, TRAVERSAL-FREE — no `.`/`..` component at any position —
/// normalized canonical form, the filesystem root refused). A local
/// connection is PATHLESS ([`ServerConnection::Local`] carries no endpoint),
/// so the slot's typed deploy_dir IS the root — there is no server-side
/// endpoint to parse or compare, and every consumer sees the same value:
///
/// * [`create_remote`] validates the slot's deploy_dir through the
///   [`crate::identity::AbsoluteDeployDir`] scalar and roots [`LocalTransport`] exactly there
///   — the canonical form the raw -> domain conversion already stored in the
///   validated [`crate::config::ProjectConfig`] graph
///   ([`crate::config::SlotConfig::with_canonical_deploy_dir`]).
/// * the transport's [`Remote::root`] is that same canonical path, so
///   `create_remote(...).root() == PhysicalBinding.deploy_dir` for every
///   accepted local slot by construction.
///
/// The `Local` connection carries no root of its own: a graph can never
/// reference a slot whose root differs from the server's connection (there is
/// no connection root), so no accepted graph can fail transport creation on a
/// static endpoint-vs-deploy_dir relationship.
///
/// Production pushes use the SSH transport keyed by the server's
/// [`ServerConnection::Ssh`] host/user/port and the slot's absolute
/// `deploy_dir`, with strict host-key verification. The local transport is
/// reserved for tests and for servers whose connection is
/// [`ServerConnection::Local`] — the PATHLESS local kind — which roots the
/// transport at the SLOT's deploy_dir (the one authoritative local root),
/// never at a server-side endpoint.
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
        ServerConnection::Local { .. } => {
            // THE EFFECTIVE ROOT: the slot's deploy_dir IS the root — a
            // local connection carries no endpoint, so there is nothing to
            // parse or compare (the mismatch class is gone by construction:
            // a local server can never reference a root other than the
            // slot's deploy_dir). The deploy_dir is still validated through
            // the `AbsoluteDeployDir` scalar here — a relative path, ANY
            // traversal component (`.`/`..` at any position), or the
            // filesystem root is rejected, and the accepted root is the
            // validated, normalized canonical form the config graph already
            // stored. The root is NEVER a raw unvalidated `PathBuf`.
            let root = AbsoluteDeployDir::parse(&deploy_dir.to_string_lossy()).map_err(|_| {
                Error::transport(format!(
                    "local server '{}': slot deploy_dir '{}' must be an absolute, traversal-free path (no `.`/`..` components) with at least one normal component below the root",
                    server.id,
                    deploy_dir.display()
                ))
            })?;
            Ok(Box::new(LocalTransport::new(
                env,
                root.as_path().to_path_buf(),
            )?))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CapacityConfig, HostIdentity, ServerConnection, ServerDef};
    use crate::identity::{CapacityPercent, Identifier};
    use std::path::Path;

    fn local_server() -> ServerDef {
        ServerDef::new(
            Identifier::parse("s1").unwrap(),
            ServerConnection::Local {
                identity: HostIdentity::Local,
            },
            CapacityConfig {
                reserve_bytes: 0,
                reserve_percent: CapacityPercent::new(0).unwrap(),
            },
        )
    }

    /// A local connection is PATHLESS: the slot's deploy_dir IS the root —
    /// there is no endpoint to parse or compare. The deploy_dir is validated
    /// through the `AbsoluteDeployDir` gate: a traversal component
    /// (`.`/`..`) at ANY position is rejected, even when the raw path is
    /// absolute and would otherwise reach a real directory.
    #[test]
    fn create_remote_local_rejects_traversal_deploy_dir() {
        for dir in [
            "/srv/../escape",
            "/srv/./dot",
            "/srv/a/..",
            "/..",
            "rel/relative",
        ] {
            let err = create_remote(&SysEnv::from_process(), &local_server(), Path::new(dir))
                .err()
                .unwrap_or_else(|| {
                    panic!("a traversal-carrying deploy_dir must be rejected: {dir}")
                });
            assert!(
                err.to_string().contains("traversal-free"),
                "error must name the traversal rule, got: {err}"
            );
        }
    }

    /// A relative slot deploy_dir is rejected (the root is a validated
    /// `AbsoluteDeployDir`, never a raw `PathBuf`).
    #[test]
    fn create_remote_local_rejects_relative_deploy_dir() {
        let err = create_remote(&SysEnv::from_process(), &local_server(), Path::new("rel/x"))
            .err()
            .unwrap_or_else(|| panic!("a relative deploy_dir must be rejected"));
        assert!(
            err.to_string().contains("traversal-free"),
            "error must name the absoluteness/traversal rule, got: {err}"
        );
    }

    /// The happy path: ANY valid slot deploy_dir is accepted (a local
    /// connection carries no endpoint, so there is nothing that could
    /// diverge), and the transport's root is the validated NORMALIZED
    /// canonical form — messy spellings (`//`, a trailing slash) fold to the
    /// same root, so `root()` is exactly what the recorded binding carries.
    #[test]
    fn create_remote_local_roots_at_slot_deploy_dir() {
        for deploy_dir in ["/srv/app", "/srv/app//", "/srv/app/", "/srv//app"] {
            let remote = create_remote(
                &SysEnv::from_process(),
                &local_server(),
                Path::new(deploy_dir),
            )
            .unwrap_or_else(|e| panic!("{deploy_dir} must be accepted: {e}"));
            assert_eq!(
                remote.root(),
                Path::new("/srv/app"),
                "the transport root is the canonical effective root"
            );
            assert_eq!(
                remote.root().to_string_lossy(),
                "/srv/app",
                "the root is the normalized canonical form, not the raw spelling"
            );
        }
    }

    /// The filesystem root (in any spelling that normalizes to it) is refused
    /// as a local root — the same rule the `AbsoluteDeployDir` parse
    /// enforces.
    #[test]
    fn create_remote_local_rejects_root_deploy_dir() {
        for dir in ["/", "//", "//./"] {
            let err = create_remote(&SysEnv::from_process(), &local_server(), Path::new(dir))
                .err()
                .unwrap_or_else(|| panic!("the filesystem root is not a valid local root: {dir}"));
            assert!(
                err.to_string().contains("traversal-free"),
                "error must name the rule, got: {err}"
            );
        }
    }
}

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
use std::fmt;
use std::path::Path;

/// THE ONE AUTHORITATIVE LOCAL DEPLOYMENT ROOT: the canonical directory a
/// LOCAL slot operates on. It is the validated [`AbsoluteDeployDir`] (absolute,
/// TRAVERSAL-FREE — no `.`/`..` component at any position — normalized
/// canonical form, the filesystem root refused) that BOTH the transport's
/// [`Remote::root`] AND the recorded [`crate::ledger::PhysicalBinding::deploy_dir`]
/// derive from. There is exactly ONE effective root per local slot, and every
/// consumer sees the same value:
///
/// * [`create_remote`] parses the `local://` ENDPOINT as an
///   [`EffectiveDeployRoot`] (rejecting relative and traversal-carrying
///   endpoints) and REQUIRES it to EQUAL the slot's deploy_dir (also parsed
///   as an [`EffectiveDeployRoot`]) — the "exact endpoint" rule. A local
///   connection therefore operates EXACTLY on the slot's recorded directory;
///   a divergent endpoint fails closed.
/// * the transport's [`Remote::root`] is the effective root's canonical path
///   ([`LocalTransport`] is rooted there).
/// * the recorded [`crate::ledger::PhysicalBinding::deploy_dir`] is the slot's
///   deploy_dir in the validated [`crate::config::ProjectConfig`] graph, which
///   the raw -> domain conversion stores in the SAME canonical form
///   ([`crate::config::SlotConfig::with_canonical_deploy_dir`]) — so
///   `create_remote(...).root() == PhysicalBinding.deploy_dir` for every
///   accepted local slot by construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EffectiveDeployRoot(AbsoluteDeployDir);

impl EffectiveDeployRoot {
    /// Parse and validate an effective root: an absolute, TRAVERSAL-FREE
    /// path with at least one normal component below the root, normalized to
    /// its canonical form (the [`AbsoluteDeployDir`] gate). A relative path,
    /// any `.`/`..` component at any position, or the filesystem root is
    /// rejected.
    pub fn parse(s: &str) -> Result<EffectiveDeployRoot> {
        Ok(EffectiveDeployRoot(AbsoluteDeployDir::parse(s)?))
    }

    /// The canonical effective root path.
    pub fn as_path(&self) -> &Path {
        self.0.as_path()
    }

    /// The underlying validated scalar.
    pub fn as_absolute(&self) -> &AbsoluteDeployDir {
        &self.0
    }
}

impl fmt::Display for EffectiveDeployRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
            // THE EFFECTIVE ROOT: the `local://` endpoint is parsed through
            // the [`AbsoluteDeployDir`] scalar — a relative path, ANY traversal
            // component (`.`/`..` at any position), or the filesystem root is
            // rejected here, and the accepted endpoint is the validated,
            // normalized canonical form. The endpoint is NEVER a raw
            // unvalidated `PathBuf`.
            let endpoint = EffectiveDeployRoot::parse(local_path).map_err(|_| {
                Error::transport(format!(
                    "local:// endpoint '{local_path}' must be an absolute, traversal-free path (no `.`/`..` components) with at least one normal component below the root"
                ))
            })?;
            // EXACT ENDPOINT SEMANTICS: a local connection operates EXACTLY on
            // the slot's recorded deploy_dir (the physical binding used for
            // exact rollback). Both sides are compared as validated effective
            // roots — normalized, so `local:///srv/a` and a deploy_dir of
            // `/srv/a/` name the SAME root and agree, while any genuine
            // divergence fails closed with both paths named.
            let slot_root = EffectiveDeployRoot::parse(&deploy_dir.to_string_lossy()).map_err(
                |_| {
                    Error::transport(format!(
                        "slot deploy_dir '{}' must be an absolute, traversal-free path (no `.`/`..` components)",
                        deploy_dir.display()
                    ))
                },
            )?;
            if endpoint != slot_root {
                return Err(Error::transport(format!(
                    "local server '{}': the local:// endpoint '{}' (effective root '{}') differs from the slot's deploy_dir '{}' (effective root '{}'); a local connection must operate on the slot's recorded deploy_dir",
                    server.id,
                    local_path,
                    endpoint,
                    deploy_dir.display(),
                    slot_root
                )));
            }
            Ok(Box::new(LocalTransport::new(
                env,
                endpoint.as_path().to_path_buf(),
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

    fn local_server(address: &str) -> ServerDef {
        ServerDef::new(
            Identifier::parse("s1").unwrap(),
            ServerConnection::Local {
                address: address.to_string(),
                identity: HostIdentity::Local,
            },
            CapacityConfig {
                reserve_bytes: 0,
                reserve_percent: CapacityPercent::new(0).unwrap(),
            },
        )
    }

    /// The `local://` endpoint is parsed as a validated [`EffectiveDeployRoot`]:
    /// a traversal component (`.`/`..`) at ANY position is rejected, even when
    /// the raw path is absolute and would otherwise reach a real directory.
    #[test]
    fn create_remote_local_rejects_traversal_endpoint() {
        for address in [
            "local:///srv/../escape",
            "local:///srv/./dot",
            "local:///srv/a/..",
            "local:///..",
        ] {
            let err = create_remote(
                &SysEnv::from_process(),
                &local_server(address),
                Path::new("/srv/escape"),
            )
            .err()
            .unwrap_or_else(|| {
                panic!("a traversal-carrying local:// endpoint must be rejected: {address}")
            });
            assert!(
                err.to_string().contains("traversal-free"),
                "error must name the traversal rule, got: {err}"
            );
        }
    }

    /// A relative `local://` endpoint is rejected (the endpoint is a validated
    /// [`AbsoluteDeployDir`], never a raw `PathBuf`).
    #[test]
    fn create_remote_local_rejects_relative_endpoint() {
        let err = create_remote(
            &SysEnv::from_process(),
            &local_server("local://rel/relative"),
            Path::new("/srv/x"),
        )
        .err()
        .unwrap_or_else(|| panic!("a relative local:// endpoint must be rejected"));
        assert!(
            err.to_string().contains("traversal-free"),
            "error must name the absoluteness/traversal rule, got: {err}"
        );
    }

    /// EXACT ENDPOINT SEMANTICS: a local connection whose endpoint differs
    /// from the slot's deploy_dir is rejected with BOTH paths named — a slot
    /// must never operate on a directory other than its recorded binding.
    #[test]
    fn create_remote_local_rejects_endpoint_deploy_dir_mismatch() {
        let err = create_remote(
            &SysEnv::from_process(),
            &local_server("local:///srv/a"),
            Path::new("/srv/b"),
        )
        .err()
        .unwrap_or_else(|| panic!("a divergent local endpoint must be rejected"));
        let msg = err.to_string();
        assert!(
            msg.contains("/srv/a") && msg.contains("/srv/b"),
            "error must name both the endpoint and the deploy_dir, got: {msg}"
        );
    }

    /// The happy path: an endpoint EQUAL to the slot's deploy_dir is accepted,
    /// and the transport's root is the validated NORMALIZED canonical form —
    /// messy spellings (`//`, a trailing slash) fold to the same effective
    /// root, so `root()` is exactly what the recorded binding carries.
    #[test]
    fn create_remote_local_accepts_exact_endpoint_and_normalizes() {
        for (address, deploy_dir) in [
            ("local:///srv/app", "/srv/app"),
            ("local:///srv/app//", "/srv/app"),
            ("local:///srv/app/", "/srv/app"),
            ("local:///srv//app", "/srv/app"),
        ] {
            let remote = create_remote(
                &SysEnv::from_process(),
                &local_server(address),
                Path::new(deploy_dir),
            )
            .unwrap_or_else(|e| panic!("{address} with {deploy_dir} must be accepted: {e}"));
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
    /// as a local endpoint — the same rule the [`AbsoluteDeployDir`] parse
    /// enforces.
    #[test]
    fn create_remote_local_rejects_root_endpoint() {
        for address in ["local:///", "local:////", "local:////./"] {
            let err = create_remote(
                &SysEnv::from_process(),
                &local_server(address),
                Path::new("/srv/x"),
            )
            .err()
            .unwrap_or_else(|| {
                panic!("the filesystem root is not a valid local endpoint: {address}")
            });
            assert!(
                err.to_string().contains("traversal-free"),
                "error must name the rule, got: {err}"
            );
        }
    }
}

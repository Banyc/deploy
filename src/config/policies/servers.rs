//! Server definitions ([`ServerDef`]): the EXACTLY ONE connection form
//! ([`ServerConnection`]) with its EXACTLY ONE host identity
//! ([`HostIdentity`]), per-server capacity, and the raw -> domain server
//! resolution.

use crate::config::capacity::CapacityConfig;
use crate::config::raw::RawServer;
use crate::error::{Error, Result};
use crate::identity::{Host, Identifier, SshUser};
use std::fmt;
use std::num::NonZeroU16;
use std::path::PathBuf;

pub(crate) fn default_ssh_port() -> u16 {
    22
}

/// A validated host-key fingerprint (e.g. `SHA256:...`). Construction is
/// gated on the `SHA256:` format rule, so an invalid fingerprint cannot
/// exist in a domain server's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Parse and validate a `SHA256:...` host-key fingerprint.
    pub fn parse(s: &str) -> Result<Fingerprint> {
        if !s.starts_with("SHA256:") {
            return Err(Error::config(
                "host_key_fingerprint must be a SHA256:... value",
            ));
        }
        Ok(Fingerprint(s.to_string()))
    }

    /// The canonical `SHA256:...` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A server's EXACTLY ONE host-identity form, replacing the raw
/// `known_hosts`/`host_key_fingerprint` option pair: `Local` for the
/// pathless local connection kind (which never performs host verification), a dedicated
/// `known_hosts` file, or a pre-verified `SHA256:` fingerprint. By
/// construction a server can never hold both or neither identity — the
/// domain conversion collapses the raw pair into exactly one variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostIdentity {
    /// The pathless local connection kind; no host verification is ever
    /// performed.
    Local,
    /// A dedicated `known_hosts` file used with `StrictHostKeyChecking=yes`.
    KnownHosts(PathBuf),
    /// A pre-verified host-key fingerprint the host key is pinned against on
    /// first contact.
    Fingerprint(Fingerprint),
}

/// A server's EXACTLY ONE connection form, consolidating the raw
/// `address`/`user`/`port`/identity fields: `Local` for the pathless local
/// connection kind (the slot's typed [`crate::identity::AbsoluteDeployDir`] is the SOLE
/// physical root — the connection carries no root path of its own, so a
/// local server can never reference a root that diverges from the slot's
/// deploy_dir), or `Ssh` carrying the validated host, deployment account,
/// nonzero port, and the EXACTLY ONE host-identity form. By construction a
/// server is either local or SSH — never both, never neither. The raw/wire
/// layer keeps the separate fields; the conversion builds this enum, so the
/// connection form is exactly-one by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerConnection {
    /// The pathless local connection kind: NO address path is carried — the
    /// transport root is the referencing slot's typed deploy_dir
    /// ([`crate::identity::AbsoluteDeployDir`]), the one authoritative physical root, so there
    /// is no endpoint for the transport to parse or compare. The raw
    /// `address` marker is the literal `local` (see [`is_local_address`]); a
    /// legacy `local://<path>` address is rejected by the conversion with
    /// migration guidance. No host verification is ever performed. The
    /// identity is ALWAYS [`HostIdentity::Local`] by construction (the
    /// conversion builds it so; the validated rebuild operations re-check
    /// it).
    Local { identity: HostIdentity },
    /// An SSH connection: the validated host, deployment account, nonzero
    /// port, and the EXACTLY ONE host-identity form ([`HostIdentity::KnownHosts`]
    /// or [`HostIdentity::Fingerprint`] — never `Local`).
    Ssh {
        address: Host,
        user: SshUser,
        port: NonZeroU16,
        identity: HostIdentity,
    },
}

/// A validated server: the validated identifier plus the EXACTLY ONE
/// connection form ([`ServerConnection`] — local or SSH, never both/neither
/// by construction). The connection is PRIVATE: a server is only built by
/// the raw -> domain conversion or the validated rebuild operations, so an
/// inconsistent connection (an SSH form with a `Local` identity) can never
/// enter a validated [`crate::config::ProjectConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDef {
    /// The server's validated identifier (non-empty, well-formed): parsed by
    /// the raw -> domain conversion, so an invalid server id cannot exist in
    /// a domain server.
    pub id: Identifier,
    /// The server's EXACTLY ONE connection form. Private: read through
    /// [`ServerDef::connection`] and the wire-view accessors
    /// ([`ServerDef::address`], [`ServerDef::user`], [`ServerDef::port`],
    /// [`ServerDef::identity`]); changed only through the validated rebuild
    /// operations, which re-validate the whole graph.
    connection: ServerConnection,
    /// Per-server capacity headroom policy (defaults to 0/0 when omitted),
    /// shared by every deployment slot on this server and resolved from the
    /// caller's current configuration at preflight time. Not part of the
    /// release identity.
    pub capacity: CapacityConfig,
}
impl ServerDef {
    /// Build a server from its validated parts. The connection's
    /// well-formedness (a `Local` form with a `Local` identity, an SSH form
    /// with a `KnownHosts`/`Fingerprint` identity) is enforced when the
    /// server enters a [`crate::config::ProjectConfig`]: the conversion and every validated
    /// rebuild operation re-validate the whole graph.
    pub fn new(
        id: Identifier,
        connection: ServerConnection,
        capacity: CapacityConfig,
    ) -> ServerDef {
        ServerDef {
            id,
            connection,
            capacity,
        }
    }

    /// The server's EXACTLY ONE connection form.
    pub fn connection(&self) -> &ServerConnection {
        &self.connection
    }

    /// The connection address: the `local` marker for a local server (a
    /// pathless connection kind — the physical root is the slot's
    /// deploy_dir, never this marker), the SSH host for an SSH server.
    pub fn address(&self) -> &str {
        match &self.connection {
            ServerConnection::Local { .. } => LOCAL_ADDRESS_MARKER,
            ServerConnection::Ssh { address, .. } => address.as_str(),
        }
    }

    /// The SSH deployment account; empty for a local server (a local
    /// endpoint has no SSH user).
    pub fn user(&self) -> &str {
        match &self.connection {
            ServerConnection::Local { .. } => "",
            ServerConnection::Ssh { user, .. } => user.as_str(),
        }
    }

    /// The SSH port (default 22); 22 for a local server (a local endpoint
    /// has no SSH port).
    pub fn port(&self) -> u16 {
        match &self.connection {
            ServerConnection::Local { .. } => 22,
            ServerConnection::Ssh { port, .. } => port.get(),
        }
    }

    /// The server's validated, single host-identity form: ALWAYS
    /// [`HostIdentity::Local`] for a local server, the exactly-one
    /// `KnownHosts`/`Fingerprint` form for an SSH server.
    pub fn identity(&self) -> &HostIdentity {
        match &self.connection {
            ServerConnection::Local { identity, .. } => identity,
            ServerConnection::Ssh { identity, .. } => identity,
        }
    }
}

/// The raw `address` marker of a LOCAL server: a pathless connection kind.
/// The marker carries NO root path — the referencing slot's typed
/// [`crate::identity::AbsoluteDeployDir`] is the SOLE physical root, so a `local` server can
/// never reference a root that diverges from the slot's deploy_dir (the
/// mismatch class that used to fail at transport creation cannot exist).
pub(crate) const LOCAL_ADDRESS_MARKER: &str = "local";

/// Whether a raw server address is the pathless LOCAL marker.
pub(crate) fn is_local_address(address: &str) -> bool {
    address == LOCAL_ADDRESS_MARKER
}

/// The LEGACY `local://<path>` endpoint form: no longer a connection shape —
/// the connection kind carries no root path, so a `local://` address would
/// either silently diverge from the slot's deploy_dir (the failure class
/// this design eliminates) or be silently ignored. The raw -> domain
/// conversion rejects it with migration guidance.
pub(crate) fn is_legacy_local_endpoint(address: &str) -> bool {
    address.starts_with("local://")
}

/// Resolve one raw server's identity pair into the single validated
/// [`HostIdentity`] form. The per-source well-formedness checks (absolute
/// `known_hosts`, `SHA256:` fingerprint) apply to every server; the
/// exactly-one rule applies to SSH addresses only — a local marker (and the
/// legacy `local://` form, which the conversion rejects with guidance)
/// never performs host verification, so its identity is always `Local`.
pub(crate) fn validate_server_identity(server: &RawServer) -> Result<HostIdentity> {
    if let Some(kh) = &server.known_hosts
        && !kh.is_absolute()
    {
        return Err(Error::config(format!(
            "server '{}' known_hosts must be an absolute path",
            server.id
        )));
    }
    if let Some(fp) = &server.host_key_fingerprint
        && !fp.starts_with("SHA256:")
    {
        return Err(Error::config(format!(
            "server '{}' host_key_fingerprint must be a SHA256:... value",
            server.id
        )));
    }
    if is_local_address(&server.address) || is_legacy_local_endpoint(&server.address) {
        return Ok(HostIdentity::Local);
    }
    match (&server.known_hosts, &server.host_key_fingerprint) {
        (Some(_), Some(_)) => Err(Error::config(format!(
            "server '{}': known_hosts and host_key_fingerprint are mutually exclusive; configure exactly one",
            server.id
        ))),
        (None, None) => Err(Error::config(format!(
            "server '{}': exactly one of known_hosts or host_key_fingerprint must be configured for an SSH address (trust-on-first-use is disabled)",
            server.id
        ))),
        (Some(kh), None) => Ok(HostIdentity::KnownHosts(kh.clone())),
        (None, Some(fp)) => Ok(HostIdentity::Fingerprint(Fingerprint::parse(fp)?)),
    }
}

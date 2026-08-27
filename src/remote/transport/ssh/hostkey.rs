//! Host-identity verification and pinning: a strict known-hosts file or a
//! pre-verified fingerprint pinned into a managed cache (`ssh-keyscan`),
//! never trust-on-first-use.

use crate::error::{Error, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::runner::{OpKind, RunError, SSH_CONNECT_TIMEOUT_SECS, SshRunner};

/// Build the `ssh-keyscan` argument vector (port, connect timeout, key
/// types, bare host). The bare address is used (not `user@address`) because
/// `ssh-keyscan` expects a hostname/address, and the configured port is
/// passed via `-p`. `-T N` is the canonical ssh-keyscan connection timeout:
/// it is supported by both OpenSSH (Linux) and the LibreSSL/macOS build
/// (which REJECTS the nonexistent `-O timeout=` variant — `-O` only
/// carries `hashalg=`). [`pin_known_hosts`] additionally
/// enforces the same N-second bound at the process level, so a keyscan
/// implementation that ignores `-T` still cannot hang the pin step.
pub(crate) fn keyscan_args(port: u16, address: &str) -> Vec<String> {
    vec![
        "-p".into(),
        port.to_string(),
        "-T".into(),
        SSH_CONNECT_TIMEOUT_SECS.to_string(),
        "-t".into(),
        "ed25519,ecdsa,rsa".into(),
        address.to_string(),
    ]
}

/// Pin the host key for `target` (the `user@host` connection string) in a
/// managed known-hosts file under the private cache directory, verifying it
/// against the configured `fingerprint` (fetched from `address` on `port`
/// via `ssh-keyscan`). Fails closed if the key cannot be fetched or does
/// not match. Returns the pinned file's path; the transport stores it for
/// use as `UserKnownHostsFile` in later ssh invocations.
pub(crate) fn pin_known_hosts(
    fingerprint: &str,
    target: &str,
    address: &str,
    port: u16,
    runner: &SshRunner,
) -> Result<PathBuf> {
    let expected = fingerprint.trim().to_lowercase();

    // Pinned keys live in a private (0700) cache directory owned by this
    // user, rather than a predictable world-readable temp file name, so a
    // locally pre-created file cannot be trusted blindly. Tests may
    // override the cache root via `DEPLOY_SSH_KNOWNHOSTS_DIR` to give each
    // test its own isolated cache; production deployments leave it unset
    // and use the default `$TMPDIR/deploy-ssh-knownhosts`.
    let cache_dir = std::env::var_os("DEPLOY_SSH_KNOWNHOSTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("deploy-ssh-knownhosts"));
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        Error::transport(format!(
            "create known_hosts cache {}: {e}",
            cache_dir.display()
        ))
    })?;
    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        Error::transport(format!(
            "chmod known_hosts cache {}: {e}",
            cache_dir.display()
        ))
    })?;
    let path = cache_dir.join(format!("knownhosts-{}.txt", simple_hash(target)));

    // Validate any existing cached file against the configured fingerprint
    // before reusing it: a changed key (or a locally pre-created file) is
    // never trusted without re-verification.
    if path.exists()
        && let Ok(text) = std::fs::read_to_string(&path)
        && fingerprints_match(&text, &expected)
    {
        return Ok(path);
    }
    if path.exists() {
        // Stale, unreadable, or mismatched cache: drop and re-pin below.
        let _ = std::fs::remove_file(&path);
    }

    // Fetch the host keys using the bare address and configured port. The
    // spawn runs through THE shared runner ([`SshRunner`]): the keyscan is
    // bounded at the process level by the runner's connect deadline (the
    // same `SSH_CONNECT_TIMEOUT_SECS` as the native `-T` option), and on
    // deadline the child is killed and reaped — a dead or unresponsive host
    // fails the pin step fast even if the local `ssh-keyscan` ignores its
    // native `-T` option.
    let mut argv = vec!["ssh-keyscan".to_string()];
    argv.extend(keyscan_args(port, address));
    let scan = runner
        .run(OpKind::KeyscanPin, &argv, None, None)
        .map_err(|e| match e {
            RunError::Spawn(m) => Error::transport(format!("ssh-keyscan {} spawn: {m}", address)),
            RunError::StdinWrite(m) => {
                Error::transport(format!("ssh-keyscan {} stdin write: {m}", address))
            }
            RunError::Wait(m) => Error::transport(format!("ssh-keyscan {} wait: {m}", address)),
            RunError::Timeout { after } => Error::transport(format!(
                "ssh-keyscan {} timed out after {after:?} (host unreachable?)",
                address
            )),
        })?;
    if !scan.status.success() {
        return Err(Error::transport(format!(
            "ssh-keyscan {} failed: {}",
            address,
            String::from_utf8_lossy(&scan.stderr)
        )));
    }
    let text = String::from_utf8_lossy(&scan.stdout);

    // For each fetched key, compute its fingerprint and keep the ones whose
    // fingerprint matches the configured value.
    let mut matched: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if key_matches_fingerprint(line, &expected) {
            matched.push(line.to_string());
        }
    }

    if matched.is_empty() {
        return Err(Error::transport(format!(
            "no host key for {} matched configured fingerprint {}",
            address, expected
        )));
    }

    // Exclusive (O_EXCL) creation with 0600 permissions so a concurrent or
    // pre-existing file cannot be silently overwritten or read by others.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            Error::transport(format!("create pinned known_hosts {}: {e}", path.display()))
        })?;
    use std::io::Write;
    f.write_all(matched.join("\n").trim_end().as_bytes())
        .and_then(|_| f.write_all(b"\n"))
        .map_err(|e| Error::transport(format!("write known_hosts {}: {e}", path.display())))?;
    drop(f);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::transport(format!("chmod known_hosts {}: {e}", path.display())))?;
    Ok(path)
}

/// Pipe a single key line into `ssh-keygen -lf` and return whether its
/// fingerprint (the second whitespace-separated field) matches `expected`.
pub(crate) fn key_matches_fingerprint(line: &str, expected: &str) -> bool {
    let mut keygen = match Command::new("ssh-keygen")
        .arg("-lf")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(k) => k,
        Err(_) => return false,
    };
    use std::io::Write;
    if keygen
        .stdin
        .as_mut()
        .unwrap()
        .write_all(line.as_bytes())
        .is_err()
    {
        return false;
    }
    let out = match keygen.wait_with_output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    if !out.status.success() {
        return false;
    }
    let fp = String::from_utf8_lossy(&out.stdout);
    let fp_field = fp.split_whitespace().nth(1).unwrap_or("").to_lowercase();
    fp_field == expected
}

/// Return true if any key line in `text` matches `expected` fingerprint.
pub(crate) fn fingerprints_match(text: &str, expected: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && key_matches_fingerprint(line, expected)
    })
}

/// Stable, filesystem-safe hash of a string for building temp-file names.
pub(crate) fn simple_hash(s: &str) -> String {
    let mut h: u64 = 1469598103934665603; // FNV-1a offset basis
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests_hostkey {
    use super::*;

    // Finding 1: the configured port is propagated to ssh-keyscan, and the
    // bare host is passed (not `user@address`).
    #[test]
    fn keyscan_uses_bare_host_and_port() {
        let args = keyscan_args(2222, "db.example.com");
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], "2222");
        assert!(args.contains(&"db.example.com".to_string()));
        // The connection target (`user@host`) must NOT be passed to ssh-keyscan.
        assert!(!args.iter().any(|a| a.contains('@')));
        // The keyscan carries the same connect timeout as ssh. `-T N` is the
        // canonical ssh-keyscan connection timeout (OpenSSH and the
        // LibreSSL/macOS build both support it; `-O timeout=` does not exist).
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-T" && w[1] == SSH_CONNECT_TIMEOUT_SECS.to_string()),
            "keyscan args must carry -T {SSH_CONNECT_TIMEOUT_SECS}, got: {args:?}"
        );
    }
}

//! Shared test-only utilities.
//!
//! # The env-lock invariant
//!
//! ANY test that mutates the process-global environment must hold
//! [`ENV_LOCK`] for the entire duration of the mutation — `PATH`,
//! `XDG_CONFIG_HOME`, `DEPLOY_SSH_KNOWNHOSTS_DIR`,
//! `FAKE_SSH_ROOT` / `FAKE_SSH_REMOTE_PREFIX`, or anything else.
//!
//! All lib unit tests share one process, and edition-2024
//! `std::env::set_var` / `remove_var` are process-global (and `unsafe`), so
//! two env-mutating tests running concurrently corrupt each other's
//! environment: the fake-`ssh`/`ssh-keyscan` fingerprint suite and the
//! fake-`systemctl` suite both rewrite the same `PATH`, and a race could make
//! one of them spawn the REAL binaries (e.g. the real `ssh-keyscan`, whose
//! getaddrinfo DNS failure panics and poisons the lock). Every env-mutating
//! test must therefore serialize on THIS single lock — a private per-suite
//! lock does not protect against the other suite.
//!
//! Per-test state that lives OUTSIDE the process env (e.g. each test's own
//! `DEPLOY_SSH_KNOWNHOSTS_DIR` temp dir for the pin cache) stays isolated as
//! before; the lock only serializes the env itself.
//!
//! Note: each integration-test *binary* (`tests/*.rs`) is a separate process
//! and cannot race the lib tests, so it only needs its own lock to serialize
//! its own tests within that binary.

use std::sync::Mutex;

/// THE lock guarding every env-mutating test in the lib test binary. See the
/// module docs for the invariant.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

//! Error types for the deployment system.

use thiserror::Error;

use crate::kernel::KernelError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("template error: {0}")]
    Template(String),

    #[error("path error: {0}")]
    Path(String),

    #[error("mapping error: {0}")]
    Mapping(String),

    #[error("materialization error: {0}")]
    Materialization(String),

    #[error("digest/integrity error: {0}")]
    Integrity(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("remote helper error: {0}")]
    Remote(String),

    #[error("plan error: {0}")]
    Plan(String),

    #[error("push preflight failed: {0}")]
    Preflight(String),

    #[error("push aborted: {0}")]
    Aborted(String),

    #[error("conflict: {0}")]
    Conflict(String),

    /// The COMPLETE typed semantic-kernel error, preserved through the
    /// facade (never flattened into a class string): the kernel error's own
    /// [`Display`](std::fmt::Display) (its five-class prefix + the typed
    /// payload's sentence) is the text, and the typed class / code /
    /// evidence remain reachable — consumers react on the kernel error's
    /// structure, not its prose.
    #[error("{0}")]
    Kernel(KernelError),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid reference: {0}")]
    Ref(String),

    #[error("rollback error: {0}")]
    Rollback(String),

    #[error("internal error: {0}")]
    Internal(String),

    /// A TYPED reserved-spelling / residue refusal from the `storekit`
    /// substrate's ONE guard gate. The variant mirrors
    /// `storekit::Error::Reserved` so a caller can branch on the typed
    /// [`storekit::ReservedKind`] instead of matching message text; the
    /// `Display` text is the crate's, byte-for-byte.
    #[error("reserved spelling: {reason:?}: {message}")]
    Reserved {
        reason: storekit::ReservedKind,
        message: String,
    },

    /// A typed advisory-lock contention signal from the `storekit`
    /// substrate, mirroring `storekit::Error::LockContended` (distinct from
    /// a real open/flock failure, which stays [`Error::Preflight`]).
    #[error("lock contended: {0}")]
    LockContended(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The migration bridge from the `storekit` substrate's error to this
/// facade: the shared classes map onto the SAME variants (so every existing
/// `matches!`/`match` arm keeps matching) and the crate-only conditions
/// ([`storekit::ReservedKind`] refusals and lock contention) get their own
/// typed variants above. The `Display` text of every class is identical on
/// both sides, so message-matching callers and tests are unaffected.
impl From<storekit::Error> for Error {
    fn from(e: storekit::Error) -> Self {
        use storekit::Error as S;
        match e {
            S::Io(e) => Error::Io(e),
            S::Json(e) => Error::Json(e),
            S::Path(message) => Error::Path(message),
            S::Materialization { message, .. } => Error::Materialization(message),
            S::Integrity(message) => Error::Integrity(message),
            S::Store { message, .. } => Error::Store(message),
            S::Transport { message, .. } => Error::Transport(message),
            S::Preflight(message) => Error::Preflight(message),
            S::NotFound(message) => Error::NotFound(message),
            S::Ref(message) => Error::Ref(message),
            S::Conflict(message) => Error::Conflict(message),
            S::Reserved { reason, message } => Error::Reserved { reason, message },
            S::LockContended(message) => Error::LockContended(message),
        }
    }
}

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }
    pub fn template(msg: impl Into<String>) -> Self {
        Error::Template(msg.into())
    }
    pub fn path(msg: impl Into<String>) -> Self {
        Error::Path(msg.into())
    }
    pub fn mapping(msg: impl Into<String>) -> Self {
        Error::Mapping(msg.into())
    }
    pub fn materialization(msg: impl Into<String>) -> Self {
        Error::Materialization(msg.into())
    }
    pub fn integrity(msg: impl Into<String>) -> Self {
        Error::Integrity(msg.into())
    }
    pub fn store(msg: impl Into<String>) -> Self {
        Error::Store(msg.into())
    }
    pub fn transport(msg: impl Into<String>) -> Self {
        Error::Transport(msg.into())
    }
    pub fn remote(msg: impl Into<String>) -> Self {
        Error::Remote(msg.into())
    }
    pub fn plan(msg: impl Into<String>) -> Self {
        Error::Plan(msg.into())
    }
    pub fn preflight(msg: impl Into<String>) -> Self {
        Error::Preflight(msg.into())
    }
    pub fn aborted(msg: impl Into<String>) -> Self {
        Error::Aborted(msg.into())
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Error::Conflict(msg.into())
    }
    pub fn kernel(err: KernelError) -> Self {
        Error::Kernel(err)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }
    pub fn r#ref(msg: impl Into<String>) -> Self {
        Error::Ref(msg.into())
    }
    pub fn rollback(msg: impl Into<String>) -> Self {
        Error::Rollback(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Error::Internal(msg.into())
    }
}

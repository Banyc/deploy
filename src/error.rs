//! Error types for the deployment system.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("configuration error: {0}")]
    Config(String),

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

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid reference: {0}")]
    Ref(String),

    #[error("rollback error: {0}")]
    Rollback(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
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

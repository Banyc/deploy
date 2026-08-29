//! KERNEL ERROR CLASSES — the semantic kernel (feature area: the pure
//! deployment semantic kernel) classifies every failure it can produce into
//! exactly FIVE classes with structured context. Consumers assert the CLASS
//! (and its structured context), never the whole error string.
//!
//! * [`Input`](KernelError::Input) — invalid CLI, configuration or scalar
//!   value (a bad digest, an unparseable timestamp, an unknown group name).
//! * [`Invariant`](KernelError::Invariant) — internally supplied facts have
//!   an invalid relationship (a plan whose selected slot is not a target
//!   slot; a report whose outcome table contradicts its disposition).
//! * [`Conflict`](KernelError::Conflict) — a valid operation against stale
//!   or concurrently changed state (a stale plan whose parent is no longer
//!   the target's successful head).
//! * [`Integrity`](KernelError::Integrity) — persisted data describes an
//!   impossible event sequence (a terminal for an unknown deployment, two
//!   terminals for one deployment, an intent_digest mismatch, a diverged
//!   wire projection).
//! * [`Transport`](KernelError::Transport) — filesystem, SSH or process
//!   failure behind a backend operation.

use std::fmt;

/// The [`KernelError::Input`] class: invalid CLI, configuration or scalar
/// value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputError {
    pub message: String,
}

/// The [`KernelError::Invariant`] class: internally supplied facts have an
/// invalid relationship.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantError {
    pub message: String,
}

/// The [`KernelError::Conflict`] class: a valid operation against stale or
/// concurrently changed state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictError {
    pub message: String,
}

/// The [`KernelError::Integrity`] class: persisted data describes an
/// impossible event sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityError {
    pub message: String,
}

/// The [`KernelError::Transport`] class: filesystem, SSH or process failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    pub message: String,
}

/// The semantic kernel's error type: exactly five classes, each carrying
/// structured context (its message). All five classes have infallible
/// constructors ([`KernelError::input`] etc.); conversions to the
/// [`crate::error::Error`] facade map each class onto the closest legacy
/// variant so every kernel-returned error stays classed end to end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelError {
    Input(InputError),
    Invariant(InvariantError),
    Conflict(ConflictError),
    Integrity(IntegrityError),
    Transport(TransportError),
}

impl KernelError {
    pub fn input(message: impl Into<String>) -> Self {
        KernelError::Input(InputError {
            message: message.into(),
        })
    }
    pub fn invariant(message: impl Into<String>) -> Self {
        KernelError::Invariant(InvariantError {
            message: message.into(),
        })
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        KernelError::Conflict(ConflictError {
            message: message.into(),
        })
    }
    pub fn integrity(message: impl Into<String>) -> Self {
        KernelError::Integrity(IntegrityError {
            message: message.into(),
        })
    }
    pub fn transport(message: impl Into<String>) -> Self {
        KernelError::Transport(TransportError {
            message: message.into(),
        })
    }

    /// The CLASS of this error — the discriminator tests assert on.
    pub fn class(&self) -> KernelErrorClass {
        match self {
            KernelError::Input(_) => KernelErrorClass::Input,
            KernelError::Invariant(_) => KernelErrorClass::Invariant,
            KernelError::Conflict(_) => KernelErrorClass::Conflict,
            KernelError::Integrity(_) => KernelErrorClass::Integrity,
            KernelError::Transport(_) => KernelErrorClass::Transport,
        }
    }

    /// The structured context (the message).
    pub fn message(&self) -> &str {
        match self {
            KernelError::Input(e) => &e.message,
            KernelError::Invariant(e) => &e.message,
            KernelError::Conflict(e) => &e.message,
            KernelError::Integrity(e) => &e.message,
            KernelError::Transport(e) => &e.message,
        }
    }
}

/// The five error CLASSES — a lightweight discriminator for tests that
/// assert the class without matching the full [`KernelError`] variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelErrorClass {
    Input,
    Invariant,
    Conflict,
    Integrity,
    Transport,
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} error: {}",
            match self.class() {
                KernelErrorClass::Input => "input",
                KernelErrorClass::Invariant => "invariant",
                KernelErrorClass::Conflict => "conflict",
                KernelErrorClass::Integrity => "integrity",
                KernelErrorClass::Transport => "transport",
            },
            self.message()
        )
    }
}

impl std::error::Error for KernelError {}

impl From<KernelError> for crate::error::Error {
    /// The facade mapping: Input → Config (the closest legacy variant for
    /// invalid CLI/configuration/scalar values, consumed by the CLI
    /// boundary), Invariant → Internal, Conflict → Conflict, Integrity →
    /// Integrity, Transport → Transport. Every kernel-returned error lands
    /// in its class on the facade too.
    fn from(e: KernelError) -> Self {
        match e {
            KernelError::Input(i) => crate::error::Error::config(i.message),
            KernelError::Invariant(i) => crate::error::Error::internal(i.message),
            KernelError::Conflict(c) => crate::error::Error::conflict(c.message),
            KernelError::Integrity(i) => crate::error::Error::integrity(i.message),
            KernelError::Transport(t) => crate::error::Error::transport(t.message),
        }
    }
}

/// A kernel `Result` alias over the five-class error.
pub type KernelResult<T> = std::result::Result<T, KernelError>;

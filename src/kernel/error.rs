//! KERNEL ERROR CLASSES — the semantic kernel (feature area: the pure
//! deployment semantic kernel) classifies every failure it can produce into
//! exactly FIVE classes, and every failure that violates a NAMED semantic
//! rule additionally carries a stable [`KernelErrorCode`] and the CONCRETE
//! EVIDENCE of the violation as typed fields.
//!
//! THE THREE-AXIS MODEL: **class = who should react** (the five-way
//! taxonomy below), **code = which semantic rule failed** (the flat
//! [`KernelErrorCode`] tests/metrics/CLI automation assert on), **typed
//! fields = the concrete evidence** (the deployment ids, physical line
//! numbers, digests and slot ids that make the violation structurally
//! distinguishable). Two failures of the same class that only differ in
//! prose are now distinguishable by their code — a `DuplicateIntent`, a
//! `TerminalWithoutIntent` and a `IntentDigestMismatch` all land in the
//! [`Integrity`](KernelError::Integrity) class but each carries its own
//! code and its own evidence fields.
//!
//! * [`Input`](KernelError::Input) — invalid CLI, configuration or scalar
//!   value (a bad digest, an unparseable timestamp, an unknown group name).
//!   Message-only: [`KernelErrorCode::Input`].
//! * [`Invariant`](KernelError::Invariant) — internally supplied facts have
//!   an invalid relationship (a plan whose selected slot is not a target
//!   slot; a report whose outcome table contradicts its disposition).
//!   Message-only: [`KernelErrorCode::Invariant`].
//! * `Conflict`(KernelError::Conflict) — a valid operation against stale
//!   or concurrently changed state: a stale plan whose parent is no longer
//!   the target's successful head ([`ConflictError::ParentMismatch`]), a
//!   still-pending attempt blocking the next one
//!   ([`ConflictError::PendingAttemptExists`]), or a selected slot whose
//!   live state no longer matches the plan
//!   ([`ConflictError::TopologyChanged`]). At the WRITE boundary the
//!   strictly-linear lineage refusals are Conflict-classed (a valid
//!   operation against stale state).
//! * [`Integrity`](KernelError::Integrity) — persisted data describes an
//!   impossible event sequence (a terminal for an unknown deployment, two
//!   terminals for one deployment, an `intent_digest` mismatch, a diverged
//!   lineage, an inherited-snapshot disagreement, an invalid checkpoint
//!   anchor). At the READ boundary the same refusals are
//!   Integrity-classed (persisted-data corruption). Each NAMED semantic
//!   rule is a typed variant of [`IntegrityError`] carrying its evidence;
//!   refusals outside the named rules are message-only
//!   ([`IntegrityError::Message`] / [`KernelErrorCode::Integrity`]).
//! * [`Transport`](KernelError::Transport) — filesystem, SSH or process
//!   failure behind a backend operation. Message-only:
//!   [`KernelErrorCode::Transport`].
//!
//! The typed [`ConflictError`] / [`IntegrityError`] payloads implement
//! `Display` generating the human sentences the refusals always carried
//! (the same keywords — "stale plan", "still pending", "one intent per
//! deployment", "must bind the EXACT canonical intent", "retained
//! suffix" — so prose-based consumers and containment assertions keep
//! working), and [`KernelError::message`] returns that Display text.
//! [`KernelError::class`] and [`KernelError::code`] derive from the
//! structural variant — a code is NEVER stored beside a message.

use std::fmt;

use crate::identity::{DeploymentId, SlotId};
use crate::kernel::terminal::IntentDigest;

/// The [`KernelError::Input`] class: invalid CLI, configuration or scalar
/// value. Message-only (its semantic rules are not in the typed list —
/// [`KernelErrorCode::Input`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputError {
    pub message: String,
}

/// The [`KernelError::Invariant`] class: internally supplied facts have an
/// invalid relationship. Message-only ([`KernelErrorCode::Invariant`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantError {
    pub message: String,
}

/// The [`KernelError::Conflict`] class: a valid operation against stale or
/// concurrently changed state — TYPED variants per semantic rule. No
/// message-only payload exists: every conflict refusal is one of the three
/// rules below. `Display` generates the human sentence (keeping the
/// "stale plan" / "still pending" / "state diverged" keywords).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictError {
    /// A stale plan: the intent's recorded parent is no longer the
    /// target's successful head (the [`ConflictError`] lineage refusal —
    /// [`KernelErrorCode::ParentMismatch`]).
    ParentMismatch {
        deployment: DeploymentId,
        recorded_parent: Option<DeploymentId>,
        actual_head: Option<DeploymentId>,
    },
    /// A still-pending attempt blocks the new one: the strictly-linear
    /// model allows at most ONE unresolved (terminal-less) intent at a
    /// time ([`KernelErrorCode::PendingAttemptExists`]).
    PendingAttemptExists { pending: DeploymentId },
    /// The finalizer's "state diverged" refusal: a selected slot's live
    /// state no longer matches the plan ([`KernelErrorCode::TopologyChanged`]).
    TopologyChanged { slot: SlotId },
}

/// The [`KernelError::Integrity`] class: persisted data describes an
/// impossible event sequence — TYPED variants per named semantic rule, each
/// carrying the concrete evidence (the deployment id, the physical line
/// numbers the store's fold knows, the expected vs recorded digest, the
/// disputed slot). The [`Message`](Self::Message) payload is the catch-all
/// for integrity refusals OUTSIDE the named rules (a foreign target, a
/// checkpoint that is not the first event, an outcome-coverage violation,
/// an internal maintained-state break) — always message-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityError {
    DuplicateIntent {
        deployment: DeploymentId,
        /// The physical line (1-based) of the FIRST intent for this
        /// deployment.
        first_line: usize,
        /// The physical line (1-based) of the duplicate that was refused.
        duplicate_line: usize,
    },
    DuplicateTerminal {
        deployment: DeploymentId,
        /// The physical line (1-based) of the FIRST terminal event.
        first_line: usize,
        /// The physical line (1-based) of the duplicate that was refused.
        duplicate_line: usize,
    },
    TerminalWithoutIntent {
        deployment: DeploymentId,
        /// The physical line (1-based) of the orphan terminal event.
        line: usize,
    },
    IntentDigestMismatch {
        deployment: DeploymentId,
        expected: IntentDigest,
        recorded: IntentDigest,
    },
    /// A FORKED lineage at READ: an ordinary intent whose records parent is
    /// not the target's successful head
    /// ([`crate::kernel::lineage::LineageViolation::ParentMismatch`]).
    ParentLineageMismatch {
        deployment: DeploymentId,
        parent: Option<DeploymentId>,
        expected_head: Option<DeploymentId>,
    },
    /// An intent's inherited slot entry disagrees with the successful head
    /// it claims (a tampered wire or a plan over a different snapshot).
    InheritedSnapshotMismatch {
        deployment: DeploymentId,
        slot: SlotId,
    },
    /// A checkpointed ledger's anchor violation: the retained suffix
    /// either carries no entry for the checkpoint deployment
    /// (`first_intent: None`) or its first intent appeared but never
    /// reached the required `Successful` terminal (`first_intent: Some`).
    CheckpointAnchorMismatch {
        retained_from: DeploymentId,
        first_intent: Option<DeploymentId>,
    },
    /// A message-only integrity refusal — an impossible persisted sequence
    /// that is NOT one of the named semantic rules (a foreign target
    /// named by an intent, a checkpoint that is not the first event, an
    /// outcome-coverage or payload-validation violation, an internally
    /// broken maintained state). [`KernelErrorCode::Integrity`].
    Message(String),
}

/// The [`KernelError::Transport`] class: filesystem, SSH or process
/// failure behind a backend operation. Message-only
/// ([`KernelErrorCode::Transport`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    pub message: String,
}

/// The semantic kernel's error type: exactly five classes. [`KernelError::class`]
/// (KernelError::class) names the class; [`code`](KernelError::code) names
/// the semantic rule; the typed payload carries the concrete evidence.
/// Every class' errors may be converted to the [`crate::error::Error`]
/// facade ([`Error::Kernel`](crate::error::Error::Kernel)) PRESERVING the
/// complete typed error — never flattened into a message string.
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
    pub fn transport(message: impl Into<String>) -> Self {
        KernelError::Transport(TransportError {
            message: message.into(),
        })
    }

    /// The CLASS of this error — the discriminator "who should react"
    /// (tests assert the class; the facade preserves it). Derived from the
    /// structural variant, never stored.
    pub fn class(&self) -> KernelErrorClass {
        match self {
            KernelError::Input(_) => KernelErrorClass::Input,
            KernelError::Invariant(_) => KernelErrorClass::Invariant,
            KernelError::Conflict(_) => KernelErrorClass::Conflict,
            KernelError::Integrity(_) => KernelErrorClass::Integrity,
            KernelError::Transport(_) => KernelErrorClass::Transport,
        }
    }

    /// The CODE of this error — "which semantic rule failed". The ten
    /// semantic codes map one-to-one onto the typed
    /// [`ConflictError`] / [`IntegrityError`] variants; the message-only
    /// classes fall back to their class-level code ([`KernelErrorCode::Input`]
    /// / [`KernelErrorCode::Invariant`] / [`KernelErrorCode::Integrity`] /
    /// [`KernelErrorCode::Transport`]) so the function is TOTAL.
    pub fn code(&self) -> KernelErrorCode {
        match self {
            KernelError::Input(_) => KernelErrorCode::Input,
            KernelError::Invariant(_) => KernelErrorCode::Invariant,
            KernelError::Transport(_) => KernelErrorCode::Transport,
            KernelError::Conflict(c) => match c {
                ConflictError::ParentMismatch { .. } => KernelErrorCode::ParentMismatch,
                ConflictError::PendingAttemptExists { .. } => KernelErrorCode::PendingAttemptExists,
                ConflictError::TopologyChanged { .. } => KernelErrorCode::TopologyChanged,
            },
            KernelError::Integrity(i) => match i {
                IntegrityError::DuplicateIntent { .. } => KernelErrorCode::DuplicateIntent,
                IntegrityError::DuplicateTerminal { .. } => KernelErrorCode::DuplicateTerminal,
                IntegrityError::TerminalWithoutIntent { .. } => {
                    KernelErrorCode::TerminalWithoutIntent
                }
                IntegrityError::IntentDigestMismatch { .. } => {
                    KernelErrorCode::IntentDigestMismatch
                }
                IntegrityError::ParentLineageMismatch { .. } => {
                    KernelErrorCode::ParentLineageMismatch
                }
                IntegrityError::InheritedSnapshotMismatch { .. } => {
                    KernelErrorCode::InheritedSnapshotMismatch
                }
                IntegrityError::CheckpointAnchorMismatch { .. } => {
                    KernelErrorCode::CheckpointAnchorMismatch
                }
                IntegrityError::Message(_) => KernelErrorCode::Integrity,
            },
        }
    }

    /// The structured context: the human sentence of this error. For the
    /// message-only classes it is the stored message; for the typed classes
    /// it is the payload's `Display` (the same sentences the refusals
    /// always carried). `finalize`/recovery consume this as the refused
    /// reason string.
    pub fn message(&self) -> String {
        match self {
            KernelError::Input(e) => e.message.clone(),
            KernelError::Invariant(e) => e.message.clone(),
            KernelError::Transport(e) => e.message.clone(),
            KernelError::Conflict(c) => c.to_string(),
            KernelError::Integrity(i) => i.to_string(),
        }
    }
}

/// The five error CLASSES — the lightweight "who should react"
/// discriminator: [`Input`](Self::Input) (invalid CLI/configuration/scalar
/// values), [`Invariant`](Self::Invariant) (internally invalid
/// relationships), `Conflict`(Self::Conflict) (valid ops against stale
/// state — the WRITE-boundary class), [`Integrity`](Self::Integrity)
/// (impossible persisted sequences — the READ-boundary class),
/// [`Transport`](Self::Transport) (backend I/O failures). Tests assert the
/// class without matching the full [`KernelError`] variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelErrorClass {
    Input,
    Invariant,
    Conflict,
    Integrity,
    Transport,
}

/// The stable flat error CODES — "which semantic rule failed", for tests,
/// metrics and CLI automation: the ten semantic codes map onto the typed
/// [`ConflictError`] / [`IntegrityError`] variants; the message-only
/// classes fall back to their class-level code
/// ([`Input`](Self::Input) / [`Invariant`](Self::Invariant) /
/// [`Integrity`](Self::Integrity) / [`Transport`](Self::Transport)) so
/// [`KernelError::code`] is TOTAL. No message-only `Conflict` code exists:
/// every [`ConflictError`] variant is a named semantic rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KernelErrorCode {
    /// The stale-plan refusal (parent ≠ the successful head) —
    /// [`ConflictError::ParentMismatch`].
    ParentMismatch,
    /// A still-pending attempt blocks the next intent —
    /// [`ConflictError::PendingAttemptExists`].
    PendingAttemptExists,
    /// The finalizer's "state diverged" refusal —
    /// [`ConflictError::TopologyChanged`].
    TopologyChanged,
    /// A duplicate intent line for one deployment.
    DuplicateIntent,
    /// A duplicate terminal line for one deployment.
    DuplicateTerminal,
    /// A terminal event with no intent line.
    TerminalWithoutIntent,
    /// The terminal binds a digest that is not the intent's canonical one.
    IntentDigestMismatch,
    /// A forked lineage: an ordinary intent whose parent is not the head.
    ParentLineageMismatch,
    /// An intent's inherited slot disagrees with the head's snapshot.
    InheritedSnapshotMismatch,
    /// A checkpointed ledger's missing or non-Successful anchor.
    CheckpointAnchorMismatch,
    /// The message-only [`Input`](KernelError::Input) class code.
    Input,
    /// The message-only [`Invariant`](KernelError::Invariant) class code.
    Invariant,
    /// The message-only [`IntegrityError::Message`] class code.
    Integrity,
    /// The message-only [`Transport`](KernelError::Transport) class code.
    Transport,
}

impl fmt::Display for ConflictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConflictError::ParentMismatch {
                deployment,
                recorded_parent,
                actual_head,
            } => write!(
                f,
                "stale plan: deployment '{deployment}' derives from parent {recorded_parent:?} but the target's successful head is {actual_head:?} (ParentMismatch) — replan against the current head; concurrent group plans are never merged automatically",
            ),
            ConflictError::PendingAttemptExists { pending } => write!(
                f,
                "intent refused: PendingAttemptExists — a previous deployment '{pending}' is still pending (its intent has no terminal); the successful history is strictly linear, so a push cannot plan a second intent while an earlier attempt is unresolved — reconcile the pending attempt first",
            ),
            ConflictError::TopologyChanged { slot } => write!(
                f,
                "state diverged: the selected slot '{slot}' no longer matches the plan (TopologyChanged) — replan against the current live state",
            ),
        }
    }
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntegrityError::DuplicateIntent {
                deployment,
                first_line,
                duplicate_line,
            } => write!(
                f,
                "two intent events for deployment '{deployment}' (lines {first_line} and {duplicate_line}) — the ledger is keyed by deployment id (one intent per deployment)",
            ),
            IntegrityError::DuplicateTerminal {
                deployment,
                first_line,
                duplicate_line,
            } => write!(
                f,
                "two terminal events for deployment '{deployment}' (lines {first_line} and {duplicate_line}) — the terminal event is written exactly once",
            ),
            IntegrityError::TerminalWithoutIntent { deployment, line } => write!(
                f,
                "a terminal event for deployment '{deployment}' has no intent line (line {line}) — a terminal requires its durable intent",
            ),
            IntegrityError::IntentDigestMismatch {
                deployment,
                expected,
                recorded,
            } => write!(
                f,
                "terminal for deployment '{deployment}' binds intent digest {recorded} but the intent's canonical digest is {expected} — a terminal must bind the EXACT canonical intent",
            ),
            IntegrityError::ParentLineageMismatch {
                deployment,
                parent,
                expected_head,
            } => write!(
                f,
                "intent for deployment '{deployment}' refused: ParentMismatch — it derives from parent {parent:?} but the target's successful head is {expected_head:?}; every ordinary intent's parent must equal the current successful head at intent-append time",
            ),
            IntegrityError::InheritedSnapshotMismatch { deployment, slot } => write!(
                f,
                "intent for deployment '{deployment}' inherits slot '{slot}' with an entry that differs from the successful head's snapshot — an intent's inherited entries must equal the head it claims (stale plan or tampered wire)",
            ),
            IntegrityError::CheckpointAnchorMismatch {
                retained_from,
                first_intent,
            } => match first_intent {
                Some(dep) => write!(
                    f,
                    "a checkpointed ledger's retained suffix starts at deployment '{dep}' but it was never finalized `Successful` — a checkpoint requires its anchor (the oldest retained entry) to be a successful deployment",
                ),
                None => write!(
                    f,
                    "a checkpointed ledger's retained suffix must start at the checkpoint deployment '{retained_from}' but no entry for it exists in the retained suffix — a checkpoint requires its anchor (the oldest retained entry)",
                ),
            },
            IntegrityError::Message(message) => f.write_str(message),
        }
    }
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
    /// The facade mapping PRESERVES the complete typed kernel error —
    /// [`Error::Kernel`](crate::error::Error::Kernel) — never flattened into
    /// a class string. The kernel error's own `Display` (its five-class
    /// prefix + the typed payload's sentence) becomes the facade error's
    /// text, so every consumer of the class and the prose keeps working
    /// while the typed evidence stays reachable end to end.
    fn from(e: KernelError) -> Self {
        crate::error::Error::Kernel(e)
    }
}

/// A kernel `Result` alias over the five-class error.
pub type KernelResult<T> = std::result::Result<T, KernelError>;

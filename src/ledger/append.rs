//! The ledger's append/read SEMANTIC types: the two physical line kinds
//! (the WIRE enum the append-only JSONL stream carries). The MERGED entry
//! ([`LedgerEntry`] — the durable intent + optional terminal event, with the
//! entry owning the deployment identity) lives in [`crate::ledger::entry`]
//! and is re-exported here for the append/read path.
//!
//! A target's ENTIRE deployment history lives in ONE ordered, append-only
//! JSONL file: `targets/<target>/ledger.jsonl`. There are exactly two
//! physical line kinds ([`LedgerLine`]):
//!
//! * [`LedgerLine::Intent`] — the DURABLE INTENT of one deployment
//!   ([`LedgerIntentWire`] → verified [`DeploymentIntent`]): deployment_id,
//!   target, behavior digest, membership, and the `desired` / `pre_push`
//!   per-slot maps. It is appended BEFORE any remote mutation (the
//!   append-attempt contract) and never edited. It carries NO status, NO
//!   outcomes, and NO rollback state.
//! * [`LedgerLine::Terminal`] — the TERMINAL EVENT of one deployment
//!   ([`LedgerTerminalWire`] → verified [`LedgerTerminal`]): the status and
//!   the DISPOSITION. Appended once, after the mutation loop, and never
//!   edited.
//!
//! CRASH-ATOMIC APPENDS: every ledger write is a SINGLE atomic line append
//! (one durable line, no partial state). An entry WITHOUT a terminal is the
//! CURRENT/INCOMPLETE state (the deployment is in flight or crashed
//! mid-finalization): its status is `PendingCommit`-like (recoverable), and
//! the next push reconciles it ([`crate::ledger::recovery`]).
//!
//! DEPLOYMENT-ID KEYING: every entry is keyed by its
//! [`crate::identity::DeploymentId`] — the ledger is the deployment's full
//! history record, and appends are idempotent by id (a duplicate intent or
//! terminal for the same deployment is refused by the store's writer).
//!
//! The PHYSICAL I/O (append_intent / append_terminal / read_ledger, the
//! atomic line appends, the wire-version gate on read) lives in
//! [`crate::store::local::LocalStore`] — infrastructure, NOT ledger
//! semantics. This module owns only the semantic TYPES the append/read path
//! carries; the wire shapes and their VERIFYING CONVERSIONS live with the
//! records in [`crate::ledger::records`].

use crate::ledger::intent::LedgerIntentWire;
use crate::ledger::terminal::LedgerTerminalWire;
use serde::{Deserialize, Serialize};

/// ONE physical line of a target's deployment ledger — the WIRE enum: the
/// raw serde shapes ([`LedgerIntentWire`], [`LedgerTerminalWire`]) exactly as
/// the append-only JSONL stream carries them. The ledger is append-only: each
/// deployment contributes at most one [`LedgerLine::Intent`] (written BEFORE
/// any remote mutation) and at most one [`LedgerLine::Terminal`] (appended
/// when the deployment completes). The line ORDER is the history order.
/// [`crate::store::local::LocalStore::read_ledger`] parses these wire lines,
/// runs the VERIFYING CONVERSION (refusing disagreeing records), and merges
/// the validated domain records into [`LedgerEntry`]s keyed by deployment id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerLine {
    /// The durable intent of one deployment, written before any remote
    /// mutation (the append-attempt contract).
    Intent(LedgerIntentWire),
    /// The terminal event of one deployment, appended after the mutation
    /// loop.
    Terminal(LedgerTerminalWire),
}

/// The MERGED deployment entry — re-exported from its home in
/// [`crate::ledger::entry`] so the append/read path (`LedgerLine` consumers,
/// [`crate::store::local::LocalStore::read_ledger`]) keeps one path to the
/// entry type.
pub use crate::ledger::entry::LedgerEntry;

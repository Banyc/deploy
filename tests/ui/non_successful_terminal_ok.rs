//! THE CONTRAST (a `.pass` case): the NON-Successful dispositions ARE
//! constructible by any caller — there is nothing to fabricate in a
//! `FailedPreflight` / `FailedRolledBack` / `Degraded` terminal (their
//! payloads are validated by their own kernel constructors). Only
//! `Successful` is gated behind the sealed proof.

use deploy::identity::Timestamp;
use deploy::kernel::terminal::{IntentDigest, LedgerTerminal, NonSuccessfulDisposition};

fn main() {
    let recorded_at = Timestamp::parse("2026-01-01T00:00:00Z").unwrap();
    let digest = IntentDigest::parse(&"0".repeat(64)).unwrap();
    let _failed_preflight = LedgerTerminal::new(
        recorded_at,
        digest,
        NonSuccessfulDisposition::FailedPreflight,
        None,
    );
}

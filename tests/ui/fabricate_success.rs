//! A library caller CANNOT fabricate a `Successful` terminal: the
//! proof-less constructor takes [`NonSuccessfulDisposition`] — the
//! `Successful` disposition is TYPE-EXCLUDED — so passing
//! `TerminalDisposition::Successful` does not compile. (A `Successful`
//! terminal is constructible only through
//! `LedgerTerminal::successful(VerifiedExecution, ...)`, and the sealed
//! proof is mintable only on the crate's verified-execution evidence path.)

use deploy::identity::Timestamp;
use deploy::kernel::terminal::{IntentDigest, LedgerTerminal, TerminalDisposition};

fn main() {
    let recorded_at = Timestamp::parse("2026-01-01T00:00:00Z").unwrap();
    let digest = IntentDigest::parse(&"0".repeat(64)).unwrap();
    // ERROR: `LedgerTerminal::new` takes `NonSuccessfulDisposition`;
    // `TerminalDisposition::Successful` cannot be fabricated without the
    // sealed `VerifiedExecution` proof.
    let _terminal =
        LedgerTerminal::new(recorded_at, digest, TerminalDisposition::Successful, None);
}

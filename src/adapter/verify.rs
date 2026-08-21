//! Command verification adapter. Executes the configured argument vector
//! directly (never through a shell) with the configured timeout, attempt count,
//! and interval. Success requires a zero exit status within the timeout.

use crate::config::VerificationConfig;
use crate::error::{Error, Result};
use crate::remote::transport::Remote;
use std::time::Duration;

/// Run verification, retrying up to `attempts` times with `interval_seconds`
/// between tries. Returns Ok on the first zero exit status.
pub fn run_verification(remote: &dyn Remote, cfg: &VerificationConfig) -> Result<()> {
    let attempts = cfg.attempts.max(1);
    let timeout = Duration::from_secs(cfg.timeout_seconds);
    let mut last_stderr = String::new();
    for attempt in 0..attempts {
        let outcome = remote.exec(&cfg.argv, timeout)?;
        if outcome.success() {
            return Ok(());
        }
        last_stderr = outcome.stderr;
        if attempt + 1 < attempts && cfg.interval_seconds > 0 {
            std::thread::sleep(Duration::from_secs(cfg.interval_seconds));
        }
    }
    Err(Error::remote(format!(
        "verification failed after {attempts} attempt(s): {last_stderr}"
    )))
}

//! Command verification adapter. Executes the configured argument vector
//! directly (never through a shell) with the configured timeout, attempt count,
//! and interval. Success requires a zero exit status within the timeout.
//!
//! Every argv element is rendered through the template module
//! ([`crate::remote::canonical`]) with the slot context BEFORE exec, so a check like
//! `argv = ["{{ deploy_dir }}/current/app/server", "health-check"]` resolves
//! to the slot's real deployment directory. Elements without templates are
//! unchanged; an unknown or malformed variable fails loudly before anything
//! is executed.

// The adapter is driven OFF the closed [`Verification`] enum: its only
// variant is [`Command`](Verification::Command), so the adapter's payload is
// fully validated (non-empty argv, nonzero attempts/timeout) by construction
// and the adapter USES it — the old code never looked at the `adapter` field
// at all, so an unsupported adapter string in a frozen record was silently
// "verified" with no check. That cannot happen: the record boundary already
// refused any adapter other than `command` before a [`Verification`] could
// exist.
use crate::config::Verification;
use crate::error::{Error, Result};
use crate::remote::canonical::TemplateVars;
use crate::remote::transport::Remote;
use std::time::Duration;

/// Run verification, retrying up to `attempts` times with `interval_seconds`
/// between tries. Returns Ok on the first zero exit status.
pub fn run_verification(
    remote: &dyn Remote,
    verification: &Verification,
    vars: &TemplateVars,
) -> Result<()> {
    let Verification::Command(vc) = verification;
    // The payload is fully validated by construction (non-empty argv, nonzero
    // attempts and timeout), so no defensive `max(1)` upgrade is possible or
    // needed — a zero-attempt command was refused at the record boundary.
    let attempts = vc.attempts().get();
    let timeout = Duration::from_secs(vc.timeout_seconds().get());
    // Render BEFORE the first exec: a template error fails the verification
    // loudly instead of executing a half-rendered command.
    let argv = crate::remote::canonical::render_argv(vc.argv(), vars)?;
    let mut last_stderr = String::new();
    for attempt in 0..attempts {
        let outcome = remote.exec(&argv, timeout)?;
        if outcome.success() {
            return Ok(());
        }
        last_stderr = outcome.stderr;
        if attempt + 1 < attempts && vc.interval_seconds() > 0 {
            std::thread::sleep(Duration::from_secs(vc.interval_seconds()));
        }
    }
    Err(Error::remote(format!(
        "verification failed after {attempts} attempt(s): {last_stderr}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ValidatedCommand, Verification};
    use crate::remote::transport::{CreateNewVerdict, RootedRelativePath};
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    /// A remote whose `exec` records the argv it was handed (and reports
    /// success), so a test can assert the RENDERED command vector — without
    /// ever spawning a process.
    struct RecordingRemote {
        base: PathBuf,
        executed: RefCell<Vec<Vec<String>>>,
    }

    impl RecordingRemote {
        fn new(base: PathBuf) -> Self {
            RecordingRemote {
                base,
                executed: RefCell::new(Vec::new()),
            }
        }
    }

    impl Remote for RecordingRemote {
        fn root(&self) -> &Path {
            &self.base
        }
        fn read(&self, _rel: &RootedRelativePath) -> Result<Vec<u8>> {
            unreachable!("not used by run_verification")
        }
        fn write(&self, _rel: &RootedRelativePath, _data: &[u8], _mode: u32) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn try_write_new(
            &self,
            _rel: &RootedRelativePath,
            _data: &[u8],
        ) -> Result<CreateNewVerdict> {
            unreachable!("not used by run_verification")
        }
        fn create_dir(&self, _rel: &RootedRelativePath) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn create_dir_all(&self, _rel: &RootedRelativePath) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn set_mode(&self, _rel: &RootedRelativePath, _mode: u32) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn list(
            &self,
            _rel: &RootedRelativePath,
        ) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
            unreachable!("not used by run_verification")
        }
        fn rename(&self, _from: &RootedRelativePath, _to: &RootedRelativePath) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn symlink(&self, _target: &Path, _link: &RootedRelativePath) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn read_link(&self, _rel: &RootedRelativePath) -> Result<PathBuf> {
            unreachable!("not used by run_verification")
        }
        fn remove_file(&self, _rel: &RootedRelativePath) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn remove_dir_all(&self, _rel: &RootedRelativePath) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn exists(&self, _rel: &RootedRelativePath) -> bool {
            unreachable!("not used by run_verification")
        }
        fn metadata(
            &self,
            _rel: &RootedRelativePath,
        ) -> Result<crate::remote::transport::RemoteMeta> {
            unreachable!("not used by run_verification")
        }
        fn exec(
            &self,
            argv: &[String],
            _timeout: Duration,
        ) -> Result<crate::remote::transport::ExecOutcome> {
            self.executed.borrow_mut().push(argv.to_vec());
            Ok(crate::remote::transport::ExecOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        fn filesystem_bytes(&self) -> Result<crate::remote::transport::FsBytes> {
            unreachable!("not used by run_verification")
        }
    }

    fn cfg(argv: &[&str]) -> Verification {
        Verification::Command(
            ValidatedCommand::new(argv.iter().map(|a| a.to_string()).collect(), 5, 1, 0)
                .expect("validated command"),
        )
    }

    fn slot_vars() -> TemplateVars {
        TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            "standard",
            "example",
            "v1",
            "production",
            "server-01",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
    }

    #[test]
    fn verification_argv_is_rendered_before_exec() {
        let remote = RecordingRemote::new(PathBuf::from("/fake/root"));
        let c = cfg(&[
            "{{ deploy_dir }}/bin/probe",
            "{{ variant }}",
            "--tag",
            "{{ target }}",
            "--user",
            "{{ user }}",
            "--slot",
            "{{ slot }}",
        ]);
        run_verification(&remote, &c, &slot_vars()).unwrap();
        let executed = remote.executed.borrow();
        assert_eq!(executed.len(), 1, "one attempt, one exec");
        assert_eq!(
            executed[0],
            vec![
                "/srv/deploy/example/bin/probe",
                "standard",
                "--tag",
                "production",
                "--user",
                "deploy",
                "--slot",
                "app-1",
            ]
        );
    }

    #[test]
    fn argv_without_templates_is_unchanged() {
        let remote = RecordingRemote::new(PathBuf::from("/fake/root"));
        let c = cfg(&["true", "--flag"]);
        run_verification(&remote, &c, &slot_vars()).unwrap();
        assert_eq!(*remote.executed.borrow(), vec![vec!["true", "--flag"]]);
    }

    #[test]
    fn unknown_template_variable_is_refused_at_construction() {
        // An argv element referencing an unknown template variable is refused
        // by the VALIDATED CONSTRUCTOR (fail closed) — a command carrying it
        // can never exist, so it can never execute a half-rendered argv. The
        // "render before exec" property is structural: the record boundary
        // already refused the unknown variable before a [`Verification`]
        // could reach the adapter.
        let err = ValidatedCommand::new(
            vec!["{{ bogus }}".to_string(), "health-check".to_string()],
            5,
            1,
            0,
        )
        .expect_err("unknown template variable must be refused");
        assert!(
            err.to_string()
                .contains("unknown template variable 'bogus'")
        );
    }
}

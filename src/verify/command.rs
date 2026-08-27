//! Command verification adapter. Executes the configured argument vector
//! directly (never through a shell) with the configured timeout, attempt count,
//! and interval. Success requires a zero exit status within the timeout.
//!
//! Every argv element is rendered through the template module
//! ([`crate::remote::materialize`]) with the slot context BEFORE exec, so a check like
//! `argv = ["{{ deploy_dir }}/current/app/server", "health-check"]` resolves
//! to the slot's real deployment directory. Elements without templates are
//! unchanged; an unknown or malformed variable fails loudly before anything
//! is executed.

use crate::config::VerificationConfig;
use crate::error::{Error, Result};
use crate::remote::materialize::TemplateVars;
use crate::remote::transport::Remote;
use std::time::Duration;

/// Run verification, retrying up to `attempts` times with `interval_seconds`
/// between tries. Returns Ok on the first zero exit status.
pub fn run_verification(
    remote: &dyn Remote,
    cfg: &VerificationConfig,
    vars: &TemplateVars,
) -> Result<()> {
    let attempts = cfg.attempts.max(1);
    let timeout = Duration::from_secs(cfg.timeout_seconds);
    // Render BEFORE the first exec: a template error fails the verification
    // loudly instead of executing a half-rendered command.
    let argv = crate::remote::materialize::render_argv(&cfg.argv, vars)?;
    let mut last_stderr = String::new();
    for attempt in 0..attempts {
        let outcome = remote.exec(&argv, timeout)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VerificationConfig;
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
        fn read(&self, _rel: &Path) -> Result<Vec<u8>> {
            unreachable!("not used by run_verification")
        }
        fn write(&self, _rel: &Path, _data: &[u8], _mode: u32) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn try_write_new(&self, _rel: &Path, _data: &[u8]) -> Result<bool> {
            unreachable!("not used by run_verification")
        }
        fn create_dir(&self, _rel: &Path) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn create_dir_all(&self, _rel: &Path) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn set_mode(&self, _rel: &Path, _mode: u32) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn list(&self, _rel: &Path) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
            unreachable!("not used by run_verification")
        }
        fn rename(&self, _from: &Path, _to: &Path) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn symlink(&self, _target: &Path, _link: &Path) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn read_link(&self, _rel: &Path) -> Result<PathBuf> {
            unreachable!("not used by run_verification")
        }
        fn remove_file(&self, _rel: &Path) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn remove_dir_all(&self, _rel: &Path) -> Result<()> {
            unreachable!("not used by run_verification")
        }
        fn exists(&self, _rel: &Path) -> bool {
            unreachable!("not used by run_verification")
        }
        fn metadata(&self, _rel: &Path) -> Result<crate::remote::transport::RemoteMeta> {
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

    fn cfg(argv: &[&str]) -> VerificationConfig {
        VerificationConfig {
            adapter: "command".to_string(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            timeout_seconds: 5,
            attempts: 1,
            interval_seconds: 0,
        }
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
    fn unknown_template_variable_fails_before_exec() {
        let remote = RecordingRemote::new(PathBuf::from("/fake/root"));
        let c = cfg(&["{{ bogus }}", "health-check"]);
        let err = run_verification(&remote, &c, &slot_vars()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown template variable 'bogus'")
        );
        assert!(
            remote.executed.borrow().is_empty(),
            "no command executed on a template error"
        );
    }
}

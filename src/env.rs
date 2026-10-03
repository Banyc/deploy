//! The environment snapshot: the ONE place the process environment enters
//! the system, resolved at the process boundary and passed down.
//!
//! [`SysEnv`] is pure data (a `BTreeMap<OsString, OsString>` snapshot) with
//! pure typed accessors: ALL XDG fallback logic (data home, config home) and
//! the temp-dir resolution live HERE, never in subsystem code. Subsystem code
//! takes `&SysEnv` or a value resolved from it; it never reads the process
//! environment itself.
//!
//! The house pattern (mirroring `cli::run_with(std::env::args())`): the
//! process boundary takes [`SysEnv::from_process`] ONCE and threads it down.
//! The only other place `std::env::` is allowed is the child-process boundary
//! ([`SysEnv::apply_to_command`]): every spawned child receives this snapshot as
//! its ENTIRE environment (`env_clear` + the snapshot's variables), so a child's
//! `PATH` (and any fake-bin/test variable) is the deterministic snapshot, never
//! whatever `PATH` won the race in the parent — and nothing else leaks in.
//!
//! # The substrate swap (`storekit::env`)
//!
//! This module was `deploy`'s own environment snapshot, the source
//! `storekit::env` was extracted from; the two are code-identical (only doc
//! comments differ), so this is a `pub use` of the crate's module and every
//! `crate::env::…` call site keeps resolving. It is a PREREQUISITE of the
//! transport swap: the crate's `LocalTransport::new` takes a
//! [`storekit::env::SysEnv`], so `deploy`'s [`SysEnv`] must BE that type (a
//! distinct `deploy` copy could not be passed). `pub` (never `pub(crate)`) is
//! required: this module is `pub mod env` and [`SysEnv`] appears in `deploy`'s
//! public `LocalTransport` API, so narrowing it would break the public
//! surface.

pub use storekit::env::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(*k), OsString::from(*v)))
            .collect()
    }

    #[test]
    fn temp_dir_prefers_tmpdir() {
        let env = SysEnv::from_map(map(&[("TMPDIR", "/hermetic/tmp")]));
        assert_eq!(env.temp_dir(), PathBuf::from("/hermetic/tmp"));
        // An empty TMPDIR falls back to the platform temp dir.
        let env = SysEnv::from_map(map(&[("TMPDIR", "")]));
        assert_eq!(env.temp_dir(), PathBuf::from("/tmp"));
        let env = SysEnv::from_map(map(&[]));
        assert_eq!(env.temp_dir(), PathBuf::from("/tmp"));
    }

    #[test]
    fn data_home_fallbacks() {
        // XDG_DATA_HOME wins.
        let env = SysEnv::from_map(map(&[("XDG_DATA_HOME", "/x/data"), ("HOME", "/h")]));
        assert_eq!(env.data_home(), PathBuf::from("/x/data"));
        // HOME falls back.
        let env = SysEnv::from_map(map(&[("HOME", "/h")]));
        assert_eq!(env.data_home(), PathBuf::from("/h"));
        // Neither -> ".".
        let env = SysEnv::from_map(map(&[]));
        assert_eq!(env.data_home(), PathBuf::from("."));
    }

    #[test]
    fn config_home_fallbacks() {
        // XDG_CONFIG_HOME wins verbatim (no extra .config appended).
        let env = SysEnv::from_map(map(&[("XDG_CONFIG_HOME", "/x/.config"), ("HOME", "/h")]));
        assert_eq!(env.config_home(), PathBuf::from("/x/.config"));
        // HOME falls back to $HOME/.config.
        let env = SysEnv::from_map(map(&[("HOME", "/h")]));
        assert_eq!(env.config_home(), PathBuf::from("/h/.config"));
        // Neither -> .config
        let env = SysEnv::from_map(map(&[]));
        assert_eq!(env.config_home(), PathBuf::from(".config"));
    }

    #[test]
    fn get_and_child_env_round_trip() {
        let env = SysEnv::from_map(map(&[("PATH", "/bin:/usr/bin"), ("TMPDIR", "/t")]));
        assert_eq!(env.get("PATH"), Some(OsString::from("/bin:/usr/bin")));
        assert_eq!(env.path(), Some(OsString::from("/bin:/usr/bin")));
        assert_eq!(env.get("UNSET"), None);
        let child = env.child_env();
        assert_eq!(child.len(), 2);
        assert!(child.contains(&(OsString::from("PATH"), OsString::from("/bin:/usr/bin"))));
        assert!(child.contains(&(OsString::from("TMPDIR"), OsString::from("/t"))));
    }

    #[test]
    fn apply_to_command_is_hermetic() {
        let env = SysEnv::from_map(map(&[("PATH", "/snapshot/bin:/usr/bin")]));
        let mut cmd = std::process::Command::new("true");
        // A parent env that would leak through a plain `envs` overlay.
        cmd.env("PATH", "/parent/bin");
        cmd.env("LEAKY_VAR", "parent-value");
        env.apply_to_command(&mut cmd);
        // The child's env is EXACTLY the snapshot: nothing from the parent.
        let vars: BTreeMap<OsString, OsString> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
            .collect();
        assert_eq!(vars.len(), 1);
        assert_eq!(
            vars.get(OsStr::new("PATH")),
            Some(&OsString::from("/snapshot/bin:/usr/bin"))
        );
        assert_eq!(vars.get(OsStr::new("LEAKY_VAR")), None);
    }
}

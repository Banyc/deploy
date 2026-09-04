//! Systemd activation adapter.
//!
//! The mapped unit file remains an ordinary artifact in the tree, but its
//! CONTENT is rendered with the slot's template context (see
//! [`crate::remote::canonical`]) at activation time: unit files use per-slot values
//! such as `ExecStart={{ deploy_dir }}/current/app/server`, and trees are
//! content-addressed and shared across slots, so the slot context can only be
//! substituted when the unit is installed, never at materialization. The
//! rendered unit is staged under the remote root as a REGULAR FILE (a rendered
//! unit can no longer be a symlink into the generation tree) and copied into
//! the user service manager directory. For `scope: user` it manages
//! `~/.config/systemd/user/<unit>` files and uses `systemctl --user`. For
//! `scope: system` it only verifies a fixed, root-owned wrapper unit and uses
//! a narrowly scoped restart permission; it never installs an
//! artifact-controlled unit into `/etc/systemd/system`.

// The adapter is driven OFF the closed [`Activation`] enum: only an
// explicit `Activation::Systemd(..)` value can reach it (the `None` variant
// is the intended no-op), so the old `if cfg.adapter != "systemd" { return
// Ok(()) }` silent no-op on unknown adapter names is structurally gone — an
// unknown adapter cannot construct an [`Activation`] in the first place.
//
// # THE ADAPTER TRANSACTION (the review's P1 fix)
//
// The systemd adapter is the MUTATING adapter: its apply installs unit
// files, enables and restarts services — persistent side effects OUTSIDE
// the generation pointer. It implements the
// [`ActivationTransaction`](crate::verify::adapters::transaction::ActivationTransaction)
// protocol (prepare/apply/restore/verify_restored): `prepare` captures the
// PRIOR live unit state (the undo record) and stages the rendered units,
// `apply` installs/enables/restarts, `restore` reverses the side effects
// back to the captured prior state (prior content / enabled / running), and
// `verify_restored` RE-READS the remote (the installed unit files / the
// active state) — the ONLY producer of the sealed
// [`VerifiedAdapterRestoration`](crate::verify::adapters::transaction::VerifiedAdapterRestoration)
// proof. The engine runs the adapter through this protocol: on an apply
// failure it calls `restore` + `verify_restored`, and only a VERIFIED
// restoration classifies the slot `Restored` — never "we called restore".
use crate::config::activation::validate_unit_name;
use crate::config::{Activation, ActivationScope, ValidatedSystemd, validate_relative_path};
use crate::error::{Error, Result};
use crate::remote::canonical::TemplateVars;
use crate::remote::transport::{Remote, RootedRelativePath};
use crate::verify::adapters::transaction::{ActivationTransaction, VerifiedAdapterRestoration};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Remote-root-relative directory where rendered unit files are staged before
/// being copied into the user service manager directory. The regular file
/// under this directory is what `cp` installs; it sits next to the
/// `adapters/systemd.json` state file (a file and a directory can coexist
/// under `adapters/`).
const RENDERED_UNITS_DIR: &str = "adapters/systemd";

/// Remote-root-relative directory where the PRIOR unit content is staged
/// during [`restore`](SystemdActivation::restore) before being installed
/// back over the unit link (the prior content was captured by `prepare` and
/// lives only in the controller's memory, so restore re-materializes it on
/// the remote). Distinct from [`RENDERED_UNITS_DIR`] so the prior content
/// never collides with the rendered units `apply` staged.
const RESTORE_UNITS_DIR: &str = "adapters/systemd-restore";

/// Resolve the XDG configuration home base from explicit variables.
///
/// Pure: takes the variable values as arguments so it can be tested without
/// mutating the process-wide environment.
///
/// * `XDG_CONFIG_HOME` wins when set and non-empty.
/// * otherwise `$HOME/.config`.
/// * otherwise `.config`.
pub fn resolve_config_home(xdg_config_home: Option<&str>, home: Option<&str>) -> PathBuf {
    match xdg_config_home.filter(|s| !s.is_empty()) {
        Some(xdg) => PathBuf::from(xdg),
        None => match home.filter(|s| !s.is_empty()) {
            Some(h) => PathBuf::from(h).join(".config"),
            None => PathBuf::from(".config"),
        },
    }
}

/// The configuration base directory, resolved from the environment
/// snapshot (never the process env): `XDG_CONFIG_HOME` → `HOME/.config` →
/// `.config`.
pub fn config_home(env: &crate::env::SysEnv) -> PathBuf {
    resolve_config_home(
        env.get("XDG_CONFIG_HOME")
            .map(|v| v.to_string_lossy().into_owned())
            .as_deref(),
        env.get("HOME")
            .map(|v| v.to_string_lossy().into_owned())
            .as_deref(),
    )
}

/// Pure variant of `user_unit_link` that takes an explicit config base, so it
/// can be tested without depending on the process environment.
pub fn user_unit_link_for(config_base: &Path, unit: &str) -> PathBuf {
    config_base.join("systemd/user").join(unit)
}

/// Resolve the XDG config base on the *remote* host by asking its shell. The
/// systemd user unit directory lives under `${XDG_CONFIG_HOME:-$HOME/.config}`,
/// and that value must come from the host where the unit will be linked and
/// activated, not from the controller's own environment.
pub fn resolve_remote_config_home(remote: &dyn Remote) -> Result<PathBuf> {
    let outcome = remote.exec(
        &[
            "sh".into(),
            "-c".into(),
            r#"printf "%s" "${XDG_CONFIG_HOME:-$HOME/.config}""#.into(),
        ],
        Duration::from_secs(30),
    )?;
    if !outcome.success() {
        return Err(Error::remote(format!(
            "resolve remote config home failed: {}",
            outcome.stderr
        )));
    }
    let home = outcome.stdout.trim().to_string();
    if home.is_empty() {
        return Err(Error::remote("remote config home resolved to empty"));
    }
    Ok(PathBuf::from(home))
}

/// Build the activation command vectors for the given remote root.
///
/// Ordering follows the required contract:
/// 1. Create the parent directory and (user scope only) install each unit:
///    the unit was staged as a rendered REGULAR FILE under
///    `<remote_root>/adapters/systemd/<unit>` by [`stage_rendered_units`], and
///    `cp` copies it into the user systemd dir (the rendered content is never
///    concatenated into a command; commands only reference file paths).
/// 2. `daemon-reload` (user scope only).
/// 3. `enable` and `restart` each declared unit.
///
/// System scope never installs an artifact-controlled unit; it only performs
/// the narrowly scoped restart of the fixed wrapper unit.
///
/// `remote_root` is the absolute deployment directory on the remote host
/// ([`Remote::root`]); `config_home` is the remote host's resolved config
/// base (see [`resolve_remote_config_home`]); unit files are installed under
/// it so the path is correct on the remote host rather than reflecting the
/// controller's env.
pub fn activation_commands(
    remote_root: &Path,
    config_home: &Path,
    sa: &ValidatedSystemd,
) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    let scope_user = matches!(sa.scope(), ActivationScope::User);

    // 0. USER SCOPE ONLY: enable lingering for the deployment account BEFORE
    //    installing any unit. Without it, the user manager (and therefore
    //    every `--user` service) is terminated when the last session ends, so
    //    a service deployed here would die on logout. `loginctl enable-linger`
    //    with no argument enables it for the caller (the deployment account);
    //    the default polkit policy allows a user to set lingering for
    //    themselves without authentication, and the operation is idempotent
    //    (an already-lingering user is a no-op). Linger is a one-time system
    //    setting, not a per-deployment effect — the restore path never
    //    disables it.
    if scope_user {
        cmds.push(vec!["loginctl".into(), "enable-linger".into()]);
    }

    // 1. Parent directory + install each unit from its rendered staging file
    //    (user scope only).
    if scope_user {
        for u in sa.units() {
            let link = user_unit_link_for(config_home, u.name());
            if let Some(parent) = link.parent() {
                cmds.push(vec![
                    "mkdir".into(),
                    "-p".into(),
                    parent.to_string_lossy().into_owned(),
                ]);
            }
            let staged = remote_root.join(RENDERED_UNITS_DIR).join(u.name());
            cmds.push(vec![
                "cp".into(),
                staged.to_string_lossy().into_owned(),
                link.to_string_lossy().into_owned(),
            ]);
            cmds.push(vec![
                "chmod".into(),
                "0644".into(),
                link.to_string_lossy().into_owned(),
            ]);
        }
    }

    // 2. daemon-reload (user scope only).
    if scope_user {
        cmds.push(vec![
            "systemctl".into(),
            "--user".into(),
            "daemon-reload".into(),
        ]);
    }

    // 3. enable + restart.
    for u in sa.units() {
        if u.enable() && scope_user {
            cmds.push(vec![
                "systemctl".into(),
                "--user".into(),
                "enable".into(),
                u.name().to_string(),
            ]);
        }
        if u.restart() {
            if scope_user {
                cmds.push(vec![
                    "systemctl".into(),
                    "--user".into(),
                    "restart".into(),
                    u.name().to_string(),
                ]);
            } else {
                // system scope: only a narrowly scoped restart of the wrapper.
                cmds.push(vec![
                    "systemctl".into(),
                    "restart".into(),
                    u.name().to_string(),
                ]);
            }
        }
    }
    cmds
}

/// One declared unit's RENDERED content (the bytes `apply` installs and
/// `verify_restored`/`verify_adapter_restored` compare the installed file
/// against).
pub(crate) struct RenderedUnit {
    pub(crate) name: String,
    pub(crate) content: Vec<u8>,
}

/// Render every declared unit's artifact content with the slot context —
/// the bytes the unit file must contain after the adapter's apply (and the
/// expected bytes a restore/compensation must reproduce). A template error
/// (unknown variable, malformed syntax) fails loudly here, before any
/// command runs.
pub(crate) fn render_units(
    remote: &dyn Remote,
    generation_root: &Path,
    sa: &ValidatedSystemd,
    vars: &TemplateVars,
) -> Result<Vec<RenderedUnit>> {
    // `generation_root` is an absolute host path (`remote.root()` joined with
    // the generation layout); the transport's read/write surface is anchored
    // at the remote root, so strip the root prefix back off and validate the
    // result at the boundary (a generation root outside the remote root is
    // refused).
    let gen_rel =
        RootedRelativePath::parse(generation_root.strip_prefix(remote.root()).map_err(|_| {
            Error::remote(format!(
                "generation root '{}' is not under remote root '{}'",
                generation_root.display(),
                remote.root().display()
            ))
        })?)?;
    let mut out = Vec::new();
    for u in sa.units() {
        let src = gen_rel.join(u.artifact_path())?;
        let raw = remote.read(&src).map_err(|e| {
            Error::remote(format!(
                "read unit artifact '{}' from generation tree: {e}",
                u.artifact_path()
            ))
        })?;
        let text = std::str::from_utf8(&raw)
            .map_err(|e| Error::remote(format!("unit '{}' is not UTF-8: {e}", u.name())))?;
        let rendered = crate::remote::canonical::render_template(text, vars).map_err(|e| {
            Error::remote(format!(
                "render unit '{}' ({}) with slot context: {e}",
                u.name(),
                u.artifact_path()
            ))
        })?;
        out.push(RenderedUnit {
            name: u.name().to_string(),
            content: rendered.as_bytes().to_vec(),
        });
    }
    Ok(out)
}

/// Render every declared unit's artifact content with the slot context and
/// stage the rendered REGULAR FILE under the remote root
/// (`adapters/systemd/<unit>`). The subsequent `cp` in
/// [`activation_commands`] installs the rendered copy into the user service
/// manager directory. A template error (unknown variable, malformed syntax)
/// fails loudly here, before any command runs.
pub fn stage_rendered_units(
    remote: &dyn Remote,
    generation_root: &Path,
    sa: &ValidatedSystemd,
    vars: &TemplateVars,
) -> Result<()> {
    for u in render_units(remote, generation_root, sa, vars)? {
        let dest = RootedRelativePath::parse(&Path::new(RENDERED_UNITS_DIR).join(&u.name))?;
        remote
            .write(&dest, &u.content, 0o644)
            .map_err(|e| Error::remote(format!("stage rendered unit '{}': {e}", u.name)))?;
    }
    Ok(())
}

/// Validate that every declared artifact path exists in the desired generation
/// tree with the correct type before changing `current`.
pub fn validate_artifact_paths(
    remote: &dyn Remote,
    generation_root_rel: &RootedRelativePath,
    sa: &ValidatedSystemd,
) -> Result<()> {
    for u in sa.units() {
        let p = generation_root_rel.join(u.artifact_path())?;
        if remote.metadata_opt(&p)?.is_none() {
            return Err(Error::remote(format!(
                "declared artifact path '{}' missing in desired tree",
                u.artifact_path()
            )));
        }
        let meta = remote.metadata(&p)?;
        if !meta.is_file {
            return Err(Error::remote(format!(
                "declared artifact path '{}' is not a regular file (type error)",
                u.artifact_path()
            )));
        }
    }
    Ok(())
}

/// Run activation: render + stage the units with the slot context, build and
/// execute the systemd commands, then record the managed unit links.
///
/// `generation_root` is the absolute generation tree path on the remote host
/// (the source of each unit's artifact content); `vars` is the slot context
/// ([`TemplateVars::slot`]) whose `deploy_dir`/`variant`/... are substituted
/// into the unit content and any templated argv.
///
/// The adapter is run through its TRANSACTION protocol (`SystemdActivation`:
/// `prepare` — validate + capture the prior state + stage — then `apply` —
/// install/enable/restart + state record). The engine's
/// per-slot flow drives the transaction itself (so a failed apply can be
/// reversed + verified); this entry point is the adapter's plain
/// "activate" call used by the compensation paths that re-run a prior
/// contract.
pub fn run_activation(
    remote: &dyn Remote,
    generation_root: &Path,
    activation: &Activation,
    vars: &TemplateVars,
) -> Result<()> {
    // Only an explicit `Activation::Systemd` payload reaches the adapter; the
    // `None` variant is the DELIBERATE no-op of `adapter = "none"`. There is
    // no other arm: an unknown adapter cannot construct an [`Activation`], so
    // an unsupported adapter can never silently skip activation here.
    let mut txn = match SystemdActivation::new(remote, generation_root, activation, vars) {
        Some(t) => t,
        None => return Ok(()),
    };
    let prepared = txn.prepare()?;
    txn.apply(&prepared)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// THE ADAPTER TRANSACTION (the review's P1 fix) — see the module docs.
// ---------------------------------------------------------------------------

/// THE ONE PRIOR-STATE RECORD of one unit, captured by [`SystemdActivation::prepare`]:
/// the unit's live state BEFORE apply — what `restore` must reverse apply to
/// and what `verify_restored` RE-READS to confirm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitPriorState {
    pub(crate) name: String,
    /// The installed content before apply (`None` = the unit was ABSENT —
    /// restore removes the installed unit, verify requires absence).
    pub(crate) content: Option<Vec<u8>>,
    /// Whether the unit was enabled before apply (restore re-enables /
    /// disables back).
    pub(crate) enabled: bool,
}

/// The `Prepared` state of the systemd transaction: the captured prior unit
/// state — `apply`'s undo record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SystemdPrepared {
    pub(crate) prior: Vec<UnitPriorState>,
}

/// The `Applied` state of the systemd transaction: the undo record survives
/// the mutation so `restore` can reverse it. Also constructible from a
/// `Prepared` when `apply` FAILED partway — `restore` only needs the captured
/// prior state, so the engine reverses whatever apply may have installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SystemdApplied {
    pub(crate) prepared: SystemdPrepared,
}

impl SystemdApplied {
    /// The engine builds the applied record from the prepared state when
    /// `apply` failed partway: restore reverses "whatever apply may have
    /// installed" back to the captured prior state, so the undo record is
    /// fully contained in `Prepared`.
    pub(crate) fn from_prepared(prepared: &SystemdPrepared) -> Self {
        SystemdApplied {
            prepared: prepared.clone(),
        }
    }
}

/// The `Restored` state of the systemd transaction: the expected prior state
/// `verify_restored` reads back against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SystemdRestored {
    pub(crate) expected: Vec<UnitPriorState>,
}

/// THE SYSTEMD ACTIVATION TRANSACTION: the mutating adapter's
/// prepare→apply→restore→verify_restored discipline. `Activation::None`
/// (no mutating adapter) has NO transaction — [`new`](Self::new) returns
/// `None` for it.
pub(crate) struct SystemdActivation<'a> {
    remote: &'a dyn Remote,
    /// The generation tree root the units render from (absolute, on the
    /// remote host).
    generation_root: PathBuf,
    sa: &'a ValidatedSystemd,
    vars: &'a TemplateVars,
    /// The remote config base (resolved in `prepare` — needed for the unit
    /// link paths in apply/restore/verify).
    config_home: Option<PathBuf>,
}

impl<'a> SystemdActivation<'a> {
    /// Build the transaction for the behavior's activation adapter: `None`
    /// for `Activation::None` (no mutating adapter — nothing to transact).
    pub(crate) fn new(
        remote: &'a dyn Remote,
        generation_root: &Path,
        activation: &'a Activation,
        vars: &'a TemplateVars,
    ) -> Option<Self> {
        let Activation::Systemd(sa) = activation else {
            return None;
        };
        Some(SystemdActivation {
            remote,
            generation_root: generation_root.to_path_buf(),
            sa,
            vars,
            config_home: None,
        })
    }
}

impl ActivationTransaction for SystemdActivation<'_> {
    type Prepared = SystemdPrepared;
    type Applied = SystemdApplied;
    type Restored = SystemdRestored;

    /// Validate every declared unit name and artifact path, capture the
    /// PRIOR live unit state (the undo record), and stage the rendered units
    /// — all BEFORE apply installs anything. A template error (unknown
    /// variable, malformed syntax) fails loudly here, never after a
    /// half-installed unit.
    fn prepare(&mut self) -> Result<Self::Prepared> {
        let sa = self.sa;
        // Defense-in-depth re-check for hand-built payloads (the
        // config/record closed-enum boundary already validated these): a
        // path traversal here would escape the generation root.
        for u in sa.units() {
            validate_unit_name(u.name())?;
            validate_relative_path(Path::new(u.artifact_path())).map_err(|e| {
                Error::remote(format!("unit '{}' artifact path invalid: {e}", u.name()))
            })?;
        }
        // Resolve the unit directory base on the *remote* host, not the
        // controller.
        let config_home = resolve_remote_config_home(self.remote)?;
        self.config_home = Some(config_home.clone());
        let scope_user = matches!(sa.scope(), ActivationScope::User);
        let mut prior = Vec::new();
        if scope_user {
            for u in sa.units() {
                let link = user_unit_link_for(&config_home, u.name());
                // The PRIOR installed content: a clean absence (`cat` exit
                // != 0) is `None`; a transport failure is an error.
                let content = match self.remote.exec(
                    &["cat".into(), link.to_string_lossy().into_owned()],
                    Duration::from_secs(30),
                ) {
                    Ok(out) if out.success() => Some(out.stdout.into_bytes()),
                    Ok(_) => None,
                    Err(e) => {
                        return Err(Error::remote(format!(
                            "read prior unit '{}': {e}",
                            u.name()
                        )));
                    }
                };
                // The PRIOR enabled state (`systemctl --user is-enabled`; a
                // missing/disabled/unreporting unit is treated as not
                // enabled). Captured for RESTORE (enable/disable back) — the
                // READ-BACK verification checks the unit FILE content.
                let enabled = self
                    .remote
                    .exec(
                        &[
                            "systemctl".into(),
                            "--user".into(),
                            "is-enabled".into(),
                            u.name().to_string(),
                        ],
                        Duration::from_secs(30),
                    )
                    .map(|o| o.success() && enabledish(&o.stdout))
                    .unwrap_or(false);
                prior.push(UnitPriorState {
                    name: u.name().to_string(),
                    content,
                    enabled,
                });
            }
        } else {
            // System scope: restart-only, no installed files — the prior
            // state is the unit NAMES (restore re-applies the restart; verify
            // checks the ACTIVE state).
            for u in sa.units() {
                prior.push(UnitPriorState {
                    name: u.name().to_string(),
                    content: None,
                    enabled: false,
                });
            }
        }
        // Render + stage the units BEFORE any command runs (user scope only).
        if scope_user {
            stage_rendered_units(self.remote, &self.generation_root, sa, self.vars)?;
        }
        Ok(SystemdPrepared { prior })
    }

    /// Install/enable/restart the staged units and record the managed unit
    /// links. A failure may be PARTIAL (some commands ran, some did not):
    /// the engine still calls `restore` (against an `Applied` built from the
    /// prepared undo record) to reverse whatever was installed.
    fn apply(&mut self, prepared: &Self::Prepared) -> Result<Self::Applied> {
        let sa = self.sa;
        let config_home = self.config_home.as_ref().expect("prepare ran before apply");
        let cmds = activation_commands(self.remote.root(), config_home, sa);
        for argv in &cmds {
            let outcome = self.remote.exec(argv, Duration::from_secs(30))?;
            if !outcome.success() {
                return Err(Error::remote(format!(
                    "systemd activation command {:?} failed: {}",
                    argv, outcome.stderr
                )));
            }
        }
        let managed: Vec<String> = sa.units().map(|u| u.name().to_string()).collect();
        let payload = serde_json::json!({ "managed_units": managed });
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| Error::remote(format!("serialize systemd state: {e}")))?;
        self.remote.write(
            &RootedRelativePath::parse(Path::new("adapters/systemd.json"))
                .expect("the adapters/systemd.json layout path is a safe relative path"),
            &bytes,
            0o644,
        )?;
        Ok(SystemdApplied {
            prepared: prepared.clone(),
        })
    }

    /// Reverse the mutation: restore the PRIOR live unit state — prior
    /// content (or removal when the unit was absent before), prior enabled
    /// state, and a restart so the restored unit is the one running. For
    /// system scope (restart-only, no persistent state) reversing the
    /// transient restart is re-applying it.
    fn restore(&mut self, applied: &Self::Applied) -> Result<Self::Restored> {
        let sa = self.sa;
        let config_home = self.config_home.as_ref().expect("prepare ran");
        if matches!(sa.scope(), ActivationScope::User) {
            for p in &applied.prepared.prior {
                let link = user_unit_link_for(config_home, &p.name);
                match &p.content {
                    Some(bytes) => {
                        // Re-materialize the prior content under the remote
                        // root and install it back over the unit link (the
                        // link lies outside the remote root, so the install
                        // goes through exec).
                        let staged =
                            RootedRelativePath::parse(&Path::new(RESTORE_UNITS_DIR).join(&p.name))
                                .expect(
                                    "a restore-unit path built from a validated unit name is safe",
                                );
                        self.remote.write(&staged, bytes, 0o644).map_err(|e| {
                            Error::remote(format!("stage prior unit '{}': {e}", p.name))
                        })?;
                        let abs = self.remote.root().join(&staged);
                        let argv = [
                            "install".to_string(),
                            "-m".to_string(),
                            "0644".to_string(),
                            abs.to_string_lossy().into_owned(),
                            link.to_string_lossy().into_owned(),
                        ];
                        let outcome = self.remote.exec(&argv, Duration::from_secs(30))?;
                        if !outcome.success() {
                            return Err(Error::remote(format!(
                                "restore unit '{}' install failed: {}",
                                p.name, outcome.stderr
                            )));
                        }
                        // Enabled state back to prior.
                        let act = if p.enabled { "enable" } else { "disable" };
                        let outcome = self.remote.exec(
                            &[
                                "systemctl".into(),
                                "--user".into(),
                                act.into(),
                                p.name.clone(),
                            ],
                            Duration::from_secs(30),
                        )?;
                        if !outcome.success() {
                            return Err(Error::remote(format!(
                                "restore unit '{}' {act} failed: {}",
                                p.name, outcome.stderr
                            )));
                        }
                    }
                    None => {
                        // The prior state had NO unit: remove the installed
                        // one.
                        let outcome = self.remote.exec(
                            &[
                                "rm".into(),
                                "-f".into(),
                                link.to_string_lossy().into_owned(),
                            ],
                            Duration::from_secs(30),
                        )?;
                        if !outcome.success() {
                            return Err(Error::remote(format!(
                                "restore: remove unit '{}' failed: {}",
                                p.name, outcome.stderr
                            )));
                        }
                    }
                }
            }
            let outcome = self.remote.exec(
                &["systemctl".into(), "--user".into(), "daemon-reload".into()],
                Duration::from_secs(30),
            )?;
            if !outcome.success() {
                return Err(Error::remote(format!(
                    "restore: daemon-reload failed: {}",
                    outcome.stderr
                )));
            }
            // Re-apply the restored units (the service runs the prior
            // content).
            for p in &applied.prepared.prior {
                if p.content.is_some() {
                    let outcome = self.remote.exec(
                        &[
                            "systemctl".into(),
                            "--user".into(),
                            "restart".into(),
                            p.name.clone(),
                        ],
                        Duration::from_secs(30),
                    )?;
                    if !outcome.success() {
                        return Err(Error::remote(format!(
                            "restore: restart '{}' failed: {}",
                            p.name, outcome.stderr
                        )));
                    }
                }
            }
            // Record the restored managed set (the prior units).
            let managed: Vec<String> = applied
                .prepared
                .prior
                .iter()
                .map(|p| p.name.clone())
                .collect();
            let payload = serde_json::json!({ "managed_units": managed });
            let bytes = serde_json::to_vec_pretty(&payload)
                .map_err(|e| Error::remote(format!("serialize systemd state: {e}")))?;
            self.remote.write(
                &RootedRelativePath::parse(Path::new("adapters/systemd.json"))
                    .expect("the adapters/systemd.json layout path is a safe relative path"),
                &bytes,
                0o644,
            )?;
        } else {
            // System scope: no persistent state — reversing the restart is
            // re-applying it.
            let cmds = activation_commands(self.remote.root(), Path::new(""), sa);
            for argv in &cmds {
                let outcome = self.remote.exec(argv, Duration::from_secs(30))?;
                if !outcome.success() {
                    return Err(Error::remote(format!(
                        "restore: systemd command {:?} failed: {}",
                        argv, outcome.stderr
                    )));
                }
            }
        }
        Ok(SystemdRestored {
            expected: applied.prepared.prior.clone(),
        })
    }

    /// RE-READ the remote and confirm the restoration took effect: the
    /// installed unit file equals the prior content (or is absent when it
    /// was absent before); system scope: the wrapper is ACTIVE. THE ONLY
    /// producer of the sealed [`VerifiedAdapterRestoration`] proof — a
    /// restore that did NOT take effect (content mismatch, a unit still
    /// installed, an inactive wrapper) is refused here.
    fn verify_restored(&self, restored: &Self::Restored) -> Result<VerifiedAdapterRestoration> {
        let sa = self.sa;
        let config_home = self.config_home.as_ref().expect("prepare ran");
        if matches!(sa.scope(), ActivationScope::User) {
            for p in &restored.expected {
                let link = user_unit_link_for(config_home, &p.name);
                match &p.content {
                    Some(bytes) => {
                        let outcome = self
                            .remote
                            .exec(
                                &["cat".into(), link.to_string_lossy().into_owned()],
                                Duration::from_secs(30),
                            )
                            .map_err(|e| {
                                Error::remote(format!("verify restored unit '{}': {e}", p.name))
                            })?;
                        if !outcome.success() || outcome.stdout.as_bytes() != bytes.as_slice() {
                            return Err(Error::remote(format!(
                                "verify restored: unit '{}' is not back at its prior content",
                                p.name
                            )));
                        }
                    }
                    None => {
                        let outcome = self
                            .remote
                            .exec(
                                &[
                                    "test".into(),
                                    "!".into(),
                                    "-e".into(),
                                    link.to_string_lossy().into_owned(),
                                ],
                                Duration::from_secs(30),
                            )
                            .map_err(|e| {
                                Error::remote(format!(
                                    "verify restored unit '{}' absent: {e}",
                                    p.name
                                ))
                            })?;
                        if !outcome.success() {
                            return Err(Error::remote(format!(
                                "verify restored: unit '{}' is still installed (prior state: absent)",
                                p.name
                            )));
                        }
                    }
                }
            }
        } else {
            for p in &restored.expected {
                let outcome = self
                    .remote
                    .exec(
                        &["systemctl".into(), "is-active".into(), p.name.clone()],
                        Duration::from_secs(30),
                    )
                    .map_err(|e| {
                        Error::remote(format!("verify restored unit '{}': {e}", p.name))
                    })?;
                if !outcome.success() {
                    return Err(Error::remote(format!(
                        "verify restored: unit '{}' is not active",
                        p.name
                    )));
                }
            }
        }
        Ok(VerifiedAdapterRestoration::verified())
    }
}

/// Parse a `systemctl is-enabled` output: the unit is ENABLED iff the
/// output names an enabled state ("enabled", "enabled-runtime", ...); every
/// other state (disabled, static, indirect, masked, not-found, or an
/// empty/unparsable fake-shim output) is NOT enabled. Tolerant by design:
/// the enabled state is captured for RESTORE (enable/disable back), while
/// the READ-BACK verification checks the unit FILE content — the
/// authoritative persistent fact.
fn enabledish(stdout: &str) -> bool {
    stdout.contains("enabled") && !stdout.contains("disabled")
}

/// The declared USER-SCOPE unit names of an activation contract — the only
/// FILE-INSTALLED units (system scope only restarts a fixed root-owned
/// wrapper; it installs nothing, so it has no removable file side effect).
pub(crate) fn declared_user_units(activation: &Activation) -> Vec<String> {
    let Activation::Systemd(sa) = activation else {
        return Vec::new();
    };
    if !matches!(sa.scope(), ActivationScope::User) {
        return Vec::new();
    }
    sa.units().map(|u| u.name().to_string()).collect()
}

/// RESTORE the adapter side effects to the state the TARGET contract would
/// install (the compensation-time restore — used when no transaction undo
/// record exists, e.g. the failure-policy pass compensating an earlier
/// batch's slot, or an activation `prepare` failure): run the target's
/// activation (installs the target's units), then REMOVE any unit the
/// ADVANCED contract installed that the target does not declare (the
/// target's prior state has those units ABSENT). For `Activation::None`
/// only the removals run.
pub(crate) fn restore_adapter_to(
    remote: &dyn Remote,
    generation_root: &Path,
    target: &Activation,
    vars: &TemplateVars,
    advanced_only_units: &[String],
) -> Result<()> {
    // Re-run the target's activation (installs the target's units).
    run_activation(remote, generation_root, target, vars)?;
    // Remove any advanced-only units (user scope only — they are the only
    // file-installed side effects).
    if !advanced_only_units.is_empty() {
        let config_home = resolve_remote_config_home(remote)?;
        for name in advanced_only_units {
            let link = user_unit_link_for(&config_home, name);
            let outcome = remote.exec(
                &[
                    "rm".into(),
                    "-f".into(),
                    link.to_string_lossy().into_owned(),
                ],
                Duration::from_secs(30),
            )?;
            if !outcome.success() {
                return Err(Error::remote(format!(
                    "restore: remove advanced unit '{name}' failed: {}",
                    outcome.stderr
                )));
            }
        }
        let outcome = remote.exec(
            &["systemctl".into(), "--user".into(), "daemon-reload".into()],
            Duration::from_secs(30),
        )?;
        if !outcome.success() {
            return Err(Error::remote(format!(
                "restore: daemon-reload failed: {}",
                outcome.stderr
            )));
        }
    }
    Ok(())
}

/// VERIFY the adapter side effects are back at the state the TARGET
/// contract would install (plus: every unit the ADVANCED contract installed
/// that the target does not declare is ABSENT): RE-READ the remote — the
/// installed unit files against the target's rendered content, the
/// advanced-only units' absence, and (system scope) the active state. THE
/// READ-BACK — the ONLY producer of the sealed
/// [`VerifiedAdapterRestoration`] proof on the compensation paths.
pub(crate) fn verify_adapter_restored(
    remote: &dyn Remote,
    generation_root: &Path,
    target: &Activation,
    vars: &TemplateVars,
    advanced_only_units: &[String],
) -> Result<VerifiedAdapterRestoration> {
    let Activation::Systemd(sa) = target else {
        // `Activation::None`: no mutating adapter — no persistent side
        // effects to verify; the advanced-only units (if any) must be ABSENT.
        if !advanced_only_units.is_empty() {
            let config_home = resolve_remote_config_home(remote)?;
            for name in advanced_only_units {
                let link = user_unit_link_for(&config_home, name);
                let outcome = remote.exec(
                    &[
                        "test".into(),
                        "!".into(),
                        "-e".into(),
                        link.to_string_lossy().into_owned(),
                    ],
                    Duration::from_secs(30),
                )?;
                if !outcome.success() {
                    return Err(Error::remote(format!(
                        "verify restored: unit '{name}' is still installed (prior state: absent)"
                    )));
                }
            }
        }
        return Ok(VerifiedAdapterRestoration::verified());
    };
    if matches!(sa.scope(), ActivationScope::User) {
        let config_home = resolve_remote_config_home(remote)?;
        // Render the target's units: the EXPECTED installed content.
        for u in render_units(remote, generation_root, sa, vars)? {
            let link = user_unit_link_for(&config_home, &u.name);
            let outcome = remote
                .exec(
                    &["cat".into(), link.to_string_lossy().into_owned()],
                    Duration::from_secs(30),
                )
                .map_err(|e| Error::remote(format!("verify restored unit '{}': {e}", u.name)))?;
            if !outcome.success() || outcome.stdout.as_bytes() != u.content.as_slice() {
                return Err(Error::remote(format!(
                    "verify restored: unit '{}' is not back at the prior content",
                    u.name
                )));
            }
        }
        // The advanced-only units must be ABSENT.
        for name in advanced_only_units {
            let link = user_unit_link_for(&config_home, name);
            let outcome = remote.exec(
                &[
                    "test".into(),
                    "!".into(),
                    "-e".into(),
                    link.to_string_lossy().into_owned(),
                ],
                Duration::from_secs(30),
            )?;
            if !outcome.success() {
                return Err(Error::remote(format!(
                    "verify restored: unit '{name}' is still installed (prior state: absent)"
                )));
            }
        }
    } else {
        let mut names: Vec<&str> = sa.units().map(|u| u.name()).collect();
        for n in advanced_only_units {
            names.push(n);
        }
        for name in names {
            let outcome = remote.exec(
                &["systemctl".into(), "is-active".into(), name.to_string()],
                Duration::from_secs(30),
            )?;
            if !outcome.success() {
                return Err(Error::remote(format!(
                    "verify restored: unit '{name}' is not active"
                )));
            }
        }
    }
    Ok(VerifiedAdapterRestoration::verified())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{ActivationScope, UnitDef, ValidatedSystemd};
    use crate::identity::{TreeDigest, test_deployment_id, test_generation_id, test_tree_digest};
    use crate::remote::transport::LocalTransport;
    use std::os::unix::fs::PermissionsExt;

    fn cfg(scope: ActivationScope, units: Vec<&str>) -> ValidatedSystemd {
        ValidatedSystemd::new(
            scope,
            true,
            units
                .into_iter()
                .map(|n| {
                    UnitDef::new(n.into(), format!("integration/systemd/{n}"), true, true)
                        .expect("validated unit")
                })
                .collect(),
        )
        .expect("validated systemd")
    }

    /// Full slot context including the per-server metadata (user, address,
    /// port), the slot ID, and the per-deployment identity, exactly as the
    /// engine's `slot_vars` fills it for the activation/verification path.
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
        .with_deployment(
            Some(&test_deployment_id("deploy-1")),
            Some(&test_generation_id("gen-1")),
            Some(&TreeDigest::new("abc123")),
        )
    }

    /// THE hermetic systemd test environment: fake `systemctl`/`loginctl` on
    /// PATH and a per-test temp `XDG_CONFIG_HOME` — the ONLY way a systemd
    /// adapter test obtains its env, so the unit link can never resolve to
    /// the real host's `$HOME/.config` (parallel tests would race each
    /// other's unit file: a concurrent restore's `rm` could remove another
    /// test's baseline-installed unit, flipping its prior capture to absent
    /// and letting the restore's rm branch succeed). Returns the env and the
    /// config home the adapter will resolve.
    fn systemd_test_env(tmp: &Path) -> (crate::env::SysEnv, PathBuf) {
        let bindir = tmp.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        for name in ["systemctl", "loginctl"] {
            let shim = bindir.join(name);
            std::fs::write(&shim, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let config_home = tmp.join("xdg");
        let base_env = crate::testutil::fixture_env();
        let mut vars: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
            base_env.child_env().into_iter().collect();
        vars.insert(
            "PATH".into(),
            format!(
                "{}:{}",
                bindir.display(),
                base_env
                    .path()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default()
            )
            .into(),
        );
        vars.insert("XDG_CONFIG_HOME".into(), config_home.as_os_str().to_owned());
        (crate::env::SysEnv::from_map(vars), config_home)
    }

    #[test]
    fn config_home_resolution() {
        // XDG wins.
        assert_eq!(
            resolve_config_home(Some("/x/.config"), Some("/h")),
            PathBuf::from("/x/.config")
        );
        // HOME falls back to $HOME/.config.
        assert_eq!(
            resolve_config_home(None, Some("/h")),
            PathBuf::from("/h/.config")
        );
        // Neither -> .config
        assert_eq!(resolve_config_home(None, None), PathBuf::from(".config"));
    }

    #[test]
    fn user_link_uses_config_base() {
        // Resolution lives under <config_base>/systemd/user/<unit>.
        let link = user_unit_link_for(Path::new("/home/deploy/.config"), "example.service");
        assert_eq!(
            link,
            PathBuf::from("/home/deploy/.config/systemd/user/example.service")
        );
        // XDG_CONFIG_HOME base is used verbatim (no extra .config appended).
        let link = user_unit_link_for(Path::new("/x/.config"), "example.service");
        assert_eq!(
            link,
            PathBuf::from("/x/.config/systemd/user/example.service")
        );
        // The public helper resolves the environment-derived base.
        let link = user_unit_link_for(Path::new("/srv/x/.config"), "example.service");
        assert!(link.ends_with("systemd/user/example.service"));
    }

    #[test]
    fn user_commands_install_rendered_unit_before_reload() {
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let cmds =
            activation_commands(Path::new("/srv/eng"), Path::new("/home/deploy/.config"), &c);
        // Linger is enabled FIRST (user scope), then mkdir + cp + chmod
        // (install), then daemon-reload after the copy.
        assert_eq!(cmds[0], vec!["loginctl", "enable-linger"]);
        assert_eq!(cmds[1][0], "mkdir");
        assert_eq!(cmds[2][0], "cp");
        assert_eq!(
            cmds[2][1], "/srv/eng/adapters/systemd/example.service",
            "cp source is the staged rendered unit under the remote root"
        );
        assert_eq!(
            cmds[2][2], "/home/deploy/.config/systemd/user/example.service",
            "cp destination is the user systemd dir"
        );
        assert_eq!(cmds[3][0], "chmod");
        assert_eq!(cmds[3][1], "0644");
        let reload_idx = cmds
            .iter()
            .position(|c| {
                c.len() >= 3 && c[0] == "systemctl" && c[1] == "--user" && c[2] == "daemon-reload"
            })
            .unwrap();
        let cp_idx = cmds.iter().position(|c| c[0] == "cp").unwrap();
        assert!(
            cp_idx < reload_idx,
            "installed unit must precede daemon-reload"
        );
        // enable + restart present with --user.
        assert!(cmds.iter().any(|c| c.contains(&"enable".to_string())));
        assert!(cmds.iter().any(|c| c.contains(&"restart".to_string())));
        assert!(
            cmds.iter().all(
                |c| !(c[0] == "systemctl" && c[1] == "--user" && c[2] == "restart") || c.len() == 4
            )
        );
    }

    #[test]
    fn system_scope_does_not_enable_linger() {
        let c = cfg(ActivationScope::System, vec!["wrapper.service"]);
        let cmds = activation_commands(Path::new("/srv/x"), Path::new("/home/deploy/.config"), &c);
        // Linger is a user-scope concern: system services persist without it.
        assert!(!cmds.iter().any(|c| c[0] == "loginctl"));
    }

    #[test]
    fn system_scope_does_not_install_user_units() {
        let c = cfg(ActivationScope::System, vec!["wrapper.service"]);
        let cmds = activation_commands(Path::new("/srv/x"), Path::new("/home/deploy/.config"), &c);
        // No mkdir/cp/chmod for artifact units in system scope.
        assert!(!cmds.iter().any(|c| c[0] == "mkdir"));
        assert!(!cmds.iter().any(|c| c[0] == "cp"));
        assert!(!cmds.iter().any(|c| c[0] == "chmod"));
        // Only a narrow restart of the wrapper (no --user).
        assert!(
            cmds.iter()
                .any(|c| c == &vec!["systemctl", "restart", "wrapper.service"])
        );
    }

    /// A unit file containing `{{ deploy_dir }}`, `{{ user }}`, `{{ address }}`,
    /// `{{ port }}`, and `{{ deployment_id }}` (plus other elected variables)
    /// renders with the slot's context when staged, and the staged REGULAR
    /// FILE is what the install commands copy into the user systemd dir. The
    /// per-server `user`/`address`/`port` values come from the matching
    /// `[[servers]]` entry; `deployment_id` from the push being activated.
    #[test]
    fn rendered_unit_uses_slot_deploy_dir_and_server_metadata() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = tmp.path().join("remote");
        let (env, _config_home) = systemd_test_env(tmp.path());
        let remote = LocalTransport::new(&env, base.clone()).unwrap();
        // Tree content under the object store, like `tree::canonicalize_tree`.
        let tree_rel = crate::remote::layout::tree_root(&test_tree_digest("abc123"));
        let unit_rel = tree_rel
            .join("integration/systemd/example.service")
            .unwrap();
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(
            base.join(&unit_rel),
            "[Service]\n# deployed by {{ user }} on {{ address }}:{{ port }} (deployment {{ deployment_id }})\nExecStart={{ deploy_dir }}/current/app/server\nArg={{ variant }} {{ application }} {{ target }}/{{ server }}\n",
        )
        .unwrap();
        // `generations/<gid>/root` -> the tree content root (symlink), as the
        // helper creates it.
        let gen_rel = crate::remote::layout::generation(&test_generation_id("g1"));
        let gen_dir = base.join(&gen_rel);
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink(
            crate::remote::layout::generation_root_link(&test_tree_digest("abc123")),
            gen_dir.join("root"),
        )
        .unwrap();

        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let generation_root = base.join(gen_rel).join("root");
        stage_rendered_units(&remote, &generation_root, &c, &slot_vars()).unwrap();

        // The staged copy is a regular file with the rendered content.
        let staged = remote
            .read(
                &RootedRelativePath::parse(Path::new("adapters/systemd/example.service")).unwrap(),
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(staged).unwrap(),
            format!(
                "[Service]\n# deployed by deploy on 10.0.0.5:22 (deployment {})\nExecStart=/srv/deploy/example/current/app/server\nArg=standard example production/server-01\n",
                test_deployment_id("deploy-1")
            )
        );
        // The install commands install the staged file into the user dir.
        let cmds = activation_commands(&base, Path::new("/home/deploy/.config"), &c);
        let cp = cmds.iter().find(|c| c[0] == "cp").unwrap();
        assert_eq!(
            cp[1],
            base.join("adapters/systemd/example.service")
                .to_string_lossy()
        );
        assert_eq!(cp[2], "/home/deploy/.config/systemd/user/example.service");
    }

    /// Regression: the activation generation root must be
    /// `<remote_root>/generations/<gid>/root` — the `root` symlink to the tree
    /// content root — never `<remote_root>/generations/<gid>/root/root`.
    /// `push/engine.rs` builds this path at both `run_activation` call sites;
    /// staging derives the unit read source from it, so a `root/root`
    /// double-join would try to read through a nonexistent nested `root`
    /// directory inside the tree content root and fail loudly. This test pins
    /// the shape and proves staging reads the unit from the canonical root.
    #[test]
    fn activation_generation_root_is_single_root_not_nested() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = tmp.path().join("remote");
        let (env, _config_home) = systemd_test_env(tmp.path());
        let remote = LocalTransport::new(&env, base.clone()).unwrap();
        // Unit artifact under the tree content root.
        let tree_rel = crate::remote::layout::tree_root(&test_tree_digest("abc123"));
        let unit_rel = tree_rel
            .join("integration/systemd/example.service")
            .unwrap();
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(
            base.join(&unit_rel),
            "[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
        )
        .unwrap();
        // `generations/<gid>/root` -> the tree content root (symlink), exactly
        // as `RemoteHelper::create_generation` installs it.
        let gen_dir = base.join(crate::remote::layout::generation(&test_generation_id("g1")));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink(
            crate::remote::layout::generation_root_link(&test_tree_digest("abc123")),
            gen_dir.join("root"),
        )
        .unwrap();

        // Build the generation root exactly as the engine does at both
        // `run_activation` call sites: `<root>/generations/<gid>/root`.
        let gid = test_generation_id("g1");
        let generation_root = remote
            .root()
            .join(crate::remote::layout::generation(&gid))
            .join("root");
        assert!(
            generation_root.ends_with(Path::new(&format!("generations/{}/root", gid.as_str()))),
            "activation generation root must be <root>/generations/<gid>/root, got {}",
            generation_root.display()
        );
        assert!(
            !generation_root.to_string_lossy().contains("root/root"),
            "activation generation root must never be a nested root/root, got {}",
            generation_root.display()
        );

        // Staging reads the unit from `generations/<gid>/root/<artifact>`:
        // assert the exact relative read source `stage_rendered_units` derives
        // from the generation root.
        let gen_rel = generation_root.strip_prefix(remote.root()).unwrap();
        let read_src = gen_rel.join("integration/systemd/example.service");
        assert_eq!(
            read_src,
            Path::new(&format!(
                "generations/{}/root/integration/systemd/example.service",
                gid.as_str()
            ))
        );
        assert!(
            !read_src.to_string_lossy().contains("root/root"),
            "unit read source must not be a nested root/root path"
        );
        // The double-joined variant resolves to nothing on this layout (the
        // tree content root has no nested `root` directory), so a `root/root`
        // generation root would fail activation with a read error.
        assert!(
            !base
                .join(format!("generations/{}/root/root", gid.as_str()))
                .exists(),
            "tree content root must have no nested root dir (a root/root double-join would ENOENT)"
        );

        // End-to-end: staging must read the content through the canonical
        // `generations/<gid>/root` symlink (only that path reaches the unit).
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        stage_rendered_units(&remote, &generation_root, &c, &slot_vars()).unwrap();
        let staged = remote
            .read(
                &RootedRelativePath::parse(Path::new("adapters/systemd/example.service")).unwrap(),
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(staged).unwrap(),
            "[Service]\nExecStart=/srv/deploy/example/current/app/server\n"
        );
    }

    /// An unknown or malformed variable in a unit file fails activation
    /// loudly: nothing is staged and nothing is installed.
    #[test]
    fn unit_template_error_fails_loudly() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = tmp.path().join("remote");
        let (env, _config_home) = systemd_test_env(tmp.path());
        let remote = LocalTransport::new(&env, base.clone()).unwrap();
        let gen_rel = crate::remote::layout::generation(&test_generation_id("g1"));
        let unit_rel = gen_rel
            .join("root/integration/systemd/example.service")
            .unwrap();
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(base.join(&unit_rel), "ExecStart={{ bogus }}\n").unwrap();

        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let generation_root = base.join(gen_rel).join("root");
        let err = stage_rendered_units(&remote, &generation_root, &c, &slot_vars()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown template variable 'bogus'")
        );
        assert!(
            !base.join("adapters/systemd/example.service").exists(),
            "nothing staged on a template error"
        );
    }

    /// End-to-end activation on a local transport: the adapter stages the
    /// rendered unit, resolves the config home on the "remote" host (the
    /// local host, via `sh`), and EXECUTES the mkdir/cp/chmod/systemctl
    /// commands. A fake `systemctl` shim in PATH and a temp `XDG_CONFIG_HOME`
    /// keep the test hermetic; the assertion is that the INSTALLED file in the
    /// user systemd dir is a regular file containing the slot-rendered unit.
    #[test]
    fn run_activation_installs_rendered_unit_end_to_end() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = tmp.path().join("remote");
        let (env, config_home) = systemd_test_env(tmp.path());
        let remote = LocalTransport::new(&env, base.clone()).unwrap();
        // Unit artifact with a slot-dependent ExecStart and the per-server
        // deployment account, under the tree.
        let tree_rel = crate::remote::layout::tree_root(&test_tree_digest("abc123"));
        let unit_rel = tree_rel
            .join("integration/systemd/example.service")
            .unwrap();
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(
            base.join(&unit_rel),
            "[Unit]\nDescription=Example service (managed by deploy, run as {{ user }})\n\n[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
        )
        .unwrap();
        let gen_dir = base.join(crate::remote::layout::generation(&test_generation_id("g1")));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink(
            crate::remote::layout::generation_root_link(&test_tree_digest("abc123")),
            gen_dir.join("root"),
        )
        .unwrap();

        // Regression pin: the activation generation root must be
        // `<remote>/generations/<gid>/root` (the symlink to the tree content
        // root), never a nested `root/root`. A double-join would make staging
        // read through a nonexistent `root` directory inside the tree content
        // root and fail below.
        let gid = test_generation_id("g1");
        let generation_root = base
            .join(crate::remote::layout::generation(&gid))
            .join("root");
        assert!(
            generation_root.ends_with(Path::new(&format!("generations/{}/root", gid.as_str()))),
            "activation root must be <root>/generations/<gid>/root, got {}",
            generation_root.display()
        );
        assert!(
            !generation_root.to_string_lossy().contains("root/root"),
            "activation root must not be a nested root/root, got {}",
            generation_root.display()
        );
        assert!(
            !base
                .join(format!("generations/{}/root/root", gid.as_str()))
                .exists(),
            "tree content root has no nested root dir: a root/root double-join would ENOENT"
        );

        let result = {
            let c = cfg(ActivationScope::User, vec!["example.service"]);
            run_activation(
                &remote,
                &generation_root,
                &Activation::Systemd(c.clone()),
                &slot_vars(),
            )
        };
        result.unwrap();

        // The installed unit is a REGULAR FILE with the slot-rendered content
        // (never a symlink into the generation tree).
        let installed = config_home.join("systemd/user/example.service");
        let meta = std::fs::symlink_metadata(&installed).unwrap();
        assert!(meta.is_file(), "installed unit must be a regular file");
        assert_eq!(
            std::fs::read_to_string(&installed).unwrap(),
            "[Unit]\nDescription=Example service (managed by deploy, run as deploy)\n\n[Service]\nExecStart=/srv/deploy/example/current/app/server\n"
        );
        // Adapter state recorded on the remote root.
        assert!(base.join("adapters/systemd.json").is_file());
    }

    /// A hermetic systemd activation context: a local transport with a fake
    /// `systemctl` on PATH (every command succeeds), a temp `XDG_CONFIG_HOME`
    /// (the installed unit lands there), and a generation tree holding the
    /// unit artifact (rendered with the slot context).
    fn hermetic_ctx() -> (
        tempfile::TempDir,
        crate::env::SysEnv,
        LocalTransport,
        PathBuf,
        PathBuf,
    ) {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = tmp.path().join("remote");
        let (env, config_home) = systemd_test_env(tmp.path());
        let remote = LocalTransport::new(&env, base.clone()).unwrap();
        // The unit artifact under the tree content root + the generation
        // symlink, exactly as the engine builds it.
        let tree_rel = crate::remote::layout::tree_root(&test_tree_digest("abc123"));
        let unit_rel = tree_rel
            .join("integration/systemd/example.service")
            .unwrap();
        std::fs::create_dir_all(base.join(unit_rel.parent().unwrap())).unwrap();
        std::fs::write(
            base.join(&unit_rel),
            "[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
        )
        .unwrap();
        let gen_dir = base.join(crate::remote::layout::generation(&test_generation_id("g1")));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink(
            crate::remote::layout::generation_root_link(&test_tree_digest("abc123")),
            gen_dir.join("root"),
        )
        .unwrap();
        let generation_root = base
            .join(crate::remote::layout::generation(&test_generation_id("g1")))
            .join("root");
        (tmp, env, remote, config_home, generation_root)
    }

    /// THE TRANSACTION ROUND TRIP (the review's P1 fix): prepare captures
    /// the PRIOR state, apply installs the rendered unit, restore reverses
    /// the apply back to the captured prior, and verify_restored RE-READS
    /// the remote and confirms the restoration — producing the sealed
    /// [`VerifiedAdapterRestoration`] proof. First a PRIOR-GENERATION-style
    /// prior (a unit already installed), then a first-deploy-style prior
    /// (absent).
    #[test]
    fn transaction_round_trips_apply_restore_and_verify_restored_reads_back() {
        let (_tmp, _env, remote, config_home, generation_root) = hermetic_ctx();
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let vars = slot_vars();

        // A PRIOR unit already installed (as a prior deploy would leave it):
        // prepare must capture it, apply must overwrite it, restore must put
        // it back, verify_restored must read it back.
        let link = config_home.join("systemd/user/example.service");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let prior_content = "[Service]\nExecStart=/srv/eng/current/app/server-v1\n";
        std::fs::write(&link, prior_content).unwrap();

        let activation = Activation::Systemd(c.clone());
        let mut txn = SystemdActivation::new(&remote, &generation_root, &activation, &vars)
            .expect("a systemd activation builds a transaction");
        let prepared = txn.prepare().unwrap();
        assert_eq!(prepared.prior.len(), 1);
        assert_eq!(
            prepared.prior[0]
                .content
                .as_deref()
                .map(String::from_utf8_lossy),
            Some(std::borrow::Cow::Borrowed(prior_content)),
            "prepare captures the prior installed content"
        );
        let applied = txn.apply(&prepared).unwrap();
        let installed = std::fs::read_to_string(&link).unwrap();
        assert_ne!(
            installed, prior_content,
            "apply installs the rendered (new) unit over the prior one"
        );
        assert!(
            installed.contains("ExecStart=/srv/deploy/example/current/app/server"),
            "the applied unit renders the slot context, got: {installed}"
        );
        let restored = txn.restore(&applied).unwrap();
        assert_eq!(
            std::fs::read_to_string(&link).unwrap(),
            prior_content,
            "restore writes the captured PRIOR content back over the unit link"
        );
        // THE READ-BACK: verify_restored must READ the remote and confirm.
        let proof = txn.verify_restored(&restored).unwrap();
        let _ = proof; // the sealed proof exists — that IS the assertion

        // FIRST-DEPLOY-style prior (absent): prepare captures absence, apply
        // installs the unit, restore REMOVES it, verify_restored confirms
        // the absence by reading.
        std::fs::remove_file(&link).unwrap();
        let activation2 = Activation::Systemd(c.clone());
        let mut txn2 = SystemdActivation::new(&remote, &generation_root, &activation2, &vars)
            .expect("a systemd activation builds a transaction");
        let prepared2 = txn2.prepare().unwrap();
        assert_eq!(
            prepared2.prior[0].content, None,
            "prepare captures the ABSENT prior unit"
        );
        let applied2 = txn2.apply(&prepared2).unwrap();
        assert!(link.exists(), "apply installs the unit");
        let restored2 = txn2.restore(&applied2).unwrap();
        assert!(
            !link.exists(),
            "restore REMOVES the installed unit (prior absent)"
        );
        txn2.verify_restored(&restored2)
            .expect("verify_restored confirms the absence by reading the remote");
    }

    /// THE MUTATION TEST (the review's acceptance: "verify_restored's read
    /// truly checks the remote — a verify_restored that always succeeds must
    /// be detectable"): after apply installed the NEW unit, verify_restored
    /// against the captured PRIOR (absent) MUST FAIL — the remote still
    /// carries the new side effect. A fabricated always-Ok verify_restored
    /// would pass this scenario; the real read-back refuses it.
    #[test]
    fn verify_restored_detects_a_still_installed_unit_when_prior_was_absent() {
        let (_tmp, _env, remote, config_home, generation_root) = hermetic_ctx();
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let vars = slot_vars();
        let activation = Activation::Systemd(c.clone());
        let mut txn = SystemdActivation::new(&remote, &generation_root, &activation, &vars)
            .expect("a systemd activation builds a transaction");
        let prepared = txn.prepare().unwrap();
        txn.apply(&prepared).unwrap();
        // The unit is INSTALLED (the new side effect) — the restore never
        // ran, so verify_restored must detect that the remote is NOT back at
        // the captured prior (absent).
        let link = config_home.join("systemd/user/example.service");
        assert!(link.exists(), "apply installed the unit");
        // Build the restored state from the CAPTURED prior WITHOUT restoring
        // (simulating a skipped/failed restore): the read-back must catch it.
        let restored = SystemdRestored {
            expected: prepared.prior.clone(),
        };
        let err = txn.verify_restored(&restored).unwrap_err();
        assert!(
            err.to_string().contains("still installed"),
            "verify_restored must READ the remote and detect the unit left in the new state, got: {err}"
        );
    }

    /// THE MUTATION TEST, prior-content variant: a restore that did NOT
    /// take effect (the installed file still carries the NEW content) must
    /// be caught by verify_restored's content read-back.
    #[test]
    fn verify_restored_detects_a_content_divergence_after_a_failed_restore() {
        let (_tmp, _env, remote, config_home, generation_root) = hermetic_ctx();
        let c = cfg(ActivationScope::User, vec!["example.service"]);
        let vars = slot_vars();
        let link = config_home.join("systemd/user/example.service");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let prior_content = "[Service]\nExecStart=/srv/eng/current/app/server-v1\n";
        std::fs::write(&link, prior_content).unwrap();
        let activation = Activation::Systemd(c.clone());
        let mut txn = SystemdActivation::new(&remote, &generation_root, &activation, &vars)
            .expect("a systemd activation builds a transaction");
        let prepared = txn.prepare().unwrap();
        txn.apply(&prepared).unwrap();
        // The unit is now in the NEW (rendered) state — a restore that did
        // NOT take effect would leave it here. verify_restored against the
        // captured PRIOR content must detect the divergence (a fabricated
        // always-Ok verify would pass).
        let installed = std::fs::read_to_string(&link).unwrap();
        assert_ne!(installed, prior_content, "apply installed the new content");
        let restored = SystemdRestored {
            expected: prepared.prior.clone(),
        };
        let err = txn.verify_restored(&restored).unwrap_err();
        assert!(
            err.to_string().contains("not back at its prior content"),
            "verify_restored must read the bytes and detect the divergence, got: {err}"
        );
    }
}

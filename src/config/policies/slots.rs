//! Deployment slots ([`SlotConfig`]): one server + one workload under an id,
//! with an absolute deploy_dir, bound to exactly one owning target.

use crate::error::Result;
use crate::identity::AbsoluteDeployDir;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A deployment slot: binds one server to one workload under an ID, with an
/// absolute `deploy_dir` on the server, and belongs to EXACTLY ONE owning
/// target. The connection details live on the top-level `[[servers]]`
/// entry; the workload choice, its on-server location, its owning target,
/// and its rollout groups live here. Slots are declared INSIDE the variant
/// file that owns the workload: the `[[slots]]` entries of
/// `<release>/<variant>.toml` are the slot declarations, the declaring
/// variant file IS the slot's variant binding (there is no `variant` field
/// — it is the enclosing file), and the slot's `target` field is what binds
/// it to its ONE top-level target. A target's members are DERIVED by
/// scanning every variant's slots for its name.
///
/// This is both the raw serialization shape of a slot and the domain record:
/// its validity (id non-empty/unique, references resolvable, groups clean,
/// location unique) is enforced by the raw -> domain conversion; a slot can
/// never enter a [`crate::config::ProjectConfig`] graph except through that conversion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlotConfig {
    pub id: String,
    /// The ID of the top-level server this slot deploys onto.
    pub server: String,
    /// Absolute directory on the server where this slot's deployment state
    /// (objects, releases, generations, `current`) lives. INVARIANT-BEARING
    /// (must be an absolute path on the server) — private, read through
    /// [`SlotConfig::deploy_dir`]; the absoluteness rule is enforced by the
    /// raw -> domain conversion and re-checked by every validated rebuild
    /// operation, so an invalid deploy_dir can never enter a validated
    /// [`ProjectConfig`].
    deploy_dir: PathBuf,
    /// The slot's EXACTLY ONE owning target: a physical slot has one owner
    /// that governs its history, checkpoints, observed state, rollout
    /// policy, and retention policy. Required and must reference an existing
    /// top-level `[targets.<name>]` key. TOML form: `target = "production"`.
    pub target: String,
    /// The rollout groups this slot belongs to, scoped to its owning target:
    /// groups only SELECT a subset of the target's slots (`deploy push
    /// <target> --group <name>`); they never own state, policy, history, or
    /// checkpoints. Defaults to empty (a slot in no group is selected only by
    /// an omitting `--group` push). A name must not appear twice (a
    /// duplicate adds no membership yet would change the release identity,
    /// so it is rejected at validation). TOML form: `groups = ["canary",
    /// "wave-1"]`.
    #[serde(default)]
    pub groups: Vec<String>,
}
impl SlotConfig {
    /// Build a slot from its raw parts. The graph-level rules (identifier
    /// validity, reference resolution, deploy_dir absoluteness, location
    /// uniqueness) are enforced when the slot enters a [`crate::config::ProjectConfig`]: the
    /// raw -> domain conversion and every validated rebuild operation
    /// re-validate the whole graph, so an invalid slot can never enter a
    /// validated config.
    pub fn new(
        id: impl Into<String>,
        server: impl Into<String>,
        deploy_dir: impl Into<PathBuf>,
        target: impl Into<String>,
        groups: Vec<String>,
    ) -> SlotConfig {
        SlotConfig {
            id: id.into(),
            server: server.into(),
            deploy_dir: deploy_dir.into(),
            target: target.into(),
            groups,
        }
    }

    /// The absolute on-server directory this slot's deployment state lives
    /// in (read-only).
    pub fn deploy_dir(&self) -> &Path {
        &self.deploy_dir
    }

    /// The slot with its deploy_dir stored in the validated CANONICAL form:
    /// the current deploy_dir is parsed through the [`crate::identity::AbsoluteDeployDir`]
    /// scalar (absolute, TRAVERSAL-FREE, normalized — no `.`/`..` at any
    /// position, the filesystem root refused) and a CLONE carrying the
    /// canonical path is returned. Fails exactly when the deploy_dir is not a
    /// valid absolute, traversal-free path. The raw -> domain conversion
    /// stores this canonical form, so the validated graph carries THE ONE
    /// authoritative effective root each slot operates on: every consumer
    /// (`SlotConfig::deploy_dir`, the recorded `PhysicalBinding.deploy_dir`,
    /// the transport root built by `create_remote`) sees the same normalized
    /// value — the location-uniqueness rule then compares effective roots,
    /// not merely the raw spellings.
    pub(crate) fn with_canonical_deploy_dir(&self) -> Result<SlotConfig> {
        let canonical = AbsoluteDeployDir::parse(&self.deploy_dir.to_string_lossy())?;
        let mut slot = self.clone();
        slot.deploy_dir = canonical.as_path().to_path_buf();
        Ok(slot)
    }

    /// Set the deploy_dir (test-only: the field is private; the
    /// absoluteness rule is re-checked by the raw -> domain conversion and
    /// every validated rebuild operation when the slot enters a
    /// [`crate::config::ProjectConfig`]).
    #[cfg(test)]
    pub(crate) fn set_deploy_dir(&mut self, deploy_dir: PathBuf) {
        self.deploy_dir = deploy_dir;
    }
}

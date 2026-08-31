//! THE VALIDATED PROJECT — the ONE authoritative, typed, canonical,
//! DISJOINT provisioned topology (the structural verdict's point 1). A
//! [`ValidatedProject`] owns EXACTLY ONE map of [`ProvisionedSlot`]s — each
//! `{id: SlotId, owner: TargetName, variant: VariantName, receiver:
//! ReceiverUuid, root: OwnedRoot, groups: GroupSet}` — with NO optional
//! receiver, NO raw path, and NO duplicate topology maps. The config's
//! slot/target/variant views and the [`PhysicalBinding`] receiver are
//! SUBSUMED: the receiver becomes MANDATORY in the provisioned topology (a
//! slot whose deploy_dir carries no receiver UUID is REFUSED at
//! construction — fail closed), and every topology leaf is consumed TYPED
//! from this value, never re-parsed from the config.
//!
//! The construction ([`ValidatedProject::new`]) takes the config (the
//! slot/target/variant declarations), the PROVISIONED receivers (read from
//! the remotes after provisioning), and the store's SEALED [`OwnedRoot`]
//! (the filesystem-ownership root every provisioned slot is bound to). It
//! validates:
//!
//! * **Disjointness** — the topology is a `BTreeMap<SlotId, ProvisionedSlot>`
//!   keyed by the canonical slot id: a duplicate slot id is unrepresentable
//!   (no duplicate topology maps);
//! * **Mandatory receiver** — every slot's deploy_dir must carry its
//!   IMMUTABLE receiver UUID (a slot without one is refused — fail closed);
//! * **Typed leaves** — every id/name is a validated identity ([`SlotId`],
//!   [`TargetName`], [`VariantName`], [`ReceiverUuid`]), the groups are a
//!   validated [`GroupSet`], and the root is the sealed [`OwnedRoot`] — no
//!   raw path, no loose strings;
//! * **Coherence** — every slot's owning target exists in the config, and
//!   every slot's variant is the variant that declares it.

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::identity::{ReceiverUuid, RolloutGroupName, SlotId, TargetName, VariantName};
use crate::store::local::OwnedRoot;
use std::collections::{BTreeMap, BTreeSet};

/// THE TYPED GROUP SET of one provisioned slot: the validated rollout
/// groups the slot belongs to (scoped to its owning target). A newtype over
/// a set of validated [`RolloutGroupName`]s — the ONLY construction path
/// ([`GroupSet::try_new`]) validates every name, so a loose group string
/// can never enter the provisioned topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSet(BTreeSet<RolloutGroupName>);

impl GroupSet {
    /// Validate every group name and build the set. A name that is not a
    /// valid [`RolloutGroupName`] (a safe single path segment) is refused.
    pub fn try_new<I>(groups: I) -> Result<GroupSet>
    where
        I: IntoIterator<Item = String>,
    {
        let mut set = BTreeSet::new();
        for g in groups {
            set.insert(RolloutGroupName::parse(&g).map_err(|e| {
                Error::config(format!("invalid rollout group name {g:?}: {e}"))
            })?);
        }
        Ok(GroupSet(set))
    }

    /// Whether the set contains the given group name.
    pub fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|g| g.as_str() == name)
    }

    /// The group names, in deterministic order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|g| g.as_str())
    }

    /// Whether the set is empty (a slot in no group is selected only by an
    /// omitting `--group` push).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// ONE PROVISIONED SLOT of the validated project: the typed, canonical,
/// disjoint topology entry — `{id, owner, variant, receiver, root, groups}`.
/// The fields are PRIVATE and the ONLY construction path is
/// [`ValidatedProject::new`] (which validates every relationship), so a
/// provisioned slot whose parts could disagree with the config or the
/// provisioned remotes is unrepresentable. There is NO optional receiver
/// and NO raw path: the receiver is the deploy_dir's IMMUTABLE physical
/// identity (mandatory), and the root is the sealed [`OwnedRoot`].
#[derive(Clone, Debug)]
pub struct ProvisionedSlot {
    /// The canonical placement-slot id.
    id: SlotId,
    /// The slot's EXACTLY ONE owning target.
    owner: TargetName,
    /// The variant whose file declares the slot.
    variant: VariantName,
    /// The deploy_dir's IMMUTABLE receiver UUID — the PHYSICAL identity of
    /// the provisioned deployment location (MANDATORY in the provisioned
    /// topology).
    receiver: ReceiverUuid,
    /// The SEALED filesystem-ownership root the slot is bound to (the
    /// project's store root — a refcounted clone sharing the project's ONE
    /// registration).
    root: OwnedRoot,
    /// The validated rollout groups the slot belongs to.
    groups: GroupSet,
}

impl ProvisionedSlot {
    /// The canonical placement-slot id.
    pub fn id(&self) -> &SlotId {
        &self.id
    }
    /// The slot's EXACTLY ONE owning target.
    pub fn owner(&self) -> &TargetName {
        &self.owner
    }
    /// The variant whose file declares the slot.
    pub fn variant(&self) -> &VariantName {
        &self.variant
    }
    /// The deploy_dir's IMMUTABLE receiver UUID (the PHYSICAL identity).
    pub fn receiver(&self) -> &ReceiverUuid {
        &self.receiver
    }
    /// The SEALED filesystem-ownership root the slot is bound to.
    pub fn root(&self) -> &OwnedRoot {
        &self.root
    }
    /// The validated rollout groups the slot belongs to.
    pub fn groups(&self) -> &GroupSet {
        &self.groups
    }
}

/// THE VALIDATED PROJECT: the ONE authoritative, typed, canonical, DISJOINT
/// provisioned topology. Owns EXACTLY ONE map of [`ProvisionedSlot`]s
/// (keyed by the canonical slot id — a duplicate topology map is
/// unrepresentable) plus the ONE sealed [`OwnedRoot`] every slot is bound
/// to. The fields are PRIVATE and the ONLY construction path is
/// [`ValidatedProject::new`], which validates disjointness, the mandatory
/// receivers, the typed leaves, and the config coherence — so a validated
/// project whose topology could disagree with the config or the provisioned
/// remotes is unrepresentable.
#[derive(Clone, Debug)]
pub struct ValidatedProject {
    /// THE ONE sealed filesystem-ownership root every provisioned slot is
    /// bound to (the project's store root).
    root: OwnedRoot,
    /// THE DISJOINT provisioned topology: one entry per slot, keyed by the
    /// canonical slot id.
    slots: BTreeMap<SlotId, ProvisionedSlot>,
}

impl ValidatedProject {
    /// THE ONLY CONSTRUCTION PATH: the config (the slot/target/variant
    /// declarations), the PROVISIONED receivers (read from the remotes
    /// after provisioning — MANDATORY: a slot whose deploy_dir carries no
    /// receiver UUID is REFUSED, fail closed), and the store's SEALED
    /// [`OwnedRoot`]. Validates:
    ///
    /// * every config slot is present in the topology exactly once (the
    ///   `BTreeMap<SlotId, _>` key makes duplicates unrepresentable);
    /// * every slot's receiver is present (mandatory — no optional
    ///   receiver);
    /// * every slot's owning target exists in the config;
    /// * every slot's variant is the variant that declares it;
    /// * every group name is a validated [`RolloutGroupName`].
    pub fn new(
        config: &ProjectConfig,
        receivers: &BTreeMap<SlotId, ReceiverUuid>,
        root: OwnedRoot,
    ) -> Result<ValidatedProject> {
        let mut slots: BTreeMap<SlotId, ProvisionedSlot> = BTreeMap::new();
        for slot in config.slot_defs() {
            let id = SlotId::parse(slot.id.as_str())
                .map_err(|e| Error::config(format!("invalid slot id {:?}: {e}", slot.id)))?;
            // The receiver is MANDATORY in the provisioned topology: a slot
            // whose deploy_dir carries no receiver UUID is refused (fail
            // closed — the physical identity is never unknown).
            let receiver = receivers.get(&id).cloned().ok_or_else(|| {
                Error::config(format!(
                    "slot '{}' has no provisioned receiver UUID — the deploy_dir was never provisioned (or was provisioned before the receiver-UUID feature); refusing to build the provisioned topology",
                    slot.id
                ))
            })?;
            let owner = TargetName::parse(slot.target.as_str()).map_err(|e| {
                Error::config(format!("invalid target name {:?}: {e}", slot.target))
            })?;
            if config.target(slot.target.as_str()).is_none() {
                return Err(Error::config(format!(
                    "slot '{}' owns target '{}' which is not declared in the config",
                    slot.id, slot.target
                )));
            }
            let variant_name = config.slot_variant(slot.id.as_str())?;
            let variant = VariantName::parse(variant_name)
                .map_err(|e| Error::config(format!("invalid variant name {variant_name:?}: {e}")))?;
            let groups = GroupSet::try_new(slot.groups.clone())?;
            slots.insert(
                id.clone(),
                ProvisionedSlot {
                    id,
                    owner,
                    variant,
                    receiver,
                    root: root.clone(),
                    groups,
                },
            );
        }
        Ok(ValidatedProject { root, slots })
    }

    /// THE ONE sealed filesystem-ownership root every provisioned slot is
    /// bound to.
    pub fn root(&self) -> &OwnedRoot {
        &self.root
    }

    /// THE DISJOINT provisioned topology: one entry per slot, keyed by the
    /// canonical slot id.
    pub fn slots(&self) -> &BTreeMap<SlotId, ProvisionedSlot> {
        &self.slots
    }

    /// The provisioned slot with the given id (`None` for an unknown slot).
    pub fn slot(&self, id: &SlotId) -> Option<&ProvisionedSlot> {
        self.slots.get(id)
    }

    /// The provisioned slots owned by the given target, in deterministic
    /// (slot-id) order.
    pub fn target_slots(&self, target: &TargetName) -> Vec<&ProvisionedSlot> {
        self.slots
            .values()
            .filter(|s| s.owner == *target)
            .collect()
    }

    /// The provisioned slots of the given target in the given rollout
    /// group, in deterministic (slot-id) order.
    pub fn group_slots(&self, target: &TargetName, group: &str) -> Vec<&ProvisionedSlot> {
        self.slots
            .values()
            .filter(|s| s.owner == *target && s.groups.contains(group))
            .collect()
    }

    /// The provisioned slot's receiver UUID — the deploy_dir's IMMUTABLE
    /// physical identity (MANDATORY: every provisioned slot carries one).
    pub fn receiver(&self, id: &SlotId) -> Option<&ReceiverUuid> {
        self.slots.get(id).map(|s| &s.receiver)
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;
    use crate::config::ProjectConfig;
    use crate::store::local::LocalStore;

    const DEPLOY_TOML: &str = r#"
schema_version = 2
application = "proj"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    const VARIANT_TOML: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = ["canary"]
deploy_dir = "/srv/proj"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    fn project() -> (tempfile::TempDir, ProjectConfig, LocalStore) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, DEPLOY_TOML).unwrap();
        let config = ProjectConfig::load(&p).unwrap();
        // A PRODUCTION store (owns its sealed root — the provisioned
        // topology binds every slot to it).
        let env = crate::env::SysEnv::from_map(std::collections::BTreeMap::from([(
            std::ffi::OsString::from("XDG_DATA_HOME"),
            dir.path().join("store-root").into_os_string(),
        )]));
        let store = LocalStore::new_in(&env, &crate::identity::ApplicationStoreKey::parse("proj").unwrap())
            .expect("the production store owns its root");
        (dir, config, store)
    }

    /// The provisioned topology is typed, canonical, and disjoint: every
    /// config slot appears exactly once with its typed leaves (id, owner,
    /// variant, receiver, groups), and the receiver is MANDATORY.
    #[test]
    fn provisioned_topology_is_typed_canonical_and_disjoint() {
        let (_dir, config, store) = project();
        let root = store.owned_root().expect("the store owns its root").clone();
        let p1 = SlotId::parse("p1").unwrap();
        let recv = ReceiverUuid::generate();
        let receivers = BTreeMap::from([(p1.clone(), recv.clone())]);
        let vp = ValidatedProject::new(&config, &receivers, root.clone()).unwrap();
        assert_eq!(vp.slots().len(), 1, "exactly one provisioned slot");
        let slot = vp.slot(&p1).expect("p1 is provisioned");
        assert_eq!(slot.id(), &p1);
        assert_eq!(slot.owner().as_str(), "t1");
        assert_eq!(slot.variant().as_str(), "standard");
        assert_eq!(slot.receiver(), &recv, "the receiver is the provisioned one");
        assert!(slot.groups().contains("canary"));
        assert_eq!(slot.root().canonical(), root.canonical());
        // The typed views resolve from the ONE topology.
        let t1 = TargetName::parse("t1").unwrap();
        assert_eq!(vp.target_slots(&t1).len(), 1);
        assert_eq!(vp.group_slots(&t1, "canary").len(), 1);
        assert_eq!(vp.group_slots(&t1, "unknown").len(), 0);
        assert_eq!(vp.receiver(&p1), Some(&recv));
    }

    /// A slot WITHOUT a provisioned receiver is REFUSED (fail closed — the
    /// receiver is MANDATORY in the provisioned topology).
    #[test]
    fn missing_receiver_is_refused() {
        let (_dir, config, store) = project();
        let root = store.owned_root().expect("the store owns its root").clone();
        let err = ValidatedProject::new(&config, &BTreeMap::new(), root)
            .expect_err("a slot without a receiver must be refused");
        assert!(
            err.to_string().contains("no provisioned receiver"),
            "the refusal must name the missing receiver, got: {err}"
        );
    }

    /// An invalid group name is refused at construction (the groups are a
    /// validated [`GroupSet`]).
    #[test]
    fn invalid_group_name_is_refused() {
        let err = GroupSet::try_new(vec!["../escape".to_string()])
            .expect_err("a traversal group name must be refused");
        assert!(
            err.to_string().contains("invalid rollout group name"),
            "the refusal must name the group rule, got: {err}"
        );
    }
}

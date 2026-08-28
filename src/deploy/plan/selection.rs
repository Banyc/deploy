//! Slot selection: the {target, group} [`SlotSelection`] and the
//! proof-bearing [`ResolvedSelection`] the assignments are derived from.

use crate::config::ProjectConfig;
use crate::error::Error;
use crate::error::Result;
use crate::identity::DeploymentId;
use crate::identity::NonEmptySlotSet;
use crate::identity::ReleaseId;
use crate::identity::ReleaseRecord;
use crate::identity::SlotId;
use crate::identity::TargetName;

// Slot SELECTION semantics (A1 deployment semantics): the branch-agnostic
// {target, group} selection normalized once near command entry
// ([`SlotSelection`]) and the PROOF-BEARING per-reference resolution the
// planner produces ([`ResolvedSelection`] / [`ResolvedSelectionSource`]).
//
// [`SlotSelection`] deliberately carries ONLY the owning target and the
// optional rollout group — never slot IDs — so each reference branch
// resolves the selected slot IDs against ITS OWN declared temporal source
// ([`crate::deploy::plan::plan_assignments`]): HEAD and deployment
// references resolve from the CURRENT config's group declarations
// ([`SlotSelection::current_members`]), a `release:<id>` reference from the
// RELEASE's FROZEN per-slot groups rebound onto the current physical slots
// ([`SlotSelection::release_members`] — the frozen partition governs, so a
// group named only in the frozen topology still resolves).
//
// [`ResolvedSelection`] is the proof-bearing counterpart: the owning target,
// the DECLARED temporal source it resolved against, and the NON-EMPTY
// resolved slot-ID set. CONSTRUCTIBLE ONLY BY THE PLANNER — the fields are
// private and the sole constructor ([`ResolvedSelection::new`]) lives in
// this module, so every consumer reads the resolution by accessor and can
// never construct one itself (a compile-level confinement via visibility).
//
// Split from the old `push::plan` (the {target, group} selection and its
// frozen-vs-current resolution formerly lived in `deploy::groups`; the
// proof-bearing resolution and its planner-only constructor in
// `deploy::plan`).

/// The NORMALIZED selection of one push/status invocation: the owning target
/// and the optional rollout group. Normalized once near command entry as the
/// branch-agnostic {target, group} pair — the selection deliberately does
/// NOT resolve slot IDs from the caller's current configuration. Each
/// reference branch resolves the selected slot IDs against ITS OWN declared
/// temporal source ([`plan_assignments`]): HEAD and deployment references
/// from the CURRENT config's group declarations, `release:<id>` from the
/// release record's FROZEN per-slot groups (rebound onto the current
/// physical slots). Planning, execution, reporting, and persistence consume
/// this selection plus the per-branch resolution instead of independently
/// filtering slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotSelection {
    pub target: TargetName,
    /// The optional rollout group (`deploy push <target> --group <name>`).
    /// `None` selects every slot owned by the target.
    pub group: Option<String>,
}

impl SlotSelection {
    /// Normalize a target + optional group into the branch-agnostic
    /// selection: ONLY the owning target and the requested group, without
    /// resolving slot IDs from the caller's current configuration. Slot-ID
    /// resolution is deliberately deferred to each reference branch: the
    /// CURRENT group partition governs a HEAD push, while a `release:<id>`
    /// push must select from the RELEASE's FROZEN per-slot groups (a group
    /// named in the release's frozen topology but unknown in the current
    /// config still works — the frozen partition governs), so resolving the
    /// group against the current config here would both reject release-only
    /// groups and select the wrong slot IDs for a historical release whose
    /// frozen partition drifted. The target must exist in the current config
    /// (validated here, before any lock or remote access).
    pub fn normalize(config: &ProjectConfig, target: &str, group: Option<&str>) -> Result<Self> {
        config
            .target(target)
            .ok_or_else(|| Error::not_found(format!("target '{target}'")))?;
        Ok(SlotSelection {
            target: TargetName::parse(target).expect("target name is a safe segment"),
            group: group.map(str::to_string),
        })
    }

    /// The selected (slot, server) pairs resolved from the caller's CURRENT
    /// configuration — the declared temporal source for HEAD and deployment
    /// references, and the physical-rebinding half of a release reference
    /// (each frozen slot id looked up in the target's current member
    /// declarations). `None` selects every slot owned by the target; a group
    /// selects exactly the target's slots whose CURRENT `groups` list
    /// contains it (an unknown group, or a group selecting zero slots in the
    /// current config, is a configuration error — HEAD/deployment behavior,
    /// unchanged). Deterministic order: variants in name order, then each
    /// variant's slots in file order.
    pub fn current_members<'a>(
        &self,
        config: &'a ProjectConfig,
    ) -> Result<Vec<(&'a crate::config::SlotConfig, &'a crate::config::ServerDef)>> {
        match &self.group {
            Some(g) => config.target_group_slots(self.target.as_str(), g),
            None => config.target_slots(self.target.as_str()),
        }
    }

    /// The selected (slot, server) pairs for a DIRECT RELEASE reference: the
    /// group's slot IDs resolve from the RELEASE's FROZEN topology — each
    /// frozen [`crate::identity::CanonicalSlot`] in the record's own snapshot
    /// carries its era's `groups` list, so the frozen partition governs (a
    /// slot the release pushed inside the group but the current config moved
    /// OUT of it still belongs to this push; a group named only in the
    /// frozen topology — unknown in the current config — still resolves).
    /// The frozen IDs are then REBOUND onto their current physical locations
    /// (server / deploy_dir from the target's CURRENT member declarations) —
    /// composing with the explicit [`RebindingPlan`]'s frozen-topology →
    /// current-physical-slot record built in the `PushRef::Release` plan
    /// branch. Deterministic order follows the frozen snapshot: variants in
    /// name order, then each variant's slots in the canonical slot order.
    /// `None` selects every slot the release froze for the target; a group
    /// selecting zero frozen slots is a configuration error as today.
    pub fn release_members<'a>(
        &self,
        config: &'a ProjectConfig,
        rec: &ReleaseRecord,
    ) -> Result<Vec<(&'a crate::config::SlotConfig, &'a crate::config::ServerDef)>> {
        let frozen_ids: Vec<SlotId> = rec
            .slots
            .values()
            .flat_map(|cs| cs.slots.iter())
            .filter(|s| s.target == self.target.as_str())
            .filter(|s| match &self.group {
                Some(g) => s.groups.iter().any(|x| x == g),
                None => true,
            })
            .map(|s| SlotId::parse(s.id.as_str()).expect("validated slot id is a safe segment"))
            .collect();
        if self.group.is_some() && frozen_ids.is_empty() {
            return Err(Error::config(format!(
                "group '{}' selects no slots of target '{}' in the release's frozen topology",
                self.group.as_deref().unwrap_or(""),
                self.target
            )));
        }
        // Rebind the frozen slot IDs onto the CURRENT physical locations.
        // The direct-release membership gate (which the caller runs first)
        // guarantees the frozen slot-ID set equals the target's complete
        // current membership, so every frozen id has a current declaration.
        let all = config.target_slots(self.target.as_str())?;
        let mut out = Vec::with_capacity(frozen_ids.len());
        for id in &frozen_ids {
            out.push(
                all.iter()
                    .find(|(s, _)| s.id == id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        Error::rollback(format!(
                            "release's frozen slot '{id}' is not declared by target '{}' today; \
                             membership drift is rejected before planning",
                            self.target
                        ))
                    })?,
            );
        }
        Ok(out)
    }
}
/// The plan for one placement slot: exactly the canonical slot→artifact
/// assignment ([`PlacementSlotAssignment`]), reused rather than re-declared.
/// The DECLARED temporal source of a resolved push reference: the reference
/// kind the planner resolved the selected slots against. This is the
/// proof-bearing form of a [`PushRef`] carried by a [`ResolvedSelection`]:
/// `Head` (the CURRENT variant slot declarations), `FrozenRelease` (the
/// release's frozen slot topology rebound onto the current physical slots), or
/// `Deployment` (the deployment's exact per-slot assignment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolvedSelectionSource {
    Head,
    FrozenRelease(ReleaseId),
    Deployment(DeploymentId),
}
/// The PROOF-BEARING resolution of one push reference: the owning target,
/// the DECLARED temporal source it resolved against, and the NON-EMPTY
/// resolved slot-ID set. CONSTRUCTIBLE ONLY BY THE PLANNER: the fields are
/// private and the sole constructor ([`ResolvedSelection::new`]) lives in
/// this module (plan.rs), so the engine and every other module consume the
/// resolution by accessor ([`ResolvedSelection::target`],
/// [`ResolvedSelection::source`], [`ResolvedSelection::slots`]) and can
/// never construct one themselves — a compile-level confinement via
/// visibility (private fields + a planner-only constructor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedSelection {
    target: TargetName,
    source: ResolvedSelectionSource,
    slots: NonEmptySlotSet,
}

impl ResolvedSelection {
    /// The PLANNER'S ONLY construction path (this module): the target, the
    /// declared temporal source, and the resolved slot ids. Refuses an EMPTY
    /// resolution (a push that resolves zero slots is never a valid
    /// resolution — the per-branch slot resolution already errors on empty
    /// selections, and this constructor is the second line of defense).
    pub(crate) fn new(
        target: TargetName,
        source: ResolvedSelectionSource,
        slots: impl IntoIterator<Item = SlotId>,
    ) -> Result<Self> {
        let slots = NonEmptySlotSet::try_new(slots).ok_or_else(|| {
            Error::plan(format!(
                "reference resolution selected no slots for target '{}'",
                target
            ))
        })?;
        Ok(ResolvedSelection {
            target,
            source,
            slots,
        })
    }

    pub(crate) fn target(&self) -> &TargetName {
        &self.target
    }

    /// The declared temporal source the resolution resolved against. The
    /// engine derives the plan's ORIGIN from the planner's
    /// [`PlannedResolution::origin`] (built from this source + the verified
    /// rebinding proof), so this accessor is test-only: the property suite
    /// asserts the resolution's declared source.
    #[cfg(test)]
    pub(crate) fn source(&self) -> &ResolvedSelectionSource {
        &self.source
    }

    pub(crate) fn slots(&self) -> &NonEmptySlotSet {
        &self.slots
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use crate::config::raw::CONFIG_SCHEMA_VERSION;
    use crate::deploy::plan::plan_assignments;
    use crate::deploy::plan::*;
    use crate::identity::{
        CanonicalSlot, CanonicalSlots, MatchingMembership, Provenance, ReleaseRecord, SlotId,
        SlotSet, TargetName, test_tree_digest,
    };
    use crate::ledger::{PlanOrigin, PushRef, VerifiedReleaseRebinding};
    use crate::store::local::LocalStore;
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::{BTreeMap, BTreeSet};

    /// Assert the planned origin is a Release origin naming the given
    /// release and carrying the VERIFIED rebinding proof; returns the proof
    /// (the caller then asserts its frozen topology / membership / physical
    /// slots). A Release origin without its proof is unrepresentable, so
    /// this single assertion covers both the release identity and the
    /// proof's presence.
    fn release_origin<'a>(
        origin: &'a PlanOrigin,
        release: &ReleaseId,
    ) -> &'a VerifiedReleaseRebinding {
        match origin {
            PlanOrigin::Release {
                release: r,
                rebinding,
            } => {
                assert_eq!(
                    r, release,
                    "the release origin must name the planned release"
                );
                rebinding
            }
            other => panic!("expected a Release origin for {release}, got {other:?}"),
        }
    }

    const DEPLOY_TOML: &str = r#"
schema_version = 2
application = "plan"
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
deploy_dir = "/srv/plan"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    fn project_with_config() -> (tempfile::TempDir, ProjectConfig) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, DEPLOY_TOML).unwrap();
        let config = ProjectConfig::load(&p).unwrap();
        (dir, config)
    }

    /// A release record in the pre-snapshot SHAPE: an EMPTY `slots` map (the
    /// shape written before the slots-into-identity refactor, and what
    /// `#[serde(default)]` yields for records without a `slots` member). The
    /// store now REJECTS empty slot snapshots at write and read (an empty
    /// snapshot cannot be verified from content), so fixtures that need a
    /// WRITABLE record must fill `slots` and recompute the identity with
    /// [`consistent`]. The bare empty-snapshot record is used directly only
    /// when a test needs the on-disk legacy shape. It still carries the
    /// per-variant tree bindings.
    fn legacy_record(id: &str, tree: &str) -> ReleaseRecord {
        ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: id.to_string(),
            release_sha256: format!("sha256-{id}"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
            },
            // The variant tree must be a VALID digest (the record is read
            // back through the validated parse), so derive the canonical
            // 64-hex form of the tag.
            variants: BTreeMap::from([(
                "standard".to_string(),
                test_tree_digest(tree).as_str().to_string(),
            )]),
            slots: BTreeMap::new(),
        }
    }

    /// Recompute a release record's stored identity from its own content so
    /// `read_release`'s recompute-and-verify passes: the digest is derived
    /// from the record's slot snapshot, bindings, and provenance digests
    /// exactly as `build_release` derives it. Returns the record's release id
    /// (the digest form, which is also the store directory key).
    fn consistent(rec: &mut ReleaseRecord) -> ReleaseId {
        let digest = crate::verify::release::recompute_release_digest(rec)
            .expect("consistent record must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::identity::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        crate::identity::ReleaseId::parse(&rec.release_id)
            .expect("consistent record carries a validated release id")
    }

    /// THE DIRECT-RELEASE GROUP PROPERTY (deterministic form): a
    /// `release:<id>` push with `--group <g>` validates the release against
    /// the target's COMPLETE current membership and then plans ONLY the
    /// group's slots. A 3-slot target (`p1`/`p2`/`p3`) with a release frozen
    /// to all three: every single-slot group (`g1`/`g2`/`g3`) and every pair
    /// group (`g12`/`g13`/`g23`) plans exactly its selected slots — the
    /// membership gate compares the FULL frozen set against the FULL target
    /// membership, never the group-filtered selection (the bug: a `--group`
    /// push compared the release's full set against the subset and failed for
    /// every proper group). Adding a 4th slot to the target's config is a
    /// COMPLETE-membership drift: the release froze 3 slots, the target now
    /// has 4, so EVERY group refuses at plan time with the membership-drift
    /// error (even a group selecting a single drifted slot).
    #[test]
    fn direct_release_group_plans_every_subset_but_full_membership_drift_refuses() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Three slots on three servers; each slot belongs to its own
        // single-slot group plus the two pair groups that contain it.
        const VARIANT_3: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = ["g1", "g12", "g13"]
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
groups = ["g2", "g12", "g23"]
deploy_dir = "/srv/p2"

[[slots]]
id = "p3"
server = "s3"
target = "t1"
groups = ["g3", "g13", "g23"]
deploy_dir = "/srv/p3"

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
        std::fs::write(release_dir.join("standard.toml"), VARIANT_3).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a1"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a2"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "a3"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(config.target_slot_ids("t1").unwrap(), ["p1", "p2", "p3"]);
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen canonical snapshot: all three slots, with
        // the SAME group declarations as the current config (the release was
        // built when the target had exactly this membership).
        let mut rec = legacy_record("unused", "tree-group");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![
                    CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/p1".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["g1".to_string(), "g12".to_string(), "g13".to_string()],
                    },
                    CanonicalSlot {
                        id: "p2".to_string(),
                        server: "s2".to_string(),
                        deploy_dir: "/srv/p2".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["g2".to_string(), "g12".to_string(), "g23".to_string()],
                    },
                    CanonicalSlot {
                        id: "p3".to_string(),
                        server: "s3".to_string(),
                        deploy_dir: "/srv/p3".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["g3".to_string(), "g13".to_string(), "g23".to_string()],
                    },
                ],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        // EVERY single-slot and pair group plans EXACTLY its selected slots:
        // the membership gate passes on the FULL set (release froze 3, the
        // target has 3) and the plan narrows to the group.
        let groups: &[(&str, &[&str])] = &[
            ("g1", &["p1"]),
            ("g2", &["p2"]),
            ("g3", &["p3"]),
            ("g12", &["p1", "p2"]),
            ("g13", &["p1", "p3"]),
            ("g23", &["p2", "p3"]),
        ];
        for (group, want) in groups {
            let selection = SlotSelection::normalize(&config, "t1", Some(group)).unwrap();
            // The selection is now the branch-agnostic {target, group} pair:
            // slot-ID resolution happens inside the release branch, against
            // the release's FROZEN topology (here identical to the current
            // partition, so the plan's assignments are the authoritative
            // answer for `want`).
            let (assignments, desired, origin) = plan_assignments(
                &selection,
                &PushRef::Release {
                    release: release.clone(),
                },
                &crate::identity::test_release_id("unused-local"),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .map(|planned| (planned.assignments, planned.releases, planned.origin))
            .unwrap_or_else(|e| panic!("group {group} must plan a direct release: {e}"));
            let got: Vec<&str> = assignments
                .iter()
                .map(|a| a.placement_slot.as_str())
                .collect();
            assert_eq!(got, *want, "group {group} must plan exactly its slots");
            for a in &assignments {
                assert_eq!(a.artifact.release, release);
                assert_eq!(a.artifact.variant.as_str(), "standard");
            }
            assert_eq!(desired, BTreeSet::from([release.clone()]));
            release_origin(&origin, &release);
        }

        // A 4th slot (`p4` on a new server `s4`) joins the target's config:
        // a COMPLETE-membership drift (the release froze 3 slots, the target
        // now has 4). EVERY group — single AND pair — refuses at plan time
        // with the membership-drift error: the gate validates the FULL set,
        // so even a group selecting a subset of the drifted slots fails.
        let mut drifted_variant = String::from(VARIANT_3);
        drifted_variant.push_str(
            "[[slots]]\nid = \"p4\"\nserver = \"s4\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/p4\"\n",
        );
        std::fs::write(release_dir.join("standard.toml"), drifted_variant).unwrap();
        std::fs::write(
            &cfg_path,
            r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a1"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a2"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "a3"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s4"
address = "a4"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let drifted = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(
            drifted.target_slot_ids("t1").unwrap(),
            ["p1", "p2", "p3", "p4"]
        );
        for (group, _) in groups {
            let selection = SlotSelection::normalize(&drifted, "t1", Some(group)).unwrap();
            let err = plan_assignments(
                &selection,
                &PushRef::Release {
                    release: release.clone(),
                },
                &crate::identity::test_release_id("unused-local"),
                &BTreeMap::new(),
                &store,
                &drifted,
            )
            .expect_err(&format!(
                "a 4th slot added to the target must refuse every group ({group})"
            ));
            let msg = err.to_string();
            assert!(
                msg.contains("membership")
                    && msg.contains("[p1, p2, p3]")
                    && msg.contains("[p1, p2, p3, p4]"),
                "drift error must name expected [p1, p2, p3] vs current [p1, p2, p3, p4], got: {msg}"
            );
            assert!(
                msg.contains("before remote access"),
                "refusal must explain it happens before remote access, got: {msg}"
            );
        }
    }

    /// THE USER'S FROZEN-GROUP FIX, deterministic form: a 3-slot target
    /// (`p1`/`p2`/`p3`) whose release FROZE group `G = {p1, p3}` while the
    /// CURRENT config declares `G = {p2}` — the SAME slot IDs, a DIFFERENT
    /// group partition across eras. `release:<id> --group G` must plan
    /// EXACTLY the FROZEN partition (`p1` + `p3`, rebound onto their current
    /// physical locations), while `HEAD --group G` must plan EXACTLY the
    /// CURRENT partition (`p2`). A second scenario drops `G` from the current
    /// config entirely: a group named only in the release's frozen topology
    /// still resolves for the release ref (the frozen partition governs),
    /// while HEAD refuses (unknown group in the current era). A third
    /// scenario: a frozen group selecting zero slots is a configuration error
    /// as today.
    #[test]
    fn release_group_resolves_frozen_partition_head_uses_current() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // CURRENT config: p1/p2/p3 on s1/s2/s3; ONLY p2 belongs to group G.
        const VARIANT_G_CURRENT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
groups = ["G"]
deploy_dir = "/srv/p2"

[[slots]]
id = "p3"
server = "s3"
target = "t1"
deploy_dir = "/srv/p3"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("standard.toml"), VARIANT_G_CURRENT).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a1"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a2"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "a3"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(config.target_slot_ids("t1").unwrap(), ["p1", "p2", "p3"]);
        assert_eq!(
            config.target_group_slots("t1", "G").unwrap().len(),
            1,
            "the CURRENT partition of G is exactly {{p2}}"
        );
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen snapshot froze G = {p1, p3}: p1 and p3
        // belong to G in the release's era, p2 does not. The slot-ID SET is
        // identical to the current membership (the logical membership gate
        // passes); only the GROUP partition differs.
        let mut rec = legacy_record("unused", "tree-frozen");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![
                    CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/p1".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["G".to_string()],
                    },
                    CanonicalSlot {
                        id: "p2".to_string(),
                        server: "s2".to_string(),
                        deploy_dir: "/srv/p2".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    },
                    CanonicalSlot {
                        id: "p3".to_string(),
                        server: "s3".to_string(),
                        deploy_dir: "/srv/p3".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["G".to_string()],
                    },
                ],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let selection = SlotSelection::normalize(&config, "t1", Some("G")).unwrap();
        let local_release = crate::identity::test_release_id("unused-local");
        let variant_trees =
            BTreeMap::from([("standard".to_string(), test_tree_digest("tree-current"))]);

        // HEAD --group G: the CURRENT partition {p2} — the current config's
        // group declarations are HEAD's declared temporal source.
        let (head, desired, origin) = plan_assignments(
            &selection,
            &PushRef::Head,
            &local_release,
            &variant_trees,
            &store,
            &config,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("HEAD --group G must plan the current partition");
        let head_ids: Vec<&str> = head.iter().map(|a| a.placement_slot.as_str()).collect();
        assert_eq!(
            head_ids,
            ["p2"],
            "HEAD --group G must select EXACTLY the CURRENT partition {{p2}}, got {head_ids:?}"
        );
        assert_eq!(desired, BTreeSet::from([local_release.clone()]));
        assert_eq!(origin, PlanOrigin::Head);
        assert!(
            matches!(origin, PlanOrigin::Head),
            "HEAD records no rebinding"
        );

        // release:R --group G: the FROZEN partition {p1, p3} — a slot the
        // release pushed inside G but the current config moved OUT of G (p1,
        // p3) still belongs to the push, and a slot the current config moved
        // INTO G (p2) does not. The frozen slots are REBOUND onto their
        // current physical locations (recorded in the RebindingPlan).
        let (rel_assignments, rel_desired, rel_origin) = plan_assignments(
            &selection,
            &PushRef::Release {
                release: release.clone(),
            },
            &local_release,
            &variant_trees,
            &store,
            &config,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("release:<id> --group G must plan the frozen partition");
        let rel_ids: Vec<&str> = rel_assignments
            .iter()
            .map(|a| a.placement_slot.as_str())
            .collect();
        assert_eq!(
            rel_ids,
            ["p1", "p3"],
            "release --group G must select EXACTLY the FROZEN partition {{p1, p3}}"
        );
        for a in &rel_assignments {
            assert_eq!(a.artifact.release, release);
            assert_eq!(a.artifact.variant.as_str(), "standard");
            assert_eq!(a.artifact.tree, test_tree_digest("tree-frozen"));
        }
        assert_eq!(rel_desired, BTreeSet::from([release.clone()]));
        release_origin(&rel_origin, &release);
        let rp = release_origin(&rel_origin, &release);
        // The frozen group's slots are REBOUND to their current physical
        // locations: the recorded current_physical_slots carry the CURRENT
        // (server, deploy_dir) for exactly the frozen partition's ids.
        let rebound: Vec<&str> = rp
            .current_physical_slots
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            rebound,
            ["p1", "p3"],
            "the rebinding records exactly the frozen partition's slots"
        );
        for id in ["p1", "p3"] {
            let got = &rp.current_physical_slots[&SlotId::new(id.to_string())];
            assert_eq!(got.server.as_str(), format!("s{}", &id[1..]));
            assert_eq!(got.deploy_dir, format!("/srv/{id}"));
        }
        // The frozen topology records the COMPLETE frozen partition with each
        // slot's era groups (never narrowed to the selection); the membership
        // check records the FULL slot-ID sets (logical only).
        assert_eq!(rp.frozen_topology.len(), 3);
        assert_eq!(
            rp.frozen_topology[&SlotId::new("p1".to_string())].groups,
            vec!["G".to_string()]
        );
        assert!(
            rp.frozen_topology[&SlotId::new("p2".to_string())]
                .groups
                .is_empty()
        );
        assert_eq!(
            rp.frozen_topology[&SlotId::new("p3".to_string())].groups,
            vec!["G".to_string()]
        );
        // The rebinding's membership is the PROOF the gate produced: the
        // frozen and current memberships verified EXACTLY EQUAL (the agreed
        // non-empty slot set — read through the proof accessor; a proof can
        // only come from [`crate::identity::MatchingMembership::verify`]).
        assert_eq!(
            rp.membership
                .slots()
                .iter()
                .map(|s| s.as_str().to_string())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["p1".to_string(), "p2".to_string(), "p3".to_string()])
        );

        // SCENARIO 2: drop G from the CURRENT config entirely — a group named
        // only in the release's frozen topology still resolves for the
        // release ref (the frozen partition governs), while HEAD refuses (an
        // unknown group is a config error for the current era).
        std::fs::write(
            release_dir.join("standard.toml"),
            VARIANT_G_CURRENT.replace("groups = [\"G\"]\n", ""),
        )
        .unwrap();
        let config2 = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(config2.target_slot_ids("t1").unwrap(), ["p1", "p2", "p3"]);
        assert!(
            config2.target_group_slots("t1", "G").is_err(),
            "the current config no longer declares G"
        );
        let selection2 = SlotSelection::normalize(&config2, "t1", Some("G")).unwrap();
        let (rel2, _, _) = plan_assignments(
            &selection2,
            &PushRef::Release {
                release: release.clone(),
            },
            &local_release,
            &variant_trees,
            &store,
            &config2,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("a frozen-only group must still resolve for the release ref");
        let rel2_ids: Vec<&str> = rel2.iter().map(|a| a.placement_slot.as_str()).collect();
        assert_eq!(
            rel2_ids,
            ["p1", "p3"],
            "a group named only in the release's frozen topology still plans the frozen partition"
        );
        let err = plan_assignments(
            &selection2,
            &PushRef::Head,
            &local_release,
            &variant_trees,
            &store,
            &config2,
        )
        .expect_err("HEAD must refuse a group unknown in the current config");
        assert!(
            err.to_string().contains("selects no slots"),
            "HEAD's refusal must be the group config error, got: {err}"
        );

        // SCENARIO 3: a frozen group selecting ZERO slots is a configuration
        // error as today (the frozen partition governs the error too).
        let mut rec2 = legacy_record("unused", "tree-frozen");
        rec2.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![
                    CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/p1".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    },
                    CanonicalSlot {
                        id: "p2".to_string(),
                        server: "s2".to_string(),
                        deploy_dir: "/srv/p2".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    },
                    CanonicalSlot {
                        id: "p3".to_string(),
                        server: "s3".to_string(),
                        deploy_dir: "/srv/p3".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    },
                ],
            },
        )]);
        let release2 = consistent(&mut rec2);
        store.write_release(&rec2).unwrap();
        let err = plan_assignments(
            &selection,
            &PushRef::Release {
                release: release2.clone(),
            },
            &local_release,
            &variant_trees,
            &store,
            &config,
        )
        .expect_err("a frozen group selecting zero slots must be a config error");
        assert!(
            err.to_string().contains("selects no slots"),
            "the refusal must name the frozen group's empty selection, got: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // THE USER'S FROZEN-GROUP PROPERTY: arbitrary OLD (frozen) / CURRENT
    // group partitions over the SAME slot-ID set. `HEAD --group G` must
    // select exactly the CURRENT partition; `release:R --group G` must select
    // exactly the FROZEN partition, planned against the frozen slots REBOUND
    // to their current physical locations — a slot in G in the release but
    // moved out of G in the current config still belongs to the release push,
    // and vice versa.
    // ---------------------------------------------------------------------

    /// Build the frozen/current group-partition fixture: a project whose
    /// CURRENT variant declares the fixed 4-slot universe `p1..p4` with the
    /// generated CURRENT partition (`G` on exactly the slots `current_inc`
    /// marks), and a release record whose OWN frozen snapshot declares the
    /// SAME 4 slot IDs with the generated FROZEN partition (`G` on exactly
    /// `frozen_inc`). The slot-ID sets are IDENTICAL across eras by
    /// construction, so the release's logical membership gate passes for
    /// every generated case; only the GROUP partition differs. Returns the
    /// fixture's tempdir, config, store, and the written release id.
    fn group_partition_fixture(
        frozen_inc: [bool; 4],
        current_inc: [bool; 4],
    ) -> (tempfile::TempDir, ProjectConfig, LocalStore, ReleaseId) {
        const SLOTS: [&str; 4] = ["p1", "p2", "p3", "p4"];
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let mut variant = String::from(
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n\
             [retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n\
             [retention.deployment]\nprotect_deployments = 1\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
        for (i, id) in SLOTS.iter().enumerate() {
            let groups = if current_inc[i] {
                "groups = [\"G\"]\n"
            } else {
                ""
            };
            variant.push_str(&format!(
                "[[slots]]\nid = \"{id}\"\nserver = \"s{}\"\ntarget = \"t1\"\n{groups}deploy_dir = \"/srv/{id}\"\n\n",
                i + 1
            ));
        }
        std::fs::write(release_dir.join("standard.toml"), variant).unwrap();
        let mut servers = String::new();
        for i in 1..=4 {
            servers.push_str(&format!(
                "[[servers]]\nid = \"s{i}\"\naddress = \"a{i}\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n"
            ));
        }
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "schema_version = 2\napplication = \"plan\"\nrelease = \"v1\"\n\n\
                 {servers}\
                 [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen snapshot: the SAME slot IDs with the
        // FROZEN partition (`G` on exactly `frozen_inc`).
        let mut rec = legacy_record("unused", "tree-frozen");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: SLOTS
                    .iter()
                    .enumerate()
                    .map(|(i, id)| CanonicalSlot {
                        id: id.to_string(),
                        server: format!("s{}", i + 1),
                        deploy_dir: format!("/srv/{id}"),
                        target: "t1".to_string(),
                        groups: if frozen_inc[i] {
                            vec!["G".to_string()]
                        } else {
                            Vec::new()
                        },
                    })
                    .collect(),
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();
        (dir, config, store, release)
    }

    proptest! {
        // THE USER'S FROZEN-GROUP PROPERTY: identical slot-ID sets with
        // ARBITRARY frozen/current group partitions (each era independently
        // decides which slots belong to `G`; both non-empty so both branches
        // plan). Bounded 8 cases + the pinned 0x5EED_5EED seed (house style)
        // keep the deterministic floor fast; each case is store-only (no
        // remote).
        #![proptest_config(ProptestConfig {
            cases: 8,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn release_group_selects_frozen_partition_head_selects_current(
            frozen_inc in prop::array::uniform4(prop::bool::ANY)
                .prop_filter("the frozen partition must be non-empty", |a| a.iter().any(|b| *b)),
            current_inc in prop::array::uniform4(prop::bool::ANY)
                .prop_filter("the current partition must be non-empty", |a| a.iter().any(|b| *b)),
        ) {
            let (_dir, config, store, release) =
                group_partition_fixture(frozen_inc, current_inc);
            const SLOTS: [&str; 4] = ["p1", "p2", "p3", "p4"];
            let frozen: Vec<&str> = SLOTS
                .iter()
                .enumerate()
                .filter(|(i, _)| frozen_inc[*i])
                .map(|(_, id)| *id)
                .collect();
            let current: Vec<&str> = SLOTS
                .iter()
                .enumerate()
                .filter(|(i, _)| current_inc[*i])
                .map(|(_, id)| *id)
                .collect();
            assert!(!frozen.is_empty(), "the frozen partition is non-empty");
            assert!(!current.is_empty(), "the current partition is non-empty");
            let selection = SlotSelection::normalize(&config, "t1", Some("G")).unwrap();
            let local_release = crate::identity::test_release_id("unused-local");
            let variant_trees = BTreeMap::from([(
                "standard".to_string(),
                test_tree_digest("tree-current"),
            )]);

            // HEAD --group G: the CURRENT partition governs.
            let (head, _, origin) = plan_assignments(
                &selection,
                &PushRef::Head,
                &local_release,
                &variant_trees,
                &store,
                &config,
            )
                .map(|planned| (planned.assignments, planned.releases, planned.origin))
            .unwrap_or_else(|e| {
                panic!("HEAD --group G must plan the current partition {current:?}: {e}")
            });
            let head_ids: Vec<&str> = head
                .iter()
                .map(|a| a.placement_slot.as_str())
                .collect();
            assert_eq!(
                head_ids, current,
                "HEAD --group G must select EXACTLY the CURRENT partition"
            );
            assert_eq!(origin, PlanOrigin::Head);
            assert!(matches!(origin, PlanOrigin::Head), "HEAD records no rebinding");

            // release:R --group G: the FROZEN partition governs — a slot in G
            // in the release but moved OUT of G in the current config still
            // belongs to the push, and a slot moved INTO G in the current
            // config but outside G in the release does not. The planned slots
            // are the frozen ids REBOUND to their current physical locations
            // (the RebindingPlan records the current binding for exactly the
            // frozen partition's ids).
            let (rel, _, rel_origin) = plan_assignments(
                &selection,
                &PushRef::Release {
                    release: release.clone(),
                },
                &local_release,
                &variant_trees,
                &store,
                &config,
            )
                .map(|planned| (planned.assignments, planned.releases, planned.origin))
            .unwrap_or_else(|e| {
                panic!("release:R --group G must plan the frozen partition {frozen:?}: {e}")
            });
            let rel_ids: Vec<&str> = rel
                .iter()
                .map(|a| a.placement_slot.as_str())
                .collect();
            assert_eq!(
                rel_ids, frozen,
                "release:R --group G must select EXACTLY the FROZEN partition"
            );
            for a in &rel {
                assert_eq!(a.artifact.release, release);
                assert_eq!(a.artifact.variant.as_str(), "standard");
                assert_eq!(a.artifact.tree, test_tree_digest("tree-frozen"));
            }
            release_origin(&rel_origin, &release);
            let rp = release_origin(&rel_origin, &release);
            let rebound: Vec<&str> = rp
                .current_physical_slots
                .keys()
                .map(|s| s.as_str())
                .collect();
            assert_eq!(
                rebound, frozen,
                "the rebinding records the frozen partition's slots, rebound to current locations"
            );
            for id in &frozen {
                let got = &rp.current_physical_slots[&SlotId::new(id.to_string())];
                assert_eq!(got.server.as_str(), &format!("s{}", &id[1..]));
                assert_eq!(got.deploy_dir, format!("/srv/{id}"));
            }
        }
    }

    // -------------------------------------------------------------------
    // IMMUTABILITY + PROOF-BEARING PROPERTY (bounded 16 cases, fixed seed
    // 0x5EED_5EED per house style, no failure persistence):
    //
    // (a) IMMUTABILITY — the validated domain is obtained ONLY by a full
    //     validated load ([`ProjectConfig::load`] / [`ProjectConfig::load_release`]),
    //     so a config can never be partially switched: `load_release` on an
    //     INVALID name returns `Err` (the name is re-validated — exactly one
    //     directory component), and on a VALID name it returns a FRESH load
    //     of the project with that release selected — equal to a fresh
    //     `ProjectConfig::load` of a project configured with that release
    //     (the original is never mutated).
    // (b) PROOF TYPES — [`crate::identity::MatchingMembership::verify`] returns
    //     `Ok` EXACTLY when the frozen and current slot-id sets are EQUAL
    //     (and non-empty: a target without slots is invalid, so an empty
    //     agreement is never a proof) and `Err` otherwise;
    //     [`ResolvedSelection`] is constructible ONLY by the planner path —
    //     the fields are private and the sole constructor
    //     ([`ResolvedSelection::new`]) lives in plan.rs (a compile-level
    //     confinement via visibility), so the planner path
    //     (`plan_assignments`) yields the only selections, and the
    //     constructor refuses an EMPTY resolution.
    // -------------------------------------------------------------------
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn validated_domain_is_immutable_and_proofs_verify_exactly(
            invalid_name in "[a-z]{1,4}/[a-z]{1,4}",
            frozen_ids in prop::collection::vec("[p][0-9]{1,2}", 0..5),
            current_ids in prop::collection::vec("[p][0-9]{1,2}", 0..5),
        ) {
            // (a) IMMUTABILITY of the validated domain.
            let (dir, config) = project_with_config();
            let original = config;
            let config_path = dir.path().join("proj").join("deploy.toml");

            // The release-name invariant lives in
            // [`crate::config::ReleaseName::parse`] too: the invalid name is
            // refused at the type boundary.
            assert!(
                crate::config::ReleaseName::parse(&invalid_name).is_err(),
                "parse must reject the invalid release name {invalid_name:?}"
            );
            // load_release on an INVALID name -> Err (the name is re-validated
            // by the operation; a partially-switched config can never escape).
            let invalid = crate::config::ReleaseName::new(invalid_name.clone());
            assert!(
                ProjectConfig::load_release(&config_path, invalid).is_err(),
                "load_release must Err on the invalid name {invalid_name:?}"
            );
            assert_eq!(original.release().as_str(), "v1");
            assert_eq!(original.schema_version(), CONFIG_SCHEMA_VERSION);
            assert_eq!(original.variant_names(), vec!["standard".to_string()]);
            assert_eq!(original.target_slot_ids("t1").unwrap(), vec!["p1".to_string()]);

            // load_release on a VALID name (the project's own release) -> a
            // FRESH, fully-validated load of the project with that release
            // selected: equal to the original `ProjectConfig::load` (the
            // release-switch re-validates the whole config; the original is
            // untouched).
            let valid = crate::config::ReleaseName::parse("v1")
                .expect("a single-component name parses");
            let switched = ProjectConfig::load_release(&config_path, valid)
                .expect("a valid release name loads");
            assert_eq!(
                switched, original,
                "a fresh load of the same release equals the original load"
            );
            assert_eq!(switched.release().as_str(), "v1");
            assert_eq!(switched.schema_version(), CONFIG_SCHEMA_VERSION);
            assert_eq!(switched.variant_names(), original.variant_names());
            assert_eq!(
                switched.target_slot_ids("t1").unwrap(),
                original.target_slot_ids("t1").unwrap()
            );

            // (b) PROOF TYPES.
            // MatchingMembership::verify is Ok EXACTLY when the frozen and
            // current slot-id sets are EQUAL and non-empty, Err otherwise.
            let frozen: Vec<SlotId> = frozen_ids
                .iter()
                .map(|s| SlotId::new(s.clone()))
                .collect();
            let current: Vec<SlotId> = current_ids
                .iter()
                .map(|s| SlotId::new(s.clone()))
                .collect();
            let frozen_set = SlotSet::new(frozen);
            let current_set = SlotSet::new(current);
            let equal = frozen_set == current_set;
            let nonempty = !frozen_set.is_empty();
            let proof = MatchingMembership::verify(frozen_set.clone(), current_set.clone());
            assert_eq!(
                proof.is_ok(),
                equal && nonempty,
                "verify must be Ok EXACTLY when the memberships match and are non-empty \
                 (frozen {frozen_ids:?}, current {current_ids:?})"
            );
            if let Ok(proof) = &proof {
                // The proof carries the AGREED non-empty membership; the
                // accessors expose exactly it.
                assert_eq!(proof.slots().len(), frozen_set.len());
                assert!(frozen_set
                    .iter()
                    .all(|f| proof.slots().contains(f) && proof.slots().len() >= 1));
                assert!(proof
                    .slots()
                    .iter()
                    .all(|id| frozen_set.iter().any(|f| f == id)));
            }

            // ResolvedSelection is constructible ONLY by the planner path: the
            // sole constructor refuses an EMPTY resolution (a non-empty
            // slot set is a proof invariant), and the planner path
            // (`plan_assignments`, HEAD below) yields a selection whose
            // accessors carry the target, the declared temporal source, and
            // the resolved non-empty slot set.
            let empty_err = ResolvedSelection::new(
                TargetName::new("t1".to_string()),
                ResolvedSelectionSource::Head,
                std::iter::empty(),
            )
            .expect_err("an empty resolution must be refused by the planner constructor");
            assert!(
                empty_err.to_string().contains("no slots"),
                "the refusal must name the empty resolution, got: {empty_err}"
            );
            let (_dir2, config2) = project_with_config();
            let store = LocalStore::with_base(_dir2.path().join("store")).unwrap();
            let planned = plan_assignments(
                &SlotSelection::normalize(&config2, "t1", None).unwrap(),
                &PushRef::Head,
                &crate::identity::test_release_id("local"),
                &BTreeMap::from([(
                    "standard".to_string(),
                    test_tree_digest("tree"),
                )]),
                &store,
                &config2,
            )
            .expect("HEAD resolves the fixture target");
            let resolved = planned.resolved();
            assert_eq!(resolved.target().as_str(), "t1");
            assert_eq!(resolved.source(), &ResolvedSelectionSource::Head);
            assert_eq!(
                resolved
                    .slots()
                    .iter()
                    .map(|s| s.as_str().to_string())
                    .collect::<Vec<_>>(),
                vec!["p1".to_string()],
                "the planner's resolution carries exactly the target's member slot"
            );
            assert_eq!(resolved.slots().len(), 1);
            assert!(resolved.slots().contains(&SlotId::new("p1")));
        }
    }
}

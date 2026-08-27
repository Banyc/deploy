use super::*;
use crate::config::domain::{RawProject, valid_identifier};
use crate::config::raw::CONFIG_SCHEMA_VERSION;
use crate::error::{Error, Result};
use crate::identity::{
    AbsoluteDeployDir, ApplicationStoreKey, BatchSize, CapacityPercent, Host, Identifier,
    RolloutGroupName, SshUser,
};
use crate::identity::{
    ArtifactRef, ReleaseId, SlotId, TargetName, VariantName, test_deployment_id,
    test_generation_id, test_tree_digest,
};
use crate::ledger::{
    DeploymentIntent, DesiredGeneration, IntentSlot, LEDGER_SCHEMA_VERSION, LedgerIntentWire,
    LedgerLine, NonEmptySlotTable,
};
use crate::store::local::LocalStore;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[test]
fn relative_path_validation() {
    assert!(validate_relative_path(Path::new("app/server")).is_ok());
    assert!(validate_relative_path(Path::new("nested/deep/file.conf")).is_ok());
    // Absolute paths are rejected.
    assert!(validate_relative_path(Path::new("/etc/passwd")).is_err());
    // Single-level parent escape is rejected.
    assert!(validate_relative_path(Path::new("../escape")).is_err());
    // Nested escapes are rejected.
    assert!(validate_relative_path(Path::new("nested/../../escape")).is_err());
}

#[test]
fn mapping_to_must_be_artifact_relative() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();
    let variant_toml = r#"
description = "escaping"

[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/esc"

[[artifact.mappings]]
from = "build/output/"
to = "../escape"
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
    std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
    let deploy_toml = r#"
schema_version = 2
application = "esc"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml).unwrap();
    assert!(
        ProjectConfig::load(&p).is_err(),
        "escaping mapping `to` must be rejected"
    );
}

#[test]
fn overlapping_mapping_destinations_are_rejected_at_load() {
    // Two mappings whose destinations overlap (identical, or one nested
    // beneath the other) are rejected at config load: the materialized
    // tree would depend on declaration order.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();
    let deploy_toml = r#"
schema_version = 2
application = "ovl"
release = "v1"


[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml).unwrap();

    // Identical destinations (with and without the trailing slash).
    std::fs::write(
        release_dir.join("standard.toml"),
        "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/ovl\"\n\n\
         [[artifact.mappings]]\nfrom = \"a/\"\nto = \"app/\"\nrecursive = true\n\n\
         [[artifact.mappings]]\nfrom = \"b/\"\nto = \"app\"\nrecursive = true\n\n\
         [activation]\nadapter = \"none\"\n\n\
         [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
    )
    .unwrap();
    let err = ProjectConfig::load(&p).expect_err("identical destinations must be rejected");
    assert!(
        err.to_string().contains("overlap"),
        "error must name the overlap, got: {err}"
    );

    // A nested `to` descending into another mapping's `to` tree.
    std::fs::write(
        release_dir.join("standard.toml"),
        "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/ovl\"\n\n[[artifact.mappings]]\nfrom = \"a/\"\nto = \"app/\"\nrecursive = true\n\n\
         [[artifact.mappings]]\nfrom = \"b/\"\nto = \"app/nested/\"\nrecursive = true\n\n\
         [activation]\nadapter = \"none\"\n\n\
         [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
    )
    .unwrap();
    let err = ProjectConfig::load(&p).expect_err("nested destinations must be rejected");
    assert!(
        err.to_string().contains("overlap"),
        "error must name the overlap, got: {err}"
    );

    // Non-overlapping destinations still load.
    std::fs::write(
        release_dir.join("standard.toml"),
        "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/ovl\"\n\n[[artifact.mappings]]\nfrom = \"a/\"\nto = \"app/\"\nrecursive = true\n\n\
         [[artifact.mappings]]\nfrom = \"b/\"\nto = \"other/\"\nrecursive = true\n\n\
         [activation]\nadapter = \"none\"\n\n\
         [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
    )
    .unwrap();
    ProjectConfig::load(&p).expect("non-overlapping destinations load");
}

#[test]
fn loads_variant_config_from_release_directory() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();

    let standard_toml = r#"
description = "Standard deployment"

[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/example"

[[artifact.mappings]]
from = "build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
    let hc_toml = r#"
description = "High capacity deployment"

[[artifact.mappings]]
from = "build/output/"
to = "app/"
recursive = true

[activation]
adapter = "systemd"
scope = "user"
units = [{ name = "x.service", artifact_path = "integration/systemd/x.service", enable = true, restart = true }]

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
    std::fs::write(release_dir.join("standard.toml"), standard_toml).unwrap();
    std::fs::write(release_dir.join("high-capacity.toml"), hc_toml).unwrap();

    let deploy_toml = r#"
schema_version = 2
application = "example"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"
capacity = { reserve_bytes = 1073741824, reserve_percent = 5 }

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml).unwrap();

    let cfg = ProjectConfig::load(&p).expect("config loads with sibling variant files");
    // Retention is SLOT-OWNED: the policy lives on the owning variant
    // (`standard` declares slot `p1`), never on the target.
    assert_eq!(
        cfg.variant("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts,
        5
    );
    assert_eq!(
        cfg.variant("standard")
            .unwrap()
            .retention
            .deployment
            .protect_deployments,
        2
    );
    assert_eq!(
        cfg.slot_retention("p1")
            .unwrap()
            .per_server
            .keep_distinct_artifacts,
        5,
        "slot_retention resolves the owning variant's policy"
    );
    let names = cfg.variant_names();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"standard".to_string()));
    assert!(names.contains(&"high-capacity".to_string()));

    let std = cfg.variant("standard").expect("standard variant present");
    assert_eq!(std.verification.argv, vec!["true".to_string()]);
    assert_eq!(std.activation, Activation::None);

    let hc = cfg
        .variant("high-capacity")
        .expect("high-capacity variant present");
    assert_eq!(hc.verification.argv, vec!["false".to_string()]);
    let Activation::Systemd(hc_act) = &hc.activation else {
        panic!("high-capacity variant must carry the systemd activation");
    };
    assert!(!hc_act.units.is_empty());

    // Capacity is per-server, not per-variant: the single server carries
    // the policy and the variant files parse without any `[capacity]` block.
    assert_eq!(cfg.servers_ref().len(), 1);
    assert_eq!(cfg.servers_ref()[0].capacity.reserve_bytes, 1073741824);
    assert_eq!(cfg.servers_ref()[0].capacity.reserve_percent.get(), 5);
    assert_eq!(cfg.variant("standard").unwrap().artifact.mappings.len(), 1);

    // Unknown variant name is rejected.
    assert!(cfg.variant("missing").is_err());
}

const MINIMAL_VARIANT: &str = r#"
[artifact]
mappings = []

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

/// The default slot body appended to the `standard` variant file used by
/// the tests below: `p1` on server `s1`, belonging to target `t1`. Slots
/// are declared inside the variant file that owns the workload and bind
/// themselves to targets with the `targets` list; a target's members are
/// derived from these declarations.
const STANDARD_SLOTS: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/forced"
"#;

/// The `standard` variant's retention policy — the single retention
/// source for its declared slot `p1` (a slot's owning variant owns its
/// policy; targets carry rollout only).
const STANDARD_ROTATION: &str = r#"
[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1
"#;

fn deploy_toml(release_value: &str) -> String {
    format!(
        r#"
schema_version = 2
application = "forced"
release = "{release_value}"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }}
"#
    )
}

fn write_standard_release(project: &Path, release: &str) {
    let release_dir = project.join("releases").join(release);
    std::fs::create_dir_all(&release_dir).unwrap();
    // The standard variant file declares the `p1` slot the `deploy_toml()`
    // target references AND owns its retention policy (retention lives in
    // the variant file, not on the target).
    std::fs::write(
        release_dir.join("standard.toml"),
        format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n{STANDARD_ROTATION}"),
    )
    .unwrap();
}

#[test]
fn forced_structure_discovers_variant_files() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    // Non-variant entries inside the release directory are ignored.
    std::fs::create_dir_all(project.join("releases/v1/artifacts")).unwrap();
    std::fs::write(project.join("releases/v1/README.md"), "notes").unwrap();
    std::fs::write(project.join("releases/v1/.hidden.toml"), MINIMAL_VARIANT).unwrap();
    std::fs::write(project.join("releases/v1/other.yml"), MINIMAL_VARIANT).unwrap();
    std::fs::write(
        project.join("releases/v1/high-capacity.toml"),
        MINIMAL_VARIANT,
    )
    .unwrap();

    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let cfg = ProjectConfig::load(&p).expect("config loads from the forced structure");
    assert_eq!(cfg.release().as_str(), "v1");
    assert_eq!(
        cfg.variant_names(),
        vec!["high-capacity".to_string(), "standard".to_string()],
        "every *.toml file stem is a variant; other entries are ignored"
    );
    assert_eq!(cfg.release_root(&p), project.join("releases").join("v1"));
}

#[test]
fn release_name_map_form_is_rejected_with_migration_hint() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    // The pre-forcing deploy.toml shape (release as a map) must not parse
    // silently.
    let legacy_toml = r#"
schema_version = 2
application = "legacy"
release = { path = "releases/v1", variants = { standard = "standard.toml" } }

[[servers]]
id = "s1"
address = "a"
user = "u"

[[slots]]
id = "p1"
server = "s1"
variant = "standard"
deploy_dir = "/srv/legacy"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
slots = ["p1"]
"#;
    let p = project.join("deploy.toml");
    std::fs::write(&p, legacy_toml).unwrap();
    let err = ProjectConfig::load(&p).expect_err("old release map form must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("release: <name>"),
        "error must explain the forced structure, got: {msg}"
    );
}

#[test]
fn release_name_must_be_a_single_directory_component() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    for bad in ["../v1", "a/b", ".", "..", "/abs"] {
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml(bad)).unwrap();
        assert!(
            ProjectConfig::load(&p).is_err(),
            "release name '{bad}' must be rejected"
        );
    }
}

#[test]
fn missing_release_directory_errors_with_structure_hint() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v9")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("missing release dir must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("releases/v9") || msg.contains("releases") && msg.contains("v9"),
        "error must point at the forced release directory, got: {msg}"
    );
}

#[test]
fn release_directory_without_variants_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(project.join("releases/v1")).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("empty release dir must fail");
    assert!(
        err.to_string().contains("no variants"),
        "error must mention the missing variant files, got: {err}"
    );
}

/// Every target named in a slot's `targets` list must be a top-level
/// `[targets.<name>]` key: membership is derived from the slot
/// declarations, so a slot bound to an undeclared target is a
/// configuration error.
#[test]
fn slot_target_must_reference_declared_target() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let bad_variant = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"ghost\"\ndeploy_dir = \"/srv/forced\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown target reference must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("references unknown target 'ghost'") && msg.contains("variant 'standard'"),
        "error must name the unknown target and the declaring variant, got: {msg}"
    );
}

/// A slot may be a member of SEVERAL targets: membership is a `targets`
/// list, and each target's members are DERIVED by scanning the slots for
/// its name. A slot in two targets is valid and both targets derive it;
/// a target with no member slot is still rejected.
#[test]
fn slots_declare_their_target_membership() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");

    // A second slot, declared in the same variant file, belongs to a
    // second target (disjoint targets, disjoint memberships).
    let standard_toml = format!(
        "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), standard_toml).unwrap();
    let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
    std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();
    let cfg = ProjectConfig::load(&p).expect("slots spread across targets are valid");
    assert_eq!(cfg.targets_ref().len(), 2);
    assert_eq!(cfg.slot_defs().len(), 2);
    // Membership is derived from each slot's declared targets list.
    assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
    assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);

    // A slot has EXACTLY ONE owning target; a rollout group selects a
    // subset of the target's slots (`deploy push t1 --group <name>`).
    let grouped = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = [\"canary\"]\ndeploy_dir = \"/srv/forced\"\n\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), grouped).unwrap();
    let cfg = ProjectConfig::load(&p).expect("a slot with a rollout group is valid");
    assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
    assert_eq!(
        cfg.target_group_slots("t1", "canary").unwrap().len(),
        1,
        "the group selects the slot"
    );
    assert!(
        cfg.target_group_slots("t1", "missing").is_err(),
        "an unknown group is a configuration error"
    );

    // A target with NO member slot is rejected.
    let t3 = "\n[targets.t3]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
    std::fs::write(&p, format!("{}{}{}", deploy_toml("v1"), t2, t3)).unwrap();
    let err = ProjectConfig::load(&p).expect_err("target without slots must fail");
    assert!(
        err.to_string().contains("target 't3' has no slots"),
        "error must name the empty target, got: {err}"
    );
}

/// A slot with an EMPTY `targets` list belongs to no target and is
/// useless (mirroring the rule that a target must have at least one
/// member), so it is rejected at validation.
#[test]
fn slot_with_no_targets_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    // The `target` key is omitted entirely: it is REQUIRED (a slot has
    // exactly one owning target), so the parse fails closed.
    let no_target = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ndeploy_dir = \"/srv/forced\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), no_target).unwrap();
    let err = ProjectConfig::load(&p).expect_err("slot without a target must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("missing field `target`") && msg.contains("variant 'standard'"),
        "error must name the missing target and the slot's variant, got: {msg}"
    );
}

/// Slots are declared inside the variant files, so the server reference of
/// a variant's slot must resolve against the top-level `[[servers]]` list
/// — reported against the declaring variant — and the slot's variant
/// binding IS the declaring file.
#[test]
fn slots_must_reference_known_servers() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");

    // A slot bound to a server that does not exist (declared in the
    // variant file, reported with the variant context).
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let bad_variant = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"ghost\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
    let err = ProjectConfig::load(&p).expect_err("slot with unknown server must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("references unknown server 'ghost'") && msg.contains("variant 'standard'"),
        "error must name the unknown server and the declaring variant, got: {msg}"
    );

    // The declaring file is the slot's variant binding: `slot_variant`
    // resolves the slot to the file that declares it.
    std::fs::write(
        project.join("releases/v1/standard.toml"),
        format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
    )
    .unwrap();
    let cfg = ProjectConfig::load(&p).unwrap();
    assert_eq!(cfg.slot_variant("p1").unwrap(), "standard");
    assert!(cfg.slot_variant("ghost-slot").is_err());
}

#[test]
fn duplicate_slot_ids_across_variants_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    // A second variant declares a slot with the SAME id: the id must be
    // unique across every variant's slots.
    let dup = format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n");
    std::fs::write(project.join("releases/v1/high-capacity.toml"), dup).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("duplicate slot id across variants must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate slot id 'p1'") && msg.contains("variant 'standard'"),
        "error must name the duplicate id and the variant where the collision was found, got: {msg}"
    );
}

#[test]
fn duplicate_target_names_in_a_slot_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    // A slot declaring the same group twice: the duplicate adds no
    // membership yet would change release identity, so it is rejected.
    let dup = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = [\"canary\", \"canary\"]\ndeploy_dir = \"/srv/forced\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("duplicate group name in a slot must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate group 'canary'") && msg.contains("slot 'p1'"),
        "error must name the duplicate group and the slot, got: {msg}"
    );
}

#[test]
fn slots_on_the_same_server_never_share_a_deploy_dir() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");

    // Second slot in the same variant file, same server, SAME deploy_dir:
    // rejected (the location collision fires regardless of target).
    let dup = format!(
        "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("shared server+deploy_dir must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("same location") && msg.contains("p1") && msg.contains("p2"),
        "error must name the colliding slots, got: {msg}"
    );

    // A DIFFERENT variant file declares p2 with a DIFFERENT deploy_dir on
    // the same server for a DIFFERENT target: accepted (the uniqueness
    // rule spans all variants' slots; two slots may share one server in
    // different targets).
    std::fs::write(
        project.join("releases/v1/standard.toml"),
        format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
    )
    .unwrap();
    let other = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/other\"\n"
    );
    std::fs::write(project.join("releases/v1/other.toml"), other).unwrap();
    let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
    std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();
    let cfg = ProjectConfig::load(&p).expect("distinct deploy_dir on the same server is valid");
    assert_eq!(cfg.slot_defs().len(), 2);
}

#[test]
fn duplicate_top_level_server_ids_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let mut toml = deploy_toml("v1");
    // Insert a second [[servers]] entry with the same ID before [targets.t1].
    let dup = "[[servers]]\nid = \"s1\"\naddress = \"a2\"\nuser = \"u\"\n\n";
    toml = toml.replacen("[targets.t1]", &format!("{dup}[targets.t1]"), 1);
    let p = project.join("deploy.toml");
    std::fs::write(&p, toml).unwrap();
    let err = ProjectConfig::load(&p).expect_err("duplicate server id must fail");
    assert!(
        err.to_string().contains("duplicate server id 's1'"),
        "error must name the duplicated id, got: {err}"
    );
}

#[test]
fn server_capacity_is_validated_and_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");

    // Omitted capacity defaults to 0/0.
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let cfg = ProjectConfig::load(&p).expect("server without capacity loads");
    assert_eq!(cfg.servers_ref()[0].capacity, CapacityConfig::default());

    // reserve_percent above 100 is rejected at load time.
    let bad = deploy_toml("v1").replace(
        "user = \"u\"",
        "user = \"u\"\ncapacity = { reserve_bytes = 1, reserve_percent = 101 }",
    );
    std::fs::write(&p, bad).unwrap();
    let err = ProjectConfig::load(&p).expect_err("reserve_percent > 100 must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("reserve_percent must be within 0..=100") && msg.contains("server 's1'"),
        "error must name the server and the violation, got: {msg}"
    );

    // A valid inline capacity table parses into the server policy.
    let ok = deploy_toml("v1").replace(
        "user = \"u\"\nhost_key_fingerprint",
        "user = \"u\"\ncapacity = { reserve_bytes = 4096, reserve_percent = 10 }\nhost_key_fingerprint",
    );
    std::fs::write(&p, ok).unwrap();
    let cfg = ProjectConfig::load(&p).expect("inline server capacity parses");
    assert_eq!(cfg.servers_ref()[0].capacity.reserve_bytes, 4096);
    assert_eq!(cfg.servers_ref()[0].capacity.reserve_percent.get(), 10);
}

/// SSH addresses require EXACTLY ONE host-identity source; `local://`
/// addresses are exempt. Neither (would-be trust-on-first-use) and both
/// (ambiguous) are rejected at load time, naming the server.
#[test]
fn ssh_identity_requires_exactly_one_source() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");

    // SSH address + neither identity source: rejected (no trust-on-first-use).
    std::fs::write(
        &p,
        deploy_toml("v1").replace("host_key_fingerprint = \"SHA256:test\"\n", ""),
    )
    .unwrap();
    let err = ProjectConfig::load(&p).expect_err("SSH address without identity must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("server 's1'")
            && msg.contains("exactly one of known_hosts or host_key_fingerprint")
            && msg.contains("trust-on-first-use is disabled"),
        "error must name the server and the missing identity, got: {msg}"
    );

    // SSH address + BOTH sources: rejected as ambiguous.
    let both = deploy_toml("v1").replace(
        "host_key_fingerprint = \"SHA256:test\"",
        "host_key_fingerprint = \"SHA256:test\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
    );
    std::fs::write(&p, both).unwrap();
    let err = ProjectConfig::load(&p).expect_err("SSH address with both identities must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("server 's1'")
            && msg.contains("mutually exclusive")
            && msg.contains("configure exactly one"),
        "error must name the server and the ambiguity, got: {msg}"
    );

    // local:// address + neither source: fine (no host verification).
    let local = deploy_toml("v1")
        .replace("address = \"a\"", "address = \"local:///srv/forced\"")
        .replace("host_key_fingerprint = \"SHA256:test\"\n", "");
    std::fs::write(&p, local).unwrap();
    let cfg = ProjectConfig::load(&p).expect("local:// address needs no identity");
    assert!(cfg.server("s1").unwrap().address().starts_with("local://"));

    // SSH address + exactly one source: valid.
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let cfg = ProjectConfig::load(&p).expect("SSH address with exactly one identity is valid");
    assert_eq!(
        match cfg.server("s1").unwrap().identity() {
            HostIdentity::Fingerprint(f) => Some(f.as_str()),
            _ => None,
        },
        Some("SHA256:test")
    );
    let kh_only = deploy_toml("v1").replace(
        "host_key_fingerprint = \"SHA256:test\"",
        "known_hosts = \"/etc/ssh/known_hosts\"",
    );
    std::fs::write(&p, kh_only).unwrap();
    let cfg = ProjectConfig::load(&p).expect("known_hosts-only SSH address is valid");
    assert_eq!(
        match cfg.server("s1").unwrap().identity() {
            HostIdentity::KnownHosts(p) => Some(p.as_path()),
            _ => None,
        },
        Some(Path::new("/etc/ssh/known_hosts"))
    );
    assert!(!matches!(
        cfg.server("s1").unwrap().identity(),
        HostIdentity::Fingerprint(_)
    ));
}

/// `local://` addresses never perform host verification, so their domain
/// identity is ALWAYS [`HostIdentity::Local`] — the raw identity fields
/// (whatever the file says) are collapsed by the conversion, and a local
/// server can never carry a `KnownHosts`/`Fingerprint` form. The old
/// exemption allowed a local endpoint to declare identity fields; the
/// typed enum makes the option space total: `Local` is the ONE form for
/// a local endpoint, exactly-one by construction.
#[test]
fn local_address_identity_collapses_to_local() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    let local = deploy_toml("v1")
        .replace("address = \"a\"", "address = \"local:///srv/forced\"")
        .replace("host_key_fingerprint = \"SHA256:test\"\n", "");

    // local:// with no identity: Local.
    std::fs::write(&p, local.clone()).unwrap();
    let cfg = ProjectConfig::load(&p).expect("local:// without identity loads");
    assert!(cfg.server("s1").unwrap().address().starts_with("local://"));
    assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);

    // local:// + known_hosts: the file may say it, but the domain
    // identity is still Local (a local endpoint never verifies a host).
    let with_kh = local.replace(
        "user = \"u\"",
        "user = \"u\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
    );
    std::fs::write(&p, with_kh).unwrap();
    let cfg = ProjectConfig::load(&p).expect("local:// + known_hosts is allowed");
    assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);

    // local:// + host_key_fingerprint: allowed, still Local.
    let with_fp = local.replace(
        "user = \"u\"",
        "user = \"u\"\nhost_key_fingerprint = \"SHA256:test\"",
    );
    std::fs::write(&p, with_fp).unwrap();
    let cfg = ProjectConfig::load(&p).expect("local:// + fingerprint is allowed");
    assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);

    // local:// + BOTH identity sources: still allowed — the ambiguity
    // rule is scoped to SSH addresses only (the exact same pair is
    // rejected above for an SSH address), and the domain collapses to
    // Local either way.
    let with_both = deploy_toml("v1")
        .replace("address = \"a\"", "address = \"local:///srv/forced\"")
        .replace(
            "host_key_fingerprint = \"SHA256:test\"",
            "host_key_fingerprint = \"SHA256:test\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
        );
    std::fs::write(&p, with_both).unwrap();
    let cfg = ProjectConfig::load(&p).expect("local:// + both identities is allowed");
    assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);
}

/// Every user-written config surface is strict: an unknown key fails at
/// load time with serde's standard wording instead of being silently
/// ignored (`deny_unknown_fields` on every config struct).
#[test]
fn unknown_fields_are_rejected_across_all_config_surfaces() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    let base = deploy_toml("v1");

    // Unknown top-level key in deploy.toml.
    std::fs::write(
        &p,
        base.replace(
            "schema_version = 2",
            "schema_version = 2\nadapterr = \"none\"",
        ),
    )
    .unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown top-level key must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("adapterr") && msg.contains("unknown field"),
        "error must name the unknown top-level field, got: {msg}"
    );

    // Unknown field inside a [[servers]] entry.
    std::fs::write(
        &p,
        base.replace("user = \"u\"", "user = \"u\"\nreserve_byts = 1"),
    )
    .unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown server field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("reserve_byts") && msg.contains("unknown field"),
        "error must name the unknown server field, got: {msg}"
    );

    // Unknown field inside a variant's [activation] table.
    let bad_variant =
        MINIMAL_VARIANT.replace("adapter = \"none\"", "adapter = \"none\"\nreserve_byts = 1");
    std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown activation field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("reserve_byts") && msg.contains("unknown field"),
        "error must name the unknown activation field, got: {msg}"
    );

    // Unknown field inside a variant's [[slots]] entry (slots are declared
    // in the variant files, and every struct stays strict there too).
    let bad_slot_variant = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\nreserve_byts = 1\ndeploy_dir = \"/srv/forced\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), bad_slot_variant).unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown slot field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("reserve_byts") && msg.contains("unknown field"),
        "error must name the unknown slot field, got: {msg}"
    );

    // Slots moved INTO the variant files: a top-level `[[slots]]` block in
    // deploy.toml is now an unknown field on the manifest.
    let with_top_slots =
        format!("{base}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ndeploy_dir = \"/srv/forced\"\n");
    std::fs::write(&p, with_top_slots).unwrap();
    let err = ProjectConfig::load(&p).expect_err("top-level [[slots]] must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("slots") && msg.contains("unknown field"),
        "error must name the unknown top-level slots field, got: {msg}"
    );

    // Enums reject unknown variants by default (no attribute needed).
    let err = toml::from_str::<Mapping>("from = \"a\"\nto = \"b\"\nconflict = \"nope\"")
        .expect_err("unknown conflict variant must fail");
    assert!(err.to_string().contains("unknown variant"), "got: {err}");

    // Strict mapping semantics: only `conflict = \"error\"` is valid —
    // `replace` and `keep` are rejected at parse (they no longer exist),
    // and `optional` was removed (deny_unknown_fields refuses it).
    for rejected in ["replace", "keep"] {
        let err = toml::from_str::<Mapping>(&format!(
            "from = \"a\"\nto = \"b\"\nconflict = \"{rejected}\""
        ))
        .expect_err("non-error conflict policies must be rejected");
        assert!(
            err.to_string().contains("unknown variant"),
            "conflict = \"{rejected}\" must fail at parse, got: {err}"
        );
    }
    let err = toml::from_str::<Mapping>("from = \"a\"\nto = \"b\"\noptional = true")
        .expect_err("optional sources must be rejected");
    assert!(
        err.to_string().contains("unknown field"),
        "optional = true must fail at parse, got: {err}"
    );

    // The known-good fixtures still load under the strict rules.
    let fixture = project.join("deploy.toml");
    std::fs::write(&fixture, base).unwrap();
    std::fs::write(
        project.join("releases/v1/standard.toml"),
        format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
    )
    .unwrap();
    ProjectConfig::load(&fixture).expect("known-good config still loads");
}

/// One server runs exactly one generation, so two member slots of the same
/// target can never share a server: a target with multiple slots on the
/// same server is rejected (the per-target `current` pointer names a
/// single generation).
#[test]
fn target_may_not_have_multiple_slots_on_one_server() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    // A second slot in the SAME target on the SAME server.
    let dup = format!(
        "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced-2\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("two slots of one target on one server must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("target 't1' has multiple slots on server 's1'"),
        "error must name the target and the shared server, got: {msg}"
    );

    // The same two slots split across TWO servers is valid.
    let ok = format!(
        "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s2\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced-2\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), ok).unwrap();
    let two_servers = deploy_toml("v1").replacen(
        "[targets.t1]",
        "[[servers]]\nid = \"s2\"\naddress = \"b\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[targets.t1]",
        1,
    );
    std::fs::write(&p, two_servers).unwrap();
    let cfg = ProjectConfig::load(&p).expect("two slots on distinct servers are valid");
    assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1", "p2"]);
}

/// The per-target one-server rule is scoped to a SINGLE target: two slots
/// on one server in the SAME target are rejected, but the same two slots
/// may share that server when they belong to DIFFERENT targets (each
/// target's per-server uniqueness is checked independently).
#[test]
fn same_server_in_different_targets_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
    std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();

    // p1 (t1) and p2 (t2) on the SAME server s1: each target has exactly
    // one slot on s1, so the config is valid — the one-server rule is
    // per-target, not global.
    let split = format!(
        "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), split).unwrap();
    let cfg =
        ProjectConfig::load(&p).expect("two slots on one server in different targets are valid");
    assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
    assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);

    // The same two slots BOTH in t1 (same server) is rejected — the
    // per-target check fires.
    let same = format!(
        "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced-2\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), same).unwrap();
    let err = ProjectConfig::load(&p).expect_err("two slots of one target on one server must fail");
    assert!(
        err.to_string()
            .contains("target 't1' has multiple slots on server 's1'"),
        "error must name the target and the shared server, got: {err}"
    );

    // Two slots on the SAME server, each owned by a DIFFERENT target, is
    // valid: each target has one slot per server, and the (server,
    // deploy_dir) locations are unique.
    let two = format!(
        "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced\"\n\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
    );
    std::fs::write(project.join("releases/v1/standard.toml"), two).unwrap();
    let cfg =
        ProjectConfig::load(&p).expect("two slots on one server in different targets is valid");
    assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
    assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);
}

/// Capacity is a per-SERVER policy: a `[capacity]` table inside a variant
/// file is an unknown field on the variant surface and must be rejected by
/// `deny_unknown_fields` (it is NOT per-variant configuration).
#[test]
fn variant_file_capacity_block_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let bad = format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[capacity]\nreserve_bytes = 1\n");
    std::fs::write(project.join("releases/v1/standard.toml"), bad).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("[capacity] inside a variant must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("capacity") && msg.contains("unknown field"),
        "error must name the unknown capacity table, got: {msg}"
    );
}

/// The SSH port defaults to 22 and is NOT a host-identity source: a server
/// with only a `port` (no known_hosts / no fingerprint) is still rejected
/// under the exactly-one rule.
#[test]
fn server_port_defaults_to_22_and_is_not_an_identity_source() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");

    // Omitted port defaults to 22.
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let cfg = ProjectConfig::load(&p).expect("config loads");
    assert_eq!(
        cfg.server("s1").unwrap().port(),
        22,
        "default SSH port is 22"
    );

    // `port` alone does not satisfy the exactly-one identity rule.
    let port_only = deploy_toml("v1")
        .replace("host_key_fingerprint = \"SHA256:test\"\n", "")
        .replace("user = \"u\"", "user = \"u\"\nport = 2200");
    std::fs::write(&p, port_only).unwrap();
    let err = ProjectConfig::load(&p).expect_err("port-only server must still be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("exactly one of known_hosts or host_key_fingerprint"),
        "port must not count as an identity source, got: {msg}"
    );

    // An explicit port WITH exactly one identity loads and is carried.
    let with_port = deploy_toml("v1").replace("user = \"u\"", "user = \"u\"\nport = 2200");
    std::fs::write(&p, with_port).unwrap();
    let cfg = ProjectConfig::load(&p).expect("explicit port with one identity is valid");
    assert_eq!(cfg.server("s1").unwrap().port(), 2200);
}

/// `deny_unknown_fields` extends to the remaining user-written surfaces:
/// the variant's `[verification]` table, the top-level `[targets.t1.rollout]`
/// table, a variant's `[[artifact.mappings]]` entries, and the retention
/// policy tables.
#[test]
fn unknown_fields_rejected_in_verification_rollout_mapping_and_retention() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    let base = deploy_toml("v1");

    // Unknown field inside a variant's [verification] table.
    let bad_ver = MINIMAL_VARIANT.replace(
        "adapter = \"command\"",
        "adapter = \"command\"\nretries = 3",
    );
    std::fs::write(project.join("releases/v1/standard.toml"), bad_ver).unwrap();
    std::fs::write(&p, base.clone()).unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown verification field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("retries") && msg.contains("unknown field"),
        "error must name the unknown verification field, got: {msg}"
    );

    // Unknown field inside a top-level [targets.t1.rollout] table.
    let bad_rollout = base.replace(
        "rollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }",
        "rollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\", max_parallel = 4 }",
    );
    std::fs::write(project.join("releases/v1/standard.toml"), MINIMAL_VARIANT).unwrap();
    std::fs::write(&p, bad_rollout).unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown rollout field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("max_parallel") && msg.contains("unknown field"),
        "error must name the unknown rollout field, got: {msg}"
    );

    // Unknown field inside a variant's [[artifact.mappings]] entry.
    let mapping_variant = r#"
[[artifact.mappings]]
from = "a"
to = "b"
conflic = "replace"

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
    std::fs::write(project.join("releases/v1/standard.toml"), mapping_variant).unwrap();
    std::fs::write(&p, base).unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown mapping field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("conflic") && msg.contains("unknown field"),
        "error must name the unknown mapping field, got: {msg}"
    );

    // Unknown field inside the variant's [retention] tables (retention is
    // slot-owned — it lives in the slot's owning variant file).
    let bad_retention = format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n{STANDARD_ROTATION}")
        .replacen(
            "[retention.per_server]",
            "[retention]\nprotect_nothing = 1\n\n[retention.per_server]",
            1,
        );
    std::fs::write(project.join("releases/v1/standard.toml"), bad_retention).unwrap();
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    let err = ProjectConfig::load(&p).expect_err("unknown retention field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("protect_nothing") && msg.contains("unknown field"),
        "error must name the unknown retention field, got: {msg}"
    );
}

// ---- config vs ledger schema-version independence --------------------

/// The full candidate set the cross-version property ranges over: BOTH
/// supported versions (`CONFIG_SCHEMA_VERSION`, `LEDGER_SCHEMA_VERSION`),
/// each ±1, zero, and `u32::MAX`.
fn schema_version_candidates() -> Vec<u32> {
    let mut v = vec![
        CONFIG_SCHEMA_VERSION,
        LEDGER_SCHEMA_VERSION,
        CONFIG_SCHEMA_VERSION.wrapping_sub(1),
        CONFIG_SCHEMA_VERSION.wrapping_add(1),
        LEDGER_SCHEMA_VERSION.wrapping_sub(1),
        LEDGER_SCHEMA_VERSION.wrapping_add(1),
        0,
        u32::MAX,
    ];
    v.sort_unstable();
    v.dedup();
    v
}

fn schema_version_candidate() -> impl Strategy<Value = u32> {
    prop::sample::select(schema_version_candidates())
}

/// A minimal but VALID ledger intent for target `t1` (EXACT key-set
/// equality: `slot_ids == desired.keys() == pre_push.keys()`).
fn intended_intent(dep: &str) -> DeploymentIntent {
    let p1 = SlotId::new("p1".to_string());
    // ONE slot table (the membership + desired/pre-push entries).
    let slots = std::collections::BTreeMap::from([(
        p1.clone(),
        IntentSlot {
            desired: DesiredGeneration {
                generation: test_generation_id("gen-1"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("tree-1"),
                },
            },
            pre_push: None,
        },
    )]);
    DeploymentIntent {
        deployment_id: test_deployment_id(dep),
        target: TargetName::new("t1".to_string()),
        group: None,
        behavior_sha256: "sha256-aa".to_string(),
        attempted_at: "2026-01-01T00:00:00Z".to_string(),
        slots: NonEmptySlotTable::build(slots)
            .expect("a fixture intent always has at least one slot"),
    }
}

/// The supported versions load together: a project config at
/// `CONFIG_SCHEMA_VERSION` and the same store's ledger at
/// `LEDGER_SCHEMA_VERSION` both decode.
#[test]
fn config_at_config_schema_and_ledger_at_ledger_schema_load() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    ProjectConfig::load(&p).expect("a config at CONFIG_SCHEMA_VERSION must load");

    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(
        &intended_intent("deploy-ok"),
    )))
    .unwrap();
    let lp = store.ledger_path("t1");
    std::fs::create_dir_all(lp.parent().unwrap()).unwrap();
    std::fs::write(&lp, format!("{line}\n")).unwrap();
    let entries = store
        .read_ledger("t1")
        .expect("a ledger at LEDGER_SCHEMA_VERSION must read");
    assert_eq!(entries.len(), 1);
}

/// Swapping the versions on either side fails THAT SIDE ONLY: a config
/// carrying a foreign `schema_version` fails the config reader while the
/// same store's ledger at `LEDGER_SCHEMA_VERSION` still decodes, and a
/// ledger carrying a foreign `deployment_schema_version` fails the
/// ledger reader while the config at `CONFIG_SCHEMA_VERSION` still
/// loads. The two gates are independent: tampering one side never
/// affects the other.
#[test]
fn schema_version_swap_fails_only_the_swapped_side() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    let store = LocalStore::with_base(dir.path().join("store")).unwrap();

    // CONFIG side tampered (a foreign version on the config field): the
    // config reader fails closed ...
    std::fs::write(
        &p,
        deploy_toml("v1").replace(
            "schema_version = 2",
            &format!("schema_version = {}", CONFIG_SCHEMA_VERSION.wrapping_add(1)),
        ),
    )
    .unwrap();
    let err =
        ProjectConfig::load(&p).expect_err("a foreign config schema_version must fail closed");
    assert!(
        err.to_string().contains("schema_version"),
        "the config error must name the version field, got: {err}"
    );
    // ... while the SAME store's ledger at LEDGER_SCHEMA_VERSION is
    // untouched by the config tamper and still decodes.
    let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(
        &intended_intent("deploy-a"),
    )))
    .unwrap();
    let lp = store.ledger_path("t1");
    std::fs::create_dir_all(lp.parent().unwrap()).unwrap();
    std::fs::write(&lp, format!("{line}\n")).unwrap();
    assert_eq!(
        store.read_ledger("t1").unwrap().len(),
        1,
        "a config-side version tamper must not affect ledger decoding"
    );

    // Restore the config at CONFIG_SCHEMA_VERSION ...
    std::fs::write(&p, deploy_toml("v1")).unwrap();
    ProjectConfig::load(&p).expect("the config at CONFIG_SCHEMA_VERSION still loads");
    // ... and tamper ONLY the ledger line: the ledger reader fails
    // closed, naming the version ... (the version is a WIRE member — the
    // domain no longer carries it, so the tamper sets it on the wire
    // form).
    let foreign = intended_intent("deploy-b");
    let mut wire = LedgerIntentWire::from(&foreign);
    wire.deployment_schema_version = LEDGER_SCHEMA_VERSION.wrapping_add(1);
    let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
    std::fs::write(&lp, format!("{line}\n")).unwrap();
    let err = store
        .read_ledger("t1")
        .expect_err("a foreign deployment_schema_version must fail closed");
    assert!(
        err.to_string().contains("deployment_schema_version"),
        "the ledger error must name the version field, got: {err}"
    );
    // ... and the CONFIG is untouched by the ledger tamper.
    ProjectConfig::load(&p).expect("the config still loads after the ledger-side tamper");
}

proptest! {
    // THE CROSS-VERSION INDEPENDENCE PROPERTY: the configuration and
    // the deployment ledger version themselves on INDEPENDENT axes. For
    // every (config_version, ledger_version) combination — ranging over
    // BOTH supported values, each ±1, zero, and u32::MAX — each reader
    // decodes exactly by its OWN constant: the config reader accepts the
    // config iff `schema_version == CONFIG_SCHEMA_VERSION`, and the
    // ledger reader accepts the ledger iff
    // `deployment_schema_version == LEDGER_SCHEMA_VERSION`. Changing one
    // side's version never affects the other side's decoding.
    //
    // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
    // failure persistence — the identical vectors on every run.
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn config_and_ledger_schema_versions_decode_independently(
        config_version in schema_version_candidate(),
        ledger_version in schema_version_candidate(),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        std::fs::write(
            &p,
            deploy_toml("v1").replace(
                "schema_version = 2",
                &format!("schema_version = {config_version}"),
            ),
        )
        .unwrap();

        // The config reader accepts exactly CONFIG_SCHEMA_VERSION — a
        // foreign value (including LEDGER_SCHEMA_VERSION once the two
        // constants diverge) is refused, independently of the ledger.
        let config_accepted = ProjectConfig::load(&p).is_ok();
        assert_eq!(
            config_accepted,
            config_version == CONFIG_SCHEMA_VERSION,
            "config schema_version {config_version} must load iff it equals CONFIG_SCHEMA_VERSION"
        );

        // The ledger reader accepts exactly LEDGER_SCHEMA_VERSION on the
        // intent line — a foreign value is refused, independently of the
        // config.
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let intent = intended_intent("deploy-x");
        let mut wire = LedgerIntentWire::from(&intent);
        wire.deployment_schema_version = ledger_version;
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        let lp = store.ledger_path("t1");
        std::fs::create_dir_all(lp.parent().unwrap()).unwrap();
        std::fs::write(&lp, format!("{line}\n")).unwrap();
        let ledger_accepted = store.read_ledger("t1").is_ok();
        assert_eq!(
            ledger_accepted,
            ledger_version == LEDGER_SCHEMA_VERSION,
            "ledger deployment_schema_version {ledger_version} must read iff it equals LEDGER_SCHEMA_VERSION"
        );
    }
}

// =====================================================================
// RawConfig -> DomainConfig conversion: total-fail-closed
// =====================================================================
//
// The deterministic per-rule tests below drive the raw -> domain
// conversion DIRECTLY (no filesystem): each invalid input class must be
// rejected with a conversion error, and each valid minimal input must
// produce a domain whose invariants hold — asserted by INSPECTING the
// DomainConfig (the typed enums, the resolved references), never by
// re-running the validation.

/// The minimal VALID raw project: local server `s1`, one target `t1`,
/// one variant `standard` (adapter none, command verification) declaring
/// slot `p1` on `s1` bound to `t1`.
fn minimal_raw_project() -> RawProject {
    RawProject {
        manifest: raw::RawConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            application: "app".to_string(),
            release: ReleaseName::new("v1"),
            pins: Vec::new(),
            servers: vec![raw::RawServer {
                id: "s1".to_string(),
                address: "local:///srv".to_string(),
                user: "u".to_string(),
                port: 22,
                known_hosts: None,
                host_key_fingerprint: None,
                capacity: raw::RawCapacityConfig::default(),
            }],
            targets: BTreeMap::from([(
                "t1".to_string(),
                raw::RawTargetConfig {
                    rollout: raw::RawRolloutConfig::default(),
                },
            )]),
        },
        variants: BTreeMap::from([("standard".to_string(), minimal_raw_variant())]),
    }
}

fn minimal_raw_variant() -> raw::RawVariant {
    raw::RawVariant {
        description: None,
        artifact: ArtifactConfig {
            mappings: Vec::new(),
        },
        activation: ActivationConfig {
            adapter: "none".to_string(),
            scope: ActivationScope::User,
            reconcile_managed_units: true,
            units: Vec::new(),
        },
        verification: VerificationConfig {
            adapter: "command".to_string(),
            argv: vec!["true".to_string()],
            timeout_seconds: 5,
            attempts: 1,
            interval_seconds: 0,
        },
        slots: vec![SlotConfig::new(
            "p1",
            "s1",
            PathBuf::from("/srv/p1"),
            "t1",
            Vec::new(),
        )],
        retention: RetentionConfig::default(),
    }
}

/// Mutate the minimal project and require the conversion to fail.
fn expect_conversion_err(project: RawProject, rule: &str) {
    let err = ProjectConfig::from_raw_parts(project.manifest, project.variants).expect_err(rule);
    assert!(
        !err.to_string().is_empty(),
        "conversion error must carry a message for {rule}"
    );
}

#[test]
fn conversion_rejects_wrong_schema_version() {
    let mut p = minimal_raw_project();
    p.manifest.schema_version = CONFIG_SCHEMA_VERSION + 1;
    expect_conversion_err(p, "wrong schema version");
}

#[test]
fn conversion_rejects_invalid_identifiers() {
    // Empty/whitespace-only identifiers are never valid names.
    for id in ["", "   "] {
        let mut p = minimal_raw_project();
        p.manifest.servers[0].id = id.to_string();
        expect_conversion_err(p, "empty server id");

        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().slots[0].id = id.to_string();
        expect_conversion_err(p, "empty slot id");

        let mut p = minimal_raw_project();
        p.manifest.targets = BTreeMap::from([(
            id.to_string(),
            raw::RawTargetConfig {
                rollout: raw::RawRolloutConfig::default(),
            },
        )]);
        p.variants.get_mut("standard").unwrap().slots[0].target = id.to_string();
        expect_conversion_err(p, "empty target name");

        let mut p = minimal_raw_project();
        p.variants = BTreeMap::from([(id.to_string(), minimal_raw_variant())]);
        expect_conversion_err(p, "empty variant name");

        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().slots[0].groups = vec![id.to_string()];
        expect_conversion_err(p, "empty group name");
    }
}

#[test]
fn conversion_rejects_duplicate_identifiers() {
    // Duplicate server ids.
    let mut p = minimal_raw_project();
    p.manifest.servers.push(raw::RawServer {
        id: "s1".to_string(),
        address: "local:///srv-2".to_string(),
        user: "u".to_string(),
        port: 22,
        known_hosts: None,
        host_key_fingerprint: None,
        capacity: raw::RawCapacityConfig::default(),
    });
    expect_conversion_err(p, "duplicate server id");

    // Duplicate slot ids across two variants.
    let mut p = minimal_raw_project();
    p.variants
        .insert("other".to_string(), minimal_raw_variant());
    expect_conversion_err(p, "duplicate slot id across variants");

    // Duplicate group names inside one slot.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().slots[0].groups =
        vec!["canary".to_string(), "canary".to_string()];
    expect_conversion_err(p, "duplicate group name");
}

#[test]
fn conversion_rejects_unresolved_references() {
    // Slot -> unknown server.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().slots[0].server = "ghost".to_string();
    expect_conversion_err(p, "slot references unknown server");

    // Slot -> unknown target.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().slots[0].target = "ghost".to_string();
    expect_conversion_err(p, "slot references unknown target");
}

#[test]
fn conversion_rejects_impossible_identity_combinations() {
    // SSH address with BOTH identity forms.
    let mut p = minimal_raw_project();
    p.manifest.servers[0].address = "db.example.com".to_string();
    p.manifest.servers[0].known_hosts = Some(PathBuf::from("/etc/ssh/known_hosts"));
    p.manifest.servers[0].host_key_fingerprint = Some("SHA256:test".to_string());
    expect_conversion_err(p, "SSH address with both identities");

    // SSH address with NEITHER identity form (no trust-on-first-use).
    let mut p = minimal_raw_project();
    p.manifest.servers[0].address = "db.example.com".to_string();
    expect_conversion_err(p, "SSH address without identity");

    // A relative known_hosts is rejected for every server (local too).
    let mut p = minimal_raw_project();
    p.manifest.servers[0].known_hosts = Some(PathBuf::from("relative/known_hosts"));
    expect_conversion_err(p, "relative known_hosts");

    // A non-SHA256 fingerprint is rejected for every server (local too).
    let mut p = minimal_raw_project();
    p.manifest.servers[0].host_key_fingerprint = Some("md5:deadbeef".to_string());
    expect_conversion_err(p, "malformed fingerprint");

    // Capacity outside its domain is rejected.
    let mut p = minimal_raw_project();
    p.manifest.servers[0].capacity.reserve_percent = 101;
    expect_conversion_err(p, "reserve_percent over 100");
}

#[test]
fn conversion_rejects_impossible_activation_and_verification() {
    // Unknown activation adapter.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().activation.adapter = "docker".to_string();
    expect_conversion_err(p, "unknown activation adapter");

    // systemd activation without units.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().activation = ActivationConfig {
        adapter: "systemd".to_string(),
        scope: ActivationScope::System,
        reconcile_managed_units: true,
        units: Vec::new(),
    };
    expect_conversion_err(p, "systemd without units");

    // Unsupported verification adapter.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().verification.adapter = "systemctl".to_string();
    expect_conversion_err(p, "unsupported verification adapter");

    // Empty verification argv.
    let mut p = minimal_raw_project();
    p.variants
        .get_mut("standard")
        .unwrap()
        .verification
        .argv
        .clear();
    expect_conversion_err(p, "empty verification argv");
}

#[test]
fn conversion_rejects_unsafe_mappings() {
    // Overlapping destinations.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().artifact = ArtifactConfig {
        mappings: vec![
            Mapping {
                from: "a/".to_string(),
                to: "app/".to_string(),
                recursive: true,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
            Mapping {
                from: "b/".to_string(),
                to: "app".to_string(),
                recursive: true,
                conflict: ConflictPolicy::Error,
                mode: None,
            },
        ],
    };
    expect_conversion_err(p, "overlapping mapping destinations");

    // A destination escaping the artifact-relative namespace.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().artifact = ArtifactConfig {
        mappings: vec![Mapping {
            from: "a/".to_string(),
            to: "../escape".to_string(),
            recursive: true,
            conflict: ConflictPolicy::Error,
            mode: None,
        }],
    };
    expect_conversion_err(p, "escaping mapping destination");

    // An invalid octal mode.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().artifact = ArtifactConfig {
        mappings: vec![Mapping {
            from: "a/".to_string(),
            to: "app/".to_string(),
            recursive: true,
            conflict: ConflictPolicy::Error,
            mode: Some("0999".to_string()),
        }],
    };
    expect_conversion_err(p, "invalid octal mode");
}

#[test]
fn conversion_rejects_graph_violations() {
    // No variants.
    let mut p = minimal_raw_project();
    p.variants.clear();
    expect_conversion_err(p, "no variants");

    // No targets.
    let mut p = minimal_raw_project();
    p.manifest.targets.clear();
    expect_conversion_err(p, "no targets");

    // Release name escaping the forced releases/<name>/ layout.
    let mut p = minimal_raw_project();
    p.manifest.release = ReleaseName::new("../v1");
    expect_conversion_err(p, "escaping release name");

    // A target with no member slots.
    let mut p = minimal_raw_project();
    p.manifest.targets.insert(
        "empty".to_string(),
        raw::RawTargetConfig {
            rollout: raw::RawRolloutConfig::default(),
        },
    );
    expect_conversion_err(p, "target without slots");

    // Two slots of one target on one server.
    let mut p = minimal_raw_project();
    p.variants
        .get_mut("standard")
        .unwrap()
        .slots
        .push(SlotConfig::new(
            "p2",
            "s1",
            PathBuf::from("/srv/p2"),
            "t1",
            Vec::new(),
        ));
    expect_conversion_err(p, "two slots of one target on one server");

    // Two slots bound to the same (server, deploy_dir) location.
    let mut p = minimal_raw_project();
    p.variants
        .get_mut("standard")
        .unwrap()
        .slots
        .push(SlotConfig::new(
            "p2",
            "s1",
            PathBuf::from("/srv/p1"),
            "t2",
            Vec::new(),
        ));
    p.manifest.targets.insert(
        "t2".to_string(),
        raw::RawTargetConfig {
            rollout: raw::RawRolloutConfig::default(),
        },
    );
    expect_conversion_err(p, "duplicate server+deploy_dir location");

    // A relative deploy_dir.
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().slots[0].set_deploy_dir(PathBuf::from("srv/p1"));
    expect_conversion_err(p, "relative deploy_dir");
}

/// The minimal valid input converts to a domain whose invariants ALL
/// hold — asserted by inspecting the DomainConfig itself: the typed
/// identity enum, the resolved references, the slot->variant binding, the
/// deterministic membership derivation.
#[test]
fn conversion_accepts_minimal_and_invariants_hold() {
    let p = minimal_raw_project();
    let cfg =
        ProjectConfig::from_raw_parts(p.manifest, p.variants).expect("minimal project converts");

    // The manifest surface is carried through.
    assert_eq!(cfg.schema_version(), CONFIG_SCHEMA_VERSION);
    assert_eq!(cfg.application().as_str(), "app");
    assert_eq!(cfg.release().as_str(), "v1");
    assert_eq!(cfg.targets().count(), 1);

    // A local:// server's identity is EXACTLY ONE form: Local.
    assert_eq!(cfg.servers().count(), 1);
    assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);
    assert!(cfg.server("s1").unwrap().address().starts_with("local://"));

    // The variant carries the typed activation enum (none here), its
    // slot, and its slot-owned retention.
    assert_eq!(cfg.variant_names(), vec!["standard"]);
    assert_eq!(
        cfg.variant("standard").unwrap().activation,
        Activation::None
    );
    assert_eq!(cfg.slot_defs().len(), 1);

    // Every reference resolves and ownership is derived, not repeated:
    // the declaring variant owns the slot and the slot owns its target.
    assert_eq!(cfg.slot_variant("p1").unwrap(), "standard");
    assert!(cfg.slot_variant("ghost").is_err());
    assert_eq!(
        cfg.slot_retention("p1").unwrap(),
        &RetentionConfig::default()
    );
    assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
    let (slot, server) = cfg.target_slots("t1").unwrap()[0];
    assert_eq!(slot.id, "p1");
    assert_eq!(server.id.as_str(), "s1");
    assert_eq!(cfg.target_slot_bindings("t1").unwrap().len(), 1);
}

/// An SSH server with a fingerprint identity converts to the typed
/// [`HostIdentity::Fingerprint`] carrying the validated [`Fingerprint`]
/// value; the transport-view field derives from it.
#[test]
fn conversion_maps_fingerprint_identity_to_typed_enum() {
    let mut p = minimal_raw_project();
    p.manifest.servers[0].address = "db.example.com".to_string();
    p.manifest.servers[0].host_key_fingerprint = Some("SHA256:abc".to_string());
    let cfg =
        ProjectConfig::from_raw_parts(p.manifest, p.variants).expect("fingerprint server converts");
    let HostIdentity::Fingerprint(fp) = cfg.server("s1").unwrap().identity() else {
        panic!("SSH + fingerprint must produce HostIdentity::Fingerprint");
    };
    assert_eq!(fp.as_str(), "SHA256:abc");
    assert_eq!(
        match cfg.server("s1").unwrap().identity() {
            HostIdentity::Fingerprint(f) => Some(f.as_str()),
            _ => None,
        },
        Some("SHA256:abc")
    );
    assert!(!matches!(
        cfg.server("s1").unwrap().identity(),
        HostIdentity::KnownHosts(_)
    ));
}

/// An SSH server with a dedicated known_hosts file resolves to
/// `HostIdentity::KnownHosts`, never to a fingerprint.
#[test]
fn conversion_maps_known_hosts_identity_to_typed_enum() {
    let mut p = minimal_raw_project();
    p.manifest.servers[0].address = "db.example.com".to_string();
    p.manifest.servers[0].known_hosts = Some(PathBuf::from("/etc/ssh/known_hosts"));
    let cfg = ProjectConfig::from_raw_parts(p.manifest, p.variants)
        .expect("known_hosts identity converts");
    assert_eq!(
        cfg.server("s1").unwrap().identity(),
        &HostIdentity::KnownHosts(PathBuf::from("/etc/ssh/known_hosts"))
    );
    assert_eq!(
        match cfg.server("s1").unwrap().identity() {
            HostIdentity::KnownHosts(p) => Some(p.as_path()),
            _ => None,
        },
        Some(Path::new("/etc/ssh/known_hosts"))
    );
    assert!(!matches!(
        cfg.server("s1").unwrap().identity(),
        HostIdentity::Fingerprint(_)
    ));
}

/// A systemd variant converts to the typed `Activation::Systemd` with its
/// scope/units, and the domain -> contract conversion reproduces the
/// canonical serialized activation contract.
#[test]
fn conversion_maps_systemd_activation_to_typed_enum() {
    let mut p = minimal_raw_project();
    p.variants.get_mut("standard").unwrap().activation = ActivationConfig {
        adapter: "systemd".to_string(),
        scope: ActivationScope::System,
        reconcile_managed_units: true,
        units: vec![UnitDef {
            name: "app.service".to_string(),
            artifact_path: "app.service".to_string(),
            enable: true,
            restart: true,
        }],
    };
    let cfg =
        ProjectConfig::from_raw_parts(p.manifest, p.variants).expect("systemd variant converts");
    let Activation::Systemd(sa) = &cfg.variant("standard").unwrap().activation else {
        panic!("systemd adapter must convert to Activation::Systemd");
    };
    assert_eq!(sa.scope, ActivationScope::System);
    assert_eq!(sa.units.len(), 1);
    assert_eq!(sa.units[0].name, "app.service");

    // The domain -> contract conversion is the ONLY path and is
    // canonical: the serialized contract has adapter systemd + the
    // carried scope/units (this is what the behavior digest hashes).
    let contract = ActivationConfig::from(Activation::Systemd(SystemdActivation {
        scope: ActivationScope::System,
        reconcile_managed_units: true,
        units: vec![UnitDef {
            name: "app.service".to_string(),
            artifact_path: "app.service".to_string(),
            enable: true,
            restart: true,
        }],
    }));
    assert_eq!(contract.adapter, "systemd");
    assert_eq!(contract.scope, ActivationScope::System);
    assert_eq!(contract.units.len(), 1);

    // None -> the canonical "none" contract (adapter none, no units).
    let none = ActivationConfig::from(Activation::None);
    assert_eq!(none.adapter, "none");
    assert!(none.units.is_empty());
}

/// `deny_unknown_fields` is a parse-level gate on the raw layer: an
/// unknown key anywhere in the manifest or a variant file is refused at
/// parse, before the conversion ever runs.
#[test]
fn raw_layer_denies_unknown_fields_at_parse() {
    let err = toml::from_str::<raw::RawConfig>(
        "schema_version = 2\napplication = \"a\"\nrelease = \"v1\"\nadapterr = \"x\"\n",
    )
    .expect_err("unknown manifest key must fail parse");
    assert!(err.to_string().contains("unknown field"), "got: {err}");

    let err =
        toml::from_str::<raw::RawVariant>("[activation]\nadapter = \"none\"\nadptr = \"x\"\n")
            .expect_err("unknown activation key must fail parse");
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

// =====================================================================
// The property: ARBITRARY raw input is total-fail-closed
// =====================================================================

/// Arbitrary identifier strings: empty, whitespace, duplicates-friendly
/// small alphabets, and arbitrary Unicode.
fn arbitrary_identifier() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            String::new(),
            " ".to_string(),
            "s".to_string(),
            "s1".to_string(),
            "α".to_string(),
            "x y".to_string(),
        ]),
        prop::collection::vec(prop::char::any(), 0..6).prop_map(|v| v.into_iter().collect()),
    ]
}

/// A VALID release id — the exact `rel-sha256-<64 lowercase hex>` form
/// [`ReleaseId::parse`] accepts, built from 64 generated hex digits. The
/// typed mutation APIs only accept typed ids, so every update-op payload
/// is valid by construction; the rebuild-op property is about invariants
/// after successful ops (an op that does not apply simply fails).
fn arbitrary_release_id() -> impl Strategy<Value = ReleaseId> {
    prop::collection::vec(prop::sample::select(b"0123456789abcdef".to_vec()), 64).prop_map(|hex| {
        ReleaseId::parse(&format!("rel-sha256-{}", String::from_utf8(hex).unwrap()))
            .expect("64 lowercase hex chars form a canonical release id")
    })
}

fn arbitrary_path() -> impl Strategy<Value = PathBuf> {
    prop::sample::select(vec![
        PathBuf::from("/etc/ssh/known_hosts"),
        PathBuf::from("/srv/deploy/p1"),
        PathBuf::from("relative/x"),
        PathBuf::new(),
    ])
}

fn arbitrary_identity_pair() -> impl Strategy<Value = (Option<PathBuf>, Option<String>)> {
    prop_oneof![
        Just((None, None)),
        Just((None, Some("SHA256:test".to_string()))),
        Just((Some(PathBuf::from("/etc/ssh/known_hosts")), None)),
        Just((Some(PathBuf::from("relative/kh")), None)),
        Just((None, Some("md5:x".to_string()))),
        Just((
            Some(PathBuf::from("/etc/ssh/known_hosts")),
            Some("SHA256:test".to_string()),
        )),
    ]
}

fn arbitrary_server() -> impl Strategy<Value = raw::RawServer> {
    (
        arbitrary_identifier(),
        prop_oneof![
            Just("local:///srv".to_string()),
            Just("db.example.com".to_string()),
            arbitrary_identifier(),
        ],
        arbitrary_identifier(),
        any::<u16>(),
        arbitrary_identity_pair(),
        arbitrary_capacity(),
    )
        .prop_map(
            |(id, address, user, port, (known_hosts, host_key_fingerprint), capacity)| {
                raw::RawServer {
                    id,
                    address,
                    user,
                    port,
                    known_hosts,
                    host_key_fingerprint,
                    capacity,
                }
            },
        )
}

fn arbitrary_capacity() -> impl Strategy<Value = raw::RawCapacityConfig> {
    (any::<u64>(), 0u8..200).prop_map(|(reserve_bytes, reserve_percent)| raw::RawCapacityConfig {
        reserve_bytes,
        reserve_percent,
    })
}

fn arbitrary_activation() -> impl Strategy<Value = ActivationConfig> {
    (
        prop::sample::select(vec![
            "none".to_string(),
            "systemd".to_string(),
            "bogus".to_string(),
            "".to_string(),
        ]),
        any::<bool>(),
        prop::collection::vec(
            (
                arbitrary_identifier(),
                arbitrary_identifier(),
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(|(name, artifact_path, enable, restart)| UnitDef {
                    name,
                    artifact_path,
                    enable,
                    restart,
                }),
            0..2,
        ),
    )
        .prop_map(
            |(adapter, reconcile_managed_units, units)| ActivationConfig {
                adapter,
                scope: ActivationScope::System,
                reconcile_managed_units,
                units,
            },
        )
}

fn arbitrary_verification() -> impl Strategy<Value = VerificationConfig> {
    (
        prop::sample::select(vec![
            "command".to_string(),
            "systemctl".to_string(),
            "".to_string(),
        ]),
        prop::collection::vec(arbitrary_identifier(), 0..2),
        any::<u64>(),
        any::<u32>(),
        any::<u64>(),
    )
        .prop_map(
            |(adapter, argv, timeout_seconds, attempts, interval_seconds)| VerificationConfig {
                adapter,
                argv,
                timeout_seconds,
                attempts,
                interval_seconds,
            },
        )
}

fn arbitrary_mapping() -> impl Strategy<Value = Mapping> {
    (
        arbitrary_identifier(),
        arbitrary_identifier(),
        any::<bool>(),
    )
        .prop_map(|(from, to, recursive)| Mapping {
            from,
            to,
            recursive,
            conflict: ConflictPolicy::Error,
            mode: None,
        })
}

fn arbitrary_slot() -> impl Strategy<Value = SlotConfig> {
    (
        arbitrary_identifier(),
        arbitrary_identifier(),
        arbitrary_path(),
        arbitrary_identifier(),
        prop::collection::vec(arbitrary_identifier(), 0..2),
    )
        .prop_map(|(id, server, deploy_dir, target, groups)| {
            SlotConfig::new(id, server, deploy_dir, target, groups)
        })
}

fn arbitrary_raw_variant() -> impl Strategy<Value = raw::RawVariant> {
    (
        prop::option::of(arbitrary_identifier()),
        prop::collection::vec(arbitrary_mapping(), 0..2),
        arbitrary_activation(),
        arbitrary_verification(),
        prop::collection::vec(arbitrary_slot(), 0..3),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(
            |(description, mappings, activation, verification, slots, keep_days, keep_distinct)| {
                raw::RawVariant {
                    description,
                    artifact: ArtifactConfig { mappings },
                    activation,
                    verification,
                    slots,
                    retention: RetentionConfig {
                        per_server: PerServerRetention {
                            keep_distinct_artifacts: keep_distinct,
                            keep_days,
                            protect_previous: true,
                        },
                        deployment: DeploymentRetention {
                            protect_deployments: 0,
                        },
                    },
                }
            },
        )
}

fn arbitrary_target() -> impl Strategy<Value = raw::RawTargetConfig> {
    (any::<u32>(), any::<bool>(), arbitrary_failure_policy()).prop_map(
        |(batch_size, stop_on_failure, failure_policy)| raw::RawTargetConfig {
            rollout: raw::RawRolloutConfig {
                batch_size,
                stop_on_failure,
                failure_policy,
            },
        },
    )
}

/// Both supported policies: the failure-policy dimension of the arbitrary
/// project. The STRICTNESS itself (an unsupported spelling is rejected)
/// is pinned by the parse-table unit test and the arbitrary-strings
/// property below — an arbitrary project cannot carry a policy outside
/// the closed enum, so the conversion's failure-policy gate can only
/// reject at parse time, never by constructing an invalid domain.
fn arbitrary_failure_policy() -> impl Strategy<Value = FailurePolicy> {
    prop_oneof![
        Just(FailurePolicy::RollbackChanged),
        Just(FailurePolicy::LeaveChanged),
    ]
}

/// A fully arbitrary raw project: wrong schema versions, arbitrary ids
/// (empty/duplicate/Unicode), arbitrary references, both/neither
/// identity forms, arbitrary group lists, arbitrary targets and variants.
fn arbitrary_raw_project() -> impl Strategy<Value = RawProject> {
    prop_oneof![
        // Fully arbitrary: explores the entire invalid space.
        (
            prop::collection::vec(arbitrary_server(), 0..3),
            prop::collection::btree_map(arbitrary_identifier(), arbitrary_target(), 0..3),
            prop_oneof![Just(CONFIG_SCHEMA_VERSION), any::<u32>()],
            prop_oneof![Just("v1".to_string()), arbitrary_identifier()],
            prop::collection::vec((arbitrary_identifier(), arbitrary_raw_variant()), 0..3,),
        )
            .prop_map(|(servers, targets, schema_version, release, variants)| {
                RawProject {
                    manifest: raw::RawConfig {
                        schema_version,
                        application: "app".to_string(),
                        release: ReleaseName::new(release),
                        pins: Vec::new(),
                        servers,
                        targets,
                    },
                    variants: variants.into_iter().collect(),
                }
            }),
        // The guaranteed-valid minimal project: some cases always reach
        // the domain so the invariants of every Ok conversion are
        // asserted (bounded seed makes the mix deterministic).
        Just(minimal_raw_project()),
    ]
}

/// Assert the invariants every successful conversion (and every
/// successful validated rebuild operation) must produce: valid + unique
/// identifiers, every reference resolves (slot->server, slot->target,
/// slot->variant, group names), the connection enum is well-formed (a
/// local form carries a `local://` absolute address and a `Local`
/// identity; an SSH form carries a `KnownHosts`/`Fingerprint` identity
/// with an absolute `known_hosts`), the activation enum covers the
/// space, and the per-target graph rules hold. This inspects the
/// DomainConfig itself — it never re-runs the validation.
fn assert_domain_invariants(cfg: &ProjectConfig) {
    let mut server_ids = HashSet::new();
    for s in cfg.servers() {
        assert!(
            valid_identifier(s.id.as_str()),
            "server id must be valid: {:?}",
            s.id
        );
        assert!(
            server_ids.insert(s.id.as_str()),
            "server ids must be unique"
        );
        match s.connection() {
            ServerConnection::Local { address, identity } => {
                assert_eq!(
                    identity,
                    &HostIdentity::Local,
                    "a local connection must carry a Local identity"
                );
                assert!(
                    address.starts_with("local://"),
                    "a local connection must carry a local:// address"
                );
                let path = address.trim_start_matches("local://");
                assert!(
                    Path::new(path).is_absolute(),
                    "a local:// endpoint must be an absolute path"
                );
            }
            ServerConnection::Ssh {
                address,
                user,
                port,
                identity,
            } => {
                assert!(
                    valid_identifier(address.as_str()),
                    "SSH host must be valid: {:?}",
                    address
                );
                assert!(
                    valid_identifier(user.as_str()),
                    "SSH user must be valid: {:?}",
                    user
                );
                assert!(port.get() > 0, "SSH port must be nonzero");
                match identity {
                    HostIdentity::Local => {
                        panic!("an SSH connection cannot carry a Local identity");
                    }
                    HostIdentity::KnownHosts(p) => {
                        assert!(p.is_absolute(), "known_hosts must be absolute");
                    }
                    HostIdentity::Fingerprint(fp) => {
                        assert!(
                            fp.as_str().starts_with("SHA256:"),
                            "fingerprints are format-checked"
                        );
                    }
                }
            }
        }
    }

    let mut variant_names = HashSet::new();
    for name in cfg.variant_names() {
        assert!(
            valid_identifier(&name),
            "variant name must be valid: {name:?}"
        );
        assert!(variant_names.insert(name.clone()), "variant names unique");
        match &cfg.variant(&name).unwrap().activation {
            Activation::None => {}
            Activation::Systemd(sa) => {
                assert!(!sa.units.is_empty(), "systemd requires at least one unit")
            }
        }
    }
    assert!(!variant_names.is_empty(), "at least one variant");

    let mut slot_ids = HashSet::new();
    for slot in cfg.slot_defs() {
        assert!(valid_identifier(&slot.id), "slot id must be valid");
        assert!(
            slot_ids.insert(slot.id.as_str()),
            "slot ids unique across variants"
        );
        assert!(
            cfg.servers().any(|s| s.id.as_str() == slot.server),
            "slot '{}' server must resolve",
            slot.id
        );
        assert!(
            cfg.target(slot.target.as_str()).is_some(),
            "slot '{}' target must resolve",
            slot.id
        );
        assert!(
            slot.deploy_dir().is_absolute(),
            "deploy_dir must be absolute"
        );
        let mut seen_groups = HashSet::new();
        for g in &slot.groups {
            assert!(!g.trim().is_empty(), "group names must be non-empty");
            assert!(seen_groups.insert(g), "group names unique per slot");
        }
        assert!(
            cfg.slot_variant(&slot.id).is_ok(),
            "every slot resolves to its declaring variant"
        );
    }

    for (tname, _) in cfg.targets() {
        assert!(valid_identifier(tname), "target name must be valid");
        let slots = cfg.target_slots(tname).expect("target exists");
        assert!(!slots.is_empty(), "a target must have at least one slot");
        let mut used_servers = HashSet::new();
        for (slot, _) in &slots {
            assert!(
                used_servers.insert(slot.server.as_str()),
                "one slot per server per target"
            );
        }
        // The failure policy is a closed typed enum by construction: the
        // raw string was consumed by the strict parse during the raw ->
        // domain conversion, so every domain target carries EXACTLY one
        // supported policy — an unsupported spelling can never enter a
        // domain (it fails the conversion instead).
        match cfg.target(tname).unwrap().rollout.failure_policy {
            FailurePolicy::RollbackChanged => {}
            FailurePolicy::LeaveChanged => {}
        }
    }
}

proptest! {
    // THE property: arbitrary deserialized raw input must EITHER fail the
    // raw -> domain conversion (any invalid identifier, unresolvable
    // reference, impossible option combination, or schema/unknown-field
    // issue rejects it) OR produce a domain graph whose invariants all
    // hold. Bounded 16 cases, fixed seed 0x5EED_5EED per house style;
    // the generation is pure (no filesystem), so the property stays fast.
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_raw_config_converts_fail_closed(project in arbitrary_raw_project()) {
        if let Ok(cfg) = ProjectConfig::from_raw_parts(project.manifest, project.variants) {
            assert_domain_invariants(&cfg);
        }
        // fail-closed: rejection is a valid outcome for arbitrary input
    }
}

// =====================================================================
// THE PIN-STRING PROPERTY: config load gates EXACTLY on the release-id
// grammar
// =====================================================================
//
// THE USER'S REQUIREMENT: strict `ReleaseId` validation must cover
// configuration pins. The raw wire `[[pins]]` entry carries a plain
// string; the raw -> domain conversion parses EVERY pin's release into
// the typed [`ReleaseId`], so a config loads exactly when every pin
// satisfies the `rel-sha256-<64 lowercase hex>` grammar — and a loaded
// config can never produce a later release-id syntax error (the
// consumers that used to parse the raw string late now receive the
// typed id by construction).

/// Arbitrary RAW pin release strings: canonical valid ids (generated via
/// hex chars) plus every near-miss class the grammar must reject — wrong
/// prefix, non-hex / non-64 / non-lowercase suffix, the bare-digest and
/// `rel-` forms, empty, garbage, Unicode. (The garbage arm may
/// accidentally produce a valid string — the property asserts the
/// equivalence against [`ReleaseId::parse`] itself, so that is fine.)
fn arbitrary_raw_pin_release() -> impl Strategy<Value = String> {
    let digest = crate::identity::test_tree_digest("prop")
        .as_str()
        .to_string();
    prop_oneof![
        // The canonical VALID form: `rel-sha256-` + 64 lowercase hex.
        prop::collection::vec(prop::sample::select(b"0123456789abcdef".to_vec()), 64)
            .prop_map(|hex| { format!("rel-sha256-{}", String::from_utf8(hex).unwrap()) }),
        // Near-misses.
        prop::sample::select(vec![
            String::new(),
            "rel-sha256-".to_string(),
            "rel-sha256".to_string(),
            format!("rel-sha256-{}", &digest[..63]),
            format!("rel-sha256-{}", digest.to_uppercase()),
            format!("rel-sha256-{}", "z".repeat(64)),
            format!("rel-sha256-{}", "0".repeat(63)),
            format!("rel-{digest}"),
            digest.clone(),
            format!("rel-sha256-{digest} "),
            "rel-sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            "rel-sha256-α".to_string(),
            "rel-sha256-0x".to_string(),
            "rel-sha256----".to_string(),
        ]),
        // Arbitrary garbage / Unicode.
        prop::collection::vec(prop::char::any(), 0..80).prop_map(|v| v.into_iter().collect()),
    ]
}

proptest! {
    // THE PROPERTY: over ARBITRARY raw pin-string lists (canonical valid
    // ids, every near-miss class, garbage, Unicode) with arbitrary
    // reasons, config loading succeeds EXACTLY when every pin satisfies
    // the release-id grammar (an invalid pin — the FIRST one — fails the
    // WHOLE load), and every successfully loaded configuration carries
    // typed release ids: for every pin, the parse the consumers used to
    // perform late can never fail. Bounded 16 cases, fixed seed
    // 0x5EED_5EED per house style; generation is pure (no filesystem).
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn raw_pin_strings_gate_config_load_exactly(
        pins in prop::collection::vec(
            (arbitrary_raw_pin_release(), arbitrary_identifier()),
            0..6,
        ),
    ) {
        let mut project = minimal_raw_project();
        project.manifest.pins = pins
            .iter()
            .map(|(release, reason)| raw::RawPin {
                release: release.clone(),
                reason: reason.clone(),
            })
            .collect();
        let every_pin_valid = pins.iter().all(|(r, _)| ReleaseId::parse(r).is_ok());
        let converted = ProjectConfig::from_raw_parts(project.manifest, project.variants);
        assert_eq!(
            converted.is_ok(),
            every_pin_valid,
            "config load must succeed exactly when every pin satisfies the \
             release-id grammar (pins: {pins:?})"
        );
        match converted {
            Ok(cfg) => {
                assert_eq!(cfg.pins().len(), pins.len());
                // THE never-a-later-error guarantee: every pin carries
                // the typed id by construction — the exact statement the
                // late-parsing consumers (history_floor / retention) made
                // can never fail.
                for pin in cfg.pins() {
                    let rid = pin.release.clone();
                    assert_eq!(ReleaseId::parse(rid.as_str()).unwrap(), rid);
                }
                assert_domain_invariants(&cfg);
            }
            Err(err) => {
                // The exactly-direction: a bad pin is present, the load
                // failed closed, and the error names the FIRST bad pin
                // (the conversion stops at the first [`ReleaseId::parse`]
                // failure).
                assert!(!every_pin_valid);
                let (first_bad, _) = pins
                    .iter()
                    .find(|(r, _)| ReleaseId::parse(r).is_err())
                    .expect("at least one bad pin when the load fails");
                let msg = err.to_string();
                assert!(
                    msg.contains(&format!("invalid ReleaseId value {first_bad:?}")),
                    "the load must fail on the FIRST bad pin (message: {msg})"
                );
            }
        }
    }
}

// =====================================================================
// THE REBUILD-OP PROPERTY: validated graph-rebuilding operations
// =====================================================================
//
// THE USER'S REQUIREMENT: the domain graph is IMMUTABLE — every mutation
// is a VALIDATED operation returning a NEW [`ProjectConfig`] (or `Err`
// with the ORIGINAL untouched). The property generates VALID
// configurations plus ARBITRARY update operations (add/remove/rename a
// server, a target, a pin, a slot; change a connection field); every
// SUCCESSFUL result must satisfy the ONE central
// [`assert_domain_invariants`], and every INVALID update must FAIL and
// PRESERVE the original (its accessors are unchanged).

/// A server template: (id, address, user, known_hosts, fingerprint).
type ServerTemplate = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
);

/// A valid raw project by construction: 1..=2 servers from a pool of
/// valid templates, 1..=2 targets, and slots that reference the chosen
/// servers/targets with unique ids and deploy_dirs (one slot per server
/// per target). The conversion always succeeds.
fn valid_raw_project() -> impl Strategy<Value = RawProject> {
    let server_templates: Vec<ServerTemplate> = vec![
        ("s1", "local:///srv/s1", "u", None, None),
        (
            "s2",
            "db.example.com",
            "ops",
            Some("/etc/ssh/known_hosts"),
            None,
        ),
        ("s3", "web.example.com", "deploy", None, Some("SHA256:test")),
    ];
    let target_names: Vec<&str> = vec!["t1", "t2", "t3"];
    prop::sample::subsequence(server_templates, 1..=2).prop_flat_map(move |servers| {
        let n_servers = servers.len();
        prop::sample::subsequence(target_names.clone(), 1..=2).prop_flat_map(move |targets| {
            // One plan per target: distinct server indices (the
            // per-target one-server rule holds by construction).
            let plan = prop::collection::vec(
                prop::sample::subsequence((0..n_servers).collect::<Vec<_>>(), 1..=n_servers),
                targets.len(),
            );
            let servers = servers.clone();
            let targets = targets.clone();
            plan.prop_map(move |plans| {
                let mut raw_servers = Vec::new();
                for (id, address, user, kh, fp) in &servers {
                    raw_servers.push(raw::RawServer {
                        id: id.to_string(),
                        address: address.to_string(),
                        user: user.to_string(),
                        port: 22,
                        known_hosts: kh.map(PathBuf::from),
                        host_key_fingerprint: fp.map(|s| s.to_string()),
                        capacity: raw::RawCapacityConfig::default(),
                    });
                }
                let mut raw_targets = BTreeMap::new();
                for t in &targets {
                    raw_targets.insert(
                        t.to_string(),
                        raw::RawTargetConfig {
                            rollout: raw::RawRolloutConfig::default(),
                        },
                    );
                }
                let mut slots = Vec::new();
                for (t, plan) in targets.iter().zip(&plans) {
                    for (i, &server_idx) in plan.iter().enumerate() {
                        let slot_id = format!("{t}-{i}");
                        slots.push(SlotConfig::new(
                            slot_id.clone(),
                            servers[server_idx].0.to_string(),
                            PathBuf::from(format!("/srv/{slot_id}")),
                            t.to_string(),
                            Vec::new(),
                        ));
                    }
                }
                let mut variant = minimal_raw_variant();
                variant.slots = slots;
                RawProject {
                    manifest: raw::RawConfig {
                        schema_version: CONFIG_SCHEMA_VERSION,
                        application: "app".to_string(),
                        release: ReleaseName::new("v1"),
                        pins: Vec::new(),
                        servers: raw_servers,
                        targets: raw_targets,
                    },
                    variants: BTreeMap::from([("standard".to_string(), variant)]),
                }
            })
        })
    })
}

/// One arbitrary update operation: add/remove/rename a server, a target,
/// a pin, or a slot, or change a server's connection. The payloads are
/// arbitrary (valid or not); the operation either succeeds (the result
/// must satisfy the domain invariants) or fails (the original is
/// untouched).
#[derive(Clone, Debug)]
enum UpdateOp {
    AddServer(ServerDef),
    RemoveServer(String),
    RenameServer(String, String),
    AddTarget(String, TargetConfig),
    RemoveTarget(String),
    RenameTarget(String, String),
    AddPin(Pin),
    RemovePin(ReleaseId),
    RenamePin(ReleaseId, ReleaseId),
    AddSlot(String, SlotConfig),
    RemoveSlot(String, String),
    RenameSlot(String, String, String),
    SetConnection(String, ServerConnection),
}

impl UpdateOp {
    fn apply(&self, config: &ProjectConfig) -> Result<ProjectConfig> {
        match self {
            UpdateOp::AddServer(s) => config.with_server(s.clone()),
            UpdateOp::RemoveServer(id) => config.without_server(id),
            UpdateOp::RenameServer(a, b) => config.rename_server(a, b),
            UpdateOp::AddTarget(n, t) => config.with_target(n, t.clone()),
            UpdateOp::RemoveTarget(n) => config.without_target(n),
            UpdateOp::RenameTarget(a, b) => config.rename_target(a, b),
            UpdateOp::AddPin(p) => config.with_pin(p.clone()),
            UpdateOp::RemovePin(r) => config.without_pin(r),
            UpdateOp::RenamePin(a, b) => config.rename_pin(a, b),
            UpdateOp::AddSlot(v, s) => config.with_slot(v, s.clone()),
            UpdateOp::RemoveSlot(v, s) => config.without_slot(v, s),
            UpdateOp::RenameSlot(v, a, b) => config.rename_slot(v, a, b),
            UpdateOp::SetConnection(id, c) => config.with_server_connection(id, c.clone()),
        }
    }
}

/// An arbitrary host identity: any form, including the impossible
/// combinations the connection well-formedness rule must reject (a
/// `Local` identity inside an SSH connection, a relative `known_hosts`).
fn arbitrary_identity() -> impl Strategy<Value = HostIdentity> {
    prop_oneof![
        Just(HostIdentity::Local),
        prop::sample::select(vec![
            PathBuf::from("/etc/ssh/known_hosts"),
            PathBuf::from("relative/kh"),
        ])
        .prop_map(HostIdentity::KnownHosts),
        Just(HostIdentity::Fingerprint(
            Fingerprint::parse("SHA256:test").unwrap()
        )),
    ]
}

/// An arbitrary connection: a local form with an arbitrary address (valid
/// or not), or an SSH form with arbitrary host/user/port/identity (the
/// identity may be any form, including the impossible `Local` inside an
/// SSH connection).
fn arbitrary_connection() -> impl Strategy<Value = ServerConnection> {
    prop_oneof![
        arbitrary_identifier().prop_map(|address| ServerConnection::Local {
            address,
            identity: HostIdentity::Local,
        }),
        (
            prop::sample::select(vec!["host", "db.example.com", "x y", ""]),
            prop::sample::select(vec!["user", "ops", "x y", ""]),
            any::<u16>(),
            arbitrary_identity(),
        )
            .prop_map(|(address, user, port, identity)| ServerConnection::Ssh {
                address: Host::parse(address).unwrap_or_else(|_| Host::parse("host").unwrap()),
                user: SshUser::parse(user).unwrap_or_else(|_| SshUser::parse("user").unwrap()),
                port: NonZeroU16::new(port).unwrap_or(NonZeroU16::new(1).unwrap()),
                identity,
            }),
    ]
}

/// An arbitrary domain server: a valid id (the scalar is validated by
/// construction) with an arbitrary connection and capacity.
fn arbitrary_server_def() -> impl Strategy<Value = ServerDef> {
    (
        prop::sample::select(vec!["s1", "s2", "s3", "s4", "new-server"]),
        arbitrary_connection(),
        arbitrary_capacity_domain(),
    )
        .prop_map(|(id, connection, capacity)| {
            ServerDef::new(Identifier::parse(id).unwrap(), connection, capacity)
        })
}

/// An arbitrary domain capacity policy (the percent is validated by
/// construction).
fn arbitrary_capacity_domain() -> impl Strategy<Value = CapacityConfig> {
    (any::<u64>(), 0u8..=100).prop_map(|(reserve_bytes, reserve_percent)| CapacityConfig {
        reserve_bytes,
        reserve_percent: CapacityPercent::new(reserve_percent).unwrap(),
    })
}

/// An arbitrary domain target (the batch size is validated by
/// construction).
fn arbitrary_target_domain() -> impl Strategy<Value = TargetConfig> {
    (any::<u32>(), any::<bool>(), arbitrary_failure_policy()).prop_map(
        |(batch_size, stop_on_failure, failure_policy)| TargetConfig {
            rollout: RolloutConfig {
                batch_size: BatchSize::new(u64::from(batch_size))
                    .unwrap_or(BatchSize::new(1).unwrap()),
                stop_on_failure,
                failure_policy,
            },
        },
    )
}

/// An arbitrary update operation over the whole op space.
fn arbitrary_op() -> impl Strategy<Value = UpdateOp> {
    prop_oneof![
        arbitrary_server_def().prop_map(UpdateOp::AddServer),
        arbitrary_identifier().prop_map(UpdateOp::RemoveServer),
        (arbitrary_identifier(), arbitrary_identifier())
            .prop_map(|(a, b)| UpdateOp::RenameServer(a, b)),
        (arbitrary_identifier(), arbitrary_target_domain())
            .prop_map(|(n, t)| UpdateOp::AddTarget(n, t)),
        arbitrary_identifier().prop_map(UpdateOp::RemoveTarget),
        (arbitrary_identifier(), arbitrary_identifier())
            .prop_map(|(a, b)| UpdateOp::RenameTarget(a, b)),
        (arbitrary_release_id(), arbitrary_identifier())
            .prop_map(|(release, reason)| UpdateOp::AddPin(Pin { release, reason })),
        arbitrary_release_id().prop_map(UpdateOp::RemovePin),
        (arbitrary_release_id(), arbitrary_release_id())
            .prop_map(|(a, b)| UpdateOp::RenamePin(a, b)),
        (arbitrary_identifier(), arbitrary_slot()).prop_map(|(v, s)| UpdateOp::AddSlot(v, s)),
        (arbitrary_identifier(), arbitrary_identifier())
            .prop_map(|(v, s)| UpdateOp::RemoveSlot(v, s)),
        (
            arbitrary_identifier(),
            arbitrary_identifier(),
            arbitrary_identifier()
        )
            .prop_map(|(v, a, b)| UpdateOp::RenameSlot(v, a, b)),
        (arbitrary_identifier(), arbitrary_connection())
            .prop_map(|(id, c)| UpdateOp::SetConnection(id, c)),
    ]
}

proptest! {
    // THE PROPERTY: over VALID configurations (generated by construction)
    // plus ARBITRARY update operations, every SUCCESSFUL result satisfies
    // the ONE central [`assert_domain_invariants`] (every reference
    // resolves, ids valid, no impossible combos, the connection enum is
    // well-formed), and every INVALID update FAILS and PRESERVES the
    // original (its accessors are unchanged). Bounded 16 cases, fixed
    // seed 0x5EED_5EED per house style, no failure persistence; the
    // generation is pure (no filesystem), so the property stays fast.
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn validated_rebuild_ops_preserve_invariants(
        project in valid_raw_project(),
        ops in prop::collection::vec(arbitrary_op(), 0..8),
    ) {
        let config = ProjectConfig::from_raw_parts(project.manifest, project.variants)
            .expect("the generated project is valid by construction");
        assert_domain_invariants(&config);
        let mut current = config;
        for op in &ops {
            let original = current.clone();
            match op.apply(&current) {
                Ok(next) => {
                    assert_domain_invariants(&next);
                    current = next;
                }
                Err(_) => {
                    assert_eq!(
                        current, original,
                        "a failed update must leave the original untouched"
                    );
                }
            }
        }
    }
}

// ---- deterministic unit tests per update class ----------------------

/// The minimal valid config used by the per-class unit tests.
fn unit_config() -> ProjectConfig {
    let p = minimal_raw_project();
    ProjectConfig::from_raw_parts(p.manifest, p.variants).expect("minimal project converts")
}

fn ssh_connection() -> ServerConnection {
    ServerConnection::Ssh {
        address: Host::parse("db.example.com").unwrap(),
        user: SshUser::parse("ops").unwrap(),
        port: NonZeroU16::new(2222).unwrap(),
        identity: HostIdentity::Fingerprint(Fingerprint::parse("SHA256:test").unwrap()),
    }
}

#[test]
fn with_server_adds_and_replaces() {
    let cfg = unit_config();
    // Add a new server: succeeds, the graph stays valid.
    let added = cfg
        .with_server(ServerDef::new(
            Identifier::parse("s2").unwrap(),
            ssh_connection(),
            CapacityConfig::default(),
        ))
        .unwrap();
    assert_eq!(added.servers().count(), 2);
    assert_domain_invariants(&added);
    // The original is untouched.
    assert_eq!(cfg.servers().count(), 1);

    // Replace an existing server: succeeds.
    let replaced = added
        .with_server(ServerDef::new(
            Identifier::parse("s1").unwrap(),
            ServerConnection::Local {
                address: "local:///srv/other".to_string(),
                identity: HostIdentity::Local,
            },
            CapacityConfig::default(),
        ))
        .unwrap();
    assert_eq!(replaced.servers().count(), 2);
    assert_domain_invariants(&replaced);

    // An ill-formed connection (SSH with a Local identity) is rejected
    // and the original is untouched.
    let bad = cfg.with_server(ServerDef::new(
        Identifier::parse("s2").unwrap(),
        ServerConnection::Ssh {
            address: Host::parse("db.example.com").unwrap(),
            user: SshUser::parse("ops").unwrap(),
            port: NonZeroU16::new(2222).unwrap(),
            identity: HostIdentity::Local,
        },
        CapacityConfig::default(),
    ));
    assert!(bad.is_err());
    assert_eq!(cfg.servers().count(), 1);
}

#[test]
fn without_server_fails_when_referenced() {
    let cfg = unit_config();
    // s1 is referenced by slot p1: removing it must fail (the graph
    // would dangle); the original is untouched.
    assert!(cfg.without_server("s1").is_err());
    assert_eq!(cfg.servers().count(), 1);
    // An unknown server fails.
    assert!(cfg.without_server("ghost").is_err());
}

#[test]
fn rename_server_rewrites_slot_references() {
    let cfg = unit_config();
    let renamed = cfg.rename_server("s1", "s1b").unwrap();
    assert!(renamed.server("s1").is_none());
    assert!(renamed.server("s1b").is_some());
    // The slot reference was rewritten.
    let (slot, server) = renamed.target_slots("t1").unwrap()[0];
    assert_eq!(slot.server, "s1b");
    assert_eq!(server.id.as_str(), "s1b");
    assert_domain_invariants(&renamed);
    // Renaming onto an existing id fails.
    assert!(cfg.rename_server("s1", "s1").is_err());
}

#[test]
fn with_target_replaces_and_rejects_empty() {
    let cfg = unit_config();
    // Replacing an existing target's rollout succeeds.
    let replaced = cfg
        .with_target(
            "t1",
            TargetConfig {
                rollout: RolloutConfig::default(),
            },
        )
        .unwrap();
    assert_domain_invariants(&replaced);
    // A NEW target with no member slots fails (the per-target non-empty
    // rule is re-validated); the original is untouched.
    assert!(
        cfg.with_target(
            "t2",
            TargetConfig {
                rollout: RolloutConfig::default()
            }
        )
        .is_err()
    );
    assert!(cfg.target("t2").is_none());
}

#[test]
fn without_target_fails_when_referenced() {
    let cfg = unit_config();
    // t1 is referenced by slot p1: removing it must fail; the original
    // is untouched.
    assert!(cfg.without_target("t1").is_err());
    assert!(cfg.target("t1").is_some());
    // An unknown target fails.
    assert!(cfg.without_target("ghost").is_err());
}

#[test]
fn rename_target_rewrites_slot_references() {
    let cfg = unit_config();
    let renamed = cfg.rename_target("t1", "t1b").unwrap();
    assert!(renamed.target("t1").is_none());
    assert!(renamed.target("t1b").is_some());
    let (slot, _) = renamed.target_slots("t1b").unwrap()[0];
    assert_eq!(slot.target, "t1b");
    assert_domain_invariants(&renamed);
    // Renaming to the same name is a valid no-op.
    let same = cfg.rename_target("t1", "t1").unwrap();
    assert_eq!(same.target_slot_ids("t1").unwrap(), vec!["p1"]);
}

#[test]
fn pin_ops_add_remove_rename() {
    let cfg = unit_config();
    let pin = Pin {
        release: crate::identity::test_release_id("rel-1"),
        reason: "known-good".to_string(),
    };
    let added = cfg.with_pin(pin.clone()).unwrap();
    assert_eq!(added.pins().len(), 1);
    assert_eq!(added.pins()[0].release, pin.release);
    // Removing a pin that is not present fails.
    assert!(cfg.without_pin(&pin.release).is_err());
    let removed = added.without_pin(&pin.release).unwrap();
    assert!(removed.pins().is_empty());
    // Renaming rewrites the release (both ids are typed, so the new
    // release is valid by construction).
    let other = crate::identity::test_release_id("rel-2");
    let renamed = added.rename_pin(&pin.release, &other).unwrap();
    assert_eq!(renamed.pins()[0].release, other);
    assert!(
        added
            .rename_pin(
                &crate::identity::test_release_id("rel-9"),
                &crate::identity::test_release_id("rel-3")
            )
            .is_err()
    );
}

#[test]
fn with_slot_adds_and_rejects_invalid() {
    let cfg = unit_config();
    // Add a second server, then a slot on it for t1.
    let two = cfg
        .with_server(ServerDef::new(
            Identifier::parse("s2").unwrap(),
            ServerConnection::Local {
                address: "local:///srv/s2".to_string(),
                identity: HostIdentity::Local,
            },
            CapacityConfig::default(),
        ))
        .unwrap();
    let added = two
        .with_slot(
            "standard",
            SlotConfig::new("p2", "s2", "/srv/p2", "t1", Vec::new()),
        )
        .unwrap();
    assert_eq!(added.slot_defs().len(), 2);
    assert_domain_invariants(&added);

    // A slot referencing an unknown server is rejected; the original is
    // untouched.
    assert!(
        two.with_slot(
            "standard",
            SlotConfig::new("p2", "ghost", "/srv/p2", "t1", Vec::new())
        )
        .is_err()
    );
    assert_eq!(two.slot_defs().len(), 1);

    // A relative deploy_dir is rejected.
    assert!(
        two.with_slot(
            "standard",
            SlotConfig::new("p2", "s2", "srv/p2", "t1", Vec::new())
        )
        .is_err()
    );

    // Replacing an existing slot (keyed by id) is a valid update.
    let replaced = two
        .with_slot(
            "standard",
            SlotConfig::new("p1", "s2", "/srv/p2", "t1", Vec::new()),
        )
        .unwrap();
    assert_eq!(replaced.slot_defs().len(), 1);
    assert_eq!(replaced.slot_defs()[0].server, "s2");
    assert_domain_invariants(&replaced);

    // An unknown variant is rejected.
    assert!(
        two.with_slot(
            "ghost",
            SlotConfig::new("p2", "s2", "/srv/p2", "t1", Vec::new())
        )
        .is_err()
    );
}

#[test]
fn without_slot_fails_when_target_loses_all_members() {
    let cfg = unit_config();
    // Removing the only slot of t1 leaves t1 without members: rejected;
    // the original is untouched.
    assert!(cfg.without_slot("standard", "p1").is_err());
    assert_eq!(cfg.slot_defs().len(), 1);
    // An unknown slot fails.
    assert!(cfg.without_slot("standard", "ghost").is_err());
}

#[test]
fn rename_slot_rewrites_the_id() {
    let cfg = unit_config();
    let renamed = cfg.rename_slot("standard", "p1", "p1b").unwrap();
    assert_eq!(renamed.target_slot_ids("t1").unwrap(), vec!["p1b"]);
    assert_domain_invariants(&renamed);
    assert!(cfg.rename_slot("standard", "ghost", "p9").is_err());
}

#[test]
fn with_server_connection_validates_the_enum() {
    let cfg = unit_config();
    // A valid SSH connection replaces the local one.
    let ssh = cfg.with_server_connection("s1", ssh_connection()).unwrap();
    assert!(matches!(
        ssh.server("s1").unwrap().connection(),
        ServerConnection::Ssh { .. }
    ));
    assert_domain_invariants(&ssh);

    // An SSH connection with a Local identity is rejected; the original
    // is untouched.
    let bad = cfg.with_server_connection(
        "s1",
        ServerConnection::Ssh {
            address: Host::parse("db.example.com").unwrap(),
            user: SshUser::parse("ops").unwrap(),
            port: NonZeroU16::new(2222).unwrap(),
            identity: HostIdentity::Local,
        },
    );
    assert!(bad.is_err());
    assert!(matches!(
        cfg.server("s1").unwrap().connection(),
        ServerConnection::Local { .. }
    ));

    // A local connection with a non-local address is rejected.
    let bad = cfg.with_server_connection(
        "s1",
        ServerConnection::Local {
            address: "not-local".to_string(),
            identity: HostIdentity::Local,
        },
    );
    assert!(bad.is_err());

    // An unknown server fails.
    assert!(
        cfg.with_server_connection(
            "ghost",
            ServerConnection::Local {
                address: "local:///x".to_string(),
                identity: HostIdentity::Local,
            },
        )
        .is_err()
    );
}

// =====================================================================
// failure_policy: the strict FailurePolicy enum
// =====================================================================
//
// THE BUG this pins: an unknown `failure_policy` spelling used to parse
// into a loose String and silently behave as "leave changed" (fail-open:
// an operator typo kept changed servers in their new state instead of
// rolling back). The policy is now a typed enum whose parse is STRICT
// EXACT — the parse-table test below pins every supported spelling, the
// load-level test pins the fail-closed rejection through the real
// `ProjectConfig::load` path, and the arbitrary-strings property pins the
// accept-only-the-supported-spellings contract over the whole space.

/// The STRICT parse table: the exact supported spellings
/// (`rollback_changed`, `leave_changed`) parse to their variants; every
/// OTHER spelling — case variants, whitespace, dashes, typos, the empty
/// string — is rejected with a config error naming the valid options.
#[test]
fn failure_policy_parse_table_is_strict_exact() {
    // The two supported spellings (matching the existing docs).
    assert_eq!(
        "rollback_changed".parse::<FailurePolicy>().unwrap(),
        FailurePolicy::RollbackChanged
    );
    assert_eq!(
        "leave_changed".parse::<FailurePolicy>().unwrap(),
        FailurePolicy::LeaveChanged
    );
    // The canonical spellings round-trip through Display/as_str.
    assert_eq!(FailurePolicy::RollbackChanged.as_str(), "rollback_changed");
    assert_eq!(FailurePolicy::LeaveChanged.as_str(), "leave_changed");
    assert_eq!(
        FailurePolicy::RollbackChanged.to_string(),
        "rollback_changed"
    );

    // Everything else is REJECTED — exact match, no normalization, no
    // case folding, no whitespace trimming, no aliases.
    for bad in [
        "",
        "rollback",
        "leave",
        "leave-changed",
        "rollback-changed",
        "ROLLBACK_CHANGED",
        "RollbackChanged",
        "Rollback_Changed",
        " rollback_changed",
        "rollback_changed ",
        "rollbackchanged",
        "frobnicate",
        "none",
        "roll back changed",
        "rollback_changed\n",
    ] {
        let err = bad
            .parse::<FailurePolicy>()
            .expect_err("unsupported spelling must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("failure_policy") && msg.contains(&format!("'{bad}'")),
            "error must name the rejected spelling, got: {msg}"
        );
        assert!(
            msg.contains("rollback_changed") && msg.contains("leave_changed"),
            "error must name the valid options, got: {msg}"
        );
    }
}

/// THE BUG end-to-end: an unknown `failure_policy` spelling in a real
/// `deploy.toml` is rejected at `ProjectConfig::load` (the merged raw -> domain
/// conversion) with a config error naming the valid options — it can
/// NEVER silently behave as "leave changed".
#[test]
fn unknown_failure_policy_spelling_is_rejected_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    // Every valid spelling loads; every unsupported spelling fails the
    // whole load with the strict parse error.
    for ok in ["rollback_changed", "leave_changed"] {
        std::fs::write(&p, deploy_toml("v1").replace("rollback_changed", ok)).unwrap();
        ProjectConfig::load(&p).expect("supported spelling loads");
    }
    for bad in ["rollback", "leave", "RollbackChanged", "ROLLBACK"] {
        std::fs::write(&p, deploy_toml("v1").replace("rollback_changed", bad)).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unsupported spelling must fail the load");
        let msg = err.to_string();
        assert!(
            msg.contains("failure_policy") && msg.contains(bad),
            "error must name the rejected spelling, got: {msg}"
        );
        assert!(
            msg.contains("rollback_changed") && msg.contains("leave_changed"),
            "error must name the valid options, got: {msg}"
        );
    }
}

/// The default stays `RollbackChanged` — an omitted `failure_policy` is
/// the safe fail-closed default, never "leave changed".
#[test]
fn failure_policy_defaults_to_rollback_changed() {
    assert_eq!(
        RolloutConfig::default().failure_policy,
        FailurePolicy::RollbackChanged
    );
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    // Drop the failure_policy key entirely (defaults to rollback_changed).
    let minimal_rollout =
        deploy_toml("v1").replace(", failure_policy = \"rollback_changed\" }", " }");
    std::fs::write(&p, minimal_rollout).unwrap();
    let cfg = ProjectConfig::load(&p).expect("omitted failure_policy defaults");
    assert_eq!(
        cfg.targets_ref()["t1"].rollout.failure_policy,
        FailurePolicy::RollbackChanged
    );
}

proptest! {
    // THE STRICT-PARSE PROPERTY: over ARBITRARY strings the failure
    // policy parses iff the string is EXACTLY one of the two supported
    // spellings, and every rejection carries a config error naming the
    // valid options. Bounded 16 cases, fixed seed 0x5EED_5EED (house
    // style), no persistence — the identical vectors on every run. This
    // is the property half of the user's requirement: parsing must be
    // success-only-for-supported-spellings, never an implicit fallback.
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn failure_policy_arbitrary_strings_parse_only_supported_spellings(s in any::<String>()) {
        let parsed = FailurePolicy::from_str(&s);
        match parsed {
            Ok(policy) => {
                assert!(
                    s == "rollback_changed" || s == "leave_changed",
                    "a non-supported string must not parse: {s:?} -> {policy:?}"
                );
                // The parse round-trips to the exact spelling.
                assert_eq!(policy.as_str(), s);
            }
            Err(e) => {
                assert!(
                    s != "rollback_changed" && s != "leave_changed",
                    "the supported spellings must always parse: {s:?}"
                );
                let msg = e.to_string();
                assert!(
                    msg.contains("rollback_changed") && msg.contains("leave_changed"),
                    "the rejection must name the valid options, got: {msg}"
                );
            }
        }
    }
}

// =====================================================================
// THE SCALAR PROPERTY: arbitrary raw scalar values convert iff the scalar
// =====================================================================

/// Arbitrary raw strings for a config scalar field: empty, whitespace,
/// format-violating, out-of-range, and valid forms.
fn arbitrary_scalar_text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            String::new(),
            " ".to_string(),
            "s1".to_string(),
            "production".to_string(),
            "wave-1".to_string(),
            " x".to_string(),
            "x ".to_string(),
            "x y".to_string(),
            "α".to_string(),
            "a\nb".to_string(),
            "/srv/p1".to_string(),
            "/srv/deploy/app".to_string(),
            "srv/relative".to_string(),
        ]),
        prop::collection::vec(prop::char::any(), 0..8).prop_map(|v| v.into_iter().collect()),
    ]
}

/// One scalar-mutation case: the minimal valid raw project with EXACTLY
/// ONE scalar field set to an arbitrary raw value, paired with the
/// scalar's own parse verdict on that value. Each mutation is isolated:
/// no other conversion gate can fire, so the conversion outcome is the
/// scalar outcome exactly.
fn scalar_mutation_project() -> impl Strategy<Value = (RawProject, bool)> {
    prop_oneof![
        // application: ApplicationStoreKey (single safe segment).
        arbitrary_scalar_text().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.manifest.application = v.clone();
            (p, ApplicationStoreKey::parse(&v).is_ok())
        }),
        // slot id: Identifier.
        arbitrary_scalar_text().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.variants.get_mut("standard").unwrap().slots[0].id = v.clone();
            (p, Identifier::parse(&v).is_ok())
        }),
        // variant name: Identifier.
        arbitrary_scalar_text().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.variants = BTreeMap::from([(v.clone(), minimal_raw_variant())]);
            (p, Identifier::parse(&v).is_ok())
        }),
        // slot group (single element: the duplicate rule cannot fire):
        // RolloutGroupName.
        arbitrary_scalar_text().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.variants.get_mut("standard").unwrap().slots[0].groups = vec![v.clone()];
            (p, RolloutGroupName::parse(&v).is_ok())
        }),
        // slot deploy_dir (single slot: the location-uniqueness rule
        // cannot fire): AbsoluteDeployDir.
        arbitrary_scalar_text().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.variants.get_mut("standard").unwrap().slots[0].set_deploy_dir(PathBuf::from(&v));
            (p, AbsoluteDeployDir::parse(&v).is_ok())
        }),
        // batch_size (any u32, including zero): BatchSize.
        any::<u32>().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.manifest.targets.get_mut("t1").unwrap().rollout.batch_size = v;
            (p, BatchSize::new(u64::from(v)).is_ok())
        }),
        // capacity reserve_percent (any u8, including 101..):
        // CapacityPercent.
        any::<u8>().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.manifest.servers[0].capacity.reserve_percent = v;
            (p, CapacityPercent::new(v).is_ok())
        }),
    ]
}

proptest! {
    // THE PROPERTY: over ARBITRARY raw values for each config scalar
    // field (empty, format-violating, out-of-range, invalid), the raw ->
    // domain conversion accepts EXACTLY the values the scalar accepts
    // (non-empty/format for names and the digest, absolute for
    // deploy_dir, nonzero for batch_size, 0..=100 for capacity percent)
    // and rejects everything else with a config error (fail closed).
    // Bounded 16 cases, fixed seed 0x5EED_5EED per house style.
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_scalar_values_convert_fail_closed((project, expected) in scalar_mutation_project()) {
        match ProjectConfig::from_raw_parts(project.manifest, project.variants) {
            Ok(cfg) => {
                assert!(
                    expected,
                    "the conversion must accept exactly the values the scalar accepts"
                );
                // The accepted scalar is carried into the domain.
                assert_domain_invariants(&cfg);
            }
            Err(e) => {
                assert!(
                    !expected,
                    "the conversion must accept a value the scalar accepts, got: {e}"
                );
                assert!(
                    matches!(e, Error::Config(_)),
                    "the rejection must be a config error, got: {e}"
                );
            }
        }
    }
}

// =====================================================================
// application: ONE safe identifier for display AND storage
// =====================================================================
//
// The config's `application` field IS the store key
// ([`crate::identity::ApplicationStoreKey`]): a single safe path segment
// used for both display and storage. The raw -> domain conversion
// parses it AS the store key, so a display name that is not a safe key
// FAILS THE LOAD (fail closed at load, not at the store boundary), and
// a successfully loaded config constructs its LocalStore directly from
// `config.application()` — no fallible identity conversion remains.

#[test]
fn application_name_is_the_store_key_load_and_store() {
    // A SAFE application name LOADS and constructs the store: the
    // config's `application` IS the store key, so the load implies the
    // store construction with no further fallible identity conversion.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    let p = project.join("deploy.toml");
    std::fs::write(
        &p,
        deploy_toml("v1").replace("application = \"forced\"", "application = \"my-app\""),
    )
    .unwrap();
    let cfg = ProjectConfig::load(&p).expect("a safe application name loads");
    assert_eq!(cfg.application().as_str(), "my-app");
    // The store is constructed DIRECTLY from the config's application
    // (the field IS the key): `LocalStore::new(&config.application())`.
    let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
    let store_root = crate::testutil::hermetic_tmpdir_root();
    unsafe { std::env::set_var("TMPDIR", &store_root) };
    let store =
        LocalStore::new(cfg.application()).expect("a loaded config must construct its LocalStore");
    assert_eq!(
        store.base().file_name(),
        Some(std::ffi::OsStr::new("my-app")),
        "the store sits under <base>/<application>"
    );
    unsafe { std::env::remove_var("TMPDIR") };
    let _ = std::fs::remove_dir_all(store_root.join("deploy-test"));

    // An UNSAFE application name (a path separator, a traversal
    // component, or padding) FAILS THE LOAD — fail closed at load, not
    // at the store boundary.
    for bad in ["a/b", "a\\b", "..", ".", "../x", "x/..", " x", "x "] {
        let mut raw = minimal_raw_project();
        raw.manifest.application = bad.to_string();
        let err = ProjectConfig::from_raw_parts(raw.manifest, raw.variants)
            .expect_err("an unsafe application name must fail the load");
        assert!(
            matches!(err, Error::Config(_)),
            "the rejection must be a config error, got: {err}"
        );
    }
}

// -------------------------------------------------------------------
// THE LOAD-IMPLIES-STORE PROPERTY: over ARBITRARY application names
// (empty, `/`/`\`-separated, `.`/`..` traversal, padded, control,
// unicode, and clean single segments), EVERY configuration the raw ->
// domain conversion ACCEPTS must ALSO construct its LocalStore — the
// config's `application` IS the store key (one safe identifier for
// display and storage), so the load implies the store construction
// with NO further fallible identity conversion; and a config whose
// application is not a safe key FAILS THE LOAD (fail closed at load,
// not at the store boundary). The generated alphabet is
// FILESYSTEM-SAFE (every accepted name is encodable on the local
// filesystem), so the store construction is asserted to SUCCEED for
// every accepted config; the full arbitrary space — including
// filesystem-incompatible unicode, which fails the store open with a
// STORE error (fail closed, never an escape) — is pinned by the
// scalar-level store-key property. Bounded 16 cases, fixed seed
// 0x5EED_5EED per house style.
// -------------------------------------------------------------------

/// Arbitrary application-name text over a FILESYSTEM-SAFE alphabet:
/// every identity-relevant class (empty, separators, traversal
/// components, padding, control characters, unicode, clean segments)
/// plus random strings over ASCII printable (minus `/`) and a safe
/// unicode letter — every generated name is encodable on the local
/// filesystem, so a name the conversion accepts ALWAYS constructs its
/// store.
fn arbitrary_application_text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            String::new(),
            " ".to_string(),
            "s1".to_string(),
            "production".to_string(),
            "wave-1".to_string(),
            " x".to_string(),
            "x ".to_string(),
            "x y".to_string(),
            "α".to_string(),
            "a\nb".to_string(),
            "/srv/p1".to_string(),
            "/srv/deploy/app".to_string(),
            "srv/relative".to_string(),
            "..".to_string(),
            ".".to_string(),
            "../x".to_string(),
            "x/..".to_string(),
            "a..b".to_string(),
            "a.b".to_string(),
        ]),
        prop::collection::vec(
            prop::sample::select(vec!['a', 'b', 'c', '1', '2', '-', '_', '.', ' ', 'α']),
            0..8,
        )
        .prop_map(|v| v.into_iter().collect()),
    ]
}

/// One application-mutation case: the minimal valid raw project with
/// ONLY the `application` field set to an arbitrary raw value, paired
/// with the store-key parse verdict on that value. No other conversion
/// gate can fire, so the conversion outcome is the application outcome
/// exactly.
fn application_mutation_project() -> impl Strategy<Value = (RawProject, bool)> {
    arbitrary_application_text().prop_map(|v| {
        let mut p = minimal_raw_project();
        p.manifest.application = v.clone();
        (p, ApplicationStoreKey::parse(&v).is_ok())
    })
}

#[test]
fn loaded_config_always_constructs_its_store() {
    // The property constructs REAL stores via `LocalStore::new`, so the
    // process-global `$TMPDIR` is pointed at a hermetic temp root for
    // the whole run (ENV_LOCK serializes against every other
    // env-mutating test; the closure-form proptest runs all 16 cases in
    // this thread).
    let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
    let store_root = crate::testutil::hermetic_tmpdir_root();
    unsafe { std::env::set_var("TMPDIR", &store_root) };
    proptest!(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    }, |((project, expected) in application_mutation_project())| {
        match ProjectConfig::from_raw_parts(project.manifest, project.variants) {
            Ok(cfg) => {
                assert!(
                    expected,
                    "the conversion must accept exactly the values the store key accepts"
                );
                // THE LOAD IMPLIES THE STORE: the config's application
                // IS the store key — no fallible identity conversion
                // remains between a loaded config and its store.
                LocalStore::new(cfg.application())
                    .expect("a loaded config must construct its LocalStore");
            }
            Err(e) => {
                assert!(
                    !expected,
                    "the conversion must accept a value the store key accepts, got: {e}"
                );
                assert!(
                    matches!(e, Error::Config(_)),
                    "the rejection must be a config error, got: {e}"
                );
            }
        }
    });
    unsafe { std::env::remove_var("TMPDIR") };
    let _ = std::fs::remove_dir_all(store_root.join("deploy-test"));
}

// =====================================================================
// load_release: the validated release-switch (a FRESH load)
// =====================================================================
//
// [`ProjectConfig::load_release`] replaces the old in-memory `with_release`
// mutation: the release switch is a FRESH LOAD of the project with the
// new release selected — the deploy.toml is re-read, the release field is
// overridden, and THAT release's variant files are re-discovered and
// re-validated by the raw -> domain conversion. The property below pins
// the contract: `load_release(path, R)` EQUALS a fresh `ProjectConfig::load`
// of a project configured with R (identical variants, policies, and
// scalars), and a MISSING or INVALID R fails the WHOLE load — no
// partially-switched config can escape.

/// Write a two-release project: `release_a` and `release_b` with
/// DIFFERENT variant files and DIFFERENT policies. Release A declares
/// the single `standard` variant (slot `p1`, retention
/// `keep_distinct_artifacts = keep_a`); release B declares `standard`
/// (slot `p1`, retention `keep_distinct_artifacts = keep_b`) PLUS the
/// extra `extra` variant (no slots) — so the two releases differ in
/// BOTH their variant sets and their retention policies. The shared
/// deploy.toml carries the generated rollout (`batch_size`). Returns
/// the `deploy.toml` path.
fn write_two_release_project(
    project: &Path,
    release_a: &str,
    release_b: &str,
    keep_a: u32,
    keep_b: u32,
    batch_size: u32,
) -> PathBuf {
    let release_a_dir = project.join("releases").join(release_a);
    let release_b_dir = project.join("releases").join(release_b);
    std::fs::create_dir_all(&release_a_dir).unwrap();
    std::fs::create_dir_all(&release_b_dir).unwrap();
    std::fs::write(
        release_a_dir.join("standard.toml"),
        format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[retention.per_server]\nkeep_distinct_artifacts = {keep_a}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        release_b_dir.join("standard.toml"),
        format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[retention.per_server]\nkeep_distinct_artifacts = {keep_b}\n"
        ),
    )
    .unwrap();
    // The extra variant (no slots) makes release B's variant set
    // strictly larger than release A's.
    std::fs::write(release_b_dir.join("extra.toml"), MINIMAL_VARIANT).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(
        &p,
        deploy_toml(release_a).replace("batch_size = 1", &format!("batch_size = {batch_size}")),
    )
    .unwrap();
    p
}

proptest! {
    // THE RELEASE-SWITCH PROPERTY: `load_release(path, R)` is a FRESH,
    // fully-validated load of the project with R selected — it EQUALS a
    // fresh `ProjectConfig::load` of a project configured with R (the two
    // configs are identical: same variants, same policies, same scalars),
    // and a MISSING or INVALID R (no variant files, or a variant file
    // that fails validation) fails the WHOLE load — the Err is a full
    // load failure, no partially-switched config escapes. Bounded 16
    // cases, fixed seed 0x5EED_5EED per house style.
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn load_release_equals_fresh_load_and_fails_closed(
        release_a in "[a-z]{1,4}",
        release_b in "[a-z]{1,4}",
        keep_a in 1u32..=3,
        keep_b in 1u32..=3,
        batch_size in 1u32..=3,
    ) {
        // The two releases must be distinct directories (a rejected case
        // is regenerated by proptest).
        prop_assume!(release_a != release_b);
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let p = write_two_release_project(
            &project, &release_a, &release_b, keep_a, keep_b, batch_size,
        );

        // `load_release(path, R)` EQUALS a fresh `ProjectConfig::load` of
        // a project configured with R: the oracle deploy.toml names R and
        // the two configs are identical (variants, policies, scalars).
        for (release, keep) in [(&release_a, keep_a), (&release_b, keep_b)] {
            std::fs::write(
                &p,
                deploy_toml(release).replace(
                    "batch_size = 1",
                    &format!("batch_size = {batch_size}"),
                ),
            )
            .unwrap();
            let oracle = ProjectConfig::load(&p).expect("the oracle project loads");
            let switched = ProjectConfig::load_release(
                &p,
                ReleaseName::parse(release).expect("a single-component release name parses"),
            )
            .expect("load_release loads the existing release");
            assert_eq!(
                switched, oracle,
                "load_release({release}) must equal a fresh load of a project configured with {release}"
            );
            assert_eq!(switched.release().as_str(), release);
            assert_eq!(
                switched
                    .variant("standard")
                    .unwrap()
                    .retention
                    .per_server
                    .keep_distinct_artifacts,
                keep,
                "the release's own retention policy is loaded"
            );
            assert_eq!(
                switched.targets_ref()["t1"].rollout.batch_size.get(),
                u64::from(batch_size),
                "the rollout scalar is carried identically"
            );
        }

        // The two releases genuinely differ: release B has the extra
        // variant and a different retention policy.
        let a = ProjectConfig::load_release(
            &p,
            ReleaseName::parse(&release_a).expect("a single-component release name parses"),
        )
        .expect("release A loads");
        let b = ProjectConfig::load_release(
            &p,
            ReleaseName::parse(&release_b).expect("a single-component release name parses"),
        )
        .expect("release B loads");
        assert_ne!(a, b, "the two releases' configs must differ");
        assert_eq!(a.variant_names(), vec!["standard".to_string()]);
        assert_eq!(
            b.variant_names(),
            vec!["extra".to_string(), "standard".to_string()]
        );

        // A MISSING release (no variant files) fails the WHOLE load: the
        // Err is a full load failure — no config object escapes.
        let err = ProjectConfig::load_release(
            &p,
            ReleaseName::parse("missing").expect("a single-component release name parses"),
        )
        .expect_err("a release with no variant files must fail the load");
        assert!(
            !err.to_string().is_empty(),
            "the load failure must carry a message"
        );

        // An INVALID release (a variant file that fails validation) fails
        // the WHOLE load: the raw -> domain conversion rejects it.
        let invalid_dir = project.join("releases").join("invalid");
        std::fs::create_dir_all(&invalid_dir).unwrap();
        std::fs::write(
            invalid_dir.join("bad.toml"),
            MINIMAL_VARIANT.replace("adapter = \"none\"", "adapter = \"bogus\""),
        )
        .unwrap();
        let err = ProjectConfig::load_release(
            &p,
            ReleaseName::parse("invalid").expect("a single-component release name parses"),
        )
        .expect_err("a release whose variant file fails validation must fail the load");
        assert!(
            !err.to_string().is_empty(),
            "the load failure must carry a message"
        );
    }
}

#[test]
fn load_release_switches_between_two_releases() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let p = write_two_release_project(&project, "v1", "v2", 1, 5, 2);

    // The oracle: a fresh load of a project configured with each release.
    std::fs::write(
        &p,
        deploy_toml("v1").replace("batch_size = 1", "batch_size = 2"),
    )
    .unwrap();
    let oracle_v1 = ProjectConfig::load(&p).unwrap();
    std::fs::write(
        &p,
        deploy_toml("v2").replace("batch_size = 1", "batch_size = 2"),
    )
    .unwrap();
    let oracle_v2 = ProjectConfig::load(&p).unwrap();

    // load_release(path, R) equals the fresh load of a project configured
    // with R — the switch is a full re-validation, never a partial switch.
    let v1 = ProjectConfig::load_release(&p, ReleaseName::parse("v1").unwrap()).unwrap();
    let v2 = ProjectConfig::load_release(&p, ReleaseName::parse("v2").unwrap()).unwrap();
    assert_eq!(v1, oracle_v1);
    assert_eq!(v2, oracle_v2);
    assert_eq!(v1.release().as_str(), "v1");
    assert_eq!(v2.release().as_str(), "v2");

    // The two releases differ in variants and policies.
    assert_ne!(v1, v2);
    assert_eq!(v1.variant_names(), vec!["standard".to_string()]);
    assert_eq!(
        v2.variant_names(),
        vec!["extra".to_string(), "standard".to_string()]
    );
    assert_eq!(
        v1.variant("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts,
        1
    );
    assert_eq!(
        v2.variant("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts,
        5
    );
}

#[test]
fn load_release_missing_release_fails_the_load() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    // A release directory with NO variant files also fails the load.
    std::fs::create_dir_all(project.join("releases").join("empty")).unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();

    // A release with no directory (and no variant files) fails the WHOLE
    // load: the Err is a full load failure — no config object escapes.
    let err = ProjectConfig::load_release(&p, ReleaseName::parse("missing").unwrap())
        .expect_err("a missing release must fail the load");
    assert!(!err.to_string().is_empty());

    // An EMPTY release directory (no variant files) fails the same way.
    let err = ProjectConfig::load_release(&p, ReleaseName::parse("empty").unwrap())
        .expect_err("a release with no variant files must fail the load");
    assert!(!err.to_string().is_empty());
}

#[test]
fn load_release_invalid_variant_fails_the_load() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    write_standard_release(&project, "v1");
    // A release whose variant file fails validation (unknown activation
    // adapter) fails the WHOLE load: the raw -> domain conversion rejects
    // it — no partially-switched config can escape.
    let bad_dir = project.join("releases").join("bad");
    std::fs::create_dir_all(&bad_dir).unwrap();
    std::fs::write(
        bad_dir.join("bad.toml"),
        MINIMAL_VARIANT.replace("adapter = \"none\"", "adapter = \"bogus\""),
    )
    .unwrap();
    let p = project.join("deploy.toml");
    std::fs::write(&p, deploy_toml("v1")).unwrap();

    let err = ProjectConfig::load_release(&p, ReleaseName::parse("bad").unwrap())
        .expect_err("a release with an invalid variant must fail the load");
    let msg = err.to_string();
    assert!(
        msg.contains("bogus"),
        "the load failure must name the invalid adapter, got: {msg}"
    );
}

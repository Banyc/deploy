use crate::config::domain::RawProject;
use crate::config::domain::tests::{
    MINIMAL_VARIANT, STANDARD_SLOTS, arbitrary_failure_policy, arbitrary_identifier,
    arbitrary_slot, assert_domain_invariants, deploy_toml, minimal_raw_project,
    minimal_raw_variant, write_standard_release,
};
use crate::config::raw;
use crate::config::raw::CONFIG_SCHEMA_VERSION;
use crate::config::{
    CapacityConfig, Fingerprint, HostIdentity, Pin, ProjectConfig, ReleaseName, RolloutConfig,
    ServerConnection, ServerDef, SlotConfig, TargetConfig,
};
use crate::error::Result;
use crate::identity::{BatchSize, CapacityPercent, Host, Identifier, ReleaseId, SshUser};
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use proptest::test_runner::RngSeed;
use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

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
        ("s1", "local", "u", None, None),
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
        // A local connection is PATHLESS: the kind carries no address —
        // the slot's deploy_dir is the sole physical root — so the form is
        // always well-formed.
        Just(ServerConnection::Local {
            identity: HostIdentity::Local
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
                identity
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

proptest! {
    // THE SERIALIZE/RELOAD PROPERTY: over VALID configurations (generated
    // by construction) plus ARBITRARY update operations, every SUCCESSFUL
    // `with_*` result must survive a serialize/reload round trip through the
    // SAME constructor (`from_raw_parts` -> `try_build`): the domain graph
    // is serialized back to the raw wire shapes ([`ProjectConfig::to_raw_parts`])
    // and reloaded, and the reloaded graph is EQUIVALENT — identical,
    // including the injective physical locations (endpoint + effective
    // deploy_dir). The typed leaves serialize to their canonical raw forms
    // and re-parse to the same typed values, and the canonical deploy_dirs
    // are a canonicalization fixed point, so the round trip is the identity.
    // Bounded `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`, fast
    // default), fixed seed 0x5EED_5EED per house style, no failure
    // persistence; the generation is pure (no filesystem), so the property
    // stays fast.
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(16),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn successful_with_ops_survive_serialize_reload(
        project in valid_raw_project(),
        ops in prop::collection::vec(arbitrary_op(), 0..8),
    ) {
        let config = ProjectConfig::from_raw_parts(project.manifest, project.variants)
            .expect("the generated project is valid by construction");
        let mut current = config;
        for op in &ops {
            if let Ok(next) = op.apply(&current) {
                current = next;
            }
        }
        // Serialize the domain graph back to the raw wire shapes and reload
        // through the SAME constructor (from_raw_parts -> try_build): a
        // config built by successful with_* ops must survive the round trip
        // unchanged — the reloaded graph is equivalent, and the injective
        // physical locations are preserved.
        let raw = current.to_raw_parts();
        let reloaded = ProjectConfig::from_raw_parts(raw.manifest, raw.variants)
            .expect("a config built by successful with_* ops must reload");
        assert_eq!(reloaded, current, "the reloaded graph is equivalent");
        assert_domain_invariants(&reloaded);
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

    // A local connection is PATHLESS and always well-formed (the slot's
    // deploy_dir is the sole physical root), so the Local form itself can
    // never be rejected; replacing back to it succeeds.
    let back = cfg
        .with_server_connection(
            "s1",
            ServerConnection::Local {
                identity: HostIdentity::Local,
            },
        )
        .unwrap();
    assert!(matches!(
        back.server("s1").unwrap().connection(),
        ServerConnection::Local { .. }
    ));

    // An unknown server fails.
    assert!(
        cfg.with_server_connection(
            "ghost",
            ServerConnection::Local {
                identity: HostIdentity::Local
            },
        )
        .is_err()
    );
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
    // load failure, no partially-switched config escapes. Bounded `proptest_cases(16)`
    // (full 16 with `DEPLOY_FULL_TESTS=1`, fast default), fixed seed
    // 0x5EED_5EED per house style.
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(16),
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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

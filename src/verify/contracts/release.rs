//! Release identity derivation and verification.
//!
//! The canonical release ID is derived from a versioned canonical identity
//! payload containing the frozen mapping digest, the name-sorted per-variant
//! slot declaration digest, all declared `variant -> tree digest` bindings,
//! and the activation and verification contract digest. It explicitly
//! excludes the resulting release ID, creation time, display name, and
//! provenance, avoiding a circular hash. The per-variant slot declarations
//! (rebind a server, move a `deploy_dir`, retarget) are part of the identity;
//! per-server capacity policy is not.
//!
//! Moved from `crate::release` (area A5). The behavior-contract digest
//! functions live in [`crate::verify::behavior`]; they are re-exported here
//! so the legacy `crate::release::*` surface resolves through
//! [`crate::verify::release`] (including `behavior_digest`, which the
//! integration tests reach as `deploy::verify::release::behavior_digest`).

pub use super::behavior::*;

use crate::config::{Mapping, SlotConfig};
use crate::digest::sha256_bytes;
use crate::error::{Error, Result};
use crate::identity::{
    AbsoluteDeployDir, BehaviorContract, CanonicalReleasePayload, CanonicalSlot, CanonicalSlots,
    Provenance, ReleaseDigest, ReleaseId, ReleaseRecord, RolloutGroupName, ServerId, SlotId,
    TargetName, TreeDigest, VariantName,
};
use jiff::Timestamp;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

/// The canonical release identity PAYLOAD version
/// (`CanonicalReleasePayload.schema_version`), FROZEN INTO the release
/// digest: the field is part of the hashed identity payload, so its value
/// can never change without producing a new release ID. Version 3 is the
/// exclusive-ownership payload: the per-variant canonical slot declaration
/// digest (`slots_digest`) now carries each slot's ONE owning target and
/// its rollout groups (replacing the multi-target `targets` membership
/// list). Read-side enforcement is implicit and fail-closed:
/// `verify_release_identity` recomputes the digest using exactly this
/// version, so a release whose identity was derived from any other payload
/// version fails the recompute-and-verify check.
pub(crate) const RELEASE_PAYLOAD_SCHEMA_VERSION: u32 = 3;

/// The `release.json` record format version
/// (`ReleaseRecord.release_schema_version`). `build_release` emits exactly
/// this value and [`verify_release_identity`] refuses any other version
/// (fail closed) on every write and read path. Version 2 records the
/// exclusive-ownership canonical slot snapshot (each slot's one `target` +
/// `groups`); version 1 records (the multi-target `targets` shape) are
/// rejected on read — no compatibility fallback.
pub(crate) const RELEASE_RECORD_SCHEMA_VERSION: u32 = 2;

/// Canonical digest of the frozen mapping set.
pub fn mapping_digest(mappings: &[Mapping]) -> String {
    let v = serde_json::to_vec(mappings).expect("mappings serialize");
    sha256_bytes(&v)
}

/// Canonical digest over name-sorted per-variant mapping sets. Two releases
/// share this digest only when every declared variant materializes the same
/// mappings.
pub fn variant_mappings_digest(mappings: &BTreeMap<String, Vec<Mapping>>) -> String {
    let value = serde_json::to_vec(mappings).expect("variant mappings serialize");
    sha256_bytes(&value)
}

/// Lexically normalize an on-server `deploy_dir` into its canonical string
/// form: collapse repeated slashes, resolve `.` and `..` components
/// lexically (no filesystem access), and strip any trailing slash. Two
/// declarations naming the same directory therefore hash identically. The
/// config validator already requires `deploy_dir` to be absolute; relative
/// paths are still cleaned defensively.
pub fn normalize_deploy_dir(path: &Path) -> String {
    let mut out = PathBuf::new();
    if path.is_absolute() {
        out.push(Path::new("/"));
    }
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    let s = out.to_string_lossy().into_owned();
    if s.len() > 1 {
        s.trim_end_matches('/').to_string()
    } else {
        s
    }
}

/// Canonicalize a variant's declared `[[slots]]` into the sorted, normalized
/// identity form: the identity-bearing fields of [`SlotConfig`] (`id`, `server`,
/// `deploy_dir` as a lexically-normalized absolute path string, the ONE
/// owning `target` verbatim, `groups` SORTED and DEDUPLICATED), sorted by
/// slot id. The `groups` dedup is defensive: a duplicate name adds no
/// membership, so a record that slipped past validation (or predates it)
/// must still canonicalize to the same identity as the deduplicated list —
/// duplicate noise never shifts the digest. Server-level policy (user,
/// address, port, capacity) is deliberately absent — it is not release
/// identity.
///
/// The sort is a TOTAL ORDER over the identity fields (id, then server,
/// then deploy_dir, then target, then groups), not a stable id-only sort: a
/// STABLE sort over the id alone would let the DECLARATION ORDER of
/// duplicate-id slots leak into the canonical form, making the digest
/// asymmetric for two logically-identical declaration orders (the
/// identity-gap class of bug). A total order makes the canonical form a pure
/// function of the declared slot set — the same slots written in any order
/// canonicalize identically, even for the degenerate duplicate-id
/// declarations a record that slipped past validation can carry.
pub fn canonicalize_slots(slots: &[SlotConfig]) -> CanonicalSlots {
    let mut out: Vec<CanonicalSlot> = slots
        .iter()
        .map(|s| CanonicalSlot {
            id: s.id.clone(),
            server: s.server.clone(),
            deploy_dir: normalize_deploy_dir(s.deploy_dir()),
            target: s.target.clone(),
            groups: {
                let mut g = s.groups.clone();
                g.sort();
                g.dedup();
                g
            },
        })
        .collect();
    out.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.server.cmp(&b.server))
            .then_with(|| a.deploy_dir.cmp(&b.deploy_dir))
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.groups.cmp(&b.groups))
    });
    CanonicalSlots { slots: out }
}

/// Canonical digest over name-sorted per-variant slot declarations. Each
/// variant's slots are canonicalized (the identity fields, `deploy_dir`
/// lexically normalized, `groups` sorted and deduplicated) and sorted by
/// the total order over those fields (id, server, deploy_dir, target,
/// groups — the content tie-break keeps the canonical form order-independent
/// even for duplicate-id declarations); the variants are name-sorted by the
/// `BTreeMap`. Two releases
/// share this digest only when every declared variant declares the same
/// slots — a rebind, `deploy_dir` move, owning-target change, or group
/// membership change alters it, while a reordering of slot declarations (or
/// of variants, or of a slot's `groups` list, or duplicate names in it —
/// deduplicated away) does not. Server-level policy (user/address/port/
/// capacity) is not part of it.
pub fn variant_slots_digest(slots: &BTreeMap<String, Vec<SlotConfig>>) -> String {
    let canonical: BTreeMap<String, CanonicalSlots> = slots
        .iter()
        .map(|(v, defs)| (v.clone(), canonicalize_slots(defs)))
        .collect();
    let value = serde_json::to_vec(&canonical).expect("variant slots serialize");
    sha256_bytes(&value)
}

/// Derive the release digest from the canonical payload.
pub fn release_digest(
    mapping_sha: &str,
    behavior_sha: &str,
    slots_sha: &str,
    variants: &BTreeMap<String, String>,
) -> ReleaseDigest {
    let payload = CanonicalReleasePayload {
        schema_version: RELEASE_PAYLOAD_SCHEMA_VERSION,
        mapping_sha256: mapping_sha.to_string(),
        behavior_sha256: behavior_sha.to_string(),
        slots_digest: slots_sha.to_string(),
        variants: variants.clone(),
    };
    let bytes = serde_json::to_vec(&payload).expect("payload serializes");
    ReleaseDigest::parse(&sha256_bytes(&bytes)).expect("sha256 hex is a valid digest")
}

/// Build a complete, immutable release record for the given variant bindings.
/// The per-variant slot declarations are canonicalized and frozen into the
/// record (as the slot snapshot) and folded into the release identity digest,
/// so a slot-only change produces a new [`ReleaseId`].
pub fn build_release(
    mapping_sha: &str,
    behavior_sha: &str,
    variants: &BTreeMap<VariantName, TreeDigest>,
    variant_slots: &BTreeMap<String, Vec<SlotConfig>>,
    _root: &Path,
) -> ReleaseRecord {
    let bindings: BTreeMap<String, String> = variants
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
        .collect();
    let slots_digest = variant_slots_digest(variant_slots);
    let slots: BTreeMap<String, CanonicalSlots> = variant_slots
        .iter()
        .map(|(v, defs)| (v.clone(), canonicalize_slots(defs)))
        .collect();
    let digest = release_digest(mapping_sha, behavior_sha, &slots_digest, &bindings);
    let id = ReleaseId::from_digest(&digest);
    ReleaseRecord {
        release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
        release_id: id.as_str().to_string(),
        release_sha256: digest.as_str().to_string(),
        created_at: Timestamp::now().to_string(),
        provenance: Provenance {
            mapping_sha256: mapping_sha.to_string(),
            behavior_sha256: behavior_sha.to_string(),
        },
        variants: bindings,
        slots,
    }
}

/// Recompute the canonical release digest from a stored record's OWN content:
/// the per-variant canonical slot snapshot, the `variant -> tree digest`
/// bindings, and the provenance digests — exactly the inputs `build_release`
/// folds into the identity. Returns `None` when the record carries no
/// canonical slot snapshot (empty `slots` map): such a record's slot
/// declarations were not persisted, so the digest cannot be recomputed from
/// the record alone. Verification (`verify_release_identity`) treats that
/// `None` as an integrity failure — an empty slot snapshot is rejected, with
/// no legacy escape hatch.
pub fn recompute_release_digest(rec: &ReleaseRecord) -> Option<ReleaseDigest> {
    if rec.slots.is_empty() {
        return None;
    }
    // Rebuild the per-variant slot declarations from the record's canonical
    // snapshot (the four identity fields map 1:1 onto `SlotConfig`) and re-run
    // the same component digest `build_release` uses, so any change to the
    // canonical slot digest inputs merges mechanically.
    let slots: BTreeMap<String, Vec<SlotConfig>> = rec
        .slots
        .iter()
        .map(|(v, cs)| {
            (
                v.clone(),
                cs.slots
                    .iter()
                    .map(|s| {
                        SlotConfig::new(
                            s.id.clone(),
                            s.server.clone(),
                            PathBuf::from(&s.deploy_dir),
                            s.target.clone(),
                            s.groups.clone(),
                        )
                    })
                    .collect(),
            )
        })
        .collect();
    let slots_digest = variant_slots_digest(&slots);
    Some(release_digest(
        &rec.provenance.mapping_sha256,
        &rec.provenance.behavior_sha256,
        &slots_digest,
        &rec.variants,
    ))
}

/// Verify that a release record's stored identity — BOTH `release_sha256` and
/// the `release_id` (`rel-sha256-<digest>`) — matches the canonical digest
/// recomputed from the record's own content. The digest is never trusted from
/// the stored fields: a tampered record whose content was edited while the
/// digest fields were left unchanged fails closed with an integrity error
/// naming the release and the expected vs recomputed digest.
///
/// The record's `release_schema_version` is checked FIRST and must be
/// exactly `RELEASE_RECORD_SCHEMA_VERSION`: a record carrying any other
/// version is refused outright (fail closed, naming the version) before any
/// digest work — only the current record format is ever interpreted. The
/// identity payload version (`RELEASE_PAYLOAD_SCHEMA_VERSION`) is enforced
/// implicitly by the recompute below, which re-derives the digest with
/// exactly that payload version: a release whose identity was derived from
/// any other payload version fails the recompute-and-verify check.
///
/// An EMPTY canonical slot snapshot is rejected outright: a current-format
/// release record must carry its own slot declarations, without which the
/// identity cannot be recomputed from the record — accepting one would let a
/// tampered record whose `slots` map was emptied bypass verification
/// entirely. There is deliberately NO legacy escape hatch:
/// `release_schema_version` is 1 for both current and pre-snapshot records,
/// so an empty snapshot cannot be proven "genuinely legacy" and is treated
/// as tampering (fail closed).
pub fn verify_release_identity(rec: &ReleaseRecord) -> Result<()> {
    // The record format version must be exactly the canonical constant: a
    // record from any other version is refused before any digest work.
    if rec.release_schema_version != RELEASE_RECORD_SCHEMA_VERSION {
        return Err(Error::integrity(format!(
            "release {} carries unsupported release_schema_version {} (expected {RELEASE_RECORD_SCHEMA_VERSION}): only RELEASE_RECORD_SCHEMA_VERSION is accepted",
            rec.release_id, rec.release_schema_version
        )));
    }
    // Reject an empty slot snapshot before anything else: a record that
    // carries no canonical slot declarations cannot be verified from its own
    // content, so its identity is not trustworthy.
    let recomputed = recompute_release_digest(rec).ok_or_else(|| {
        Error::integrity(format!(
            "release {} carries an empty canonical slot snapshot: a release record must persist its slot declarations to be verifiable (fail closed)",
            rec.release_id
        ))
    })?;
    let expected_id = ReleaseId::from_digest(&recomputed);
    if rec.release_sha256 != recomputed.as_str() || rec.release_id != expected_id.as_str() {
        return Err(Error::integrity(format!(
            "release {} identity mismatch: stored release_sha256 {} / release_id {} do not match the digest {} recomputed from the record content",
            rec.release_id,
            rec.release_sha256,
            rec.release_id,
            recomputed.as_str()
        )));
    }
    Ok(())
}

/// The COMPLETE release-graph validator: converts a frozen
/// [`ReleaseRecord`] (plus its per-variant closed behavior contracts and the
/// available-server set) into the [`ValidatedRelease`] DOMAIN value, checking
/// the record MEANINGFULLY — not just re-hashing it:
///
/// 1. **Identity** — the stored `release_sha256`/`release_id` still recompute
///    from the record's own content ([`verify_release_identity`]), and the
///    record's provenance `behavior_sha256` equals the canonical digest of
///    the supplied behavior contracts (the release graph and the behavior
///    graph agree).
/// 2. **Slot snapshot as a graph** — the slot declarations are COMPLETE
///    (every variant the record binds has declared slots, and no slot
///    snapshot names an undeclared variant), every slot is PARSEABLE (its
///    id/server/target are valid identifiers, its deploy_dir is an absolute
///    traversal-free path, its group names are valid), no slot id is
///    DUPLICATED anywhere in the snapshot, and every slot's `server` exists
///    in the available-server set (the graph's server nodes).
/// 3. **Behavior coverage** — EVERY variant the record binds has a behavior
///    contract, and no contract names an undeclared variant (incomplete
///    behavior coverage is rejected, as are orphan contracts).
///
/// The domain value is what consumers use thereafter; it is constructed ONLY
/// through [`ValidatedRelease::try_new`], with no unchecked public
/// constructor — a record that fails any rule here cannot become a
/// [`ValidatedRelease`].
///
/// The domain value carries the TYPED release graph: every leaf of the wire
/// record (variant names, tree digests, slot ids/servers/targets, deploy_dirs,
/// group names) is parsed ONCE at [`ValidatedRelease::try_new`] into a
/// validated identity (fail closed on any invalid leaf), so the "fully typed
/// release" claim is PROVEN by the type — a consumer reads the typed
/// accessors and never re-parses a release-record leaf with `expect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRelease {
    /// The identity-verified, semantically validated frozen record (the
    /// wire bytes, re-serializable for remote publication).
    record: ReleaseRecord,
    /// The per-variant behavior contracts (closed enums), coverage-complete
    /// and digest-consistent with the record's provenance.
    behaviors: BTreeMap<String, BehaviorContract>,
    /// The TYPED `variant -> tree digest` bindings, parsed once at
    /// [`ValidatedRelease::try_new`] (fail closed on any invalid variant name
    /// or tree digest).
    variant_bindings: BTreeMap<VariantName, TreeDigest>,
    /// The TYPED per-variant slot projections (each variant's slots in the
    /// canonical slot order), parsed once at [`ValidatedRelease::try_new`].
    slots: BTreeMap<VariantName, Vec<ValidatedSlot>>,
}

/// A TYPED slot projection: every leaf of one canonical slot declaration
/// parsed ONCE at [`ValidatedRelease::try_new`] into a validated identity,
/// so downstream consumers read the typed values directly — no parse, no
/// `expect`. The group set is CANONICAL: a `BTreeSet` is sorted and
/// deduplicated by construction, so the typed set is exactly the record's
/// deduplicated membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSlot {
    id: SlotId,
    server: ServerId,
    deploy_dir: AbsoluteDeployDir,
    target: TargetName,
    groups: BTreeSet<RolloutGroupName>,
}

impl ValidatedSlot {
    /// The slot's validated id.
    pub fn id(&self) -> &SlotId {
        &self.id
    }
    /// The slot's validated server id.
    pub fn server(&self) -> &ServerId {
        &self.server
    }
    /// The slot's validated, normalized absolute deploy_dir.
    pub fn deploy_dir(&self) -> &AbsoluteDeployDir {
        &self.deploy_dir
    }
    /// The slot's validated owning target.
    pub fn target(&self) -> &TargetName {
        &self.target
    }
    /// The slot's CANONICAL rollout group set (sorted, deduplicated).
    pub fn groups(&self) -> &BTreeSet<RolloutGroupName> {
        &self.groups
    }
}

impl ValidatedRelease {
    /// Validate the frozen wire record + behavior contracts + server set
    /// and build the domain value. Any rule violation (identity mismatch,
    /// slot-graph inconsistency, unknown/unsupported adapter already
    /// refused at the closed-enum parse, incomplete behavior coverage,
    /// behavior-digest disagreement) fails closed WITHOUT producing a
    /// [`ValidatedRelease`].
    pub fn try_new(
        rec: ReleaseRecord,
        behaviors: BTreeMap<String, BehaviorContract>,
        servers: &BTreeSet<String>,
    ) -> Result<ValidatedRelease> {
        // 1. IDENTITY: the stored identity must recompute from the record's
        // own content, and the behavior graph must agree with the record's
        // provenance digest (what [`verify_behavior_json`] enforces on the
        // serialized behavior document).
        verify_release_identity(&rec)?;
        if variant_behaviors_digest(&behaviors) != rec.provenance.behavior_sha256 {
            return Err(Error::integrity(format!(
                "release {} behavior graph inconsistent: the per-variant behavior digest {} does not match the record provenance behavior_sha256 {}",
                rec.release_id,
                variant_behaviors_digest(&behaviors),
                rec.provenance.behavior_sha256
            )));
        }

        // 3. BEHAVIOR COVERAGE: every variant the record binds must carry a
        // behavior contract, and no contract may name an undeclared variant.
        // (The BTreeMaps iterate in sorted key order, so the key-set
        // comparison is exact.)
        if !rec.variants.keys().eq(behaviors.keys()) {
            let missing: Vec<&String> = rec
                .variants
                .keys()
                .filter(|v| !behaviors.contains_key(*v))
                .collect();
            let extra: Vec<&String> = behaviors
                .keys()
                .filter(|v| !rec.variants.contains_key(*v))
                .collect();
            return Err(Error::integrity(format!(
                "release {} behavior coverage incomplete or orphaned: missing contracts for variants {:?}, contracts for undeclared variants {:?}",
                rec.release_id, missing, extra
            )));
        }

        // 2. SLOT SNAPSHOT AS A GRAPH: complete declarations, parseable
        // slots, unique slot ids, and every slot's server inside the
        // available-server set. Every leaf is parsed ONCE into its typed
        // identity (fail closed on any invalid leaf): the typed graph is
        // built HERE, so a consumer never re-parses a release-record leaf.
        if !rec.variants.keys().eq(rec.slots.keys()) {
            let missing: Vec<&String> = rec
                .variants
                .keys()
                .filter(|v| !rec.slots.contains_key(*v))
                .collect();
            let extra: Vec<&String> = rec
                .slots
                .keys()
                .filter(|v| !rec.variants.contains_key(*v))
                .collect();
            return Err(Error::integrity(format!(
                "release {} slot snapshot incomplete or dangling: variants without declared slots {:?}, slot snapshot entries for undeclared variants {:?}",
                rec.release_id, missing, extra
            )));
        }
        // The TYPED variant -> tree bindings: every variant name and every
        // tree digest must be a valid leaf (fail closed — an invalid name or
        // digest can never become a [`ValidatedRelease`]).
        let mut variant_bindings: BTreeMap<VariantName, TreeDigest> = BTreeMap::new();
        for (name, tree) in &rec.variants {
            let name = VariantName::parse(name).map_err(|e| {
                Error::integrity(format!(
                    "release {} variant name {:?} is not a valid variant name: {e}",
                    rec.release_id, name
                ))
            })?;
            let tree = TreeDigest::parse(tree).map_err(|e| {
                Error::integrity(format!(
                    "release {} variant '{}' tree digest {:?} is not a valid tree digest: {e}",
                    rec.release_id, name, tree
                ))
            })?;
            variant_bindings.insert(name, tree);
        }
        let mut seen_ids: BTreeSet<String> = BTreeSet::new();
        let mut slots: BTreeMap<VariantName, Vec<ValidatedSlot>> = BTreeMap::new();
        for (variant, cs) in &rec.slots {
            let variant = VariantName::parse(variant).map_err(|e| {
                Error::integrity(format!(
                    "release {} slot snapshot names invalid variant {:?}: {e}",
                    rec.release_id, variant
                ))
            })?;
            let mut typed_slots = Vec::with_capacity(cs.slots.len());
            for s in &cs.slots {
                let id = SlotId::parse(&s.id).map_err(|e| {
                    Error::integrity(format!(
                        "release {} slot id {:?} is not a valid identifier: {e}",
                        rec.release_id, s.id
                    ))
                })?;
                let server = ServerId::parse(&s.server).map_err(|e| {
                    Error::integrity(format!(
                        "release {} slot '{}' server {:?} is not a valid identifier: {e}",
                        rec.release_id, s.id, s.server
                    ))
                })?;
                let deploy_dir = AbsoluteDeployDir::parse(&s.deploy_dir).map_err(|e| {
                    Error::integrity(format!(
                        "release {} slot '{}' deploy_dir {:?} is not an absolute valid path: {e}",
                        rec.release_id, s.id, s.deploy_dir
                    ))
                })?;
                let target = TargetName::parse(&s.target).map_err(|e| {
                    Error::integrity(format!(
                        "release {} slot '{}' owning target {:?} is not a valid identifier: {e}",
                        rec.release_id, s.id, s.target
                    ))
                })?;
                let mut groups: BTreeSet<RolloutGroupName> = BTreeSet::new();
                for g in &s.groups {
                    groups.insert(RolloutGroupName::parse(g).map_err(|e| {
                        Error::integrity(format!(
                            "release {} slot '{}' group {:?} is not a valid group name: {e}",
                            rec.release_id, s.id, g
                        ))
                    })?);
                }
                if !seen_ids.insert(s.id.clone()) {
                    return Err(Error::integrity(format!(
                        "release {} declares duplicate slot id '{}'",
                        rec.release_id, s.id
                    )));
                }
                if !servers.contains(&s.server) {
                    return Err(Error::integrity(format!(
                        "release {} slot '{}' binds unknown server '{}': the server is not in the available server set",
                        rec.release_id, s.id, s.server
                    )));
                }
                typed_slots.push(ValidatedSlot {
                    id,
                    server,
                    deploy_dir,
                    target,
                    groups,
                });
            }
            slots.insert(variant, typed_slots);
        }

        Ok(ValidatedRelease {
            record: rec,
            behaviors,
            variant_bindings,
            slots,
        })
    }

    /// The validated frozen record (the wire bytes — re-serializable for
    /// remote publication).
    pub fn record(&self) -> &ReleaseRecord {
        &self.record
    }

    /// The per-variant behavior contracts (coverage-complete, closed enums,
    /// digest-consistent with the record's provenance).
    pub fn behaviors(&self) -> &BTreeMap<String, BehaviorContract> {
        &self.behaviors
    }

    /// The TYPED `variant -> tree digest` bindings (parsed once at
    /// [`ValidatedRelease::try_new`]): every variant name and tree digest is
    /// a validated identity, so a consumer reads the typed values directly —
    /// no parse, no `expect`.
    pub fn variant_bindings(&self) -> &BTreeMap<VariantName, TreeDigest> {
        &self.variant_bindings
    }

    /// The TYPED per-variant slot projections (each variant's slots in the
    /// canonical slot order): every slot's id/server/target is a validated
    /// identity, its deploy_dir a validated absolute path, and its groups a
    /// canonical (sorted, deduplicated) typed set.
    pub fn slots(&self) -> &BTreeMap<VariantName, Vec<ValidatedSlot>> {
        &self.slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdef(id: &str, server: &str, deploy_dir: &str, target: &str) -> SlotConfig {
        SlotConfig::new(
            id.to_string(),
            server.to_string(),
            PathBuf::from(deploy_dir),
            target.to_string(),
            Vec::new(),
        )
    }

    /// Two variants with the same slot declarations written in different file
    /// orders and with lexically equivalent (but textually different)
    /// deploy_dir strings hash identically.
    #[test]
    fn variant_slots_digest_is_order_independent() {
        let mut a: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
        a.insert(
            "standard".to_string(),
            vec![
                sdef("p2", "s2", "/srv/deploy/p2", "production"),
                sdef("p1", "s1", "/srv/deploy/p1", "production"),
            ],
        );
        a.insert(
            "canary".to_string(),
            vec![sdef("c1", "s3", "/srv/edge/c1", "edge")],
        );

        // Same declarations: per-variant file order reversed (p1 before p2), a
        // textually different but lexically identical deploy_dir (double slash,
        // trailing slash), and the variants inserted in the opposite order.
        let mut b: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
        b.insert(
            "canary".to_string(),
            vec![sdef("c1", "s3", "/srv/edge/c1", "edge")],
        );
        b.insert(
            "standard".to_string(),
            vec![
                sdef("p1", "s1", "/srv/deploy//p1/", "production"),
                sdef("p2", "s2", "/srv/deploy/p2", "production"),
            ],
        );
        assert_eq!(
            variant_slots_digest(&a),
            variant_slots_digest(&b),
            "slot declaration order must not affect the digest"
        );
    }

    /// Changing any of the four identity fields changes the digest; server
    /// policy fields are not part of the input at all.
    #[test]
    fn variant_slots_digest_is_sensitive_to_each_field() {
        let base: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let base_sha = variant_slots_digest(&base);
        for variant in [
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p2", "server-01", "/srv/deploy/example", "production")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p1", "server-02", "/srv/deploy/example", "production")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p1", "server-01", "/srv/elsewhere", "production")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![sdef("p1", "server-01", "/srv/deploy/example", "edge")],
            )]),
            BTreeMap::from([(
                "standard".to_string(),
                vec![
                    sdef("p1", "server-01", "/srv/deploy/example", "production"),
                    sdef("p9", "server-09", "/srv/deploy/example", "production"),
                ],
            )]),
        ] {
            assert_ne!(
                variant_slots_digest(&variant),
                base_sha,
                "every slot field change must alter the digest"
            );
        }
    }

    /// The slot's ONE owning target is part of the identity: changing it
    /// changes the digest, while the canonical form (sorted `groups`, slot
    /// order normalized) is a pure function of the declaration set — so
    /// identical declarations canonicalize identically.
    #[test]
    fn variant_slots_digest_is_sensitive_to_owning_target() {
        let base: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotConfig::new(
                "p1".to_string(),
                "server-01".to_string(),
                PathBuf::from("/srv/deploy/example"),
                "production".to_string(),
                Vec::new(),
            )],
        )]);
        let base_sha = variant_slots_digest(&base);

        // Changing the slot's ONE owning target changes the digest.
        let retargeted: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotConfig::new(
                "p1".to_string(),
                "server-01".to_string(),
                PathBuf::from("/srv/deploy/example"),
                "staging".to_string(),
                Vec::new(),
            )],
        )]);
        assert_ne!(
            variant_slots_digest(&retargeted),
            base_sha,
            "an owning-target change must alter the digest"
        );

        // Reordering the same list canonicalizes identically.
        let reordered: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotConfig::new(
                "p1".to_string(),
                "server-01".to_string(),
                PathBuf::from("/srv/deploy/example"),
                "staging".to_string(),
                Vec::new(),
            )],
        )]);
        assert_eq!(
            variant_slots_digest(&reordered),
            variant_slots_digest(&retargeted),
            "the owning target must not affect the digest when unchanged"
        );
    }

    /// Duplicate names in a slot's `groups` list add no membership, so the
    /// canonical form DEDUPS them: `["canary","canary"]` and `["canary"]`
    /// produce the SAME digest (a record that slipped past validation, or
    /// predates it, must not shift release identity), while a change that
    /// DOES alter membership (changing the owning target) still changes the
    /// digest.
    #[test]
    fn variant_slots_digest_dedups_duplicate_groups() {
        let single: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotConfig::new(
                "p1".to_string(),
                "server-01".to_string(),
                PathBuf::from("/srv/deploy/example"),
                "t1".to_string(),
                vec!["canary".to_string()],
            )],
        )]);
        let duplicated: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotConfig::new(
                "p1".to_string(),
                "server-01".to_string(),
                PathBuf::from("/srv/deploy/example"),
                "t1".to_string(),
                vec!["canary".to_string(), "canary".to_string()],
            )],
        )]);
        assert_eq!(
            variant_slots_digest(&single),
            variant_slots_digest(&duplicated),
            "a duplicated group name must not change the digest (membership is unchanged)"
        );

        // A change that DOES alter membership still changes the digest.
        let retargeted: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotConfig::new(
                "p1".to_string(),
                "server-01".to_string(),
                PathBuf::from("/srv/deploy/example"),
                "t2".to_string(),
                vec!["canary".to_string()],
            )],
        )]);
        assert_ne!(
            variant_slots_digest(&single),
            variant_slots_digest(&retargeted),
            "an owning-target change must still alter the digest"
        );
    }

    /// `deploy_dir` canonicalization collapses slashes, resolves `.`/`..`
    /// lexically, and keeps the absolute root.
    #[test]
    fn normalize_deploy_dir_is_lexical() {
        assert_eq!(
            normalize_deploy_dir(Path::new("/srv/deploy/example")),
            "/srv/deploy/example"
        );
        assert_eq!(
            normalize_deploy_dir(Path::new("//srv/deploy//example/")),
            "/srv/deploy/example"
        );
        assert_eq!(
            normalize_deploy_dir(Path::new("/srv/deploy/../deploy/example")),
            "/srv/deploy/example"
        );
        assert_eq!(normalize_deploy_dir(Path::new("/")), "/");
    }

    /// A slot-only change yields a different release digest while the tree
    /// bindings stay identical.
    #[test]
    fn slot_only_change_changes_release_digest() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let bindings: BTreeMap<String, String> = variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let slot_a: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let slot_b: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-02", "/srv/deploy/example", "production")],
        )]);
        let da = release_digest("m", "b", &variant_slots_digest(&slot_a), &bindings);
        let db = release_digest("m", "b", &variant_slots_digest(&slot_b), &bindings);
        assert_ne!(
            da.as_str(),
            db.as_str(),
            "a slot-only change must produce a new release digest"
        );
        // The release record persists the canonical slot snapshot it was built
        // from.
        let rec_a = build_release("m", "b", &variants, &slot_a, Path::new("."));
        let rec_b = build_release("m", "b", &variants, &slot_b, Path::new("."));
        assert_eq!(rec_a.slots["standard"].slots[0].server, "server-01");
        assert_eq!(rec_b.slots["standard"].slots[0].server, "server-02");
        assert_eq!(rec_a.variants, rec_b.variants, "trees unchanged");
        assert_ne!(rec_a.release_sha256, rec_b.release_sha256);
    }

    /// The release digest is sensitive to EVERY canonical identity input —
    /// mapping set, behavior contract set, per-variant tree bindings, and
    /// canonical slot declarations — and to nothing else: an identical payload
    /// always produces the identical digest. Server-level policy (user,
    /// address, port, capacity) is not even an input to the digest function.
    #[test]
    fn release_digest_sensitivity_matrix() {
        let base_slots: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let base_variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("tree-1"))]);
        let bindings: BTreeMap<String, String> = base_variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let base = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&base_slots),
            &bindings,
        );

        // Identical payload -> identical digest.
        assert_eq!(
            release_digest(
                "mapping-sha",
                "behavior-sha",
                &variant_slots_digest(&base_slots),
                &bindings
            )
            .as_str(),
            base.as_str()
        );

        // Mapping change -> new digest.
        let m = release_digest(
            "mapping-sha-2",
            "behavior-sha",
            &variant_slots_digest(&base_slots),
            &bindings,
        );
        assert_ne!(base.as_str(), m.as_str(), "mapping change must re-digest");

        // Behavior contract change -> new digest.
        let b = release_digest(
            "mapping-sha",
            "behavior-sha-2",
            &variant_slots_digest(&base_slots),
            &bindings,
        );
        assert_ne!(base.as_str(), b.as_str(), "behavior change must re-digest");

        // Tree-binding change -> new digest.
        let t_variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("tree-2"))]);
        let t_bindings: BTreeMap<String, String> = t_variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let tb = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&base_slots),
            &t_bindings,
        );
        assert_ne!(
            base.as_str(),
            tb.as_str(),
            "tree-binding change must re-digest"
        );

        // Canonical-slot change -> new digest (already asserted per-field by
        // `variant_slots_digest_is_sensitive_to_each_field`, folded into the
        // full digest here).
        let s2: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-02", "/srv/deploy/example", "production")],
        )]);
        let sb = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&s2),
            &bindings,
        );
        assert_ne!(
            base.as_str(),
            sb.as_str(),
            "canonical-slot change must re-digest"
        );

        // Owning-target change -> new digest: a slot-only change to the
        // `target` field creates a new ReleaseId.
        let s3: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![SlotConfig::new(
                "p1".to_string(),
                "server-01".to_string(),
                PathBuf::from("/srv/deploy/example"),
                "staging".to_string(),
                Vec::new(),
            )],
        )]);
        let st = release_digest(
            "mapping-sha",
            "behavior-sha",
            &variant_slots_digest(&s3),
            &bindings,
        );
        assert_ne!(
            base.as_str(),
            st.as_str(),
            "an owning-target change must re-digest"
        );

        // The built release record follows the digest: identical inputs build
        // the identical ReleaseId, any single changed input builds a new one.
        let rec = build_release(
            "mapping-sha",
            "behavior-sha",
            &base_variants,
            &base_slots,
            Path::new("."),
        );
        assert_eq!(rec.release_sha256, base.as_str());
        assert_eq!(rec.release_id, format!("rel-sha256-{}", base.as_str()));
        let rec_m = build_release(
            "mapping-sha-2",
            "behavior-sha",
            &base_variants,
            &base_slots,
            Path::new("."),
        );
        assert_ne!(rec.release_id, rec_m.release_id);
    }

    /// `verify_release_identity` recomputes the canonical digest from the
    /// record's OWN content and checks it against BOTH stored identity fields:
    /// a pristine record verifies, a record whose slot declaration or variant
    /// binding was edited while the digest fields were retained fails closed
    /// with an integrity error naming the mismatch, and a record whose slot
    /// snapshot was EMPTIED fails closed (no legacy escape hatch).
    #[test]
    fn verify_release_identity_recomputes_from_content() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));

        // Pristine: the recomputed digest matches both stored fields.
        verify_release_identity(&rec).expect("pristine record verifies");

        // Tampered slot declaration (deploy_dir moved) with the digest fields
        // retained -> Err naming the stored vs recomputed digest.
        let mut tampered = rec.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        let err = verify_release_identity(&tampered)
            .expect_err("tampered slot content must fail verification");
        let msg = err.to_string();
        assert!(
            msg.contains("identity mismatch"),
            "error must name the mismatch, got: {msg}"
        );
        assert!(
            msg.contains(&rec.release_sha256),
            "error must name the stored digest, got: {msg}"
        );

        // Tampered variant binding with the digest fields retained -> Err.
        let mut tampered2 = rec.clone();
        tampered2
            .variants
            .insert("standard".to_string(), "tree-2".to_string());
        let err2 = verify_release_identity(&tampered2)
            .expect_err("tampered variant binding must fail verification");
        assert!(err2.to_string().contains("identity mismatch"));

        // Empty slot snapshot: rejected outright (fail closed) — a record
        // whose `slots` map was emptied cannot be verified from its own
        // content, and there is no legacy escape hatch.
        let mut empty_slots = rec.clone();
        empty_slots.slots.clear();
        let err = verify_release_identity(&empty_slots)
            .expect_err("an empty slot snapshot must fail verification");
        let msg = err.to_string();
        assert!(
            msg.contains("slot snapshot"),
            "error must name the empty slot snapshot, got: {msg}"
        );
        assert!(
            msg.contains("fail closed"),
            "error must explain the fail-closed rejection, got: {msg}"
        );
    }

    /// A current-format record whose slot snapshot was EMPTIED while the
    /// digest fields were left unchanged (the classic empty-snapshot bypass)
    /// must fail verification with an integrity error: the digest fields are
    /// re-derived from the record content, and the emptied snapshot makes the
    /// record unverifiable.
    #[test]
    fn verify_release_identity_rejects_empty_slot_snapshot_even_with_retained_digests() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));
        verify_release_identity(&rec).expect("pristine record verifies");

        // Tamper: empty the slots map but RETAIN the stored digest fields.
        let mut tampered = rec.clone();
        tampered.slots.clear();
        assert_eq!(
            tampered.release_sha256, rec.release_sha256,
            "digest retained"
        );
        assert_eq!(tampered.release_id, rec.release_id, "release id retained");
        let err = verify_release_identity(&tampered)
            .expect_err("an emptied slot snapshot must fail verification");
        assert!(
            err.to_string().contains("fail closed"),
            "error must explain the fail-closed rejection, got: {err}"
        );
    }
    /// A tampered behavior.json whose canonical digest does not match the
    /// provenance `behavior_sha256` fails closed, while a payload that parses
    /// to the SAME canonical contract set (JSON key reordering) passes.
    #[test]
    fn verify_behavior_json_matches_provenance_digest() {
        let mut contracts: BTreeMap<String, BehaviorContract> = BTreeMap::new();
        contracts.insert(
            "standard".to_string(),
            BehaviorContract::new(
                crate::config::Activation::Systemd(
                    crate::config::ValidatedSystemd::new(
                        crate::config::ActivationScope::System,
                        true,
                        vec![
                            crate::config::UnitDef::new(
                                "app.service".to_string(),
                                "integration/systemd/app.service".to_string(),
                                true,
                                true,
                            )
                            .expect("validated unit"),
                        ],
                    )
                    .expect("validated systemd"),
                ),
                crate::config::Verification::Command(
                    crate::config::ValidatedCommand::new(vec!["true".to_string()], 30, 2, 1)
                        .expect("validated command"),
                ),
            ),
        );
        let sha = variant_behaviors_digest(&contracts);
        let canonical = serde_json::to_vec(&contracts).unwrap();

        // The canonical payload verifies.
        verify_behavior_json(&canonical, "rel-x", &sha).expect("canonical payload verifies");

        // Key reordering in the raw bytes parses to the SAME contract set, so
        // the digest stays equal and verification passes (the "unless the
        // canonical behavior digest remains equal" clause).
        let reordered = br#"{"standard":{"verification":{"adapter":"command","argv":["true"],"timeout_seconds":30,"attempts":2,"interval_seconds":1},"activation":{"adapter":"systemd","scope":"system","reconcile_managed_units":true,"units":[{"name":"app.service","artifact_path":"integration/systemd/app.service","enable":true,"restart":true}]}}}"#;
        verify_behavior_json(reordered, "rel-x", &sha).expect("reordered JSON passes");

        // Every identity-bearing change that still PARSES to a valid (but
        // different) contract set alters the digest -> fail closed with the
        // digest mismatch.
        let mutations: Vec<serde_json::Value> = vec![
            serde_json::json!({"standard": {"activation": {"adapter": "none", "scope": "user", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "other.service", "artifact_path": "integration/systemd/other.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["false"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 31, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "user", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"canary": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({}),
        ];
        for (i, m) in mutations.iter().enumerate() {
            let bytes = serde_json::to_vec(m).unwrap();
            let err = verify_behavior_json(&bytes, "rel-x", &sha)
                .expect_err("every valid-but-different contract set must fail verification");
            assert!(
                err.to_string().contains("digest mismatch"),
                "mutation {i} must name the digest mismatch, got: {err}"
            );
        }

        // CLOSED-ENUM REFUSALS (the review's fix): a behavior document that
        // PARSES to a DIFFERENT canonical set is a digest mismatch, but a
        // document that can no longer form a VALID contract at all — an
        // unsupported adapter, a `none` contract carrying units/non-default
        // scope (irrelevant fields), a systemd contract without units, an
        // empty argv, zero attempts/timeout, an unknown template variable,
        // or an unknown field at any nesting level — is REFUSED at the
        // closed-enum parse (fail closed, never silently accepted/dropped).
        let refusals: Vec<serde_json::Value> = vec![
            serde_json::json!({"standard": {"activation": {"adapter": "bogus", "scope": "user", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "none", "scope": "system", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "none", "scope": "user", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": []}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "../app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "docker", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": [], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 0, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 0, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["{{ bogus }}"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}, "extra": 1}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true, "bogus": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}}}),
            serde_json::json!({"standard": {"activation": {"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}, "verification": {"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1, "bogus": 1}}}),
        ];
        for (i, m) in refusals.iter().enumerate() {
            let bytes = serde_json::to_vec(m).unwrap();
            let err = verify_behavior_json(&bytes, "rel-x", &sha)
                .expect_err("an invalid contract shape must be refused at the closed-enum parse");
            assert!(
                err.to_string().contains("malformed"),
                "refusal {i} must be a closed-enum parse refusal, got: {err}"
            );
        }

        // Unparseable bytes fail closed as malformed.
        let err = verify_behavior_json(b"{ not json", "rel-x", &sha)
            .expect_err("malformed bytes must fail closed");
        assert!(err.to_string().contains("malformed"));
    }
    /// The schema-version property for the RELEASE RECORD: generate arbitrary
    /// `u32` `release_schema_version` values; ONLY
    /// `RELEASE_RECORD_SCHEMA_VERSION` verifies, every other version fails
    /// closed with an integrity error naming the version (checked BEFORE any
    /// digest work — never a panic, never silent acceptance).
    #[test]
    fn verify_release_identity_accepts_only_record_schema_version() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));
        verify_release_identity(&rec).expect("the canonical version verifies");
        // Representative arbitrary-u32 set: 0, version - 1, version,
        // version + 1, 3, u32::MAX (duplicates harmless).
        let versions = [
            0u32,
            RELEASE_RECORD_SCHEMA_VERSION.wrapping_sub(1),
            RELEASE_RECORD_SCHEMA_VERSION,
            RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1),
            3,
            u32::MAX,
        ];
        for v in versions {
            let mut r = rec.clone();
            r.release_schema_version = v;
            if v == RELEASE_RECORD_SCHEMA_VERSION {
                verify_release_identity(&r).expect("the canonical version verifies");
            } else {
                let err = verify_release_identity(&r)
                    .expect_err("a record from any other version must fail closed");
                let msg = err.to_string();
                assert!(
                    msg.contains("release_schema_version"),
                    "error must name the version field, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{v}")),
                    "error must name the stored version {v}, got: {msg}"
                );
                assert!(
                    msg.contains("RELEASE_RECORD_SCHEMA_VERSION"),
                    "error must name the accepted version, got: {msg}"
                );
            }
        }
    }

    /// The schema-version property for the RELEASE IDENTITY PAYLOAD: the
    /// payload version is FROZEN into the release digest, so a release whose
    /// identity was derived with any `u32` version other than
    /// `RELEASE_PAYLOAD_SCHEMA_VERSION` fails the recompute-and-verify check
    /// (the stored digest never matches the digest re-derived with the
    /// canonical payload version). Only the canonical version produces a
    /// self-consistent, verifiable release.
    #[test]
    fn verify_release_identity_accepts_only_payload_schema_version() {
        let variants: BTreeMap<VariantName, TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), TreeDigest::new("t1"))]);
        let slots: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![sdef("p1", "server-01", "/srv/deploy/example", "production")],
        )]);
        let bindings: BTreeMap<String, String> = variants
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect();
        let rec = build_release("m", "b", &variants, &slots, Path::new("."));
        let slots_digest = variant_slots_digest(&slots);
        // Representative arbitrary-u32 set over the payload version.
        let versions = [
            0u32,
            RELEASE_PAYLOAD_SCHEMA_VERSION.wrapping_sub(1),
            RELEASE_PAYLOAD_SCHEMA_VERSION,
            RELEASE_PAYLOAD_SCHEMA_VERSION.wrapping_add(1),
            3,
            u32::MAX,
        ];
        let mut digest_by_version: BTreeMap<u32, String> = BTreeMap::new();
        for v in versions {
            // Simulate a release whose identity was derived from a payload
            // carrying version `v` (the digest is the sha256 of the payload).
            let payload = CanonicalReleasePayload {
                schema_version: v,
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
                slots_digest: slots_digest.clone(),
                variants: bindings.clone(),
            };
            let digest = sha256_bytes(&serde_json::to_vec(&payload).expect("payload serializes"));
            let mut r = rec.clone();
            r.release_sha256 = digest.clone();
            r.release_id = format!("rel-sha256-{digest}");
            if v == RELEASE_PAYLOAD_SCHEMA_VERSION {
                verify_release_identity(&r).expect("a payload with the canonical version verifies");
            } else {
                let err = verify_release_identity(&r).expect_err(
                    "a payload from any other version must fail the recompute-and-verify check",
                );
                let msg = err.to_string();
                assert!(
                    msg.contains("identity mismatch"),
                    "error must name the recompute-and-verify mismatch, got: {msg}"
                );
                assert!(
                    msg.contains(&r.release_sha256),
                    "error must name the stored (payload-derived) digest, got: {msg}"
                );
            }
            // Every version in the set produces a DISTINCT identity digest:
            // the payload version is part of the hash, so each arbitrary
            // version is distinguishable from the canonical one.
            digest_by_version.insert(v, digest);
        }
        // All digests distinct across the representative set.
        let canonical = &digest_by_version[&RELEASE_PAYLOAD_SCHEMA_VERSION];
        for (v, d) in &digest_by_version {
            if *v == RELEASE_PAYLOAD_SCHEMA_VERSION {
                continue;
            }
            assert_ne!(
                d, canonical,
                "payload version {v} must produce a different digest than the canonical version"
            );
        }
    }

    // -------------------------------------------------------------------
    // Release-identity digest contract (property tests)
    // -------------------------------------------------------------------
    //
    // The property covers the FULL identity contract of
    // `build_release` + `recompute_release_digest` + `verify_release_identity`
    // over generated release components:
    //
    // 1. ROUND-TRIP: a built release's stored `release_sha256` / `release_id`
    //    are exactly what the recompute path (which `verify` uses) re-derives
    //    from the record's own content, and verification passes.
    // 2. MUTATION SENSITIVITY: every identity field — mapping digest, behavior
    //    digest, every variant's tree digest, the variant→tree binding, every
    //    slot's id/server/deploy_dir/targets, the self-referential output
    //    fields (`release_sha256`, `release_id`), and the schema versions —
    //    is tamper-evident: mutating it makes the recompute disagree (for
    //    content fields) and ALWAYS fails verification with an integrity
    //    error. The intentionally non-identity field (`created_at`) is
    //    whitelisted: mutating it must NOT change the digest and must NOT
    //    break verification. (There is no display-name field on
    //    `ReleaseRecord`; the docs' exclusion is realized by `created_at` +
    //    provenance.)
    // 3. CANONICAL ORDER-INDEPENDENCE: the same logical release written with
    //    differently-ordered slot declarations, differently-ordered target
    //    lists, duplicate targets, or textually-different-but-lexically-
    //    equivalent `deploy_dir` spellings canonicalizes to the SAME digest.

    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    /// One generated release component set: the frozen mapping digest, the
    /// behavior digest, the `variant -> tree digest` bindings, and the raw
    /// per-variant slot declarations. The shapes are adversarial: slot ids
    /// come from a small pool (slots SHARE ids across variants, and may
    /// collide within a variant), `groups` lists are generated unsorted with
    /// duplicates, `deploy_dir`s include `..`/`//`/trailing-slash/relative
    /// spellings, and variant names include empty and odd strings.
    #[derive(Clone, Debug)]
    struct ReleaseComponents {
        mapping_sha256: String,
        behavior_sha256: String,
        /// `variant -> tree digest` bindings (name-sorted map).
        variants: BTreeMap<String, String>,
        /// Raw per-variant slot declarations, pre-canonicalization.
        variant_slots: BTreeMap<String, Vec<SlotConfig>>,
    }

    fn variant_name_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "standard".to_string(),
            "canary".to_string(),
            "".to_string(),
            "v".to_string(),
            "Variant-2".to_string(),
            "edge/blue-green".to_string(),
        ])
    }

    fn slot_id_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec!["p1".to_string(), "p2".to_string(), "s1".to_string()])
    }

    fn server_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "server-01".to_string(),
            "server-02".to_string(),
            "edge-1".to_string(),
        ])
    }

    fn deploy_dir_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "/srv/deploy/example".to_string(),
            "//srv//deploy/example/".to_string(),
            "/srv/deploy/../deploy/example".to_string(),
            "/srv/deploy/example/..".to_string(),
            "/srv/./deploy/example".to_string(),
            "/".to_string(),
            "..".to_string(),
            "./srv/deploy/example".to_string(),
            "/srv/deploy/example//".to_string(),
            "/srv/../srv/deploy/example".to_string(),
        ])
    }

    fn target_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "production".to_string(),
            "staging".to_string(),
            "edge".to_string(),
        ])
    }

    fn group_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "canary".to_string(),
            "wave-1".to_string(),
            "wave-2".to_string(),
        ])
    }

    fn slot_strategy() -> impl Strategy<Value = SlotConfig> {
        (
            slot_id_strategy(),
            server_strategy(),
            deploy_dir_strategy(),
            target_strategy(),
            prop::collection::vec(group_strategy(), 0..3),
        )
            .prop_map(|(id, server, deploy_dir, target, groups)| {
                SlotConfig::new(id, server, PathBuf::from(deploy_dir), target, groups)
            })
    }

    /// The component grammar: 1..4 `(variant name, tree seed, slots)` groups.
    /// Variant names are deduplicated keeping the FIRST occurrence (so the
    /// bindings and the slot declarations share exactly the same key set), the
    /// tree digest is the hex of a random 16-byte seed, and each variant
    /// carries 1..2 slots drawn from the adversarial slot grammar.
    fn release_components_strategy() -> impl Strategy<Value = ReleaseComponents> {
        (
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            prop::collection::vec(
                (
                    variant_name_strategy(),
                    any::<[u8; 16]>(),
                    prop::collection::vec(slot_strategy(), 1..3),
                ),
                1..4,
            ),
        )
            .prop_map(|(mapping_seed, behavior_seed, groups)| {
                let mut components = ReleaseComponents {
                    mapping_sha256: hex::encode(mapping_seed),
                    behavior_sha256: hex::encode(behavior_seed),
                    variants: BTreeMap::new(),
                    variant_slots: BTreeMap::new(),
                };
                for (name, tree_seed, slots) in groups {
                    if components.variants.contains_key(&name) {
                        continue;
                    }
                    components
                        .variants
                        .insert(name.clone(), hex::encode(tree_seed));
                    components.variant_slots.insert(name, slots);
                }
                components
            })
    }

    /// Three textual spellings of the same canonical directory `n`: the form
    /// itself, a doubled-slash + trailing-slash form, and a `<last>/../<last>`
    /// round-trip form. All three lexically normalize back to `n`. The
    /// degenerate forms (`""`, `"/"`, and relative paths) have no
    /// textually-different equivalent spelling, so all three spellings are
    /// `n` itself.
    fn equivalent_dir_spellings(n: &str) -> [String; 3] {
        if n.is_empty() || n == "/" || !n.starts_with('/') {
            return [n.to_string(), n.to_string(), n.to_string()];
        }
        let (prefix, last) = n.rsplit_once('/').expect("absolute path has a slash");
        [
            n.to_string(),
            format!("{prefix}//{last}/"),
            format!("{n}/../{last}"),
        ]
    }

    /// A record whose CONTENT was mutated (a field that feeds the recompute)
    /// must re-digest differently AND fail verification with an integrity
    /// error. The recompute is allowed to refuse an emptied slot snapshot
    /// (`None` — which is itself a recompute != original, since the original
    /// recomputes to `Some`); in every other case the recomputed digest must
    /// differ from the stored one.
    fn assert_content_mutation(original: &ReleaseRecord, mutated: &ReleaseRecord, label: &str) {
        if let Some(recomputed) = recompute_release_digest(mutated) {
            assert_ne!(
                recomputed.as_str(),
                original.release_sha256,
                "{label}: mutating an identity content field must change the recomputed digest"
            );
        }
        let err = verify_release_identity(mutated).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "{label}: tampering must fail with an integrity error, got: {err}"
        );
    }

    /// A record whose self-referential OUTPUT field was mutated
    /// (`release_sha256`, `release_id`, or a schema version) is detected by
    /// verification — the stored field is checked against the recompute —
    /// even though the recompute itself is unaffected (those fields are not
    /// digest inputs).
    fn assert_output_mutation(original: &ReleaseRecord, mutated: &ReleaseRecord, label: &str) {
        let recomputed = recompute_release_digest(mutated)
            .expect("output-field mutations never touch the slot snapshot");
        assert_eq!(
            recomputed.as_str(),
            original.release_sha256,
            "{label}: output fields are not digest inputs"
        );
        let err = verify_release_identity(mutated).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "{label}: a tampered output field must fail with an integrity error, got: {err}"
        );
    }

    /// A record whose WHITELISTED (intentionally non-identity) field was
    /// mutated — `created_at` — must digest IDENTICALLY and still verify:
    /// the field is excluded from the identity contract, so changing it is
    /// not tampering.
    fn assert_whitelist_mutation(original: &ReleaseRecord, mutated: &ReleaseRecord, label: &str) {
        let recomputed = recompute_release_digest(mutated)
            .expect("whitelist mutations never touch the slot snapshot");
        assert_eq!(
            recomputed.as_str(),
            original.release_sha256,
            "{label}: whitelisted fields must not enter the digest"
        );
        verify_release_identity(mutated)
            .expect("{label}: a whitelisted-field change must not break verification");
    }

    /// The three-part contract for one generated component set.
    fn run_release_identity_contract(c: &ReleaseComponents) {
        let variants: BTreeMap<VariantName, TreeDigest> = c
            .variants
            .iter()
            .map(|(name, digest)| {
                (
                    VariantName::new(name.clone()),
                    TreeDigest::new(digest.clone()),
                )
            })
            .collect();
        let rec = build_release(
            &c.mapping_sha256,
            &c.behavior_sha256,
            &variants,
            &c.variant_slots,
            Path::new("."),
        );

        // (1) ROUND-TRIP: build and the recompute path `verify` uses agree on
        // the exact field partition — the stored digest/id are exactly what
        // the record's own content re-derives, and verification passes.
        let recomputed = recompute_release_digest(&rec)
            .expect("a built release always carries its canonical slot snapshot");
        assert_eq!(
            recomputed.as_str(),
            rec.release_sha256,
            "recompute must reproduce the digest build derived"
        );
        assert_eq!(
            ReleaseId::from_digest(&recomputed).as_str(),
            rec.release_id,
            "recompute must reproduce the release id build derived"
        );
        verify_release_identity(&rec).expect("a freshly built release verifies");

        // (2) MUTATION SENSITIVITY — content fields that feed the recompute.
        // Mapping digest.
        let mut r = rec.clone();
        r.provenance.mapping_sha256 = format!("{}!tampered", r.provenance.mapping_sha256);
        assert_content_mutation(&rec, &r, "mapping_sha256");
        // Behavior digest.
        let mut r = rec.clone();
        r.provenance.behavior_sha256 = format!("{}!tampered", r.provenance.behavior_sha256);
        assert_content_mutation(&rec, &r, "behavior_sha256");
        // The first variant's tree digest (the variant->tree binding value).
        let first_variant = rec
            .variants
            .keys()
            .next()
            .cloned()
            .expect("the grammar always yields at least one variant");
        let mut r = rec.clone();
        r.variants.insert(
            first_variant.clone(),
            format!("{}!tampered", rec.variants[&first_variant]),
        );
        assert_content_mutation(&rec, &r, "variant tree digest");
        // The variant->tree BINDING: adding a variant key changes the map.
        let mut r = rec.clone();
        let mut extra_name = "zzz-extra-variant".to_string();
        while rec.variants.contains_key(&extra_name) {
            extra_name.push('x');
        }
        r.variants.insert(extra_name, "tree-extra".to_string());
        assert_content_mutation(&rec, &r, "variant binding addition");
        // ... and removing a variant key changes the map.
        let mut r = rec.clone();
        r.variants.remove(&first_variant);
        assert_content_mutation(&rec, &r, "variant binding removal");
        // EVERY slot field of EVERY slot of EVERY variant is identity.
        for (variant, cs) in &rec.slots {
            for (i, slot) in cs.slots.iter().enumerate() {
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].id = format!("{}!tampered", slot.id);
                assert_content_mutation(&rec, &r, "slot id");

                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].server =
                    format!("{}!tampered", slot.server);
                assert_content_mutation(&rec, &r, "slot server");

                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].deploy_dir =
                    format!("{}!tampered", slot.deploy_dir);
                assert_content_mutation(&rec, &r, "slot deploy_dir");

                let mut r = rec.clone();
                let mut groups = slot.groups.clone();
                groups.push("tampered".to_string());
                r.slots.get_mut(variant).unwrap().slots[i].groups = groups;
                assert_content_mutation(&rec, &r, "slot groups");
            }
        }
        // Removing a slot changes the digest; clearing a variant's slots does
        // too (the snapshot keeps the variant key).
        let mut r = rec.clone();
        let (any_variant, any_cs) = rec.slots.iter().next().expect("at least one variant");
        if any_cs.slots.len() > 1 {
            r.slots.get_mut(any_variant).unwrap().slots.remove(0);
        } else {
            r.slots.get_mut(any_variant).unwrap().slots.clear();
        }
        assert_content_mutation(&rec, &r, "slot removal");
        // Emptying the ENTIRE slot snapshot: recompute refuses (None) and
        // verification fails closed (no legacy escape hatch).
        let mut r = rec.clone();
        r.slots.clear();
        assert!(
            recompute_release_digest(&r).is_none(),
            "an emptied slot snapshot must be refused by recompute"
        );
        let err = verify_release_identity(&r).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "an emptied slot snapshot must fail with an integrity error, got: {err}"
        );

        // (2) MUTATION SENSITIVITY — self-referential OUTPUT fields. The
        // stored digest, stored id, and record schema version are checked by
        // verification against the recompute, not trusted as inputs.
        let mut r = rec.clone();
        r.release_sha256 = "tampered-digest".to_string();
        assert_output_mutation(&rec, &r, "release_sha256");
        let mut r = rec.clone();
        r.release_id = "rel-sha256-tampered".to_string();
        assert_output_mutation(&rec, &r, "release_id");
        let mut r = rec.clone();
        r.release_schema_version = RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1);
        assert_output_mutation(&rec, &r, "release_schema_version");
        // The PAYLOAD schema version is frozen into the digest: a release
        // whose identity was derived from any other payload version fails the
        // recompute-and-verify check (the recompute always uses the canonical
        // payload version).
        let raw_slots: BTreeMap<String, Vec<SlotConfig>> = rec
            .slots
            .iter()
            .map(|(v, cs)| {
                (
                    v.clone(),
                    cs.slots
                        .iter()
                        .map(|s| {
                            SlotConfig::new(
                                s.id.clone(),
                                s.server.clone(),
                                PathBuf::from(&s.deploy_dir),
                                s.target.clone(),
                                s.groups.clone(),
                            )
                        })
                        .collect(),
                )
            })
            .collect();
        let slots_digest = variant_slots_digest(&raw_slots);
        for v in [
            0u32,
            RELEASE_PAYLOAD_SCHEMA_VERSION.wrapping_add(1),
            u32::MAX,
        ] {
            let mut r = rec.clone();
            let payload = CanonicalReleasePayload {
                schema_version: v,
                mapping_sha256: rec.provenance.mapping_sha256.clone(),
                behavior_sha256: rec.provenance.behavior_sha256.clone(),
                slots_digest: slots_digest.clone(),
                variants: rec.variants.clone(),
            };
            let digest = sha256_bytes(&serde_json::to_vec(&payload).expect("payload serializes"));
            r.release_sha256 = digest.clone();
            r.release_id = format!("rel-sha256-{digest}");
            assert_output_mutation(&rec, &r, &format!("payload schema version {v}"));
        }

        // (2) WHITELIST — the intentionally non-identity field. Mutating
        // `created_at` must NOT change the digest and must NOT break
        // verification.
        let mut r = rec.clone();
        r.created_at = "2099-12-31T23:59:59Z".to_string();
        assert_whitelist_mutation(&rec, &r, "created_at");

        // (3) CANONICAL ORDER-INDEPENDENCE: the same LOGICAL release written
        // differently canonicalizes to the SAME digest.
        //
        // B: each variant's slot declarations reversed, each slot's `groups`
        // reversed, and each `deploy_dir` respelled textually-differently but
        // lexically-equivalently. C: each slot's `groups` list gets its first
        // name appended again (a duplicate — deduplicated away by the
        // canonical form).
        let b_slots: BTreeMap<String, Vec<SlotConfig>> = c
            .variant_slots
            .iter()
            .map(|(v, defs)| {
                let mut out: Vec<SlotConfig> = defs.iter().rev().cloned().collect();
                for (i, s) in out.iter_mut().enumerate() {
                    s.groups.reverse();
                    let n = normalize_deploy_dir(s.deploy_dir());
                    *s = SlotConfig::new(
                        s.id.clone(),
                        s.server.clone(),
                        PathBuf::from(equivalent_dir_spellings(&n)[i % 3].clone()),
                        s.target.clone(),
                        s.groups.clone(),
                    );
                }
                (v.clone(), out)
            })
            .collect();
        let c_slots: BTreeMap<String, Vec<SlotConfig>> = c
            .variant_slots
            .iter()
            .map(|(v, defs)| {
                let out: Vec<SlotConfig> = defs
                    .iter()
                    .map(|s| {
                        let mut dup = s.clone();
                        if let Some(first) = dup.groups.first().cloned() {
                            dup.groups.push(first);
                        }
                        dup
                    })
                    .collect();
                (v.clone(), out)
            })
            .collect();
        let rec_b = build_release(
            &c.mapping_sha256,
            &c.behavior_sha256,
            &variants,
            &b_slots,
            Path::new("."),
        );
        let rec_c = build_release(
            &c.mapping_sha256,
            &c.behavior_sha256,
            &variants,
            &c_slots,
            Path::new("."),
        );
        assert_eq!(
            rec_b.release_sha256, rec.release_sha256,
            "reordered/reshuffled slot declarations must canonicalize to the same digest"
        );
        assert_eq!(
            rec_c.release_sha256, rec.release_sha256,
            "duplicated target names must dedup to the same digest"
        );
        assert_eq!(rec_b.release_id, rec.release_id, "reshuffled release id");
        assert_eq!(rec_c.release_id, rec.release_id, "deduplicated release id");
        assert_eq!(
            rec_b.slots, rec.slots,
            "the frozen canonical slot snapshot must be identical across spellings"
        );
        assert_eq!(
            rec_c.slots, rec.slots,
            "the frozen canonical slot snapshot must be identical after dedup"
        );
        verify_release_identity(&rec_b).expect("the reshuffled release verifies");
        verify_release_identity(&rec_c).expect("the deduplicated release verifies");
    }

    // -------------------------------------------------------------------
    // COMPLETE-VALIDATOR ACCEPTANCE (the review's property): arbitrary
    // nested release/behavior documents — valid and systematically-invalid
    // (bad adapter names, duplicate slots, missing behavior coverage, empty
    // argv, zero attempts, irrelevant fields at each nesting level) — are
    // compared against an INDEPENDENT semantic reference validator; they
    // must AGREE on every document, and every document the production
    // validator accepts must yield a [`ValidatedRelease`] whose domain
    // invariants hold.
    // -------------------------------------------------------------------

    /// One generated document: a frozen release record (identity-consistent
    /// with its OWN composition, optionally identity-tampered), its behavior
    /// document (wire JSON), and the available-server set of the graph.
    #[derive(Clone, Debug)]
    struct GraphDoc {
        rec: ReleaseRecord,
        behaviors_json: serde_json::Value,
        servers: BTreeSet<String>,
    }

    fn doc_variant_name_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "standard".to_string(),
            "canary".to_string(),
            "".to_string(),
            "Variant-2".to_string(),
        ])
    }

    fn doc_slot_id_strategy() -> impl Strategy<Value = String> {
        // A SMALL pool: slots SHARE ids across variants (duplicate detection
        // must be snapshot-wide), and the pool includes an invalid id.
        prop::sample::select(vec![
            "p1".to_string(),
            "p2".to_string(),
            "p3".to_string(),
            "".to_string(),
        ])
    }

    fn doc_server_strategy() -> impl Strategy<Value = String> {
        // The graph's server set is FIXED at {server-01, server-02}; the
        // pool includes known servers (valid bindings) and unknown/malformed
        // servers (invalid bindings).
        prop::sample::select(vec![
            "server-01".to_string(),
            "server-02".to_string(),
            "server-03".to_string(),
            "".to_string(),
            "edge/1".to_string(),
        ])
    }

    fn doc_target_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "production".to_string(),
            "edge".to_string(),
            "".to_string(),
        ])
    }

    fn doc_deploy_dir_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "/srv/deploy/example".to_string(),
            "//srv/deploy/example/".to_string(),
            "relative/path".to_string(),
            "/".to_string(),
            "/srv/../x".to_string(),
            "".to_string(),
        ])
    }

    fn doc_group_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "canary".to_string(),
            "wave-1".to_string(),
            "".to_string(),
            "a/b".to_string(),
        ])
    }

    /// A VALID closed-enum activation wire (common case): `none` with the
    /// canonical defaults, or `systemd` with 1..2 valid units.
    fn valid_activation_wire() -> impl Strategy<Value = serde_json::Value> {
        prop_oneof![
            Just(serde_json::json!({
                "adapter": "none", "scope": "user", "reconcile_managed_units": true,
                "units": []
            })),
            (any::<bool>(), any::<bool>()).prop_map(|(a, b)| {
                serde_json::json!({
                    "adapter": "systemd", "scope": "system",
                    "reconcile_managed_units": true,
                    "units": [{
                        "name": "app.service",
                        "artifact_path": "integration/systemd/app.service",
                        "enable": a,
                        "restart": b
                    }]
                })
            }),
        ]
    }

    /// A VALID closed-enum verification wire: `command` with a non-empty
    /// argv (template variables known), nonzero attempts/timeout.
    fn valid_verification_wire() -> impl Strategy<Value = serde_json::Value> {
        (
            prop::sample::select(vec![
                vec!["true".to_string()],
                vec!["{{ deploy_dir }}/bin/probe".to_string(), "--x".to_string()],
            ]),
            1..5u64,
            1..4u32,
            0..2u64,
        )
            .prop_map(|(argv, timeout, attempts, interval)| {
                serde_json::json!({
                    "adapter": "command",
                    "argv": argv,
                    "timeout_seconds": timeout,
                    "attempts": attempts,
                    "interval_seconds": interval
                })
            })
    }

    /// A SYSTEMATICALLY-INVALID wire contract: an unsupported adapter, a
    /// `none` contract carrying irrelevant fields, a systemd contract
    /// without units or with an unsafe unit, an empty argv, zero
    /// attempts/timeout, an unknown template variable, or an unknown field
    /// at the contract/activation/unit/verification nesting level.
    fn invalid_contract_wire() -> impl Strategy<Value = serde_json::Value> {
        let activation_invalids = vec![
            serde_json::json!({"adapter": "bogus", "scope": "user", "reconcile_managed_units": true, "units": []}),
            serde_json::json!({"adapter": "none", "scope": "system", "reconcile_managed_units": true, "units": []}),
            serde_json::json!({"adapter": "none", "scope": "user", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}),
            serde_json::json!({"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": []}),
            serde_json::json!({"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "../app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}]}),
            serde_json::json!({"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "/etc/x.service", "enable": true, "restart": true}]}),
            serde_json::json!({"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true}], "scope2": "user"}),
            serde_json::json!({"adapter": "systemd", "scope": "system", "reconcile_managed_units": true, "units": [{"name": "app.service", "artifact_path": "integration/systemd/app.service", "enable": true, "restart": true, "bogus": true}]}),
        ];
        let verification_invalids = vec![
            serde_json::json!({"adapter": "docker", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}),
            serde_json::json!({"adapter": "command", "argv": [], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}),
            serde_json::json!({"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 0, "interval_seconds": 1}),
            serde_json::json!({"adapter": "command", "argv": ["true"], "timeout_seconds": 0, "attempts": 2, "interval_seconds": 1}),
            serde_json::json!({"adapter": "command", "argv": ["{{ bogus }}"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1}),
            serde_json::json!({"adapter": "command", "argv": ["true"], "timeout_seconds": 30, "attempts": 2, "interval_seconds": 1, "retries": 3}),
        ];
        (
            prop::sample::select(activation_invalids),
            prop::sample::select(verification_invalids),
        )
            .prop_map(|(activation, verification)| {
                serde_json::json!({"activation": activation, "verification": verification})
            })
    }

    fn contract_wire_strategy() -> impl Strategy<Value = serde_json::Value> {
        prop_oneof![
            4 => valid_activation_wire().prop_flat_map(|activation| {
                valid_verification_wire().prop_map(move |verification| {
                    serde_json::json!({"activation": activation, "verification": verification})
                })
            }),
            1 => invalid_contract_wire(),
            1 => valid_verification_wire().prop_map(|verification| {
                serde_json::json!({
                    "activation": {"adapter": "none", "scope": "user", "reconcile_managed_units": true, "units": []},
                    "verification": verification,
                    "extra": 1
                })
            }),
        ]
    }

    fn behavior_doc_strategy() -> impl Strategy<Value = serde_json::Value> {
        prop::collection::btree_map(doc_variant_name_strategy(), contract_wire_strategy(), 0..3)
            .prop_map(|m| {
                let mut map = serde_json::Map::new();
                for (k, v) in m {
                    map.insert(k, v);
                }
                serde_json::Value::Object(map)
            })
    }

    fn canonical_slot_strategy() -> impl Strategy<Value = CanonicalSlot> {
        (
            doc_slot_id_strategy(),
            doc_server_strategy(),
            doc_deploy_dir_strategy(),
            doc_target_strategy(),
            prop::collection::vec(doc_group_strategy(), 0..2),
        )
            .prop_map(|(id, server, deploy_dir, target, groups)| CanonicalSlot {
                id,
                server,
                deploy_dir,
                target,
                groups,
            })
    }

    /// The full generated document. The record's identity digest is built
    /// A CANONICALLY-VALID document: distinct valid variant names, each with
    /// its slots on KNOWN servers (server-01/02) and valid absolute
    /// deploy_dirs, behaviors covering EXACTLY the variant set (valid
    /// closed-enum contracts), and the CANONICAL behavior digest — so the
    /// generator provably reaches the ACCEPTED branch (the agreement
    /// property is never vacuous: it compares production and the reference
    /// on BOTH accepted and refused documents).
    fn canonical_valid_doc_strategy() -> impl Strategy<Value = GraphDoc> {
        (1..=2usize).prop_flat_map(|count| {
            prop::sample::subsequence(vec!["standard".to_string(), "canary".to_string()], count)
                .prop_flat_map(move |names| {
                    let name_count = names.len();
                    let names_for_slots = names.clone();
                    // Per-variant slots (each variant 0..2 slots on KNOWN
                    // servers only — the valid graph's server set).
                    prop::collection::vec(
                        prop::collection::vec(
                            (
                                doc_slot_id_strategy(),
                                prop::sample::select(vec![
                                    "server-01".to_string(),
                                    "server-02".to_string(),
                                ]),
                                doc_deploy_dir_strategy(),
                                doc_target_strategy(),
                                prop::collection::vec(doc_group_strategy(), 0..2),
                            )
                                .prop_map(
                                    |(id, server, deploy_dir, target, groups)| CanonicalSlot {
                                        id,
                                        server,
                                        deploy_dir,
                                        target,
                                        groups,
                                    },
                                ),
                            0..2,
                        ),
                        name_count,
                    )
                    .prop_flat_map(move |per_variant_slots| {
                        let names = names_for_slots.clone();
                        // Valid contracts covering EXACTLY the variants.
                        prop::collection::vec(
                            valid_activation_wire().prop_flat_map(|activation| {
                                valid_verification_wire().prop_map(move |verification| {
                                    serde_json::json!({
                                        "activation": activation,
                                        "verification": verification,
                                    })
                                })
                            }),
                            names.len(),
                        )
                        .prop_map(move |contracts| {
                            let servers =
                                BTreeSet::from(["server-01".to_string(), "server-02".to_string()]);
                            let mut variants: BTreeMap<String, String> = BTreeMap::new();
                            let mut slot_defs: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
                            let mut behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::new();
                            for (i, name) in names.iter().enumerate() {
                                // A VALID 64-hex tree digest (the typed graph
                                // gates tree digests at `try_new`).
                                variants.insert(name.clone(), hex::encode([0xAAu8; 32]));
                                slot_defs.insert(
                                    name.clone(),
                                    per_variant_slots[i]
                                        .iter()
                                        .map(|s| {
                                            SlotConfig::new(
                                                s.id.clone(),
                                                s.server.clone(),
                                                PathBuf::from(&s.deploy_dir),
                                                s.target.clone(),
                                                s.groups.clone(),
                                            )
                                        })
                                        .collect(),
                                );
                                behaviors.insert(
                                    name.clone(),
                                    serde_json::from_value(contracts[i].clone())
                                        .expect("a valid contract wire parses"),
                                );
                            }
                            let bindings: BTreeMap<VariantName, TreeDigest> = variants
                                .iter()
                                .map(|(n, t)| {
                                    (VariantName::new(n.clone()), TreeDigest::new(t.clone()))
                                })
                                .collect();
                            let behavior_sha = variant_behaviors_digest(&behaviors);
                            let rec = build_release(
                                &hex::encode([0xBBu8; 8]),
                                &behavior_sha,
                                &bindings,
                                &slot_defs,
                                Path::new("."),
                            );
                            GraphDoc {
                                rec,
                                behaviors_json: serde_json::to_value(&behaviors)
                                    .expect("behaviors serialize"),
                                servers,
                            }
                        })
                    })
                })
        })
    }

    /// The mixed generator: mostly MUTATED (often-invalid) documents plus a
    /// canonical-valid arm, so the agreement property compares production and
    /// the independent reference on both accepted and refused documents.
    fn graph_doc_strategy() -> impl Strategy<Value = GraphDoc> {
        prop_oneof![
            3 => mutated_doc_strategy(),
            2 => canonical_valid_doc_strategy(),
        ]
    }

    /// from the SAME composition (via [`build_release`], so a non-tampered
    /// record is internally consistent), then mutated per the generated
    /// flags: identity tamper, a variant binding addition, a removed /
    /// dangling / emptied slot snapshot entry, and a behavior-digest
    /// disagreement (arbitrary `behavior_sha256`).
    fn mutated_doc_strategy() -> impl Strategy<Value = GraphDoc> {
        (
            prop::collection::vec(
                (
                    doc_variant_name_strategy(),
                    any::<[u8; 32]>(),
                    prop::collection::vec(canonical_slot_strategy(), 0..3),
                ),
                1..4,
            ),
            behavior_doc_strategy(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<bool>(),
            prop::sample::select(vec![0u8, 1, 2]),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    groups,
                    behaviors_json,
                    mapping_seed,
                    digest_seed,
                    tamper_identity,
                    slot_mutation,
                    extra_variant_binding,
                    canonical_digest,
                )| {
                    let servers =
                        BTreeSet::from(["server-01".to_string(), "server-02".to_string()]);
                    let mut variants: BTreeMap<String, String> = BTreeMap::new();
                    let mut slot_defs: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
                    for (name, tree_seed, slots) in &groups {
                        if variants.contains_key(name) {
                            continue;
                        }
                        variants.insert(name.clone(), hex::encode(tree_seed));
                        let defs: Vec<SlotConfig> = slots
                            .iter()
                            .map(|s| {
                                SlotConfig::new(
                                    s.id.clone(),
                                    s.server.clone(),
                                    PathBuf::from(&s.deploy_dir),
                                    s.target.clone(),
                                    s.groups.clone(),
                                )
                            })
                            .collect();
                        slot_defs.insert(name.clone(), defs);
                    }
                    // SNAPSHOT MUTATIONS happen on the PRE-BUILD inputs so
                    // the record's stored identity recomputes CONSISTENTLY
                    // from the mutated snapshot: the refusal then comes from
                    // the GRAPH rule (completeness / dangling entries), not
                    // from an identity mismatch that would shadow it.
                    match slot_mutation {
                        1 => {
                            // A variant binding with NO declared slots
                            // (incomplete slot declarations).
                            if let Some(first) = slot_defs.keys().next().cloned() {
                                slot_defs.remove(&first);
                            }
                        }
                        2 => {
                            // A DANGLE: a slot snapshot entry for an
                            // undeclared variant.
                            slot_defs.insert(
                                "zzz-dangling-variant".to_string(),
                                vec![SlotConfig::new(
                                    "p9",
                                    "server-01",
                                    PathBuf::from("/srv/dangling"),
                                    "production",
                                    Vec::new(),
                                )],
                            );
                        }
                        _ => {}
                    }
                    if extra_variant_binding {
                        // A variant binding with no slots and (usually) no
                        // behavior contract: incomplete on both graphs.
                        variants.insert("zzz-extra".to_string(), hex::encode(digest_seed));
                    }
                    let bindings: BTreeMap<VariantName, TreeDigest> = variants
                        .iter()
                        .map(|(n, t)| (VariantName::new(n.clone()), TreeDigest::new(t.clone())))
                        .collect();
                    // The provenance behavior_sha256 is sometimes the
                    // CANONICAL digest of the wire behaviors (when the wire
                    // parses) — a digest-consistent behavior graph —
                    // sometimes an arbitrary hex (disagreement).
                    let behaviors_digest = match serde_json::from_value::<
                        BTreeMap<String, BehaviorContract>,
                    >(behaviors_json.clone())
                    {
                        Ok(contracts) if canonical_digest => variant_behaviors_digest(&contracts),
                        _ => hex::encode(digest_seed),
                    };
                    let mut rec = build_release(
                        &hex::encode(mapping_seed),
                        &behaviors_digest,
                        &bindings,
                        &slot_defs,
                        Path::new("."),
                    );
                    if tamper_identity {
                        rec.release_sha256 = "tampered-identity".to_string();
                    }
                    GraphDoc {
                        rec,
                        behaviors_json,
                        servers,
                    }
                },
            )
    }

    /// The INDEPENDENT leaf predicates (the scalar rules, re-implemented
    /// plainly — NOT the production parsers).
    fn ref_name_ok(s: &str) -> bool {
        !s.trim().is_empty()
            && s.trim() == s
            && !s.chars().any(|c| c.is_control())
            && !s.contains('/')
            && !s.contains('\\')
            && s != "."
            && s != ".."
    }

    /// The deploy_dir rule: absolute, traversal-free (`/`-split `.`/`..`
    /// segments refused), at least one normal component below the root.
    fn ref_deploy_dir_ok(s: &str) -> bool {
        if !Path::new(s).is_absolute() {
            return false;
        }
        let mut normal = 0usize;
        for seg in s.split('/') {
            if seg == "." || seg == ".." {
                return false;
            }
            if !seg.is_empty() {
                normal += 1;
            }
        }
        normal > 0
    }

    /// The tree-digest rule: exactly 64 lowercase hex characters (the exact
    /// form [`crate::digest::sha256_bytes`] produces) — the rule
    /// [`crate::identity::TreeDigest::parse`] enforces.
    fn ref_digest_ok(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// The INDEPENDENT semantic reference validator: re-implements the
    /// release-graph + closed-behavior rules without calling
    /// [`ValidatedRelease`]. The only shared machinery is the digest
    /// recompute (the identity rule itself) and the closed-enum serde parse
    /// of the behavior wire (the wire boundary both sides use); every
    /// GRAPH rule below is re-derived from the plain predicates.
    fn reference_accepts(doc: &GraphDoc) -> bool {
        let rec = &doc.rec;
        // Identity: schema version + recompute-and-verify.
        if rec.release_schema_version != RELEASE_RECORD_SCHEMA_VERSION {
            return false;
        }
        let Some(rd) = recompute_release_digest(rec) else {
            return false;
        };
        if rec.release_sha256 != rd.as_str()
            || rec.release_id != ReleaseId::from_digest(&rd).as_str()
        {
            return false;
        }
        // Behavior wire must parse through the closed enums (unsupported
        // adapters / empty argv / zero attempts / irrelevant fields refuse
        // HERE) and must agree with the record provenance digest.
        let Ok(behaviors) = serde_json::from_value::<BTreeMap<String, BehaviorContract>>(
            doc.behaviors_json.clone(),
        ) else {
            return false;
        };
        if variant_behaviors_digest(&behaviors) != rec.provenance.behavior_sha256 {
            return false;
        }
        // Complete behavior coverage (both directions).
        if rec.variants.keys().ne(behaviors.keys()) {
            return false;
        }
        // Complete slot declarations (both directions).
        if rec.variants.keys().ne(rec.slots.keys()) {
            return false;
        }
        // Every variant name and every tree digest must be a valid leaf (the
        // typed graph's gate: an invalid name or digest is refused at
        // `try_new`).
        if !rec.variants.keys().all(|v| ref_name_ok(v)) {
            return false;
        }
        if !rec.variants.values().all(|t| ref_digest_ok(t)) {
            return false;
        }
        // Per-slot graph rules.
        let mut seen_ids = BTreeSet::new();
        for cs in rec.slots.values() {
            for s in &cs.slots {
                if !ref_name_ok(&s.id) || !ref_name_ok(&s.server) || !ref_name_ok(&s.target) {
                    return false;
                }
                if !s.groups.iter().all(|g| ref_name_ok(g)) {
                    return false;
                }
                if !ref_deploy_dir_ok(&s.deploy_dir) {
                    return false;
                }
                if !seen_ids.insert(s.id.clone()) {
                    return false;
                }
                if !doc.servers.contains(&s.server) {
                    return false;
                }
            }
        }
        true
    }

    /// Production acceptance: the wire behaviors parsed through the closed
    /// enums, then [`ValidatedRelease::try_new`].
    fn production_accepts(doc: &GraphDoc) -> bool {
        let Ok(behaviors) = serde_json::from_value::<BTreeMap<String, BehaviorContract>>(
            doc.behaviors_json.clone(),
        ) else {
            return false;
        };
        ValidatedRelease::try_new(doc.rec.clone(), behaviors, &doc.servers).is_ok()
    }

    /// The acceptance contract for one generated document: production and
    /// the independent reference AGREE, and an accepted document yields a
    /// [`ValidatedRelease`] whose domain invariants hold.
    fn run_acceptance_contract(doc: &GraphDoc) {
        let prod_ok = production_accepts(doc);
        let ref_ok = reference_accepts(doc);
        assert_eq!(
            prod_ok, ref_ok,
            "production validator and the independent reference must agree on the document:\n{doc:#?}"
        );
        if prod_ok {
            let behaviors = serde_json::from_value::<BTreeMap<String, BehaviorContract>>(
                doc.behaviors_json.clone(),
            )
            .expect("accepted documents parse");
            let vr = ValidatedRelease::try_new(doc.rec.clone(), behaviors, &doc.servers)
                .expect("accepted");
            // Domain invariants of the accepted value.
            verify_release_identity(vr.record()).expect("record identity still verifies");
            assert!(
                vr.record().variants.keys().eq(vr.record().slots.keys()),
                "every variant's slots declared"
            );
            assert!(
                vr.record().variants.keys().eq(vr.behaviors().keys()),
                "behavior coverage complete"
            );
            assert_eq!(
                crate::verify::release::variant_behaviors_digest(vr.behaviors()),
                vr.record().provenance.behavior_sha256,
                "behavior graph consistent with the record provenance"
            );
            let mut ids = BTreeSet::new();
            for cs in vr.record().slots.values() {
                for s in &cs.slots {
                    assert!(ids.insert(s.id.clone()), "no duplicate slot id '{}'", s.id);
                    assert!(
                        doc.servers.contains(&s.server),
                        "slot '{}' binds a known server",
                        s.id
                    );
                    assert!(
                        AbsoluteDeployDir::parse(&s.deploy_dir).is_ok(),
                        "slot '{}' deploy_dir absolute and valid",
                        s.id
                    );
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // TYPED-GRAPH PROJECTION (the review's property): every release the
    // validator ACCEPTS must support ALL downstream projections — the typed
    // variant→tree bindings, the typed slot projections, the canonical
    // group sets — WITHOUT panic (no parse/expect anywhere downstream). The
    // record is mutated at EVERY key/value (variant bindings, slot fields,
    // groups, identity fields) and its identity RECOMPUTED from the mutated
    // content, so the validator's SEMANTIC rules — not the identity check —
    // decide acceptance, and every accepted mutation must still project.
    // -------------------------------------------------------------------

    /// Flip the first hex digit of a 64-hex digest to a DIFFERENT valid hex
    /// digit, producing a distinct valid digest (the accepted-branch
    /// mutation for a tree binding).
    fn flip_hex_digit(s: &str) -> String {
        let mut bytes = s.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("a valid digest is ASCII")
    }

    /// Every single key/value mutation of a release record's CONTENT, with
    /// the identity RECOMPUTED from the mutated content (so the record is
    /// self-consistent and the validator's SEMANTIC rules — not the identity
    /// check — decide acceptance). The base record is included first.
    fn mutated_records_with_recomputed_identity(rec: &ReleaseRecord) -> Vec<ReleaseRecord> {
        let mut out = vec![rec.clone()];
        // Variant binding VALUES: a valid different digest (accepted when the
        // name is valid) and an invalid digest (refused).
        for (name, tree) in &rec.variants {
            let mut r = rec.clone();
            r.variants.insert(name.clone(), flip_hex_digit(tree));
            out.push(r);
            let mut r = rec.clone();
            r.variants.insert(name.clone(), format!("{tree}!tampered"));
            out.push(r);
        }
        // Variant binding KEYS: add a new variant (refused: behavior
        // coverage + slot completeness) and remove the first variant
        // (refused: orphan contract + dangling snapshot).
        let mut r = rec.clone();
        let mut extra = "zzz-extra".to_string();
        while r.variants.contains_key(&extra) {
            extra.push('x');
        }
        r.variants.insert(extra, hex::encode([0xAAu8; 32]));
        out.push(r);
        let mut r = rec.clone();
        if let Some(first) = r.variants.keys().next().cloned() {
            r.variants.remove(&first);
        }
        out.push(r);
        // EVERY slot field of EVERY slot of EVERY variant.
        for (variant, cs) in &rec.slots {
            for (i, _slot) in cs.slots.iter().enumerate() {
                // id: a valid different id (accepted when no duplicate) and
                // an invalid id (refused).
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].id = "p9".to_string();
                out.push(r);
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].id = "".to_string();
                out.push(r);
                // server: a known server (accepted) and an unknown server
                // (refused).
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].server = "server-01".to_string();
                out.push(r);
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].server = "server-99".to_string();
                out.push(r);
                // deploy_dir: a valid different path (accepted) and an
                // invalid one (refused).
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].deploy_dir = "/srv/other".to_string();
                out.push(r);
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].deploy_dir = "relative/path".to_string();
                out.push(r);
                // target: a valid different target (accepted).
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i].target = "staging".to_string();
                out.push(r);
                // groups: a valid extra group (accepted) and an invalid
                // group (refused).
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i]
                    .groups
                    .push("wave-9".to_string());
                out.push(r);
                let mut r = rec.clone();
                r.slots.get_mut(variant).unwrap().slots[i]
                    .groups
                    .push("a/b".to_string());
                out.push(r);
            }
        }
        // Identity fields: mapping digest (accepted — not checked against
        // anything), behavior digest (refused — the behaviors no longer
        // match), created_at (accepted — whitelisted).
        let mut r = rec.clone();
        r.provenance.mapping_sha256 = format!("{}!tampered", r.provenance.mapping_sha256);
        out.push(r);
        let mut r = rec.clone();
        r.provenance.behavior_sha256 = format!("{}!tampered", r.provenance.behavior_sha256);
        out.push(r);
        let mut r = rec.clone();
        r.created_at = "2099-12-31T23:59:59Z".to_string();
        out.push(r);
        // Recompute the identity from each mutated record's own content.
        out.into_iter()
            .map(|mut r| {
                if let Some(d) = recompute_release_digest(&r) {
                    r.release_sha256 = d.as_str().to_string();
                    r.release_id = ReleaseId::from_digest(&d).as_str().to_string();
                }
                r
            })
            .collect()
    }

    /// THE TYPED-GRAPH PROJECTION CONTRACT for one generated document: for
    /// the record and every single key/value mutation of it (with the
    /// identity recomputed), EVERY release the validator ACCEPTS must
    /// support ALL downstream projections — the typed variant→tree bindings,
    /// the typed slot projections, the canonical group sets — WITHOUT panic.
    fn run_typed_projection_contract(doc: &GraphDoc) {
        let Ok(behaviors) = serde_json::from_value::<BTreeMap<String, BehaviorContract>>(
            doc.behaviors_json.clone(),
        ) else {
            return; // unparseable behaviors: try_new refuses; nothing to project
        };
        for rec in mutated_records_with_recomputed_identity(&doc.rec) {
            let Ok(vr) = ValidatedRelease::try_new(rec.clone(), behaviors.clone(), &doc.servers)
            else {
                continue; // refused: nothing to project
            };
            // (1) The TYPED variant→tree bindings: every record binding is
            // typed and agrees with the wire record.
            assert_eq!(
                vr.variant_bindings().len(),
                vr.record().variants.len(),
                "every record variant binding is typed"
            );
            for (name, tree) in vr.variant_bindings() {
                assert_eq!(
                    vr.record().variants[name.as_str()],
                    tree.as_str(),
                    "the typed binding agrees with the wire binding"
                );
            }
            // (2) The TYPED slot projections: every record slot leaf is
            // typed and agrees with the wire record.
            assert_eq!(vr.slots().len(), vr.record().slots.len());
            for (variant, slots) in vr.slots() {
                let cs = &vr.record().slots[variant.as_str()];
                assert_eq!(slots.len(), cs.slots.len());
                for (i, slot) in slots.iter().enumerate() {
                    assert_eq!(slot.id().as_str(), cs.slots[i].id);
                    assert_eq!(slot.server().as_str(), cs.slots[i].server);
                    assert_eq!(
                        slot.deploy_dir().as_path().to_string_lossy(),
                        cs.slots[i].deploy_dir,
                        "the typed deploy_dir is the normalized wire form"
                    );
                    assert_eq!(slot.target().as_str(), cs.slots[i].target);
                    // (3) The CANONICAL group set: sorted, deduplicated,
                    // typed — exactly the wire set's deduplicated membership.
                    let typed: BTreeSet<String> = slot
                        .groups()
                        .iter()
                        .map(|g| g.as_str().to_string())
                        .collect();
                    let wire: BTreeSet<String> = cs.slots[i].groups.iter().cloned().collect();
                    assert_eq!(
                        typed, wire,
                        "the canonical group set is the deduplicated wire set"
                    );
                }
            }
        }
    }

    /// The generator must actually REACH the accepted branch (otherwise the
    /// acceptance property would be vacuously agreeing on refusals only):
    /// under the pinned seed, drawing 400 documents yields at least one that
    /// the reference accepts, and every drawn document keeps production and
    /// reference in agreement.
    #[test]
    fn acceptance_generator_reaches_valid_documents() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
        let mut runner = TestRunner::new_with_rng(
            proptest::test_runner::Config::default(),
            TestRng::from_seed(
                RngAlgorithm::XorShift,
                &0x5EED_5EEDu64.to_le_bytes().repeat(2),
            ),
        );
        let mut accepted = 0;
        for _ in 0..400 {
            let doc = graph_doc_strategy()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            assert_eq!(
                production_accepts(&doc),
                reference_accepts(&doc),
                "agreement"
            );
            if reference_accepts(&doc) {
                accepted += 1;
            }
        }
        assert!(
            accepted > 0,
            "generator must reach accepted documents (got {accepted}/400)"
        );
    }

    proptest! {
        // MAIN acceptance property: ORDINARY RANDOMIZED SEEDS with FAILURE
        // PERSISTENCE
        // (proptest's defaults) — a failing vector writes to
        // `proptest-regressions/release.txt` and is replayed on the next run
        // (commit it so CI keeps reproducing the regression until fixed). The
        // case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn release_identity_digest_contract(components in release_components_strategy()) {
            run_release_identity_contract(&components);
        }

        #[test]
        fn validated_release_acceptance_property(doc in graph_doc_strategy()) {
            run_acceptance_contract(&doc);
        }

        #[test]
        fn validated_release_typed_projection_property(doc in graph_doc_strategy()) {
            run_typed_projection_contract(&doc);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION: the deterministic floor for CI. The same
        // generator under the pinned 0x5EED_5EED seed with no persistence runs
        // the IDENTICAL vectors on every invocation, so the suite stays
        // reproducible even when no failure has ever been persisted by the
        // main test. The case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn release_identity_digest_contract_fixed_seed_regression(
            components in release_components_strategy(),
        ) {
            run_release_identity_contract(&components);
        }

        #[test]
        fn validated_release_acceptance_property_fixed_seed_regression(doc in graph_doc_strategy()) {
            run_acceptance_contract(&doc);
        }

        #[test]
        fn validated_release_typed_projection_property_fixed_seed_regression(
            doc in graph_doc_strategy(),
        ) {
            run_typed_projection_contract(&doc);
        }
    }

    // -------------------------------------------------------------------
    // THE UNFORGEABILITY PROPERTY: every publicly constructible behavior
    // round-trips through the wire, and every rejected raw behavior is
    // unconstructible directly.
    // -------------------------------------------------------------------
    //
    // (a) ROUND-TRIP: every [`BehaviorContract`] built through the validated
    //     constructors (a closed-enum `Activation`/`Verification` pair)
    //     serializes to the canonical wire form and deserializes back to an
    //     EQUAL contract — the wire shape the frozen behavior records and
    //     the digest functions depend on stays byte-stable.
    // (b) UNCONSTRUCTIBLE: every systematically-invalid raw behavior the
    //     wire refuses (empty argv, zero attempts, zero timeout, unknown
    //     template variables, irrelevant fields, systemd without units, an
    //     invalid unit name/artifact path) is IMPOSSIBLE to construct
    //     directly — the validated constructors refuse it, so an invalid
    //     contract can only ever enter through the raw wire parse (which
    //     refuses it at the record boundary).
    //
    // Bounded `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`, fast
    // default), fixed seed 0x5EED_5EED (house style), no failure
    // persistence — the identical vectors on every run.

    use crate::config::{
        Activation, ActivationScope, UnitDef, ValidatedCommand, ValidatedSystemd, Verification,
    };

    /// A valid verification argv element: a plain token or a reference to a
    /// KNOWN template variable (both pass `validate_template_variables`).
    fn valid_argv_element() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                "true".to_string(),
                "health-check".to_string(),
                "--tag".to_string(),
                "probe".to_string(),
            ]),
            prop::sample::select(vec![
                "{{ deploy_dir }}".to_string(),
                "{{ variant }}".to_string(),
                "{{ target }}".to_string(),
                "{{ slot }}".to_string(),
                "{{ server }}".to_string(),
            ]),
        ]
    }

    /// A valid systemd unit: a single-filename name and an artifact-relative
    /// path (both pass the validated [`UnitDef::new`]).
    fn valid_unit() -> impl Strategy<Value = UnitDef> {
        (
            prop::sample::select(vec![
                "app.service".to_string(),
                "example.service".to_string(),
                "worker.service".to_string(),
            ]),
            prop::sample::select(vec![
                "app/example.service".to_string(),
                "integration/systemd/app.service".to_string(),
                "units/app.service".to_string(),
            ]),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(name, artifact_path, enable, restart)| {
                UnitDef::new(name, artifact_path, enable, restart).expect("validated unit")
            })
    }

    /// A valid closed-enum activation: `None`, or `Systemd` with 1..=2
    /// validated units.
    fn valid_activation() -> impl Strategy<Value = Activation> {
        prop_oneof![
            Just(Activation::None),
            (
                prop::sample::select(vec![ActivationScope::User, ActivationScope::System]),
                any::<bool>(),
                prop::collection::vec(valid_unit(), 1..=2),
            )
                .prop_map(|(scope, reconcile, units)| {
                    Activation::Systemd(
                        ValidatedSystemd::new(scope, reconcile, units).expect("validated systemd"),
                    )
                }),
        ]
    }

    /// A valid closed-enum verification: a `Command` with a non-empty argv
    /// of known-variable elements and nonzero timeout/attempts.
    fn valid_verification() -> impl Strategy<Value = Verification> {
        (
            prop::collection::vec(valid_argv_element(), 1..=3),
            1u64..=3600,
            1u32..=10,
            0u64..=60,
        )
            .prop_map(|(argv, timeout, attempts, interval)| {
                Verification::Command(
                    ValidatedCommand::new(argv, timeout, attempts, interval)
                        .expect("validated command"),
                )
            })
    }

    /// A valid [`BehaviorContract`] built ONLY through the validated
    /// constructors — the publicly constructible space.
    fn valid_behavior_contract() -> impl Strategy<Value = BehaviorContract> {
        (valid_activation(), valid_verification())
            .prop_map(|(activation, verification)| BehaviorContract::new(activation, verification))
    }

    /// One systematically-invalid raw behavior class the wire refuses.
    #[derive(Clone, Copy, Debug)]
    enum InvalidBehaviorClass {
        EmptyArgv,
        ZeroAttempts,
        ZeroTimeout,
        UnknownTemplateVariable,
        SystemdWithoutUnits,
        InvalidUnitName,
        InvalidUnitArtifactPath,
        NoneWithUnits,
        NoneWithNonDefaultScope,
    }

    fn invalid_behavior_class() -> impl Strategy<Value = InvalidBehaviorClass> {
        prop::sample::select(vec![
            InvalidBehaviorClass::EmptyArgv,
            InvalidBehaviorClass::ZeroAttempts,
            InvalidBehaviorClass::ZeroTimeout,
            InvalidBehaviorClass::UnknownTemplateVariable,
            InvalidBehaviorClass::SystemdWithoutUnits,
            InvalidBehaviorClass::InvalidUnitName,
            InvalidBehaviorClass::InvalidUnitArtifactPath,
            InvalidBehaviorClass::NoneWithUnits,
            InvalidBehaviorClass::NoneWithNonDefaultScope,
        ])
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        // (a) THE ROUND-TRIP PROPERTY: every publicly constructible behavior
        // contract serializes to the canonical wire form and deserializes
        // back to an EQUAL contract — the wire shape the frozen behavior
        // records and the digest functions depend on stays byte-stable.
        #[test]
        fn constructible_behaviors_round_trip_the_wire(contract in valid_behavior_contract()) {
            let wire = serde_json::to_value(&contract).expect("contract serializes");
            let back: BehaviorContract =
                serde_json::from_value(wire.clone()).expect("wire form deserializes");
            assert_eq!(back, contract, "round-trip must preserve the contract");
            // The wire form is the canonical `ActivationConfig`/`VerificationConfig`
            // shape (what the digest functions hash).
            let canonical = serde_json::json!({
                "activation": contract.activation().to_config(),
                "verification": contract.verification().to_config(),
            });
            assert_eq!(
                wire, canonical,
                "the wire form must be the canonical contract shape"
            );
        }

        // (b) THE UNCONSTRUCTIBILITY PROPERTY: every rejected raw behavior
        // (the systematically-invalid wires the config/release tests
        // enumerate) is IMPOSSIBLE to construct directly — the validated
        // constructors refuse it, so an invalid contract can only ever
        // enter through the raw wire parse (which refuses it at the record
        // boundary).
        #[test]
        fn rejected_raw_behaviors_are_unconstructible(class in invalid_behavior_class()) {
            match class {
                InvalidBehaviorClass::EmptyArgv => {
                    assert!(
                        ValidatedCommand::new(Vec::new(), 5, 1, 0).is_err(),
                        "empty argv must be refused by the validated constructor"
                    );
                }
                InvalidBehaviorClass::ZeroAttempts => {
                    assert!(
                        ValidatedCommand::new(vec!["true".to_string()], 5, 0, 0).is_err(),
                        "zero attempts must be refused by the validated constructor"
                    );
                }
                InvalidBehaviorClass::ZeroTimeout => {
                    assert!(
                        ValidatedCommand::new(vec!["true".to_string()], 0, 1, 0).is_err(),
                        "zero timeout must be refused by the validated constructor"
                    );
                }
                InvalidBehaviorClass::UnknownTemplateVariable => {
                    assert!(
                        ValidatedCommand::new(vec!["{{ bogus }}".to_string()], 5, 1, 0).is_err(),
                        "an unknown template variable must be refused by the validated constructor"
                    );
                }
                InvalidBehaviorClass::SystemdWithoutUnits => {
                    assert!(
                        ValidatedSystemd::new(ActivationScope::User, true, Vec::new()).is_err(),
                        "systemd without units must be refused by the validated constructor"
                    );
                }
                InvalidBehaviorClass::InvalidUnitName => {
                    assert!(
                        UnitDef::new(
                            "../app.service".to_string(),
                            "app/x.service".to_string(),
                            true,
                            true,
                        )
                        .is_err(),
                        "a traversal unit name must be refused by the validated constructor"
                    );
                }
                InvalidBehaviorClass::InvalidUnitArtifactPath => {
                    assert!(
                        UnitDef::new(
                            "app.service".to_string(),
                            "/etc/systemd/app.service".to_string(),
                            true,
                            true,
                        )
                        .is_err(),
                        "an absolute unit artifact path must be refused by the validated constructor"
                    );
                }
                InvalidBehaviorClass::NoneWithUnits => {
                    // A `none` activation carrying units is an irrelevant-field
                    // refusal: the domain enum cannot even represent it
                    // (`Activation::None` carries no units by construction),
                    // and the wire parse refuses it.
                    let wire = serde_json::json!({
                        "adapter": "none",
                        "scope": "user",
                        "reconcile_managed_units": true,
                        "units": [{
                            "name": "app.service",
                            "artifact_path": "app/x.service",
                            "enable": true,
                            "restart": true,
                        }],
                    });
                    assert!(
                        serde_json::from_value::<Activation>(wire).is_err(),
                        "a none contract carrying units must be refused at the wire"
                    );
                }
                InvalidBehaviorClass::NoneWithNonDefaultScope => {
                    // A `none` activation carrying a non-default scope is an
                    // irrelevant-field refusal (same structural argument).
                    let wire = serde_json::json!({
                        "adapter": "none",
                        "scope": "system",
                        "reconcile_managed_units": true,
                        "units": [],
                    });
                    assert!(
                        serde_json::from_value::<Activation>(wire).is_err(),
                        "a none contract carrying a non-default scope must be refused at the wire"
                    );
                }
            }
        }
    }
}

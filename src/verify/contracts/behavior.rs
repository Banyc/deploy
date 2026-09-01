//! Frozen behavior-contract semantics.
//!
//! The canonical digest derivation and verification for the activation +
//! verification contract that pins a release's runtime behavior. Moved from
//! `crate::release` (area A5, verification/activation semantics) so the
//! behavior-contract functions live with the adapters they describe.
//!
//! A resolved contract is a [`crate::identity::BehaviorContract`] (one activation
//! config + one verification config). Its canonical digest (`behavior_sha256`)
//! is frozen into the release identity at build time; [`verify_behavior_json`]
//! recomputes it from a stored `behavior.json` and fails closed on any
//! payload whose canonical contract set differs.

use crate::config::{Activation, Verification};
use crate::digest::sha256_bytes;
use crate::error::{Error, Result};
use crate::identity::{BehaviorContract, BehaviorDigest, ReleaseId};
use std::collections::BTreeMap;

/// Canonical digest of the activation + verification contract. The closed
/// enums serialize to the canonical wire bytes (identical to the raw
/// `ActivationConfig`/`VerificationConfig` shapes), so the digest is
/// byte-stable with the pre-closed-enum form.
pub fn behavior_digest(activation: &Activation, verification: &Verification) -> String {
    let act = serde_json::to_value(activation).expect("activation serializes");
    let ver = serde_json::to_value(verification).expect("verification serializes");
    let payload = serde_json::json!({ "activation": act, "verification": ver });
    sha256_bytes(&serde_json::to_vec(&payload).expect("payload serializes"))
}

/// Canonical digest of a resolved [`BehaviorContract`].
pub fn behavior_contract_digest(contract: &BehaviorContract) -> String {
    behavior_digest(contract.activation(), contract.verification())
}

/// Reconstruct a [`BehaviorContract`] from serialized JSON bytes.
pub fn behavior_contract_from_json(
    bytes: &[u8],
) -> std::result::Result<BehaviorContract, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Canonical digest over name-sorted per-variant behavior contracts. Two
/// releases share this digest only when every declared variant's activation and
/// verification behavior is identical.
pub fn variant_behaviors_digest(contracts: &BTreeMap<String, BehaviorContract>) -> String {
    let value = serde_json::to_vec(contracts).expect("variant behaviors serialize");
    sha256_bytes(&value)
}

/// Canonical digest over the PER-RELEASE, PER-VARIANT behavior index an
/// attempt is bound to ([`crate::ledger::BehaviorIndex`]: release id ->
/// variant name -> contract). An attempt whose slots reference several
/// releases (a partial snapshot spans groups) carries ONE snapshot-wide
/// behavior digest over the whole index; two attempts share it only when
/// every referenced release's every declared variant behavior is identical.
/// `serde_json` serializes `BTreeMap`s in sorted key order, so the digest is
/// canonical (name-sorted, deterministic).
pub fn behavior_index_digest(
    index: &BTreeMap<ReleaseId, BTreeMap<String, BehaviorContract>>,
) -> String {
    let value = serde_json::to_vec(index).expect("behavior index serializes");
    sha256_bytes(&value)
}

/// Reconstruct the name-keyed per-variant behavior map from serialized JSON.
pub fn behavior_contracts_from_json(
    bytes: &[u8],
) -> std::result::Result<BTreeMap<String, BehaviorContract>, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Verify a serialized `behavior.json` payload against the canonical digest
/// recorded in a release's provenance (`behavior_sha256`), which is itself
/// part of the release identity (`release_sha256`). The payload is parsed and
/// the canonical digest recomputed over the name-sorted per-variant contract
/// map ([`variant_behaviors_digest`]); an UNPARSEABLE payload fails closed
/// with an integrity error, and so does a payload whose recomputed digest
/// differs from the provenance — a tampered `behavior.json` never yields a
/// historical contract that does not match the release it is stored under.
/// Only a payload that PARSES TO THE SAME canonical contract set (e.g. JSON
/// key reordering that deserializes identically, or any change that leaves
/// the contract set equal) passes — that is the "unless the canonical
/// behavior digest remains equal" clause. On success the parsed contracts
/// are returned so callers never parse twice.
pub fn verify_behavior_json(
    bytes: &[u8],
    release_id: &ReleaseId,
    expected_digest: &BehaviorDigest,
) -> Result<BTreeMap<String, BehaviorContract>> {
    let contracts = behavior_contracts_from_json(bytes).map_err(|e| {
        Error::integrity(format!(
            "release {release_id} behavior.json is malformed: {e}"
        ))
    })?;
    let recomputed = variant_behaviors_digest(&contracts);
    if recomputed != expected_digest.as_str() {
        return Err(Error::integrity(format!(
            "release {release_id} behavior.json digest mismatch: stored provenance behavior_sha256 {expected_digest} does not match the digest {recomputed} recomputed from the behavior contracts (fail closed)"
        )));
    }
    Ok(contracts)
}

//! Release-record I/O: the immutable `releases/<release-id>/` directory —
//! the identity-verified `release.json`, the CAS'd `mapping.toml` /
//! `behavior.json` snapshots — and the verifying read-back.

use crate::error::{Error, Result};
use crate::identity::{BehaviorContract, BehaviorDigest, ReleaseId, ReleaseRecord};
use crate::remote::layout;
use crate::store::atomic::read_json;
use crate::store::local::LocalStore;
use std::collections::BTreeMap;
use std::path::PathBuf;

impl LocalStore {
    // ---- releases ---------------------------------------------------------

    /// The on-disk directory for a release id (`releases/<release-id>/`).
    /// The id is a validated [`ReleaseId`] (`rel-sha256-<64 lowercase hex>` —
    /// a filesystem-safe ASCII string by the fixed grammar), stored VERBATIM:
    /// two distinct release ids always map to two distinct directories
    /// (injective by construction).
    pub fn release_dir(&self, id: &ReleaseId) -> PathBuf {
        self.base.join(layout::RELEASES).join(id.as_str())
    }

    pub fn release_exists(&self, id: &ReleaseId) -> bool {
        self.release_dir(id).join("release.json").exists()
    }

    /// Write an immutable release record. Replacing an existing ID with
    /// different content fails.
    ///
    /// The INCOMING record is verified from its OWN content BEFORE anything
    /// is written: an unverifiable record (digest fields inconsistent with
    /// the slot snapshot/bindings/provenance, or an empty slot snapshot) is
    /// never persisted — fail closed before the release directory or file is
    /// created. When the directory already exists, the EXISTING record is
    /// verified from its content as well, and the comparison is between the
    /// two content-verified identities (each record's `release_sha256` after
    /// recompute-and-verify): a same-id record with different content still
    /// fails, but never by trusting the stored digest fields.
    pub(crate) fn write_release(&self, rec: &ReleaseRecord) -> Result<()> {
        // (a) Verify the incoming record from its content before any write.
        crate::verify::release::verify_release_identity(rec)?;
        // THE EMBEDDED-IDENTITY BINDING (write side): the release record's
        // directory is derived from its OWN embedded `release_id` — the
        // storage key IS the record's identity, so a mismatched write is
        // structurally unrepresentable (there is no separate key argument
        // to disagree with). The read side ([`LocalStore::read_release`])
        // verifies the binding the other way: a record swapped into the
        // wrong release directory is refused.
        let id = ReleaseId::parse(&rec.release_id).map_err(|e| {
            Error::integrity(format!(
                "incoming release record carries an invalid release id {:?}: {e}",
                rec.release_id
            ))
        })?;
        let dir = self.release_dir(&id);
        if dir.exists() {
            // (b) Verify the EXISTING record from its content too, then
            // compare the recomputed identities (both records verified above,
            // so `release_sha256` equals the recomputed digest in each).
            let existing: ReleaseRecord = read_json(&dir.join("release.json"))?;
            crate::verify::release::verify_release_identity(&existing)?;
            if existing.release_sha256 != rec.release_sha256 {
                return Err(Error::store(format!(
                    "release {} already exists with different content",
                    rec.release_id
                )));
            }
            return Ok(()); // idempotent
        }
        self.ensure_private_dir_at(&dir)?;
        let bytes = serde_json::to_vec_pretty(rec)
            .map_err(|e| Error::store(format!("serialize release: {e}")))?;
        self.write_atomic_cas(&dir.join("release.json"), &bytes)
    }

    /// Read and verify a release record by its canonical id.
    ///
    /// The record's identity is recomputed from its OWN content (slot
    /// snapshot, bindings, provenance digests), never trusted from the stored
    /// `release_sha256`/`release_id` fields — a tampered record whose content
    /// was edited while the digest fields were left unchanged fails closed
    /// with an integrity error. An empty slot snapshot is rejected outright
    /// (a current-format record must persist its slot declarations).
    ///
    /// Additionally, the STORED record's `release_id` must equal the `id` the
    /// caller asked for (the directory path): a record swapped into the wrong
    /// release directory — its `release_id` edited to a consistent-but-
    /// different id, or the file relocated — is refused with an integrity
    /// error naming both ids instead of being returned as if it were `id`.
    pub fn read_release(&self, id: &ReleaseId) -> Result<ReleaseRecord> {
        let rec: ReleaseRecord = read_json(&self.release_dir(id).join("release.json"))?;
        // Recompute-and-verify: the release's canonical digest is derived from
        // its own content (slot snapshot, bindings, provenance digests), never
        // trusted from the stored `release_sha256`/`release_id` fields. A
        // tampered record whose content was edited while the digest fields
        // were left unchanged fails closed with an integrity error, and an
        // empty slot snapshot is rejected outright.
        crate::verify::release::verify_release_identity(&rec)?;
        // THE EMBEDDED-IDENTITY BINDING (read side): the stored record's own
        // `release_id` must equal the requested `id` (the path key —
        // `releases/<release-id>/release.json`) — a record swapped into the
        // wrong release directory is refused with an integrity error naming
        // both ids, never returned as if it were `id`.
        if rec.release_id != id.as_str() {
            return Err(Error::integrity(format!(
                "release record read from {id} declares release_id {}: the stored record's identity does not match the requested release id (a record swapped into the wrong release directory)",
                rec.release_id
            )));
        }
        Ok(rec)
    }

    pub(crate) fn write_release_aux(
        &self,
        id: &ReleaseId,
        mapping_toml: &str,
        behavior_json: &serde_json::Value,
    ) -> Result<()> {
        let dir = self.release_dir(id);
        self.ensure_private_dir_at(&dir)?;
        self.write_atomic_cas(&dir.join("mapping.toml"), mapping_toml.as_bytes())?;
        let bytes = serde_json::to_vec_pretty(behavior_json)
            .map_err(|e| Error::store(format!("serialize behavior: {e}")))?;
        self.write_atomic_cas(&dir.join("behavior.json"), &bytes)?;
        Ok(())
    }

    /// Read the name-keyed per-variant behavior contracts stored alongside a
    /// release record.
    ///
    /// The release record is read and identity-verified FIRST (its canonical
    /// digest is recomputed from its own content); its provenance
    /// `behavior_sha256` — itself part of the release identity — is then the
    /// digest the `behavior.json` snapshot must match. The snapshot is parsed
    /// and re-digested and compared against that provenance digest: a
    /// tampered `behavior.json` whose canonical contract set digests to
    /// anything else fails closed with an integrity error naming the release
    /// and the expected vs recomputed digest, and an unparseable snapshot
    /// fails closed too. Only a payload that yields the SAME canonical
    /// contract set (e.g. JSON key reordering) passes — the historical
    /// contract is never returned unverified.
    pub fn read_release_behaviors(
        &self,
        id: &ReleaseId,
    ) -> Result<BTreeMap<String, BehaviorContract>> {
        // Verify the release record first: its provenance `behavior_sha256` is
        // the canonical digest the behavior snapshot must match, and the
        // record's own identity is recomputed-and-verified before its
        // provenance is trusted.
        let rec = self.read_release(id)?;
        let p = self.release_dir(id).join("behavior.json");
        let bytes = std::fs::read(&p)
            .map_err(|e| Error::store(format!("read behavior {}: {e}", p.display())))?;
        crate::verify::release::verify_behavior_json(
            &bytes,
            &ReleaseId::parse(&rec.release_id)?,
            &BehaviorDigest::parse(&rec.provenance.behavior_sha256)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{BehaviorContract, ReleaseId, TreeDigest, test_tree_digest};
    use std::collections::BTreeMap;
    /// A canonical behavior fixture: adapter `systemd` (a NON-default value,
    /// so deleting `activation.adapter` changes the contract), a system scope,
    /// one managed unit, and a command verification with a distinctive argv.
    /// `behavior_digest` is its canonical name-sorted per-variant digest.
    fn behavior_fixture() -> (BTreeMap<String, BehaviorContract>, String) {
        let contracts: BTreeMap<String, BehaviorContract> = BTreeMap::from([(
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
        )]);
        let sha = crate::verify::release::variant_behaviors_digest(&contracts);
        (contracts, sha)
    }

    /// Store a release record whose provenance `behavior_sha256` matches the
    /// canonical digest of [`behavior_fixture`] and write its aux snapshot.
    fn write_behavior_fixture(
        store: &LocalStore,
    ) -> (ReleaseId, BTreeMap<String, BehaviorContract>, String) {
        let (contracts, sha) = behavior_fixture();
        let variants: BTreeMap<crate::identity::VariantName, TreeDigest> = BTreeMap::from([(
            crate::identity::VariantName::new("standard"),
            test_tree_digest("1"),
        )]);
        let slots: BTreeMap<String, Vec<crate::config::SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            vec![crate::config::SlotConfig::new(
                "p1".to_string(),
                "s1".to_string(),
                std::path::PathBuf::from("/srv/deploy/p1"),
                "t1".to_string(),
                Vec::new(),
            )],
        )]);
        let rec = crate::verify::release::build_release(
            "m",
            &sha,
            &variants,
            &slots,
            std::path::Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        let behavior_json = serde_json::to_value(&contracts).unwrap();
        store
            .write_release_aux(&id, "mapping", &behavior_json)
            .expect("behavior snapshot writes");
        (id, contracts, sha)
    }

    #[test]
    fn release_aux_snapshots_are_immutable_and_atomic() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let (id, _contracts, _sha) = write_behavior_fixture(&store);
        let behavior = serde_json::to_value(behavior_fixture().0).unwrap();

        // Identical rewrite is an idempotent success.
        store
            .write_release_aux(&id, "mapping", &behavior)
            .expect("identical rewrite must succeed");

        // Replacing the behavior snapshot with different content fails...
        let conflicting = serde_json::json!({
            "standard": {
                "activation": { "adapter": "none", "scope": "user", "reconcile_managed_units": true, "units": [] },
                "verification": {
                    "adapter": "command",
                    "argv": ["true"],
                    "timeout_seconds": 5,
                    "attempts": 1,
                    "interval_seconds": 0
                }
            }
        });
        let err = store
            .write_release_aux(&id, "mapping", &conflicting)
            .expect_err("conflicting rewrite must fail");
        assert!(
            err.to_string().contains("different content"),
            "error must name the immutability violation, got: {err}"
        );

        // ...and the stored snapshot is untouched (no torn write).
        let read = store.read_release_behaviors(&id).expect("snapshot exists");
        assert_eq!(read["standard"].activation().to_config().adapter, "systemd");
    }

    /// `read_release` recomputes the canonical digest from the record's own
    /// content and verifies it against the stored identity fields: a pristine
    /// record reads fine, while an edited slot declaration fails closed.
    #[test]
    fn read_release_recomputes_and_verifies_identity() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let (id, _c, _sha) = write_behavior_fixture(&store);
        let read = store.read_release(&id).unwrap();
        assert_eq!(read.release_id, id.as_str());
        let mut tampered = read.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        let path = store.release_dir(&id).join("release.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
        let err = store
            .read_release(&id)
            .expect_err("tampered record must fail verification");
        assert!(err.to_string().contains("identity mismatch"), "got: {err}");
    }
}

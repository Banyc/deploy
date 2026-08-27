//! The per-slot ordered TABLES (feature area A2: Ledger semantics) — the
//! domain's keyed-by-slot collection types the ledger records share.
//!
//! THIS module owns the PRIVATE [`OrderedSlotMap`] and the two tables built
//! on it: the possibly-empty [`SlotTable`] (the terminal's per-slot
//! OUTCOMES, legitimately empty for a pre-mutation failure) and the
//! NON-EMPTY [`NonEmptySlotTable`] (the deployment intent's slots and the
//! degraded disposition's remaining changes — the only constructor is the
//! VERIFIED [`NonEmptySlotTable::build`], which refuses the empty table).
//! The wire outcome row ([`SlotResult`], the RAW serde form the ledger's
//! JSONL carries) lives with its domain sibling in
//! [`crate::ledger::outcomes`]; the deployment-record shapes that use these
//! tables live in [`crate::ledger::records`].
//!
//! THE TABLE IS ORDERED: iteration (`keys` / `values` / `iter`) is in
//! INSERTION order — the DEPLOYMENT order — never sorted by slot id.

use crate::error::{Error, Result};
use crate::identity::SlotId;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::Index;

// DOMAIN SLOT TABLES: the membership + per-slot data are ONE table
// ---------------------------------------------------------------------------
//
// The DOMAIN intent collapses the wire's `slot_ids` / `desired` / `pre_push`
// split into a single authoritative slot→slot-data table, so the
// exact-key-set invariant (membership == desired keys == pre_push keys, no
// duplicates) becomes STRUCTURAL: a [`NonEmptySlotTable`] is non-empty and
// its keys are unique (the ordered map has no duplicate keys), so an intent
// can never carry a member slot without its desired/pre-push entries, or an
// entry for a non-member slot. The WIRE types keep the split on-disk shape;
// the wire → domain conversion builds the table and refuses disagreements
// exactly as before.
//
// THE TABLE IS ORDERED: iteration (`keys` / `values` / `iter`) is in
// INSERTION order — the DEPLOYMENT order — never sorted by slot id. The
// wire's `slot_ids` is the authoritative deployment order (the same set the
// commit marker `slots` payload records), and the wire → domain conversion
// builds the table from that SEQUENCE, so the round trip preserves the
// exact `slot_ids` order instead of silently re-sorting it.

/// A PRIVATE ordered slot→value map: a `Vec<(SlotId, T)>` keeps the
/// INSERTION SEQUENCE (the deployment order) and a `BTreeMap<SlotId, usize>`
/// index gives O(log n) lookup. Iteration (`keys` / `values` / `iter`) is in
/// INSERTION order — the deployment order — never sorted by slot id.
/// `insert` APPENDS a new key at the end of the sequence and OVERWRITES an
/// existing key in place (its position is preserved), so the sequence is
/// exactly the order the entries were first inserted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OrderedSlotMap<T> {
    entries: Vec<(SlotId, T)>,
    index: BTreeMap<SlotId, usize>,
}

impl<T> Default for OrderedSlotMap<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeMap::new(),
        }
    }
}

impl<T> OrderedSlotMap<T> {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    fn from_map(map: BTreeMap<SlotId, T>) -> Self {
        let entries: Vec<(SlotId, T)> = map.into_iter().collect();
        let index = entries
            .iter()
            .enumerate()
            .map(|(i, (k, _))| (k.clone(), i))
            .collect();
        Self { entries, index }
    }

    fn into_map(self) -> BTreeMap<SlotId, T> {
        self.entries.into_iter().collect()
    }

    fn insert(&mut self, key: SlotId, value: T) {
        if let Some(&i) = self.index.get(&key) {
            self.entries[i].1 = value;
        } else {
            self.index.insert(key.clone(), self.entries.len());
            self.entries.push((key, value));
        }
    }

    fn get(&self, key: &SlotId) -> Option<&T> {
        self.index.get(key).map(|&i| &self.entries[i].1)
    }

    fn contains_key(&self, key: &SlotId) -> bool {
        self.index.contains_key(key)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.entries.iter().map(|(k, _)| k)
    }

    fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, v)| v)
    }

    fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

impl<T> Index<&SlotId> for OrderedSlotMap<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        self.get(key).expect("no entry found for key")
    }
}

/// A possibly-empty ordered slot→value table keyed by
/// [`SlotId`] — the domain's keyed-by-slot collection type
/// (the possibly-empty variant of [`NonEmptySlotTable`], used for the
/// terminal's per-slot OUTCOMES, which are legitimately empty for a
/// pre-mutation failure). Uniqueness is structural (the ordered map has no
/// duplicate keys); the table carries no other invariant. Iteration
/// (`keys` / `values` / `iter`) is in INSERTION order — the deployment
/// order — never sorted by slot id.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SlotTable<T>(OrderedSlotMap<T>);

impl<T> SlotTable<T> {
    pub const fn new() -> Self {
        Self(OrderedSlotMap::new())
    }

    pub fn from_map<U: Into<T>>(map: BTreeMap<SlotId, U>) -> Self {
        Self(OrderedSlotMap::from_map(
            map.into_iter().map(|(k, v)| (k, v.into())).collect(),
        ))
    }

    pub fn into_map(self) -> BTreeMap<SlotId, T> {
        self.0.into_map()
    }

    /// Insert a slot→value entry, APPENDING a new key at the end of the
    /// table's sequence (the deployment order) and overwriting an existing
    /// key in place (its position is preserved).
    pub fn insert(&mut self, key: SlotId, value: T) {
        self.0.insert(key, value);
    }

    pub fn get(&self, key: &SlotId) -> Option<&T> {
        self.0.get(key)
    }

    pub fn contains_key(&self, key: &SlotId) -> bool {
        self.0.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.0.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.0.iter()
    }
}

impl<T> Index<&SlotId> for SlotTable<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        &self.0[key]
    }
}

impl<T: Serialize> Serialize for SlotTable<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for SlotTable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SlotTableVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for SlotTableVisitor<T> {
            type Value = SlotTable<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a slot table")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut table = OrderedSlotMap::new();
                while let Some((k, v)) = access.next_entry()? {
                    table.insert(k, v);
                }
                Ok(SlotTable(table))
            }
        }
        deserializer.deserialize_map(SlotTableVisitor(PhantomData))
    }
}

/// A NON-EMPTY ordered slot→value table keyed by [`SlotId`] — the
/// domain's authoritative membership-bearing collection type (the
/// non-empty variant of [`SlotTable`], used for the deployment intent's
/// slots and the degraded disposition's remaining changes). The domain
/// invariant is STRUCTURAL: the key set is unique (the ordered map) and
/// NON-EMPTY (the only constructor is the VERIFIED
/// [`NonEmptySlotTable::build`], which refuses the empty table — a
/// deployment that selects no slot cannot be represented). No
/// duplicate/missing-key state exists in the domain: a member slot always
/// carries its desired + pre-push entry, and no entry exists for a
/// non-member. Iteration (`keys` / `values` / `iter`) is in INSERTION
/// order — the deployment order — never sorted by slot id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptySlotTable<T>(OrderedSlotMap<T>);

impl<T> NonEmptySlotTable<T> {
    /// The VERIFIED constructor: refuse the empty table (fail closed — the
    /// domain cannot represent an empty deployment membership or an empty
    /// remaining-changes set). Uniqueness needs no check (the ordered map
    /// keys are unique by construction). The table's INSERTION SEQUENCE is
    /// the entry order of `entries` — the wire's `slot_ids` order — and
    /// iteration preserves it exactly.
    pub fn build<I>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (SlotId, T)>,
    {
        let mut table = OrderedSlotMap::new();
        for (key, value) in entries {
            table.insert(key, value);
        }
        if table.is_empty() {
            return Err(Error::integrity(
                "a non-empty slot table cannot be empty — the domain refuses an empty deployment membership / remaining-changes set",
            ));
        }
        Ok(Self(table))
    }

    pub fn get(&self, key: &SlotId) -> Option<&T> {
        self.0.get(key)
    }

    pub fn contains_key(&self, key: &SlotId) -> bool {
        self.0.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.0.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn into_map(self) -> BTreeMap<SlotId, T> {
        self.0.into_map()
    }
}

impl<T> Index<&SlotId> for NonEmptySlotTable<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        &self.0[key]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, TargetName, VariantName,
        test_deployment_id, test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::ledger::intent::LedgerIntentWire;
    use crate::ledger::records::SlotAttemptState;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    fn slot_strategy() -> impl Strategy<Value = SlotId> {
        (0u32..6).prop_map(slot)
    }

    /// A generation ref whose assignment names its own key (the agreeing
    /// form); the artifact's release is derived from the slot id.
    fn gen_ref_for(key: &SlotId) -> GenerationRef {
        GenerationRef {
            generation: test_generation_id(key.as_str()),
            assignment: PlacementSlotAssignment {
                placement_slot: key.clone(),
                artifact: ArtifactRef {
                    release: test_release_id(key.as_str()),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest(key.as_str()),
                },
            },
        }
    }

    /// A valid base intent wire over the given membership (the ordering
    /// property needs an AGREEING wire whose `slot_ids` is the authoritative
    /// deployment order).
    fn agreeing_intent(keys: &[SlotId]) -> LedgerIntentWire {
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: test_deployment_id("deploy-w"),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids: keys.to_vec(),
            behavior_sha256: "sha256-w".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    /// UNIQUE slot ids in an ARBITRARY PERMUTATION: a shuffled non-empty
    /// subset of the slot universe — the wire's `slot_ids` is the
    /// authoritative deployment order, so the ordering property must cover
    /// orders that are NOT sorted by id.
    fn slot_ids_permutation() -> impl Strategy<Value = Vec<SlotId>> {
        prop::collection::btree_set(slot_strategy(), 1..4).prop_flat_map(|set| {
            let ids: Vec<SlotId> = set.into_iter().collect();
            let n = ids.len();
            // Shuffle the selected ids by sorting random keys: every order is
            // reachable (with n ≤ 3 the key space is collision-free in
            // practice), and the strategy shrinks naturally.
            prop::collection::vec(0u32..1000, n).prop_map(move |keys| {
                let mut order: Vec<usize> = (0..n).collect();
                order.sort_by_key(|&i| keys[i]);
                order.into_iter().map(|i| ids[i].clone()).collect()
            })
        })
    }

    /// [`NonEmptySlotTable`] refuses the empty map; [`SlotTable`] is the
    /// possibly-empty variant (terminal outcomes are legitimately empty for
    /// a preflight failure).
    #[test]
    fn slot_tables_enforce_non_emptiness_where_the_domain_requires_it() {
        assert!(NonEmptySlotTable::<u32>::build(BTreeMap::new()).is_err());
        let ok = NonEmptySlotTable::build(BTreeMap::from([(slot(1), 7u32)])).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[&slot(1)], 7);
        assert!(SlotTable::<u32>::new().is_empty());
    }

    /// The ordered tables PRESERVE INSERTION ORDER across build / get /
    /// iter / keys: a table built from a deliberately NON-sorted sequence
    /// iterates in exactly that sequence (never sorted by slot id), and
    /// `get` / `contains_key` / `len` / indexing still work.
    /// `SlotTable::insert` appends new keys and keeps an overwritten key's
    /// position.
    #[test]
    fn slot_tables_preserve_insertion_order_across_build_get_iter_keys() {
        // Deliberately NOT sorted by id: the deployment order.
        let order = vec![slot(3), slot(1), slot(5), slot(0)];
        let table = NonEmptySlotTable::build(
            order
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, k)| (k, i as u32)),
        )
        .unwrap();
        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            order,
            "keys() iterates in insertion order, not sorted by id"
        );
        assert_eq!(
            table.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            order,
            "iter() iterates in insertion order"
        );
        assert_eq!(
            table.values().cloned().collect::<Vec<_>>(),
            vec![0, 1, 2, 3],
            "values() iterates in insertion order"
        );
        assert_eq!(table.len(), 4);
        assert_eq!(table.get(&slot(1)), Some(&1));
        assert!(table.contains_key(&slot(5)));
        assert!(!table.contains_key(&slot(2)));
        assert_eq!(table[&slot(0)], 3, "indexing works");

        // The possibly-empty variant preserves the same order.
        let mut empty = SlotTable::new();
        assert!(empty.is_empty());
        empty.insert(slot(2), 2u32);
        empty.insert(slot(0), 0u32);
        assert_eq!(
            empty.keys().cloned().collect::<Vec<_>>(),
            vec![slot(2), slot(0)],
            "SlotTable::insert appends in insertion order"
        );
        // Overwriting an existing key keeps its position.
        empty.insert(slot(2), 9u32);
        assert_eq!(
            empty.keys().cloned().collect::<Vec<_>>(),
            vec![slot(2), slot(0)],
            "an overwritten key keeps its original position"
        );
        assert_eq!(empty[&slot(2)], 9, "the overwritten value is visible");
    }

    proptest! {
        // THE ORDERING PROPERTY (the user's requirement): the wire's
        // `slot_ids` is the AUTHORITATIVE deployment order, and the domain
        // table must PRESERVE it exactly — never silently re-sort by slot
        // id. Over UNIQUE slot ids in ARBITRARY PERMUTATIONS, the wire →
        // domain → wire round trip must reproduce the EXACT `slot_ids`
        // sequence (not the sorted order): the domain table iterates in the
        // wire's sequence, the domain → wire re-expansion emits the same
        // sequence, and the full JSON round trip preserves it. Bounded 16
        // cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wire_slot_ids_sequence_round_trips_exactly(keys in slot_ids_permutation()) {
            let wire = agreeing_intent(&keys);
            let domain = wire
                .clone()
                .into_domain()
                .expect("the agreeing intent converts");
            // The DOMAIN table iterates in the wire's sequence order.
            assert_eq!(
                domain.membership(),
                keys,
                "the domain table must preserve the wire's slot_ids sequence (deployment order), not sort by id"
            );
            // The domain → wire re-expansion emits the SAME sequence.
            let wire2 = LedgerIntentWire::from(&domain);
            assert_eq!(
                wire2.slot_ids, keys,
                "the domain → wire re-expansion must reproduce the exact slot_ids sequence"
            );
            // The full JSON round trip (serialize → deserialize) too.
            let json = serde_json::to_string(&domain).unwrap();
            let wire3: LedgerIntentWire = serde_json::from_str(&json).unwrap();
            assert_eq!(
                wire3.slot_ids, keys,
                "the JSON round trip must preserve the exact slot_ids sequence"
            );
        }
    }
}

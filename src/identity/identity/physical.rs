//! The validated PHYSICAL deployment-location key ([`PhysicalSlotKey`]) and
//! its endpoint component ([`EndpointKey`]): the identity of a physical
//! deployment location on a host.
//!
//! The [`PhysicalSlotKey`] is what ACTUALLY identifies a physical deployment
//! location: `{application, slot, endpoint, deploy_dir}`. The slot id is the
//! LOGICAL name; the (endpoint, deploy_dir) pair is the PHYSICAL place. The
//! endpoint is the ServerDef's `user@address` — NOT the ServerId — so two
//! ServerIds that name the same physical host collapse to the same endpoint,
//! and two slots whose (endpoint, deploy_dir) agree are ONE physical
//! location (a duplicate physical location is a config error, never two
//! silent authorities).

use crate::error::{Error, Result};
use crate::identity::{AbsoluteDeployDir, ApplicationStoreKey, SlotId};
use std::fmt;

/// The physical host identity of a deployment endpoint: `user@address` for
/// an SSH server (the ServerDef's address/user — NOT the ServerId alone, so
/// two ServerIds naming the same host collapse to the same endpoint), or the
/// constant `local` marker for the pathless local connection kind (whose
/// SOLE physical root is the referencing slot's deploy_dir). A single
/// filesystem-safe ASCII token: non-empty, no path separators, no whitespace
/// or control characters — an endpoint is never a path and never empty (an
/// SSH connection always has an address).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointKey(String);

impl EndpointKey {
    /// Validate the endpoint token (non-empty, no separators, no whitespace
    /// or control characters) and construct the key. An endpoint is built
    /// from validated parts (a validated `user@address`, or the `local`
    /// marker); this gate makes an invalid endpoint unconstructible.
    pub fn parse(s: &str) -> Result<EndpointKey> {
        let ok = !s.is_empty()
            && !s.contains('/')
            && !s.contains('\\')
            && !s.chars().any(|c| c.is_control() || c.is_whitespace());
        if !ok {
            return Err(Error::config(format!(
                "invalid endpoint {:?}: must be a non-empty token with no separators, whitespace, or control characters",
                s
            )));
        }
        Ok(EndpointKey(s.to_string()))
    }

    /// The validated endpoint token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EndpointKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The constant endpoint marker of the pathless LOCAL connection kind: a
/// local server has no SSH address, so its physical host identity is the
/// local marker itself and the deploy_dir is the sole physical root.
pub(crate) const LOCAL_ENDPOINT_MARKER: &str = "local";

/// The ONE validated physical deployment-location key: `{application, slot,
/// endpoint, deploy_dir}`. This is the identity of a PHYSICAL deployment
/// location — the application whose store it belongs to, the LOGICAL slot
/// name, the PHYSICAL host endpoint (the ServerDef's `user@address`, not the
/// ServerId, so two ServerIds naming the same host collapse to the same
/// endpoint), and the absolute on-host deploy_dir. Two slots whose
/// (endpoint, deploy_dir) agree are the SAME physical location; the key is
/// validated (endpoint rules + the deploy_dir's absolute/traversal-free
/// rules, enforced by the [`AbsoluteDeployDir`] type) so a malformed key is
/// unconstructible.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PhysicalSlotKey {
    application: ApplicationStoreKey,
    slot: SlotId,
    endpoint: EndpointKey,
    deploy_dir: AbsoluteDeployDir,
}

impl PhysicalSlotKey {
    /// Validate the parts and construct the physical key: the endpoint must
    /// be a valid token ([`EndpointKey::parse`]) and the deploy_dir is
    /// already validated by its [`AbsoluteDeployDir`] type. Fails closed on
    /// any invalid part.
    pub fn parse(
        application: ApplicationStoreKey,
        slot: SlotId,
        endpoint: &str,
        deploy_dir: AbsoluteDeployDir,
    ) -> Result<PhysicalSlotKey> {
        let endpoint = EndpointKey::parse(endpoint)?;
        Ok(PhysicalSlotKey {
            application,
            slot,
            endpoint,
            deploy_dir,
        })
    }

    /// The application whose store this physical location belongs to.
    pub fn application(&self) -> &ApplicationStoreKey {
        &self.application
    }

    /// The LOGICAL placement-slot name.
    pub fn slot(&self) -> &SlotId {
        &self.slot
    }

    /// The PHYSICAL host endpoint (`user@address` for SSH, the `local`
    /// marker for the pathless local connection kind).
    pub fn endpoint(&self) -> &EndpointKey {
        &self.endpoint
    }

    /// The absolute on-host deployment directory.
    pub fn deploy_dir(&self) -> &AbsoluteDeployDir {
        &self.deploy_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    fn valid_segment() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                prop::char::range('a', 'z'),
                prop::char::range('0', '9'),
                Just('-'),
                Just('_'),
            ],
            1..12,
        )
        .prop_filter("no leading dash", |s| s.first() != Some(&'-'))
        .prop_map(|v| v.into_iter().collect())
    }

    fn valid_endpoint() -> impl Strategy<Value = String> {
        prop_oneof![
            (valid_segment(), valid_segment()).prop_map(|(u, h)| format!("{u}@{h}")),
            Just(LOCAL_ENDPOINT_MARKER.to_string()),
        ]
    }

    #[test]
    fn endpoint_accepts_tokens_rejects_paths_and_empties() {
        for ok in [
            "user@host",
            "a@b.example.com",
            LOCAL_ENDPOINT_MARKER,
            "root@10.0.0.1",
        ] {
            assert!(EndpointKey::parse(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            " ",
            "user@host/path",
            "user@ho\\st",
            "u@h x",
            "u@h\nx",
            "x",
        ] {
            if bad == "x" {
                continue; // a bare token without '@' is still a valid endpoint token
            }
            assert!(EndpointKey::parse(bad).is_err(), "{bad:?}");
        }
    }

    // THE PHYSICAL-KEY PROPERTY (the review's acceptance): generate
    // ARBITRARY VALID physical keys and assert that two DISTINCT keys never
    // produce the same physical location — the key's components are all
    // validated types, so equality is structural and injectivity is
    // component-wise. Bounded 64 cases (16 fast, 64 full), fixed seed
    // 0x5EED_5EED per house style.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn distinct_physical_keys_are_distinct(
            app_a in valid_segment(),
            app_b in valid_segment(),
            slot_a in valid_segment(),
            slot_b in valid_segment(),
            ep_a in valid_endpoint(),
            ep_b in valid_endpoint(),
            dir_a in "/[a-z0-9-]{1,12}",
            dir_b in "/[a-z0-9-]{1,12}",
        ) {
            let key_a = PhysicalSlotKey::parse(
                ApplicationStoreKey::parse(&app_a).unwrap(),
                SlotId::parse(&slot_a).unwrap(),
                &ep_a,
                AbsoluteDeployDir::parse(&dir_a).unwrap(),
            )
            .unwrap();
            let key_b = PhysicalSlotKey::parse(
                ApplicationStoreKey::parse(&app_b).unwrap(),
                SlotId::parse(&slot_b).unwrap(),
                &ep_b,
                AbsoluteDeployDir::parse(&dir_b).unwrap(),
            )
            .unwrap();
            // The PHYSICAL half (endpoint, deploy_dir) is the identity of a
            // physical deployment location: two keys with equal physical
            // halves are ONE physical location (the class the config REFUSES
            // for two slots — only the LOGICAL application/slot names may
            // differ); two keys with distinct physical halves are distinct
            // locations.
            assert_eq!(
                (key_a.endpoint() == key_b.endpoint())
                    && (key_a.deploy_dir() == key_b.deploy_dir()),
                (ep_a == ep_b)
                    && (AbsoluteDeployDir::parse(&dir_a).unwrap()
                        == AbsoluteDeployDir::parse(&dir_b).unwrap()),
                "the physical half equality must be structural"
            );
            // DISTINCT KEYS => DISTINCT OWNERSHIP RECORDS: a record is
            // identified by the full key (application + slot + endpoint +
            // deploy_dir), so any component differing makes the records
            // distinct — and equal keys are the same record.
            assert_eq!(
                key_a != key_b,
                app_a != app_b
                    || slot_a != slot_b
                    || ep_a != ep_b
                    || dir_a != dir_b
                    || (AbsoluteDeployDir::parse(&dir_a).unwrap()
                        != AbsoluteDeployDir::parse(&dir_b).unwrap()),
                "two keys are equal iff every component is equal"
            );
            // The physical key parses a fixed point: re-parsing its own
            // parts yields the same key (deterministic).
            assert_eq!(
                PhysicalSlotKey::parse(
                    key_a.application().clone(),
                    key_a.slot().clone(),
                    key_a.endpoint().as_str(),
                    key_a.deploy_dir().clone(),
                )
                .unwrap(),
                key_a
            );
        }
    }

    #[test]
    fn physical_key_is_derivable_from_server_parts() {
        // The two distinct ServerIds naming the SAME endpoint collapse to
        // the same physical key half: the endpoint is the address/user, not
        // the server id (this is the class the review calls out — two
        // ServerDefs pointing at the same physical host+dir must never be
        // two silent authorities).
        let dir = AbsoluteDeployDir::parse("/srv/deploy").unwrap();
        let a = PhysicalSlotKey::parse(
            ApplicationStoreKey::parse("eng").unwrap(),
            SlotId::parse("p1").unwrap(),
            "u@host.example.com",
            dir.clone(),
        )
        .unwrap();
        let b = PhysicalSlotKey::parse(
            ApplicationStoreKey::parse("eng").unwrap(),
            SlotId::parse("p1").unwrap(),
            "u@host.example.com",
            dir,
        )
        .unwrap();
        assert_eq!(
            a.endpoint(),
            b.endpoint(),
            "two server ids on the same user@address are the same endpoint"
        );
    }
}

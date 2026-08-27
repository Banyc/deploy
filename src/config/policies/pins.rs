//! Durable release pins ([`Pin`]): one whole release retained forever, with
//! the raw -> domain conversion parsing the pin's release into the typed
//! [`crate::identity::ReleaseId`].

use crate::config::raw::RawPin;
use crate::error::{Error, Result};
use crate::identity::ReleaseId;
use serde::{Deserialize, Serialize};

/// Durable protection for one whole release: every variant's artifact in the
/// pinned release is retained forever; retention never sweeps it.
///
/// The DOMAIN shape: `release` carries the TYPED [`ReleaseId`], so a pin can
/// only name a release that satisfies the exact `rel-sha256-<64 lowercase
/// hex>` grammar — a loaded configuration can never carry a pin whose
/// release would later fail [`ReleaseId::parse`] (the consumers that used to
/// parse the raw string late now receive the typed id by construction). The
/// raw WIRE shape is `RawPin` (a plain string); the raw -> domain
/// conversion validates every pin during load via `TryFrom<RawPin>`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub release: ReleaseId,
    pub reason: String,
}

/// Raw -> domain conversion for ONE pin: the raw wire `release` string is
/// parsed into the typed [`ReleaseId`]. A pin string that does not satisfy
/// the exact `rel-sha256-<64 lowercase hex>` grammar fails the WHOLE config
/// load (fail closed, like every sibling raw -> domain gate), so a
/// successfully loaded configuration can never produce a later release-id
/// syntax error.
impl TryFrom<RawPin> for Pin {
    type Error = Error;
    fn try_from(raw: RawPin) -> Result<Pin> {
        Ok(Pin {
            release: ReleaseId::parse(&raw.release)?,
            reason: raw.reason,
        })
    }
}

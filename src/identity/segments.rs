//! The SEGMENT identities: [`SlotId`], [`ServerId`], [`TargetName`],
//! [`VariantName`] — a single safe path segment (non-empty, no path
//! separators or traversal components, no surrounding whitespace or control
//! characters), the shared segment rule from [`super::scalars::valid_name`].
//!
//! [`SlotId`] is the DEPLOYMENT-LOCATION identity — the key of every
//! slot→assignment relationship (plans, attempts, observed state, snapshots,
//! commit markers). [`ServerId`] is the ACTUAL SERVER identity used for
//! transport addressing (user@host lives on `ServerDef`). They are distinct
//! concepts: a server can host slots in multiple targets, and a slot may be
//! a member of several targets (each carrying its own `deploy_dir`). Today
//! one target runs at most one slot per server, so the two ID spaces are
//! interchangeable within a target, but the model keys assignments by
//! [`SlotId`] and addresses transports by [`ServerId`].

use super::id_newtype;
use super::scalars::valid_name;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

id_newtype!(
    ServerId,
    valid_name,
    "A server identity: a single safe path segment (non-empty, no path \
     separators or traversal components, no surrounding whitespace or control \
     characters) — the shared segment rule from [`crate::scalar`]."
);
id_newtype!(
    SlotId,
    valid_name,
    "A slot identity: a single safe path segment (the shared \
     segment rule from [`crate::scalar`])."
);
id_newtype!(
    TargetName,
    valid_name,
    "A target name: a single safe path segment (the shared segment rule \
     from [`crate::scalar`])."
);
id_newtype!(
    VariantName,
    valid_name,
    "A variant name: a single safe path segment (the shared segment rule \
     from [`crate::scalar`])."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::scalars::RolloutGroupName;

    /// The segment identities require a single safe path segment.
    #[test]
    fn segment_ids_require_safe_single_segment() {
        for ok in [
            "p1",
            "s1",
            "standard",
            "production",
            "wave-1",
            "α",
            "a..b",
            "a.b",
        ] {
            assert!(ServerId::parse(ok).is_ok(), "{ok:?}");
            assert!(SlotId::parse(ok).is_ok(), "{ok:?}");
            assert!(TargetName::parse(ok).is_ok(), "{ok:?}");
            assert!(RolloutGroupName::parse(ok).is_ok(), "{ok:?}");
            assert!(VariantName::parse(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "", "   ", " x", "x ", "\u{0}", "a\nb", "a/b", "a\\b", ".", "..", "../x", "x/..",
        ] {
            ServerId::parse(bad).expect_err("invalid server id rejected");
            SlotId::parse(bad).expect_err("invalid slot id rejected");
            TargetName::parse(bad).expect_err("invalid target name rejected");
            RolloutGroupName::parse(bad).expect_err("invalid group name rejected");
            VariantName::parse(bad).expect_err("invalid variant name rejected");
        }
    }
}

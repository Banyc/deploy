// =====================================================================
// ---- mapping resolution ----
// =====================================================================
// Artifact mappings — the leaf types BOTH layers use unchanged, plus the
// artifact-relative path and octal-mode helpers. These are the raw
// serialization shapes (`Mapping`, `ArtifactConfig`) and the pure
// destination/mode functions (`validate_relative_path`,
// `normalize_destination`, `destinations_overlap`, `parse_octal_mode`,
// `resolved_mode`); every validity rule on them (non-empty from/to,
// artifact-relative destinations, no overlapping destinations, the strict
// conflict/mode spellings) is enforced by the raw -> domain conversion in
// [`crate::config::domain`], which consumes these types unchanged.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Artifact mappings — the leaf types both layers use unchanged, validated by
// the raw -> domain conversion below.
// ---------------------------------------------------------------------------

/// Reject any path that is absolute or contains a parent/root/prefix component,
/// so a mapping destination cannot escape the artifact-relative namespace.
///
/// `PackageRelativePath`/`Mapping.to` values must stay beneath the staging root.
pub fn validate_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Error::path("path must remain artifact-relative"));
    }
    Ok(())
}

/// A mapping's destination-collision policy. Strict semantics: a collision is
/// ALWAYS an error. `keep`/`replace` behavior is intentionally not offered —
/// overlapping destinations are rejected before any staging write, and the
/// staging tree itself is a disposable cache that is cleared and rebuilt, so
/// re-materializing the same push is an idempotent no-op. Because this is the
/// only variant, any other `conflict = "..."` value is rejected at config
/// parse.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    #[default]
    Error,
}

/// Normalize a mapping destination for comparison: NFC, forward slashes,
/// trailing `/` stripped — a trailing slash only selects the directory-merge
/// semantics, so `app/` and `app` name the same destination tree.
pub fn normalize_destination(to: &str) -> String {
    let s = to.nfc().collect::<String>().replace('\\', "/");
    s.trim_end_matches('/').to_string()
}

/// Whether two mapping destinations overlap: identical, or one is a
/// component-wise prefix of the other (a nested `to` descending into another
/// mapping's `to` tree). An empty destination (the entry lands at the staging
/// root) is a prefix of every destination. Overlapping destinations would make
/// the materialized tree depend on declaration order, so they are rejected.
pub fn destinations_overlap(a: &str, b: &str) -> bool {
    let a_norm = normalize_destination(a);
    let b_norm = normalize_destination(b);
    let ac: Vec<_> = Path::new(&a_norm).components().collect();
    let bc: Vec<_> = Path::new(&b_norm).components().collect();
    let (short, long) = if ac.len() <= bc.len() {
        (&ac, &bc)
    } else {
        (&bc, &ac)
    };
    short == &long[..short.len()]
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    /// Source path relative to the release directory (`releases/<release>/`),
    /// where the convention is `artifacts/...`. The path is rendered with the
    /// template module (`crate::remote::materialize`): `{{ variant }}` is available at
    /// materialization; slot-level variables such as `deploy_dir` are not
    /// (trees are content-addressed and shared across slots) and referencing
    /// them fails loudly.
    pub from: String,
    /// Artifact-relative destination path.
    pub to: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub conflict: ConflictPolicy,
    /// `preserve` or an explicit octal mode such as `"0644"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConfig {
    pub mappings: Vec<Mapping>,
}

/// Parse an octal mode string such as `"0644"` into a `u32`.
pub fn parse_octal_mode(s: &str) -> Result<u32> {
    let s = s.trim();
    let digits: String = s.chars().filter(|c| *c != '_').collect();
    u32::from_str_radix(&digits, 8).map_err(|_| Error::config(format!("invalid octal mode '{s}'")))
}

/// Resolve an activation mode override, returning `None` when `preserve`.
pub fn resolved_mode(mode: &Option<String>) -> Result<Option<u32>> {
    match mode {
        None => Ok(None),
        Some(m) if m == "preserve" => Ok(None),
        Some(m) => Ok(Some(parse_octal_mode(m)?)),
    }
}

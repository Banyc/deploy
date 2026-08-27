//! The release name ([`ReleaseName`]): exactly ONE directory component, so
//! the forced `<project>/releases/<name>/` structure can never be escaped.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Component, Path};

/// The active release: the name of a directory directly beneath `releases/` in
/// the project root. The project structure is forced to
/// `<project>/releases/<name>/<variant>.toml`; there is no configurable path.
/// The name carries the single-directory-component invariant
/// ([`ReleaseName::parse`] is the production constructor; the raw
/// deserialization path is re-validated by the raw -> domain conversion and by
/// [`crate::config::ProjectConfig::load_release`], so an invalid name can never enter a validated
/// [`crate::config::ProjectConfig`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReleaseName(String);
impl ReleaseName {
    /// Parse and validate a release name: exactly ONE directory component
    /// (the forced structure is `<project>/releases/<name>/`), so the name
    /// can never escape the release directory. This is the PRODUCTION
    /// constructor for a validated release name; the deserialization path
    /// stays raw and the conversion / [`crate::config::ProjectConfig::load_release`] re-validate.
    pub fn parse(s: &str) -> Result<ReleaseName> {
        validate_release_name(s)?;
        Ok(ReleaseName(s.to_string()))
    }

    /// Build a release name for the crate-internal raw layer (the conversion
    /// re-checks that it is a single directory component).
    #[cfg(test)]
    pub(crate) fn new(s: impl Into<String>) -> Self {
        ReleaseName(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReleaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A release name must be exactly ONE directory component (the forced
/// structure is `<project>/releases/<name>/<variant>.toml`), so it can never
/// escape the release directory. Shared by the raw -> domain conversion
/// ([`ProjectConfig::try_from`]), [`ReleaseName::parse`], and the validated
/// release-switch operation [`ProjectConfig::load_release`].
pub(crate) fn validate_release_name(name: &str) -> Result<()> {
    let single_component = matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(c)] if *c == std::ffi::OsStr::new(name)
    );
    if !single_component {
        return Err(Error::config(format!(
            "release '{name}' must be a single directory name (the release directory is forced to `releases/<name>/`)"
        )));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ReleaseName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReleaseNameVisitor;
        impl<'d> serde::de::Visitor<'d> for ReleaseNameVisitor {
            type Value = ReleaseName;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    "a release name like `release: v1` (the release directory is forced to `releases/<name>/`)",
                )
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<ReleaseName, E> {
                Ok(ReleaseName(v.to_string()))
            }

            fn visit_map<A>(self, _map: A) -> std::result::Result<ReleaseName, A::Error>
            where
                A: serde::de::MapAccess<'d>,
            {
                Err(serde::de::Error::custom(
                    "schema v1 forces the project structure `<project>/releases/<name>/<variant>.toml`: \
                     set `release: <name>` and drop the release.path/release.variants map",
                ))
            }
        }
        deserializer.deserialize_any(ReleaseNameVisitor)
    }
}

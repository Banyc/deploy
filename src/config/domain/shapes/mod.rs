//! The serialization shapes both layers share unchanged: the raw WIRE shapes
//! ([`raw`]) — exactly what the file says (`deny_unknown_fields` refuses
//! unknown fields at parse), plus the schema-version gate the raw -> domain
//! conversion enforces — and the artifact-mapping leaf types + the
//! artifact-relative path / octal-mode helpers ([`mapping`]). Both are
//! consumed as-is by the raw -> domain conversion in
//! [`crate::config::domain`].

pub(crate) mod mapping;
pub(crate) mod raw;

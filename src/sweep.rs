//! Re-export shim: the two-sided sweep contract tests moved to
//! [`crate::retention::sweep_tests`]. The old `crate::sweep` module exposed
//! ONLY private items (its test helpers and `#[test]` functions), so the shim
//! carries no re-exports — the module path itself is kept for compatibility.

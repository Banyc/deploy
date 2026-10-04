//! Canonical tree content: the substrate's manifest plus `deploy`'s
//! mapping/template materialization.
//!
//! The canonical tree objects ([`canonicalize_tree`], [`compute_tree_digest`],
//! [`entry_paths`]) and the remote verification wire
//! ([`remote_tree_verify_script`], [`canonicalize_remote_entries_checked`],
//! [`verify_tree_metadata`]) are now the SUBSTRATE's (`storekit::manifest`):
//! `deploy`'s copies are deleted, and the substrate names are re-exported below
//! so every existing `crate::remote::canonical::{...}` spelling keeps
//! resolving. Mapping/template materialization ([`materialize_variant`],
//! [`TemplateVars`], [`render_template`], [`render_argv`]) STAYS here: it is
//! `deploy`'s config-driven mapping composition (multiple sources placed into
//! one content-addressed staging tree, `{{var}}` rendering, per-mapping mode
//! overrides, symlink/special sources refused), not a plain mirror of one tree
//! into another, so the substrate's `sync` engine does not replace it — see
//! `storekit/MIGRATION.md` step 4.
//!
//! # What the swap changes
//!
//! The deleted `deploy` tree half resolved a relative symlink target LEXICALLY
//! against the tree ROOT and required the collapsed path to stay under it. The
//! substrate resolves it PHYSICALLY, on the target's spelled components, from
//! the link's CONTAINING directory (POSIX), and refuses any target the walk
//! cannot show to stay in the root — including one that reaches a symlink
//! component (intermediate or final), which the kernel would follow. The
//! replacements are therefore:
//!
//! * **Symlink containment is physical, not lexical.** `deploy` accepted
//!   `dir/link -> sub` where `dir/sub` is a symlink (a target that ends at a
//!   symlink), because it never followed a component; the substrate refuses it
//!   (fail closed: the walk cannot know where the follow ends). `deploy`
//!   refused a POSIX-valid in-root target such as `dir/link -> ../other`
//!   (lexically it pops the root); the substrate accepts it, resolving from the
//!   link's parent. Both directions are deliberate; the acceptance of
//!   `../sibling` is a relaxation of an over-refusal on trees `deploy` could
//!   never have stored, and the refusal of a target through a symlink component
//!   is a tightening on trees `deploy` would have stored with a containment
//!   answer that does not match the kernel's.
//! * **Names must already be NFC/UTF-8; targets must be UTF-8.** `deploy`
//!   NFC-normalized names (storing a spelling that can address a different
//!   on-disk name on a normalization-sensitive filesystem) and lossily decoded
//!   targets while hashing the raw bytes. The substrate REFUSES a non-NFC or
//!   non-UTF-8 name and a non-UTF-8 target, naming the entry.
//! * **The wire script is fail-closed.** The substrate script refuses an
//!   absent/non-directory/unreadable root, a non-UTF-8/non-NFC name, and a
//!   NUL/LF/CR/TAB in a name or target where `deploy`'s `File::Find` script
//!   emitted a possibly-short listing. The assembler now takes the walk's exit
//!   status ([`canonicalize_remote_entries_checked`]), splits on LF alone and
//!   refuses a bare CR (Rust's `str::lines` would fold it into the last field),
//!   requires exactly six tab-separated fields, requires the manifest to be
//!   parent-closed, and enforces the `NAME_MAX` component bound.
//! * **The destination observation is a distinct type.** The substrate's
//!   [`storekit::manifest::canonicalize_tree_destination`] returns a
//!   `DestinationTree` that cannot be used as a source manifest or serialized
//!   as a `tree.json`. `deploy` has no tolerant destination path — it uses the
//!   strict walk on destinations too and compares digests — so it does not
//!   adopt the tolerant type here.
//!
//! The canonical format itself is UNCHANGED for a tree both walks accept: the
//! entry fields, their serializer, and the digest are byte-identical, so no
//! stored object's `tree.json` or digest changes.

mod materialize;

pub use materialize::{
    ELECTED_VARIABLES, TemplateVars, materialize_variant, render_argv, render_template,
    validate_template_variables,
};

pub use storekit::manifest::{
    EntryKind, TreeEntry, TreeMetadata, canonicalize_remote_entries_checked, canonicalize_tree,
    compute_tree_digest, entry_paths, remote_tree_verify_script, verify_tree_metadata,
};

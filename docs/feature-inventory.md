# deploy — feature inventory (post-encapsulation)

Generated 2026-08-27. **The extraction loop is COMPLETE: all features are
confirmed encapsulated — the `src/` tree itself is the doc.** Every inventory
feature lives in a cohesive feature module under `src/<area>/` (verified with
the full gate after every pass). No module map is maintained here — the source
tree is the map. The only content that remains is actionable follow-up.

---

## A1. DEPLOYMENT SEMANTICS — all confirmed
## A2. LEDGER SEMANTICS — all confirmed
## A3. REMOTE / STORE SEMANTICS — all confirmed
## A4. RETENTION / SWEEP SEMANTICS — all confirmed
## A5. VERIFICATION / ACTIVATION SEMANTICS — all confirmed
## A6. IDENTITY / PROOF SEMANTICS — all confirmed
## A7. HIDDEN / IMPLICIT SEMANTICS — all confirmed

---

## B. Mismatches (stale docs vs code) — RESOLVED 2026-08-28

The public docs now describe ONE schema — the one `CONFIG_SCHEMA_VERSION`
enforces — guarded by two doc-consistency tests in
`src/config/domain/tests.rs`:

- `docs_render_schema_version_from_config_schema_version`: every
  `schema_version = N` literal (and the `schema vN:` shorthand) in
  README.md + requirement.md must equal `CONFIG_SCHEMA_VERSION`.
- `every_documented_toml_block_parses_under_the_strict_loader`: every
  ```toml block in README.md + requirement.md parses under the strict raw
  schemas (`deny_unknown_fields`) the loader uses.

Resolved: the `schema_version = 1` claims, the plural `targets` slot shape,
the removed release-refid `parent(<release-id>, 0)` leftover prose, the
`conflict`/`optional` mapping controls, and the SFTP claim. The scaffold's
generated `deploy.toml` doc comment renders the version from
`CONFIG_SCHEMA_VERSION`, and the InitOptions scaffold/load round-trip
property asserts the emitted schema version + slot ownership equals the
domain model.

- Transaction-record read-back + remote helper binary: documented PLANNED.

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

## B. Mismatches (stale docs vs code) — actionable follow-up

- README says `schema_version = 1` — loader REFUSES anything but 2.
- README slot `targets = ["production"]` plural — code requires singular `target`
  (plural rejected by deny_unknown_fields).
- README Maintenance mentions removed release-refid `parent(<release-id>, 0)`.
- requirement.md documents `conflict: error|replace|keep` + `optional` — code:
  `conflict="error"` only, no `optional`.
- requirement.md says SFTP/framed channel — implementation: shell-quoted
  `mkdir -p && cat >` over ssh.
- Transaction-record read-back + remote helper binary: documented PLANNED.

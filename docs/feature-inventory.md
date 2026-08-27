# deploy — feature inventory (post-encapsulation)

Generated 2026-08-27. **The extraction loop is COMPLETE: all features are
confirmed encapsulated — the codebase structure itself is the doc.** Every
inventory feature now lives in a dedicated module (verified with the full
gate after every pass). The A-sections below are intentionally EMPTY; the
Module map is the single source of truth for where each feature lives. The
B-section (doc/code mismatches) remains as actionable follow-up.

---

## A1. DEPLOYMENT SEMANTICS — all confirmed

*(empty — every feature in `src/deploy/`: push.rs orchestration, refs, groups,
batching, failure, noop, maintenance, coverage, plan, server, partial_rollout,
exact_rollback, compensation, results, status, staging, dryrun, capacity,
lock)*

## A2. LEDGER SEMANTICS — all confirmed

*(empty — every feature in `src/ledger/` + `src/remote/assignment.rs` +
`src/store/ledger.rs`)*

## A3. REMOTE / STORE SEMANTICS — all confirmed

*(empty — every feature in `src/remote/` + `src/store/`)*

## A4. RETENTION / SWEEP SEMANTICS — all confirmed

*(empty — every feature in `src/retention/` + `src/remote/rotate.rs`)*

## A5. VERIFICATION / ACTIVATION SEMANTICS — all confirmed

*(empty — every feature in `src/verify/` + `src/remote/{hostkey,protocol,runner}.rs`)*

## A6. IDENTITY / PROOF SEMANTICS — all confirmed

*(empty — every feature in `src/identity/`)*

## A7. HIDDEN / IMPLICIT SEMANTICS — all confirmed

*(empty — every hidden behavior has a documented home in the module map or in
its hosting module's doc comment; test-only shims live in
`src/remote/materialize.rs` + `src/deploy/push.rs` tests)*

## Module map (the doc — the codebase structure)

| Feature area | Module paths |
| --- | --- |
| A1 deployment | `src/deploy/` — `push.rs` (orchestration spine), `refs.rs`, `groups.rs`, `batching.rs`, `failure.rs`, `noop.rs`, `maintenance.rs`, `coverage.rs`, `plan.rs`, `server.rs`, `partial_rollout.rs`, `exact_rollback.rs`, `compensation.rs`, `results.rs`, `status.rs`, `staging.rs`, `dryrun.rs`, `capacity.rs`, `lock.rs` |
| A2 ledger | `src/ledger/` — `records.rs`, `intent.rs`, `terminal.rs`, `outcomes.rs`, `observation.rs`, `schema.rs`, `append.rs`, `membership.rs`, `rollback.rs`, `finalize.rs`, `recovery.rs`, `refs.rs`, `rebinding.rs`, `log.rs`; `src/remote/assignment.rs`; `src/store/ledger.rs` |
| A3 remote / store | `src/remote/` — `helper.rs`, `current.rs`, `markers.rs`, `transactions.rs`, `publish.rs`, `rotate.rs`, `protocol.rs`, `assignment.rs`, `canonical.rs`, `materialize.rs`, `layout.rs`, `observed.rs`, `transport.rs`, `ssh.rs`, `hostkey.rs`, `runner.rs`; `src/store/` — `local.rs`, `ledger.rs`, `objects.rs`, `observed.rs`, `deployments.rs`, `debt.rs`, `layout.rs`, `pins.rs`, `releases.rs`, `atomic.rs` |
| A4 retention / sweep | `src/retention/` — `policy.rs`, `pins.rs`, `gc.rs`, `history_floor.rs`, `checkpoint.rs`, `debt.rs`, `rotate.rs`, `sweep_tests.rs`; `src/remote/rotate.rs` |
| A5 verification / activation | `src/verify/` — `command.rs`, `systemd.rs`, `behavior.rs`, `release.rs`; `src/remote/{hostkey,protocol,runner,ssh}.rs` |
| A6 identity / proof | `src/identity/` — `release_id.rs`, `ids.rs`, `digests.rs`, `segments.rs`, `scalars.rs`, `payload.rs`, `proofs.rs` |
| A7 hidden / implicit | documented in each hosting module's doc comment (e.g. `src/remote/ssh.rs` `DEPLOY_SSH_KNOWNHOSTS_DIR`, `src/deploy/push.rs` lock ordering) |
| Configuration | `src/config/` — `raw.rs`, `domain.rs`, `pins.rs`, `slots.rs`, `rollout.rs`, `retention.rs`, `activation.rs`, `verification.rs`, `servers.rs`, `capacity.rs`, `release_name.rs` |

Integration tests address the crate through the new tree: `deploy::deploy::…`
(the A1 area), `deploy::ledger::…`, `deploy::identity::…`,
`deploy::verify::release::…`, `deploy::remote::layout::…`, etc.

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

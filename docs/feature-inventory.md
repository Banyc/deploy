# deploy — feature inventory (post-encapsulation)

Generated 2026-08-27. **Confirmed-encapsulated features have been REMOVED**:
each now lives in its own dedicated module (verified with the full gate per
pass). Per the extraction principle, the loop continues until this doc is
EMPTY — the codebase structure itself becomes the doc. The sections below
retain ONLY the features not yet individually extracted, each with its current
home.

---

## A1. DEPLOYMENT SEMANTICS — remaining

- **Head-files push** — home: `src/deploy/push.rs` (the orchestration spine).
- **Skipped slots still appear** in the attempt with their reconciled assignment — home: `src/deploy/push.rs`.

## A2. LEDGER SEMANTICS — remaining

- **`assignment.json`** (per-generation record read/write) — home: `src/remote/helper.rs` (core helper).

## A3. REMOTE / STORE SEMANTICS — remaining

- **Local object recovery** (`recover_if_missing` from a retaining server) — home: `src/deploy/push.rs`.

## A4. RETENTION / SWEEP SEMANTICS — remaining

- **Pusher/receiver split** (receiver rotation vs pusher checkpoint sweep; conceptual framing) — receiver I/O `src/remote/rotate.rs` + contract `src/retention/rotate.rs`; pusher `src/retention/checkpoint.rs` + `gc.rs`.

## A5. VERIFICATION / ACTIVATION SEMANTICS — remaining

*(none)*

## A6. IDENTITY / PROOF SEMANTICS — remaining

*(none)*

## A7. HIDDEN / IMPLICIT SEMANTICS — remaining (host module not yet dedicated)

- [HIDDEN] PendingCommit demotion reasons ("recoverable metadata failure", "commit diverged", "marker integrity conflict") — home: `src/deploy/push.rs`.
- [HIDDEN] Three lock layers (local `FileLock` `src/deploy/lock.rs`, per-target, per-slot remote mutation locks `src/remote/current.rs`/`helper.rs`) — spans.
- [HIDDEN] Abandoned incoming cleanup before mutating — home: `src/deploy/push.rs`.
- [HIDDEN] `UMASK_PROBE_MODE`/`UMASK_RESULT_FILE`, `FAKE_SYSTEMCTL_FAIL`/`FAKE_SYSTEMCTL_ONCE` — test-only shims — home: `src/remote/materialize.rs` + `src/deploy/push.rs` tests.

## Module map (encapsulation)

Post-encapsulation layout: every inventory feature now lives in the feature
area that owns its semantics, and the crate is wired to the NEW paths only
(no re-export shims). The module tree is the single source of truth for
where each feature lives.

| Feature | Module path |
| --- | --- |
| A1 deployment semantics | `src/deploy/` — `push.rs` (orchestration spine), `refs.rs`, `groups.rs`, `batching.rs`, `failure.rs`, `noop.rs`, `maintenance.rs`, `coverage.rs`, `plan.rs`, `server.rs`, `partial_rollout.rs`, `exact_rollback.rs`, `compensation.rs`, `staging.rs`, `dryrun.rs`, `capacity.rs`, `lock.rs` |
| A2 ledger semantics | `src/ledger/` — `records.rs`, `intent.rs`, `terminal.rs`, `outcomes.rs`, `observation.rs`, `schema.rs`, `append.rs`, `membership.rs`, `rollback.rs`, `finalize.rs`, `recovery.rs`, `refs.rs`, `rebinding.rs`, `log.rs` |
| A3 remote / store semantics | `src/remote/` — `helper.rs`, `current.rs`, `markers.rs`, `transactions.rs`, `publish.rs`, `rotate.rs`, `protocol.rs`, `canonical.rs`, `materialize.rs`, `layout.rs`, `observed.rs`, `transport.rs`, `ssh.rs`, `hostkey.rs`, `runner.rs`; `src/store/` — `local.rs`, `ledger.rs`, `objects.rs`, `observed.rs`, `deployments.rs`, `debt.rs`, `layout.rs`, `pins.rs`, `releases.rs`, `atomic.rs` |
| A4 retention / sweep | `src/retention/` — `policy.rs`, `pins.rs`, `gc.rs`, `history_floor.rs`, `checkpoint.rs`, `debt.rs`, `rotate.rs`, `sweep_tests.rs` |
| A5 verification / activation | `src/verify/` — `command.rs`, `systemd.rs`, `behavior.rs`, `release.rs` |
| A6 identity / proof | `src/identity/` — `release_id.rs`, `ids.rs`, `digests.rs`, `segments.rs`, `scalars.rs`, `payload.rs`, `proofs.rs` |
| A7 hidden / implicit | the remaining items above, each annotated with its hosting module |
| Configuration | `src/config/` — `raw.rs`, `domain.rs`, `pins.rs`, `slots.rs`, `rollout.rs`, `retention.rs`, `activation.rs`, `verification.rs`, `servers.rs`, `capacity.rs`, `release_name.rs` |

Integration tests address the crate through the new tree: `deploy::deploy::…`
(the A1 area), `deploy::ledger::…`, `deploy::identity::…`,
`deploy::verify::release::…`, `deploy::remote::layout::…`, etc.

## B. Mismatches (stale docs vs code)

- README says `schema_version = 1` — loader REFUSES anything but 2.
- README slot `targets = ["production"]` plural — code requires singular `target`
  (plural rejected by deny_unknown_fields).
- README Maintenance mentions removed release-refid `parent(<release-id>, 0)`.
- requirement.md documents `conflict: error|replace|keep` + `optional` — code:
  `conflict="error"` only, no `optional`.
- requirement.md says SFTP/framed channel — implementation: shell-quoted
  `mkdir -p && cat >` over ssh.
- Transaction-record read-back + remote helper binary: documented PLANNED.

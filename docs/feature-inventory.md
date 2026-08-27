# deploy — feature inventory (post-encapsulation)

Generated 2026-08-27. **Confirmed-encapsulated features have been REMOVED**:
each of them now lives in its own dedicated module (verified per-pass with the
full gate; see the Module map below for where every feature lives). The
sections below retain ONLY the features that are NOT yet individually
encapsulated — those still sharing a module (or spread across areas) — each
with a note of its current home. A7 (hidden/implicit semantics) is retained
in full: it is inherently spread across the owning areas.

---

## A1. DEPLOYMENT SEMANTICS — remaining

- **Head-files push** — home: `src/deploy/push.rs` (shares the orchestration module with the push steps).
- **Group push = COMPLETE snapshot** (unselected slots carried forward, fully rollback-capable) — home: `src/ledger/finalize.rs` (shared with finalization).
- **Partial-rollout guards** (first-deployment / membership-change rules) — home: `src/deploy/plan.rs` (shared with planning).
- **"Everything up to date" no-op** (ArtifactRef equality + per-slot verification) — home: `src/deploy/push.rs`.
- **Per-slot compensation (step 11)** (restore prior generation / remove `current` on first deploy) — home: `src/deploy/server.rs` (shared with the per-server process).
- **Outcome dispositions** (InProgress/Successful/PendingCommit/FailedPreflight/FailedRolledBack/Degraded) — home: `src/ledger/records.rs`.
- **Per-slot outcome kinds** (Activated/Failed/Skipped/Restored; Compensated reserved) — home: `src/ledger/records.rs`.
- **Degraded semantics** (remaining-changes derivation, all-restored refusal) — home: `src/ledger/records.rs`.
- **CAS precondition** (`swap_current` only advances on the expected generation) — home: `src/remote/helper.rs` (shared with the remote helper).
- **Skipped slots still appear** in the attempt with their reconciled assignment — home: `src/deploy/push.rs`.

## A2. LEDGER SEMANTICS — remaining

- **One ledger per target** (`targets/<target>/ledger.jsonl`, append-only JSONL) — home: `src/store/local.rs` (infrastructure).
- **Two line kinds** (intent / terminal, merged on read) — home: `src/ledger/records.rs` (shared with the record types).
- **Deployment-id-keyed** (duplicate intent refused; terminal requires matching intent) — home: `src/store/local.rs` + `src/ledger/records.rs`.
- **`deploy log`** rendering — home: `src/cli.rs`.
- **Commit markers** (idempotent per-server markers; integrity conflict → Degraded) — home: `src/remote/helper.rs` (shared).
- **Schema versions** (fail-closed, independent; constants live in their owning areas) — home: `LEDGER`/`PINS` → `src/ledger/records.rs`, `CONFIG` → `src/config/raw.rs`, `TREE` → `src/remote/canonical.rs`, `RELEASE_PAYLOAD`/`RELEASE_RECORD` → `src/verify/release.rs`, `PROTOCOL` → `src/remote/transport.rs`.
- **Exact rollback verification** (rebound slot / moved deploy_dir refuses) — home: `src/deploy/push.rs`.
- **Transaction records** (written `prepared`→`committed`/`compensated`, never read back — PLANNED) — home: `src/remote/helper.rs` (shared).

## A3. REMOTE / STORE SEMANTICS — remaining

- **`current` symlink chain** (full integrity validation) — home: `src/remote/helper.rs` (shared with the remote helper).
- **`assignment.json`** (per-generation record) — home: `src/remote/helper.rs` (shared).
- **Content-addressed object store** (immutable, re-verified) — home: `src/store/local.rs` (infrastructure).
- **Publish** (rename staged `.partial`; existing remote objects re-hashed before trust) — home: `src/remote/helper.rs` (shared).
- **Local object recovery** (`recover_if_missing` from a retaining server) — home: `src/remote/helper.rs` (shared) / `src/store/local.rs`.
- **Local store layout** (default_base, 0700 dirs, per-deployment plan records) — home: `src/store/local.rs` (infrastructure).
- **`deployments/<id>/`** per-deployment plan records (swept by checkpoint) — home: `src/store/local.rs`.
- **Three-state observation types** (`Observation<T>`, `ObservedState/Generation/Slot/Target`) — home: `src/ledger/records.rs` (shared; re-exported by `src/remote/observed.rs`).

## A4. RETENTION / SWEEP SEMANTICS — remaining

- **Post-commit step-17 retention** (never fails the push; debt marker + warning) — home: `src/deploy/push.rs` (`retain_slot_post_commit`).
- **Deferred-retention retry** (later pushes + the no-op path) — home: `src/deploy/push.rs`.
- **Receiver rotation** (contract in `src/retention/rotate.rs`; the mark-and-sweep I/O lives in `src/remote/helper.rs` — spans both).
- **Pusher/receiver split** (receiver rotation vs pusher checkpoint sweep; conceptual, spans `src/retention/` + `src/remote/helper.rs`).

## A5. VERIFICATION / ACTIVATION SEMANTICS — remaining

- **Behavior coverage gate** (every planned (release, variant) needs a frozen contract before mutation) — home: `src/deploy/push.rs`.
- **Protocol handshake** (first-contact `control/protocol.json`, later contacts refuse on version mismatch) — home: `src/remote/helper.rs` (shared).

## A6. IDENTITY / PROOF SEMANTICS — remaining

- **`RebindingPlan` / `VerifiedReleaseRebinding`** (the verified rebinding proof) — home: `src/ledger/records.rs` (shared with the record types).

## A7. HIDDEN / IMPLICIT SEMANTICS (retained in full — inherently spread)

- [HIDDEN] `DEPLOY_SSH_KNOWNHOSTS_DIR` env var — LIVE in production builds (relocates the pinned-known-hosts cache); undocumented — home: `src/remote/ssh.rs` / `src/remote/hostkey.rs`.
- [HIDDEN] No-op push silently runs: deferred-retention retry, pending-sweep retry, observed refresh, per-slot verification — home: `src/deploy/push.rs`.
- [HIDDEN] `reconcile_pending_commits` runs before ref resolution (relative refs see the post-recovery chain) — home: `src/ledger/recovery.rs`.
- [HIDDEN] PendingCommit demotion reasons ("recoverable metadata failure", "commit diverged", "marker integrity conflict") — home: `src/deploy/push.rs`.
- [HIDDEN] Commit-marker integrity conflicts finalize Degraded, never stranded-pending — home: `src/ledger/recovery.rs`.
- [HIDDEN] Step-17 test hook (`step17_hook_barrier`, `HookPhase`) — `#[cfg(test)]` only — home: `src/deploy/push.rs`.
- [HIDDEN] `UMASK_PROBE_MODE`/`UMASK_RESULT_FILE`, `FAKE_SYSTEMCTL_FAIL`/`FAKE_SYSTEMCTL_ONCE` — test-only shims — home: `src/remote/materialize.rs`, `src/deploy/push.rs`.
- [HIDDEN] Transaction records written but never read back (documented PLANNED) — home: `src/remote/helper.rs`.
- [HIDDEN] `helpers/` remote dir created but unused (planned helper binary) — home: `src/remote/layout.rs`.
- [HIDDEN] Full current-chain integrity on every status read (malformed != nothing deployed) — home: `src/remote/helper.rs`.
- [HIDDEN] Remote objects never trusted (re-canonicalize + digest compare before use) — home: `src/remote/helper.rs`.
- [HIDDEN] `verify_release_identity` on every release read — home: `src/verify/release.rs`.
- [HIDDEN] Filesystem root refused as deploy_dir — home: `src/remote/transport.rs`.
- [HIDDEN] Abandoned incoming cleanup before mutating — home: `src/deploy/push.rs`.
- [HIDDEN] First-deployment compensation removes `current` (CAS), never writes — home: `src/deploy/server.rs`.
- [HIDDEN] Compensation re-runs the PRIOR generation's stored behavior contract with the PRIOR assignment's identity — home: `src/deploy/server.rs`.
- [HIDDEN] `SlotOutcomeKind::Compensated` reserved, never emitted — home: `src/ledger/records.rs`.
- [HIDDEN] `parent(@,0) ≡ @` fold — home: `src/deploy/refs.rs` + `src/ledger/refs.rs`.
- [HIDDEN] Group pushes still yield COMPLETE snapshots + partial-rollout guards — home: `src/ledger/finalize.rs` + `src/deploy/plan.rs`.
- [HIDDEN] Dry-run still connects to remotes (read-only) — home: `src/deploy/dryrun.rs`.
- [HIDDEN] Three lock layers (local `FileLock` in `src/deploy/lock.rs`, per-target, per-slot remote mutation locks in `src/remote/helper.rs`).
- [HIDDEN] `ensure_target_dir_durable` (fsync before the lock file) — home: `src/store/local.rs`.
- [HIDDEN] Durable debt markers (`retention-debt.json`, `sweep-debt.json`) — home: `src/store/local.rs` (I/O) + `src/retention/debt.rs`.
- [HIDDEN] `deploy log` ` group=<name>` annotation — home: `src/cli.rs`.
- [HIDDEN] No-op verification renders EXISTING generation identities, never fabricated ones — home: `src/deploy/push.rs`.
- [HIDDEN] All names are single safe path segments — home: `src/identity/segments.rs` + `src/identity/scalars.rs`.

## Module map (encapsulation)

Post-encapsulation layout: every inventory feature now lives in the feature
area that owns its semantics, and the crate is wired to the NEW paths only
(no re-export shims). The module tree is the single source of truth for
where each feature lives.

| Feature | Module path |
| --- | --- |
| A1 deployment semantics | `src/deploy/` — `push.rs` (orchestration), `refs.rs` (reference grammar, the old `revset`), `groups.rs`, `batching.rs`, `failure.rs`, `plan.rs`, `server.rs`, `staging.rs`, `dryrun.rs`, `capacity.rs`, `lock.rs` |
| A2 ledger semantics | `src/ledger/` — `records.rs` (wire + domain records, `LEDGER_SCHEMA_VERSION`/`PINS_SCHEMA_VERSION`), `append.rs`, `membership.rs`, `rollback.rs`, `finalize.rs`, `recovery.rs` (the old `push::reconcile`), `refs.rs` (resolution) |
| A3 remote / store semantics | `src/remote/` — `helper.rs`, `canonical.rs` (the old `tree`, `TREE_SCHEMA_VERSION`), `materialize.rs` (the old `mapper`/`template`), `layout.rs` (the old `layout`), `observed.rs`, `transport.rs`, `ssh.rs`, `hostkey.rs`, `runner.rs`; `src/store/` — `local.rs`, `atomic.rs` |
| A4 retention / sweep | `src/retention/` — `policy.rs`, `pins.rs`, `gc.rs` (the old `store::gc`), `history_floor.rs` (the old `store::history_floor`), `checkpoint.rs` (the old `push::checkpoint`), `debt.rs`, `rotate.rs`, `sweep_tests.rs` (the old `sweep`) |
| A5 verification / activation | `src/verify/` — `command.rs` (the old `adapter::verify`), `systemd.rs` (the old `adapter::systemd`), `behavior.rs` + `release.rs` (the old `release`; `RELEASE_PAYLOAD_`/`RELEASE_RECORD_SCHEMA_VERSION`) |
| A6 identity / proof | `src/identity/` — `release_id.rs`, `ids.rs`, `digests.rs`, `segments.rs`, `scalars.rs`, `payload.rs`, `proofs.rs` (the old `model` + `scalar` surface) |
| A7 hidden / implicit | spread across the owning areas: `src/cli.rs` (log rendering, checkpoint CLI), `src/deploy/push.rs` (lock ordering, durable debt wiring), `src/retention/debt.rs` (durable markers), `src/remote/ssh.rs` (`DEPLOY_SSH_KNOWNHOSTS_DIR`), `src/config/raw.rs` (`CONFIG_SCHEMA_VERSION`) |
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

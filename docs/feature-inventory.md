# deploy — semantic feature inventory

Generated 2026-08-27 (readonly research agent, cross-checked cli.rs / model.rs /
revset.rs / push engine / records / config / store / retention / gc / checkpoint /
adapters / transports / README.md / requirement.md). Gitignored — not tracked.

---

## A1. DEPLOYMENT SEMANTICS

- **Head-files push**: `deploy push <target>` materializes the locally mapped files
  of the active release (`releases/<release>/<variant>.toml` -> trees) and deploys
  to every member slot of the target (cli.rs:180, engine.rs:386).
- **Reference grammar** (`push <target> [ref]`, jj-style; parsed store-free by
  winnow, resolved against the target's ledger; revset.rs):
  - `` / `HEAD` / `@` — current local files (default).
  - `@-` / `@--` — 1/2 deployments before the latest *successful* deployment.
  - `parent(@, N)` — N steps back from latest (shell-quote needed: comma).
  - `<deployment-id>` — restore that deployment's exact stored snapshot.
  - `<deployment-id>-` / `<deployment-id>--` — 1/2 steps back from that deployment.
  - `parent(<deployment-id>, N)` — N steps back (N=0 = the deployment itself).
  - `release:<id>` — DIRECT release deploy (cross-target, no snapshot history
    needed; full `rel-sha256-...` id or bare 64-hex digest at the CLI boundary).
  - **REMOVED** (fail closed with migration hints): `sN`/`fN` forms, release-refid
    ancestor forms (`rel-...--`, `parent(rel-..., M)`), bare release ids,
    `release/<id>`, target-repeated `target@ref`, `:current`.
  - `parent(@, 0)` folds to `@` (is_head_push).
  - Out-of-range refs are ref errors — never underflow/guess.
- **Rollout groups**: `--group <name>` selects the target's slots whose `groups`
  list contains the name; membership for historical/HEAD refs from the CURRENT
  topology, for `release:<id>` from the RELEASE's frozen topology (plan.rs:502).
- **Group push = COMPLETE snapshot**: unselected slots carried forward from the
  latest successful base; fully rollback-capable (history.rs:259).
- **Partial-rollout guards**: first deployment requires the group to cover every
  slot; after membership changes every unselected slot needs a prior assignment
  with matching physical binding (plan.rs:332).
- **`--dry-run`**: prints the per-slot plan, touches nothing (no store writes, no
  locks, no remote mutation; still connects READ-ONLY + pins host key locally).
- **"Everything up to date"** no-op for HEAD pushes: requires complete ArtifactRef
  equality (release+variant+tree) AND a successful per-slot verification run.
- **Batching**: `rollout.batch_size` (validated NONZERO) slots per batch, in
  deployment (assignment) order — not sorted slot ids.
- **`stop_on_failure`**: halts remaining batches after the first failed slot.
- **Failure policies** (strict typed enum; unknown spelling = config load error):
  `rollback_changed` (default) and `leave_changed`.
- **Per-slot compensation (step 11)**: activation/verification failure after
  `current` advanced -> restore prior generation (or remove `current` on first
  deploy, CAS) with the prior generation's stored behavior contract + identity.
- **Batch-failure compensation (step 13)**: under `rollback_changed`, every
  `advanced` server compensated via CAS; failed compensation -> Degraded.
- **Outcome dispositions**: InProgress (intent-only), Successful, PendingCommit,
  FailedPreflight, FailedRolledBack, Degraded.
- **Per-slot outcome kinds**: Activated, Failed, Skipped, Restored;
  `Compensated` RESERVED, never emitted.
- **Degraded semantics**: remaining changes DERIVED from outcomes (never stored);
  all-restored outcomes refused for Degraded (must be FailedRolledBack).
- **CAS precondition**: `swap_current` only advances if `current` still points at
  the expected generation; divergence -> Skipped, never a clobber.
- **Skipped slots still appear** in the attempt with their reconciled assignment.
- **Per-slot mutation lock** held across publish/swap/activate/commit (RAII).

## A2. LEDGER SEMANTICS

- **One ledger per target**: `targets/<target>/ledger.jsonl`, append-only JSONL.
- **Two line kinds**: `intent` (durable, persisted BEFORE any remote mutation)
  and `terminal` (status, outcomes, rollback); merged on read.
- **Crash-atomic appends**: temp + fsync + rename + parent-dir fsync.
- **Deployment-id-keyed**: duplicate intent refused; terminal requires matching
  intent (fail closed).
- **`deploy log <target>`**: newest last, PREFIXED with the rollback payload's
  deployment id (or `-`); failed/degraded visible but never valid rollback refs;
  optional ` group=<name>` note.
- **Recovery / pending-commit reconciliation** (`reconcile_pending_commits`): runs
  at the START of every real push (before ref resolution + no-op check);
  intent-only entries processed oldest-first: membership check, fresh remote
  generation == desired, idempotent commit markers under slot locks, finalize via
  the SHARED finalizer; mismatch/integrity conflict -> Degraded; transient
  failures stay pending.
- **Replay-safe finalization**: `append_terminal` refuses duplicates.
- **Commit markers** (remote, per server): `state/commits/<deployment-id>.json`
  with deployment id, generation, full participating slot set, target; written
  idempotently; differing content = integrity conflict -> Degraded.
- **Schema versions** (each fail-closed on read, independent): CONFIG=2,
  LEDGER=3 (three-state pre_push + persisted selected/full memberships; v1/v2
  REJECTED), RELEASE_PAYLOAD=3, RELEASE_RECORD=2, TREE=1, PINS=1, PROTOCOL=1.
- **Membership proof equations** (every Successful terminal): outcomes ==
  selected_membership, rollback == full_membership, selected ⊆ full, full-push
  selected == full.
- **Rollback payload** = complete resulting target snapshot: per-slot
  GenerationRef + PhysicalBinding {server, deploy_dir}.
- **Exact rollback verification**: rebound slot or moved deploy_dir refuses.
- **Transaction records**: `transactions/<op-id>.json` prepared -> committed /
  compensated — [HIDDEN] WRITTEN but never read back (documented PLANNED).

## A3. REMOTE / STORE SEMANTICS

- **`current` symlink chain**: `current` -> `generations/<gen>/root` ->
  `../../objects/sha256/<tree>/root` (canonical byte-exact target); the COMPLETE
  chain validated on every status read — missing gen dir, malformed/mismatched
  assignment, non-symlink or wrong root link, missing tree object are integrity
  errors (never reported as absent).
- **`assignment.json`** (per generation): deployment_id, generation_id, artifact,
  behavior_sha256, prior_generation, created_at, owning target.
- **Content-addressed object store** (local + remote): `objects/sha256/<digest>/root`
  + `tree.json`; immutable, re-verified on reuse.
- **Tree canonicalization**: NFC-normalized UTF-8 paths, umask-independent modes,
  relative in-root symlinks only, absolute/devices/sockets/FIFOs/hard links
  rejected, ownership/timestamps/xattrs stripped.
- **Materialization**: mappings `from` relative to release dir (cannot escape);
  overlapping destinations rejected; dirs keep source mode; `{{ variant }}` only
  at mapping time.
- **Staging**: per-variant persistent staging dirs; operation-unique remote
  incoming dirs (`incoming/<deployment-id>/<digest>.partial`); dry-run disposable.
- **Publish**: rename staged `.partial` into the store only if digest absent;
  EXISTING remote objects re-hashed (download -> canonicalize -> digest compare)
  before trust.
- **Local object recovery**: `recover_if_missing` downloads from a retaining server.
- **Remote layout**: control/protocol.json, helpers/ (created, unused), objects/,
  releases/, generations/, incoming/, state/ (operation.lock, inventory.json,
  commits/), adapters/, transactions/, current.
- **Observed state**: ONE physical record per slot (`slots/<slot-id>/observed.json`);
  target views are projections.
- **Three-state observation**: Known / KnownAbsent / Unknown(error) — unreadable
  assignment is a DISTINCT value, never a valid-looking artifact; `deploy status`
  renders Unknown as None columns + "observation failed: ...", never unchanged.
- **Filesystem-root refusal**: LocalTransport + deploy_dir validation refuse `/`.
- **Local transport** mirrors the SSH layout exactly (local:// full peers).

## A4. RETENTION / SWEEP SEMANTICS

- **Slot-owned retention**: one policy per slot, from the OWNING VARIANT; targets
  carry rollout only, membership changes never change retention.
- **Per-server policy**: keep_distinct_artifacts (5), keep_days (14),
  protect_previous (true — protects the immediate rollback target).
- **Deployment window**: protect_deployments (0 = off).
- **Current tree always retained**; malformed current chain already failed closed.
- **Post-commit step-17 retention**: per slot after durable commit, under the slot
  mutation lock; failure/lock contention NEVER fails the push — durable debt
  marker + warning.
- **Deferred-retention retry**: later pushes + the no-op path.
- **Pins**: config `[[pins]]` AND store `pins.json`; whole-release or exact-binding;
  retain artifact content only, never history.
- **Pin fail-closed**: unreadable/unverifiable pinned release ABORTS before deletion.
- **Receiver rotation**: mark-and-sweep per server (trees not in retained set +
  abandoned incoming); rewrites inventory.
- **Checkpoint command**: retained-suffix computation at a SUCCESSFUL deployment,
  ATOMIC suffix replace (the only logical commit), best-effort GLOBAL sweep.
- **Irreversibility guards**: deployment id required positional, `--yes` required,
  `--dry-run` previews the EXACT discard list (same LedgerOverride).
- **Global GC reachability** (fail closed on every anchor: unreadable ledger /
  observed / pins aborts before any deletion).
- **Unknown-observation conservatism**: an Unknown observed slot aborts the sweep.
- **Sweep debt**: `<base>/sweep-debt.json`; next push recomputes fresh; no
  persisted deletion worklist.
- **Both sweeps post-commit maintenance**: failures are WARNINGS, never errors.
- **Not secure erasure**: unlink + fsync only.

## A5. VERIFICATION / ACTIVATION SEMANTICS

- **Verification adapter `command`**: argv executed directly (never a shell),
  timeout_seconds, attempts (default 1), interval_seconds; zero exit within
  timeout = success.
- **argv templating** with the full slot context BEFORE exec; unknown/malformed
  variable fails loudly.
- **Activation adapters**: `none` (default) and `systemd`.
- **systemd user scope**: staged rendered units, copied to ~/.config/systemd/user/,
  daemon-reload, enable, restart.
- **systemd system scope**: NEVER links units into /etc/systemd/system; only a
  scoped restart of the fixed admin wrapper.
- **`reconcile_managed_units`** (default true): disables/removes formerly managed
  links absent from the desired contract; ownership in adapters/systemd.json.
- **Unit-name safety**: absolute paths / `..` / `.` / empty names rejected.
- **Artifact-path validation** before `current` changes.
- **Behavior contract frozen**: canonicalized + hashed into release identity
  (behavior_sha256) + copied into every deployment/generation record; historical
  pushes use historical contracts, never current config.
- **Behavior coverage gate**: every planned (release, variant) must have a frozen
  contract BEFORE any remote mutation.
- **Host identity**: exactly one of known_hosts (StrictHostKeyChecking=yes) or
  host_key_fingerprint (SSH256:..., pinned via ssh-keyscan); TOFU refused; both
  rejected as ambiguous.
- **Key-pin cache**: $TMPDIR/deploy-ssh-knownhosts/knownhosts-<hash>.txt,
  validated against the fingerprint before reuse.
- **Protocol handshake**: first contact records control/protocol.json (exclusive
  create); later contacts refuse on version mismatch.
- **SSH transport bounds**: ConnectTimeout=10 bounds the connection; a process
  deadline (60s) bounds the whole operation; on deadline SIGKILL + deterministic
  reap (no zombies).

## A6. IDENTITY / PROOF SEMANTICS

- **ReleaseId**: exact `rel-sha256-<64 lowercase hex>`; bare/`rel-` forms rejected
  at the domain boundary; CLI accepts a bare 64-hex digest (converted first).
- **DeploymentId / GenerationId / OperationId**: `deploy-`/`gen-`/`op-` +
  canonical hyphenated UUIDv7 (version nibble enforced; v4 rejected).
- **TreeDigest / ReleaseDigest**: exactly 64 lowercase hex.
- **Segment identities**: SlotId, ServerId, TargetName, VariantName,
  RolloutGroupName — single safe path segment.
- **ApplicationStoreKey**: single safe segment; store = base.join(key).
- **BatchSize**: nonzero u64; **CapacityPercent**: 0..=100; **AbsoluteDeployDir**:
  absolute.
- **Release identity payload**: name-sorted mapping digest + behavior digest +
  slot-declaration digest + variant->tree bindings; capacity excluded; slots ARE
  identity (rebind/move/retarget = new release).
- **verify_release_identity**: recompute on EVERY read; foreign payload version
  fails verification.
- **Membership proofs**: SlotSet / NonEmptySlotSet / MatchingMembership — only
  construction path is `MatchingMembership::verify` (frozen == current).
- **RebindingPlan / VerifiedReleaseRebinding**: `release:<id>` pushes carry the
  verified rebinding proof (frozen topology -> current physical slots).
- **No `Default` on identities** (empty identity unrepresentable).

## A7. HIDDEN / IMPLICIT SEMANTICS [HIDDEN]

- [HIDDEN] `DEPLOY_SSH_KNOWNHOSTS_DIR` env var — LIVE in production builds,
  relocates the pinned-known-hosts cache; undocumented (hostkey.rs:74).
- [HIDDEN] No-op push silently runs: deferred-retention retry, pending-sweep
  retry, observed projection refresh, per-slot verification (invisible except the
  `warning:` line).
- [HIDDEN] `reconcile_pending_commits` runs before ref resolution — relative refs
  like `@-` see the post-recovery chain.
- [HIDDEN] PendingCommit demotion reasons: "recoverable metadata failure",
  "commit diverged", "marker integrity conflict".
- [HIDDEN] Commit-marker integrity conflicts finalize Degraded, never
  stranded-pending.
- [HIDDEN] Step-17 test hook (`step17_hook_barrier`, `HookPhase`) — #[cfg(test)]
  only; cannot be armed in production builds.
- [HIDDEN] `UMASK_PROBE_MODE`/`UMASK_RESULT_FILE`, `FAKE_SYSTEMCTL_FAIL`/
  `FAKE_SYSTEMCTL_ONCE` — test-only shims.
- [HIDDEN] Transaction records written but never read back (documented PLANNED).
- [HIDDEN] `helpers/` remote dir created but unused (planned helper binary).
- [HIDDEN] Full current-chain integrity on every status read (malformed != nothing
  deployed).
- [HIDDEN] Remote objects never trusted (re-canonicalize + digest compare before
  use).
- [HIDDEN] `verify_release_identity` on every release read.
- [HIDDEN] Filesystem root refused as deploy_dir.
- [HIDDEN] Abandoned incoming cleanup before mutating.
- [HIDDEN] First-deployment compensation removes `current` (CAS), never writes.
- [HIDDEN] Compensation re-runs the PRIOR generation's stored behavior contract
  with the PRIOR assignment's identity (no torn combinations).
- [HIDDEN] `SlotOutcomeKind::Compensated` reserved, never emitted.
- [HIDDEN] `parent(@,0) ≡ @` fold (parse + resolution).
- [HIDDEN] Group pushes still yield COMPLETE snapshots (unselected carried
  forward) + partial-rollout guards.
- [HIDDEN] Dry-run still connects to remotes (read-only status; pins host keys) —
  "touches nothing" means no writes/locks/mutation, not no network.
- [HIDDEN] Three lock layers: local operation.lock, per-target lock, per-slot
  remote mutation locks.
- [HIDDEN] `ensure_target_dir_durable` (fsync before the lock file lives inside).
- [HIDDEN] Durable debt markers (retention-debt.json, sweep-debt.json) are the
  only persisted sweep/retention state.
- [HIDDEN] `deploy log` ` group=<name>` annotation.
- [HIDDEN] No-op verification renders EXISTING generation identities, never
  fabricated ones.
- [HIDDEN] All names (application/server/slot/target/variant/group) are single
  safe path segments — can never escape their directory.

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

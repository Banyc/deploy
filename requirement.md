# Simple Deployment System Plan
## Goal
Build a small deployment system with a Git-push-style interface

```sh
deploy push production
```

A user configures a named deployment target once. A push then constructs the required artifacts, stores them locally, distributes the appropriate variant to each server, activates it, verifies it, records the result, and safely rotates stale artifacts.

The system must support:
- multiple immutable releases locally and on every server;
- multiple arbitrary variants within a release;
- a different variant assignment for each server;
- declarative local-to-artifact file mappings;
- multiple servers grouped into named deployment targets;
- atomic per-server activation with recoverable rollback;
- configurable, server-aware retention;
- optional systemd registration and activation.

## Core model
The deployment core is deliberately ignorant of application semantics. It does not distinguish executables, configuration, static assets, scripts, or service definitions. It understands only filesystem entries, mappings, trees, artifacts, variants, releases, targets, activation adapters.
The important identities are:

```text
tree        = immutable filesystem content, identified only by its tree digest
variant     = a name bound to one tree within a release
artifact    = the immutable release + variant + tree binding
release     = an immutable map of every declared variant to a tree digest
target      = a named group of stable server IDs and its rollout policy
deployment  = an attempted push and its exact per-server assignments
generation  = one server's durable activation record for one assignment
```

Deployment, operation, and generation IDs are opaque collision-resistant IDs (UUIDv7 in schema version 1). They identify events and are never used as content identity.

Tree objects contain no release- or variant-specific metadata, so identical trees can be deduplicated safely. Release records bind variants to trees.

The canonical release ID is derived from a versioned canonical identity payload covering the name-sorted per-variant mapping digests, all declared `variant → tree digest` bindings, and the name-sorted per-variant activation and verification behavior-contract digest. It explicitly excludes the resulting release ID, creation time, display name, and provenance, avoiding a circular hash. Two variants may share tree bytes while still requiring different activation and verification behavior, so behavior is captured per variant rather than once per release. Its stored form is `pel-sha256-full-`
release-digest`; the CLI may display and accept an unambiguous digest prefix. Git revision and creation time are provenance only because mapped inputs can include generated or untracked files.

Mapping and behavior digests are computed from versioned canonical data after schema defaults, path normalization, and validation, not from YAML whitespace, comments, or key order. The original configuration remains available as provenance, while `behavior.json` records the canonical behavior contract. Each variant's capacity and rotation policy is likewise persisted with the release record in `policies.json`; historical deployments resolve capacity headroom and retention from that snapshot rather than the caller's current configuration, so a variant that was renamed or removed after the release was created still rolls back exactly.

The first materialization fixes the immutable release record's `created_at` and first-seen provenance. Reusing the same release later does not rewrite that record; the new deployment attempt records its own current provenance.

Materializing a release always resolves every declared variant, even if a particular target uses only a subset. Therefore the same local inputs have one target-independent release identity.

An activated tree is read-only application state. A program that needs mutable runtime data must address storage outside `current`; the deployment core does not classify or manage that data. Any change beneath a published tree is detected as corruption and repaired from a verified copy rather than accepted as a new artifact.
## User interface
The normal workflow is remote-centric and intentionally small:

```sh
# Deploy the current local inputs to a named target.
deploy push production
# Show what would change without modifying servers.
deploy push production --dry-run
# Inspect the target's deployment history.
deploy log production
# Inspect the actual generation on every server.
deploy status production
# Restore the exact fleet assignment from an earlier deployment
deploy push production production@f1}:current
```

`production` is not a built-in environment type. It is a user-chosen target name, analogous to a Git remote name such as `origin`, except that one target may fan out to multiple servers. Other valid names include `test-lab`, `datacenter-hk`, or `customer-acme`.

The default command:

```sh
deploy push production
```

is equivalent to:

```sh
deploy push production HEAD: current
```

`HEAD` means "materialize the currently mapped local files" rather than "use only Git-tracked bytes." Pushing identical content reuses the existing local release and tree objects. It is a complete no-op only when reconciliation also shows that every target server already has the intended assignment and passes verification; otherwise the push repairs or completes the remote state.

There are no required user-facing package, upload, activate, systemd-register, or rotate commands. Those are stages of `push`. A `rollback` command may exist as a convenience alias, but rollback remains a push of an older deployment reference.

## Declarative configuration
The project file structure is forced: one deployment definition naming the active release, and a `releases/` tree where each release directory holds its variant files (every `*.toml` file inside is a variant named by its file stem) and its artifact sources:

```text
my-project/
  deploy.toml            # release = "v1"
  releases/
    v1/
      standard.toml      # variant file: mappings + policies
      high-capacity.toml
      artifacts/         # artifact sources referenced by mappings
    v2/
      ...
```

Example `deploy.toml`:

```toml
schema_version = 1
application = "example"
remote_root = "/srv/deploy/example"
release = "v1"              # the release directory is forced to releases/v1/

[[pins]]
release = "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1"
variants = "all"
reason = "known-good recovery release"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[[targets.production.servers]]
id = "server-01"
address = "server-01.example.com"
user = "deploy"
variant = "standard"

[[targets.production.servers]]
id = "server-02"
address = "server-02.example.com"
user = "deploy"
variant = "standard"

[[targets.production.servers]]
id = "server-03"
address = "server-03.example.com"
user = "deploy"
variant = "high-capacity"
```

Each variant is described by its own file inside the release directory (e.g.
`releases/v1/standard.toml`); there is no explicit variant list to keep in
sync. A variant file owns its artifact mappings and its deployment policies:

```toml
# releases/v1/standard.toml
# All `from` paths are relative to the release directory (`releases/v1/` — the
# project structure is forced), so artifact sources live under `artifacts/`.
description = "Standard deployment"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/variants/{{ variant }}/"
to = "app/"
recursive = true
conflict = "replace"

[[artifact.mappings]]
from = "artifacts/deployment/systemd/example.service"
to = "integration/systemd/example.service"
mode = "0644"

[activation]
adapter = "systemd"
scope = "user"
reconcile_managed_units = true

[[activation.units]]
name = "example.service"
artifact_path = "integration/systemd/example.service"
enable = true
restart = true

[verification]
adapter = "command"
argv = ["/srv/deploy/example/current/app/server", "health-check"]
timeout_seconds = 15
attempts = 3
interval_seconds = 2

[capacity]
reserve_bytes = 1073741824
reserve_percent = 5

[rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[rotation.fleet]
protect_deployments = 2
```

Server IDs are durable identities and cannot be inferred from mutable network addresses. Deployment history is keyed by server ID. A rollback connects using the server's current address and verifies its configured SSH host identity; it never silently connects to a historical address.

### Mapping semantics
A mapping is only:

```text
local source path → artifact-relative destination path
```

In schema version 1, `from` is relative to the release directory (`releases/<release>/`) and must remain beneath it. Absolute and escaping source paths are rejected. Recursive directory mappings merge directories; their conflict policy applies to colliding descendant entries rather than deleting unrelated entries already placed at the destination.

Supported mapping controls should include:

```toml
[[artifact.mappings]]
from = "local/path"
to = "artifact/path"
recursive = true
conflict = "error"
mode = "preserve"
optional = false
# conflict: "error" | "replace" | "keep"
# mode: "preserve" or an explicit octal mode
```

Mappings are applied in declaration order. A collision fails unless the mapping explicitly selects another conflict behavior. In schema version 1, `{{ variant }}` is the only interpolation variable. Target name and server, environment variables, and machine state cannot influence a tree; all servers assigned the same release variant must receive the same digest.

The mapper does not implicitly template file contents.

Materialization uses a canonical tree format:
- paths must be valid UTF-8, Unicode NFC-normalized relative paths;
- absolute paths, `..`, NUL bytes, and duplicate normalized paths are rejected;
- regular files and directories are supported;
- relative symbolic links are supported only when their resolved target stays inside the artifact root;
- absolute or escaping symbolic links, devices, sockets, FIFOs, and hard links are rejected;
- user/group ownership and timestamps are omitted from identity and normalized to the deployment account when installed;
- ACLs, extended attributes, and platform-specific metadata are not part of schema version 1 and are stripped from materialized trees;
- modes are recorded, with an explicit mapping mode overriding the source;
## Local storage
The local store contains the exact immutable trees sent to servers, immutable release bindings, and the observed state of each target:

```text
~/.local/share/simple-deploy/example/
  objects/
    sha256/
      <tree-digest>/
        root/
          ... arbitrary files
  tree.json
  releases/
    <release-id>/
      mapping.toml
      behavior.json
      policies.json
      release.json
  targets/
    production/
      observed.json
      attempts.jsonl
      refs/
        last-successful
        reflog.jsonl
  servers/
    server-01.json
    server-02.json
    server-03.json
  deployments/
    <deployment-id>/
      plan.json
      results.json
      status
```

Tree metadata is identity-neutral. For example,

```json
{
  "tree_schema_version": 1,
  "hash_algorithm": "sha256",
  "tree_sha256": "8cc1...",
  "entries": [
    {
      "path": "app/server",
      "type": "file",
      "mode": "0755",
      "content_sha256": "72ed..."
    }
  ]
}
```

`tree.json` is:
Release-specific metadata lives outside the tree object. For example, `release.json` is:

```json
{
  "release_schema_version": 1,
  "release_id": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
  "release_sha256": "41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
  "created_at": "2026-08-21T10:15:00Z",
  "provenance": {
    "git_revision": "a13f09c",
    "mapping_sha256": "b380...",
    "behavior_sha256": "03df..."
  },
  "variants": {
    "standard": "8cc1...",
    "high-capacity": "197b..."
  }
}
```

This separation allows two releases or variants with identical bytes to share one tree safely. Release records and tree objects are immutable; attempts to replace an existing ID or digest with different content fail.

Local target state is a mirror and cache, not unquestioned authority. Before a mutating operation, the tool reconciles it with the actual remote generation, object inventory, and in-progress transaction state. If a remote retains a
verified tree that is missing locally, reconciliation downloads it into local staging, verifies its canonical digest, and republishes it into the local object store. Local rotation must never remove an object still retained on a known remote server.

The local store is created with permissions accessible only to its owning user. The system treats all tree bytes as confidential because it cannot know which files contain sensitive material. It never logs file contents; manifests and logs contain paths, modes, and digests only.

## Remote storage
Each server stores only variants it has actually received:

```text
/srv/deploy/example/
  control/
  helpers/
    <protocol-version>/deploy-helper
    current-helper → helpers/<protocol-version>/deploy-helper
  objects/
    sha256/
      <tree-digest>/
        root/
          ... arbitrary files
        tree.json
  files
  releases/
    <release-id>/
      behavior.json
      release.json
  generations/
    <generation-id>/
      assignment.json
      root → ../../objects/sha256/<tree-digest>/root
      current → generations/<generation-id>/root
    incoming/
      <deployment-id>/
        <tree-digest>.partial/
    state/
      history.jsonl
      inventory.json
      pins.json
      operation.lock
    adapters/
      systemd.json
    transactions/
      <operation-id>.json
```

Tree objects, release records, and generation records are immutable. Staging uploads may run concurrently because each uses a deployment-specific incoming path that is invisible to activation and rotation. The remote mutation lock is acquired before a staged tree is published and held through publication, generation creation, activation, verification, state recording, and rotation. Existing objects are reused only after their digest and manifest are verified.

Publishing renames a verified incoming directory into `objects/` on the same filesystem. A generation binds a deployment ID, release ID, `variant`, tree digest, behavior snapshot, and prior generation. After its files and a durable transaction record have been written and synced, activation cre
ates a temporary symlink beside `current`, atomically renames it over `current`, and syncs the parent directory. This single durable pointer replacement is the per-server commit point.

There is no independently updated `previous` symlink. The previous successful generation is derived from the immutable generation chain and history. This avoids pretending that two reference updates can be atomic. On startup or the next connection, the remote helper reconciles any unfinished transaction with the actual `current` target and either completes its record or restores the prior generation before accepting another mutation.

Atomicity is per server, not across a fleet. Fleet consistency is provided by the rollout and compensation policy described below.

## Push transaction
`deploy push <target>` performs the following:
1. Validate the configuration, unique stable server IDs, variant assignments, paths, adapter settings, and SSH host identities.
2. Acquire the local application-store lock and target lock in that order. Application-store publication and local rotation are serialized across targets; target history updates are serialized per target.
3. Materialize every declared variant, generate canonical tree objects, and reuse any object whose digest already exists and verifies correctly.
4. Freeze the mapping, activation, and verification contract; generate or reuse the immutable release record.
5. Reconcile every server's actual `current`, object inventory, and unfinished transactions. Recovery must complete before planning a new mutation.
6. Create and durably save a deployment attempt containing the expected pre-push generation and desired assignment for every server.
7. Before changing any server, prove that every desired tree is available locally. For historical pushes, also require the current target membership to match the historical deployment's stable server-ID set.
8. Check local and remote capacity with configured safety headroom. If needed, run the ordinary protected rotation under each remote mutation lock before staging, then recheck. Abort before activation if required space is still unavailable.
9. Upload and verify missing trees in operation-unique incoming paths on every server before activating the first batch. Uploading and staged verification may be parallel, but incoming content is not installable and rotation ignores it.
10. Process servers in configured batches. For each server, acquire its remote mutation lock and compare `current` with the plan's expected generation. If it differs, fail that server without mutation. Otherwise publish and reverify the tree and release record, create a generation and transaction record, atomically move `current`, run the activation adapter, and run
verification.
11. On per-server activation or verification failure, atomically restore the prior generation, reconcile the prior activation contract, verify the restored service, and record both the failure and compensation result. On a first deployment with no prior generation, compensation removes `current` and reverses only adapter resources created by that attempt.
12. If `stop_on_failure` is enabled, do not start another batch after any failure.
13. Under the default `failure_policy: rollback_changed`, compensate every server already advanced by this deployment. Compensation uses a compare-and-swap and restores a server only if `current` still names the generation created by this attempt. If all compensation succeeds, mark the attempt `failed_rolled_back`; otherwise mark it `degraded` and retain the actual mixed per-server state. An optional `leave_changed` policy may retain successful advances deliberately; any attempt with failures under that policy is `degraded`.
14. Record every attempt, not just successful attempts, in `attempts.jsonl` and refresh `observed.json` from the actual server generations.
15. After every server verifies, write an idempotent fleet-commit marker under each participating server's mutation lock. If this metadata phase is interrupted, mark the attempt `pending_commit`; reconciliation completes
the markers without reactivating healthy servers when their generations still match. Any mismatch changes the attempt to `degraded`.
16. Only an attempt whose fleet-commit markers are complete becomes `successful`, advances `refs/last-successful`, and appends to its successful-deployment reflog.
17. Apply rotation under each server's mutation lock using the protection set defined below.

The tool never claims fleet-wide atomicity. It reports `successful`, `pending_commit`, `failed_preflight`, `failed_rolled_back`, or `degraded`, including the actual generation on every server. An attempt that fails before any `current` change is `failed_preflight`. A later push always reconciles and can finish or repair an incomplete target.

The local target lock prevents competing pushes from the same local store. Expected-generation and compensation compare-and-swap checks prevent a second controller from being silently overwritten. Concurrent controllers can still cause a visible failed or degraded fleet attempt, but cannot create a lost update on an individual server.

If materialization produces an existing release and reconciliation finds the exact desired generation healthy on every server, the command prints `Everything up to date` without creating a deployment attempt. Existing local
content never suppresses required remote repair.

`-dry-run` materializes and inspects local content and performs read-only remote status queries in disposable staging. It does not publish local objects, recover remote transactions, upload, publish remotely, activate, execute application verification, write history, or rotate. Instead, it reports any recovery that a real push would have to perform.

## Fleet history and rollback
Every deployment attempt records its target snapshot, behavior contract, pre-push state, desired state, and actual result. A successful example is:

```json
{
  "deployment_schema_version": 1,
  "deployment_id": "deploy-20260821T102000Z",
  "status": "successful",
  "target": "production",
  "server_ids": ["server-01", "server-02", "server-03"],
  "behavior_sha256": "03df...",
  "servers": {
    "server-01": {
      "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
      "variant": "standard",
      "tree_sha256": "8cc1...",
      "generation": "gen-01..."
    },
    "server-02": {
      "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
      "variant": "standard",
      "tree_sha256": "8cc1...",
      "generation": "gen-02..."
    },
    "server-03": {
      "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
      "variant": "high-capacity",
      "tree_sha256": "197b...",
      "generation": "gen-03..."
    }
  }
}
```

The target reflog contains only fully successful fleet snapshots and exposes them as `production@f0}`, `production@f1}`, and so on. Failed and degraded attempts remain visible through `deploy log production` and `attempts.jsonl`, but are not valid rollback sources.

A fleet commit is authoritative only when the same deployment ID and server-ID set are committed on every member. This lets a fresh or repaired local store reconstruct successful fleet history from the servers instead of trusting a stale local ref.

Pushing an older successful reference restores its complete assignment, including the historical behavior contract and different variants on different servers:

```sh
deploy push production production@f1}:current
```

Exact fleet rollback requires the current target to contain the same stable server-ID set as the saved deployment. Addresses may change and are taken from the current target definition after host-identity verification. If membership has changed, exact rollback fails during preflight without modifying a server.

Schema version 1 permits a target-history ref only as a source for that same target; cross-target deployment uses a release ref instead.

The operator may instead push an old release to the new target membership:

```sh
deploy push production release/rel-41da2f63a950:current
```

That form assigns each current server the named release's tree for its current variant. The abbreviated release ID must be unambiguous; scripts and persistent configuration use the full ID. The push fails if the release lacks any assigned variant.

Rollback never rebuilds a tree. It uses the retained immutable object with the recorded digest. All required objects are checked locally and staged remotely before the first server changes. If an object is missing locally, reconciliation first attempts to recover it from a target server that retains the verified digest. If no verified copy can be recovered, preflight fails and leaves every `current` pointer unchanged.

## Protection and rotation
Retention is evaluated per server because servers may have different release and variant histories. A successful fleet deployment is committed back to each participating server before rotation, allowing its generation history to record the fleet deployment ID. Rotation does not run if those commit markers cannot be reconciled.

Capacity preflight reserves the larger of `capacity.reserve_bytes` and `capacity.reserve_percent` of the destination filesystem after the upload. It may invoke the same protected rotation before staging, but never weakens the retained set merely to make a deployment fit.

For each server, the retained content set is exactly this union:

```text
- the artifact referenced by the current generation
- the prior distinct successful artifact when protect_previous is true
- artifacts referenced by incomplete transactions
- artifacts or releases selected by durable pins
- the newest keep_distinct_artifacts distinct successful artifact bindings
- artifacts successfully activated less than keep_days ago
- that server's artifacts in the newest fleet. protect_deployments
- fleet commits
```

An artifact binding is `(release ID, variant, tree digest)`. Repeated repair or restart generations for the same binding consume one retention slot, not many.
Distinct artifacts are ordered by their most recent successful activation. `keep_distinct_artifacts` and `keep_days` are union rules, not conditions that must both match. Age is measured from the binding's most recent successful activation rather than release creation time.

Rotation is a mark-and-sweep operation under the remote mutation lock:
1. Reconcile `current`, unfinished transactions, history, pins, and fleet commit markers.
2. Mark tree objects referenced by the retained artifact bindings.
3. Keep generation, release, fleet-commit, and history metadata by default; metadata is small and continues to explain unavailable historical states.
4. Delete a tree object only when no retained binding or applicable pin on that server references it. A release or generation record may continue to describe a tree that is no longer installed and must report it as unavailable.
5. Remove abandoned operation-specific incoming directories only after their owner transaction has expired and is known not to be running.

Local rotation protects the complete set of variants for every release selected by the same count, age, current, prior, fleet-window, pin, remote-inventory, or unfinished-attempt rules across all targets.

Successful reflog metadata may be
kept indefinitely, but only entries inside the configured protection windows retain release and tree content. An older reflog entry whose content was rotated remains auditable but is reported as unavailable for rollback. A local tree object is deleted only after no retained release or known remote inventory requires it.

Rotation runs automatically after a successful, fully recorded push. It may later be exposed as an explicit maintenance command without changing these safety rules.

## systemd adapter
Systemd support is an optional adapter outside the generic artifact engine. The mapped unit remains an ordinary artifact file. The adapter alone knows how to register and activate it. The activation and verification definitions are canonicalized, hashed into the release identity, and copied into each deployment and generation record. A historical push therefore uses its historical behavior contract rather than the caller's current configuration.

Before changing `current`, the helper validates that every declared `artifact_path` exists with the required type in the desired tree. Command verification is executed directly as an argument vector, never through a shell, with the configured deployment identity, timeout, attempt count, and
interval. Success requires a zero exit status within the timeout.

Registration creates a stable link such as:

```text
~/.config/systemd/user/example.service
  → /srv/deploy/example/current/integration/systemd/example.service
```

The first push moves `current` to the prepared generation and then registers and enables missing units idempotently as part of the recoverable activation transaction. Every activation or rollback performs the declared `daemon-reload`, enable, restart, and verification operations.

The adapter records the unit links it owns in `state/adapters/systemd.json`. With `reconcile_managed_units: true`, a successful transition disables and removes formerly managed links absent from the desired behavior contract; it never modifies unrelated units. On failure, compensation restores `current` and reconciles the prior generation's behavior contract before verification.

Artifact-controlled unit files are supported by default only with `scope: user`, using `systemctl --user`; they consequently have no more authority than the deployment account. A host may require one-time administrator configuration to keep that user's systemd manager running when the user is logged out.
For a system service, an administrator installs a root-owned wrapper unit whose security-sensitive directives, service user, and stable command entry point are not writable by the deployment account. In `scope: system`, `push` only verifies that wrapper's identity and uses a narrowly scoped permission to restart that specific unit. It never links an artifact-controlled unit into `/etc/systemd/system`. Treating a deployment account as authorized to replace system unit contents would make that account effectively root and is outside the safe default design.

## Transport and remote helper
The initial transport is SSH with strict host-key verification. Server IDs, target names, variant names, release IDs, and paths are validated data and are never concatenated into remote shell commands. Bulk tree transfer uses SFTP or an equivalent framed channel.

A small versioned remote helper owns status inspection, locking, object publication, generation switching, transaction recovery, adapter invocation, and rotation. Client and helper perform a protocol-version handshake before mutation. Every mutating request carries an operation ID and is idempotent, so a disconnected client can reconnect and learn whether the operation prepared, committed, compensated, or never began.

Remote-helper bootstrap is an internal first-push stage. After authenticating
the server, the client uploads its matching helper into a versioned location beneath `remote_root`, verifies the expected digest, and atomically updates the unprivileged helper entry point. If the deployment account cannot create `remote_root`, an administrator must provision that directory once. Privileged systemd control must likewise be provisioned through the fixed, root-owned wrapper and narrowly scoped restart permission described above; `push` does not grant itself privileges.

The remote application root and state are writable only by the deployment account. Artifact permissions may make selected files readable by the runtime service account, but state, incoming content, and manifests are not generally readable. Because the core cannot recognize secrets, users must understand that any sensitive bytes mapped into a tree will be retained in multiple local and remote versions. External credential references are preferred when versioned secret retention is undesirable.

## Required safety properties
- Never modify a published tree object, release record, or generation record.
- Never reuse an object or release ID until its existing contents verify.
- Never point `current` at a partial, unverified, or unrecorded generation.
- Make one atomic `current` replacement the only per-server commit point.
- Require the planned current generation as a compare-and-swap precondition; compensate only a generation still owned by the failing operation.
- Recover or compensate every unfinished transaction before another mutation.
- Hold the server mutation lock across publication, activation, state commit, and rotation; staging alone may occur outside it in unique incoming paths.
- Never delete a tree, release, or generation in the computed retained set.
- Never infer fleet success from the local plan; reconcile actual generations and fleet-commit markers, and record successful, pending, failed, compensated, and degraded results.
- Never describe fleet rollout as atomic; expose partial state explicitly.
- Ensure a release variant always resolves to one canonical tree digest, independent of target or server.
- Snapshot mappings, variant bindings, behavior contract, target server IDs, pre-push generations, desired generations, timestamps, and actual results.
- Treat all artifact bytes as confidential and never log their contents.

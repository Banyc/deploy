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
release     = an immutable map of every declared variant to a tree digest plus the release's own canonical per-variant slot declarations (the slot snapshot, folded into the ReleaseId)
server      = a durable machine identity: a stable ID plus its current address
deployment slot = a binding of one top-level server to one variant under an ID, with an absolute deploy_dir, declared inside the variant file that owns the workload; its `target` field binds it to exactly one target
physical binding = a slot's `{server, deploy_dir}` pair at a point in time: the exact on-host deployment location; snapshots record it so exact rollback can verify a slot still lives where it was deployed
target      = a named group of slots (derived from the slots' `target` fields) plus its rollout and retention policy
deployment  = an attempted push and its exact per-server assignments
generation  = one placement slot's durable activation record for one assignment
```

Deployment, operation, and generation IDs are opaque collision-resistant IDs (UUIDv7 in schema version 1). They identify events and are never used as content identity.

Tree objects contain no release- or variant-specific metadata, so identical trees can be deduplicated safely. Release records bind variants to trees and freeze the release's own canonical per-variant slot declarations (the slot snapshot).

The canonical release ID is derived from a versioned canonical identity payload covering the name-sorted per-variant mapping digests, the name-sorted per-variant SLOT DECLARATION digest (each variant's `[[slots]]` entries canonicalized to their four identity fields `id`/`server`/`deploy_dir`/`target` — `deploy_dir` lexically normalized — and sorted by slot id), all declared `variant → tree digest` bindings, and the name-sorted per-variant activation and verification behavior-contract digest. It explicitly excludes the resulting release ID, creation time, display name, and provenance, avoiding a circular hash. Two variants may share tree bytes while still requiring different activation and verification behavior, so behavior is captured per variant rather than once per release. A slot-only change — rebinding a slot to another server, moving its `deploy_dir`, or retargeting it — produces a NEW release ID: the canonical slot declarations are part of the identity, and the release record persists them as its slot snapshot. Capacity is NOT part of the release identity: it is a per-server policy declared on the server entry and resolved from the caller's current configuration at preflight time, so a server-capacity change never produces a new release. Its stored form is `rel-sha256-<release-digest>`; the CLI may display and accept an unambiguous digest prefix. Git revision and creation time are provenance only because mapped inputs can include generated or untracked files.

Mapping and behavior digests are computed from versioned canonical data after schema defaults, path normalization, and validation, not from TOML formatting, comments, or key order. The original configuration remains available as provenance, while `behavior.json` records the canonical behavior contract. Snapshot files are written atomically and immutably with create-or-compare semantics: an identical rewrite is an idempotent no-op, and replacing an existing release's `behavior.json` with different content fails. A historical deployment restores the variant's original activation and verification behavior from this snapshot (so a variant renamed or removed after the release was created still rolls back exactly), and resolution fails closed: a missing or corrupt historical behavior snapshot aborts the attempt during preflight rather than silently substituting the caller's current configuration or defaults. Capacity headroom, by contrast, is a per-server policy that is never snapshotted: servers have no per-release history, so every push — HEAD or historical — resolves it from the caller's current `deploy.toml`. Retention (`rotation`) is target-level configuration declared within each target of the project file, not a per-variant or global setting, and is read from the caller's current configuration on every push.

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
deploy push production production@f1
```

`production` is not a built-in environment type. It is a user-chosen target name, analogous to a Git remote name such as `origin`, except that one target may fan out to multiple servers. Other valid names include `test-lab`, `datacenter-hk`, or `customer-acme`.

The default command:

```sh
deploy push production
```

is equivalent to:

```sh
deploy push production HEAD
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
release = "v1"              # the release directory is forced to releases/v1/

[[pins]]
release = "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1"
reason = "known-good recovery release"

# Retention policy — a target-level setting, not a per-variant or global one.
[targets.production.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.production.rotation.fleet]
protect_deployments = 2

# Servers are declared once; slots are declared inside the variant files and
# bind themselves to a target with their `target` field (a target's members
# are derived from the slots). Capacity is a per-server policy, shared by
# every deployment slot on the server and resolved from this file at preflight
# time — it is never part of a release.
[[servers]]
id = "server-01"
address = "server-01.example.com"
user = "deploy"
capacity = { reserve_bytes = 1073741824, reserve_percent = 5 }

[[servers]]
id = "server-02"
address = "server-02.example.com"
user = "deploy"
capacity = { reserve_bytes = 1073741824, reserve_percent = 5 }

[[servers]]
id = "server-03"
address = "server-03.example.com"
user = "deploy"
capacity = { reserve_bytes = 1073741824, reserve_percent = 5 }

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
```

Servers and targets are declared once at the top level of `deploy.toml`;
slots are declared inside the variant files. Each slot binds one server to the
variant whose file declares it, names an absolute `deploy_dir`, and carries a
`target` field naming the ONE target it belongs to — a target's member slots
are DERIVED by scanning every variant's slots for that target name. A slot
belongs to exactly one target (its on-server `deploy_dir` state is single;
the per-target records keyed by slot ID cannot attribute it otherwise), and
this is STRUCTURAL: a slot has a single `target` field, so it cannot be a
member of two targets. Two slots may share one server in different targets,
but within a single target each server appears at most once (one running
generation per server). Besides `id`,
`address`, and `user`, every server accepts an
optional `port` (default 22), exactly one host-identity source — a dedicated
`known_hosts` file used with `StrictHostKeyChecking=yes`, or a pre-verified
`host_key_fingerprint` (`SHA256:...`) that is pinned on first contact — and an
optional per-server capacity policy (`capacity = { reserve_bytes = ...,
reserve_percent = ... }`, defaulting to 0/0). The capacity policy is shared by
every deployment slot on that server and is resolved from the caller's CURRENT
configuration at preflight time; servers have no per-release history, so it is
not part of any release snapshot.
The exactly-one host-identity rule is ENFORCED, not merely documented: for
every SSH-shaped `address`, a config with neither source (which would fall back
to trust-on-first-use) and a config with both sources (an ambiguous choice) are
both rejected at validation with a message naming the server, and the SSH
transport defensively rejects both states at construction even when validation
was bypassed. `local://` endpoints perform no host verification and need no
identity source. The `deploy init` CLI mirrors the rule: the two identity flags
conflict at parse time, and an SSH `--address` without exactly one of them is
rejected by the init handler.
Trust-on-first-use without a configured identity source is disabled. All configuration is parsed strictly: every config struct carries `deny_unknown_fields`, so an unrecognized key anywhere in `deploy.toml` or in a variant file is rejected at load rather than silently ignored.

Each variant is described by its own file inside the release directory (e.g.
`releases/v1/standard.toml`); there is no explicit variant list to keep in
sync. A variant file owns its artifact mappings, its deployment policies
(activation, verification), AND its deployment slots — the `[[slots]]`
entries of the file, whose `target` field binds each slot to exactly one
top-level target; rotation is declared once per target:

```toml
# releases/v1/standard.toml
# All `from` paths are relative to the release directory (`releases/v1/` — the
# project structure is forced), so artifact sources live under `artifacts/`.
description = "Standard deployment"

# This variant's deployment slots: app-1/app-2 (server-01/server-02) belong to
# target `production`; the variant's `high-capacity` sibling declares hc-1
# (server-03) the same way. A target's members are derived from these fields.
[[slots]]
id = "app-1"
server = "server-01"
target = "production"
deploy_dir = "/srv/deploy/example"

[[slots]]
id = "app-2"
server = "server-02"
target = "production"
deploy_dir = "/srv/deploy/example"

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
argv = ["{{ deploy_dir }}/current/app/server", "health-check"]
timeout_seconds = 15
attempts = 3
interval_seconds = 2
```

The `argv` above is rendered with the slot's template context before exec:
`{{ deploy_dir }}` resolves to the slot's absolute on-server deployment
directory. The same rendering applies to systemd unit-file content at
activation time (unit files like `ExecStart={{ deploy_dir }}/current/app/server`
stay slot-independent in the tree and are rendered per slot when installed).
The elected variables are `deploy_dir`, `variant`, `application`, `release`,
`target`, `server`, `user`, `address`, `port`, `slot`, `deployment_id`,
`generation`, and `tree`; only these exact names are substituted — no
arbitrary expressions or filters, and unknown/malformed templates fail the
push loudly. Availability is context-dependent: materialization provides only
`variant`, `application`, and `release` (where `release` is the release NAME
from `deploy.toml`), while activation and verification render the full slot
context, where `release` is the IMMUTABLE `ReleaseId` (`rel-sha256-…`) of the
deployed artifact — consistent for historical pushes, never the caller's
current release name. An elected variable that is unavailable at its render
site fails loudly rather than rendering an empty value.

Server IDs are durable identities and cannot be inferred from mutable network addresses. Deployment history, attempts, and rollback are keyed by placement slot ID (the deployment-location identity), while the server ID names the physical host for transport addressing. A rollback connects using the server's current address and verifies its configured SSH host identity; it never silently connects to a historical address.

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

Mappings are applied in declaration order. A collision fails unless the mapping explicitly selects another conflict behavior. Mapping `from` paths are rendered through the template module (`src/template.rs`) with the fixed set of 13 elected variables (see the activation paragraph above). At materialization only the per-variant subset is available: `variant`, `application`, and `release` — where `release` is the release NAME from `deploy.toml`, not the immutable `ReleaseId` (the `ReleaseId` is derived from the materialized trees, so rendering it into a tree would be a circular digest). Every per-slot and per-server variable (`deploy_dir`, `target`, `server`, `user`, `address`, `port`, `slot`, `deployment_id`, `generation`, `tree`) fails loudly at materialization: trees are content-addressed and shared across slots, so target name, server, environment variables, and machine state cannot influence a tree — all servers assigned the same release variant must receive the same digest. Activation (unit-file content) and verification (`argv`) render with the full slot context, where `release` is the deployed artifact's immutable `ReleaseId`. Unknown variables, expressions, filters, and malformed templates fail loudly; the mapper does not implicitly template file contents — unit files and argv are rendered explicitly at activation/verification time.

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
  staging/
  releases/
    <release-id>/
      mapping.toml
      behavior.json
      release.json
  targets/
    production/
      observed.json
      attempts.jsonl
      refs/
        last-successful
        snapshots.jsonl
  servers/
    server-01.json
    server-02.json
    server-03.json
  deployments/
    <deployment-id>/
      plan.json
      results.json
      transitions.jsonl
```

The records model splits deployment identity from mutable status:
`attempts.jsonl` records the immutable attempt (intent + assignments, no
status); each deployment's status is an append-only transition stream
(`deployments/<id>/transitions.jsonl`) whose LATEST entry is the deployment's
current status; and successful deployments additionally produce a rollback
snapshot (`refs/snapshots.jsonl` + `refs/last-successful`), exposed as
`<target>@fN`.

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

`tree.json` is content-addressed, identity-neutral metadata stored next to
every tree object (locally and remotely), as shown earlier. Release-specific
metadata lives outside the tree object. For example, `release.json` is:

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
  },
  "slots": {
    "standard": {
      "slots": [
        {"id": "app-1", "server": "server-01", "deploy_dir": "/srv/deploy/example", "target": "production"},
        {"id": "app-2", "server": "server-02", "deploy_dir": "/srv/deploy/example", "target": "production"}
      ]
    },
    "high-capacity": {
      "slots": [
        {"id": "hc-1", "server": "server-03", "deploy_dir": "/srv/deploy/example", "target": "production"}
      ]
    }
  }
}
```

This separation allows two releases or variants with identical bytes to share one tree safely. The `slots` member is the release's OWN canonical per-variant slot snapshot — each variant's `[[slots]]` declarations in canonical form (`id`/`server`/`deploy_dir`/`target`, `deploy_dir` lexically normalized, slots sorted by id) — frozen into the record and folded into the release digest. Historical and rollback pushes resolve slot→variant bindings from this snapshot rather than the caller's current variant files; a record written before the snapshot existed (`slots` absent) falls back to the current configuration. Release records and tree objects are immutable; attempts to replace an existing ID or digest with different content fail.

Local target state is a mirror and cache, not unquestioned authority. Before a mutating operation, the tool reconciles it with the actual remote generation, object inventory, and in-progress transaction state. If a remote retains a
verified tree that is missing locally, reconciliation downloads it into local staging, verifies its canonical digest, and republishes it into the local object store. Local rotation must never remove an object still retained on a known remote server.

The local store is created with permissions accessible only to its owning user. The system treats all tree bytes as confidential because it cannot know which files contain sensitive material. It never logs file contents; manifests and logs contain paths, modes, and digests only.

## Remote storage
Each server stores only variants it has actually received:

```text
/srv/deploy/example/
  control/
    protocol.json            # protocol-version handshake marker
  objects/
    sha256/
      <tree-digest>/
        root/
          ... arbitrary files
        tree.json
  releases/
    <release-id>/
      release.json
      behavior.json
  generations/
    <generation-id>/
      assignment.json
      root → ../../objects/sha256/<tree-digest>/root
  current → generations/<generation-id>/root
  incoming/
    <deployment-id>/
      <tree-digest>.partial/
  adapters/
    systemd.json             # unit links owned by the systemd adapter
  transactions/
    <operation-id>.json
  state/
    inventory.json
    operation.lock
    commits/
      <deployment-id>.json   # write-once fleet-commit marker
```

Tree objects, release records, and generation records are immutable. Staging uploads may run concurrently because each uses a deployment-specific incoming path that is invisible to activation and rotation. The remote mutation lock is acquired before a staged tree is published and held through publication, generation creation, activation, verification, state recording, and rotation. Existing objects are reused only after their digest and manifest are verified.

### Immutable datatypes and their guarantees
Every datatype below carries an immutability semantic. For each one: what must never change, the mechanism that guarantees it, and where that mechanism is enforced.

1. **Tree object** — local `objects/sha256/<digest>/root` + `tree.json`, remote `objects/sha256/<digest>/root`.
   *Semantic*: bytes at a digest path always hash back to that digest.
   *Guarantee*: content-addressed identity; an existing object is re-canonicalized before reuse (`store.store_object`), freshly stored content is verified after copy and deleted on mismatch; staged uploads land in deployment-scoped `incoming/<deployment>/<digest>.partial` and become visible via a single same-filesystem rename (`helper.publish_from_incoming`); every activation re-canonicalizes the downloaded tree before `current` moves (`process_server` integrity check).
2. **Release record** — local `releases/<id>/release.json`.
   *Semantic*: a release ID permanently denotes one mapping set, per-variant slot-declaration set, behavior-contract set, and variant→tree binding set.
   *Guarantee*: the ID is derived from the canonical identity payload covering the mapping, slot-declaration, behavior, and binding digests (`release.release_digest`, schema version 2 with `slots_digest`); the record freezes the canonical per-variant slot snapshot it was built from, so a slot-only change (rebind, `deploy_dir` move, retarget) produces a new release ID and historical pushes resolve slot→variant bindings from the stored snapshot; `store.write_release` refuses to replace an existing ID with different `release_sha256` and treats identical rewrite as idempotent. Capacity is deliberately excluded: it is per-server live configuration, not a release property.
3. **Release snapshots** — `mapping.toml`, `behavior.json` beside the release record.
   *Semantic*: the frozen inputs behind a release ID can never be rewritten in place, not even partially.
   *Guarantee*: atomic create-or-compare writes (`store.write_atomic_cas`: temp file + rename for atomicity; existing content must match byte-for-byte or the write fails); remotely mirrored by `helper.publish_release_file` (exclusive create via `try_write_new`, then semantic-JSON or byte comparison, refuse replace). There is no capacity snapshot: capacity headroom is live per-server configuration read from the caller's current `deploy.toml`.
4. **Generation record** — remote `generations/<gen>/assignment.json` + `root` symlink.
   *Semantic*: once a generation exists, its assignment (deployment, placement slot, release, variant, tree, behavior digest, prior generation) is fixed forever.
   *Guarantee*: generation IDs are fresh UUIDv7 values minted under the operation lock; `helper.create_generation` installs `assignment.json` with exclusive create-or-compare — an ID collision with divergent content fails integrity instead of rewriting history — and the `root` symlink target is derived deterministically from the verified assignment, making crash recovery idempotent. `current` moves only through the compare-and-swap rename in `helper.swap_current`.
5. **Fleet commit marker** — remote `state/commits/<deployment-id>.json`.
   *Semantic*: a recorded fleet commit is a durable fact of that deployment.
   *Guarantee*: the marker is write-once: `helper.write_commit_marker` installs it by exclusive create, and if a marker already exists it must match byte-for-byte (the payload is deterministic in the deployment ID, generation, and participating placement-slot set) or the rewrite fails integrity. A retried or concurrent commit can therefore never alter a recorded fact; a `pending_commit` recovery reusing the original deployment ID either creates the missing marker or confirms the recorded one byte-for-byte.
6. **Deployment plan and results** — local `deployments/<id>/plan.json`, `results.json`.
   *Semantic*: what an attempt intended and produced is fixed once recorded.
   *Guarantee*: written once per unique deployment ID through `write_atomic_cas`; a same-ID conflicting rewrite fails instead of silently rewriting history (`store.write_plan`, `store.write_results`). The deployment's status is not part of these immutable records: it is an append-only transition stream (`deployments/<id>/transitions.jsonl`), deliberately NOT a mutable progress marker file, so status history is never rewritten. The attempt INTENT (`attempts.jsonl`, step 7) is persisted BEFORE any server mutation; `results.json` is the separate outcomes store written after the mutation loop.
7. **Attempt history and rollback snapshots** — `targets/<target>/attempts.jsonl`, `refs/snapshots.jsonl`.
   *Semantic*: recorded attempts (immutable intent, no status, no outcomes) and successful fleet snapshots are append-only facts; entries are never edited or reordered.
   *Guarantee*: append-mode-only writers under the target lock (`store.append_attempt`, `store.append_snapshot`); snapshot indices are assigned monotonically from the current entry count. Each deployment's status is a per-deployment append-only transition stream (`store.append_transition`), one event per line; the LATEST transition is the deployment's current status (`store.latest_status`).
Mutable by design (excluded from these guarantees): observed target state, per-server records, the `last-successful` ref, the per-deployment transition stream, incoming staging areas, transaction records, and all declarative configuration (`deploy.toml`, variant files), which are versioned through the release identity rather than frozen.

Publishing renames a verified incoming directory into `objects/` on the same filesystem. A generation binds a deployment ID, an artifact (release ID + `variant` + tree digest) for a placement slot, the behavior snapshot, and the prior generation. After its files and a durable transaction record have been written and synced, activation creates a temporary symlink beside `current`, atomically renames it over `current`, and syncs the parent directory. This single durable pointer replacement is the per-slot commit point.

There is no independently updated `previous` symlink. The previous successful generation is derived from the immutable generation chain and history. This avoids pretending that two reference updates can be atomic. On startup or the next connection, the remote helper reconciles any unfinished transaction with the actual `current` target and either completes its record or restores the prior generation before accepting another mutation.

Atomicity is per server, not across a fleet. Fleet consistency is provided by the rollout and compensation policy described below.

## Push transaction
`deploy push <target>` performs the following:
1. Validate the configuration, unique stable server IDs, slot-to-variant bindings, paths, adapter settings, and SSH host identities.
2. Acquire the local application-store lock and target lock in that order. Application-store publication and local rotation are serialized across targets; target history updates are serialized per target.
3. Materialize every declared variant, generate canonical tree objects, and reuse any object whose digest already exists and verifies correctly.
4. Freeze the mapping, activation, verification, and per-variant slot declaration contract; generate or reuse the immutable release record (the canonical slot declarations are part of the release identity, so a slot-only change yields a new release ID).
5. Reconcile every server's actual `current`, object inventory, and unfinished transactions. Recovery must complete before planning a new mutation.
6. Create and durably save the deployment attempt INTENT (expected pre-push generation and desired assignment for every placement slot; no outcomes) BEFORE changing any server, so a crash after servers advanced can never lose the deployment.
7. Before changing any server, prove that every desired tree is available locally. For historical pushes, also require the current target membership to match the historical deployment's stable placement-slot set, and each slot's COMPLETE physical binding — the `{server, deploy_dir}` pair from its current variant-file `[[slots]]` entry — to match the binding the snapshot recorded: a slot rebound to a different server, or moved to a different `deploy_dir` on the SAME server, is refused (an unrecorded legacy binding is unverifiable and refused the same way).
8. Check local and remote capacity with the configured safety headroom (the per-server `capacity` policy read from the caller's current `deploy.toml`). If needed, run the ordinary protected rotation under each remote mutation lock before staging, then recheck. Abort before activation if required space is still unavailable.
9. Upload and verify missing trees in operation-unique incoming paths on every server before activating the first batch. Uploading and staged verification may be parallel, but incoming content is not installable and rotation ignores it.
10. Process servers in configured batches. For each server, acquire its remote mutation lock and compare `current` with the plan's expected generation. If it differs, fail that server without mutation. Otherwise publish and reverify the tree and release record, create a generation and transaction record, atomically move `current`, run the activation adapter, and run
verification.
11. On per-server activation or verification failure, atomically restore the prior generation, reconcile the prior activation contract, verify the restored service, and record both the failure and compensation result. On a first deployment with no prior generation, compensation removes `current` and reverses only adapter resources created by that attempt.
12. If `stop_on_failure` is enabled, do not start another batch after any failure.
13. Under the default `failure_policy: rollback_changed`, compensate every server already advanced by this deployment. Compensation uses a compare-and-swap and restores a server only if `current` still names the generation created by this attempt. If all compensation succeeds, mark the attempt `failed_rolled_back`; otherwise mark it `degraded` and retain the actual mixed per-server state. An optional `leave_changed` policy may retain successful advances deliberately; any attempt with failures under that policy is `degraded`.
14. Record every attempt, not just successful attempts, in `attempts.jsonl` — the immutable INTENT (deployment id, membership, desired assignments, pre-push state; no status, no outcomes) — and refresh `observed.json` from the actual slot generations. The intent is persisted BEFORE any server mutation (right after the plan and the initial `in_progress` transition are written), so a crash after servers advanced to new generations can never lose the deployment: without the durable intent the next push would see every server already at the desired generation and report "Everything up to date" with no attempt/snapshot/ref ever recorded. The actual per-slot OUTCOMES are recorded separately in `deployments/<id>/results.json` after the mutation loop (the outcomes store the snapshot and `observed.json` are built from — never from the intent record). The attempt's status is recorded as an append-only transition on the deployment (`deployments/<id>/transitions.jsonl`): an initial `in_progress` transition, then the final status transition (with a reason when the metadata phase demoted it).
15. After every slot's server verifies, write an idempotent, write-once fleet-commit marker under each participating server's mutation lock (exclusive create; an existing marker must match byte-for-byte). The marker carries the deployment ID, the generation, and the full placement-slot set of the fleet commit. If this metadata phase is interrupted by a transient failure, mark the attempt `pending_commit`; the next push reconciles it before its own no-op check. Reconciliation also covers attempts whose latest transition is `InProgress` — intent durable (persisted before mutation, step 14) but finalization never completed (a crash between `append_attempt` and the finalize marker, or a faulted `write_results`). It loads the eligible attempts (oldest first, latest transition `PendingCommit` OR `InProgress`), verifies that every recorded participant slot still belongs to the target and that each slot's current generation still equals the generation the attempt recorded (fresh status reads), and only then writes the missing markers (under each server's mutation lock, with the original deployment ID) and finalizes the attempt as `successful` through the SAME replay-safe finalizer the normal success path uses (step 16): first persist the recoverable `pending_commit` marker when the latest transition is not already `pending_commit`, then the snapshot entry and `refs/last-successful` (idempotent — a replay never duplicates the snapshot and repairs the ref), and the terminal `Successful` transition LAST, so a crash mid-finalization leaves the attempt's latest transition still `pending_commit` and therefore re-eligible. The verification is read-only; recovery never reactivates or restarts healthy servers. Any membership or generation mismatch changes the attempt to `degraded` (no snapshot entry). An existing marker whose content differs (an integrity conflict — a concurrent controller recorded a different fact, or the remote state diverged) is likewise NOT transient: the conflicting marker is left untouched and the attempt is finalized `degraded` (transition only, no snapshot entry), never stranded `pending_commit` forever. Only transient failures — lock acquisition, status reads, or transport-level marker writes — leave the attempt `pending_commit` for a later retry rather than falsely reporting `successful` or `degraded`.
16. Only an attempt whose fleet-commit markers are complete becomes `successful`. Both the normal success path and recovery finalize through ONE replay-safe finalizer that writes the recoverable `pending_commit` marker, then the snapshot entry and `refs/last-successful`, and appends the terminal `Successful` transition LAST (snapshot and ref first, status last, so the attempt is never recorded `successful` while its fleet snapshot is missing); the snapshot log (`<target>@fN`) and `refs/last-successful` advance only for such fully finalized attempts. The snapshot is built from the attempt's OUTCOMES — the per-slot actuals the engine observed on the main path, or `deployments/<id>/results.json` (falling back to the verified desired state when the outcomes were never persisted, e.g. a faulted `write_results`) during recovery — never from the intent record (`attempts.jsonl`), which carries no outcomes.
17. Apply rotation under each server's mutation lock using the protection set defined below.

The tool never claims fleet-wide atomicity. It reports `successful`, `pending_commit`, `failed_preflight`, `failed_rolled_back`, or `degraded`, including the actual generation on every server. An attempt that fails before any `current` change is `failed_preflight`. A later push always reconciles first and can finish an incomplete fleet commit (see step 15) or repair an incomplete target.

The local target lock prevents competing pushes from the same local store. Expected-generation and compensation compare-and-swap checks prevent a second controller from being silently overwritten. Concurrent controllers can still cause a visible failed or degraded fleet attempt, but cannot create a lost update on an individual server.

If materialization produces an existing release and reconciliation finds the exact desired generation healthy on every server, the command prints `Everything up to date` without creating a deployment attempt. Existing local
content never suppresses required remote repair.

`--dry-run` materializes and inspects local content and performs read-only remote status queries in disposable staging. It does not publish local objects, recover remote transactions, upload, publish remotely, activate, execute application verification, write history, or rotate. Instead, it reports any recovery that a real push would have to perform.

## Fleet history and rollback
Every deployment attempt records its immutable intent: target snapshot, behavior contract, pre-push state, desired state, and actual result — carrying NO status (the status lives in the deployment's transition stream). Assignment relationships are expressed through the canonical model types (`ArtifactRef` = release+variant+tree, `GenerationRef` = generation + placement-slot assignment); every per-location map is keyed by the deployment slot ID. A successful example (attempt record schema version 2) is:

```json
{
  "deployment_schema_version": 2,
  "deployment_id": "deploy-20260821T102000Z",
  "target": "production",
  "slot_ids": ["p1", "p2", "p3"],
  "behavior_sha256": "03df...",
  "attempted_at": "2026-08-21T10:20:00Z",
  "slots": {
    "p1": {
      "artifact": {
        "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
        "variant": "standard",
        "tree": "8cc1..."
      },
      "generation": "gen-01..."
    },
    "p2": {
      "artifact": {
        "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
        "variant": "standard",
        "tree": "8cc1..."
      },
      "generation": "gen-02..."
    },
    "p3": {
      "artifact": {
        "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
        "variant": "high-capacity",
        "tree": "197b..."
      },
      "generation": "gen-03..."
    }
  }
}
```

(The example omits the parallel `desired` and `pre_push` maps for brevity; the
stored record contains both alongside `slots`. `desired` holds each slot's
minted `GenerationRef` — `{generation, assignment: {placement_slot, artifact}}`
— while `pre_push` holds the pre-push `AttemptServer` per slot, `None` when the
slot was never deployed before. Schema version 1 keyed these maps by server ID
and stored the artifact triple as flat fields; version 2 rekeys to placement
slots and nests the artifact.)

The deployment's status is an append-only transition stream
(`deployments/<id>/transitions.jsonl`), one event per line; the current status
is the LATEST transition. For example:

```jsonl
{"deployment_id": "deploy-20260821T102000Z", "status": "in_progress", "recorded_at": "2026-08-21T10:20:00Z", "reason": "attempt started"}
{"deployment_id": "deploy-20260821T102000Z", "status": "successful", "recorded_at": "2026-08-21T10:25:00Z"}
```

The target snapshot log contains only fully successful fleet snapshots and exposes them as `production@f0`, `production@f1`, and so on. Failed and degraded attempts remain visible through `deploy log production` and `attempts.jsonl`, but are not valid rollback sources. Each snapshot entry records every slot's advanced generation AND the complete physical binding it had (`bindings`, keyed by slot ID — the slot's `{server, deploy_dir}` pair at deployment time): exact rollback maps generations to slots by slot ID, so the recorded binding is what proves a slot still lives at the exact on-host location it was deployed onto.

A fleet commit is authoritative only when the same deployment ID and placement-slot set are committed on every member. This lets a fresh or repaired local store reconstruct successful fleet history from the servers instead of trusting a stale local ref.

Pushing an older successful reference restores its complete assignment, including the historical behavior contract and different variants on different servers:

```sh
deploy push production production@f1
```

Exact fleet rollback requires the current target to contain the same stable placement-slot set as the saved deployment AND each slot's complete physical binding to match the binding the snapshot recorded (`bindings[slot]` = the `{server, deploy_dir}` pair from the slot's variant-file `[[slots]]` entry): a slot rebound to a different server — or moved to a different `deploy_dir` on the SAME server — would otherwise receive the historical generations on the wrong host or at the wrong on-server location. A legacy snapshot entry that never recorded the binding (pre-feature lines, or the intermediate server-only `servers` shape) is unverifiable and is refused the same way. Addresses may change and are taken from the current target definition after host-identity verification. If membership has changed or any slot's physical binding changed, exact rollback fails during preflight without modifying a server.

Schema version 1 permits a target-history ref only as a source for that same target; cross-target deployment uses a release ref instead.

The operator may instead push an old release to the new target membership:

```sh
deploy push production release/rel-41da2f63a950:current
```

That form assigns each slot the named release's tree for the variant the release's OWN stored slot snapshot assigns to it: a historical release resolves slot→variant bindings against the slots it was materialized from, never the caller's current variant files (only a legacy record without a stored slot snapshot falls back to the current declaring file). The abbreviated release ID must be unambiguous; scripts and persistent configuration use the full ID. The push fails if the release lacks any assigned variant.

Rollback never rebuilds a tree. It uses the retained immutable object with the recorded digest. All required objects are checked locally and staged remotely before the first server changes. If an object is missing locally, reconciliation first attempts to recover it from a target server that retains the verified digest. If no verified copy can be recovered, preflight fails and leaves every `current` pointer unchanged.

## Protection and rotation
The retention policy comes from the pushed target's own `rotation` configuration, so different targets can retain differently (a canary target may retain more than production). Retention is evaluated per server because servers may have different release and variant histories. A successful fleet deployment is committed back to each participating server before rotation, allowing its generation history to record the fleet deployment ID. Rotation does not run if those commit markers cannot be reconciled.

Capacity preflight reserves the larger of `capacity.reserve_bytes` and `capacity.reserve_percent` of the destination filesystem after the upload. Capacity is a per-server policy declared on the server entry (`capacity = { reserve_bytes = ..., reserve_percent = ... }`) and resolved from the caller's CURRENT configuration on every push — HEAD and historical alike, because servers have no per-release history; it is never part of a release snapshot. The check may invoke the same protected rotation before staging, but never weakens the retained set merely to make a deployment fit.

For each server, the retained content set is exactly this union:

```text
- the artifact referenced by the current generation
- the prior distinct successful artifact when protect_previous is true
- artifacts referenced by incomplete transactions
- releases selected by durable pins
- the newest keep_distinct_artifacts distinct successful artifact bindings
- artifacts successfully activated less than keep_days ago
- that server's artifacts in the newest protect_deployments fleet commits
```

An artifact binding is `(release ID, variant, tree digest)`. Repeated repair or restart generations for the same binding consume one retention slot, not many.

Pins are controller-side configuration (top-level `[[pins]]` entries in the project file), never server-stored state. The controller evaluates them from its local store when computing each server's retained set (`rotation::compute_retained`); servers hold no pin records and never learn them remotely.
Distinct artifacts are ordered by their most recent successful activation. `keep_distinct_artifacts` and `keep_days` are union rules, not conditions that must both match. Age is measured from the binding's most recent successful activation rather than release creation time.

Rotation is a mark-and-sweep operation under the remote mutation lock:
1. Reconcile `current`, unfinished transactions, pins, and fleet commit markers.
2. Mark tree objects referenced by the retained artifact bindings.
3. Keep generation, release, and fleet-commit metadata by default; metadata is small and continues to explain unavailable historical states.
4. Delete a tree object only when no retained binding or applicable pin on that server references it. A release or generation record may continue to describe a tree that is no longer installed and must report it as unavailable.
5. Remove abandoned operation-specific incoming directories only after their owner transaction has expired and is known not to be running.

Local rotation protects the complete set of variants for every release selected by the same count, age, current, prior, fleet-window, pin, remote-inventory, or unfinished-attempt rules across all targets.

Successful snapshot metadata may be
kept indefinitely, but only entries inside the configured protection windows retain release and tree content. An older snapshot entry whose content was rotated remains auditable but is reported as unavailable for rollback. A local tree object is deleted only after no retained release or known remote inventory requires it.

Rotation runs automatically after a successful, fully recorded push. It may later be exposed as an explicit maintenance command without changing these safety rules.

## systemd adapter
Systemd support is an optional adapter outside the generic artifact engine. The mapped unit remains an ordinary artifact file whose CONTENT is rendered through the template module (see “Mapping semantics” and “Activation”) with the slot's template context at activation time — `ExecStart={{ deploy_dir }}/current/app/server` resolves per slot, and the tree itself stays slot-independent (content-addressed and shared across slots). The adapter alone knows how to register and activate it. The activation and verification definitions are canonicalized, hashed into the release identity, and copied into each deployment and generation record. A historical push therefore uses its historical behavior contract rather than the caller's current configuration.

Before changing `current`, the helper validates that every declared `artifact_path` exists with the required type in the desired tree. Command verification is executed directly as an argument vector, never through a shell, with the configured deployment identity, timeout, attempt count, and
interval. Success requires a zero exit status within the timeout. Both the unit content and the verification `argv` are rendered with the full slot context — all 13 elected variables (`deploy_dir`, `variant`, `application`, `release`, `target`, `server`, `user`, `address`, `port`, `slot`, `deployment_id`, `generation`, `tree`), where `release` is the deployed artifact's immutable `ReleaseId` — before they are executed; an unknown or malformed template fails activation/verification loudly. Compensation re-runs the PRIOR generation's contract with the PRIOR artifact's identity (`release`/`variant`/`tree` move together via the `with_artifact` context), so a restored slot that switches variants never renders a torn combination (e.g. the prior variant with the desired release).

Registration stages the rendered unit as a REGULAR FILE under the deployment root (`adapters/systemd/<unit>`) and copies it into the user service manager directory, so the installed unit reflects the slot context (a rendered unit can no longer be a symlink into the generation tree):

```text
~/.config/systemd/user/example.service   (regular file, rendered from the unit artifact)
  content: ExecStart=/srv/deploy/example/current/integration/systemd/example.service
```

The first push moves `current` to the prepared generation and then registers and enables missing units idempotently as part of the recoverable activation transaction. Every activation or rollback performs the declared `daemon-reload`, enable, restart, and verification operations.

The adapter records the unit links it owns in `adapters/systemd.json` on the deployment root, next to the rendered-units directory `adapters/systemd/`. With `reconcile_managed_units: true`, a successful transition disables and removes formerly managed links absent from the desired behavior contract; it never modifies unrelated units. On failure, compensation restores `current` and reconciles the prior generation's behavior contract before verification.

Artifact-controlled unit files are supported by default only with `scope: user`, using `systemctl --user`; they consequently have no more authority than the deployment account. A host may require one-time administrator configuration to keep that user's systemd manager running when the user is logged out.
For a system service, an administrator installs a root-owned wrapper unit whose security-sensitive directives, service user, and stable command entry point are not writable by the deployment account. In `scope: system`, `push` only verifies that wrapper's identity and uses a narrowly scoped permission to restart that specific unit. It never links an artifact-controlled unit into `/etc/systemd/system`. Treating a deployment account as authorized to replace system unit contents would make that account effectively root and is outside the safe default design.

## Transport and remote helper
The initial transport is SSH with strict host-key verification (per-server `known_hosts` or pinned `host_key_fingerprint` — exactly one source per SSH server, enforced at config validation and re-checked defensively at transport construction). An explicit `local://<absolute-path>` server address instead routes the transport to that exact filesystem endpoint; it exists for tests and for local targets. Server IDs, target names, variant names, release IDs, and paths are validated data and are never concatenated into remote shell commands. Bulk tree transfer uses SFTP or an equivalent framed channel.

A small versioned remote helper owns status inspection, locking, object publication, generation switching, transaction recovery, adapter invocation, and rotation. Client and helper perform a protocol-version handshake before mutation (the negotiated version is recorded under `control/`; schema version 1 speaks protocol 1). Every mutating request carries an operation ID and is idempotent, and each operation's durable per-server transaction record (`transactions/<operation-id>.json`, advanced `prepared` → `committed`/`compensated` by the helper) lets a disconnected client reconnect and learn whether the operation prepared, committed, compensated, or never began. Packaging these operations as a single versioned helper binary uploaded beneath each slot's `deploy_dir` is the planned evolution; it does not change this contract.

If the deployment account cannot create a slot's `deploy_dir`, an administrator must provision that directory once. Privileged systemd control must likewise be provisioned through the fixed, root-owned wrapper and narrowly scoped restart permission described above; `push` does not grant itself privileges.

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
- Snapshot mappings, variant bindings, behavior contract, target placement-slot IDs, pre-push generations, desired generations, timestamps, and actual results.
- Never fail open: a missing or corrupt historical behavior snapshot fails the attempt in preflight instead of falling back to the caller's current configuration or defaults. (Capacity is never snapshotted: it is live per-server configuration read from the caller's current `deploy.toml`, for HEAD and historical pushes alike.)
- Treat all artifact bytes as confidential and never log their contents.
